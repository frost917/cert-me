// Package tlsruntime owns the in-memory HTTPS configuration used by the
// application's listener.
package tlsruntime

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sync"
	"sync/atomic"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

var (
	ErrForeignHandle  = errors.New("tlsruntime: prepared handle belongs to another installer")
	ErrHandleConsumed = errors.New("tlsruntime: prepared handle is unknown, consumed, or discarded")
	ErrClosed         = errors.New("tlsruntime: configuration manager is closed")
	ErrNoActiveConfig = errors.New("tlsruntime: no active TLS configuration")
)

// TLSCertificateLoader decrypts and validates the candidate's private key
// and returns its certificate chain. The returned private key is transferred
// to ConfigManager, which copies it into manager-owned storage and clears the
// loader's copy.
type TLSCertificateLoader interface {
	LoadTLSCertificate(context.Context, domain.TLSVersion, domain.EncryptedSecret) (tls.Certificate, error)
}

type tlsSnapshot struct {
	config     *tls.Config
	privateKey crypto.Signer
}

// ConfigManager implements port.TLSInstaller and atomically publishes the
// active TLS snapshot to net/http through ServerConfig. Config snapshots are
// never returned directly: the callback supplies a fresh configuration copy
// for each handshake.
type ConfigManager struct {
	mu      sync.Mutex
	loader  TLSCertificateLoader
	token   port.TLSPrepareToken
	pending map[any]*tlsSnapshot
	active  atomic.Pointer[tlsSnapshot]
	closed  bool
}

var _ port.TLSInstaller = (*ConfigManager)(nil)

// NewConfigManager constructs an empty manager. A server may receive its
// ServerConfig before a certificate is active; handshakes will fail with
// ErrNoActiveConfig until the first successful Apply.
func NewConfigManager(loader TLSCertificateLoader) (*ConfigManager, error) {
	if loader == nil || isNilInterface(loader) {
		return nil, errors.New("tlsruntime: certificate loader is required")
	}
	return &ConfigManager{
		loader:  loader,
		token:   port.NewTLSPrepareToken(),
		pending: make(map[any]*tlsSnapshot),
	}, nil
}

func isNilInterface(value any) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// Prepare loads the certificate, creates a manager-owned immutable snapshot,
// and registers it under a fresh opaque handle. It does not affect the live
// listener.
func (m *ConfigManager) Prepare(ctx context.Context, candidate domain.TLSVersion, key domain.EncryptedSecret) (port.PreparedTLSConfig, error) {
	if ctx == nil {
		return port.PreparedTLSConfig{}, errors.New("tlsruntime: request context is required")
	}
	if err := ctx.Err(); err != nil {
		return port.PreparedTLSConfig{}, err
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return port.PreparedTLSConfig{}, ErrClosed
	}

	loaded, err := m.loader.LoadTLSCertificate(ctx, candidate, key)
	if err != nil {
		clearPrivateKey(loaded.PrivateKey)
		return port.PreparedTLSConfig{}, fmt.Errorf("tlsruntime: load candidate certificate: %w", err)
	}
	if err := ctx.Err(); err != nil {
		clearPrivateKey(loaded.PrivateKey)
		return port.PreparedTLSConfig{}, err
	}

	snapshot, err := makeSnapshot(candidate, loaded)
	if err != nil {
		clearPrivateKey(loaded.PrivateKey)
		return port.PreparedTLSConfig{}, err
	}
	// makeSnapshot copies the supported private-key type before returning. The
	// loader's value is no longer needed even when validation succeeds.
	clearPrivateKey(loaded.PrivateKey)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		clearSnapshot(snapshot)
		return port.PreparedTLSConfig{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		clearSnapshot(snapshot)
		return port.PreparedTLSConfig{}, err
	}
	prepared := port.NewPreparedTLSConfig(m.token)
	m.pending[prepared.ID()] = snapshot
	return prepared, nil
}

// Apply consumes an owned handle exactly once. It verifies the installer
// token before using the opaque ID, then either swaps the live snapshot or
// clears the consumed candidate while leaving the previous snapshot active.
func (m *ConfigManager) Apply(ctx context.Context, prepared port.PreparedTLSConfig) error {
	if !m.token.Verify(prepared) {
		return ErrForeignHandle
	}

	id := prepared.ID()
	m.mu.Lock()
	snapshot, ok := m.pending[id]
	if !ok {
		m.mu.Unlock()
		return ErrHandleConsumed
	}
	delete(m.pending, id)
	if ctx == nil {
		m.mu.Unlock()
		clearSnapshot(snapshot)
		return errors.New("tlsruntime: request context is required")
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		clearSnapshot(snapshot)
		return err
	}
	if m.closed {
		m.mu.Unlock()
		clearSnapshot(snapshot)
		return ErrClosed
	}

	// All remaining work is infallible. Do not clear the previous snapshot:
	// handshakes that already received its per-connection config may still use
	// the signer. It becomes collectible when those configs are released.
	m.active.Swap(snapshot)
	m.mu.Unlock()
	return nil
}

// Discard is context-free, idempotent, and only releases this installer's
// still-pending handles. It never affects the active snapshot.
func (m *ConfigManager) Discard(prepared port.PreparedTLSConfig) {
	if !m.token.Verify(prepared) {
		return
	}
	m.mu.Lock()
	snapshot, ok := m.pending[prepared.ID()]
	if ok {
		delete(m.pending, prepared.ID())
	}
	m.mu.Unlock()
	if ok {
		clearSnapshot(snapshot)
	}
}

// ServerConfig returns the stable entry-point configuration for an
// http.Server. Its callback atomically reads the current snapshot and returns
// a per-handshake copy, never the manager's mutable internal tls.Config.
func (m *ConfigManager) ServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			snapshot := m.active.Load()
			if snapshot == nil {
				return nil, ErrNoActiveConfig
			}
			return snapshot.handshakeConfig()
		},
	}
}

// Close releases all pending and active private-key material. Call it only
// after the HTTP listener has shut down and no handshakes can still be using
// the active key. It is safe to call more than once.
func (m *ConfigManager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	pending := make([]*tlsSnapshot, 0, len(m.pending))
	for id, snapshot := range m.pending {
		delete(m.pending, id)
		pending = append(pending, snapshot)
	}
	active := m.active.Swap(nil)
	m.mu.Unlock()

	for _, snapshot := range pending {
		clearSnapshot(snapshot)
	}
	clearSnapshot(active)
}

func makeSnapshot(version domain.TLSVersion, loaded tls.Certificate) (*tlsSnapshot, error) {
	// The source key is owned by this call from here onward and is cleared by
	// Prepare after makeSnapshot returns. Only RSA and ECDSA are accepted; both
	// have explicit, safe zeroing paths below.
	privateKey, err := clonePrivateSigner(loaded.PrivateKey)
	if err != nil {
		return nil, err
	}
	keepCopy := false
	defer func() {
		if !keepCopy {
			clearPrivateKey(privateKey)
		}
	}()

	chain := loaded.Certificate
	if len(chain) == 0 {
		return nil, errors.New("tlsruntime: certificate chain is empty")
	}
	expectedLeaf := version.LeafDER()
	defer clearBytes(expectedLeaf)
	if len(expectedLeaf) == 0 || !equalBytes(chain[0], expectedLeaf) {
		return nil, errors.New("tlsruntime: loaded leaf does not match the TLS version")
	}
	certificates := make([][]byte, len(chain))
	var leaf *x509.Certificate
	for i, der := range chain {
		if len(der) == 0 {
			return nil, errors.New("tlsruntime: certificate chain contains an empty entry")
		}
		certificates[i] = append([]byte(nil), der...)
		parsed, parseErr := x509.ParseCertificate(certificates[i])
		if parseErr != nil || !equalBytes(parsed.Raw, certificates[i]) {
			return nil, fmt.Errorf("tlsruntime: certificate chain entry %d is invalid DER", i)
		}
		if i == 0 {
			leaf = parsed
		}
	}

	leafPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, errors.New("tlsruntime: certificate public key cannot be encoded")
	}
	defer clearBytes(leafPublic)
	keyPublic, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, errors.New("tlsruntime: private key public component cannot be encoded")
	}
	defer clearBytes(keyPublic)
	if !equalBytes(leafPublic, keyPublic) {
		return nil, errors.New("tlsruntime: private key does not match the TLS leaf")
	}

	certificate := tls.Certificate{
		Certificate: certificates,
		PrivateKey:  &privateSigner{signer: privateKey},
		Leaf:        leaf,
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{certificate},
	}
	keepCopy = true
	return &tlsSnapshot{config: config, privateKey: privateKey}, nil
}

func (s *tlsSnapshot) handshakeConfig() (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	certificate := s.config.Certificates[0]
	certificate.Certificate = cloneByteSlices(certificate.Certificate)
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("tlsruntime: stored TLS leaf is invalid: %w", err)
	}
	certificate.Leaf = leaf
	config.Certificates = []tls.Certificate{certificate}
	return config, nil
}

type privateSigner struct {
	signer crypto.Signer
}

func (s *privateSigner) Public() crypto.PublicKey {
	return clonePublicKey(s.signer.Public())
}

func (s *privateSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signer.Sign(random, digest, opts)
}

func clonePublicKey(public crypto.PublicKey) crypto.PublicKey {
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		if key == nil {
			return (*ecdsa.PublicKey)(nil)
		}
		return &ecdsa.PublicKey{Curve: key.Curve, X: cloneBigInt(key.X), Y: cloneBigInt(key.Y)}
	case *rsa.PublicKey:
		if key == nil {
			return (*rsa.PublicKey)(nil)
		}
		return &rsa.PublicKey{N: cloneBigInt(key.N), E: key.E}
	default:
		return public
	}
}

func clonePrivateSigner(private any) (crypto.Signer, error) {
	switch key := private.(type) {
	case *ecdsa.PrivateKey:
		if key == nil || key.Curve == nil || key.D == nil || key.X == nil || key.Y == nil || key.D.Sign() <= 0 || !key.Curve.IsOnCurve(key.X, key.Y) {
			return nil, errors.New("tlsruntime: ECDSA private key is invalid")
		}
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() {
			return nil, errors.New("tlsruntime: ECDSA curve is unsupported")
		}
		params := key.Curve.Params()
		if params == nil || params.N == nil || key.D.Cmp(params.N) >= 0 {
			return nil, errors.New("tlsruntime: ECDSA private key is invalid")
		}
		x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
		if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
			return nil, errors.New("tlsruntime: ECDSA public and private components differ")
		}
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: key.Curve, X: cloneBigInt(key.X), Y: cloneBigInt(key.Y)},
			D:         cloneBigInt(key.D),
		}, nil
	case *rsa.PrivateKey:
		if key == nil || key.N == nil || key.D == nil || len(key.Primes) < 2 {
			return nil, errors.New("tlsruntime: RSA private key is invalid")
		}
		for _, prime := range key.Primes {
			if prime == nil {
				return nil, errors.New("tlsruntime: RSA private key is invalid")
			}
		}
		if key.Validate() != nil {
			return nil, errors.New("tlsruntime: RSA private key is invalid")
		}
		copy := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: cloneBigInt(key.N), E: key.E},
			D:         cloneBigInt(key.D),
			Primes:    make([]*big.Int, len(key.Primes)),
		}
		for i, prime := range key.Primes {
			copy.Primes[i] = cloneBigInt(prime)
		}
		copy.Precompute()
		return copy, nil
	default:
		return nil, errors.New("tlsruntime: private key type is unsupported")
	}
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func clearSnapshot(snapshot *tlsSnapshot) {
	if snapshot == nil {
		return
	}
	clearPrivateKey(snapshot.privateKey)
	snapshot.privateKey = nil
	if snapshot.config != nil {
		for i := range snapshot.config.Certificates {
			certificate := &snapshot.config.Certificates[i]
			for _, der := range certificate.Certificate {
				clearBytes(der)
			}
			certificate.Certificate = nil
			certificate.PrivateKey = nil
			certificate.Leaf = nil
		}
		snapshot.config.Certificates = nil
		snapshot.config = nil
	}
}

func clearPrivateKey(private any) {
	switch key := private.(type) {
	case *ecdsa.PrivateKey:
		if key != nil && key.D != nil {
			key.D.SetInt64(0)
			key.D = nil
		}
	case *rsa.PrivateKey:
		if key == nil {
			return
		}
		if key.D != nil {
			key.D.SetInt64(0)
			key.D = nil
		}
		for _, prime := range key.Primes {
			if prime != nil {
				prime.SetInt64(0)
			}
		}
		key.Primes = nil
		for _, value := range []*big.Int{key.Precomputed.Dp, key.Precomputed.Dq, key.Precomputed.Qinv} {
			if value != nil {
				value.SetInt64(0)
			}
		}
		for i := range key.Precomputed.CRTValues {
			crt := &key.Precomputed.CRTValues[i]
			for _, value := range []*big.Int{crt.Exp, crt.Coeff, crt.R} {
				if value != nil {
					value.SetInt64(0)
				}
			}
		}
		key.Precomputed = rsa.PrecomputedValues{}
	case ed25519.PrivateKey:
		clearBytes(key)
	}
}

func cloneByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for i, value := range values {
		cloned[i] = append([]byte(nil), value...)
	}
	return cloned
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtleCompare(a, b) == 1
}

// subtleCompare uses a constant-time comparison for the key/certificate
// equality check without exposing a mutable copy of either input.
func subtleCompare(a, b []byte) int {
	return subtle.ConstantTimeCompare(a, b)
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
