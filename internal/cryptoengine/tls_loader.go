package cryptoengine

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"cert-me/internal/cryptowork"
	"cert-me/internal/domain"
)

type TLSKeyLoader struct {
	ring *KeyRing
}

func NewTLSKeyLoader(ring *KeyRing) (*TLSKeyLoader, error) {
	if ring == nil {
		return nil, errors.New("cryptoengine: key ring is required")
	}
	if err := ring.withActiveKey(func(string, []byte) error { return nil }); err != nil {
		return nil, err
	}
	return &TLSKeyLoader{ring: ring}, nil
}

// LoadTLSCertificate decrypts an internal_tls secret for the lifetime of a
// single TLS preparation call and returns the private signer to the listener
// adapter that will own the resulting in-memory certificate.
func (l *TLSKeyLoader) LoadTLSCertificate(ctx context.Context, version domain.TLSVersion, encrypted domain.EncryptedSecret) (tls.Certificate, error) {
	if err := checkContext(ctx); err != nil {
		return tls.Certificate{}, err
	}
	if version.ID() == "" || version.KeyMaterialID() == "" || encrypted.IsZero() ||
		encrypted.OwnerKeyID() != version.KeyMaterialID() || encrypted.Purpose() != domain.SecretPurposeInternalTLS ||
		encrypted.FormatVersion() != secretFormatVersion {
		return tls.Certificate{}, errors.New("cryptoengine: TLS secret owner, purpose, or format is invalid")
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer release()

	leafDER := version.LeafDER()
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil || !bytes.Equal(leaf.Raw, leafDER) {
		return tls.Certificate{}, errors.New("cryptoengine: TLS leaf certificate DER is invalid")
	}
	if !leaf.NotAfter.Equal(version.NotAfter().Time()) || !hasServerAuth(leaf) || len(leaf.UnhandledCriticalExtensions) != 0 {
		return tls.Certificate{}, errors.New("cryptoengine: TLS leaf facts or serverAuth usage do not match its DER")
	}
	chainDER, chain, err := parseTLSChain(version.ChainBundle())
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := validateTLSChain(leaf, chain); err != nil {
		return tls.Certificate{}, err
	}

	privateDER, err := decryptTLSKey(l.ring, encrypted)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer zero(privateDER)
	privateKey, err := parsePrivateKey(privateDER)
	if err != nil {
		return tls.Certificate{}, errors.New("cryptoengine: TLS private key is invalid")
	}
	keepPrivateKey := false
	defer func() {
		if !keepPrivateKey {
			clearPrivateKey(privateKey)
		}
	}()
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, errors.New("cryptoengine: TLS private key cannot sign handshakes")
	}
	algorithm, err := publicKeyAlgorithm(leaf.PublicKey)
	if err != nil {
		return tls.Certificate{}, errors.New("cryptoengine: TLS certificate public key is unsupported")
	}
	key, err := publicKeyFor(privateKey, algorithm)
	if err != nil || !key.Equal(domainPublicKeyOrZero(leaf)) {
		return tls.Certificate{}, errors.New("cryptoengine: TLS private key does not match its certificate")
	}
	if err := checkContext(ctx); err != nil {
		return tls.Certificate{}, err
	}
	chainBytes := make([][]byte, 0, len(chainDER)+1)
	chainBytes = append(chainBytes, append([]byte(nil), leaf.Raw...))
	for _, der := range chainDER {
		chainBytes = append(chainBytes, append([]byte(nil), der...))
	}
	keepPrivateKey = true
	return tls.Certificate{Certificate: chainBytes, PrivateKey: signer, Leaf: leaf}, nil
}

func parseTLSChain(bundle []byte) ([][]byte, []*x509.Certificate, error) {
	remaining := bytes.TrimSpace(bundle)
	if len(remaining) == 0 {
		return nil, nil, errors.New("cryptoengine: TLS issuer chain is empty")
	}
	var ders [][]byte
	var certificates []*x509.Certificate
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errors.New("cryptoengine: TLS issuer chain PEM is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !bytes.Equal(certificate.Raw, block.Bytes) {
			return nil, nil, errors.New("cryptoengine: TLS issuer certificate DER is invalid")
		}
		ders = append(ders, append([]byte(nil), block.Bytes...))
		certificates = append(certificates, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	if len(ders) == 0 || len(ders) > 2 {
		return nil, nil, errors.New("cryptoengine: TLS issuer chain exceeds the supported depth")
	}
	return ders, certificates, nil
}

func validateTLSChain(leaf *x509.Certificate, chain []*x509.Certificate) error {
	ordered := append([]*x509.Certificate{leaf}, chain...)
	for i := 0; i+1 < len(ordered); i++ {
		parent := ordered[i+1]
		if !parent.BasicConstraintsValid || !parent.IsCA || parent.KeyUsage&x509.KeyUsageCertSign == 0 ||
			len(parent.UnhandledCriticalExtensions) != 0 ||
			!bytes.Equal(ordered[i].RawIssuer, parent.RawSubject) || ordered[i].CheckSignatureFrom(parent) != nil {
			return errors.New("cryptoengine: TLS certificate chain link is invalid")
		}
	}
	root := chain[len(chain)-1]
	if !bytes.Equal(root.RawSubject, root.RawIssuer) || root.CheckSignatureFrom(root) != nil {
		return errors.New("cryptoengine: TLS chain does not end at a self-signed root")
	}
	return nil
}

func hasServerAuth(certificate *x509.Certificate) bool {
	if len(certificate.UnknownExtKeyUsage) != 0 {
		return false
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func decryptTLSKey(ring *KeyRing, encrypted domain.EncryptedSecret) ([]byte, error) {
	nonce := encrypted.Nonce()
	ciphertext := encrypted.Ciphertext()
	defer zero(nonce)
	defer zero(ciphertext)
	if len(nonce) != secretNonceSize {
		return nil, errors.New("cryptoengine: TLS secret nonce is invalid")
	}
	var plaintext []byte
	err := ring.withGenerationKeys(encrypted.EncryptionGenerationID(), encrypted.EncryptionGenerationID(), func(key, _ []byte) error {
		opened, err := openSecret(key, encrypted.OwnerKeyID(), encrypted.Purpose(), encrypted.FormatVersion(),
			encrypted.EncryptionGenerationID(), nonce, ciphertext)
		if err != nil {
			return err
		}
		plaintext = opened
		return nil
	})
	if err != nil {
		zero(plaintext)
		return nil, errors.New("cryptoengine: TLS secret could not be authenticated")
	}
	return plaintext, nil
}
