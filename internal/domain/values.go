// Package domain holds pure objects, policies and value types. It must not
// reference HTTP, SQL, files, environment variables or a global clock.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Identifier types are distinct named string types so that an ID of one kind
// cannot be passed where another kind is expected. Values are UUIDs; parsing
// validates the textual form.
type (
	AuthorityID         string
	CAKeyGenerationID   string
	CertificateID       string
	SeriesID            string
	LeafKeyGenerationID string
	KeyMaterialID       string
	DeliveryID          string
	GrantID             string
	RevocationID        string
	AccountID           string
	SessionID           string
	TransitionID        string
	TLSVersionID        string
	JobID               string
	ResetTokenID        string
	CRLDocumentID       string
)

// uuidLength is the canonical 8-4-4-4-12 hyphenated form length.
const uuidLength = 36

// IDGenerator produces new identifiers. Adapters own the randomness source so
// that domain and app code stay deterministic under test.
type IDGenerator interface {
	NewUUID() string
}

func parseUUID(kind, raw string) (string, error) {
	if len(raw) != uuidLength {
		return "", fmt.Errorf("%w: %s must be a 36 character uuid", ErrInvalidValue, kind)
	}
	for i := 0; i < uuidLength; i++ {
		c := raw[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "", fmt.Errorf("%w: %s has a misplaced separator", ErrInvalidValue, kind)
			}
		default:
			if !isLowerHexDigit(c) {
				return "", fmt.Errorf("%w: %s must use lowercase hex digits", ErrInvalidValue, kind)
			}
		}
	}
	return raw, nil
}

func isLowerHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// ParseAuthorityID and the parsers below reject anything that is not a
// canonical lowercase UUID.
func ParseAuthorityID(raw string) (AuthorityID, error) {
	v, err := parseUUID("authority id", raw)
	return AuthorityID(v), err
}

func ParseCAKeyGenerationID(raw string) (CAKeyGenerationID, error) {
	v, err := parseUUID("ca key generation id", raw)
	return CAKeyGenerationID(v), err
}

func ParseCertificateID(raw string) (CertificateID, error) {
	v, err := parseUUID("certificate id", raw)
	return CertificateID(v), err
}

func ParseSeriesID(raw string) (SeriesID, error) {
	v, err := parseUUID("series id", raw)
	return SeriesID(v), err
}

func ParseLeafKeyGenerationID(raw string) (LeafKeyGenerationID, error) {
	v, err := parseUUID("leaf key generation id", raw)
	return LeafKeyGenerationID(v), err
}

func ParseKeyMaterialID(raw string) (KeyMaterialID, error) {
	v, err := parseUUID("key material id", raw)
	return KeyMaterialID(v), err
}

func ParseDeliveryID(raw string) (DeliveryID, error) {
	v, err := parseUUID("delivery id", raw)
	return DeliveryID(v), err
}

func ParseGrantID(raw string) (GrantID, error) {
	v, err := parseUUID("grant id", raw)
	return GrantID(v), err
}

func ParseRevocationID(raw string) (RevocationID, error) {
	v, err := parseUUID("revocation id", raw)
	return RevocationID(v), err
}

func ParseAccountID(raw string) (AccountID, error) {
	v, err := parseUUID("account id", raw)
	return AccountID(v), err
}

func ParseSessionID(raw string) (SessionID, error) {
	v, err := parseUUID("session id", raw)
	return SessionID(v), err
}

func ParseTransitionID(raw string) (TransitionID, error) {
	v, err := parseUUID("transition id", raw)
	return TransitionID(v), err
}

func ParseTLSVersionID(raw string) (TLSVersionID, error) {
	v, err := parseUUID("tls version id", raw)
	return TLSVersionID(v), err
}

func ParseJobID(raw string) (JobID, error) {
	v, err := parseUUID("job id", raw)
	return JobID(v), err
}

func ParseResetTokenID(raw string) (ResetTokenID, error) {
	v, err := parseUUID("reset token id", raw)
	return ResetTokenID(v), err
}

func ParseCRLDocumentID(raw string) (CRLDocumentID, error) {
	v, err := parseUUID("crl document id", raw)
	return CRLDocumentID(v), err
}

// Version is a non-negative optimistic locking counter.
type Version int64

func ParseVersion(raw int64) (Version, error) {
	if raw < 0 {
		return 0, fmt.Errorf("%w: version must not be negative", ErrInvalidValue)
	}
	return Version(raw), nil
}

// Next returns the version a successful save must write.
func (v Version) Next() Version { return v + 1 }

func (v Version) Int64() int64 { return int64(v) }

// Fingerprint is a SHA-256 digest rendered as 64 lowercase hex characters.
type Fingerprint struct {
	hex string
}

const fingerprintHexLength = sha256.Size * 2

// NewFingerprint hashes the given bytes. The input is not retained.
func NewFingerprint(data []byte) Fingerprint {
	sum := sha256.Sum256(data)
	return Fingerprint{hex: hex.EncodeToString(sum[:])}
}

// ParseFingerprint accepts the lowercase hex form only.
func ParseFingerprint(raw string) (Fingerprint, error) {
	if len(raw) != fingerprintHexLength {
		return Fingerprint{}, fmt.Errorf("%w: fingerprint must be %d hex characters", ErrInvalidValue, fingerprintHexLength)
	}
	for i := 0; i < len(raw); i++ {
		if !isLowerHexDigit(raw[i]) {
			return Fingerprint{}, fmt.Errorf("%w: fingerprint must use lowercase hex digits", ErrInvalidValue)
		}
	}
	return Fingerprint{hex: raw}, nil
}

func (f Fingerprint) Hex() string { return f.hex }

func (f Fingerprint) IsZero() bool { return f.hex == "" }

func (f Fingerprint) Equal(other Fingerprint) bool { return f.hex == other.hex }

func (f Fingerprint) String() string {
	if f.hex == "" {
		return "<empty fingerprint>"
	}
	return f.hex
}

// maxSerialHexLength matches the storage constraint: at most 20 octets.
const maxSerialHexLength = 40

// SerialNumber is a validated positive certificate serial in minimal
// lowercase hex form, comparable as a big integer.
type SerialNumber struct {
	hex string
}

// ParseSerialNumber accepts minimal lowercase hex without a leading zero.
func ParseSerialNumber(raw string) (SerialNumber, error) {
	if err := validateMinimalHex("serial number", raw, maxSerialHexLength); err != nil {
		return SerialNumber{}, err
	}
	if raw == "0" {
		return SerialNumber{}, fmt.Errorf("%w: serial number must be positive", ErrInvalidValue)
	}
	return SerialNumber{hex: raw}, nil
}

// NewSerialNumberFromBig converts a positive integer to its minimal hex form.
func NewSerialNumberFromBig(n *big.Int) (SerialNumber, error) {
	if n == nil || n.Sign() <= 0 {
		return SerialNumber{}, fmt.Errorf("%w: serial number must be positive", ErrInvalidValue)
	}
	return ParseSerialNumber(n.Text(16))
}

func (s SerialNumber) Hex() string { return s.hex }

func (s SerialNumber) IsZero() bool { return s.hex == "" }

func (s SerialNumber) Big() *big.Int {
	n := new(big.Int)
	if s.hex == "" {
		return n
	}
	n.SetString(s.hex, 16)
	return n
}

func (s SerialNumber) Equal(other SerialNumber) bool { return s.hex == other.hex }

// Compare returns -1, 0 or 1 by numeric value, not by string order.
func (s SerialNumber) Compare(other SerialNumber) int { return s.Big().Cmp(other.Big()) }

func (s SerialNumber) String() string { return s.hex }

// CRLNumber is a non-negative monotonically increasing CRL counter.
type CRLNumber struct {
	hex string
}

// ParseCRLNumber accepts minimal lowercase hex; "0" is a valid CRL number.
func ParseCRLNumber(raw string) (CRLNumber, error) {
	if err := validateMinimalHex("crl number", raw, maxSerialHexLength); err != nil {
		return CRLNumber{}, err
	}
	return CRLNumber{hex: raw}, nil
}

func NewCRLNumberFromBig(n *big.Int) (CRLNumber, error) {
	if n == nil || n.Sign() < 0 {
		return CRLNumber{}, fmt.Errorf("%w: crl number must not be negative", ErrInvalidValue)
	}
	return ParseCRLNumber(n.Text(16))
}

func (c CRLNumber) Hex() string { return c.hex }

func (c CRLNumber) IsZero() bool { return c.hex == "" }

func (c CRLNumber) Big() *big.Int {
	n := new(big.Int)
	if c.hex == "" {
		return n
	}
	n.SetString(c.hex, 16)
	return n
}

func (c CRLNumber) Compare(other CRLNumber) int { return c.Big().Cmp(other.Big()) }

// Increment returns the next CRL number.
func (c CRLNumber) Increment() CRLNumber {
	next := new(big.Int).Add(c.Big(), big.NewInt(1))
	return CRLNumber{hex: next.Text(16)}
}

func (c CRLNumber) String() string { return c.hex }

func validateMinimalHex(kind, raw string, maxLen int) error {
	if raw == "" {
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidValue, kind)
	}
	if len(raw) > maxLen {
		return fmt.Errorf("%w: %s must be at most %d hex characters", ErrInvalidValue, kind, maxLen)
	}
	if len(raw) > 1 && raw[0] == '0' {
		return fmt.Errorf("%w: %s must not have a leading zero", ErrInvalidValue, kind)
	}
	for i := 0; i < len(raw); i++ {
		if !isLowerHexDigit(raw[i]) {
			return fmt.Errorf("%w: %s must use lowercase hex digits", ErrInvalidValue, kind)
		}
	}
	return nil
}

// Instant is a UTC point in time truncated to microseconds, matching the
// storage representation so that round-trips do not change comparisons.
type Instant struct {
	micros int64
}

// NewInstant truncates to microseconds in UTC. A zero time.Time maps to the
// zero Instant rather than to year 1: every "must be set" check in this
// package is IsZero, and an adapter reading a NULL or unset timestamp column
// naturally reaches for this constructor. Without the mapping, such a value
// passes validation and stores a year-1 record.
//
// The zero Instant is micros == 0, so the Unix epoch is also treated as unset.
// A caller that genuinely means 1970-01-01T00:00:00Z uses InstantFromUnixMicro.
func NewInstant(t time.Time) Instant {
	if t.IsZero() {
		return Instant{}
	}
	return Instant{micros: t.UTC().UnixMicro()}
}

func InstantFromUnixMicro(micros int64) Instant { return Instant{micros: micros} }

func (i Instant) UnixMicro() int64 { return i.micros }

func (i Instant) Time() time.Time { return time.UnixMicro(i.micros).UTC() }

func (i Instant) IsZero() bool { return i.micros == 0 }

func (i Instant) Before(other Instant) bool { return i.micros < other.micros }

func (i Instant) After(other Instant) bool { return i.micros > other.micros }

func (i Instant) Equal(other Instant) bool { return i.micros == other.micros }

// Add returns the instant shifted by d, truncated to microseconds.
func (i Instant) Add(d Duration) Instant {
	return Instant{micros: i.micros + d.Microseconds()}
}

// Sub returns the duration from other to i.
func (i Instant) Sub(other Instant) Duration {
	return Duration{micros: i.micros - other.micros}
}

// IsExpiredAt applies the project-wide rule that now >= expiresAt is expired.
func (i Instant) IsExpiredAt(now Instant) bool { return !now.Before(i) }

func (i Instant) String() string { return i.Time().Format(time.RFC3339Nano) }

// Duration is a signed span stored in microseconds.
type Duration struct {
	micros int64
}

func NewDuration(d time.Duration) Duration {
	return Duration{micros: int64(d / time.Microsecond)}
}

func DurationFromMicros(micros int64) Duration { return Duration{micros: micros} }

// ParsePositiveDuration rejects zero and negative spans.
func ParsePositiveDuration(kind string, d time.Duration) (Duration, error) {
	if d <= 0 {
		return Duration{}, fmt.Errorf("%w: %s must be positive", ErrInvalidValue, kind)
	}
	return NewDuration(d), nil
}

func (d Duration) Microseconds() int64 { return d.micros }

func (d Duration) StdDuration() time.Duration { return time.Duration(d.micros) * time.Microsecond }

func (d Duration) IsZero() bool { return d.micros == 0 }

func (d Duration) IsPositive() bool { return d.micros > 0 }

func (d Duration) Compare(other Duration) int {
	switch {
	case d.micros < other.micros:
		return -1
	case d.micros > other.micros:
		return 1
	default:
		return 0
	}
}

func (d Duration) String() string { return d.StdDuration().String() }

// ValidityWindow is an immutable [NotBefore, NotAfter) certificate period.
type ValidityWindow struct {
	notBefore Instant
	notAfter  Instant
}

// NewValidityWindow requires notAfter strictly after notBefore, matching the
// storage CHECK constraint.
func NewValidityWindow(notBefore, notAfter Instant) (ValidityWindow, error) {
	if !notAfter.After(notBefore) {
		return ValidityWindow{}, fmt.Errorf("%w: not_after must be after not_before", ErrInvalidValue)
	}
	return ValidityWindow{notBefore: notBefore, notAfter: notAfter}, nil
}

func (w ValidityWindow) NotBefore() Instant { return w.notBefore }

func (w ValidityWindow) NotAfter() Instant { return w.notAfter }

func (w ValidityWindow) Duration() Duration { return w.notAfter.Sub(w.notBefore) }

// ContainsAt reports whether now falls inside the window. Expiry uses the
// project-wide now >= notAfter rule.
func (w ValidityWindow) ContainsAt(now Instant) bool {
	return !now.Before(w.notBefore) && now.Before(w.notAfter)
}

// Covers reports whether w fully contains inner, used for issuer period checks.
func (w ValidityWindow) Covers(inner ValidityWindow) bool {
	return !inner.notBefore.Before(w.notBefore) && !inner.notAfter.After(w.notAfter)
}

func (w ValidityWindow) IsZero() bool { return w.notBefore.IsZero() && w.notAfter.IsZero() }

// PublicKey is an immutable DER SubjectPublicKeyInfo with its algorithm label.
type PublicKey struct {
	algorithm KeyAlgorithm
	spki      []byte
}

// NewPublicKey copies the SPKI bytes so later mutation cannot change the value.
func NewPublicKey(algorithm KeyAlgorithm, spkiDER []byte) (PublicKey, error) {
	if err := algorithm.Validate(); err != nil {
		return PublicKey{}, err
	}
	if len(spkiDER) == 0 {
		return PublicKey{}, fmt.Errorf("%w: public key spki must not be empty", ErrInvalidValue)
	}
	return PublicKey{algorithm: algorithm, spki: cloneBytes(spkiDER)}, nil
}

func (k PublicKey) Algorithm() KeyAlgorithm { return k.algorithm }

// SPKIDER returns a copy; callers cannot mutate the stored value.
func (k PublicKey) SPKIDER() []byte { return cloneBytes(k.spki) }

// Fingerprint is the SHA-256 of the SPKI, used for same-public-key checks.
func (k PublicKey) Fingerprint() Fingerprint { return NewFingerprint(k.spki) }

func (k PublicKey) IsZero() bool { return len(k.spki) == 0 }

func (k PublicKey) Equal(other PublicKey) bool {
	return k.algorithm == other.algorithm && k.Fingerprint().Equal(other.Fingerprint())
}

// KeyAlgorithm names a supported key type. The permitted set is the one in
// the OpenAPI key_algorithm enum and docs/certificate-lifecycle.md: ECDSA
// P-256 and P-384 and RSA 2048, 3072 and 4096. Ed25519 and every other
// algorithm are outside the MVP issuance scope and are rejected here so that
// generation, import and request validation all apply the same list.
// Adapters map these to real curves and moduli; the domain only carries the
// choice.
type KeyAlgorithm string

const (
	KeyAlgorithmECDSAP256 KeyAlgorithm = "ecdsa_p256"
	KeyAlgorithmECDSAP384 KeyAlgorithm = "ecdsa_p384"
	KeyAlgorithmRSA2048   KeyAlgorithm = "rsa_2048"
	KeyAlgorithmRSA3072   KeyAlgorithm = "rsa_3072"
	KeyAlgorithmRSA4096   KeyAlgorithm = "rsa_4096"
)

// DefaultKeyAlgorithm is the product default for both CA and leaf keys.
const DefaultKeyAlgorithm = KeyAlgorithmECDSAP256

// DefaultCARSASize and DefaultLeafRSASize are the sizes applied when an
// operator picks RSA without naming one.
const (
	DefaultCARSAAlgorithm   = KeyAlgorithmRSA3072
	DefaultLeafRSAAlgorithm = KeyAlgorithmRSA2048
)

func (a KeyAlgorithm) Validate() error {
	switch a {
	case KeyAlgorithmECDSAP256, KeyAlgorithmECDSAP384, KeyAlgorithmRSA2048, KeyAlgorithmRSA3072, KeyAlgorithmRSA4096:
		return nil
	default:
		return fmt.Errorf("%w: unsupported key algorithm %q", ErrInvalidValue, string(a))
	}
}

func (a KeyAlgorithm) String() string { return string(a) }

// SecretPurpose scopes an encrypted secret to one use. Signing and delivery
// adapters check the purpose before decrypting.
type SecretPurpose string

const (
	SecretPurposeCASigning     SecretPurpose = "ca_signing"
	SecretPurposeBootstrapCA   SecretPurpose = "bootstrap_ca"
	SecretPurposeLeafDelivery  SecretPurpose = "leaf_delivery"
	SecretPurposeInternalTLS   SecretPurpose = "internal_tls"
	SecretPurposeStoreVerifier SecretPurpose = "store_verifier"
)

func (p SecretPurpose) Validate() error {
	switch p {
	case SecretPurposeCASigning, SecretPurposeBootstrapCA, SecretPurposeLeafDelivery,
		SecretPurposeInternalTLS, SecretPurposeStoreVerifier:
		return nil
	default:
		return fmt.Errorf("%w: unsupported secret purpose %q", ErrInvalidValue, string(p))
	}
}

func (p SecretPurpose) String() string { return string(p) }

// EncryptedSecret is stored ciphertext bound to its owner and purpose. The
// AAD check that rejects a ciphertext moved to another record lives in the
// crypto adapter; this value only carries the binding fields.
type EncryptedSecret struct {
	ownerKeyID             KeyMaterialID
	purpose                SecretPurpose
	formatVersion          int
	encryptionGenerationID string
	nonce                  []byte
	ciphertext             []byte
}

// EncryptedSecretFacts is the constructor input for an encrypted secret.
type EncryptedSecretFacts struct {
	OwnerKeyID             KeyMaterialID
	Purpose                SecretPurpose
	FormatVersion          int
	EncryptionGenerationID string
	Nonce                  []byte
	Ciphertext             []byte
}

// NewEncryptedSecret copies the byte slices it is given.
func NewEncryptedSecret(facts EncryptedSecretFacts) (EncryptedSecret, error) {
	if _, err := ParseKeyMaterialID(string(facts.OwnerKeyID)); err != nil {
		return EncryptedSecret{}, err
	}
	if err := facts.Purpose.Validate(); err != nil {
		return EncryptedSecret{}, err
	}
	if facts.FormatVersion <= 0 {
		return EncryptedSecret{}, fmt.Errorf("%w: encrypted secret format version must be positive", ErrInvalidValue)
	}
	if strings.TrimSpace(facts.EncryptionGenerationID) == "" {
		return EncryptedSecret{}, fmt.Errorf("%w: encryption generation id must not be empty", ErrInvalidValue)
	}
	if len(facts.Nonce) == 0 {
		return EncryptedSecret{}, fmt.Errorf("%w: encrypted secret nonce must not be empty", ErrInvalidValue)
	}
	if len(facts.Ciphertext) == 0 {
		return EncryptedSecret{}, fmt.Errorf("%w: encrypted secret ciphertext must not be empty", ErrInvalidValue)
	}
	return EncryptedSecret{
		ownerKeyID:             facts.OwnerKeyID,
		purpose:                facts.Purpose,
		formatVersion:          facts.FormatVersion,
		encryptionGenerationID: facts.EncryptionGenerationID,
		nonce:                  cloneBytes(facts.Nonce),
		ciphertext:             cloneBytes(facts.Ciphertext),
	}, nil
}

func (s EncryptedSecret) OwnerKeyID() KeyMaterialID { return s.ownerKeyID }

func (s EncryptedSecret) Purpose() SecretPurpose { return s.purpose }

func (s EncryptedSecret) FormatVersion() int { return s.formatVersion }

func (s EncryptedSecret) EncryptionGenerationID() string { return s.encryptionGenerationID }

func (s EncryptedSecret) Nonce() []byte { return cloneBytes(s.nonce) }

func (s EncryptedSecret) Ciphertext() []byte { return cloneBytes(s.ciphertext) }

func (s EncryptedSecret) IsZero() bool { return len(s.ciphertext) == 0 }

// String never renders ciphertext or nonce.
func (s EncryptedSecret) String() string {
	return fmt.Sprintf("EncryptedSecret{owner:%s purpose:%s}", string(s.ownerKeyID), string(s.purpose))
}

// TokenHash is the stored SHA-256 of a bearer token. Plaintext tokens never
// reach the domain.
type TokenHash struct {
	fingerprint Fingerprint
}

func NewTokenHash(digest Fingerprint) (TokenHash, error) {
	if digest.IsZero() {
		return TokenHash{}, fmt.Errorf("%w: token hash must not be empty", ErrInvalidValue)
	}
	return TokenHash{fingerprint: digest}, nil
}

func ParseTokenHash(raw string) (TokenHash, error) {
	digest, err := ParseFingerprint(raw)
	if err != nil {
		return TokenHash{}, err
	}
	return TokenHash{fingerprint: digest}, nil
}

func (h TokenHash) Hex() string { return h.fingerprint.Hex() }

func (h TokenHash) IsZero() bool { return h.fingerprint.IsZero() }

func (h TokenHash) Equal(other TokenHash) bool { return h.fingerprint.Equal(other.fingerprint) }

// String is redacted: a token hash is a credential lookup key.
func (h TokenHash) String() string { return "<token hash>" }

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// cloneStrings copies a string slice for immutable accessors.
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
