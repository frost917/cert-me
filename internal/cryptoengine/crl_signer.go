package cryptoengine

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sort"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/cryptowork"
	"cert-me/internal/domain"
)

// CRLSigner decrypts one CA key only for the signing call and validates the
// resulting DER against the reserved CRL snapshot before returning it.
type CRLSigner struct {
	ring *KeyRing
}

var _ port.CRLSigner = (*CRLSigner)(nil)

func NewCRLSigner(ring *KeyRing) (*CRLSigner, error) {
	if ring == nil {
		return nil, errors.New("cryptoengine: key ring is required")
	}
	if err := ring.withActiveKey(func(string, []byte) error { return nil }); err != nil {
		return nil, err
	}
	return &CRLSigner{ring: ring}, nil
}

func (s *CRLSigner) SignCRL(ctx context.Context, snapshot port.CRLSnapshot, encrypted domain.EncryptedSecret) (port.SignedCRL, error) {
	if err := checkContext(ctx); err != nil {
		return port.SignedCRL{}, err
	}
	issuer, err := validateCRLIssuer(snapshot, encrypted)
	if err != nil {
		return port.SignedCRL{}, err
	}
	if err := validateCRLSnapshot(snapshot); err != nil {
		return port.SignedCRL{}, err
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return port.SignedCRL{}, err
	}
	defer release()

	privateDER, err := decryptCRLKey(s.ring, encrypted)
	if err != nil {
		return port.SignedCRL{}, err
	}
	defer zero(privateDER)
	privateKey, err := parsePrivateKey(privateDER)
	if err != nil {
		return port.SignedCRL{}, errors.New("cryptoengine: CA signing key is invalid")
	}
	defer clearPrivateKey(privateKey)
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return port.SignedCRL{}, errors.New("cryptoengine: CA signing key cannot sign CRLs")
	}
	publicKey, err := publicKeyFor(privateKey, issuer.KeyAlgorithm())
	if err != nil || !publicKey.Equal(publicKeyFromCertificate(issuer)) {
		return port.SignedCRL{}, errors.New("cryptoengine: CA signing key does not match the CRL issuer certificate")
	}

	entries, err := revokedEntries(snapshot)
	if err != nil {
		return port.SignedCRL{}, err
	}
	list := &x509.RevocationList{
		Number:                    snapshot.Number.Big(),
		ThisUpdate:                snapshot.ThisUpdate.Time(),
		NextUpdate:                snapshot.NextUpdate.Time(),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, issuerCertificate(issuer), signer)
	if err != nil {
		return port.SignedCRL{}, errors.New("cryptoengine: CRL creation failed")
	}
	if err := checkContext(ctx); err != nil {
		zero(der)
		return port.SignedCRL{}, err
	}
	if err := verifyGeneratedCRL(der, snapshot, issuer, entries); err != nil {
		zero(der)
		return port.SignedCRL{}, err
	}
	digest := domain.NewFingerprint(der)
	return port.SignedCRL{DER: der, DERSHA256: digest}, nil
}

func validateCRLIssuer(snapshot port.CRLSnapshot, encrypted domain.EncryptedSecret) (domain.Certificate, error) {
	if _, err := domain.ParseCAKeyGenerationID(string(snapshot.CAKeyGenerationID)); err != nil {
		return domain.Certificate{}, errors.New("cryptoengine: CRL key generation id is invalid")
	}
	if _, err := domain.ParseKeyMaterialID(string(snapshot.CAKeyMaterialID)); err != nil {
		return domain.Certificate{}, errors.New("cryptoengine: CRL key material id is invalid")
	}
	if encrypted.IsZero() || encrypted.OwnerKeyID() != snapshot.CAKeyMaterialID ||
		(snapshotPurpose(encrypted.Purpose()) == false) ||
		encrypted.FormatVersion() != secretFormatVersion {
		return domain.Certificate{}, errors.New("cryptoengine: encrypted CRL key metadata is invalid")
	}
	issuer := snapshot.IssuerCertificate
	if issuer.ID() == "" || issuer.Kind() != domain.CertificateKindCA ||
		issuer.KeyMaterialID() != snapshot.CAKeyMaterialID || issuer.KeyAlgorithm().Validate() != nil {
		return domain.Certificate{}, errors.New("cryptoengine: CRL issuer certificate does not match the CA key generation")
	}
	return issuer, nil
}

func snapshotPurpose(purpose domain.SecretPurpose) bool {
	return purpose == domain.SecretPurposeCASigning || purpose == domain.SecretPurposeBootstrapCA
}

func validateCRLSnapshot(snapshot port.CRLSnapshot) error {
	if snapshot.Number.IsZero() || snapshot.ThisUpdate.IsZero() || snapshot.NextUpdate.IsZero() ||
		!snapshot.NextUpdate.After(snapshot.ThisUpdate) || snapshot.CoveredGeneration < 0 {
		return errors.New("cryptoengine: CRL snapshot number or time range is invalid")
	}
	if !isWholeSecond(snapshot.ThisUpdate) || !isWholeSecond(snapshot.NextUpdate) {
		return errors.New("cryptoengine: CRL snapshot times must have whole-second precision")
	}
	if snapshot.IssuerCertificate.Validity().IsZero() ||
		snapshot.ThisUpdate.Before(snapshot.IssuerCertificate.Validity().NotBefore()) ||
		!snapshot.ThisUpdate.Before(snapshot.IssuerCertificate.Validity().NotAfter()) {
		return errors.New("cryptoengine: CRL issuer certificate is not valid at thisUpdate")
	}
	return nil
}

func decryptCRLKey(ring *KeyRing, encrypted domain.EncryptedSecret) ([]byte, error) {
	nonce := encrypted.Nonce()
	ciphertext := encrypted.Ciphertext()
	defer zero(nonce)
	defer zero(ciphertext)
	if len(nonce) != secretNonceSize {
		return nil, errors.New("cryptoengine: encrypted CRL key nonce is invalid")
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
		return nil, errors.New("cryptoengine: encrypted CRL key could not be authenticated")
	}
	return plaintext, nil
}

func revokedEntries(snapshot port.CRLSnapshot) ([]x509.RevocationListEntry, error) {
	revocations := append([]domain.Revocation(nil), snapshot.Revoked...)
	sort.Slice(revocations, func(i, j int) bool { return revocations[i].Serial().Compare(revocations[j].Serial()) < 0 })
	entries := make([]x509.RevocationListEntry, 0, len(revocations))
	var previous domain.SerialNumber
	for i, revocation := range revocations {
		if revocation.IssuerID() != snapshot.CAKeyGenerationID || revocation.Serial().IsZero() ||
			revocation.RevokedAt().IsZero() || revocation.ChangeGeneration() > snapshot.CoveredGeneration ||
			revocation.Reason().Validate() != nil {
			return nil, errors.New("cryptoengine: revocation does not belong to the reserved CRL snapshot")
		}
		if i > 0 && previous.Equal(revocation.Serial()) {
			return nil, errors.New("cryptoengine: CRL snapshot contains duplicate serial numbers")
		}
		reason, ok := crlReasonCode(revocation.Reason())
		if !ok {
			return nil, errors.New("cryptoengine: revocation reason is unsupported in a CRL")
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   revocation.Serial().Big(),
			RevocationTime: x509TimeCeil(revocation.RevokedAt()),
			ReasonCode:     reason,
		})
		previous = revocation.Serial()
	}
	return entries, nil
}

func crlReasonCode(reason domain.RevocationReason) (int, bool) {
	switch reason {
	case domain.RevocationReasonUnspecified:
		return 0, true
	case domain.RevocationReasonKeyCompromise:
		return 1, true
	case domain.RevocationReasonCACompromise:
		return 2, true
	case domain.RevocationReasonAffiliationChanged:
		return 3, true
	case domain.RevocationReasonSuperseded:
		return 4, true
	case domain.RevocationReasonCessationOfOperation:
		return 5, true
	case domain.RevocationReasonPrivilegeWithdrawn:
		return 9, true
	case domain.RevocationReasonAACompromise:
		return 10, true
	default:
		return 0, false
	}
}

func verifyGeneratedCRL(der []byte, snapshot port.CRLSnapshot, issuer domain.Certificate, expected []x509.RevocationListEntry) error {
	parsed, err := x509.ParseRevocationList(der)
	if err != nil || !bytes.Equal(parsed.Raw, der) {
		return errors.New("cryptoengine: generated CRL DER is invalid")
	}
	issuerX509, err := x509.ParseCertificate(issuer.DER())
	if err != nil || parsed.CheckSignatureFrom(issuerX509) != nil {
		return errors.New("cryptoengine: generated CRL signature is invalid")
	}
	if parsed.Number == nil || parsed.Number.Cmp(snapshot.Number.Big()) != 0 ||
		!parsed.ThisUpdate.Equal(snapshot.ThisUpdate.Time()) || !parsed.NextUpdate.Equal(snapshot.NextUpdate.Time()) ||
		!bytes.Equal(parsed.RawIssuer, issuerX509.RawSubject) || len(parsed.RevokedCertificateEntries) != len(expected) {
		return errors.New("cryptoengine: generated CRL does not match the reserved snapshot")
	}
	for i, entry := range parsed.RevokedCertificateEntries {
		want := expected[i]
		if entry.SerialNumber == nil || entry.SerialNumber.Cmp(want.SerialNumber) != 0 ||
			!entry.RevocationTime.Equal(want.RevocationTime) || entry.ReasonCode != want.ReasonCode {
			return errors.New("cryptoengine: generated CRL entries do not match the reserved snapshot")
		}
	}
	return nil
}

func publicKeyFromCertificate(certificate domain.Certificate) domain.PublicKey {
	parsed, err := x509.ParseCertificate(certificate.DER())
	if err != nil {
		return domain.PublicKey{}
	}
	spki, err := x509.MarshalPKIXPublicKey(parsed.PublicKey)
	if err != nil {
		return domain.PublicKey{}
	}
	defer zero(spki)
	key, err := domain.NewPublicKey(certificate.KeyAlgorithm(), spki)
	if err != nil {
		return domain.PublicKey{}
	}
	return key
}

func issuerCertificate(certificate domain.Certificate) *x509.Certificate {
	parsed, _ := x509.ParseCertificate(certificate.DER())
	return parsed
}

func isWholeSecond(value domain.Instant) bool {
	return value.Time().Nanosecond() == 0 && value.UnixMicro()%int64(time.Second/time.Microsecond) == 0
}

func x509TimeCeil(value domain.Instant) time.Time {
	timestamp := value.Time()
	rounded := timestamp.Truncate(time.Second)
	if rounded.Before(timestamp) {
		rounded = rounded.Add(time.Second)
	}
	return rounded
}
