package cryptoengine

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

var (
	certificateSANExtensionOID = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// CertificateSigner creates X.509 certificates from the fully specified
// application request. It shares the configured key ring with KeyEngine,
// but never retains a decrypted signing key between calls.
type CertificateSigner struct {
	ring *KeyRing
}

var _ port.CertificateSigner = (*CertificateSigner)(nil)

// NewCertificateSigner binds the signer to an open key ring.
func NewCertificateSigner(ring *KeyRing) (*CertificateSigner, error) {
	if ring == nil {
		return nil, errors.New("cryptoengine: key ring is required")
	}
	if err := ring.withActiveKey(func(string, []byte) error { return nil }); err != nil {
		return nil, err
	}
	return &CertificateSigner{ring: ring}, nil
}

// Sign decrypts the selected CA key only for this invocation, builds the
// requested certificate, parses the resulting DER, and returns a domain
// value made from those parsed facts. Any request/DER discrepancy is an
// error; request metadata is never used to paper over a different DER value.
func (s *CertificateSigner) Sign(ctx context.Context, request port.CertificateSigningRequest, caKey domain.EncryptedSecret) (domain.Certificate, error) {
	if err := checkContext(ctx); err != nil {
		return domain.Certificate{}, err
	}
	if s == nil || s.ring == nil {
		return domain.Certificate{}, errors.New("cryptoengine: certificate signer is unavailable")
	}
	issuer, selfSigned, err := validateCertificateSigningRequest(request)
	if err != nil {
		return domain.Certificate{}, err
	}

	expectedOwner := request.KeyMaterialID
	if !selfSigned {
		expectedOwner = request.IssuerCertificate.KeyMaterialID()
	}
	if err := validateSigningSecret(caKey, expectedOwner); err != nil {
		return domain.Certificate{}, err
	}

	nonce := caKey.Nonce()
	ciphertext := caKey.Ciphertext()
	defer zero(nonce)
	defer zero(ciphertext)

	var result domain.Certificate
	err = s.ring.withGenerationKeys(caKey.EncryptionGenerationID(), caKey.EncryptionGenerationID(), func(generationKey, _ []byte) error {
		plaintext, err := openSecret(generationKey, caKey.OwnerKeyID(), caKey.Purpose(), caKey.FormatVersion(),
			caKey.EncryptionGenerationID(), nonce, ciphertext)
		if err != nil {
			return err
		}
		defer zero(plaintext)

		privateKey, err := parsePrivateKey(plaintext)
		if err != nil {
			return errors.New("cryptoengine: CA signing key is invalid")
		}
		defer clearSigningKey(privateKey)

		signer, ok := privateKey.(crypto.Signer)
		if !ok {
			return errors.New("cryptoengine: CA signing key cannot sign certificates")
		}
		keyAlgorithm, _ := algorithmAndPublic(privateKey)
		if keyAlgorithm == "" {
			return errors.New("cryptoengine: CA signing key algorithm is unsupported")
		}

		if selfSigned {
			publicKey, err := publicKeyFor(privateKey, request.Plan.KeyAlgorithm)
			if err != nil || !publicKey.Equal(request.SubjectPublicKey) {
				return errors.New("cryptoengine: self-signed CA key does not match the requested public key")
			}
		} else {
			issuerPublicKey, err := domainPublicKey(issuer)
			if err != nil {
				return errors.New("cryptoengine: issuer certificate public key is invalid")
			}
			caPublicKey, err := publicKeyFor(privateKey, keyAlgorithm)
			if err != nil || !caPublicKey.Equal(issuerPublicKey) {
				return errors.New("cryptoengine: CA signing key does not match issuer certificate")
			}
		}

		der, err := createRequestedCertificate(request, issuer, selfSigned, signer, keyAlgorithm)
		if err != nil {
			return err
		}
		defer zero(der)

		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return errors.New("cryptoengine: generated certificate could not be parsed")
		}
		facts, err := certificateFactsFromDER(request, parsed, issuer, selfSigned, keyAlgorithm)
		if err != nil {
			return err
		}
		result, err = domain.NewCertificate(facts)
		if err != nil {
			return fmt.Errorf("cryptoengine: generated certificate facts are invalid: %w", err)
		}
		return nil
	})
	if err != nil {
		return domain.Certificate{}, err
	}
	if err := checkContext(ctx); err != nil {
		return domain.Certificate{}, err
	}
	return result, nil
}

func clearSigningKey(private any) {
	switch key := private.(type) {
	case ed25519.PrivateKey:
		zero(key)
	default:
		clearPrivateKey(private)
	}
}

func validateCertificateSigningRequest(request port.CertificateSigningRequest) (*x509.Certificate, bool, error) {
	if _, err := domain.ParseCertificateID(string(request.CertificateID)); err != nil {
		return nil, false, errors.New("cryptoengine: certificate id is invalid")
	}
	if _, err := domain.ParseKeyMaterialID(string(request.KeyMaterialID)); err != nil {
		return nil, false, errors.New("cryptoengine: key material id is invalid")
	}
	if _, err := domain.ParseAuthorityID(string(request.Plan.IssuerAuthorityID)); err != nil {
		return nil, false, errors.New("cryptoengine: issuer authority id is invalid")
	}
	if _, err := domain.ParseCAKeyGenerationID(string(request.Plan.IssuerKeyGenerationID)); err != nil {
		return nil, false, errors.New("cryptoengine: issuer key generation id is invalid")
	}
	if request.CreatedByAccountID != "" {
		if _, err := domain.ParseAccountID(string(request.CreatedByAccountID)); err != nil {
			return nil, false, errors.New("cryptoengine: creator account id is invalid")
		}
	}
	if request.Serial.IsZero() || request.Serial.Big().Sign() <= 0 || request.Serial.Big().BitLen() > 159 {
		return nil, false, errors.New("cryptoengine: certificate serial is invalid")
	}
	if err := request.Plan.KeyAlgorithm.Validate(); err != nil {
		return nil, false, errors.New("cryptoengine: subject key algorithm is unsupported")
	}
	if request.SubjectPublicKey.IsZero() || request.SubjectPublicKey.Algorithm() != request.Plan.KeyAlgorithm {
		return nil, false, errors.New("cryptoengine: subject public key does not match the issuance algorithm")
	}
	if _, err := parseDomainPublicKey(request.SubjectPublicKey); err != nil {
		return nil, false, errors.New("cryptoengine: subject public key is invalid")
	}
	if request.Plan.Subject.CommonName() == "" || request.Plan.Window.IsZero() {
		return nil, false, errors.New("cryptoengine: certificate subject and validity window are required")
	}
	if !wholeSecond(request.Plan.Window.NotBefore().Time()) || !wholeSecond(request.Plan.Window.NotAfter().Time()) {
		return nil, false, errors.New("cryptoengine: X.509 validity bounds must have whole-second precision")
	}
	if !request.Plan.Window.NotAfter().After(request.Plan.Window.NotBefore()) {
		return nil, false, errors.New("cryptoengine: certificate validity window is invalid")
	}
	if err := request.Kind.Validate(); err != nil {
		return nil, false, errors.New("cryptoengine: certificate kind is unsupported")
	}

	if request.Kind == domain.CertificateKindCA {
		if request.Plan.Profile != "" || len(request.Plan.SANs) != 0 {
			return nil, false, errors.New("cryptoengine: CA certificate must not carry a leaf profile or SANs")
		}
	} else {
		if err := domain.ValidateSANsForProfile(request.Plan.Profile, request.Plan.SANs); err != nil {
			return nil, false, errors.New("cryptoengine: leaf profile or SANs are invalid")
		}
	}
	for _, san := range request.Plan.SANs {
		if _, err := sanRawValue(san); err != nil {
			return nil, false, err
		}
	}
	for _, point := range request.CRLDistributionPoints {
		if err := validateCRLDistributionPoint(point); err != nil {
			return nil, false, err
		}
	}

	selfSigned := request.SelfSigned()
	if selfSigned {
		if request.Kind != domain.CertificateKindCA || len(request.CRLDistributionPoints) != 0 {
			return nil, false, errors.New("cryptoengine: only a CA Root may be self-signed")
		}
		return nil, true, nil
	}
	issuer, err := validateIssuerCertificate(request.IssuerCertificate)
	if err != nil {
		return nil, false, err
	}
	if !issuer.BasicConstraintsValid || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 || issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, false, errors.New("cryptoengine: issuer certificate is not a usable CA")
	}
	if issuer.NotBefore.After(request.Plan.Window.NotBefore().Time()) || issuer.NotAfter.Before(request.Plan.Window.NotAfter().Time()) {
		return nil, false, errors.New("cryptoengine: issuer certificate does not cover the requested validity window")
	}
	return issuer, false, nil
}

func validateSigningSecret(secret domain.EncryptedSecret, expectedOwner domain.KeyMaterialID) error {
	if secret.IsZero() || secret.OwnerKeyID() != expectedOwner {
		return errors.New("cryptoengine: CA signing secret owner does not match the request")
	}
	if secret.Purpose() != domain.SecretPurposeCASigning && secret.Purpose() != domain.SecretPurposeBootstrapCA {
		return errors.New("cryptoengine: secret purpose is not allowed for CA signing")
	}
	if secret.FormatVersion() != secretFormatVersion || !validGenerationID(secret.EncryptionGenerationID()) {
		return errors.New("cryptoengine: CA signing secret metadata is unsupported")
	}
	if err := validateOwnerPurpose(secret.OwnerKeyID(), secret.Purpose()); err != nil {
		return err
	}
	nonce := secret.Nonce()
	validNonce := len(nonce) == secretNonceSize
	zero(nonce)
	if !validNonce {
		return errors.New("cryptoengine: CA signing secret nonce is invalid")
	}
	return nil
}

func validateIssuerCertificate(certificate domain.Certificate) (*x509.Certificate, error) {
	if certificate.ID() == "" || certificate.Kind() != domain.CertificateKindCA || certificate.KeyMaterialID() == "" {
		return nil, errors.New("cryptoengine: issuer certificate facts are incomplete")
	}
	parsed, err := x509.ParseCertificate(certificate.DER())
	if err != nil {
		return nil, errors.New("cryptoengine: issuer certificate DER is invalid")
	}
	if !parsed.BasicConstraintsValid || !parsed.IsCA {
		return nil, errors.New("cryptoengine: issuer certificate DER is not a CA")
	}
	serial, err := domain.NewSerialNumberFromBig(parsed.SerialNumber)
	if err != nil || !serial.Equal(certificate.Serial()) {
		return nil, errors.New("cryptoengine: issuer certificate serial does not match its DER")
	}
	window, err := parsedValidity(parsed)
	if err != nil || !sameCertificateWindow(window, certificate.Validity()) {
		return nil, errors.New("cryptoengine: issuer certificate validity does not match its DER")
	}
	subject, err := domainSubject(parsed.Subject)
	if err != nil || !sameCertificateSubject(subject, certificate.Subject()) {
		return nil, errors.New("cryptoengine: issuer certificate subject does not match its DER")
	}
	algorithm, err := publicKeyAlgorithm(parsed.PublicKey)
	if err != nil || algorithm != certificate.KeyAlgorithm() {
		return nil, errors.New("cryptoengine: issuer certificate key algorithm does not match its DER")
	}
	if len(parsed.UnhandledCriticalExtensions) != 0 {
		return nil, errors.New("cryptoengine: issuer certificate has an unsupported critical extension")
	}
	return parsed, nil
}

func createRequestedCertificate(
	request port.CertificateSigningRequest,
	issuer *x509.Certificate,
	selfSigned bool,
	signer crypto.Signer,
	issuerAlgorithm domain.KeyAlgorithm,
) ([]byte, error) {
	subjectKey, err := parseDomainPublicKey(request.SubjectPublicKey)
	if err != nil {
		return nil, err
	}
	if selfSigned {
		issuer = &x509.Certificate{
			Subject:               toPKIXName(request.Plan.Subject),
			PublicKey:             subjectKey,
			SubjectKeyId:          nil,
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
	}

	keyUsage, extendedKeyUsage, isCA, maxPathLen, maxPathLenZero, err := requestedUsages(request)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          request.Serial.Big(),
		Subject:               toPKIXName(request.Plan.Subject),
		NotBefore:             request.Plan.Window.NotBefore().Time(),
		NotAfter:              request.Plan.Window.NotAfter().Time(),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extendedKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLenZero,
		CRLDistributionPoints: append([]string(nil), request.CRLDistributionPoints...),
		SignatureAlgorithm:    certificateSignatureAlgorithm(issuerAlgorithm),
	}
	if isCA {
		template.MaxPathLen = maxPathLen
		template.MaxPathLenZero = maxPathLenZero
	}
	if len(request.Plan.SANs) != 0 {
		value, err := marshalOrderedSANs(request.Plan.SANs)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = []pkix.Extension{{
			Id:    certificateSANExtensionOID,
			Value: value,
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, subjectKey, signer)
	if err != nil {
		return nil, fmt.Errorf("cryptoengine: X.509 certificate creation failed: %w", err)
	}
	return der, nil
}

func requestedUsages(request port.CertificateSigningRequest) (x509.KeyUsage, []x509.ExtKeyUsage, bool, int, bool, error) {
	if request.Kind == domain.CertificateKindCA {
		// The fixed Root -> Intermediate -> Leaf topology bounds the Root to
		// one subordinate CA level and the Intermediate to none.
		if request.SelfSigned() {
			return x509.KeyUsageCertSign | x509.KeyUsageCRLSign, nil, true, 1, false, nil
		}
		return x509.KeyUsageCertSign | x509.KeyUsageCRLSign, nil, true, 0, true, nil
	}
	// Profile policy uses digital signatures for all leaf uses. RSA server
	// profiles also permit key encipherment for older TLS handshakes; client
	// authentication does not use key encipherment.
	usage := x509.KeyUsageDigitalSignature
	if request.Plan.KeyAlgorithm == domain.KeyAlgorithmRSA2048 || request.Plan.KeyAlgorithm == domain.KeyAlgorithmRSA3072 || request.Plan.KeyAlgorithm == domain.KeyAlgorithmRSA4096 {
		if request.Plan.Profile == domain.CertificateProfileServerTLS || request.Plan.Profile == domain.CertificateProfileDual {
			usage |= x509.KeyUsageKeyEncipherment
		}
	}
	switch request.Plan.Profile {
	case domain.CertificateProfileServerTLS:
		return usage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false, -1, false, nil
	case domain.CertificateProfileClientMTLS:
		return usage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false, -1, false, nil
	case domain.CertificateProfileDual:
		return usage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, false, -1, false, nil
	default:
		return 0, nil, false, 0, false, errors.New("cryptoengine: leaf profile is unsupported")
	}
}

func certificateSignatureAlgorithm(algorithm domain.KeyAlgorithm) x509.SignatureAlgorithm {
	switch algorithm {
	case domain.KeyAlgorithmECDSAP256:
		return x509.ECDSAWithSHA256
	case domain.KeyAlgorithmECDSAP384:
		return x509.ECDSAWithSHA384
	case domain.KeyAlgorithmRSA2048, domain.KeyAlgorithmRSA3072, domain.KeyAlgorithmRSA4096:
		return x509.SHA256WithRSA
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

func certificateFactsFromDER(
	request port.CertificateSigningRequest,
	parsed *x509.Certificate,
	issuer *x509.Certificate,
	selfSigned bool,
	issuerAlgorithm domain.KeyAlgorithm,
) (domain.CertificateFacts, error) {
	if parsed == nil {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate is missing")
	}
	serial, err := domain.NewSerialNumberFromBig(parsed.SerialNumber)
	if err != nil || !serial.Equal(request.Serial) {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate serial does not match the request")
	}
	window, err := parsedValidity(parsed)
	if err != nil || !sameCertificateWindow(window, request.Plan.Window) {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate validity does not match the request")
	}
	subject, err := domainSubject(parsed.Subject)
	if err != nil || !sameCertificateSubject(subject, request.Plan.Subject) {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate subject does not match the request")
	}
	algorithm, err := publicKeyAlgorithm(parsed.PublicKey)
	if err != nil || algorithm != request.Plan.KeyAlgorithm {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate public key algorithm does not match the request")
	}
	spki, err := x509.MarshalPKIXPublicKey(parsed.PublicKey)
	if err != nil {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate public key could not be encoded")
	}
	actualPublic, err := domain.NewPublicKey(algorithm, spki)
	zero(spki)
	if err != nil || !actualPublic.Equal(request.SubjectPublicKey) {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate public key does not match the request")
	}
	sans, err := orderedSANsFromDER(parsed)
	if err != nil || !sameCertificateSANs(sans, request.Plan.SANs) {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate SANs do not match the request")
	}
	if !sameStrings(parsed.CRLDistributionPoints, request.CRLDistributionPoints) {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate CRL distribution points do not match the request")
	}
	if err := verifyRequestedCertificateExtensions(parsed, request); err != nil {
		return domain.CertificateFacts{}, err
	}
	if len(parsed.UnhandledCriticalExtensions) != 0 {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate has an unsupported critical extension")
	}
	if selfSigned {
		if !bytes.Equal(parsed.RawSubject, parsed.RawIssuer) || parsed.CheckSignatureFrom(parsed) != nil {
			return domain.CertificateFacts{}, errors.New("cryptoengine: generated Root is not self-signed")
		}
	} else {
		if !bytes.Equal(parsed.RawIssuer, issuer.RawSubject) || parsed.CheckSignatureFrom(issuer) != nil {
			return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate signature or issuer does not match the request")
		}
	}
	if parsed.SignatureAlgorithm != certificateSignatureAlgorithm(issuerAlgorithm) {
		return domain.CertificateFacts{}, errors.New("cryptoengine: generated certificate signature algorithm does not match the signing key")
	}

	return domain.CertificateFacts{
		ID:                      request.CertificateID,
		DER:                     parsed.Raw,
		KeyMaterialID:           request.KeyMaterialID,
		IssuerCAKeyGenerationID: request.Plan.IssuerKeyGenerationID,
		Serial:                  serial,
		Validity:                window,
		Subject:                 subject,
		SANs:                    sans,
		Kind:                    request.Kind,
		Profile:                 request.Plan.Profile,
		KeyAlgorithm:            algorithm,
		Origin:                  domain.CertificateOriginGenerated,
		CreatedByAccountID:      request.CreatedByAccountID,
		Version:                 0,
	}, nil
}

func verifyRequestedCertificateExtensions(parsed *x509.Certificate, request port.CertificateSigningRequest) error {
	expectedKeyUsage, expectedEKU, expectedCA, expectedPathLen, expectedPathLenZero, err := requestedUsages(request)
	if err != nil {
		return err
	}
	if parsed.IsCA != expectedCA || !parsed.BasicConstraintsValid || parsed.KeyUsage != expectedKeyUsage {
		return errors.New("cryptoengine: generated certificate constraints or key usage do not match the request")
	}
	if parsed.MaxPathLen != expectedPathLen || parsed.MaxPathLenZero != expectedPathLenZero {
		return errors.New("cryptoengine: generated certificate path length does not match the request")
	}
	if len(parsed.ExtKeyUsage) != len(expectedEKU) {
		return errors.New("cryptoengine: generated certificate extended key usage does not match the request")
	}
	for i := range expectedEKU {
		if parsed.ExtKeyUsage[i] != expectedEKU[i] {
			return errors.New("cryptoengine: generated certificate extended key usage does not match the request")
		}
	}
	return nil
}

func parseDomainPublicKey(key domain.PublicKey) (any, error) {
	spki := key.SPKIDER()
	defer zero(spki)
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("cryptoengine: public key SPKI is invalid")
	}
	algorithm, err := publicKeyAlgorithm(parsed)
	if err != nil || algorithm != key.Algorithm() {
		return nil, errors.New("cryptoengine: public key algorithm does not match its SPKI")
	}
	canonical, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil {
		return nil, errors.New("cryptoengine: public key SPKI could not be encoded")
	}
	defer zero(canonical)
	if !bytes.Equal(canonical, spki) {
		return nil, errors.New("cryptoengine: public key SPKI is not canonical")
	}
	return parsed, nil
}

func domainPublicKey(certificate *x509.Certificate) (domain.PublicKey, error) {
	if certificate == nil {
		return domain.PublicKey{}, errors.New("cryptoengine: certificate is missing")
	}
	algorithm, err := publicKeyAlgorithm(certificate.PublicKey)
	if err != nil {
		return domain.PublicKey{}, err
	}
	return domain.NewPublicKey(algorithm, certificate.RawSubjectPublicKeyInfo)
}

func publicKeyAlgorithm(public any) (domain.KeyAlgorithm, error) {
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
			return "", errors.New("cryptoengine: ECDSA public key is invalid")
		}
		switch key.Curve {
		case elliptic.P256():
			return domain.KeyAlgorithmECDSAP256, nil
		case elliptic.P384():
			return domain.KeyAlgorithmECDSAP384, nil
		default:
			return "", errors.New("cryptoengine: ECDSA curve is unsupported")
		}
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.E < 3 || key.E%2 == 0 {
			return "", errors.New("cryptoengine: RSA public key is invalid")
		}
		switch key.N.BitLen() {
		case 2048:
			return domain.KeyAlgorithmRSA2048, nil
		case 3072:
			return domain.KeyAlgorithmRSA3072, nil
		case 4096:
			return domain.KeyAlgorithmRSA4096, nil
		default:
			return "", errors.New("cryptoengine: RSA modulus size is unsupported")
		}
	default:
		return "", errors.New("cryptoengine: public key algorithm is unsupported")
	}
}

func toPKIXName(subject domain.Subject) pkix.Name {
	name := pkix.Name{CommonName: subject.CommonName()}
	if subject.Organization() != "" {
		name.Organization = []string{subject.Organization()}
	}
	if subject.OrganizationalUnit() != "" {
		name.OrganizationalUnit = []string{subject.OrganizationalUnit()}
	}
	if subject.Country() != "" {
		name.Country = []string{subject.Country()}
	}
	return name
}

func domainSubject(name pkix.Name) (domain.Subject, error) {
	if len(name.Organization) > 1 || len(name.OrganizationalUnit) > 1 || len(name.Country) > 1 {
		return domain.Subject{}, errors.New("cryptoengine: certificate subject has unsupported repeated attributes")
	}
	var organization, organizationalUnit, country string
	if len(name.Organization) == 1 {
		organization = name.Organization[0]
	}
	if len(name.OrganizationalUnit) == 1 {
		organizationalUnit = name.OrganizationalUnit[0]
	}
	if len(name.Country) == 1 {
		country = name.Country[0]
	}
	return domain.NewSubject(domain.SubjectFacts{
		CommonName:         name.CommonName,
		Organization:       organization,
		OrganizationalUnit: organizationalUnit,
		Country:            country,
	})
}

func sanRawValue(san domain.SAN) (asn1.RawValue, error) {
	switch san.Type() {
	case domain.SANTypeDNS:
		if !ia5String(san.Value()) {
			return asn1.RawValue{}, errors.New("cryptoengine: DNS SAN is not an IA5 string")
		}
		return asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(san.Value())}, nil
	case domain.SANTypeURI:
		if !ia5String(san.Value()) {
			return asn1.RawValue{}, errors.New("cryptoengine: URI SAN is not an IA5 string")
		}
		return asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(san.Value())}, nil
	case domain.SANTypeIP:
		address, err := netip.ParseAddr(san.Value())
		if err != nil || address.Zone() != "" {
			return asn1.RawValue{}, errors.New("cryptoengine: IP SAN is invalid")
		}
		return asn1.RawValue{Class: 2, Tag: 7, Bytes: address.AsSlice()}, nil
	default:
		return asn1.RawValue{}, errors.New("cryptoengine: SAN type is unsupported")
	}
}

func marshalOrderedSANs(sans []domain.SAN) ([]byte, error) {
	names := make([]asn1.RawValue, 0, len(sans))
	for _, san := range sans {
		value, err := sanRawValue(san)
		if err != nil {
			return nil, err
		}
		names = append(names, value)
	}
	der, err := asn1.Marshal(names)
	if err != nil {
		return nil, errors.New("cryptoengine: SAN extension encoding failed")
	}
	return der, nil
}

func orderedSANsFromDER(certificate *x509.Certificate) ([]domain.SAN, error) {
	var extension *pkix.Extension
	for i := range certificate.Extensions {
		if certificate.Extensions[i].Id.Equal(certificateSANExtensionOID) {
			if extension != nil {
				return nil, errors.New("cryptoengine: certificate has duplicate SAN extensions")
			}
			extension = &certificate.Extensions[i]
		}
	}
	if extension == nil {
		return nil, nil
	}
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(extension.Value, &names)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("cryptoengine: certificate SAN extension is malformed")
	}
	sans := make([]domain.SAN, 0, len(names))
	for _, name := range names {
		var kind domain.SANType
		var value string
		switch {
		case name.Class == 2 && name.Tag == 2:
			kind = domain.SANTypeDNS
			value = string(name.Bytes)
		case name.Class == 2 && name.Tag == 6:
			kind = domain.SANTypeURI
			value = string(name.Bytes)
		case name.Class == 2 && name.Tag == 7:
			kind = domain.SANTypeIP
			address, ok := netip.AddrFromSlice(name.Bytes)
			if !ok {
				return nil, errors.New("cryptoengine: certificate IP SAN is malformed")
			}
			value = address.String()
		default:
			return nil, errors.New("cryptoengine: certificate contains an unsupported SAN type")
		}
		san, err := domain.NewSAN(kind, value)
		if err != nil || san.Value() != value {
			return nil, errors.New("cryptoengine: certificate SAN is invalid or non-canonical")
		}
		sans = append(sans, san)
	}
	return sans, nil
}

func parsedValidity(certificate *x509.Certificate) (domain.ValidityWindow, error) {
	window, err := domain.NewValidityWindow(domain.NewInstant(certificate.NotBefore), domain.NewInstant(certificate.NotAfter))
	if err != nil {
		return domain.ValidityWindow{}, err
	}
	return window, nil
}

func sameCertificateWindow(a, b domain.ValidityWindow) bool {
	return a.NotBefore().Equal(b.NotBefore()) && a.NotAfter().Equal(b.NotAfter())
}

func sameCertificateSubject(a, b domain.Subject) bool {
	return a.CommonName() == b.CommonName() && a.Organization() == b.Organization() &&
		a.OrganizationalUnit() == b.OrganizationalUnit() && a.Country() == b.Country()
}

func sameCertificateSANs(a, b []domain.SAN) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type() != b[i].Type() || a[i].Value() != b[i].Value() {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validateCRLDistributionPoint(raw string) error {
	if !ia5String(raw) {
		return errors.New("cryptoengine: CRL distribution point is not an IA5 string")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("cryptoengine: CRL distribution point is invalid")
	}
	return nil
}

func ia5String(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 0x7f || value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func wholeSecond(value time.Time) bool { return value.Nanosecond() == 0 }
