package cryptoengine

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"cert-me/internal/app/port"
	"cert-me/internal/cryptowork"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
	p12 "software.sslmate.com/src/go-pkcs12"
)

const maxPKCS12PasswordBytes = 16 * 1024

type DeliveryEncoder struct {
	ring *KeyRing
}

var _ port.DeliveryEncoder = (*DeliveryEncoder)(nil)

func NewDeliveryEncoder(ring *KeyRing) (*DeliveryEncoder, error) {
	if ring == nil {
		return nil, errors.New("cryptoengine: key ring is required")
	}
	if err := ring.withActiveKey(func(string, []byte) error { return nil }); err != nil {
		return nil, err
	}
	return &DeliveryEncoder{ring: ring}, nil
}

func (e *DeliveryEncoder) Encode(ctx context.Context, input port.DeliveryEncodeInput) (port.EncodedBundle, error) {
	if err := checkContext(ctx); err != nil {
		return port.EncodedBundle{}, err
	}
	if err := input.Format.Validate(); err != nil {
		return port.EncodedBundle{}, errors.New("cryptoengine: delivery format is unsupported")
	}
	if err := validatePrivateFormat(input); err != nil {
		return port.EncodedBundle{}, err
	}
	certificate, issuerChain, err := validateDeliveryCertificate(input)
	if err != nil {
		return port.EncodedBundle{}, err
	}
	if err := validateDeliverySecret(input.Certificate, input.LeafSecret); err != nil {
		return port.EncodedBundle{}, err
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return port.EncodedBundle{}, err
	}
	defer release()

	privateDER, err := decryptDeliveryKey(e.ring, input.LeafSecret)
	if err != nil {
		return port.EncodedBundle{}, err
	}
	defer zero(privateDER)
	privateKey, err := parsePrivateKey(privateDER)
	if err != nil {
		return port.EncodedBundle{}, errors.New("cryptoengine: delivered leaf key is invalid")
	}
	defer clearPrivateKey(privateKey)
	publicKey, err := publicKeyFor(privateKey, input.Certificate.KeyAlgorithm())
	if err != nil || !publicKey.Equal(domainPublicKeyOrZero(certificate)) {
		return port.EncodedBundle{}, errors.New("cryptoengine: delivered leaf key does not match the certificate")
	}
	if err := checkContext(ctx); err != nil {
		return port.EncodedBundle{}, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return port.EncodedBundle{}, errors.New("cryptoengine: delivered leaf key encoding failed")
	}
	defer zero(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer zero(keyPEM)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	defer zero(certPEM)
	chainPEM, err := encodeCertificateChain(issuerChain)
	if err != nil {
		return port.EncodedBundle{}, err
	}
	defer zero(chainPEM)

	var payload []byte
	contentType := ""
	switch input.Format {
	case port.DeliveryFormatPEM:
		payload = append([]byte(nil), keyPEM...)
		contentType = "application/x-pem-file"
	case port.DeliveryFormatZIP:
		payload, err = encodePrivateZIP(keyPEM, certPEM, chainPEM)
		contentType = "application/zip"
	case port.DeliveryFormatPKCS12:
		payload, err = encodePrivatePKCS12(ctx, input.PKCS12Password, privateKey, certificate, issuerChain)
		contentType = "application/x-pkcs12"
	}
	if err != nil {
		zero(payload)
		return port.EncodedBundle{}, err
	}
	if err := checkContext(ctx); err != nil {
		zero(payload)
		return port.EncodedBundle{}, err
	}
	return port.NewEncodedBundle(payload, contentType), nil
}

func validatePrivateFormat(input port.DeliveryEncodeInput) error {
	hasPassword := input.PKCS12Password != nil && !input.PKCS12Password.IsEmpty()
	switch input.Format {
	case port.DeliveryFormatPEM:
		if (input.PEMPart != "" && input.PEMPart != "private_key") || hasPassword {
			return errors.New("cryptoengine: private PEM output only supports the private_key part")
		}
	case port.DeliveryFormatZIP:
		if input.PEMPart != "" || hasPassword {
			return errors.New("cryptoengine: ZIP output does not accept PEM parts or a PKCS#12 password")
		}
	case port.DeliveryFormatPKCS12:
		if input.PEMPart != "" || input.PKCS12Password == nil {
			return errors.New("cryptoengine: PKCS#12 output requires a password and no PEM part")
		}
	}
	return nil
}

func validateDeliverySecret(certificate domain.Certificate, encrypted domain.EncryptedSecret) error {
	if certificate.Kind() != domain.CertificateKindLeaf || certificate.ID() == "" ||
		certificate.KeyMaterialID() == "" || encrypted.IsZero() ||
		encrypted.OwnerKeyID() != certificate.KeyMaterialID() ||
		encrypted.Purpose() != domain.SecretPurposeLeafDelivery ||
		encrypted.FormatVersion() != secretFormatVersion {
		return errors.New("cryptoengine: delivery secret owner, purpose, or format is invalid")
	}
	return nil
}

func validateDeliveryCertificate(input port.DeliveryEncodeInput) (*x509.Certificate, []*x509.Certificate, error) {
	der := input.Certificate.DER()
	certificate, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(certificate.Raw, der) {
		return nil, nil, errors.New("cryptoengine: delivered certificate DER is invalid")
	}
	if input.Certificate.Kind() != domain.CertificateKindLeaf || certificate.IsCA || certificate.SerialNumber == nil ||
		certificate.SerialNumber.Cmp(input.Certificate.Serial().Big()) != 0 {
		return nil, nil, errors.New("cryptoengine: delivered certificate facts do not match its DER")
	}
	algorithm, err := publicKeyAlgorithm(certificate.PublicKey)
	if err != nil || algorithm != input.Certificate.KeyAlgorithm() {
		return nil, nil, errors.New("cryptoengine: delivered certificate key algorithm does not match its DER")
	}
	window, err := parsedValidity(certificate)
	if err != nil || !sameCertificateWindow(window, input.Certificate.Validity()) {
		return nil, nil, errors.New("cryptoengine: delivered certificate validity does not match its DER")
	}
	subject, err := domainSubject(certificate.Subject)
	if err != nil || !sameCertificateSubject(subject, input.Certificate.Subject()) {
		return nil, nil, errors.New("cryptoengine: delivered certificate subject does not match its DER")
	}
	sans, err := orderedSANsFromDER(certificate)
	if err != nil || !sameCertificateSANs(sans, input.Certificate.SANs()) ||
		domain.ValidateSANsForProfile(input.Certificate.Profile(), sans) != nil {
		return nil, nil, errors.New("cryptoengine: delivered certificate SANs do not match its DER or profile")
	}
	if !deliveryProfileMatches(input.Certificate.Profile(), certificate) {
		return nil, nil, errors.New("cryptoengine: delivered certificate profile does not match its DER")
	}
	keyUsage, eku, isCA, _, _, err := requestedUsages(port.CertificateSigningRequest{
		Plan: domain.IssuancePlan{Profile: input.Certificate.Profile(), KeyAlgorithm: input.Certificate.KeyAlgorithm()},
		Kind: domain.CertificateKindLeaf,
	})
	if err != nil || certificate.KeyUsage != keyUsage || certificate.IsCA != isCA ||
		len(certificate.ExtKeyUsage) != len(eku) || len(certificate.UnhandledCriticalExtensions) != 0 {
		return nil, nil, errors.New("cryptoengine: delivered certificate constraints do not match its profile")
	}
	for i := range eku {
		if certificate.ExtKeyUsage[i] != eku[i] {
			return nil, nil, errors.New("cryptoengine: delivered certificate extended usage does not match its profile")
		}
	}
	if len(input.ChainDER) == 0 || len(input.ChainDER) > 2 {
		return nil, nil, errors.New("cryptoengine: delivered certificate chain is missing or too deep")
	}
	chain := make([]*x509.Certificate, 0, len(input.ChainDER))
	for _, raw := range input.ChainDER {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil || !bytes.Equal(parsed.Raw, raw) {
			return nil, nil, errors.New("cryptoengine: delivered issuer certificate DER is invalid")
		}
		chain = append(chain, parsed)
	}
	ordered := append([]*x509.Certificate{certificate}, chain...)
	for i := 0; i+1 < len(ordered); i++ {
		parent := ordered[i+1]
		if !parent.BasicConstraintsValid || !parent.IsCA || parent.KeyUsage&x509.KeyUsageCertSign == 0 ||
			!bytes.Equal(ordered[i].RawIssuer, parent.RawSubject) || ordered[i].CheckSignatureFrom(parent) != nil {
			return nil, nil, errors.New("cryptoengine: delivered certificate chain link is invalid")
		}
	}
	root := chain[len(chain)-1]
	if !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil {
		return nil, nil, errors.New("cryptoengine: delivered certificate chain does not end at a self-signed root")
	}
	return certificate, chain, nil
}

func deliveryProfileMatches(profile domain.CertificateProfile, certificate *x509.Certificate) bool {
	if len(certificate.UnknownExtKeyUsage) != 0 {
		return false
	}
	var expected []x509.ExtKeyUsage
	switch profile {
	case domain.CertificateProfileServerTLS:
		expected = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case domain.CertificateProfileClientMTLS:
		expected = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case domain.CertificateProfileDual:
		expected = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return false
	}
	if len(certificate.ExtKeyUsage) != len(expected) {
		return false
	}
	for _, usage := range expected {
		found := false
		for _, actual := range certificate.ExtKeyUsage {
			if usage == actual {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func domainPublicKeyOrZero(certificate *x509.Certificate) domain.PublicKey {
	key, err := domainPublicKey(certificate)
	if err != nil {
		return domain.PublicKey{}
	}
	return key
}

func decryptDeliveryKey(ring *KeyRing, encrypted domain.EncryptedSecret) ([]byte, error) {
	nonce := encrypted.Nonce()
	ciphertext := encrypted.Ciphertext()
	defer zero(nonce)
	defer zero(ciphertext)
	if len(nonce) != secretNonceSize {
		return nil, errors.New("cryptoengine: delivery secret nonce is invalid")
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
		return nil, errors.New("cryptoengine: delivery secret could not be authenticated")
	}
	return plaintext, nil
}

func encodeCertificateChain(chain []*x509.Certificate) ([]byte, error) {
	var output bytes.Buffer
	for _, certificate := range chain {
		if err := pem.Encode(&output, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
			return nil, errors.New("cryptoengine: issuer certificate PEM encoding failed")
		}
	}
	return output.Bytes(), nil
}

func encodePrivateZIP(keyPEM, certificatePEM, chainPEM []byte) ([]byte, error) {
	var output bytes.Buffer
	success := false
	defer func() {
		if !success {
			zero(output.Bytes())
		}
	}()
	writer := zip.NewWriter(&output)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{name: "private-key.pem", data: keyPEM},
		{name: "certificate.pem", data: certificatePEM},
		{name: "chain.pem", data: chainPEM},
	} {
		file, err := writer.Create(entry.name)
		if err != nil {
			_ = writer.Close()
			return nil, errors.New("cryptoengine: private ZIP entry creation failed")
		}
		if _, err := file.Write(entry.data); err != nil {
			_ = writer.Close()
			return nil, errors.New("cryptoengine: private ZIP content write failed")
		}
	}
	if err := writer.Close(); err != nil {
		return nil, errors.New("cryptoengine: private ZIP finalization failed")
	}
	success = true
	return output.Bytes(), nil
}

func encodePrivatePKCS12(ctx context.Context, passwordInput *secret.Input, privateKey any, certificate *x509.Certificate, chain []*x509.Certificate) ([]byte, error) {
	if passwordInput == nil {
		return nil, errors.New("cryptoengine: PKCS#12 password is required")
	}
	caCerts := append([]*x509.Certificate(nil), chain...)
	var output []byte
	err := passwordInput.Use(func(raw []byte) error {
		if len(raw) > maxPKCS12PasswordBytes {
			return errors.New("cryptoengine: PKCS#12 password exceeds the supported size")
		}
		// The PKCS#12 library accepts a string and consumes it synchronously;
		// it does not retain the password after Encode returns.
		password := string(raw)
		pfx, err := p12.Modern2023.Encode(privateKey, certificate, caCerts, password)
		if err != nil {
			zero(pfx)
			return errors.New("cryptoengine: PKCS#12 encoding failed")
		}
		output = pfx
		return nil
	})
	if err != nil {
		zero(output)
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := checkContext(ctx); err != nil {
		zero(output)
		return nil, err
	}
	return output, nil
}
