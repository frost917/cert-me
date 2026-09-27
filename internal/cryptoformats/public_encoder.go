// Package cryptoformats contains the concrete cryptographic format adapters.
package cryptoformats

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

const (
	publicPEMPartCertificate = "certificate"
	publicPEMPartChain       = "chain"
	publicPEMPartPrivateKey  = "private_key"
)

// PublicCertificateEncoder is the public-material download encoder. It has
// no key, secret, or decryption dependency: all bytes it handles are the
// certificate DER supplied by the caller and the already-resolved issuer
// chain.
type PublicCertificateEncoder struct{}

// NewPublicCertificateEncoder constructs the stateless public encoder.
func NewPublicCertificateEncoder() *PublicCertificateEncoder {
	return &PublicCertificateEncoder{}
}

var _ port.PublicCertificateEncoder = (*PublicCertificateEncoder)(nil)

// Encode validates the supplied certificate DER and chain DER before creating
// a public PEM or ZIP bundle. ChainDER is supplied in issuer-to-root order;
// PEM chain output places the target first, while ZIP separates it into
// certificate.pem. A public PKCS#12 shape is intentionally undefined by the
// API contract and is rejected without creating a bundle.
func (e *PublicCertificateEncoder) Encode(ctx context.Context, input port.PublicEncodeInput) (port.EncodedBundle, error) {
	if err := checkPublicEncodeContext(ctx); err != nil {
		return port.EncodedBundle{}, err
	}
	if err := input.Format.Validate(); err != nil {
		return port.EncodedBundle{}, publicValidationError("download_format_invalid", "unsupported public download format", err)
	}
	if err := validatePublicCombination(input.Format, input.PEMPart); err != nil {
		return port.EncodedBundle{}, err
	}

	targetDER := input.Certificate.DER()
	target, err := parsePublicCertificateDER(targetDER, "certificate")
	if err != nil {
		return port.EncodedBundle{}, err
	}
	if err := validatePublicCertificateFacts(input.Certificate, target); err != nil {
		return port.EncodedBundle{}, err
	}

	chainDER := make([][]byte, len(input.ChainDER))
	chain := make([]*x509.Certificate, len(input.ChainDER))
	for i, der := range input.ChainDER {
		if err := checkPublicEncodeContext(ctx); err != nil {
			return port.EncodedBundle{}, err
		}
		parsed, err := parsePublicCertificateDER(der, fmt.Sprintf("chain[%d]", i))
		if err != nil {
			return port.EncodedBundle{}, err
		}
		// Copy the validated bytes before encoding. Certificate.DER already
		// returns a copy, but ChainDER is a caller-owned nested slice.
		chainDER[i] = append([]byte(nil), der...)
		chain[i] = parsed
	}

	if err := validatePublicChainShape(targetDER, target, chainDER, chain, input.Format, input.PEMPart); err != nil {
		return port.EncodedBundle{}, err
	}
	if err := checkPublicEncodeContext(ctx); err != nil {
		return port.EncodedBundle{}, err
	}

	switch input.Format {
	case port.DeliveryFormatPEM:
		return encodePublicPEM(targetDER, chainDER, input.PEMPart)
	case port.DeliveryFormatZIP:
		return encodePublicZIP(targetDER, chainDER)
	case port.DeliveryFormatPKCS12:
		// validatePublicCombination handles this before DER parsing. Keep a
		// defensive case here so a future format validation change cannot
		// accidentally turn the public path into a key container.
		return port.EncodedBundle{}, publicValidationError("public_pkcs12_undefined", "pkcs12 is not defined for a public certificate download", domain.ErrInvalidValue)
	default:
		return port.EncodedBundle{}, publicValidationError("download_format_invalid", "unsupported public download format", domain.ErrInvalidValue)
	}
}

func checkPublicEncodeContext(ctx context.Context) error {
	if ctx == nil {
		return publicValidationError("public_encode_context_invalid", "a context is required for public certificate encoding", domain.ErrInvalidValue)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("public_encode_canceled: %w", err)
	}
	return nil
}

func validatePublicCombination(format port.DeliveryFormat, part string) error {
	if format == port.DeliveryFormatPKCS12 {
		return publicValidationError("public_pkcs12_undefined", "pkcs12 is not defined for a public certificate download", domain.ErrInvalidValue)
	}
	if format != port.DeliveryFormatPEM && format != port.DeliveryFormatZIP {
		return publicValidationError("download_format_invalid", "unsupported public download format", domain.ErrInvalidValue)
	}

	switch part {
	case "", publicPEMPartCertificate, publicPEMPartChain:
		// Empty means the complete public PEM bundle for compatibility with
		// the optional API part parameter. ZIP has one fixed shape and the
		// same empty part is the only unambiguous request for it.
		if format == port.DeliveryFormatZIP && part != "" {
			return publicValidationError("public_zip_part_invalid", "zip public downloads do not accept a pem part", domain.ErrInvalidValue)
		}
		return nil
	case publicPEMPartPrivateKey:
		return publicValidationError("public_download_no_private_key", "a public download cannot include the private key", domain.ErrInvalidValue)
	default:
		return publicValidationError("download_part_invalid", "unsupported public download part", domain.ErrInvalidValue)
	}
}

// validatePublicCertificateFacts checks that the DER being emitted still
// describes the immutable certificate record that the caller selected. The
// certificate ID and key-generation IDs are deliberately not copied into the
// output format; the exact target DER is. The DER itself must agree on its
// serial, public-key algorithm, kind, and leaf profile. Subject, SAN, and
// validity bytes remain exactly as signed because the encoder never rebuilds
// the certificate.
func validatePublicCertificateFacts(record domain.Certificate, parsed *x509.Certificate) error {
	if record.ID() == "" || record.KeyMaterialID() == "" || record.IssuerCAKeyGenerationID() == "" || record.Serial().IsZero() {
		return publicValidationError("public_certificate_identity_invalid", "certificate identity fields are incomplete", domain.ErrInvalidValue)
	}
	if parsed.SerialNumber == nil || parsed.SerialNumber.Cmp(record.Serial().Big()) != 0 {
		return publicValidationError("public_certificate_metadata_mismatch", "certificate serial does not match its stored identity", domain.ErrInvalidValue)
	}
	if algorithm, ok := publicKeyAlgorithm(parsed.PublicKey); !ok || algorithm != record.KeyAlgorithm() {
		return publicValidationError("public_certificate_metadata_mismatch", "certificate public-key algorithm does not match its stored identity", domain.ErrInvalidValue)
	}

	switch record.Kind() {
	case domain.CertificateKindCA:
		if !parsed.IsCA || !parsed.BasicConstraintsValid || record.Profile() != "" {
			return publicValidationError("public_certificate_metadata_mismatch", "CA certificate kind or profile does not match its DER", domain.ErrInvalidValue)
		}
	case domain.CertificateKindLeaf:
		if parsed.IsCA || !publicProfileMatches(record.Profile(), parsed) {
			return publicValidationError("public_certificate_metadata_mismatch", "leaf certificate kind or profile does not match its DER", domain.ErrInvalidValue)
		}
	default:
		return publicValidationError("public_certificate_identity_invalid", "certificate kind is unsupported", domain.ErrInvalidValue)
	}
	return nil
}

func publicKeyAlgorithm(publicKey any) (domain.KeyAlgorithm, bool) {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Curve.Params() == nil {
			return "", false
		}
		switch key.Curve.Params().Name {
		case "P-256":
			return domain.KeyAlgorithmECDSAP256, true
		case "P-384":
			return domain.KeyAlgorithmECDSAP384, true
		default:
			return "", false
		}
	case *rsa.PublicKey:
		switch key.N.BitLen() {
		case 2048:
			return domain.KeyAlgorithmRSA2048, true
		case 3072:
			return domain.KeyAlgorithmRSA3072, true
		case 4096:
			return domain.KeyAlgorithmRSA4096, true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

func publicProfileMatches(profile domain.CertificateProfile, parsed *x509.Certificate) bool {
	var want []x509.ExtKeyUsage
	switch profile {
	case domain.CertificateProfileServerTLS:
		want = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case domain.CertificateProfileClientMTLS:
		want = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case domain.CertificateProfileDual:
		want = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return false
	}
	if len(parsed.UnknownExtKeyUsage) != 0 || len(parsed.ExtKeyUsage) != len(want) {
		return false
	}
	got := append([]x509.ExtKeyUsage(nil), parsed.ExtKeyUsage...)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func publicChainIsSelfSignedRoot(cert *x509.Certificate) bool {
	return cert != nil && cert.IsCA && cert.BasicConstraintsValid &&
		bytes.Equal(cert.RawSubject, cert.RawIssuer) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func parsePublicCertificateDER(der []byte, position string) (*x509.Certificate, error) {
	code := "public_certificate_der_invalid"
	if position != "certificate" {
		code = "public_chain_der_invalid"
	}
	if len(der) == 0 {
		return nil, publicValidationError(code, position+" DER must not be empty", domain.ErrInvalidValue)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		cause := fmt.Errorf("%w: %v", domain.ErrInvalidValue, err)
		return nil, publicValidationError(code, position+" DER is invalid", cause)
	}
	// ParseCertificate returns Raw for the single certificate it parsed. A
	// byte-for-byte check rejects a valid certificate followed by arbitrary
	// trailing bytes instead of silently dropping input from a public bundle.
	if !bytes.Equal(parsed.Raw, der) {
		return nil, publicValidationError(code, position+" DER contains trailing data", domain.ErrInvalidValue)
	}
	return parsed, nil
}

func validatePublicChainShape(targetDER []byte, target *x509.Certificate, chainDER [][]byte, chain []*x509.Certificate, format port.DeliveryFormat, part string) error {
	needsChain := format == port.DeliveryFormatZIP || (format == port.DeliveryFormatPEM && (part == "" || part == publicPEMPartChain))
	if len(chainDER) == 0 {
		if needsChain && !publicChainIsSelfSignedRoot(target) {
			return publicValidationError("public_chain_der_invalid", "certificate chain must include its issuer through the Root", domain.ErrInvalidValue)
		}
		return nil
	}
	child := target
	for i, der := range chainDER {
		if bytes.Equal(targetDER, der) {
			return publicValidationError("public_chain_der_invalid", fmt.Sprintf("chain[%d] repeats the target certificate", i), domain.ErrInvalidValue)
		}
		for prior := 0; prior < i; prior++ {
			if bytes.Equal(chainDER[prior], der) {
				return publicValidationError("public_chain_der_invalid", fmt.Sprintf("chain[%d] repeats chain[%d]", i, prior), domain.ErrInvalidValue)
			}
		}
		if !bytes.Equal(child.RawIssuer, chain[i].RawSubject) || child.CheckSignatureFrom(chain[i]) != nil {
			return publicValidationError("public_chain_issuer_mismatch", fmt.Sprintf("chain[%d] is not the issuer of the preceding certificate", i), domain.ErrInvalidValue)
		}
		child = chain[i]
	}
	if !publicChainIsSelfSignedRoot(child) {
		return publicValidationError("public_chain_der_invalid", "certificate chain does not end at a self-signed Root", domain.ErrInvalidValue)
	}
	return nil
}

func encodePublicPEM(targetDER []byte, chainDER [][]byte, part string) (port.EncodedBundle, error) {
	var buf bytes.Buffer

	writeCertificate := func(der []byte) error {
		return pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	switch part {
	case publicPEMPartCertificate:
		if err := writeCertificate(targetDER); err != nil {
			return port.EncodedBundle{}, publicValidationError("public_bundle_encode_failed", "could not encode the certificate", err)
		}
	case publicPEMPartChain:
		if err := writeCertificate(targetDER); err != nil {
			return port.EncodedBundle{}, publicValidationError("public_bundle_encode_failed", "could not encode the certificate", err)
		}
		for _, der := range chainDER {
			if err := writeCertificate(der); err != nil {
				return port.EncodedBundle{}, publicValidationError("public_bundle_encode_failed", "could not encode the certificate chain", err)
			}
		}
	default:
		// The empty part is the complete public chain, target first.
		if err := writeCertificate(targetDER); err != nil {
			return port.EncodedBundle{}, publicValidationError("public_bundle_encode_failed", "could not encode the certificate", err)
		}
		for _, der := range chainDER {
			if err := writeCertificate(der); err != nil {
				return port.EncodedBundle{}, publicValidationError("public_bundle_encode_failed", "could not encode the certificate chain", err)
			}
		}
	}
	return port.NewEncodedBundle(buf.Bytes(), "application/x-pem-file"), nil
}

func encodePublicZIP(targetDER []byte, chainDER [][]byte) (port.EncodedBundle, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	writePEM := func(name string, ders [][]byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		for _, der := range ders {
			if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
				return err
			}
		}
		return nil
	}

	if err := writePEM("certificate.pem", [][]byte{targetDER}); err != nil {
		_ = zw.Close()
		return port.EncodedBundle{}, publicValidationError("public_bundle_encode_failed", "could not encode the certificate archive", err)
	}
	if err := writePEM("chain.pem", chainDER); err != nil {
		_ = zw.Close()
		return port.EncodedBundle{}, publicValidationError("public_bundle_encode_failed", "could not encode the certificate chain archive", err)
	}
	if err := zw.Close(); err != nil {
		return port.EncodedBundle{}, publicValidationError("public_bundle_encode_failed", "could not finish the certificate archive", err)
	}
	return port.NewEncodedBundle(buf.Bytes(), "application/zip"), nil
}

func publicValidationError(code, detail string, cause error) error {
	if cause == nil {
		cause = domain.ErrInvalidValue
	}
	return domain.NewPolicyError(cause, code, detail)
}
