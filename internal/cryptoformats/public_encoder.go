// Package cryptoformats contains the concrete cryptographic format adapters.
package cryptoformats

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

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
// the target is inserted at the front only for PEM part=chain. A public
// PKCS#12 shape is intentionally undefined by the API contract and is
// rejected without creating a bundle.
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
	if _, err := parsePublicCertificateDER(targetDER, "certificate"); err != nil {
		return port.EncodedBundle{}, err
	}

	chainDER := make([][]byte, len(input.ChainDER))
	for i, der := range input.ChainDER {
		if err := checkPublicEncodeContext(ctx); err != nil {
			return port.EncodedBundle{}, err
		}
		if _, err := parsePublicCertificateDER(der, fmt.Sprintf("chain[%d]", i)); err != nil {
			return port.EncodedBundle{}, err
		}
		// Copy the validated bytes before encoding. Certificate.DER already
		// returns a copy, but ChainDER is a caller-owned nested slice.
		chainDER[i] = append([]byte(nil), der...)
	}

	if err := validatePublicChainShape(targetDER, chainDER, input.Format, input.PEMPart); err != nil {
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

func validatePublicChainShape(targetDER []byte, chainDER [][]byte, format port.DeliveryFormat, part string) error {
	needsChain := format == port.DeliveryFormatZIP || (format == port.DeliveryFormatPEM && (part == "" || part == publicPEMPartChain))
	if needsChain && len(chainDER) == 0 {
		return publicValidationError("public_chain_der_invalid", "certificate chain must contain at least one issuer certificate", domain.ErrInvalidValue)
	}
	for i, der := range chainDER {
		if bytes.Equal(targetDER, der) {
			return publicValidationError("public_chain_der_invalid", fmt.Sprintf("chain[%d] repeats the target certificate", i), domain.ErrInvalidValue)
		}
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
