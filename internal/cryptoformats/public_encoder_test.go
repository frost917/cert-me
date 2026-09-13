package cryptoformats

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type publicEncoderFixture struct {
	target    domain.Certificate
	targetDER []byte
	issuerDER []byte
	rootDER   []byte
}

func newPublicEncoderFixture(t *testing.T) publicEncoderFixture {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := now.Add(365 * 24 * time.Hour)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		NotBefore:             now,
		NotAfter:              end,
		Subject:               pkix.Name{CommonName: "root.example.internal"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             now,
		NotAfter:              end,
		Subject:               pkix.Name{CommonName: "issuer.example.internal"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, rootCert, &issuerKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}

	targetKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	targetTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now,
		NotAfter:     end,
		Subject:      pkix.Name{CommonName: "leaf.example.internal"},
		DNSNames:     []string{"leaf.example.internal"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	targetDER, err := x509.CreateCertificate(rand.Reader, targetTemplate, issuerCert, &targetKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := domain.NewSerialNumberFromBig(targetTemplate.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: targetTemplate.Subject.CommonName})
	if err != nil {
		t.Fatal(err)
	}
	san, err := domain.NewSAN(domain.SANTypeDNS, targetTemplate.DNSNames[0])
	if err != nil {
		t.Fatal(err)
	}
	window, err := domain.NewValidityWindow(domain.NewInstant(now), domain.NewInstant(end))
	if err != nil {
		t.Fatal(err)
	}
	targetID, err := domain.ParseCertificateID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := domain.ParseKeyMaterialID("22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	generationID, err := domain.ParseCAKeyGenerationID("33333333-3333-3333-3333-333333333333")
	if err != nil {
		t.Fatal(err)
	}
	target, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      targetID,
		DER:                     targetDER,
		KeyMaterialID:           keyID,
		IssuerCAKeyGenerationID: generationID,
		Serial:                  serial,
		Validity:                window,
		Subject:                 subject,
		SANs:                    []domain.SAN{san},
		Kind:                    domain.CertificateKindLeaf,
		Profile:                 domain.CertificateProfileServerTLS,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatal(err)
	}
	return publicEncoderFixture{target: target, targetDER: targetDER, issuerDER: issuerDER, rootDER: rootDER}
}

func readEncodedBundle(t *testing.T, bundle port.EncodedBundle) []byte {
	t.Helper()
	defer bundle.Close()
	var payload []byte
	if err := bundle.Use(func(data []byte) error {
		payload = append(payload, data...)
		return nil
	}); err != nil {
		t.Fatalf("read encoded bundle: %v", err)
	}
	return payload
}

func decodePEMCertificates(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var certs [][]byte
	for len(data) != 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			t.Fatalf("PEM contains undecodable trailing data")
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("PEM block type = %q, want CERTIFICATE", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatalf("PEM block is not an X.509 certificate: %v", err)
		}
		certs = append(certs, append([]byte(nil), block.Bytes...))
		data = rest
	}
	return certs
}

func TestPublicCertificateEncoderPEMPartsProduceCompatibleCertificates(t *testing.T) {
	fx := newPublicEncoderFixture(t)
	encoder := NewPublicCertificateEncoder()
	chain := [][]byte{fx.issuerDER, fx.rootDER}

	tests := []struct {
		name string
		part string
		want [][]byte
	}{
		{name: "certificate", part: "certificate", want: [][]byte{fx.targetDER}},
		{name: "chain", part: "chain", want: [][]byte{fx.targetDER, fx.issuerDER, fx.rootDER}},
		{name: "unspecified", want: [][]byte{fx.targetDER, fx.issuerDER, fx.rootDER}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := encoder.Encode(context.Background(), port.PublicEncodeInput{
				Certificate: fx.target,
				ChainDER:    chain,
				Format:      port.DeliveryFormatPEM,
				PEMPart:     tt.part,
			})
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if bundle.ContentType != "application/x-pem-file" {
				t.Fatalf("ContentType = %q, want application/x-pem-file", bundle.ContentType)
			}
			got := decodePEMCertificates(t, readEncodedBundle(t, bundle))
			if len(got) != len(tt.want) {
				t.Fatalf("PEM certificate count = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if !bytes.Equal(got[i], tt.want[i]) {
					t.Fatalf("PEM certificate %d does not match requested DER", i)
				}
			}
		})
	}
}

func TestPublicCertificateEncoderZIPHasFixedPEMEntries(t *testing.T) {
	fx := newPublicEncoderFixture(t)
	bundle, err := NewPublicCertificateEncoder().Encode(context.Background(), port.PublicEncodeInput{
		Certificate: fx.target,
		ChainDER:    [][]byte{fx.issuerDER, fx.rootDER},
		Format:      port.DeliveryFormatZIP,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if bundle.ContentType != "application/zip" {
		t.Fatalf("ContentType = %q, want application/zip", bundle.ContentType)
	}
	archive := readEncodedBundle(t, bundle)
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	if len(reader.File) != 2 {
		t.Fatalf("ZIP entry count = %d, want 2", len(reader.File))
	}
	want := map[string][][]byte{
		"certificate.pem": {fx.targetDER},
		"chain.pem":       {fx.issuerDER, fx.rootDER},
	}
	for _, file := range reader.File {
		wantDER, ok := want[file.Name]
		if !ok {
			t.Fatalf("unexpected ZIP entry %q", file.Name)
		}
		body, err := file.Open()
		if err != nil {
			t.Fatalf("open %q: %v", file.Name, err)
		}
		data, readErr := io.ReadAll(body)
		closeErr := body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read %q: read=%v close=%v", file.Name, readErr, closeErr)
		}
		gotDER := decodePEMCertificates(t, data)
		if len(gotDER) != len(wantDER) {
			t.Fatalf("%s certificate count = %d, want %d", file.Name, len(gotDER), len(wantDER))
		}
		for i := range wantDER {
			if !bytes.Equal(gotDER[i], wantDER[i]) {
				t.Fatalf("%s certificate %d does not match requested DER", file.Name, i)
			}
		}
	}
}

func TestPublicCertificateEncoderRejectsMalformedAndForbiddenInputs(t *testing.T) {
	fx := newPublicEncoderFixture(t)
	tests := []struct {
		name  string
		input port.PublicEncodeInput
		code  string
	}{
		{
			name: "malformed target DER",
			input: port.PublicEncodeInput{
				Certificate: mustDomainCertificateWithDER(t, fx.target, []byte{0x30, 0x01, 0x00}),
				Format:      port.DeliveryFormatPEM,
				PEMPart:     "certificate",
			},
			code: "public_certificate_der_invalid",
		},
		{
			name: "malformed chain DER",
			input: port.PublicEncodeInput{
				Certificate: fx.target,
				ChainDER:    [][]byte{{0x01, 0x02, 0x03}},
				Format:      port.DeliveryFormatPEM,
				PEMPart:     "certificate",
			},
			code: "public_chain_der_invalid",
		},
		{
			name: "public pkcs12",
			input: port.PublicEncodeInput{
				Certificate: fx.target,
				Format:      port.DeliveryFormatPKCS12,
			},
			code: "public_pkcs12_undefined",
		},
		{
			name: "private key part",
			input: port.PublicEncodeInput{
				Certificate: fx.target,
				Format:      port.DeliveryFormatPEM,
				PEMPart:     "private_key",
			},
			code: "public_download_no_private_key",
		},
		{
			name: "zip pem part",
			input: port.PublicEncodeInput{
				Certificate: fx.target,
				ChainDER:    [][]byte{fx.issuerDER, fx.rootDER},
				Format:      port.DeliveryFormatZIP,
				PEMPart:     "certificate",
			},
			code: "public_zip_part_invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPublicCertificateEncoder().Encode(context.Background(), tt.input)
			if err == nil {
				t.Fatal("Encode unexpectedly succeeded")
			}
			var policyErr *domain.PolicyError
			if !errors.As(err, &policyErr) {
				t.Fatalf("error = %T %v, want domain.PolicyError", err, err)
			}
			if policyErr.Code != tt.code {
				t.Fatalf("error code = %q, want %q", policyErr.Code, tt.code)
			}
			if !errors.Is(err, domain.ErrInvalidValue) {
				t.Fatalf("error does not preserve domain.ErrInvalidValue: %v", err)
			}
		})
	}
}

func mustDomainCertificateWithDER(t *testing.T, original domain.Certificate, der []byte) domain.Certificate {
	t.Helper()
	serial := original.Serial()
	window := original.Validity()
	copyFacts := domain.CertificateFacts{
		ID:                      original.ID(),
		DER:                     der,
		KeyMaterialID:           original.KeyMaterialID(),
		IssuerCAKeyGenerationID: original.IssuerCAKeyGenerationID(),
		Serial:                  serial,
		Validity:                window,
		Subject:                 original.Subject(),
		SANs:                    original.SANs(),
		Kind:                    original.Kind(),
		Profile:                 original.Profile(),
		KeyAlgorithm:            original.KeyAlgorithm(),
		Origin:                  original.Origin(),
		CreatedByAccountID:      original.CreatedByAccountID(),
		Version:                 original.Version(),
	}
	cert, err := domain.NewCertificate(copyFacts)
	if err != nil {
		t.Fatalf("domain.NewCertificate: %v", err)
	}
	return cert
}
