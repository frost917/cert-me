package cryptoengine

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func TestCertificateSignerFixedBootstrapSAN(t *testing.T) {
	for _, purpose := range []domain.SecretPurpose{domain.SecretPurposeBootstrapCA, domain.SecretPurposeCASigning} {
		t.Run(string(purpose), func(t *testing.T) {
			ring := testRing(t, testGenA, map[string][]byte{testGenA: make([]byte, 32)})
			engine, err := NewKeyEngine(ring)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := NewCertificateSigner(ring)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			rootKey, err := engine.Generate(ctx, port.KeySpec{KeyMaterialID: testOwnerID, Algorithm: domain.KeyAlgorithmECDSAP256, Purpose: purpose})
			if err != nil {
				t.Fatal(err)
			}
			window, err := domain.NewValidityWindow(domain.NewInstant(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)), domain.NewInstant(time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)))
			if err != nil {
				t.Fatal(err)
			}
			subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "cert-me"})
			if err != nil {
				t.Fatal(err)
			}
			serial, err := domain.ParseSerialNumber("1")
			if err != nil {
				t.Fatal(err)
			}
			plan := domain.IssuancePlan{Subject: subject, KeyAlgorithm: domain.KeyAlgorithmECDSAP256, Window: window,
				IssuerAuthorityID: "33333333-3333-4333-8333-333333333333", IssuerKeyGenerationID: "44444444-4444-4444-8444-444444444444"}
			root, err := signer.Sign(ctx, port.CertificateSigningRequest{Plan: plan, CertificateID: "55555555-5555-4555-8555-555555555555", KeyMaterialID: testOwnerID, SubjectPublicKey: rootKey.PublicKey, Kind: domain.CertificateKindCA, Serial: serial}, rootKey.EncryptedSecret)
			if err != nil {
				t.Fatal(err)
			}
			leafKey, err := engine.Generate(ctx, port.KeySpec{KeyMaterialID: testOtherID, Algorithm: domain.KeyAlgorithmECDSAP256, Purpose: domain.SecretPurposeInternalTLS})
			if err != nil {
				t.Fatal(err)
			}
			san, err := domain.NewBootstrapDNSNameSAN()
			if err != nil {
				t.Fatal(err)
			}
			plan.Profile, plan.SANs = domain.CertificateProfileServerTLS, []domain.SAN{san}
			leaf, err := signer.Sign(ctx, port.CertificateSigningRequest{Plan: plan, CertificateID: "66666666-6666-4666-8666-666666666666", KeyMaterialID: testOtherID, SubjectPublicKey: leafKey.PublicKey, Kind: domain.CertificateKindLeaf, Serial: serial, IssuerCertificate: root}, rootKey.EncryptedSecret)
			if purpose == domain.SecretPurposeCASigning {
				if err == nil {
					t.Fatal("ordinary CA signing must not accept the fixed bootstrap SAN")
				}
				return
			}
			if err != nil {
				t.Fatalf("bootstrap signer must preserve the fixed SAN: %v", err)
			}
			parsed, err := x509.ParseCertificate(leaf.DER())
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "cert-me" || len(leaf.SANs()) != 1 || leaf.SANs()[0].Value() != "cert-me" {
				t.Fatal("bootstrap SAN differs between DER and domain certificate")
			}
			otherSubject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "other.example"})
			if err != nil {
				t.Fatal(err)
			}
			plan.Subject = otherSubject
			if _, err := signer.Sign(ctx, port.CertificateSigningRequest{Plan: plan, CertificateID: "77777777-7777-4777-8777-777777777777", KeyMaterialID: testOtherID, SubjectPublicKey: leafKey.PublicKey, Kind: domain.CertificateKindLeaf, Serial: serial, IssuerCertificate: root}, rootKey.EncryptedSecret); err == nil {
				t.Fatal("non-fixed subject must not use the bootstrap SAN exception")
			}
		})
	}
}
