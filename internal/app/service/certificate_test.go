package service

import (
	"context"
	"errors"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func TestResolveSigningKeyGeneratesAFreshKey(t *testing.T) {
	engine := &fakeKeyEngine{}
	keyMaterialID, err := domain.ParseKeyMaterialID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}
	spec := port.KeySpec{KeyMaterialID: keyMaterialID, Algorithm: domain.KeyAlgorithmECDSAP256, Purpose: domain.SecretPurposeLeafDelivery}

	gotID, publicKey, secret, err := resolveSigningKey(context.Background(), engine, signingKeyRef{Fresh: &spec})
	if err != nil {
		t.Fatalf("resolveSigningKey: %v", err)
	}
	if gotID != keyMaterialID {
		t.Fatalf("key material id = %s, want %s", gotID, keyMaterialID)
	}
	if publicKey.IsZero() {
		t.Fatal("want a non-zero generated public key")
	}
	if secret == nil {
		t.Fatal("want a generated secret for a fresh key")
	}
	if engine.generateCalls != 1 {
		t.Fatalf("generate calls = %d, want 1", engine.generateCalls)
	}
}

func TestResolveSigningKeyReusesAnExistingKeyWithoutGenerating(t *testing.T) {
	engine := &fakeKeyEngine{}
	existing, err := domain.ParseKeyMaterialID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}

	gotID, publicKey, secret, err := resolveSigningKey(context.Background(), engine, signingKeyRef{Existing: existing})
	if err != nil {
		t.Fatalf("resolveSigningKey: %v", err)
	}
	if gotID != existing {
		t.Fatalf("key material id = %s, want %s", gotID, existing)
	}
	if !publicKey.IsZero() {
		t.Fatal("want a zero-value public key when reusing an existing one (the caller already knows it)")
	}
	if secret != nil {
		t.Fatal("want no generated secret when reusing an existing key")
	}
	if engine.generateCalls != 0 {
		t.Fatalf("generate calls = %d, want 0 for a reused key", engine.generateCalls)
	}
}

func TestResolveSigningKeyRejectsAnEmptyRef(t *testing.T) {
	_, _, _, err := resolveSigningKey(context.Background(), &fakeKeyEngine{}, signingKeyRef{})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindValidation {
		t.Fatalf("err = %v, want a validation AppError", err)
	}
}

func TestResolveSigningKeyPropagatesAGenerateFailure(t *testing.T) {
	failure := errors.New("hsm unavailable")
	engine := &fakeKeyEngine{fail: failure}
	keyMaterialID, _ := domain.ParseKeyMaterialID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	spec := port.KeySpec{KeyMaterialID: keyMaterialID, Algorithm: domain.KeyAlgorithmECDSAP256, Purpose: domain.SecretPurposeLeafDelivery}

	_, _, _, err := resolveSigningKey(context.Background(), engine, signingKeyRef{Fresh: &spec})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindUnavailable {
		t.Fatalf("err = %v, want an unavailable AppError", err)
	}
	if !errors.Is(err, failure) {
		t.Fatalf("err = %v, want it to wrap the original failure", err)
	}
}

func testPlan(t *testing.T) domain.IssuancePlan {
	t.Helper()
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "leaf.example.internal"})
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	san, err := domain.NewSAN(domain.SANTypeDNS, "leaf.example.internal")
	if err != nil {
		t.Fatalf("san: %v", err)
	}
	window, err := domain.NewValidityWindow(testNow(), testNow().Add(domain.NewDuration(24*365*1)))
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	issuerKeyGenID := caKeyID(t, 1)
	return domain.IssuancePlan{
		Profile:               domain.CertificateProfileServerTLS,
		Subject:               subject,
		SANs:                  []domain.SAN{san},
		KeyAlgorithm:          domain.KeyAlgorithmECDSAP256,
		Window:                window,
		IssuerAuthorityID:     "",
		IssuerKeyGenerationID: issuerKeyGenID,
	}
}

func testIssuerSecret(t *testing.T) domain.EncryptedSecret {
	t.Helper()
	owner, err := domain.ParseKeyMaterialID("ffffffff-ffff-4fff-8fff-ffffffffffff")
	if err != nil {
		t.Fatalf("owner id: %v", err)
	}
	secret, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID: owner, Purpose: domain.SecretPurposeCASigning, FormatVersion: 1,
		EncryptionGenerationID: "gen-1", Nonce: []byte("noncenoncenonce12345"), Ciphertext: []byte("ciphertext"),
	})
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	return secret
}

func TestSignCertificateRebuildsKeyMaterialIDFromTheCaller(t *testing.T) {
	signer := &fakeSigner{}
	ids := &seqIDs{}
	plan := testPlan(t)
	keyMaterialID, err := domain.ParseKeyMaterialID("11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}

	cert, err := signCertificate(context.Background(), signer, ids, plan, testIssuerSecret(t), keyMaterialID, domain.CertificateKindLeaf, "")
	if err != nil {
		t.Fatalf("signCertificate: %v", err)
	}
	// The fake signer embeds a placeholder KeyMaterialID unrelated to the
	// one this test asked for; signCertificate must override it with the
	// caller-known value rather than trusting whatever the signer set (see
	// signCertificate's doc comment on the CertificateSigner contract gap).
	if cert.KeyMaterialID() != keyMaterialID {
		t.Fatalf("certificate key material id = %s, want %s", cert.KeyMaterialID(), keyMaterialID)
	}
	if cert.Subject().CommonName() != plan.Subject.CommonName() {
		t.Fatalf("certificate subject = %+v, want %+v", cert.Subject(), plan.Subject)
	}
	if !cert.Validity().NotBefore().Equal(plan.Window.NotBefore()) {
		t.Fatal("certificate validity does not match the requested plan window")
	}
}

func TestSignCertificatePropagatesASignFailure(t *testing.T) {
	failure := errors.New("signing backend down")
	signer := &fakeSigner{fail: failure}
	ids := &seqIDs{}
	keyMaterialID, _ := domain.ParseKeyMaterialID("11111111-2222-4333-8444-555555555556")

	_, err := signCertificate(context.Background(), signer, ids, testPlan(t), testIssuerSecret(t), keyMaterialID, domain.CertificateKindLeaf, "")
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindUnavailable {
		t.Fatalf("err = %v, want an unavailable AppError", err)
	}
	if !errors.Is(err, failure) {
		t.Fatalf("err = %v, want it to wrap the original failure", err)
	}
}

func TestPrepareCertificateComposesKeyResolutionAndSigning(t *testing.T) {
	engine := &fakeKeyEngine{}
	signer := &fakeSigner{}
	ids := &seqIDs{}
	keyMaterialID, err := domain.ParseKeyMaterialID("22222222-3333-4444-8555-666666666666")
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}
	spec := port.KeySpec{KeyMaterialID: keyMaterialID, Algorithm: domain.KeyAlgorithmECDSAP256, Purpose: domain.SecretPurposeLeafDelivery}

	prepared, err := prepareCertificate(context.Background(), engine, signer, ids, testPlan(t), signingKeyRef{Fresh: &spec}, testIssuerSecret(t), domain.CertificateKindLeaf, "")
	if err != nil {
		t.Fatalf("prepareCertificate: %v", err)
	}
	if prepared.KeyMaterialID != keyMaterialID {
		t.Fatalf("key material id = %s, want %s", prepared.KeyMaterialID, keyMaterialID)
	}
	if prepared.Certificate.KeyMaterialID() != keyMaterialID {
		t.Fatalf("certificate key material id = %s, want %s", prepared.Certificate.KeyMaterialID(), keyMaterialID)
	}
	if prepared.GeneratedSecret == nil {
		t.Fatal("want a generated secret to store for a fresh key")
	}
	if engine.generateCalls != 1 || signer.calls != 1 {
		t.Fatalf("generate calls = %d, sign calls = %d, want 1 and 1", engine.generateCalls, signer.calls)
	}
}

func TestPrepareCertificatePropagatesAKeyRefError(t *testing.T) {
	_, err := prepareCertificate(context.Background(), &fakeKeyEngine{}, &fakeSigner{}, &seqIDs{}, testPlan(t), signingKeyRef{}, testIssuerSecret(t), domain.CertificateKindLeaf, "")
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindValidation {
		t.Fatalf("err = %v, want a validation AppError", err)
	}
}
