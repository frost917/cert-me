package service

import (
	"context"
	"errors"
	"testing"
	"time"

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

// testIssuerCertificate is the CA public certificate a §14.10
// CertificateSigningRequest.IssuerCertificate carries. Its own identity does
// not matter to signCertificate/verifySignedCertificate (they never inspect
// it), only that it is non-empty so SelfSigned() reads false, matching an
// ordinary (non-Root) issuance.
func testIssuerCertificate(t *testing.T) domain.Certificate {
	t.Helper()
	id, err := domain.ParseCertificateID("99999999-8888-4777-8666-555555555555")
	if err != nil {
		t.Fatalf("issuer certificate id: %v", err)
	}
	keyMaterialID, err := domain.ParseKeyMaterialID("99999999-8888-4777-8666-555555555556")
	if err != nil {
		t.Fatalf("issuer key material id: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "Test Intermediate CA"})
	if err != nil {
		t.Fatalf("issuer subject: %v", err)
	}
	window, err := domain.NewValidityWindow(testNow(), testNow().Add(domain.NewDuration(24*365*5)))
	if err != nil {
		t.Fatalf("issuer window: %v", err)
	}
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      id,
		DER:                     []byte("issuer-cert-der"),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: caKeyID(t, 1),
		Serial:                  serial(t, "1"),
		Validity:                window,
		Subject:                 subject,
		Kind:                    domain.CertificateKindCA,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("issuer certificate: %v", err)
	}
	return cert
}

func testSigningRequest(t *testing.T, plan domain.IssuancePlan, keyMaterialID domain.KeyMaterialID) port.CertificateSigningRequest {
	t.Helper()
	certID, err := domain.ParseCertificateID("11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("certificate id: %v", err)
	}
	pub, err := domain.NewPublicKey(plan.KeyAlgorithm, []byte("subject-public-key-bytes-000000000"))
	if err != nil {
		t.Fatalf("subject public key: %v", err)
	}
	return port.CertificateSigningRequest{
		Plan:               plan,
		CertificateID:      certID,
		KeyMaterialID:      keyMaterialID,
		SubjectPublicKey:   pub,
		Serial:             serial(t, "abc"),
		Kind:               domain.CertificateKindLeaf,
		CreatedByAccountID: "",
		IssuerCertificate:  testIssuerCertificate(t),
	}
}

func TestSignCertificateReturnsWhatWasRequestedWhenItMatches(t *testing.T) {
	signer := &fakeSigner{}
	plan := testPlan(t)
	keyMaterialID, err := domain.ParseKeyMaterialID("11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}
	request := testSigningRequest(t, plan, keyMaterialID)

	cert, err := signCertificate(context.Background(), signer, request, testIssuerSecret(t))
	if err != nil {
		t.Fatalf("signCertificate: %v", err)
	}
	if cert.ID() != request.CertificateID {
		t.Fatalf("certificate id = %s, want %s", cert.ID(), request.CertificateID)
	}
	if cert.KeyMaterialID() != keyMaterialID {
		t.Fatalf("certificate key material id = %s, want %s", cert.KeyMaterialID(), keyMaterialID)
	}
	if !cert.Serial().Equal(request.Serial) {
		t.Fatalf("certificate serial = %s, want %s", cert.Serial().Hex(), request.Serial.Hex())
	}
	if cert.Subject().CommonName() != plan.Subject.CommonName() {
		t.Fatalf("certificate subject = %+v, want %+v", cert.Subject(), plan.Subject)
	}
	if !cert.Validity().NotBefore().Equal(plan.Window.NotBefore()) {
		t.Fatal("certificate validity does not match the requested plan window")
	}
	if len(signer.requests) != 1 {
		t.Fatalf("signer received %d requests, want 1", len(signer.requests))
	}
}

func TestSignCertificatePropagatesASignFailure(t *testing.T) {
	failure := errors.New("signing backend down")
	signer := &fakeSigner{fail: failure}
	plan := testPlan(t)
	keyMaterialID, _ := domain.ParseKeyMaterialID("11111111-2222-4333-8444-555555555556")
	request := testSigningRequest(t, plan, keyMaterialID)

	_, err := signCertificate(context.Background(), signer, request, testIssuerSecret(t))
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindUnavailable {
		t.Fatalf("err = %v, want an unavailable AppError", err)
	}
	if !errors.Is(err, failure) {
		t.Fatalf("err = %v, want it to wrap the original failure", err)
	}
}

// §14.10 requires the app to reject a signer response that does not match
// what was asked for, field by field, rather than rebuilding metadata around
// whatever DER came back. Each case below asks the fake signer to return a
// certificate differing from the request in exactly one respect.
func TestSignCertificateRejectsAMismatchedResponse(t *testing.T) {
	plan := testPlan(t)
	keyMaterialID, err := domain.ParseKeyMaterialID("11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}

	otherCertID, _ := domain.ParseCertificateID("22222222-2222-4222-8222-222222222222")
	otherKeyMaterialID, _ := domain.ParseKeyMaterialID("33333333-3333-4333-8333-333333333333")
	otherSerial := serial(t, "def")
	otherSubject, _ := domain.NewSubject(domain.SubjectFacts{CommonName: "wrong.example.internal"})
	otherSAN := mustSAN(t, "dns", "wrong.example.internal")
	otherWindow, err := domain.NewValidityWindow(testNow().Add(domain.NewDuration(time.Hour)), testNow().Add(domain.NewDuration(2*time.Hour)))
	if err != nil {
		t.Fatalf("other window: %v", err)
	}
	otherIssuerKeyGenID := caKeyID(t, 2)

	for _, tc := range []struct {
		name   string
		field  string
		mutate func(domain.CertificateFacts) domain.CertificateFacts
	}{
		{"certificate_id", "certificate_id", func(f domain.CertificateFacts) domain.CertificateFacts { f.ID = otherCertID; return f }},
		{"key_material_id", "key_material_id", func(f domain.CertificateFacts) domain.CertificateFacts {
			f.KeyMaterialID = otherKeyMaterialID
			return f
		}},
		{"serial", "serial", func(f domain.CertificateFacts) domain.CertificateFacts { f.Serial = otherSerial; return f }},
		{"issuer_ca_key_generation_id", "issuer_ca_key_generation_id", func(f domain.CertificateFacts) domain.CertificateFacts {
			f.IssuerCAKeyGenerationID = otherIssuerKeyGenID
			return f
		}},
		{"kind", "kind", func(f domain.CertificateFacts) domain.CertificateFacts {
			// A CA-kind certificate must carry no Leaf profile/SANs
			// (domain.NewCertificate), so both are cleared here to isolate
			// the mismatch to Kind alone rather than tripping that
			// unrelated construction rule instead.
			f.Kind = domain.CertificateKindCA
			f.Profile = ""
			f.SANs = nil
			return f
		}},
		{"profile", "profile", func(f domain.CertificateFacts) domain.CertificateFacts {
			f.Profile = domain.CertificateProfileClientMTLS
			return f
		}},
		{"key_algorithm", "key_algorithm", func(f domain.CertificateFacts) domain.CertificateFacts {
			f.KeyAlgorithm = domain.KeyAlgorithmRSA2048
			return f
		}},
		{"validity", "validity", func(f domain.CertificateFacts) domain.CertificateFacts { f.Validity = otherWindow; return f }},
		{"subject", "subject", func(f domain.CertificateFacts) domain.CertificateFacts { f.Subject = otherSubject; return f }},
		{"sans", "sans", func(f domain.CertificateFacts) domain.CertificateFacts { f.SANs = []domain.SAN{otherSAN}; return f }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := &fakeSigner{mutateFacts: tc.mutate}
			request := testSigningRequest(t, plan, keyMaterialID)

			_, err := signCertificate(context.Background(), signer, request, testIssuerSecret(t))
			var appErr *contract.AppError
			if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindUnavailable {
				t.Fatalf("err = %v, want an unavailable AppError", err)
			}
			if appErr.Code() != "issuance_signed_certificate_mismatch" {
				t.Fatalf("code = %q, want issuance_signed_certificate_mismatch", appErr.Code())
			}
			if got := appErr.PublicFields()["field"]; got != tc.field {
				t.Fatalf("mismatch field = %q, want %q", got, tc.field)
			}
		})
	}
}

func TestPrepareCertificateComposesKeyResolutionAndSigning(t *testing.T) {
	engine := &fakeKeyEngine{}
	signer := &fakeSigner{}
	serials := &fakeSerialGenerator{}
	keyMaterialID, err := domain.ParseKeyMaterialID("22222222-3333-4444-8555-666666666666")
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}
	certID, err := domain.ParseCertificateID("44444444-4444-4444-8444-444444444444")
	if err != nil {
		t.Fatalf("certificate id: %v", err)
	}
	spec := port.KeySpec{KeyMaterialID: keyMaterialID, Algorithm: domain.KeyAlgorithmECDSAP256, Purpose: domain.SecretPurposeLeafDelivery}

	prepared, err := prepareCertificate(context.Background(), engine, signer, serials, testPlan(t), signingKeyRef{Fresh: &spec},
		domain.PublicKey{}, certID, testIssuerCertificate(t), testIssuerSecret(t), domain.CertificateKindLeaf, "", nil)
	if err != nil {
		t.Fatalf("prepareCertificate: %v", err)
	}
	if prepared.KeyMaterialID != keyMaterialID {
		t.Fatalf("key material id = %s, want %s", prepared.KeyMaterialID, keyMaterialID)
	}
	if prepared.Certificate.KeyMaterialID() != keyMaterialID {
		t.Fatalf("certificate key material id = %s, want %s", prepared.Certificate.KeyMaterialID(), keyMaterialID)
	}
	if prepared.Certificate.ID() != certID {
		t.Fatalf("certificate id = %s, want %s", prepared.Certificate.ID(), certID)
	}
	if prepared.GeneratedSecret == nil {
		t.Fatal("want a generated secret to store for a fresh key")
	}
	if engine.generateCalls != 1 || signer.calls != 1 {
		t.Fatalf("generate calls = %d, sign calls = %d, want 1 and 1", engine.generateCalls, signer.calls)
	}
	// §14.10: the signer must actually receive the subject public key
	// resolveSigningKey generated, the app-chosen certificate/key material
	// ids and the serial SerialGenerator minted.
	got := signer.requests[0]
	if got.SubjectPublicKey.IsZero() {
		t.Fatal("signer did not receive a subject public key")
	}
	if got.CertificateID != certID {
		t.Fatalf("signer received certificate id %s, want %s", got.CertificateID, certID)
	}
	if got.KeyMaterialID != keyMaterialID {
		t.Fatalf("signer received key material id %s, want %s", got.KeyMaterialID, keyMaterialID)
	}
	if got.Serial.IsZero() {
		t.Fatal("signer received a zero serial")
	}
	if got.IssuerCertificate.ID() == "" {
		t.Fatal("signer did not receive an issuer certificate")
	}
}

func TestPrepareCertificatePropagatesAKeyRefError(t *testing.T) {
	certID, _ := domain.ParseCertificateID("55555555-5555-4555-8555-555555555555")
	_, err := prepareCertificate(context.Background(), &fakeKeyEngine{}, &fakeSigner{}, &fakeSerialGenerator{}, testPlan(t), signingKeyRef{},
		domain.PublicKey{}, certID, testIssuerCertificate(t), testIssuerSecret(t), domain.CertificateKindLeaf, "", nil)
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindValidation {
		t.Fatalf("err = %v, want a validation AppError", err)
	}
}
