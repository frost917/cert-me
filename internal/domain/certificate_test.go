package domain

import (
	"errors"
	"testing"
	"time"
)

func mustSubject(t *testing.T, cn string) Subject {
	t.Helper()
	s, err := NewSubject(SubjectFacts{CommonName: cn})
	if err != nil {
		t.Fatalf("NewSubject: %v", err)
	}
	return s
}

func mustSAN(t *testing.T, kind SANType, value string) SAN {
	t.Helper()
	s, err := NewSAN(kind, value)
	if err != nil {
		t.Fatalf("NewSAN(%s,%s): %v", kind, value, err)
	}
	return s
}

func mustWindow(t *testing.T, notBefore, notAfter time.Time) ValidityWindow {
	t.Helper()
	w, err := NewValidityWindow(NewInstant(notBefore), NewInstant(notAfter))
	if err != nil {
		t.Fatalf("NewValidityWindow: %v", err)
	}
	return w
}

func TestNewSAN_DNSWildcardRules(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"plain", "example.internal", false},
		{"leftmost wildcard", "*.example.internal", false},
		{"nested wildcard rejected", "a.*.example.internal", true},
		{"partial label wildcard rejected", "*foo.example.internal", true},
		{"single label rejected", "localhost", true},
		{"empty label rejected", "example..internal", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSAN(SANTypeDNS, tc.value)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.value, err)
			}
		})
	}
}

func TestNewSAN_URIMustBeAbsolute(t *testing.T) {
	if _, err := NewSAN(SANTypeURI, "/relative/path"); err == nil {
		t.Fatal("expected error for relative uri")
	}
	if _, err := NewSAN(SANTypeURI, "spiffe://example.internal/svc"); err != nil {
		t.Fatalf("unexpected error for absolute uri: %v", err)
	}
}

func TestValidateSANsForProfile(t *testing.T) {
	dnsSAN := mustSAN(t, SANTypeDNS, "svc.example.internal")

	cases := []struct {
		name    string
		profile CertificateProfile
		sans    []SAN
		wantErr bool
	}{
		{"server_tls needs san", CertificateProfileServerTLS, nil, true},
		{"server_tls with dns ok", CertificateProfileServerTLS, []SAN{dnsSAN}, false},
		{"dual needs san", CertificateProfileDual, nil, true},
		{"client_mtls no san required", CertificateProfileClientMTLS, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSANsForProfile(tc.profile, tc.sans)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && !errors.Is(err, ErrPolicyViolation) {
				t.Fatalf("expected ErrPolicyViolation, got %v", err)
			}
		})
	}
}

func newTestAuthority(t *testing.T, window ValidityWindow, state IssuanceState) Authority {
	t.Helper()
	a, err := NewAuthority(AuthorityFacts{
		ID:                 AuthorityID("11111111-1111-1111-1111-111111111111"),
		Kind:               AuthorityKindIntermediate,
		Name:               "issuing-ca",
		ManagementParentID: AuthorityID("22222222-2222-2222-2222-222222222222"),
		IssuanceState:      state,
		KeyGenerationID:    CAKeyGenerationID("33333333-3333-3333-3333-333333333333"),
		KeyAvailable:       true,
		CertificateWindow:  window,
		Version:            1,
	})
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	return a
}

func TestCertificate_IsValidAt(t *testing.T) {
	window := mustWindow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	cert, err := NewCertificate(CertificateFacts{
		ID:                      CertificateID("44444444-4444-4444-4444-444444444444"),
		DER:                     []byte{0x01, 0x02, 0x03},
		KeyMaterialID:           KeyMaterialID("55555555-5555-5555-5555-555555555555"),
		IssuerCAKeyGenerationID: CAKeyGenerationID("33333333-3333-3333-3333-333333333333"),
		Serial:                  mustSerial(t, "1"),
		Validity:                window,
		Subject:                 mustSubject(t, "svc.example.internal"),
		SANs:                    []SAN{mustSAN(t, SANTypeDNS, "svc.example.internal")},
		Profile:                 CertificateProfileServerTLS,
		KeyAlgorithm:            KeyAlgorithmECDSAP256,
		Origin:                  CertificateOriginGenerated,
		Version:                 1,
	})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}

	// DER must be copied, not aliased.
	der := cert.DER()
	der[0] = 0xff
	if cert.DER()[0] != 0x01 {
		t.Fatal("Certificate.DER() leaked mutable backing array")
	}

	inside := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if !cert.IsValidAt(inside) {
		t.Fatal("expected certificate to be valid mid-window")
	}
	// now >= not_after is expired (project-wide rule).
	atExpiry := NewInstant(window.NotAfter().Time())
	if cert.IsValidAt(atExpiry) {
		t.Fatal("expected certificate to be invalid exactly at not_after")
	}
}

func mustSerial(t *testing.T, hex string) SerialNumber {
	t.Helper()
	s, err := ParseSerialNumber(hex)
	if err != nil {
		t.Fatalf("ParseSerialNumber: %v", err)
	}
	return s
}

// TestPlanIssuance_RejectsPeriodExceedingIssuer verifies the mandatory B01
// rule: a leaf validity window that extends beyond the issuer's own window is
// rejected outright, not silently clamped.
func TestPlanIssuance_RejectsPeriodExceedingIssuer(t *testing.T) {
	issuerWindow := mustWindow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
	authority := newTestAuthority(t, issuerWindow, IssuanceStateEnabled)

	req := IssuanceRequest{
		Profile:      CertificateProfileServerTLS,
		Subject:      mustSubject(t, "svc.example.internal"),
		SANs:         []SAN{mustSAN(t, SANTypeDNS, "svc.example.internal")},
		KeyAlgorithm: KeyAlgorithmECDSAP256,
		Window:       mustWindow(t, time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC)), // extends past issuer notAfter
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	_, err := PlanIssuance(authority, req, now)
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("expected ErrPolicyViolation for over-length request, got %v", err)
	}
}

func TestPlanIssuance_AcceptsCoveredWindow(t *testing.T) {
	issuerWindow := mustWindow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	authority := newTestAuthority(t, issuerWindow, IssuanceStateEnabled)

	req := IssuanceRequest{
		Profile:      CertificateProfileServerTLS,
		Subject:      mustSubject(t, "svc.example.internal"),
		SANs:         []SAN{mustSAN(t, SANTypeDNS, "svc.example.internal")},
		KeyAlgorithm: KeyAlgorithmECDSAP256,
		Window:       mustWindow(t, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)),
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	plan, err := PlanIssuance(authority, req, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.IssuerAuthorityID != authority.ID() {
		t.Fatalf("plan issuer mismatch: got %s", plan.IssuerAuthorityID)
	}
}

func TestPlanIssuance_RejectsStoppedIssuer(t *testing.T) {
	issuerWindow := mustWindow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	authority := newTestAuthority(t, issuerWindow, IssuanceStateStopped)

	req := IssuanceRequest{
		Profile:      CertificateProfileServerTLS,
		Subject:      mustSubject(t, "svc.example.internal"),
		SANs:         []SAN{mustSAN(t, SANTypeDNS, "svc.example.internal")},
		KeyAlgorithm: KeyAlgorithmECDSAP256,
		Window:       mustWindow(t, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)),
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	_, err := PlanIssuance(authority, req, now)
	if !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("expected ErrNotPermitted for stopped issuer, got %v", err)
	}
}
