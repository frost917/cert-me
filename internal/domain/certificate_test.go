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
		Kind:                    CertificateKindLeaf,
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

// newTestAuthorityWithKind builds an authority fixture of the given kind so
// PlanIssuance's issuer-kind enforcement can be exercised directly. Root and
// bootstrap fixtures must not carry a management parent.
func newTestAuthorityWithKind(t *testing.T, kind AuthorityKind, window ValidityWindow) Authority {
	t.Helper()
	facts := AuthorityFacts{
		ID:                AuthorityID("11111111-1111-1111-1111-111111111111"),
		Kind:              kind,
		Name:              "issuing-ca",
		IssuanceState:     IssuanceStateEnabled,
		KeyGenerationID:   CAKeyGenerationID("33333333-3333-3333-3333-333333333333"),
		KeyAvailable:      true,
		CertificateWindow: window,
		Version:           1,
	}
	if kind == AuthorityKindIntermediate {
		facts.ManagementParentID = AuthorityID("22222222-2222-2222-2222-222222222222")
	}
	a, err := NewAuthority(facts)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	return a
}

// TestPlanIssuance_OrdinaryLeafRequiresIntermediateIssuer covers P1 finding
// #1: an ordinary Leaf issuance (server_tls/client_mtls/dual) must be
// rejected when the issuer is a Root, and must succeed against an
// Intermediate. [data-model.md: "일반 Leaf issuer는 Intermediate ... 만 허용"]
func TestPlanIssuance_OrdinaryLeafRequiresIntermediateIssuer(t *testing.T) {
	window := mustWindow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	req := IssuanceRequest{
		Profile:      CertificateProfileServerTLS,
		Subject:      mustSubject(t, "svc.example.internal"),
		SANs:         []SAN{mustSAN(t, SANTypeDNS, "svc.example.internal")},
		KeyAlgorithm: KeyAlgorithmECDSAP256,
		Window:       mustWindow(t, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)),
	}

	root := newTestAuthorityWithKind(t, AuthorityKindRoot, window)
	if _, err := PlanIssuance(root, req, now); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("expected ErrNotPermitted issuing ordinary leaf from a root, got %v", err)
	}

	intermediate := newTestAuthorityWithKind(t, AuthorityKindIntermediate, window)
	if _, err := PlanIssuance(intermediate, req, now); err != nil {
		t.Fatalf("expected intermediate issuer to be accepted, got %v", err)
	}
}

// TestPlanBootstrapIssuance_RequiresBootstrapIssuer covers the bootstrap_tls
// exception as its own distinct path: only a bootstrap-kind authority may
// sign a bootstrap_tls leaf, and an ordinary Intermediate must not be usable
// through this path either.
func TestPlanBootstrapIssuance_RequiresBootstrapIssuer(t *testing.T) {
	window := mustWindow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	req := IssuanceRequest{
		Profile:      CertificateProfileServerTLS,
		Subject:      mustSubject(t, "cert-me.internal"),
		SANs:         []SAN{mustSAN(t, SANTypeDNS, "cert-me.internal")},
		KeyAlgorithm: KeyAlgorithmECDSAP256,
		Window:       mustWindow(t, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)),
	}

	bootstrap := newTestAuthorityWithKind(t, AuthorityKindBootstrap, window)
	if _, err := PlanBootstrapIssuance(bootstrap, req, now); err != nil {
		t.Fatalf("expected bootstrap issuer to be accepted on the bootstrap path, got %v", err)
	}

	intermediate := newTestAuthorityWithKind(t, AuthorityKindIntermediate, window)
	if _, err := PlanBootstrapIssuance(intermediate, req, now); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("expected ErrNotPermitted for intermediate issuer on the bootstrap path, got %v", err)
	}
}

// TestNewCertificate_CAKindSkipsLeafProfileValidation covers P1 finding #3: a
// Root/Intermediate certificate has no Leaf profile concept and must be
// constructible with no SANs and no profile.
func TestNewCertificate_CAKindSkipsLeafProfileValidation(t *testing.T) {
	window := mustWindow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	_, err := NewCertificate(CertificateFacts{
		ID:                      CertificateID("44444444-4444-4444-4444-444444444444"),
		DER:                     []byte{0x01, 0x02, 0x03},
		KeyMaterialID:           KeyMaterialID("55555555-5555-5555-5555-555555555555"),
		IssuerCAKeyGenerationID: CAKeyGenerationID("33333333-3333-3333-3333-333333333333"),
		Serial:                  mustSerial(t, "1"),
		Validity:                window,
		Subject:                 mustSubject(t, "Example Root CA"),
		Kind:                    CertificateKindCA,
		KeyAlgorithm:            KeyAlgorithmECDSAP256,
		Origin:                  CertificateOriginGenerated,
		Version:                 1,
	})
	if err != nil {
		t.Fatalf("expected ca certificate with no sans/profile to be constructible, got %v", err)
	}
}

// TestNewSAN_RejectsBogusIPAndDNS covers P2 finding #4: SAN construction must
// reject syntactically invalid IP and DNS values rather than passing them
// through untouched.
func TestNewSAN_RejectsBogusIPAndDNS(t *testing.T) {
	if _, err := NewSAN(SANTypeIP, "not-an-ip"); err == nil {
		t.Fatal("expected error for invalid ip san")
	}
	if _, err := NewSAN(SANTypeDNS, "bad name.internal"); err == nil {
		t.Fatal("expected error for dns san containing a space")
	}
}

// TestPlanSubordinateCAIssuance_RequiresRootIssuer covers the third issuance
// path. Restricting ordinary Leaf issuance to an Intermediate must not leave a
// Root unable to sign the Intermediate CA it is the parent of, which
// docs/data-model.md requires ("관리 parent는 MVP에서 Root→Intermediate만
// 허용하고 루프를 거부한다") and AuthorityService.Create depends on.
func TestPlanSubordinateCAIssuance_RequiresRootIssuer(t *testing.T) {
	window := mustWindow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC))
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	// A subordinate CA request carries no leaf profile and no SANs.
	req := IssuanceRequest{
		Subject:      mustSubject(t, "cert-me issuing ca"),
		KeyAlgorithm: KeyAlgorithmECDSAP256,
		Window:       mustWindow(t, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)),
	}

	root := newTestAuthorityWithKind(t, AuthorityKindRoot, window)
	plan, err := PlanSubordinateCAIssuance(root, req, now)
	if err != nil {
		t.Fatalf("expected a root to sign a subordinate ca, got %v", err)
	}
	if plan.IssuerAuthorityID != root.ID() {
		t.Errorf("plan issuer = %q, want the root %q", plan.IssuerAuthorityID, root.ID())
	}
	if plan.Profile != "" {
		t.Errorf("subordinate ca plan carries profile %q, want none", plan.Profile)
	}

	// The other kinds must not reach this path.
	for _, kind := range []AuthorityKind{AuthorityKindIntermediate, AuthorityKindBootstrap} {
		issuer := newTestAuthorityWithKind(t, kind, window)
		if _, err := PlanSubordinateCAIssuance(issuer, req, now); !errors.Is(err, ErrNotPermitted) {
			t.Errorf("PlanSubordinateCAIssuance from %s = %v, want ErrNotPermitted", kind, err)
		}
	}

	// And the CA path must not accept a leaf-shaped request.
	leafShaped := req
	leafShaped.Profile = CertificateProfileServerTLS
	leafShaped.SANs = []SAN{mustSAN(t, SANTypeDNS, "svc.example.internal")}
	if _, err := PlanSubordinateCAIssuance(root, leafShaped, now); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("subordinate ca request with a leaf profile = %v, want ErrInvalidValue", err)
	}
}

// TestIssuanceIntent_UnknownIsRejected keeps an unrecognised intent from
// defaulting into an allowed path.
func TestIssuanceIntent_UnknownIsRejected(t *testing.T) {
	window := mustWindow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	issuer := newTestAuthorityWithKind(t, AuthorityKindIntermediate, window)
	ctx := IssuerContext{Intent: IssuanceIntent("anything_else")}
	if err := issuer.CanIssue(ctx, now); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("CanIssue with an unknown intent = %v, want ErrInvalidValue", err)
	}
}
