package domain

import (
	"errors"
	"testing"
	"time"
)

func baseAuthorityFacts() AuthorityFacts {
	return AuthorityFacts{
		ID:                 AuthorityID("11111111-1111-1111-1111-111111111111"),
		Kind:               AuthorityKindIntermediate,
		Name:               "issuing-ca",
		ManagementParentID: AuthorityID("22222222-2222-2222-2222-222222222222"),
		IssuanceState:      IssuanceStateEnabled,
		KeyGenerationID:    CAKeyGenerationID("33333333-3333-3333-3333-333333333333"),
		KeyAvailable:       true,
		CertificateWindow: mustWindowFacts(
			time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
		),
		Version: 1,
	}
}

func mustWindowFacts(nb, na time.Time) ValidityWindow {
	w, err := NewValidityWindow(NewInstant(nb), NewInstant(na))
	if err != nil {
		panic(err)
	}
	return w
}

func TestAuthority_CanIssue(t *testing.T) {
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	insideWindow := mustWindowFacts(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))
	overLength := mustWindowFacts(time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC))

	cases := []struct {
		name    string
		mutate  func(AuthorityFacts) AuthorityFacts
		ctx     IssuerContext
		wantErr error
	}{
		{
			name:    "enabled key available covers window: ok",
			mutate:  func(f AuthorityFacts) AuthorityFacts { return f },
			ctx:     IssuerContext{RequestedWindow: insideWindow},
			wantErr: nil,
		},
		{
			name: "stopped issuer rejected",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.IssuanceState = IssuanceStateStopped
				return f
			},
			ctx:     IssuerContext{RequestedWindow: insideWindow},
			wantErr: ErrNotPermitted,
		},
		{
			name: "inventory issuer rejected",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.IssuanceState = IssuanceStateInventory
				return f
			},
			ctx:     IssuerContext{RequestedWindow: insideWindow},
			wantErr: ErrNotPermitted,
		},
		{
			name: "key unavailable rejected",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.KeyAvailable = false
				return f
			},
			ctx:     IssuerContext{RequestedWindow: insideWindow},
			wantErr: ErrNotPermitted,
		},
		{
			name: "compromise impact rejected",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.Affected = true
				return f
			},
			ctx:     IssuerContext{RequestedWindow: insideWindow},
			wantErr: ErrNotPermitted,
		},
		{
			name: "pending unconfirmed takeover rejected",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.PendingTakeover = true
				return f
			},
			ctx:     IssuerContext{RequestedWindow: insideWindow},
			wantErr: ErrNotPermitted,
		},
		{
			name: "pending confirmed takeover allowed",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.PendingTakeover = true
				return f
			},
			ctx:     IssuerContext{RequestedWindow: insideWindow, TakeoverConfirmed: true},
			wantErr: nil,
		},
		{
			name: "expired issuer certificate rejected",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.CertificateWindow = mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
				return f
			},
			ctx:     IssuerContext{RequestedWindow: insideWindow},
			wantErr: ErrNotPermitted,
		},
		{
			name:    "requested window exceeding issuer period rejected",
			mutate:  func(f AuthorityFacts) AuthorityFacts { return f },
			ctx:     IssuerContext{RequestedWindow: overLength},
			wantErr: ErrPolicyViolation,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := tc.mutate(baseAuthorityFacts())
			authority, err := NewAuthority(facts)
			if err != nil {
				t.Fatalf("NewAuthority: %v", err)
			}
			err = authority.CanIssue(tc.ctx, now)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestAuthority_StopIssuanceSeparateFromCRLSigning(t *testing.T) {
	authority, err := NewAuthority(baseAuthorityFacts())
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	stopped, err := authority.StopIssuance()
	if err != nil {
		t.Fatalf("StopIssuance: %v", err)
	}
	if stopped.IssuanceState() != IssuanceStateStopped {
		t.Fatalf("expected stopped state, got %s", stopped.IssuanceState())
	}
	if stopped.Version() != authority.Version().Next() {
		t.Fatalf("expected version bump")
	}
	// Original value must be unchanged (pure transition).
	if authority.IssuanceState() != IssuanceStateEnabled {
		t.Fatal("StopIssuance mutated the receiver")
	}

	// Stopping issuance blocks new issuance...
	if err := stopped.CanIssue(IssuerContext{}, now); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("expected issuance blocked, got %v", err)
	}
	// ...but CRL signing continues.
	if err := stopped.CanSignCRL(now); err != nil {
		t.Fatalf("expected stopped authority to still sign CRLs, got %v", err)
	}

	// Stopping again is an invalid transition.
	if _, err := stopped.StopIssuance(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition re-stopping, got %v", err)
	}
}

func TestAuthority_CanSignCRL_RequiresKeyAvailable(t *testing.T) {
	facts := baseAuthorityFacts()
	facts.KeyAvailable = false
	authority, err := NewAuthority(facts)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err := authority.CanSignCRL(now); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("expected ErrNotPermitted, got %v", err)
	}
}

func TestAuthority_ConfirmTakeoverClearsOnlyPendingGate(t *testing.T) {
	facts := baseAuthorityFacts()
	facts.PendingTakeover = true
	facts.IssuanceState = IssuanceStateStopped
	authority, err := NewAuthority(facts)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}

	confirmed, err := authority.ConfirmTakeover()
	if err != nil {
		t.Fatalf("ConfirmTakeover: %v", err)
	}
	if confirmed.PendingTakeover() {
		t.Fatal("confirmed authority still has a pending takeover")
	}
	if confirmed.IssuanceState() != IssuanceStateStopped {
		t.Fatalf("issuance state = %s, want stopped", confirmed.IssuanceState())
	}
	if confirmed.KeyAvailable() != authority.KeyAvailable() {
		t.Fatal("ConfirmTakeover changed key availability")
	}
	if confirmed.Version() != authority.Version().Next() {
		t.Fatalf("version = %d, want %d", confirmed.Version(), authority.Version().Next())
	}
	if !authority.PendingTakeover() {
		t.Fatal("ConfirmTakeover mutated the receiver")
	}
	if _, err := confirmed.ConfirmTakeover(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("second ConfirmTakeover = %v, want ErrInvalidTransition", err)
	}
}

// TestAuthority_CanIssue_FullValidityWindow covers P1 finding #2: CanIssue
// must reject issuance both before the CA's own notBefore and at/after its
// notAfter, and must reject a missing (zero) certificate window outright.
func TestAuthority_CanIssue_FullValidityWindow(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(AuthorityFacts) AuthorityFacts
		now    time.Time
	}{
		{
			name: "notBefore not yet reached",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.CertificateWindow = mustWindowFacts(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
				return f
			},
			now: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "notAfter reached",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.CertificateWindow = mustWindowFacts(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
				return f
			},
			now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), // == notAfter: expired under project rule
		},
		{
			name: "missing certificate window",
			mutate: func(f AuthorityFacts) AuthorityFacts {
				f.CertificateWindow = ValidityWindow{}
				return f
			},
			now: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := tc.mutate(baseAuthorityFacts())
			authority, err := NewAuthority(facts)
			if err != nil {
				t.Fatalf("NewAuthority: %v", err)
			}
			now := NewInstant(tc.now)
			err = authority.CanIssue(IssuerContext{}, now)
			if !errors.Is(err, ErrNotPermitted) {
				t.Fatalf("expected ErrNotPermitted, got %v", err)
			}
		})
	}
}

// TestAuthority_CanSignCRL_EnforcesValidityWindow covers P1 finding #2: CRL
// signing must also check the CA certificate's own window (notBefore and
// notAfter), while remaining allowed for a stopped-but-valid authority.
func TestAuthority_CanSignCRL_EnforcesValidityWindow(t *testing.T) {
	t.Run("notBefore not yet reached rejected", func(t *testing.T) {
		facts := baseAuthorityFacts()
		facts.CertificateWindow = mustWindowFacts(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
		authority, err := NewAuthority(facts)
		if err != nil {
			t.Fatalf("NewAuthority: %v", err)
		}
		now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
		if err := authority.CanSignCRL(now); !errors.Is(err, ErrNotPermitted) {
			t.Fatalf("expected ErrNotPermitted, got %v", err)
		}
	})

	t.Run("notAfter reached rejected", func(t *testing.T) {
		facts := baseAuthorityFacts()
		facts.CertificateWindow = mustWindowFacts(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		authority, err := NewAuthority(facts)
		if err != nil {
			t.Fatalf("NewAuthority: %v", err)
		}
		now := NewInstant(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		if err := authority.CanSignCRL(now); !errors.Is(err, ErrNotPermitted) {
			t.Fatalf("expected ErrNotPermitted, got %v", err)
		}
	})

	t.Run("missing certificate window rejected", func(t *testing.T) {
		facts := baseAuthorityFacts()
		facts.CertificateWindow = ValidityWindow{}
		authority, err := NewAuthority(facts)
		if err != nil {
			t.Fatalf("NewAuthority: %v", err)
		}
		now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
		if err := authority.CanSignCRL(now); !errors.Is(err, ErrNotPermitted) {
			t.Fatalf("expected ErrNotPermitted, got %v", err)
		}
	})

	t.Run("stopped but still valid CA can still sign crls", func(t *testing.T) {
		facts := baseAuthorityFacts()
		facts.IssuanceState = IssuanceStateStopped
		authority, err := NewAuthority(facts)
		if err != nil {
			t.Fatalf("NewAuthority: %v", err)
		}
		now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
		if err := authority.CanSignCRL(now); err != nil {
			t.Fatalf("expected stopped-but-valid authority to sign crls, got %v", err)
		}
	})
}

func TestAuthority_CanDestroyKey(t *testing.T) {
	now := NewInstant(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))

	t.Run("blocked while still enabled", func(t *testing.T) {
		authority, err := NewAuthority(baseAuthorityFacts())
		if err != nil {
			t.Fatalf("NewAuthority: %v", err)
		}
		err = authority.CanDestroyKey(ClosureFacts{AllDependentCertificatesExpired: true, RequiredCRLsPublished: true}, now)
		if !errors.Is(err, ErrNotPermitted) {
			t.Fatalf("expected ErrNotPermitted, got %v", err)
		}
	})

	t.Run("blocked without dependents expired", func(t *testing.T) {
		facts := baseAuthorityFacts()
		facts.IssuanceState = IssuanceStateStopped
		authority, err := NewAuthority(facts)
		if err != nil {
			t.Fatalf("NewAuthority: %v", err)
		}
		err = authority.CanDestroyKey(ClosureFacts{AllDependentCertificatesExpired: false, RequiredCRLsPublished: true}, now)
		if !errors.Is(err, ErrNotPermitted) {
			t.Fatalf("expected ErrNotPermitted, got %v", err)
		}
	})

	t.Run("blocked without required crls published", func(t *testing.T) {
		facts := baseAuthorityFacts()
		facts.IssuanceState = IssuanceStateStopped
		authority, err := NewAuthority(facts)
		if err != nil {
			t.Fatalf("NewAuthority: %v", err)
		}
		err = authority.CanDestroyKey(ClosureFacts{AllDependentCertificatesExpired: true, RequiredCRLsPublished: false}, now)
		if !errors.Is(err, ErrNotPermitted) {
			t.Fatalf("expected ErrNotPermitted, got %v", err)
		}
	})

	t.Run("allowed once stopped, expired, and crls published", func(t *testing.T) {
		facts := baseAuthorityFacts()
		facts.IssuanceState = IssuanceStateStopped
		authority, err := NewAuthority(facts)
		if err != nil {
			t.Fatalf("NewAuthority: %v", err)
		}
		err = authority.CanDestroyKey(ClosureFacts{AllDependentCertificatesExpired: true, RequiredCRLsPublished: true}, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("already destroyed key rejected", func(t *testing.T) {
		facts := baseAuthorityFacts()
		facts.IssuanceState = IssuanceStateStopped
		facts.KeyAvailable = false
		authority, err := NewAuthority(facts)
		if err != nil {
			t.Fatalf("NewAuthority: %v", err)
		}
		err = authority.CanDestroyKey(ClosureFacts{AllDependentCertificatesExpired: true, RequiredCRLsPublished: true}, now)
		if !errors.Is(err, ErrAlreadyConsumed) {
			t.Fatalf("expected ErrAlreadyConsumed, got %v", err)
		}
	})
}

func TestAuthority_ArchiveDoesNotDestroyKeyAndDestroyedKeyMayFollow(t *testing.T) {
	facts := baseAuthorityFacts()
	facts.IssuanceState = IssuanceStateStopped
	authority, err := NewAuthority(facts)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	now := NewInstant(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	closure := ClosureFacts{AllDependentCertificatesExpired: true, RequiredCRLsPublished: true}

	archived, err := authority.Archive(closure, now)
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if !archived.IsArchived() || !archived.ArchivedAt().Equal(now) {
		t.Fatalf("archived_at = %v, want %v", archived.ArchivedAt(), now)
	}
	if !archived.KeyAvailable() {
		t.Fatal("Archive must not destroy the signing key")
	}

	destroyed, err := archived.DestroyKey(closure, now)
	if err != nil {
		t.Fatalf("DestroyKey after Archive: %v", err)
	}
	if destroyed.KeyAvailable() {
		t.Fatal("DestroyKey must make the signing key unavailable")
	}
}

func TestAuthority_AttachSigningKeyOnlyChangesAvailability(t *testing.T) {
	facts := baseAuthorityFacts()
	facts.IssuanceState = IssuanceStateInventory
	facts.KeyAvailable = false
	authority, err := NewAuthority(facts)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}

	attached, err := authority.AttachSigningKey()
	if err != nil {
		t.Fatalf("AttachSigningKey: %v", err)
	}
	if !attached.KeyAvailable() || attached.KeyGenerationID() != authority.KeyGenerationID() || attached.IssuanceState() != authority.IssuanceState() {
		t.Fatal("AttachSigningKey must preserve the existing generation and issuance state")
	}
	if attached.Version() != authority.Version().Next() {
		t.Fatalf("version = %v, want %v", attached.Version(), authority.Version().Next())
	}

	if _, err := attached.AttachSigningKey(); !errors.Is(err, ErrConflict) {
		t.Fatalf("second AttachSigningKey error = %v, want ErrConflict", err)
	}
	archived := attached
	archivedFacts := ClosureFacts{AllDependentCertificatesExpired: true, RequiredCRLsPublished: true}
	archived, err = archived.Archive(archivedFacts, NewInstant(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if _, err := archived.AttachSigningKey(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("AttachSigningKey after Archive error = %v, want ErrInvalidTransition", err)
	}
}
