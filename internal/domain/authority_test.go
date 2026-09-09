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
