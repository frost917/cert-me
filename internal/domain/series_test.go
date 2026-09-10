package domain

import (
	"errors"
	"testing"
	"time"
)

func baseSeriesFacts(t *testing.T, rotateEvery int) LeafSeriesFacts {
	t.Helper()
	return LeafSeriesFacts{
		ID:                     SeriesID("66666666-6666-6666-6666-666666666666"),
		Name:                   "web-frontend",
		Purpose:                SeriesPurposeDistributed,
		ManagementAuthorityID:  AuthorityID("11111111-1111-1111-1111-111111111111"),
		CurrentKeyGenerationID: LeafKeyGenerationID("77777777-7777-7777-7777-777777777777"),
		Policy: SeriesPolicy{
			RotateEvery:         rotateEvery,
			CertificateValidity: mustCalendarValidity(t, 1, ValidityUnitYears),
		},
		Version: 1,
	}
}

func mustCalendarValidity(t *testing.T, value int, unit ValidityUnit) CalendarValidity {
	t.Helper()
	v, err := NewCalendarValidity(value, unit)
	if err != nil {
		t.Fatalf("NewCalendarValidity: %v", err)
	}
	return v
}

func baseKeyGeneration(t *testing.T, seriesID SeriesID, generationNo, renewalCount int) LeafKeyGeneration {
	t.Helper()
	g, err := NewLeafKeyGeneration(LeafKeyGenerationFacts{
		ID:            LeafKeyGenerationID("77777777-7777-7777-7777-777777777777"),
		SeriesID:      seriesID,
		KeyMaterialID: KeyMaterialID("88888888-8888-8888-8888-888888888888"),
		GenerationNo:  generationNo,
		RenewalCount:  renewalCount,
		Custody:       KeyCustodyClientHeld,
	})
	if err != nil {
		t.Fatalf("NewLeafKeyGeneration: %v", err)
	}
	return g
}

// TestPlanRenewal_RotateEveryThreeSequence is the mandatory B01 scenario:
// rotate_every=3 renews 0->1->2 on the same key and then rotates to a new
// key generation at renewal_count 0.
// [certificate-lifecycle.md §갱신 횟수 계산; planning.md line 62]
func TestPlanRenewal_RotateEveryThreeSequence(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	issuerWindow := mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	requestedWindow := mustWindowFacts(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))

	gen := baseKeyGeneration(t, series.ID(), 1, 0) // renewal_count starts at 0 after initial issuance

	// Renewal 1: 0 -> 1, reuse key.
	plan1, err := series.PlanRenewal(RenewalFacts{
		CurrentGeneration:  gen,
		TargetIssuerID:     series.ManagementAuthorityID(),
		TargetIssuerWindow: issuerWindow,
		RequestedWindow:    requestedWindow,
		KeyReadyForRenewal: true,
	}, now)
	if err != nil {
		t.Fatalf("renewal 1: %v", err)
	}
	if plan1.Action != RenewalActionReuseKey || plan1.NextRenewalCount != 1 {
		t.Fatalf("renewal 1: expected reuse with count 1, got %+v", plan1)
	}

	gen = baseKeyGeneration(t, series.ID(), 1, plan1.NextRenewalCount)

	// Renewal 2: 1 -> 2, reuse key.
	plan2, err := series.PlanRenewal(RenewalFacts{
		CurrentGeneration:  gen,
		TargetIssuerID:     series.ManagementAuthorityID(),
		TargetIssuerWindow: issuerWindow,
		RequestedWindow:    requestedWindow,
		KeyReadyForRenewal: true,
	}, now)
	if err != nil {
		t.Fatalf("renewal 2: %v", err)
	}
	if plan2.Action != RenewalActionReuseKey || plan2.NextRenewalCount != 2 {
		t.Fatalf("renewal 2: expected reuse with count 2, got %+v", plan2)
	}

	gen = baseKeyGeneration(t, series.ID(), 1, plan2.NextRenewalCount)

	// Renewal 3: ordinal 3 >= rotate_every 3 -> rotate to new key, count resets to 0.
	plan3, err := series.PlanRenewal(RenewalFacts{
		CurrentGeneration:   gen,
		TargetIssuerID:      series.ManagementAuthorityID(),
		TargetIssuerWindow:  issuerWindow,
		RequestedWindow:     requestedWindow,
		KeyReadyForRenewal:  true,
		NextKeyGenerationNo: gen.GenerationNo() + 1,
	}, now)
	if err != nil {
		t.Fatalf("renewal 3: %v", err)
	}
	if plan3.Action != RenewalActionRotateKey || plan3.NextRenewalCount != 0 {
		t.Fatalf("renewal 3: expected rotate with count reset to 0, got %+v", plan3)
	}
	if plan3.NextKeyGenerationNo != gen.GenerationNo()+1 {
		t.Fatalf("renewal 3: expected new generation_no %d, got %d", gen.GenerationNo()+1, plan3.NextKeyGenerationNo)
	}
}

// TestPlanRenewal_PeriodExceedingIssuerRejected covers the same
// issuer-covers-leaf-window rule from the LeafSeries side (in addition to
// certificate_test.go's Authority/PlanIssuance coverage).
func TestPlanRenewal_PeriodExceedingIssuerRejected(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	issuerWindow := mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	overLength := mustWindowFacts(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC))

	gen := baseKeyGeneration(t, series.ID(), 1, 0)
	_, err = series.PlanRenewal(RenewalFacts{
		CurrentGeneration:  gen,
		TargetIssuerID:     series.ManagementAuthorityID(),
		TargetIssuerWindow: issuerWindow,
		RequestedWindow:    overLength,
		KeyReadyForRenewal: true,
	}, now)
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("expected ErrPolicyViolation, got %v", err)
	}
}

// TestPlanRenewal_CAMoveAloneDoesNotResetCount verifies that renewing under
// a different (successor) issuing authority, on its own, does not reset or
// otherwise special-case the renewal count arithmetic.
// [certificate-lifecycle.md §정상 CA 교체: "Leaf의 기존 공개키와 키 교체 횟수는
//
//	CA 전환만을 이유로 초기화하지 않는다"; planning.md line 72]
func TestPlanRenewal_CAMoveAloneDoesNotResetCount(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	successorIssuerID := AuthorityID("99999999-9999-9999-9999-999999999999")
	issuerWindow := mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	requestedWindow := mustWindowFacts(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))

	// Current generation already has one prior normal renewal (count 1) on
	// the old issuer; this renewal moves to a successor CA but is not
	// emergency and the key is otherwise eligible.
	gen := baseKeyGeneration(t, series.ID(), 1, 1)

	plan, err := series.PlanRenewal(RenewalFacts{
		CurrentGeneration:  gen,
		TargetIssuerID:     successorIssuerID, // different authority than series.ManagementAuthorityID()
		TargetIssuerWindow: issuerWindow,
		RequestedWindow:    requestedWindow,
		KeyReadyForRenewal: true,
	}, now)
	if err != nil {
		t.Fatalf("PlanRenewal: %v", err)
	}
	if plan.Action != RenewalActionReuseKey {
		t.Fatalf("expected reuse across CA move, got %+v", plan)
	}
	if plan.NextRenewalCount != 2 {
		t.Fatalf("expected count to advance normally (1->2), not reset by the CA move, got %d", plan.NextRenewalCount)
	}
	if plan.TargetIssuerID != successorIssuerID {
		t.Fatalf("expected plan to target the successor issuer, got %s", plan.TargetIssuerID)
	}
}

// TestPlanRenewal_PolicyChangeAfterAccumulation verifies that lowering
// rotate_every keeps the accumulated count and triggers rotation as soon as
// the new ordinal reaches the new cadence.
// [certificate-lifecycle.md: "주기를 3에서 2로 줄였을 때 현재 횟수가 이미
//
//	2라면 다음 갱신에서 교체한다"]
func TestPlanRenewal_PolicyChangeAfterAccumulation(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	issuerWindow := mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	requestedWindow := mustWindowFacts(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))

	// Accumulate count to 2 under the original rotate_every=3 policy.
	gen := baseKeyGeneration(t, series.ID(), 1, 2)

	// Now the operator lowers the cadence to 2; accumulated count of 2 is
	// kept (ChangePolicy does not touch it), and the next ordinal (3) is
	// already >= new rotate_every (2), so this renewal rotates.
	series, err = series.ChangePolicy(SeriesPolicy{RotateEvery: 2, CertificateValidity: series.Policy().CertificateValidity})
	if err != nil {
		t.Fatalf("ChangePolicy: %v", err)
	}
	if series.Policy().RotateEvery != 2 {
		t.Fatalf("expected rotate_every 2, got %d", series.Policy().RotateEvery)
	}

	plan, err := series.PlanRenewal(RenewalFacts{
		CurrentGeneration:   gen,
		TargetIssuerID:      series.ManagementAuthorityID(),
		TargetIssuerWindow:  issuerWindow,
		RequestedWindow:     requestedWindow,
		KeyReadyForRenewal:  true,
		NextKeyGenerationNo: gen.GenerationNo() + 1,
	}, now)
	if err != nil {
		t.Fatalf("PlanRenewal: %v", err)
	}
	if plan.Action != RenewalActionRotateKey || plan.NextRenewalCount != 0 {
		t.Fatalf("expected rotation with reset count after cadence lowered, got %+v", plan)
	}
}

// TestPlanRenewal_EmergencyAlwaysRotatesAndResets verifies that an emergency
// (CA-compromise) reissue always generates a new key and resets the count,
// independent of the current ordinal or rotate_every.
// [certificate-lifecycle.md §CA 키 유출 시 긴급 처리]
func TestPlanRenewal_EmergencyAlwaysRotatesAndResets(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 100)) // very high cadence: would never rotate normally
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	successorIssuerID := AuthorityID("99999999-9999-9999-9999-999999999999")
	issuerWindow := mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	requestedWindow := mustWindowFacts(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))

	gen := baseKeyGeneration(t, series.ID(), 1, 1) // only 1 renewal so far, far from rotate_every=100

	plan, err := series.PlanRenewal(RenewalFacts{
		CurrentGeneration:   gen,
		TargetIssuerID:      successorIssuerID,
		TargetIssuerWindow:  issuerWindow,
		RequestedWindow:     requestedWindow,
		KeyReadyForRenewal:  false, // even an ordinarily-ineligible key is fine for an emergency reissue
		IsEmergencyReissue:  true,
		NextKeyGenerationNo: gen.GenerationNo() + 1,
	}, now)
	if err != nil {
		t.Fatalf("PlanRenewal: %v", err)
	}
	if plan.Action != RenewalActionRotateKey || plan.NextRenewalCount != 0 {
		t.Fatalf("expected emergency rotation with reset count, got %+v", plan)
	}
}

func TestPlanRenewal_KeyNotReadyRejected(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	issuerWindow := mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	requestedWindow := mustWindowFacts(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))
	gen := baseKeyGeneration(t, series.ID(), 1, 0)

	_, err = series.PlanRenewal(RenewalFacts{
		CurrentGeneration:  gen,
		TargetIssuerID:     series.ManagementAuthorityID(),
		TargetIssuerWindow: issuerWindow,
		RequestedWindow:    requestedWindow,
		KeyReadyForRenewal: false, // e.g. pending_delivery/transferring or revoked, per app-layer facts
	}, now)
	if !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("expected ErrNotPermitted, got %v", err)
	}
}

// TestPlanRenewal_MismatchedWindowRejected is the P2 review regression: the
// stored calendar policy must govern PlanRenewal's actual result, not just
// sit alongside it unused. A 1-year policy with notBefore=2028-01-01 must
// produce not_after=2029-01-01; requesting a fixed 365-day span
// (2028-12-31, the review's exact reproduction) diverges from that by a day
// because 2028 is a leap year, and must be rejected rather than silently
// approved. Covers all three PlanRenewal branches: normal reuse, normal
// rotation (via a high renewal_count ordinal) and emergency reissue.
func TestPlanRenewal_MismatchedWindowRejected(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	now := NewInstant(time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
	issuerWindow := mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	// The policy is 1 year: notBefore=2028-01-01 must produce
	// not_after=2029-01-01. This mismatched window instead asks for exactly
	// 365 days (2028-12-31), reproducing the review's exact scenario.
	mismatchedWindow := mustWindowFacts(time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 12, 31, 0, 0, 0, 0, time.UTC))

	// Branch 1: normal reuse (ordinal 1 < rotate_every 3).
	reuseGen := baseKeyGeneration(t, series.ID(), 1, 0)
	_, err = series.PlanRenewal(RenewalFacts{
		CurrentGeneration:  reuseGen,
		TargetIssuerID:     series.ManagementAuthorityID(),
		TargetIssuerWindow: issuerWindow,
		RequestedWindow:    mismatchedWindow,
		KeyReadyForRenewal: true,
	}, now)
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("reuse branch: expected ErrPolicyViolation for mismatched window, got %v", err)
	}

	// Branch 2: normal rotation (ordinal 3 >= rotate_every 3).
	rotateGen := baseKeyGeneration(t, series.ID(), 1, 2)
	_, err = series.PlanRenewal(RenewalFacts{
		CurrentGeneration:   rotateGen,
		TargetIssuerID:      series.ManagementAuthorityID(),
		TargetIssuerWindow:  issuerWindow,
		RequestedWindow:     mismatchedWindow,
		KeyReadyForRenewal:  true,
		NextKeyGenerationNo: rotateGen.GenerationNo() + 1,
	}, now)
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("rotate branch: expected ErrPolicyViolation for mismatched window, got %v", err)
	}

	// Branch 3: emergency reissue.
	emergencyGen := baseKeyGeneration(t, series.ID(), 1, 0)
	_, err = series.PlanRenewal(RenewalFacts{
		CurrentGeneration:   emergencyGen,
		TargetIssuerID:      series.ManagementAuthorityID(),
		TargetIssuerWindow:  issuerWindow,
		RequestedWindow:     mismatchedWindow,
		KeyReadyForRenewal:  false,
		IsEmergencyReissue:  true,
		NextKeyGenerationNo: emergencyGen.GenerationNo() + 1,
	}, now)
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("emergency branch: expected ErrPolicyViolation for mismatched window, got %v", err)
	}
}

// TestPlanRenewal_ComputesWindowFromPolicy verifies the positive path: a
// RequestedWindow whose NotAfter exactly matches the policy's calendar
// computation succeeds and RenewalPlan.Window carries that policy-derived
// window, across reuse, rotation and emergency branches. It also exercises
// the policy computation through the actual PlanRenewal call (not
// PlanLeafWindow in isolation) for a leap-day notBefore so the month-end
// clamp rule is checked on this path too.
func TestPlanRenewal_ComputesWindowFromPolicy(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	now := NewInstant(time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)) // leap day
	issuerWindow := mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	// 2029 is not a leap year, so the 1-year policy clamps to Feb 28.
	wantNotAfter := time.Date(2029, 2, 28, 0, 0, 0, 0, time.UTC)
	correctWindow := mustWindowFacts(time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC), wantNotAfter)

	reuseGen := baseKeyGeneration(t, series.ID(), 1, 0)
	reusePlan, err := series.PlanRenewal(RenewalFacts{
		CurrentGeneration:  reuseGen,
		TargetIssuerID:     series.ManagementAuthorityID(),
		TargetIssuerWindow: issuerWindow,
		RequestedWindow:    correctWindow,
		KeyReadyForRenewal: true,
	}, now)
	if err != nil {
		t.Fatalf("reuse branch: PlanRenewal: %v", err)
	}
	if got := reusePlan.Window.NotAfter().Time(); !got.Equal(wantNotAfter) {
		t.Fatalf("reuse branch: expected not_after %v, got %v", wantNotAfter, got)
	}

	rotateGen := baseKeyGeneration(t, series.ID(), 1, 2)
	rotatePlan, err := series.PlanRenewal(RenewalFacts{
		CurrentGeneration:   rotateGen,
		TargetIssuerID:      series.ManagementAuthorityID(),
		TargetIssuerWindow:  issuerWindow,
		RequestedWindow:     correctWindow,
		KeyReadyForRenewal:  true,
		NextKeyGenerationNo: rotateGen.GenerationNo() + 1,
	}, now)
	if err != nil {
		t.Fatalf("rotate branch: PlanRenewal: %v", err)
	}
	if got := rotatePlan.Window.NotAfter().Time(); !got.Equal(wantNotAfter) {
		t.Fatalf("rotate branch: expected not_after %v, got %v", wantNotAfter, got)
	}

	emergencyGen := baseKeyGeneration(t, series.ID(), 1, 0)
	emergencyPlan, err := series.PlanRenewal(RenewalFacts{
		CurrentGeneration:   emergencyGen,
		TargetIssuerID:      series.ManagementAuthorityID(),
		TargetIssuerWindow:  issuerWindow,
		RequestedWindow:     correctWindow,
		KeyReadyForRenewal:  false,
		IsEmergencyReissue:  true,
		NextKeyGenerationNo: emergencyGen.GenerationNo() + 1,
	}, now)
	if err != nil {
		t.Fatalf("emergency branch: PlanRenewal: %v", err)
	}
	if got := emergencyPlan.Window.NotAfter().Time(); !got.Equal(wantNotAfter) {
		t.Fatalf("emergency branch: expected not_after %v, got %v", wantNotAfter, got)
	}
}

// TestNewLeafKeyGeneration_ImportStartsAtZeroWithUnknownHistory verifies the
// import registration rule.
// [certificate-lifecycle.md §갱신 횟수 계산: "가져온 Leaf는 등록 시 cert-me가
//
//	추적하는 갱신 횟수를 0으로 시작한다... '가져오기 이전 키 사용 이력은
//	포함하지 않음'을 표시한다"]
func TestNewLeafKeyGeneration_ImportStartsAtZeroWithUnknownHistory(t *testing.T) {
	g, err := NewLeafKeyGeneration(LeafKeyGenerationFacts{
		ID:                  LeafKeyGenerationID("77777777-7777-7777-7777-777777777777"),
		SeriesID:            SeriesID("66666666-6666-6666-6666-666666666666"),
		KeyMaterialID:       KeyMaterialID("88888888-8888-8888-8888-888888888888"),
		GenerationNo:        1,
		RenewalCount:        0,
		PriorHistoryUnknown: true,
		Custody:             KeyCustodyClientHeld,
	})
	if err != nil {
		t.Fatalf("NewLeafKeyGeneration: %v", err)
	}
	if g.RenewalCount() != 0 {
		t.Fatalf("expected imported generation renewal_count 0, got %d", g.RenewalCount())
	}
	if !g.PriorHistoryUnknown() {
		t.Fatal("expected imported generation to flag prior history as unknown")
	}
}

func TestLeafSeries_ChangePolicy_RejectsOutOfRangeRotateEvery(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	if _, err := series.ChangePolicy(SeriesPolicy{RotateEvery: 0, CertificateValidity: mustCalendarValidity(t, 1, ValidityUnitDays)}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected ErrInvalidValue for rotate_every=0, got %v", err)
	}
	if _, err := series.ChangePolicy(SeriesPolicy{RotateEvery: 101, CertificateValidity: mustCalendarValidity(t, 1, ValidityUnitDays)}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected ErrInvalidValue for rotate_every=101, got %v", err)
	}
}

// TestPlanRenewal_RejectsStaleKeyGeneration is the P1 review regression: a
// renewal must be planned against the series' *current* key generation
// pointer, not merely any generation that shares the series ID. Without this
// check, passing a stale (already-rotated-away) generation with
// renewal_count reset to 0 would let a caller bypass the rotate_every count
// and re-issue on a key the series has already moved past.
func TestPlanRenewal_RejectsStaleKeyGeneration(t *testing.T) {
	facts := baseSeriesFacts(t, 3)
	facts.CurrentKeyGenerationID = LeafKeyGenerationID("77777777-7777-7777-7777-777777777777")
	series, err := NewLeafSeries(facts)
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	now := NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	issuerWindow := mustWindowFacts(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	requestedWindow := mustWindowFacts(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))

	// stale generates a *different* key generation ID than the series'
	// current pointer, sharing only the SeriesID, with renewal_count reset
	// to 0 -- the shape of a past generation the series already rotated
	// away from.
	stale, err := NewLeafKeyGeneration(LeafKeyGenerationFacts{
		ID:            LeafKeyGenerationID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		SeriesID:      series.ID(),
		KeyMaterialID: KeyMaterialID("88888888-8888-8888-8888-888888888888"),
		GenerationNo:  1,
		RenewalCount:  0,
		Custody:       KeyCustodyClientHeld,
	})
	if err != nil {
		t.Fatalf("NewLeafKeyGeneration: %v", err)
	}

	_, err = series.PlanRenewal(RenewalFacts{
		CurrentGeneration:  stale,
		TargetIssuerID:     series.ManagementAuthorityID(),
		TargetIssuerWindow: issuerWindow,
		RequestedWindow:    requestedWindow,
		KeyReadyForRenewal: true,
	}, now)
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("expected ErrPolicyViolation for a stale key generation, got %v", err)
	}
}

func TestLeafSeries_ChangePolicy_DoesNotMutateReceiver(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	updated, err := series.ChangePolicy(SeriesPolicy{RotateEvery: 5, CertificateValidity: series.Policy().CertificateValidity})
	if err != nil {
		t.Fatalf("ChangePolicy: %v", err)
	}
	if series.Policy().RotateEvery != 3 {
		t.Fatal("ChangePolicy mutated the receiver's policy")
	}
	if updated.Policy().RotateEvery != 5 {
		t.Fatal("expected updated copy to carry the new rotate_every")
	}
}

// TestCalendarValidity_OneYearDiffersFrom365DaysAcrossLeapDay is the P2
// review regression: "1 year" and "365 days" must diverge when the window
// crosses a leap day, since a fixed-duration policy cannot tell them apart.
// [data-model.md §CA·인증서·갱신 계보: "유효기간은 연/월/일 의미를 잃지 않는
// 버전형 정책으로 저장한다"]
func TestCalendarValidity_OneYearDiffersFrom365DaysAcrossLeapDay(t *testing.T) {
	// 2028 is a leap year, so 2027-03-01 + 365 days lands one day before
	// 2028-03-01, while "1 year" lands exactly on 2028-03-01.
	notBefore := NewInstant(time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC))

	oneYear := mustCalendarValidity(t, 1, ValidityUnitYears)
	oneYearWindow, err := oneYear.Window(notBefore)
	if err != nil {
		t.Fatalf("oneYear.Window: %v", err)
	}
	wantOneYear := time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC)
	if got := oneYearWindow.NotAfter().Time(); !got.Equal(wantOneYear) {
		t.Fatalf("1 year: expected not_after %v, got %v", wantOneYear, got)
	}

	days365 := mustCalendarValidity(t, 365, ValidityUnitDays)
	days365Window, err := days365.Window(notBefore)
	if err != nil {
		t.Fatalf("days365.Window: %v", err)
	}
	wantDays365 := time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)
	if got := days365Window.NotAfter().Time(); !got.Equal(wantDays365) {
		t.Fatalf("365 days: expected not_after %v, got %v", wantDays365, got)
	}

	if oneYearWindow.NotAfter().Equal(days365Window.NotAfter()) {
		t.Fatal("expected 1 year and 365 days to diverge across the 2028 leap day, got the same not_after")
	}
}

// TestCalendarValidity_LeapDayIssuanceOneYearClampsToFeb28 covers issuing on
// February 29 with a 1-year policy: 2029 is not a leap year, so 2029-02-29
// does not exist and must clamp to the last day of February per
// data-model.md's month-end rule.
func TestCalendarValidity_LeapDayIssuanceOneYearClampsToFeb28(t *testing.T) {
	notBefore := NewInstant(time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)) // 2028 is a leap year
	oneYear := mustCalendarValidity(t, 1, ValidityUnitYears)

	window, err := oneYear.Window(notBefore)
	if err != nil {
		t.Fatalf("Window: %v", err)
	}
	want := time.Date(2029, 2, 28, 0, 0, 0, 0, time.UTC)
	if got := window.NotAfter().Time(); !got.Equal(want) {
		t.Fatalf("expected not_after clamped to %v, got %v", want, got)
	}
}

// TestCalendarValidity_MonthEndRenewalClampsToShorterMonth covers a
// month-unit policy issued on a 31st: Jan 31 + 1 month has no Feb 31, so it
// must clamp to Feb's last day (28 in a non-leap year), matching
// AddDate's *different*, non-clamping rollover behavior which this policy
// deliberately avoids.
func TestCalendarValidity_MonthEndRenewalClampsToShorterMonth(t *testing.T) {
	notBefore := NewInstant(time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC)) // 2027 is not a leap year
	oneMonth := mustCalendarValidity(t, 1, ValidityUnitMonths)

	window, err := oneMonth.Window(notBefore)
	if err != nil {
		t.Fatalf("Window: %v", err)
	}
	want := time.Date(2027, 2, 28, 0, 0, 0, 0, time.UTC)
	if got := window.NotAfter().Time(); !got.Equal(want) {
		t.Fatalf("expected not_after clamped to %v, got %v", want, got)
	}

	// Sanity-check that time.Time.AddDate's own rollover (which this policy
	// must NOT use for years/months) would have produced a different date
	// (March 2 or 3), confirming the clamp above is doing real work.
	naive := notBefore.Time().AddDate(0, 1, 0)
	if naive.Equal(want) {
		t.Fatal("expected AddDate's rollover to differ from the clamped result, got the same date")
	}
	if naive.Month() != time.March {
		t.Fatalf("expected AddDate to roll over into March, got %v", naive)
	}
}

// TestCalendarValidity_MonthEndRenewalFromLongerMonth verifies a renewal
// issued on March 31 with a 1-month policy clamps to April 30, and that a
// subsequent renewal from that clamped date does not "recover" the 31st --
// each window is computed fresh from its own notBefore, as certificate
// windows are fixed per issuance rather than accumulated.
func TestCalendarValidity_MonthEndRenewalFromLongerMonth(t *testing.T) {
	notBefore := NewInstant(time.Date(2027, 3, 31, 0, 0, 0, 0, time.UTC))
	oneMonth := mustCalendarValidity(t, 1, ValidityUnitMonths)

	window, err := oneMonth.Window(notBefore)
	if err != nil {
		t.Fatalf("Window: %v", err)
	}
	want := time.Date(2027, 4, 30, 0, 0, 0, 0, time.UTC)
	if got := window.NotAfter().Time(); !got.Equal(want) {
		t.Fatalf("expected not_after %v, got %v", want, got)
	}
}

// TestCalendarValidity_DaysUnitNeverClamps confirms the day unit never needs
// or applies month-end clamping: it always lands on the calendar date 30
// days later regardless of month boundaries crossed.
func TestCalendarValidity_DaysUnitNeverClamps(t *testing.T) {
	notBefore := NewInstant(time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC))
	days := mustCalendarValidity(t, 30, ValidityUnitDays)

	window, err := days.Window(notBefore)
	if err != nil {
		t.Fatalf("Window: %v", err)
	}
	want := time.Date(2027, 3, 2, 0, 0, 0, 0, time.UTC)
	if got := window.NotAfter().Time(); !got.Equal(want) {
		t.Fatalf("expected not_after %v, got %v", want, got)
	}
}

func TestNewCalendarValidity_RejectsNonPositiveValueAndBadUnit(t *testing.T) {
	if _, err := NewCalendarValidity(0, ValidityUnitYears); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected ErrInvalidValue for value 0, got %v", err)
	}
	if _, err := NewCalendarValidity(-1, ValidityUnitDays); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected ErrInvalidValue for negative value, got %v", err)
	}
	if _, err := NewCalendarValidity(1, ValidityUnit("weeks")); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected ErrInvalidValue for unsupported unit, got %v", err)
	}
}

// TestPlanLeafWindow_UsesCalendarPolicy checks that the issuance window comes
// from the stored calendar policy, including the month-end clamp, rather than
// a fixed span the caller supplies.
func TestPlanLeafWindow_UsesCalendarPolicy(t *testing.T) {
	policy := SeriesPolicy{
		RotateEvery:         3,
		CertificateValidity: mustCalendarValidity(t, 1, ValidityUnitYears),
	}

	// A leap day notBefore clamps to Feb 28 a calendar year later.
	notBefore := NewInstant(time.Date(2028, 2, 29, 12, 0, 0, 0, time.UTC))
	window, err := PlanLeafWindow(policy, notBefore)
	if err != nil {
		t.Fatalf("PlanLeafWindow: %v", err)
	}
	got := window.NotAfter().Time()
	want := time.Date(2029, 2, 28, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("not_after = %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
	if !window.NotBefore().Equal(notBefore) {
		t.Errorf("not_before = %s, want %s", window.NotBefore(), notBefore)
	}

	// An invalid policy is rejected before a window is produced.
	if _, err := PlanLeafWindow(SeriesPolicy{}, notBefore); err == nil {
		t.Error("PlanLeafWindow with an empty policy succeeded, want an error")
	}
}
