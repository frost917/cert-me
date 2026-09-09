package domain

import (
	"errors"
	"testing"
	"time"
)

func baseSeriesFacts(rotateEvery int) LeafSeriesFacts {
	return LeafSeriesFacts{
		ID:                    SeriesID("66666666-6666-6666-6666-666666666666"),
		Name:                  "web-frontend",
		Purpose:               SeriesPurposeDistributed,
		ManagementAuthorityID: AuthorityID("11111111-1111-1111-1111-111111111111"),
		Policy: SeriesPolicy{
			RotateEvery:         rotateEvery,
			CertificateValidity: NewDuration(365 * 24 * time.Hour),
		},
		Version: 1,
	}
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
	series, err := NewLeafSeries(baseSeriesFacts(3))
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
	series, err := NewLeafSeries(baseSeriesFacts(3))
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
	series, err := NewLeafSeries(baseSeriesFacts(3))
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
	series, err := NewLeafSeries(baseSeriesFacts(3))
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
	series, err := NewLeafSeries(baseSeriesFacts(100)) // very high cadence: would never rotate normally
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
	series, err := NewLeafSeries(baseSeriesFacts(3))
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
	series, err := NewLeafSeries(baseSeriesFacts(3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	if _, err := series.ChangePolicy(SeriesPolicy{RotateEvery: 0, CertificateValidity: NewDuration(24 * time.Hour)}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected ErrInvalidValue for rotate_every=0, got %v", err)
	}
	if _, err := series.ChangePolicy(SeriesPolicy{RotateEvery: 101, CertificateValidity: NewDuration(24 * time.Hour)}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected ErrInvalidValue for rotate_every=101, got %v", err)
	}
}

func TestLeafSeries_ChangePolicy_DoesNotMutateReceiver(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(3))
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
