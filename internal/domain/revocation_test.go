package domain

import (
	"errors"
	"testing"
	"time"
)

func mkCAKeyGenID(t *testing.T) CAKeyGenerationID {
	t.Helper()
	id, err := ParseCAKeyGenerationID("66666666-6666-4666-8666-666666666666")
	if err != nil {
		t.Fatalf("parse ca key gen id: %v", err)
	}
	return id
}

func mkRevocationID(t *testing.T) RevocationID {
	t.Helper()
	id, err := ParseRevocationID("77777777-7777-4777-8777-777777777777")
	if err != nil {
		t.Fatalf("parse revocation id: %v", err)
	}
	return id
}

func mkSerial(t *testing.T, hex string) SerialNumber {
	t.Helper()
	s, err := ParseSerialNumber(hex)
	if err != nil {
		t.Fatalf("parse serial: %v", err)
	}
	return s
}

func newRevocation(t *testing.T, reason RevocationReason, revokedAt Instant) Revocation {
	t.Helper()
	r, err := NewRevocation(RevocationFacts{
		ID:        mkRevocationID(t),
		IssuerID:  mkCAKeyGenID(t),
		Serial:    mkSerial(t, "1a"),
		RevokedAt: revokedAt,
		Reason:    reason,
		Source:    RevocationSourceManual,
	})
	if err != nil {
		t.Fatalf("new revocation: %v", err)
	}
	return r
}

// planning.md: identical merged facts leave the record unchanged.
func TestRevocation_MergeIdenticalIsNoop(t *testing.T) {
	revokedAt := t0()
	r := newRevocation(t, RevocationReasonKeyCompromise, revokedAt)

	merged, changed, err := r.Merge(RevocationFacts{
		IssuerID:  r.IssuerID(),
		Serial:    r.Serial(),
		RevokedAt: revokedAt,
		Reason:    RevocationReasonKeyCompromise,
		Source:    RevocationSourceImport,
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if changed {
		t.Fatalf("expected identical merge to report unchanged")
	}
	if merged.Version() != r.Version() {
		t.Fatalf("expected version to stay put on a no-op merge")
	}
	if merged.NeedsReview() {
		t.Fatalf("expected no review flag on identical merge")
	}
}

// planning.md/B01: a conflicting time or reason is never auto-overwritten;
// the existing record is kept and flagged for review.
func TestRevocation_MergeConflictKeepsExistingAndFlagsReview(t *testing.T) {
	revokedAt := t0()
	r := newRevocation(t, RevocationReasonKeyCompromise, revokedAt)

	conflictingTime := plus(revokedAt, time.Hour)
	merged, changed, err := r.Merge(RevocationFacts{
		IssuerID:  r.IssuerID(),
		Serial:    r.Serial(),
		RevokedAt: conflictingTime,
		Reason:    RevocationReasonKeyCompromise,
		Source:    RevocationSourceImport,
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !changed {
		t.Fatalf("expected the review flag to count as a change")
	}
	if merged.RevokedAt() != revokedAt {
		t.Fatalf("expected existing revoked_at to be kept, got %v", merged.RevokedAt())
	}
	if !merged.NeedsReview() {
		t.Fatalf("expected conflict to set needs_review")
	}

	conflictingReason, _, err := r.Merge(RevocationFacts{
		IssuerID:  r.IssuerID(),
		Serial:    r.Serial(),
		RevokedAt: revokedAt,
		Reason:    RevocationReasonSuperseded,
		Source:    RevocationSourceImport,
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if conflictingReason.Reason() != RevocationReasonKeyCompromise {
		t.Fatalf("expected existing reason to be kept")
	}
	if !conflictingReason.NeedsReview() {
		t.Fatalf("expected conflict to set needs_review")
	}
}

// There is no un-revoke: Correct can change reason/time but the record
// stays revoked, and Merge cannot be used to clear a revocation.
func TestRevocation_CorrectClearsReviewButNeverUnrevokes(t *testing.T) {
	revokedAt := t0()
	r := newRevocation(t, RevocationReasonKeyCompromise, revokedAt)
	conflictingTime := plus(revokedAt, time.Hour)
	flagged, _, err := r.Merge(RevocationFacts{
		IssuerID: r.IssuerID(), Serial: r.Serial(), RevokedAt: conflictingTime,
		Reason: RevocationReasonKeyCompromise, Source: RevocationSourceImport,
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	corrected, err := flagged.Correct(RevocationReasonSuperseded, conflictingTime, "operator verified import timestamp")
	if err != nil {
		t.Fatalf("correct: %v", err)
	}
	if corrected.NeedsReview() {
		t.Fatalf("expected correction to clear review flag")
	}
	if corrected.Reason() != RevocationReasonSuperseded {
		t.Fatalf("expected corrected reason to apply")
	}
	// Still revoked - there is no method that clears a revocation record.
	if corrected.Serial().IsZero() {
		t.Fatalf("revocation must remain in effect")
	}

	if _, err := flagged.Correct(RevocationReasonSuperseded, conflictingTime, ""); err == nil {
		t.Fatalf("expected correction without justification to be rejected")
	}
}

// PR review (round 3): Merge previously took a caller-computed
// nextChangeGeneration and silently discarded it on every path - a record
// with changeGeneration=4 stayed at 4 even when the caller passed 9 and the
// merge produced a real, needs-review-flagging change. Per
// backend-implementation.md §5, generation bookkeeping is applyRevocations'
// job (it locks CRLState and stamps the shared batch generation when it
// persists), so Merge was changed to match the design's Merge(incoming)
// signature instead of taking a generation argument it could not honor.
// This pins that Merge no longer accepts or needs such a value.
func TestRevocation_MergeSignatureCarriesNoChangeGeneration(t *testing.T) {
	revokedAt := t0()
	r, err := NewRevocation(RevocationFacts{
		ID: mkRevocationID(t), IssuerID: mkCAKeyGenID(t), Serial: mkSerial(t, "1a"),
		RevokedAt: revokedAt, Reason: RevocationReasonKeyCompromise, Source: RevocationSourceManual,
		ChangeGeneration: 4,
	})
	if err != nil {
		t.Fatalf("new revocation: %v", err)
	}

	merged, changed, err := r.Merge(RevocationFacts{
		IssuerID:  r.IssuerID(),
		Serial:    r.Serial(),
		RevokedAt: plus(revokedAt, time.Hour),
		Reason:    RevocationReasonSuperseded,
		Source:    RevocationSourceImport,
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !changed || !merged.NeedsReview() {
		t.Fatalf("expected conflicting merge to change the record and flag review")
	}
	if merged.Version() != r.Version().Next() {
		t.Fatalf("expected version to advance on the conflict change")
	}
	// changeGeneration is untouched by Merge; the caller (applyRevocations)
	// is responsible for persisting the batch generation it computed under
	// the CRLState lock alongside this result.
	if merged.ChangeGeneration() != r.ChangeGeneration() {
		t.Fatalf("expected Merge to leave changeGeneration alone, got %d want %d",
			merged.ChangeGeneration(), r.ChangeGeneration())
	}
}

// PR review (round 3): Correct previously took an unused "now" and let a
// revoked_at set ~146,000 years in the future through with no error. The
// design signature (backend-implementation.md §57) is Correct(reason, time,
// justification) with no clock argument at all, and neither
// certificate-lifecycle.md nor pki-import.md defines what counts as
// "future" for an imported or corrected revocation (imported entries carry
// an external system's clock, not cert-me's). So the fix removes the
// parameter rather than adding an undocumented threshold. This pins that a
// far-future revokedAt is still accepted by the domain (any plausibility
// check belongs at the service/import layer, which has the context to
// define one) and that Correct no longer takes a "now" at all.
func TestRevocation_CorrectAcceptsFarFutureRevokedAt(t *testing.T) {
	r := newRevocation(t, RevocationReasonSuperseded, t0())
	farFuture := plus(t0(), 1<<62)

	corrected, err := r.Correct(RevocationReasonSuperseded, farFuture, "ticket-2")
	if err != nil {
		t.Fatalf("expected far-future revoked_at to be accepted by the domain, got %v", err)
	}
	if !corrected.RevokedAt().Equal(farFuture) {
		t.Fatalf("expected corrected revoked_at to be stored as given, got %v", corrected.RevokedAt())
	}
}

func mkCRLState(t *testing.T, state PublicationState) CRLState {
	t.Helper()
	s, err := NewCRLState(CRLStateFacts{
		CAKeyGenerationID: mkCAKeyGenID(t),
		PublicationState:  state,
	})
	if err != nil {
		t.Fatalf("new crl state: %v", err)
	}
	return s
}

func mkCRLDocID(t *testing.T, suffix byte) CRLDocumentID {
	t.Helper()
	raw := "88888888-8888-4888-8888-88888888888" + string(suffix)
	id, err := ParseCRLDocumentID(raw)
	if err != nil {
		t.Fatalf("parse crl document id: %v", err)
	}
	return id
}

// planning.md/certificate-lifecycle.md: CRL number and covered generation
// never regress, even if a later-started job finishes first.
func TestCRLState_NumberAndGenerationMonotonic(t *testing.T) {
	s := mkCRLState(t, PublicationStateInactive)

	n1, s := s.ReserveNext()
	n2, s := s.ReserveNext()
	if n1.Compare(n2) >= 0 {
		t.Fatalf("expected reservations to strictly increase")
	}

	published, err := s.MarkPublished(mkCRLDocID(t, '1'), n2, 5, plus(t0(), 12*time.Hour))
	if err != nil {
		t.Fatalf("mark published: %v", err)
	}
	if published.PublicationState() != PublicationStateActive {
		t.Fatalf("expected first publish to activate publication state")
	}

	// A late-finishing job with the older reserved number must be rejected.
	if err := published.CanPublish(n1, 6); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected number regression to be rejected, got %v", err)
	}
	// A late-finishing job with an older covered generation must be rejected
	// even if the number would be new (completion-order reversal case).
	n3, published2 := published.ReserveNext()
	if err := published2.CanPublish(n3, 3); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected generation regression to be rejected, got %v", err)
	}
	// A same-number republish attempt (e.g. duplicate job) must be rejected.
	if err := published.CanPublish(n2, 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected equal number to be rejected as non-advancing, got %v", err)
	}
	// A strictly newer number and generation is fine.
	if err := published2.CanPublish(n3, 5); err != nil {
		t.Fatalf("expected newer number/generation to be publishable: %v", err)
	}
}

// New numbers must exceed any previously imported/operator-set maximum, not
// just previously generated numbers: reservation always starts above
// max_reserved_number_hex, which import/restore raise directly.
func TestCRLState_ReservationExceedsImportedMaximum(t *testing.T) {
	importedMax, err := ParseCRLNumber("ff")
	if err != nil {
		t.Fatalf("parse crl number: %v", err)
	}
	s, err := NewCRLState(CRLStateFacts{
		CAKeyGenerationID: mkCAKeyGenID(t),
		MaxReservedNumber: importedMax,
		PublicationState:  PublicationStateInactive,
	})
	if err != nil {
		t.Fatalf("new crl state: %v", err)
	}
	next, _ := s.ReserveNext()
	if next.Compare(importedMax) <= 0 {
		t.Fatalf("expected reservation to exceed imported maximum, got %s vs %s", next.Hex(), importedMax.Hex())
	}
}

// certificate-lifecycle.md: issuance being stopped does not by itself
// forbid CRL signing - SetSigningCertificate has no dependency on issuance
// state at all, only on publication being open.
func TestCRLState_SigningNotBlockedByIssuanceStopped(t *testing.T) {
	s := mkCRLState(t, PublicationStateActive)
	updated, err := s.SetSigningCertificate(mkCertID(t))
	if err != nil {
		t.Fatalf("expected signing certificate assignment to succeed independent of issuance state: %v", err)
	}
	if updated.SigningCACertificateID() != mkCertID(t) {
		t.Fatalf("expected signing certificate to be recorded")
	}
}

func TestCRLState_ClosedStateRejectsFurtherPublication(t *testing.T) {
	s := mkCRLState(t, PublicationStateClosed)
	if err := s.CanPublish(mustCRLNumber(t, "1"), 1); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("expected closed state to reject publication, got %v", err)
	}
}

func mustCRLNumber(t *testing.T, hex string) CRLNumber {
	t.Helper()
	n, err := ParseCRLNumber(hex)
	if err != nil {
		t.Fatalf("parse crl number: %v", err)
	}
	return n
}

// data-model.md: entries without a matching local certificate are still
// preserved; the domain object does not require a certificate id.
func TestRevocation_PreservedWithoutCertificate(t *testing.T) {
	r := newRevocation(t, RevocationReasonUnspecified, t0())
	if r.CertificateID() != "" {
		t.Fatalf("expected zero certificate id to be a valid, preserved state")
	}
}

// Bumping the revocation generation counter is independent of the CRL
// publish/close lifecycle and always advances.
func TestCRLState_BumpRevocationGeneration(t *testing.T) {
	s := mkCRLState(t, PublicationStateInactive)
	bumped := s.BumpRevocationGeneration()
	if bumped.RevocationGeneration() != s.RevocationGeneration()+1 {
		t.Fatalf("expected generation to increase by 1")
	}
}

// TestRevocationReason_CoversContractValues pins the domain reason set to the
// OpenAPI reason enum and the SQL reason CHECK. The wire form is camelCase and
// the domain form is snake_case; the mapping must be total in both directions
// so that no contract reason is unrepresentable.
func TestRevocationReason_CoversContractValues(t *testing.T) {
	// Left: the value used by OpenAPI and the stored SQL CHECK.
	wireToDomain := map[string]RevocationReason{
		"unspecified":          RevocationReasonUnspecified,
		"keyCompromise":        RevocationReasonKeyCompromise,
		"caCompromise":         RevocationReasonCACompromise,
		"affiliationChanged":   RevocationReasonAffiliationChanged,
		"superseded":           RevocationReasonSuperseded,
		"cessationOfOperation": RevocationReasonCessationOfOperation,
		"privilegeWithdrawn":   RevocationReasonPrivilegeWithdrawn,
		"aACompromise":         RevocationReasonAACompromise,
	}

	seen := make(map[RevocationReason]string, len(wireToDomain))
	for wire, reason := range wireToDomain {
		if err := reason.Validate(); err != nil {
			t.Errorf("contract reason %q maps to %q, which Validate rejects: %v", wire, reason, err)
		}
		if prior, dup := seen[reason]; dup {
			t.Errorf("reasons %q and %q both map to %q", prior, wire, reason)
		}
		seen[reason] = wire
	}

	// Every domain constant must correspond to a contract value, so a reason
	// cannot be added here without a wire representation.
	allDomain := []RevocationReason{
		RevocationReasonUnspecified,
		RevocationReasonKeyCompromise,
		RevocationReasonCACompromise,
		RevocationReasonAffiliationChanged,
		RevocationReasonSuperseded,
		RevocationReasonCessationOfOperation,
		RevocationReasonPrivilegeWithdrawn,
		RevocationReasonAACompromise,
	}
	for _, reason := range allDomain {
		if _, ok := seen[reason]; !ok {
			t.Errorf("domain reason %q has no contract value", reason)
		}
	}
	if len(allDomain) != len(wireToDomain) {
		t.Errorf("domain has %d reasons, contract has %d", len(allDomain), len(wireToDomain))
	}

	// A reason outside the contract is still rejected.
	for _, bogus := range []RevocationReason{"removeFromCRL", "remove_from_crl", "aACompromise", ""} {
		if err := RevocationReason(bogus).Validate(); err == nil {
			t.Errorf("Validate(%q) = nil, want an error", bogus)
		}
	}
}
