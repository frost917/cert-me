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
	}, r.ChangeGeneration()+1)
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
	}, r.ChangeGeneration()+1)
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
	}, r.ChangeGeneration()+1)
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
	}, r.ChangeGeneration()+1)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	corrected, err := flagged.Correct(RevocationReasonSuperseded, conflictingTime, "operator verified import timestamp", plus(revokedAt, 2*time.Hour))
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

	if _, err := flagged.Correct(RevocationReasonSuperseded, conflictingTime, "", plus(revokedAt, 2*time.Hour)); err == nil {
		t.Fatalf("expected correction without justification to be rejected")
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
