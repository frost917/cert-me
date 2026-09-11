package porttest

import (
	"context"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type auditRepo struct{ s *state }

var _ port.AuditRepository = auditRepo{}

// Append stores the event and its scopes as two separate values, mirroring
// the port contract: the event itself deliberately carries no AuthorityIDs
// field, so scopes is the single source of the visibility rows.
func (r auditRepo) Append(_ context.Context, event port.AuditEvent, scopes []domain.AuthorityID) error {
	r.s.auditEvents = append(r.s.auditEvents, auditRow{
		event:  cloneAuditEvent(event),
		scopes: cloneAuthorityIDs(scopes),
	})
	return nil
}

// DeleteBefore removes at most limit events occurring strictly before
// cutoff. Audit rows are never a FK parent for business data
// (docs/data-model.md), so pruning them cannot cascade into PKI history --
// this double keeps every other map untouched to make that property
// testable.
func (r auditRepo) DeleteBefore(_ context.Context, cutoff domain.Instant, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	kept := make([]auditRow, 0, len(r.s.auditEvents))
	deleted := 0
	for _, row := range r.s.auditEvents {
		if deleted < limit && row.event.OccurredAt.Before(cutoff) {
			deleted++
			continue
		}
		kept = append(kept, row)
	}
	r.s.auditEvents = kept
	return deleted, nil
}

// AuditEvents exposes the stored audit trail to tests. It returns copies so
// a test assertion cannot mutate the store.
func (s *Store) AuditEvents() []port.AuditEvent {
	snapshot := s.root.Load()
	out := make([]port.AuditEvent, 0, len(snapshot.auditEvents))
	for _, row := range snapshot.auditEvents {
		out = append(out, cloneAuditEvent(row.event))
	}
	return out
}
