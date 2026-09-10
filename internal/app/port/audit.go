package port

import (
	"context"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

// AuditRepository is the storage boundary for the append-only business
// audit log (docs/backend-implementation.md §4 table row "AuditRepository";
// docs/data-model.md "audit_events"/"audit_event_scopes"). It reuses
// contract.AuditEventView -- the same shape QueryService already returns to
// callers -- as the write-side type too, since an audit row's public fields
// are identical on write and read; there is no separate command DTO to
// invent here.
type AuditRepository interface {
	// Append writes one audit event together with the authority scopes it
	// is visible under. scopes is built by the service from stored
	// relations (the account/certificate/authority rows it just read or
	// wrote in this same commit), never from a client-supplied root id
	// (docs/backend-implementation.md §2 "권한 검사 입력의 Scope는 DB
	// 관계에서 구성하며 사용자 제공 Root ID를 신뢰하지 않는다" -- the same
	// rule that shapes Authorizer's scope argument in services.go applies
	// here to the audit trail a multi-CA operation is later found under).
	// event.ID is assigned by the caller's IDGenerator before this call.
	Append(ctx context.Context, event contract.AuditEventView, scopes []domain.AuthorityID) error

	// DeleteBefore removes at most limit audit events (and their scope
	// rows) occurring strictly before cutoff, for the once-a-day retention
	// sweep (docs/backend-implementation.md §9 "감사 정리는 하루 한 번").
	// Audit rows are never a FK parent for business data
	// (docs/data-model.md "감사 행은 업무 데이터의 FK 부모로 사용하지
	// 않는다"), so pruning them never cascades into PKI history. It returns
	// the number of rows actually deleted.
	DeleteBefore(ctx context.Context, cutoff domain.Instant, limit int) (int, error)
}
