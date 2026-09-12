package port

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

// AuditScopeKind identifies the relation that makes an audit event visible.
// Installation is the single installation-wide scope; Authorities is a
// non-empty set of stored authority relations. The explicit kind prevents an
// empty authority slice from becoming an accidental wildcard.
type AuditScopeKind string

const (
	AuditScopeInstallation AuditScopeKind = "installation"
	AuditScopeAuthorities  AuditScopeKind = "authorities"
)

// AuditScope is the typed write-side visibility scope for one audit event.
// Its fields are private so callers can only construct a valid shape through
// the constructors below and cannot smuggle an arbitrary root id into a
// repository call.
type AuditScope struct {
	kind         AuditScopeKind
	authorityIDs []domain.AuthorityID
}

// NewInstallationAuditScope creates the installation-wide scope used by
// Settings, TLS management, Maintenance summaries, Setup and Identity.
func NewInstallationAuditScope() AuditScope {
	return AuditScope{kind: AuditScopeInstallation}
}

// NewAuthoritiesAuditScope creates an authority scope. Duplicate ids are
// removed while preserving their first-seen order; an empty input remains an
// invalid scope and is rejected by Validate/Append.
func NewAuthoritiesAuditScope(ids ...domain.AuthorityID) AuditScope {
	seen := make(map[domain.AuthorityID]struct{}, len(ids))
	unique := make([]domain.AuthorityID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return AuditScope{kind: AuditScopeAuthorities, authorityIDs: unique}
}

// Kind returns the persisted scope kind.
func (s AuditScope) Kind() AuditScopeKind { return s.kind }

// AuthorityIDs returns a copy of the authority relation ids. Installation
// scopes return nil.
func (s AuditScope) AuthorityIDs() []domain.AuthorityID {
	if s.authorityIDs == nil {
		return nil
	}
	out := make([]domain.AuthorityID, len(s.authorityIDs))
	copy(out, s.authorityIDs)
	return out
}

// Validate checks the storage invariants for a typed scope.
func (s AuditScope) Validate() error {
	switch s.kind {
	case AuditScopeInstallation:
		if len(s.authorityIDs) != 0 {
			return errors.New("installation audit scope must not contain authority ids")
		}
		return nil
	case AuditScopeAuthorities:
		if len(s.authorityIDs) == 0 {
			return errors.New("authority audit scope must contain at least one authority id")
		}
		seen := make(map[domain.AuthorityID]struct{}, len(s.authorityIDs))
		for _, id := range s.authorityIDs {
			if id == "" {
				return errors.New("authority audit scope must not contain an empty authority id")
			}
			if _, ok := seen[id]; ok {
				return errors.New("authority audit scope must not contain duplicate authority ids")
			}
			seen[id] = struct{}{}
		}
		return nil
	default:
		return errors.New("audit scope kind is not supported")
	}
}

// AuditEvent is the write-side shape Append accepts: every public field of
// contract.AuditEventView except AuthorityIDs. §4's table row is literally
// "Append(publicEvent,scopes)" -- two separate inputs, not one bundled
// event -- and there is exactly one reason for the split: scope is decided
// solely by the scopes argument, built by the service from stored relations
// in this same commit, never by a client-supplied value riding along on the
// event. Reusing contract.AuditEventView (which still carries its own
// AuthorityIDs, populated for QueryService's read side) as the write-side
// type as well would leave an implementation with two candidate sources for
// the stored scope rows that can disagree with each other, so this type
// deliberately drops that field rather than inheriting it.
type AuditEvent struct {
	ID         string
	OccurredAt domain.Instant
	ActorKind  contract.AuditActorKind
	ActorID    string
	TokenID    string
	Action     string
	TargetType string
	TargetID   string
	ClientIP   string
	Result     contract.AuditResult
	Details    contract.AuditDetails
}

// AuditRepository is the storage boundary for the append-only business
// audit log (docs/backend-implementation.md §4 table row "AuditRepository";
// docs/data-model.md "audit_events"/"audit_event_scopes").
type AuditRepository interface {
	// Append writes one audit event with an explicit installation or
	// authority scope. The scope is built by the service from stored
	// relations (the account/certificate/authority rows it just read or
	// wrote in this same commit), never from a client-supplied root id.
	// event.ID is assigned by the caller's IDGenerator before this call.
	Append(ctx context.Context, event AuditEvent, scope AuditScope) error

	// DeleteBefore removes at most limit audit events (and their scope
	// rows) occurring strictly before cutoff, for the once-a-day retention
	// sweep (docs/backend-implementation.md §9 "감사 정리는 하루 한 번").
	// Audit rows are never a FK parent for business data
	// (docs/data-model.md "감사 행은 업무 데이터의 FK 부모로 사용하지
	// 않는다"), so pruning them never cascades into PKI history. It returns
	// the number of rows actually deleted.
	DeleteBefore(ctx context.Context, cutoff domain.Instant, limit int) (int, error)
}
