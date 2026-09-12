package port

import (
	"context"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

// QueryRepository is the read side QueryService needs
// (docs/backend-implementation.md §3 table row "QueryService": "List/Get
// Authority, Series, Certificate, Revocation, Transition, Import, Job,
// Audit; GetCRLStatus; ReadPublicCA").
//
// Why this is a new repository rather than read methods scattered across the
// twelve write-side repositories: §13 settles both halves of the question.
// "§4의 축약 목록은 메서드의 상한이 아니다. 서비스가 TxStores만으로 필요한
// 사실을 읽고 결과를 저장할 수 있어야 하며, 대역 내부 map에 직접 fixture를
// 넣어야만 가능한 정상 업무 흐름은 계약 완성으로 인정하지 않는다", and
// "범용 raw SQL 우회 대신 소비 서비스가 필요한 typed port를 추가한다". A
// paged, filtered, permission-scoped list is not the same operation as the
// single-row GetXForUpdate the write path uses -- those lock, these must not
// -- so folding them into the existing interfaces would put two different
// contracts behind similar names. One repository named for its consumer
// keeps the distinction visible.
//
// Three rules hold across every method here:
//
//  1. Nothing in this interface locks. These run under ReadStore.Read, whose
//     results are "사전 준비용 읽기 결과는 commit 권한이 아니다" (§4): a
//     query answers a question, it never authorizes a later commit.
//
//  2. The permission filter is applied by the STORE, not by the caller
//     filtering returned pages. A service that fetched a page and then
//     dropped the rows it may not see would return short pages and a cursor
//     that skips rows, so scope has to be part of the query. QueryService
//     builds the QueryScope from the principal and stored relations before
//     calling (§2 "권한 검사 입력의 Scope는 DB 관계에서 구성하며 사용자 제공
//     Root ID를 신뢰하지 않는다"; §3 "검색·상세마다 권한 재확인").
//
//  3. These return stored records -- domain objects and this package's
//     projections -- not contract views. The service maps to the view and
//     computes the time-derived fields (Expired, Pending) against a clock it
//     reads itself, so no "now" is ever carried in as a query argument. The
//     one exception is audit, whose read-side shape contract already defines
//     with its scope list attached; see ListAudit.
type QueryRepository interface {
	// ListAuthorities returns one page of authorities within scope.
	ListAuthorities(ctx context.Context, query contract.AuthorityListQuery, scope QueryScope) (contract.Page[domain.Authority], error)
	// GetAuthority reads one authority without locking it. It returns
	// ErrNotFound both for an authority that does not exist and for one
	// outside scope, so a caller cannot probe for the existence of a range
	// it may not see.
	GetAuthority(ctx context.Context, id domain.AuthorityID, scope QueryScope) (domain.Authority, error)

	// ListSeries returns one page of leaf series within scope.
	ListSeries(ctx context.Context, query contract.SeriesListQuery, scope QueryScope) (contract.Page[SeriesSnapshot], error)
	// GetSeries reads one series snapshot without locking it.
	GetSeries(ctx context.Context, id domain.SeriesID, scope QueryScope) (SeriesSnapshot, error)

	// ListCertificates returns one page of certificates within scope.
	ListCertificates(ctx context.Context, query contract.CertificateListQuery, scope QueryScope) (contract.Page[QueriedCertificate], error)
	// GetCertificate reads one certificate and the stored relations the
	// view needs, without locking.
	GetCertificate(ctx context.Context, id domain.CertificateID, scope QueryScope) (QueriedCertificate, error)

	// ListRevocations returns one page of revocations within scope.
	ListRevocations(ctx context.Context, query contract.RevocationListQuery, scope QueryScope) (contract.Page[domain.Revocation], error)
	// GetRevocation reads one revocation by its own id. RevocationRepository
	// keys by (issuer, serial) because that is the ledger's business key
	// (§4); the read API addresses a row by id, which is why this is here
	// and not there.
	GetRevocation(ctx context.Context, id domain.RevocationID, scope QueryScope) (domain.Revocation, error)

	// ListTransitions returns one page of transitions within scope.
	ListTransitions(ctx context.Context, query contract.TransitionListQuery, scope QueryScope) (contract.Page[domain.Transition], error)
	// GetTransition reads one transition and its impacts without locking.
	GetTransition(ctx context.Context, id domain.TransitionID, scope QueryScope) (QueriedTransition, error)

	// ListImports returns one page of import batches within scope.
	ListImports(ctx context.Context, query contract.ImportListQuery, scope QueryScope) (contract.Page[ImportBatch], error)
	// GetImport reads one import batch without locking.
	GetImport(ctx context.Context, id domain.ImportBatchID, scope QueryScope) (ImportBatch, error)

	// ListJobs returns one page of background jobs. Jobs are installation-
	// wide rather than authority-scoped, so scope is carried for uniformity
	// and an implementation that has nothing to narrow by may ignore it.
	ListJobs(ctx context.Context, query contract.JobListQuery, scope QueryScope) (contract.Page[Job], error)
	// GetJob reads one job without locking it. GetForUpdate on
	// JobRepository is the worker's path and must not be used to answer a
	// read request.
	GetJob(ctx context.Context, id domain.JobID, scope QueryScope) (Job, error)

	// ListAudit returns one page of audit events visible under scope.
	//
	// This is the one method returning a contract view rather than a stored
	// record, because the stored record alone is not the answer: an audit
	// event's scope list is part of what a reader sees, and AuditEvent (the
	// write-side type) deliberately drops AuthorityIDs so that Append cannot
	// be given two disagreeing sources for the stored scope rows. The read
	// side needs those rows joined back on, and contract.AuditEventView is
	// already declared with exactly that field "populated for QueryService's
	// read side".
	//
	// §14.6's ACL rule applies here, not in the caller: an event stored
	// under several scopes requires permission on ALL of them ("복수 scope는
	// 모든 관련 범위의 권한을 요구하므로"), and a root administrator's reach
	// into a descendant's events follows the stored management_parent
	// relation ("저장된 management_parent 관계에 따른 권한 상속으로
	// 판정한다").
	ListAudit(ctx context.Context, query contract.AuditListQuery, scope QueryScope) (contract.Page[contract.AuditEventView], error)
	// IterateAudit streams every event matching the same filter under the
	// same scope, for the export endpoint (§3 "감사 export는 QueryService가
	// 같은 권한 필터를 적용한 iterator를 반환하고 HTTP/CLI 어댑터가
	// JSON/CSV로 표현한다"). The caller owns Close.
	IterateAudit(ctx context.Context, query contract.AuditExportQuery, scope QueryScope) (contract.AuditEventIterator, error)

	// GetCRLStatus reads one CA key generation's CRL state without locking.
	// CRLRepository.GetStateForUpdate is the publication path's, and a read
	// request must not take that lock.
	GetCRLStatus(ctx context.Context, caKeyGenerationID domain.CAKeyGenerationID, scope QueryScope) (domain.CRLState, error)

	// ReadPublicCA reads an authority's current public CA certificate. This
	// is the only method here that answers a request made without an
	// administrator session -- the CA certificate is public material served
	// from a public path -- so an implementation must treat a QueryScope
	// with Public set as the anonymous reader it is.
	ReadPublicCA(ctx context.Context, authorityID domain.AuthorityID, scope QueryScope) (domain.Certificate, error)
}

// QueryScope is the permission filter a read is narrowed by. It is built by
// QueryService from the principal and stored relations, never from an
// AuthorityID that arrived on the request (§2, §14.6).
//
// The three states are distinct on purpose rather than collapsed into a
// possibly-empty list, because an empty list is ambiguous -- "sees nothing"
// and "unrestricted" would encode identically, and a bug that produced the
// zero value would then silently mean "show everything". Here the zero value
// is the safe one: no All, no ids, not Public, which matches nothing.
type QueryScope struct {
	// All lifts the authority filter entirely. MVP Authorization allows only
	// the global administrator (§2 "MVP Authorization은 전체 관리자만
	// 허용한다"), which is the case this represents; the field exists rather
	// than being assumed so a later role model narrows by populating
	// AuthorityIDs without any signature change here.
	All bool
	// AuthorityIDs is the explicit set of authority ranges the reader may
	// see, used when All is false. It already includes whatever descendants
	// the stored management_parent relation grants (§14.6), resolved by the
	// service before the call -- the store does not re-derive inheritance.
	AuthorityIDs []domain.AuthorityID
	// Public marks the anonymous public-material path (ReadPublicCA). It
	// grants nothing on any other method.
	Public bool
}

// QueriedCertificate is a certificate plus the stored relations
// contract.CertificateView needs, gathered by the store so the service does
// not issue one follow-up read per row.
//
// Revoked and Affected are stored facts (a revocation ledger row exists; a
// transition impact row names this certificate), so they are answered here.
// Expired is NOT: it is a comparison against the current time, and the
// service computes it against a clock it reads itself inside the read, so
// there is no way to pass this struct a "now" that has gone stale.
type QueriedCertificate struct {
	Certificate domain.Certificate
	// SeriesID is set for a leaf certificate, nil for a CA certificate.
	SeriesID *domain.SeriesID
	Revoked  bool
	Affected bool
	// Delivery is the certificate's delivery record when one exists. It
	// never carries key material or a download token.
	Delivery *domain.Delivery
}

// QueriedTransition is a transition together with the impacts the detail
// view lists.
type QueriedTransition struct {
	Transition domain.Transition
	Impacts    []domain.TransitionImpact
}
