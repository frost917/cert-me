package contract

import (
	"fmt"

	"cert-me/internal/domain"
)

// This file is QueryService's command/result contract
// (docs/backend-implementation.md §3): List/Get for Authority, Series,
// Certificate, Revocation, Transition, Import, Job, Audit; GetCRLStatus;
// ReadPublicCA.
//
// Every filter type below holds only domain ids, UTC domain.Instant values,
// a fixed enum, or Limit/Cursor -- never a free-form SQL ordering or
// condition string (§3 "조회 목록의 필터 struct는 domain ID·UTC 시간·허용
// enum·Limit/Cursor만 포함한다. 자유 SQL 정렬·조건 문자열은 받지 않는다.").
// The OpenAPI "q" query parameter is a plain search term the read store
// applies internally (e.g. against an indexed name/CN column); it is
// carried here as an opaque string, never as a caller-supplied SQL
// fragment, ordering clause or condition.

// requireNoDomainError adapts a possibly-nil domain error to the error
// interface correctly. FromDomainError returns a concrete *AppError; a
// direct `return FromDomainError(err)` when err is nil would box a nil
// *AppError into a non-nil error interface (the classic Go typed-nil-
// interface trap), so every single-check Validate below routes through
// this instead of calling FromDomainError directly on a value that might be
// nil.
func requireNoDomainError(err error) error {
	if err == nil {
		return nil
	}
	return FromDomainError(err)
}

const (
	defaultPageLimit = 50
	maxPageLimit     = 200
	maxSearchLength  = 255
)

// PageRequest is the Limit/Cursor pair every list query embeds.
type PageRequest struct {
	Cursor string
	Limit  int
}

// Validate applies the OpenAPI limit bounds and fills in the default.
// Cursor is opaque: it is only ever a token this service itself issued
// (from a prior Page's NextCursor), so it is not further constrained here
// beyond a sane length bound to reject obviously foreign input.
func (p PageRequest) normalized() (PageRequest, error) {
	if len(p.Cursor) > 4096 {
		return PageRequest{}, NewAppError(ErrorKindValidation, "cursor_invalid", "cursor is too long")
	}
	limit := p.Limit
	if limit == 0 {
		limit = defaultPageLimit
	}
	if limit < 1 || limit > maxPageLimit {
		return PageRequest{}, NewAppError(ErrorKindValidation, "limit_invalid", "limit must be between 1 and 200")
	}
	return PageRequest{Cursor: p.Cursor, Limit: limit}, nil
}

func validateSearch(search string) error {
	if len(search) > maxSearchLength {
		return NewAppError(ErrorKindValidation, "search_too_long", "q must be at most 255 characters")
	}
	return nil
}

// Page is the generic list result: items plus an opaque cursor for the next
// page, nil once exhausted. It mirrors every OpenAPI list response's
// {data, next_cursor} envelope.
type Page[T any] struct {
	Items      []T
	NextCursor *string
}

// AuthorityListQuery is Authority's List filter.
type AuthorityListQuery struct {
	Search string
	Page   PageRequest
}

func (q AuthorityListQuery) Validate() error {
	if err := validateSearch(q.Search); err != nil {
		return err
	}
	if _, err := q.Page.normalized(); err != nil {
		return err
	}
	return nil
}

// AuthorityGetQuery is Authority's Get filter. AuthorityID is the path
// target.
type AuthorityGetQuery struct {
	AuthorityID domain.AuthorityID
}

func (q AuthorityGetQuery) Validate() error {
	_, err := domain.ParseAuthorityID(string(q.AuthorityID))
	return requireNoDomainError(err)
}

// SeriesListQuery is LeafSeries's List filter.
type SeriesListQuery struct {
	Search      string
	AuthorityID *domain.AuthorityID
	Page        PageRequest
}

func (q SeriesListQuery) Validate() error {
	if err := validateSearch(q.Search); err != nil {
		return err
	}
	if q.AuthorityID != nil {
		if _, err := domain.ParseAuthorityID(string(*q.AuthorityID)); err != nil {
			return FromDomainError(err)
		}
	}
	_, err := q.Page.normalized()
	return err
}

// SeriesGetQuery is LeafSeries's Get filter. SeriesID is the path target.
type SeriesGetQuery struct {
	SeriesID domain.SeriesID
}

func (q SeriesGetQuery) Validate() error {
	_, err := domain.ParseSeriesID(string(q.SeriesID))
	return requireNoDomainError(err)
}

// CertificateListQuery is Certificate's List filter.
type CertificateListQuery struct {
	Search        string
	AuthorityID   *domain.AuthorityID
	ExpiresBefore *domain.Instant
	Revoked       *bool
	Affected      *bool
	Page          PageRequest
}

func (q CertificateListQuery) Validate() error {
	if err := validateSearch(q.Search); err != nil {
		return err
	}
	if q.AuthorityID != nil {
		if _, err := domain.ParseAuthorityID(string(*q.AuthorityID)); err != nil {
			return FromDomainError(err)
		}
	}
	_, err := q.Page.normalized()
	return err
}

// CertificateGetQuery is Certificate's Get filter. CertificateID is the
// path target.
type CertificateGetQuery struct {
	CertificateID domain.CertificateID
}

func (q CertificateGetQuery) Validate() error {
	_, err := domain.ParseCertificateID(string(q.CertificateID))
	return requireNoDomainError(err)
}

// RevocationListQuery is Revocation's List filter.
type RevocationListQuery struct {
	Search      string
	AuthorityID *domain.AuthorityID
	SerialHex   string
	Page        PageRequest
}

func (q RevocationListQuery) Validate() error {
	if err := validateSearch(q.Search); err != nil {
		return err
	}
	if q.AuthorityID != nil {
		if _, err := domain.ParseAuthorityID(string(*q.AuthorityID)); err != nil {
			return FromDomainError(err)
		}
	}
	if q.SerialHex != "" {
		if _, err := domain.ParseSerialNumber(q.SerialHex); err != nil {
			return FromDomainError(err)
		}
	}
	_, err := q.Page.normalized()
	return err
}

// RevocationGetQuery is Revocation's Get filter. RevocationID is the path
// target.
type RevocationGetQuery struct {
	RevocationID domain.RevocationID
}

func (q RevocationGetQuery) Validate() error {
	_, err := domain.ParseRevocationID(string(q.RevocationID))
	return requireNoDomainError(err)
}

// TransitionListQuery is Transition's List filter.
type TransitionListQuery struct {
	Search string
	Page   PageRequest
}

func (q TransitionListQuery) Validate() error {
	if err := validateSearch(q.Search); err != nil {
		return err
	}
	_, err := q.Page.normalized()
	return err
}

// TransitionGetQuery is Transition's Get filter. TransitionID is the path
// target.
type TransitionGetQuery struct {
	TransitionID domain.TransitionID
}

func (q TransitionGetQuery) Validate() error {
	_, err := domain.ParseTransitionID(string(q.TransitionID))
	return requireNoDomainError(err)
}

// ImportListQuery is Import's List filter. There is no OpenAPI list
// endpoint documented for import runs beyond Limit/Cursor, so this only
// carries the page request.
type ImportListQuery struct {
	Page PageRequest
}

func (q ImportListQuery) Validate() error {
	_, err := q.Page.normalized()
	return err
}

// ImportGetQuery is Import's Get filter. ImportID is the path target; it
// stays a plain string for the same reason ImportResultView.ID does (no
// domain.ImportID type exists).
type ImportGetQuery struct {
	ImportID string
}

func (q ImportGetQuery) Validate() error {
	if len(q.ImportID) != 36 {
		return NewAppError(ErrorKindValidation, "import_id_invalid", "import id must be a uuid")
	}
	return nil
}

// JobListQuery is Job's List filter.
type JobListQuery struct {
	Page PageRequest
}

func (q JobListQuery) Validate() error {
	_, err := q.Page.normalized()
	return err
}

// JobGetQuery is Job's Get filter. JobID is the path target.
type JobGetQuery struct {
	JobID domain.JobID
}

func (q JobGetQuery) Validate() error {
	_, err := domain.ParseJobID(string(q.JobID))
	return requireNoDomainError(err)
}

// AuditResultFilter mirrors the OpenAPI audit result enum filter value.
type AuditResultFilter AuditResult

// AuditFilter is shared by List and Export (§3 "감사 export는 QueryService가
// 같은 권한 필터를 적용한 iterator를 반환"): both apply the identical
// permission-scoped filter, only the output shape (paged list vs iterator)
// differs.
type AuditFilter struct {
	From          *domain.Instant
	Until         *domain.Instant
	AccountID     *domain.AccountID
	AuthorityID   *domain.AuthorityID
	CertificateID *domain.CertificateID
	Action        string
	ClientIP      string
	Result        *AuditResultFilter
}

const maxAuditActionLength = 255

func (f AuditFilter) validate() error {
	if f.From != nil && f.Until != nil && f.Until.Before(*f.From) {
		return NewAppError(ErrorKindValidation, "audit_range_invalid", "until must not be before from")
	}
	if f.AccountID != nil {
		if _, err := domain.ParseAccountID(string(*f.AccountID)); err != nil {
			return FromDomainError(err)
		}
	}
	if f.AuthorityID != nil {
		if _, err := domain.ParseAuthorityID(string(*f.AuthorityID)); err != nil {
			return FromDomainError(err)
		}
	}
	if f.CertificateID != nil {
		if _, err := domain.ParseCertificateID(string(*f.CertificateID)); err != nil {
			return FromDomainError(err)
		}
	}
	if len(f.Action) > maxAuditActionLength {
		return NewAppError(ErrorKindValidation, "audit_action_too_long", "action must be at most 255 characters")
	}
	if f.Result != nil {
		switch AuditResult(*f.Result) {
		case AuditResultSuccess, AuditResultFailure:
		default:
			return NewAppError(ErrorKindValidation, "audit_result_invalid", "result must be success or failure")
		}
	}
	return nil
}

// AuditListQuery is Audit's List filter.
type AuditListQuery struct {
	Filter AuditFilter
	Page   PageRequest
}

func (q AuditListQuery) Validate() error {
	if err := q.Filter.validate(); err != nil {
		return err
	}
	_, err := q.Page.normalized()
	return err
}

// AuditExportFormat mirrors the export endpoint's format enum.
type AuditExportFormat string

const (
	AuditExportFormatJSON AuditExportFormat = "json"
	AuditExportFormatCSV  AuditExportFormat = "csv"
)

func (f AuditExportFormat) Validate() error {
	switch f {
	case AuditExportFormatJSON, AuditExportFormatCSV:
		return nil
	default:
		return fmt.Errorf("%w: unsupported audit export format %q", domain.ErrInvalidValue, string(f))
	}
}

// AuditExportQuery is Audit's Export filter: the same permission-scoped
// AuditFilter, with no Limit/Cursor since the adapter drives the returned
// iterator to completion rather than paging it.
type AuditExportQuery struct {
	Filter AuditFilter
	Format AuditExportFormat
}

func (q AuditExportQuery) Validate() error {
	if err := q.Filter.validate(); err != nil {
		return err
	}
	if err := q.Format.Validate(); err != nil {
		return FromDomainError(err)
	}
	return nil
}

// AuditEventIterator is the shape Export returns: a same-permission-filter
// stream the HTTP/CLI adapter drives to JSON or CSV
// (§3 "HTTP/CLI 어댑터가 JSON/CSV로 표현한다"). It intentionally has no
// domain/port dependency beyond contract, so this file can define it
// without owning app/port.
type AuditEventIterator interface {
	// Next advances to the next event, returning false once exhausted or on
	// error (check Err after Next returns false).
	Next(ctxDone <-chan struct{}) bool
	Event() AuditEventView
	Err() error
	Close() error
}

// GetCRLStatusQuery is QueryService.GetCRLStatus's filter. CAKeyGenerationID
// is the path target: CRLStatus is per CA key generation
// (domain.CRLState is keyed the same way).
type GetCRLStatusQuery struct {
	CAKeyGenerationID domain.CAKeyGenerationID
}

func (q GetCRLStatusQuery) Validate() error {
	_, err := domain.ParseCAKeyGenerationID(string(q.CAKeyGenerationID))
	return requireNoDomainError(err)
}

// ReadPublicCAQuery is QueryService.ReadPublicCA's filter: the public CA
// certificate for one authority. AuthorityID is the path target.
type ReadPublicCAQuery struct {
	AuthorityID domain.AuthorityID
}

func (q ReadPublicCAQuery) Validate() error {
	_, err := domain.ParseAuthorityID(string(q.AuthorityID))
	return requireNoDomainError(err)
}
