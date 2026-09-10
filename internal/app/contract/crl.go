package contract

import (
	"cert-me/internal/domain"
)

// This file is CRLService's command/result contract
// (docs/backend-implementation.md §3): RequestPublication, Publish.

// CRLRequestPublicationCommand carries only the target authority; AuthorityID
// is the path target (§3: "RequestPublication(authorityID) → JobAccepted").
type CRLRequestPublicationCommand struct {
	AuthorityID domain.AuthorityID `json:"-"`
}

func (c CRLRequestPublicationCommand) Validate() error {
	if _, err := domain.ParseAuthorityID(string(c.AuthorityID)); err != nil {
		return FromDomainError(err)
	}
	return nil
}

// JobAcceptedView is the OpenAPI JobAccepted data object.
type JobAcceptedView struct {
	JobID domain.JobID
}

// CRLPublishCommand is CRLService.Publish's internal command
// (§3: "Publish(jobID, CAKeyGenerationID) → PublicationResult"). It is not
// wire-decoded from a client request: Publish is worker/maintenance only
// (§3 "Publish는 worker/maintenance 전용"), so this has no JSON tags and no
// path-target convention to follow -- both ids are supplied by the worker
// loop that claimed the job.
type CRLPublishCommand struct {
	JobID             domain.JobID
	CAKeyGenerationID domain.CAKeyGenerationID
}

func (c CRLPublishCommand) Validate() error {
	if _, err := domain.ParseJobID(string(c.JobID)); err != nil {
		return FromDomainError(err)
	}
	if _, err := domain.ParseCAKeyGenerationID(string(c.CAKeyGenerationID)); err != nil {
		return FromDomainError(err)
	}
	return nil
}

// PublicationResult is the internal result docs/backend-implementation.md §3
// names explicitly: "PublicationResult는 CAKeyGenerationID, DocumentID,
// Number, CoveredGeneration, Published, FollowupRequired다. 이들은 내부
// 결과이며 새 공개 HTTP API를 만들지 않는다." It is deliberately not an
// OpenAPI schema (there is no PublicationResult entry in api/openapi.json)
// and must not become the JSON shape of any client-facing endpoint; a
// client only ever observes a CRL through GetCRLStatus's CRLStatus view.
type PublicationResult struct {
	CAKeyGenerationID domain.CAKeyGenerationID
	DocumentID        domain.CRLDocumentID
	Number            domain.CRLNumber
	CoveredGeneration int64
	Published         bool
	FollowupRequired  bool
}

// CRLStatusView is the OpenAPI CRLStatus data object, returned by
// QueryService.GetCRLStatus (query.go), listed here since it is CRL-shaped
// state rather than a generic query filter/result.
type CRLStatusView struct {
	Number               *domain.CRLNumber
	CoveredGeneration    *int64
	RevocationGeneration int64
	NextPublishAt        *domain.Instant
	NextUpdate           *domain.Instant
	PublicationState     domain.PublicationState
	Pending              bool
	Expired              bool
	LastErrorCode        string
	Version              domain.Version
}
