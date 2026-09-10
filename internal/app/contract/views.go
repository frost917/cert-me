package contract

import (
	"fmt"

	"cert-me/internal/domain"
)

// This file holds the DTO shapes that more than one service returns or
// accepts. Wire-facing input types carry the OpenAPI property names as JSON
// tags and validate into domain values; result views carry domain types and
// are mapped to JSON explicitly by the adapter.

// SubjectInput mirrors the OpenAPI Subject schema on the request side.
type SubjectInput struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
}

// Domain converts to the validated domain value.
func (s SubjectInput) Domain() (domain.Subject, error) {
	return domain.NewSubject(domain.SubjectFacts{
		CommonName:         s.CommonName,
		Organization:       s.Organization,
		OrganizationalUnit: s.OrganizationalUnit,
		Country:            s.Country,
	})
}

// SANInput mirrors the OpenAPI SAN schema on the request side.
type SANInput struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Domain converts to the validated domain value.
func (s SANInput) Domain() (domain.SAN, error) {
	return domain.NewSAN(domain.SANType(s.Type), s.Value)
}

// SANInputs converts a list, reporting the index of the first bad entry so the
// caller can attach it as a public field.
func SANInputs(list []SANInput) ([]domain.SAN, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]domain.SAN, 0, len(list))
	for i, item := range list {
		san, err := item.Domain()
		if err != nil {
			return nil, fmt.Errorf("san[%d]: %w", i, err)
		}
		out = append(out, san)
	}
	return out, nil
}

// ValidityInput mirrors the OpenAPI Validity schema.
type ValidityInput struct {
	Value int    `json:"value"`
	Unit  string `json:"unit"`
}

// Domain converts to the validated calendar validity.
func (v ValidityInput) Domain() (domain.CalendarValidity, error) {
	return domain.NewCalendarValidity(v.Value, domain.ValidityUnit(v.Unit))
}

// SubjectView is the response shape of a subject.
type SubjectView struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
}

// NewSubjectView projects a domain subject.
func NewSubjectView(s domain.Subject) SubjectView {
	return SubjectView{
		CommonName:         s.CommonName(),
		Organization:       s.Organization(),
		OrganizationalUnit: s.OrganizationalUnit(),
		Country:            s.Country(),
	}
}

// SANView is the response shape of one subjectAltName.
type SANView struct {
	Type  string
	Value string
}

// NewSANViews projects a list of domain SANs.
func NewSANViews(list []domain.SAN) []SANView {
	if len(list) == 0 {
		return nil
	}
	out := make([]SANView, 0, len(list))
	for _, san := range list {
		out = append(out, SANView{Type: string(san.Type()), Value: san.Value()})
	}
	return out
}

// CertificateOrigin distinguishes a certificate this installation generated
// from one that arrived through import.
type CertificateOrigin string

const (
	CertificateOriginGenerated CertificateOrigin = "generated"
	CertificateOriginImported  CertificateOrigin = "imported"
)

// CertificateView is the OpenAPI Certificate data object. Revoked/Affected/
// Expired are computed by the service against the same now it used elsewhere
// in the request, not recomputed by the adapter.
type CertificateView struct {
	ID                      domain.CertificateID
	DERSHA256               domain.Fingerprint
	KeyMaterialID           domain.KeyMaterialID
	IssuerCAKeyGenerationID domain.CAKeyGenerationID
	Serial                  domain.SerialNumber
	NotBefore               domain.Instant
	NotAfter                domain.Instant
	Subject                 SubjectView
	SANs                    []SANView
	Origin                  CertificateOrigin
	SeriesID                *domain.SeriesID
	Revoked                 bool
	Affected                bool
	Expired                 bool
	Delivery                *DeliveryView
	CreatedAt               domain.Instant
}

// DeliveryView is the OpenAPI Delivery data object. It never carries the
// download token or any key material.
type DeliveryView struct {
	ID            domain.DeliveryID
	CertificateID domain.CertificateID
	State         domain.DeliveryState
	ExpiresAt     domain.Instant
	ConsumedAt    *domain.Instant
	FinishedAt    *domain.Instant
	FailureCode   string
	Version       domain.Version
}

// ImpactView is the OpenAPI Impact data object: one certificate a transition
// affects, plus its replacement once one exists.
type ImpactView struct {
	CertificateID            domain.CertificateID
	ReplacementCertificateID *domain.CertificateID
	ReissuedAt               *domain.Instant
}

// JobState is the persisted lifecycle of a background job.
type JobState string

const (
	JobStatePending   JobState = "pending"
	JobStateRunning   JobState = "running"
	JobStateSucceeded JobState = "succeeded"
	JobStateFailed    JobState = "failed"
)

// JobView is the OpenAPI Job data object. The payload is never exposed.
type JobView struct {
	ID            domain.JobID
	Kind          string
	State         JobState
	LastErrorCode string
	AvailableAt   domain.Instant
	AttemptCount  int64
	Version       domain.Version
}

// AuditActorKind names who performed an audited action.
type AuditActorKind string

const (
	AuditActorAccount       AuditActorKind = "account"
	AuditActorDownloadToken AuditActorKind = "download_token"
	AuditActorCLI           AuditActorKind = "cli"
	AuditActorSystem        AuditActorKind = "system"
	AuditActorAnonymous     AuditActorKind = "anonymous"
)

// AuditResult is the outcome recorded on an audit event.
type AuditResult string

const (
	AuditResultSuccess AuditResult = "success"
	AuditResultFailure AuditResult = "failure"
)

// AuditDetails is the versioned public metadata of an audit event. Private
// keys, tokens and unlock passwords must never be placed in it.
type AuditDetails struct {
	SchemaVersion int
	Fields        map[string]string
}

// AuditEventView is the OpenAPI AuditEvent data object. AuthorityIDs is the
// scope the event is visible under and is built from stored relations, never
// from a client-supplied root id.
type AuditEventView struct {
	ID           string
	OccurredAt   domain.Instant
	ActorKind    AuditActorKind
	ActorID      string
	TokenID      string
	Action       string
	TargetType   string
	TargetID     string
	ClientIP     string
	Result       AuditResult
	Details      AuditDetails
	AuthorityIDs []domain.AuthorityID
}

// EmptyCommand is the explicit empty command. Methods that take no arguments
// still take one of these rather than dropping the parameter.
type EmptyCommand struct{}
