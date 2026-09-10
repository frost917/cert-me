// Revocation and CRLState model the revocation ledger and the per-CA-key
// publication state. Policy source: docs/certificate-lifecycle.md "CRL";
// docs/data-model.md "폐기·CRL·기존 PKI 인수"; docs/planning.md revocation
// conflict and CRL number rules.
package domain

import (
	"fmt"
	"time"
)

// RevocationReason mirrors RFC 5280 CRL reason codes actually used by the
// product (certificate-lifecycle.md mentions keyCompromise and
// caCompromise explicitly; the remaining CRL-eligible reasons are included
// so Merge/Correct can carry any legitimate value).
type RevocationReason string

const (
	RevocationReasonUnspecified          RevocationReason = "unspecified"
	RevocationReasonKeyCompromise        RevocationReason = "key_compromise"
	RevocationReasonCACompromise         RevocationReason = "ca_compromise"
	RevocationReasonAffiliationChanged   RevocationReason = "affiliation_changed"
	RevocationReasonSuperseded           RevocationReason = "superseded"
	RevocationReasonCessationOfOperation RevocationReason = "cessation_of_operation"
	RevocationReasonPrivilegeWithdrawn   RevocationReason = "privilege_withdrawn"
	// RevocationReasonAACompromise is RFC 5280 aACompromise. It is in the
	// OpenAPI reason enum and the initial SQL reason CHECK, so a revoke
	// request or an imported CRL entry using it must be representable here.
	RevocationReasonAACompromise RevocationReason = "aa_compromise"
)

func (r RevocationReason) Validate() error {
	switch r {
	case RevocationReasonUnspecified, RevocationReasonKeyCompromise, RevocationReasonCACompromise,
		RevocationReasonAffiliationChanged, RevocationReasonSuperseded,
		RevocationReasonCessationOfOperation, RevocationReasonPrivilegeWithdrawn,
		RevocationReasonAACompromise:
		return nil
	default:
		return fmt.Errorf("%w: unsupported revocation reason %q", ErrInvalidValue, string(r))
	}
}

func (r RevocationReason) String() string { return string(r) }

// RevocationSource mirrors revocations.source: who asserted the revocation.
type RevocationSource string

const (
	RevocationSourceManual  RevocationSource = "manual"
	RevocationSourceImport  RevocationSource = "import"
	RevocationSourceCascade RevocationSource = "cascade"
)

func (s RevocationSource) Validate() error {
	switch s {
	case RevocationSourceManual, RevocationSourceImport, RevocationSourceCascade:
		return nil
	default:
		return fmt.Errorf("%w: unsupported revocation source %q", ErrInvalidValue, string(s))
	}
}

// Revocation is keyed by (issuer CA key generation, serial), not by
// certificate: data-model.md "폐기의 기준 키는 issuer/serial이고 연결 여부가
// 효력에 영향을 주지 않는다." CertificateID is optional so an entry can be
// preserved even when no local certificate row exists (imported CRL entry
// for an unknown certificate).
type Revocation struct {
	id               RevocationID
	issuerID         CAKeyGenerationID
	serial           SerialNumber
	certificateID    CertificateID // zero if unknown
	revokedAt        Instant
	reason           RevocationReason
	source           RevocationSource
	changeGeneration int64
	needsReview      bool
	version          Version
}

// RevocationFacts is both the constructor input and the shape of an
// incoming assertion passed to Merge/Correct.
type RevocationFacts struct {
	ID               RevocationID
	IssuerID         CAKeyGenerationID
	Serial           SerialNumber
	CertificateID    CertificateID
	RevokedAt        Instant
	Reason           RevocationReason
	Source           RevocationSource
	ChangeGeneration int64
	NeedsReview      bool
	Version          Version
}

// NewRevocation builds a Revocation from stored facts.
func NewRevocation(facts RevocationFacts) (Revocation, error) {
	if _, err := ParseRevocationID(string(facts.ID)); err != nil {
		return Revocation{}, err
	}
	if _, err := ParseCAKeyGenerationID(string(facts.IssuerID)); err != nil {
		return Revocation{}, err
	}
	if facts.Serial.IsZero() {
		return Revocation{}, fmt.Errorf("%w: revocation serial must be set", ErrInvalidValue)
	}
	if facts.RevokedAt.IsZero() {
		return Revocation{}, fmt.Errorf("%w: revocation revoked_at must be set", ErrInvalidValue)
	}
	if err := facts.Reason.Validate(); err != nil {
		return Revocation{}, err
	}
	if err := facts.Source.Validate(); err != nil {
		return Revocation{}, err
	}
	return Revocation{
		id:               facts.ID,
		issuerID:         facts.IssuerID,
		serial:           facts.Serial,
		certificateID:    facts.CertificateID,
		revokedAt:        facts.RevokedAt,
		reason:           facts.Reason,
		source:           facts.Source,
		changeGeneration: facts.ChangeGeneration,
		needsReview:      facts.NeedsReview,
		version:          facts.Version,
	}, nil
}

func (r Revocation) ID() RevocationID             { return r.id }
func (r Revocation) IssuerID() CAKeyGenerationID  { return r.issuerID }
func (r Revocation) Serial() SerialNumber         { return r.serial }
func (r Revocation) CertificateID() CertificateID { return r.certificateID }
func (r Revocation) RevokedAt() Instant           { return r.revokedAt }
func (r Revocation) Reason() RevocationReason     { return r.reason }
func (r Revocation) Source() RevocationSource     { return r.source }
func (r Revocation) ChangeGeneration() int64      { return r.changeGeneration }
func (r Revocation) NeedsReview() bool            { return r.needsReview }
func (r Revocation) Version() Version             { return r.version }

// sameKey reports whether incoming targets the same (issuer, serial) ledger
// row as r. Merge/Correct never re-key a revocation.
func (r Revocation) sameKey(issuerID CAKeyGenerationID, serial SerialNumber) bool {
	return r.issuerID == issuerID && r.serial.Equal(serial)
}

// Merge reconciles an incoming assertion (from a new manual revoke, an
// import, or a CRL cascade) into the existing record.
//
//   - Identical facts (reason, revokedAt, source) leave the record
//     unchanged: certificate-lifecycle.md "동일 기록은 무변경".
//   - Conflicting facts (different reason or time) never auto-overwrite the
//     existing record; the existing record is kept and flagged
//     NeedsReview for an operator: planning.md "폐기 시각·사유 충돌은 기존
//     기록 유지 후 관리자 확인 대상으로 표시한다."
//   - There is no un-revoke: once revoked, Merge cannot clear the record.
//
// nextChangeGeneration is the generation to stamp on a record that actually
// changes (the CRL-affecting counter is bumped by the caller under the
// issuer's CRLState lock); it is ignored when nothing changes.
func (r Revocation) Merge(incoming RevocationFacts, nextChangeGeneration int64) (Revocation, bool, error) {
	if err := incoming.Reason.Validate(); err != nil {
		return Revocation{}, false, err
	}
	if err := incoming.Source.Validate(); err != nil {
		return Revocation{}, false, err
	}
	if incoming.Serial.IsZero() || incoming.RevokedAt.IsZero() {
		return Revocation{}, false, fmt.Errorf("%w: incoming revocation must carry serial and revoked_at", ErrInvalidValue)
	}
	if !r.sameKey(incoming.IssuerID, incoming.Serial) {
		return Revocation{}, false, fmt.Errorf("%w: merge target issuer/serial does not match existing revocation", ErrInvalidValue)
	}

	sameFacts := r.reason == incoming.Reason && r.revokedAt.Equal(incoming.RevokedAt)
	if sameFacts {
		next := r
		// A certificate link discovered later (e.g. import attaching an
		// unmatched entry) is not a conflict; it only fills in a
		// previously-unknown certificate id.
		if next.certificateID == "" && incoming.CertificateID != "" {
			next.certificateID = incoming.CertificateID
			next.version = r.version.Next()
			return next, true, nil
		}
		return r, false, nil
	}

	if r.needsReview {
		// Already flagged; a further conflicting assertion does not need a
		// second flag or version bump.
		return r, false, nil
	}
	next := r
	next.needsReview = true
	next.version = r.version.Next()
	return next, true, nil
}

// Correct is an explicit administrator correction: it is allowed to change
// reason/time even over a conflict flag, but it can never remove the
// revocation itself (certificate-lifecycle.md "폐기 해제 불가").
// justification is required and is expected to be preserved by the caller
// as a revocation_revisions row; the domain object itself does not retain
// history.
func (r Revocation) Correct(reason RevocationReason, revokedAt Instant, justification string, now Instant) (Revocation, error) {
	if err := reason.Validate(); err != nil {
		return Revocation{}, err
	}
	if revokedAt.IsZero() {
		return Revocation{}, fmt.Errorf("%w: corrected revoked_at must be set", ErrInvalidValue)
	}
	if justification == "" {
		return Revocation{}, fmt.Errorf("%w: correction requires a justification", ErrInvalidValue)
	}
	next := r
	next.reason = reason
	next.revokedAt = revokedAt
	next.needsReview = false
	next.version = r.version.Next()
	return next, nil
}

// PublicationState mirrors crl_states.publication_state.
type PublicationState string

const (
	PublicationStateInactive PublicationState = "inactive"
	PublicationStateActive   PublicationState = "active"
	PublicationStateClosed   PublicationState = "closed"
)

func (s PublicationState) Validate() error {
	switch s {
	case PublicationStateInactive, PublicationStateActive, PublicationStateClosed:
		return nil
	default:
		return fmt.Errorf("%w: unsupported publication state %q", ErrInvalidValue, string(s))
	}
}

// CRLState is the per-CA-key-generation publication ledger: reserved
// numbers, the revocation change generation and the currently published
// document. certificate-lifecycle.md: "CRL 번호는 CA별로 단조 증가... 번호와
// covered_generation 모두 후퇴하지 않아야 한다."
type CRLState struct {
	caKeyGenerationID      CAKeyGenerationID
	maxReservedNumber      CRLNumber
	revocationGeneration   int64
	publishedDocumentID    CRLDocumentID
	publishedNumber        CRLNumber
	publishedGeneration    int64
	nextPublishAt          Instant
	publicationState       PublicationState
	signingCACertificateID CertificateID // zero if not yet chosen
	version                Version
}

// CRLStateFacts is the constructor input, matching crl_states columns plus
// the two fields (publishedNumber/publishedGeneration) that the domain
// needs to enforce monotonicity and that the document row otherwise carries.
type CRLStateFacts struct {
	CAKeyGenerationID      CAKeyGenerationID
	MaxReservedNumber      CRLNumber
	RevocationGeneration   int64
	PublishedDocumentID    CRLDocumentID
	PublishedNumber        CRLNumber
	PublishedGeneration    int64
	NextPublishAt          Instant
	PublicationState       PublicationState
	SigningCACertificateID CertificateID
	Version                Version
}

// NewCRLState builds a CRLState from stored facts.
func NewCRLState(facts CRLStateFacts) (CRLState, error) {
	if _, err := ParseCAKeyGenerationID(string(facts.CAKeyGenerationID)); err != nil {
		return CRLState{}, err
	}
	if err := facts.PublicationState.Validate(); err != nil {
		return CRLState{}, err
	}
	if facts.RevocationGeneration < 0 {
		return CRLState{}, fmt.Errorf("%w: revocation generation must not be negative", ErrInvalidValue)
	}
	if facts.PublishedGeneration < 0 {
		return CRLState{}, fmt.Errorf("%w: published generation must not be negative", ErrInvalidValue)
	}
	return CRLState{
		caKeyGenerationID:      facts.CAKeyGenerationID,
		maxReservedNumber:      facts.MaxReservedNumber,
		revocationGeneration:   facts.RevocationGeneration,
		publishedDocumentID:    facts.PublishedDocumentID,
		publishedNumber:        facts.PublishedNumber,
		publishedGeneration:    facts.PublishedGeneration,
		nextPublishAt:          facts.NextPublishAt,
		publicationState:       facts.PublicationState,
		signingCACertificateID: facts.SigningCACertificateID,
		version:                facts.Version,
	}, nil
}

func (c CRLState) CAKeyGenerationID() CAKeyGenerationID  { return c.caKeyGenerationID }
func (c CRLState) MaxReservedNumber() CRLNumber          { return c.maxReservedNumber }
func (c CRLState) RevocationGeneration() int64           { return c.revocationGeneration }
func (c CRLState) PublishedDocumentID() CRLDocumentID    { return c.publishedDocumentID }
func (c CRLState) PublishedNumber() CRLNumber            { return c.publishedNumber }
func (c CRLState) PublishedGeneration() int64            { return c.publishedGeneration }
func (c CRLState) NextPublishAt() Instant                { return c.nextPublishAt }
func (c CRLState) PublicationState() PublicationState    { return c.publicationState }
func (c CRLState) SigningCACertificateID() CertificateID { return c.signingCACertificateID }
func (c CRLState) Version() Version                      { return c.version }

// DefaultCRLReissuePeriod and DefaultCRLValidity are the product defaults
// (certificate-lifecycle.md CRL table): reissue every 12h, valid for 48h
// from publication.
var (
	DefaultCRLReissuePeriod = NewDuration(12 * time.Hour)
	DefaultCRLValidity      = NewDuration(48 * time.Hour)
)

// BumpRevocationGeneration records that the revocation ledger changed. The
// caller does this once per commit (possibly for several revocation rows
// sharing one generation): data-model.md "여러 항목은 issuer별 generation을
// 한 번 증가시키고 같은 generation을 부여할 수 있다."
func (c CRLState) BumpRevocationGeneration() CRLState {
	next := c
	next.revocationGeneration = c.revocationGeneration + 1
	next.version = c.version.Next()
	return next
}

// ReserveNext reserves the next CRL number for this CA key. A failed
// reservation (the caller never publishes with it) is never reused:
// certificate-lifecycle.md "실패한 번호는 되돌리지 않는다." Reserving always
// advances maxReservedNumber, independent of whether publication later
// succeeds.
func (c CRLState) ReserveNext() (CRLNumber, CRLState) {
	next := c.maxReservedNumber.Increment()
	state := c
	state.maxReservedNumber = next
	state.version = c.version.Next()
	return next, state
}

// CanPublish reports whether a completed CRL document may become the
// published one. Both the number and the covered generation must not go
// backwards, even if completion order is reversed across concurrent CRL
// generation jobs: certificate-lifecycle.md "완료 순서가 역전돼도 게시가
// 후퇴하지 않는다."
func (c CRLState) CanPublish(number CRLNumber, coveredGeneration int64) error {
	if c.publicationState == PublicationStateClosed {
		return NewPolicyError(ErrNotPermitted, "crl_publication_closed", "CA key CRL publication is closed")
	}
	if !c.publishedNumber.IsZero() || c.publishedGeneration != 0 || !c.publishedDocumentID.equalZero() {
		if number.Compare(c.publishedNumber) <= 0 {
			return NewPolicyError(ErrConflict, "crl_number_regression",
				"a CRL with this number or older is already published")
		}
	}
	if coveredGeneration < c.publishedGeneration {
		return NewPolicyError(ErrConflict, "crl_generation_regression",
			"this CRL covers an older revocation generation than what is already published")
	}
	return nil
}

func (id CRLDocumentID) equalZero() bool { return id == "" }

// MarkPublished records a completed CRL document as the current published
// one. It re-checks CanPublish so callers cannot bypass the monotonicity
// rule by constructing state directly.
func (c CRLState) MarkPublished(documentID CRLDocumentID, number CRLNumber, coveredGeneration int64, nextPublishAt Instant) (CRLState, error) {
	if _, err := ParseCRLDocumentID(string(documentID)); err != nil {
		return CRLState{}, err
	}
	if err := c.CanPublish(number, coveredGeneration); err != nil {
		return CRLState{}, err
	}
	if nextPublishAt.IsZero() {
		return CRLState{}, fmt.Errorf("%w: next_publish_at must be set", ErrInvalidValue)
	}
	next := c
	next.publishedDocumentID = documentID
	next.publishedNumber = number
	next.publishedGeneration = coveredGeneration
	next.nextPublishAt = nextPublishAt
	if next.publicationState == PublicationStateInactive {
		next.publicationState = PublicationStateActive
	}
	next.version = c.version.Next()
	return next, nil
}

// SetSigningCertificate records which CA certificate signs this key
// generation's CRL. It does not depend on the authority's issuance state:
// certificate-lifecycle.md "발급 중지로 CRL 서명까지 자동 금지하지 않는다."
func (c CRLState) SetSigningCertificate(certificateID CertificateID) (CRLState, error) {
	if _, err := ParseCertificateID(string(certificateID)); err != nil {
		return CRLState{}, err
	}
	if c.publicationState == PublicationStateClosed {
		return CRLState{}, NewPolicyError(ErrNotPermitted, "crl_publication_closed", "CA key CRL publication is closed")
	}
	next := c
	next.signingCACertificateID = certificateID
	next.version = c.version.Next()
	return next, nil
}

// CRLClosureFacts carries the raw facts a service must have already
// gathered (from the CA/leaf domain area, which this file must not define)
// before a CA key's publication can be closed.
type CRLClosureFacts struct {
	AllCoveredCertificatesExpired bool
	FinalCRLCoversLastExpiry      bool
}

// Close ends CRL publication for a CA key generation once every certificate
// it ever signed has expired and a final CRL covering the last expiry has
// been published: certificate-lifecycle.md "등록된 하위 인증서 모두가 만료될
// 때까지 기존 CA의 CRL을 주기적으로 발행한다... 최종 CRL은 마지막 하위
// 만료일까지 검증에 사용 가능하도록 미리 발행한다."
func (c CRLState) Close(facts CRLClosureFacts) (CRLState, error) {
	if c.publicationState == PublicationStateClosed {
		return c, nil
	}
	if !facts.AllCoveredCertificatesExpired {
		return CRLState{}, NewPolicyError(ErrNotPermitted, "crl_close_pending_certificates",
			"not every certificate under this CA key has expired")
	}
	if !facts.FinalCRLCoversLastExpiry {
		return CRLState{}, NewPolicyError(ErrNotPermitted, "crl_close_missing_final_crl",
			"no final CRL covering the last expiry has been published")
	}
	next := c
	next.publicationState = PublicationStateClosed
	next.version = c.version.Next()
	return next, nil
}
