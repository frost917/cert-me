// Transition models normal and emergency CA replacement: the transition
// record itself, the per-certificate impact ledger, and manual deployment
// confirmations. Policy source: docs/certificate-lifecycle.md "정상 CA
// 교체", "CA 키 유출 시 긴급 처리"; docs/data-model.md "전환·외부 배포 확인".
package domain

import "fmt"

// TransitionMode mirrors ca_transitions.mode.
type TransitionMode string

const (
	TransitionModeNormal    TransitionMode = "normal"
	TransitionModeEmergency TransitionMode = "emergency"
)

func (m TransitionMode) Validate() error {
	switch m {
	case TransitionModeNormal, TransitionModeEmergency:
		return nil
	default:
		return fmt.Errorf("%w: unsupported transition mode %q", ErrInvalidValue, string(m))
	}
}

// TransitionState is the transition record's own lifecycle, distinct from
// per-certificate impacts and deployment confirmations. This mirrors
// api/openapi.json's Transition.state enum and the ca_transitions.state SQL
// column exactly: in_progress -> externally_completed -> closed (B02 ruling
// on Decision 1). Whether a successor authority has been chosen is NOT part
// of this state machine -- it is expressed by TargetAuthorityID being empty
// or set, so there is no longer a dedicated "target set" state.
type TransitionState string

const (
	// TransitionStateInProgress is the state right after Create: the source
	// (and, for emergency, its issuance) is already blocked by the caller,
	// but no target authority needs to exist yet
	// (data-model.md "긴급 신고 시 후속 CA가 없어도 등록 가능"). SetTarget is
	// legal at any point while the transition is in_progress, regardless of
	// whether a target has already been recorded (B02 ruling: "SetTarget은
	// in_progress 안에서 수행한다").
	TransitionStateInProgress TransitionState = "in_progress"
	// TransitionStateExternallyCompleted is reached via Complete once the
	// existing impact-handling and manual external-deployment-confirmation
	// conditions are satisfied (B02 ruling: "Complete는 기존 영향 처리·수동
	// 외부 배포 확인 조건을 검사해 externally_completed로 옮긴다").
	TransitionStateExternallyCompleted TransitionState = "externally_completed"
	// TransitionStateClosed additionally requires that the source
	// authority's own publication-termination condition (CRL issuance
	// having ended) is satisfied. It is terminal, but it must never be
	// inferred from Complete alone -- reaching it requires the separate
	// CloseAfterPublicationEnded transition below, which takes that fact as
	// explicit input (B02 ruling: "closed는 원본 CA의 게시 종료 조건까지
	// 충족한 상태이며 Complete만으로 추정하지 않는다").
	TransitionStateClosed TransitionState = "closed"
)

func (s TransitionState) Validate() error {
	switch s {
	case TransitionStateInProgress, TransitionStateExternallyCompleted, TransitionStateClosed:
		return nil
	default:
		return fmt.Errorf("%w: unsupported transition state %q", ErrInvalidValue, string(s))
	}
}

// Transition is one ca_transitions row: a single source authority's
// replacement, normal or emergency.
type Transition struct {
	id                TransitionID
	sourceAuthorityID AuthorityID
	targetAuthorityID AuthorityID // zero until SetTarget
	mode              TransitionMode
	state             TransitionState
	reportedBy        AccountID
	reportedAt        Instant
	reason            string
	version           Version
}

// TransitionFacts is the constructor input, matching ca_transitions columns.
type TransitionFacts struct {
	ID                TransitionID
	SourceAuthorityID AuthorityID
	TargetAuthorityID AuthorityID
	Mode              TransitionMode
	State             TransitionState
	ReportedBy        AccountID
	ReportedAt        Instant
	Reason            string
	Version           Version
}

// NewTransition builds a Transition from stored facts. A fresh emergency
// transition may be created with no target authority at all.
func NewTransition(facts TransitionFacts) (Transition, error) {
	if _, err := ParseTransitionID(string(facts.ID)); err != nil {
		return Transition{}, err
	}
	if _, err := ParseAuthorityID(string(facts.SourceAuthorityID)); err != nil {
		return Transition{}, err
	}
	if facts.TargetAuthorityID != "" {
		if _, err := ParseAuthorityID(string(facts.TargetAuthorityID)); err != nil {
			return Transition{}, err
		}
	}
	if err := facts.Mode.Validate(); err != nil {
		return Transition{}, err
	}
	if err := facts.State.Validate(); err != nil {
		return Transition{}, err
	}
	if _, err := ParseAccountID(string(facts.ReportedBy)); err != nil {
		return Transition{}, err
	}
	if facts.ReportedAt.IsZero() {
		return Transition{}, fmt.Errorf("%w: transition reported_at must be set", ErrInvalidValue)
	}
	return Transition{
		id:                facts.ID,
		sourceAuthorityID: facts.SourceAuthorityID,
		targetAuthorityID: facts.TargetAuthorityID,
		mode:              facts.Mode,
		state:             facts.State,
		reportedBy:        facts.ReportedBy,
		reportedAt:        facts.ReportedAt,
		reason:            facts.Reason,
		version:           facts.Version,
	}, nil
}

func (t Transition) ID() TransitionID               { return t.id }
func (t Transition) SourceAuthorityID() AuthorityID { return t.sourceAuthorityID }
func (t Transition) TargetAuthorityID() AuthorityID { return t.targetAuthorityID }
func (t Transition) Mode() TransitionMode           { return t.mode }
func (t Transition) State() TransitionState         { return t.state }
func (t Transition) ReportedBy() AccountID          { return t.reportedBy }
func (t Transition) ReportedAt() Instant            { return t.reportedAt }
func (t Transition) Reason() string                 { return t.reason }
func (t Transition) Version() Version               { return t.version }

// IsInProgress reports whether the transition is still open (B02: the only
// state SetTarget and ConfirmDeployment may act on).
func (t Transition) IsInProgress() bool { return t.state == TransitionStateInProgress }

// IsExternallyCompleted reports whether Complete has run, i.e. the transition
// has reached externally_completed but not yet closed.
func (t Transition) IsExternallyCompleted() bool {
	return t.state == TransitionStateExternallyCompleted
}

// IsClosed reports whether the transition has reached the terminal closed
// state (B02: only reachable via Close, never via Complete alone).
func (t Transition) IsClosed() bool { return t.state == TransitionStateClosed }

// SetTarget records or replaces the successor authority. B02 ruling: this is
// legal any time the transition is in_progress, so a transition created
// without a target (emergency report before a replacement CA exists) can
// adopt one later, and it is rejected once the transition has moved past
// in_progress (Complete/Close already run).
func (t Transition) SetTarget(targetAuthorityID AuthorityID, now Instant) (Transition, error) {
	if !t.IsInProgress() {
		return Transition{}, NewPolicyError(ErrInvalidTransition, "transition_not_in_progress",
			"transition is no longer in_progress")
	}
	if _, err := ParseAuthorityID(string(targetAuthorityID)); err != nil {
		return Transition{}, err
	}
	next := t
	next.targetAuthorityID = targetAuthorityID
	next.version = t.version.Next()
	// now is accepted for signature uniformity with every other domain
	// transition, but ca_transitions stores no timestamp beyond reported_at
	// (data-model.md), so there is nothing here to stamp. This is a schema
	// fact, not an oversight: if a closed_at/completed_at column is ever
	// added, the value is already threaded in.
	_ = now
	return next, nil
}

// ConfirmDeployment validates that a manual deployment confirmation may be
// recorded against this transition right now. The confirmation row itself
// (target label, action, actor) is a separate DeploymentConfirmation,
// appended by the caller: manual confirmations are never overwritten or
// dropped by other transition operations
// (backend-implementation.md §2 "수동 확인 보존"). Confirmations only make
// sense while the transition is still in_progress; once Complete has run the
// external deployment has already been confirmed and closed off.
func (t Transition) ConfirmDeployment(now Instant) error {
	if !t.IsInProgress() {
		return NewPolicyError(ErrInvalidTransition, "transition_not_in_progress",
			"transition is no longer in_progress")
	}
	// now is accepted for signature uniformity with every other domain
	// transition, but ca_transitions stores no timestamp beyond reported_at
	// (data-model.md), so there is nothing here to stamp. This is a schema
	// fact, not an oversight: if a closed_at/completed_at column is ever
	// added, the value is already threaded in.
	_ = now
	return nil
}

// TransitionClosureFacts is the raw evidence Complete needs, gathered by
// the caller from the impact ledger and the confirmation rows.
type TransitionClosureFacts struct {
	// AllImpactsAddressed is true once every affected certificate either has
	// a recorded replacement or has been explicitly acknowledged as not
	// needing one (e.g. already expired).
	AllImpactsAddressed bool
	// ManualDeploymentConfirmed is true once an operator has recorded the
	// out-of-band trust/rollout confirmation for this transition. MVP never
	// infers this from internal state alone
	// (certificate-lifecycle.md "외부 장비의 전환이 자동으로 완료됐다고
	// 추정하지 않는다").
	ManualDeploymentConfirmed bool
}

// Complete moves the transition from in_progress to externally_completed
// once both the certificate-level impact and the external deployment have
// been confirmed. It requires a target authority to exist by this point even
// though Create/SetTarget allowed one to be added later. B02 ruling:
// externally_completed is NOT the same as closed -- reaching closed also
// requires the source CA's publication-termination condition, checked
// separately by Close, and must never be inferred from Complete alone.
func (t Transition) Complete(facts TransitionClosureFacts, now Instant) (Transition, error) {
	if !t.IsInProgress() {
		return Transition{}, NewPolicyError(ErrInvalidTransition, "transition_not_in_progress",
			"transition is no longer in_progress")
	}
	if t.targetAuthorityID == "" {
		return Transition{}, NewPolicyError(ErrNotPermitted, "transition_no_target",
			"transition has no successor authority")
	}
	if !facts.AllImpactsAddressed {
		return Transition{}, NewPolicyError(ErrNotPermitted, "transition_impacts_pending",
			"not every affected certificate has been reissued or explicitly resolved")
	}
	if !facts.ManualDeploymentConfirmed {
		return Transition{}, NewPolicyError(ErrNotPermitted, "transition_deployment_unconfirmed",
			"external deployment has not been confirmed")
	}
	next := t
	next.state = TransitionStateExternallyCompleted
	next.version = t.version.Next()
	// now is accepted for signature uniformity with every other domain
	// transition, but ca_transitions stores no timestamp beyond reported_at
	// (data-model.md), so there is nothing here to stamp. This is a schema
	// fact, not an oversight: if a closed_at/completed_at column is ever
	// added, the value is already threaded in.
	_ = now
	return next, nil
}

// TransitionTerminationFacts is the raw evidence Close needs, gathered by
// the caller (B04 wires this to the source authority's CRL state; the
// domain itself never reaches into a repository -- B02 ruling: "CRL 종료와
// 연결하는 별도 도메인 전이가 필요하다").
type TransitionTerminationFacts struct {
	// SourceCAPublicationEnded is true once the source authority's own
	// publication of revocation status (CRL issuance) has ended. This is
	// the additional condition closed requires beyond Complete's checks
	// (B02 ruling: "closed는 원본 CA의 게시 종료 조건까지 충족한 상태").
	SourceCAPublicationEnded bool
}

// Close moves the transition from externally_completed to the terminal
// closed state once the source authority's publication-termination
// condition is also satisfied. This is deliberately a separate transition
// from Complete: closed must never be assumed just because the external
// deployment was confirmed (B02 ruling, same citation as
// TransitionTerminationFacts above).
func (t Transition) Close(facts TransitionTerminationFacts, now Instant) (Transition, error) {
	if t.IsInProgress() {
		return Transition{}, NewPolicyError(ErrInvalidTransition, "transition_not_externally_completed",
			"transition must be externally_completed before it can be closed")
	}
	if t.IsClosed() {
		return Transition{}, NewPolicyError(ErrInvalidTransition, "transition_closed",
			"transition is already closed")
	}
	if !facts.SourceCAPublicationEnded {
		return Transition{}, NewPolicyError(ErrNotPermitted, "transition_publication_not_ended",
			"source authority has not finished ending its publication of revocation status")
	}
	next := t
	next.state = TransitionStateClosed
	next.version = t.version.Next()
	// now is accepted for signature uniformity with every other domain
	// transition, but ca_transitions stores no timestamp beyond reported_at
	// (data-model.md), so there is nothing here to stamp. This is a schema
	// fact, not an oversight: if a closed_at/completed_at column is ever
	// added, the value is already threaded in.
	_ = now
	return next, nil
}

// TransitionImpact is one transition_impacts row: it records that a
// certificate is affected by a CA-level transition. Recording an impact
// never itself revokes anything — CA-level impact and per-certificate
// revocation are deliberately separate facts
// (certificate-lifecycle.md "상위 CA 폐기와 하위 인증서 각각의 명시적 폐기
// 기록은 구분한다"; planning.md "상위 영향이 자동 개별 폐기로 표시되지
// 않는다"). Producing a Revocation for an affected certificate is a
// distinct, explicit act the caller performs separately.
type TransitionImpact struct {
	transitionID             TransitionID
	certificateID            CertificateID
	replacementCertificateID CertificateID // zero until reissued
	reissuedAt               Instant
}

// TransitionImpactFacts is the constructor input.
type TransitionImpactFacts struct {
	TransitionID             TransitionID
	CertificateID            CertificateID
	ReplacementCertificateID CertificateID
	ReissuedAt               Instant
}

// NewTransitionImpact builds a TransitionImpact from stored facts.
func NewTransitionImpact(facts TransitionImpactFacts) (TransitionImpact, error) {
	if _, err := ParseTransitionID(string(facts.TransitionID)); err != nil {
		return TransitionImpact{}, err
	}
	if _, err := ParseCertificateID(string(facts.CertificateID)); err != nil {
		return TransitionImpact{}, err
	}
	if facts.ReplacementCertificateID != "" {
		if _, err := ParseCertificateID(string(facts.ReplacementCertificateID)); err != nil {
			return TransitionImpact{}, err
		}
		if facts.ReissuedAt.IsZero() {
			return TransitionImpact{}, fmt.Errorf("%w: an impact with a replacement needs reissued_at", ErrInvalidValue)
		}
	}
	return TransitionImpact{
		transitionID:             facts.TransitionID,
		certificateID:            facts.CertificateID,
		replacementCertificateID: facts.ReplacementCertificateID,
		reissuedAt:               facts.ReissuedAt,
	}, nil
}

func (i TransitionImpact) TransitionID() TransitionID              { return i.transitionID }
func (i TransitionImpact) CertificateID() CertificateID            { return i.certificateID }
func (i TransitionImpact) ReplacementCertificateID() CertificateID { return i.replacementCertificateID }
func (i TransitionImpact) ReissuedAt() Instant                     { return i.reissuedAt }
func (i TransitionImpact) IsResolved() bool                        { return i.replacementCertificateID != "" }

// RecordReplacement attaches a successful reissue's certificate to this
// impact. A failed reissue attempt must not call this: it stays unresolved
// so the pending-impact list keeps surfacing it
// (data-model.md "실패한 대체 발급은 인증서 계보에 남고 성공 대상 포인터
// 갱신").
func (i TransitionImpact) RecordReplacement(replacementCertificateID CertificateID, now Instant) (TransitionImpact, error) {
	if i.IsResolved() {
		return TransitionImpact{}, NewPolicyError(ErrInvalidTransition, "impact_already_resolved",
			"this impact already has a replacement certificate")
	}
	if _, err := ParseCertificateID(string(replacementCertificateID)); err != nil {
		return TransitionImpact{}, err
	}
	if now.IsZero() {
		return TransitionImpact{}, fmt.Errorf("%w: reissued_at must be set", ErrInvalidValue)
	}
	next := i
	next.replacementCertificateID = replacementCertificateID
	next.reissuedAt = now
	return next, nil
}

// DeploymentAction mirrors deployment_confirmations.action.
type DeploymentAction string

const (
	DeploymentActionTrustAdded DeploymentAction = "trust_added"
	// DeploymentActionCertificateInstalled is an admin's manual confirmation
	// that the named certificate and its corresponding key have been
	// installed on the target. It is recordable for an ordinary same-key
	// renewal too, and does NOT by itself imply that a new key was
	// generated -- the emergency-transition rule requiring a new key is
	// enforced separately by issuance policy, not by this enum (B02 ruling
	// on Decision 2: "같은 키를 재사용한 정상 갱신에도 기록할 수 있으며 항상
	// 새 키를 만들었다는 뜻은 아니다").
	DeploymentActionCertificateInstalled DeploymentAction = "certificate_installed"
	DeploymentActionTrustRemoved         DeploymentAction = "trust_removed"
)

func (a DeploymentAction) Validate() error {
	switch a {
	case DeploymentActionTrustAdded, DeploymentActionCertificateInstalled, DeploymentActionTrustRemoved:
		return nil
	default:
		return fmt.Errorf("%w: unsupported deployment action %q", ErrInvalidValue, string(a))
	}
}

// DeploymentConfirmation is one manual, operator-entered record that a
// target device's trust store or certificate/key was updated, or that trust
// in the retired CA was removed. It is never inferred automatically
// (certificate-lifecycle.md "MVP에서는 관리자가 전환을 진행하며").
type DeploymentConfirmation struct {
	transitionID  TransitionID
	certificateID CertificateID // optional: some confirmations are trust-store-wide
	targetLabel   string
	action        DeploymentAction
	confirmedBy   AccountID
	confirmedAt   Instant
}

// DeploymentConfirmationFacts is the constructor input.
type DeploymentConfirmationFacts struct {
	TransitionID  TransitionID
	CertificateID CertificateID
	TargetLabel   string
	Action        DeploymentAction
	ConfirmedBy   AccountID
	ConfirmedAt   Instant
}

// NewDeploymentConfirmation builds a DeploymentConfirmation from stored
// facts.
func NewDeploymentConfirmation(facts DeploymentConfirmationFacts) (DeploymentConfirmation, error) {
	if _, err := ParseTransitionID(string(facts.TransitionID)); err != nil {
		return DeploymentConfirmation{}, err
	}
	if facts.CertificateID != "" {
		if _, err := ParseCertificateID(string(facts.CertificateID)); err != nil {
			return DeploymentConfirmation{}, err
		}
	}
	if facts.TargetLabel == "" {
		return DeploymentConfirmation{}, fmt.Errorf("%w: deployment confirmation needs a target label", ErrInvalidValue)
	}
	if err := facts.Action.Validate(); err != nil {
		return DeploymentConfirmation{}, err
	}
	if _, err := ParseAccountID(string(facts.ConfirmedBy)); err != nil {
		return DeploymentConfirmation{}, err
	}
	if facts.ConfirmedAt.IsZero() {
		return DeploymentConfirmation{}, fmt.Errorf("%w: deployment confirmation needs confirmed_at", ErrInvalidValue)
	}
	return DeploymentConfirmation{
		transitionID:  facts.TransitionID,
		certificateID: facts.CertificateID,
		targetLabel:   facts.TargetLabel,
		action:        facts.Action,
		confirmedBy:   facts.ConfirmedBy,
		confirmedAt:   facts.ConfirmedAt,
	}, nil
}

func (c DeploymentConfirmation) TransitionID() TransitionID   { return c.transitionID }
func (c DeploymentConfirmation) CertificateID() CertificateID { return c.certificateID }
func (c DeploymentConfirmation) TargetLabel() string          { return c.targetLabel }
func (c DeploymentConfirmation) Action() DeploymentAction     { return c.action }
func (c DeploymentConfirmation) ConfirmedBy() AccountID       { return c.confirmedBy }
func (c DeploymentConfirmation) ConfirmedAt() Instant         { return c.confirmedAt }
