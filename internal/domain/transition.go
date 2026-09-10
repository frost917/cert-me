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
// per-certificate impacts and deployment confirmations.
type TransitionState string

const (
	// TransitionStateReported is the state right after Create: the source
	// (and, for emergency, its issuance) is already blocked by the caller,
	// but no target authority needs to exist yet
	// (data-model.md "긴급 신고 시 후속 CA가 없어도 등록 가능").
	TransitionStateReported TransitionState = "reported"
	// TransitionStateTargetSet means a successor authority has been chosen.
	TransitionStateTargetSet TransitionState = "target_set"
	// TransitionStateCompleted is terminal.
	TransitionStateCompleted TransitionState = "completed"
)

func (s TransitionState) Validate() error {
	switch s {
	case TransitionStateReported, TransitionStateTargetSet, TransitionStateCompleted:
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

func (t Transition) IsCompleted() bool { return t.state == TransitionStateCompleted }

// SetTarget records or replaces the successor authority. It is legal any
// time before completion, so a transition created without a target
// (emergency report before a replacement CA exists) can adopt one later.
func (t Transition) SetTarget(targetAuthorityID AuthorityID, now Instant) (Transition, error) {
	if t.IsCompleted() {
		return Transition{}, NewPolicyError(ErrInvalidTransition, "transition_completed",
			"transition is already completed")
	}
	if _, err := ParseAuthorityID(string(targetAuthorityID)); err != nil {
		return Transition{}, err
	}
	next := t
	next.targetAuthorityID = targetAuthorityID
	if next.state == TransitionStateReported {
		next.state = TransitionStateTargetSet
	}
	next.version = t.version.Next()
	_ = now
	return next, nil
}

// ConfirmDeployment validates that a manual deployment confirmation may be
// recorded against this transition right now. The confirmation row itself
// (target label, action, actor) is a separate DeploymentConfirmation,
// appended by the caller: manual confirmations are never overwritten or
// dropped by other transition operations
// (backend-implementation.md §2 "수동 확인 보존").
func (t Transition) ConfirmDeployment(now Instant) error {
	if t.IsCompleted() {
		return NewPolicyError(ErrInvalidTransition, "transition_completed",
			"transition is already completed")
	}
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

// Complete closes the transition once both the certificate-level impact and
// the external deployment have been confirmed. It requires a target
// authority to exist by this point even though Create/SetTarget allowed one
// to be added later.
func (t Transition) Complete(facts TransitionClosureFacts, now Instant) (Transition, error) {
	if t.IsCompleted() {
		return Transition{}, NewPolicyError(ErrInvalidTransition, "transition_completed",
			"transition is already completed")
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
	next.state = TransitionStateCompleted
	next.version = t.version.Next()
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
	DeploymentActionTrustAdded   DeploymentAction = "trust_added"
	DeploymentActionCertReplaced DeploymentAction = "cert_key_replaced"
	DeploymentActionTrustRemoved DeploymentAction = "trust_removed"
)

func (a DeploymentAction) Validate() error {
	switch a {
	case DeploymentActionTrustAdded, DeploymentActionCertReplaced, DeploymentActionTrustRemoved:
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
