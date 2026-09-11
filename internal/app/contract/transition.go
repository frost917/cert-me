package contract

import (
	"cert-me/internal/domain"
)

// This file is TransitionService's command/result contract
// (docs/backend-implementation.md §3): Create, SetTarget, ConfirmDeployment,
// Complete.
//
// B02 planning ruling settled the two open questions this file used to
// carry translation tables for: domain.TransitionState now uses the exact
// same vocabulary as api/openapi.json's Transition.state enum
// (in_progress/externally_completed/closed), and domain.DeploymentAction
// now uses the exact same vocabulary as OpenAPI's
// Deployment/DeploymentInput.action enum (including
// certificate_installed). So the wire types below are aliases of the
// domain types, not translated views -- there is nothing left to bridge.

// TransitionModeInput mirrors domain.TransitionMode 1:1 on the wire (both
// use normal/emergency), so no translation table is needed for mode.
type TransitionModeInput string

func (m TransitionModeInput) Domain() (domain.TransitionMode, error) {
	mode := domain.TransitionMode(m)
	if err := mode.Validate(); err != nil {
		return "", err
	}
	return mode, nil
}

const maxTransitionReasonLength = 4096

// TransitionCreateCommand is the OpenAPI TransitionCreate schema.
type TransitionCreateCommand struct {
	SourceAuthorityID domain.AuthorityID  `json:"source_authority_id"`
	TargetAuthorityID domain.AuthorityID  `json:"target_authority_id,omitempty"`
	Mode              TransitionModeInput `json:"mode"`
	Reason            string              `json:"reason"`
}

func (c TransitionCreateCommand) Validate() error {
	if _, err := domain.ParseAuthorityID(string(c.SourceAuthorityID)); err != nil {
		return FromDomainError(err)
	}
	if c.TargetAuthorityID != "" {
		if _, err := domain.ParseAuthorityID(string(c.TargetAuthorityID)); err != nil {
			return FromDomainError(err)
		}
	}
	if _, err := c.Mode.Domain(); err != nil {
		return FromDomainError(err)
	}
	if c.Reason == "" {
		return NewAppError(ErrorKindValidation, "reason_required", "reason must not be empty")
	}
	if len(c.Reason) > maxTransitionReasonLength {
		return NewAppError(ErrorKindValidation, "reason_too_long", "reason must be at most 4096 characters")
	}
	return nil
}

// TransitionSetTargetCommand is the OpenAPI TransitionPatch schema.
// TransitionID is the path target; §3 requires the Transition version via
// MutationMeta.
type TransitionSetTargetCommand struct {
	TransitionID      domain.TransitionID `json:"-"`
	TargetAuthorityID domain.AuthorityID  `json:"target_authority_id"`
}

func (c TransitionSetTargetCommand) Validate() error {
	if _, err := domain.ParseTransitionID(string(c.TransitionID)); err != nil {
		return FromDomainError(err)
	}
	if _, err := domain.ParseAuthorityID(string(c.TargetAuthorityID)); err != nil {
		return FromDomainError(err)
	}
	return nil
}

// DeploymentActionInput mirrors domain.DeploymentAction 1:1 on the wire
// (B02 ruling: both now spell the manual-install case
// "certificate_installed"), so no translation table is needed, matching
// TransitionModeInput's pattern above.
type DeploymentActionInput string

const (
	DeploymentActionInputTrustAdded           DeploymentActionInput = "trust_added"
	DeploymentActionInputCertificateInstalled DeploymentActionInput = "certificate_installed"
	DeploymentActionInputTrustRemoved         DeploymentActionInput = "trust_removed"
)

func (a DeploymentActionInput) Domain() (domain.DeploymentAction, error) {
	action := domain.DeploymentAction(a)
	if err := action.Validate(); err != nil {
		return "", err
	}
	return action, nil
}

// DeploymentActionView renders a domain action back to its wire form. Since
// the two vocabularies are identical (B02 ruling), this is a plain cast, not
// a lookup.
func DeploymentActionView(a domain.DeploymentAction) string {
	return string(a)
}

const maxTargetLabelLength = 255

// TransitionConfirmDeploymentCommand is the OpenAPI DeploymentInput schema.
// TransitionID is the path target.
type TransitionConfirmDeploymentCommand struct {
	TransitionID  domain.TransitionID   `json:"-"`
	TargetLabel   string                `json:"target_label"`
	CertificateID domain.CertificateID  `json:"certificate_id,omitempty"`
	Action        DeploymentActionInput `json:"action"`
}

func (c TransitionConfirmDeploymentCommand) Validate() error {
	if _, err := domain.ParseTransitionID(string(c.TransitionID)); err != nil {
		return FromDomainError(err)
	}
	if c.TargetLabel == "" || len(c.TargetLabel) > maxTargetLabelLength {
		return NewAppError(ErrorKindValidation, "target_label_invalid", "target_label must be 1..255 characters")
	}
	if c.CertificateID != "" {
		if _, err := domain.ParseCertificateID(string(c.CertificateID)); err != nil {
			return FromDomainError(err)
		}
	}
	if _, err := c.Action.Domain(); err != nil {
		return FromDomainError(err)
	}
	return nil
}

// TransitionCompleteCommand is the empty command for Complete.
// TransitionID is the path target.
type TransitionCompleteCommand struct {
	TransitionID domain.TransitionID `json:"-"`
}

func (c TransitionCompleteCommand) Validate() error {
	if _, err := domain.ParseTransitionID(string(c.TransitionID)); err != nil {
		return FromDomainError(err)
	}
	return nil
}

// TransitionStateView mirrors OpenAPI's Transition.state enum, which is now
// identical to domain.TransitionState (B02 ruling on Decision 1).
type TransitionStateView string

const (
	TransitionStateViewInProgress          TransitionStateView = "in_progress"
	TransitionStateViewExternallyCompleted TransitionStateView = "externally_completed"
	TransitionStateViewClosed              TransitionStateView = "closed"
)

// TransitionStateViewOf renders a domain state to its wire form. Since the
// two vocabularies are identical (B02 ruling), this is a plain cast.
func TransitionStateViewOf(s domain.TransitionState) TransitionStateView {
	return TransitionStateView(s)
}

// DeploymentView is the OpenAPI Deployment data object. Action is the wire
// enum type (DeploymentActionInput) rather than domain.DeploymentAction
// purely to keep the wire-shaped views consistent with the input side; the
// two vocabularies hold identical values (B02 ruling), so
// NewDeploymentActionView is a plain cast, not a translation.
type DeploymentView struct {
	ID            string // deployment_confirmations has no dedicated typed ID in domain
	TargetLabel   string
	CertificateID *domain.CertificateID
	Action        DeploymentActionInput
	ConfirmedAt   domain.Instant
	ConfirmedBy   domain.AccountID
}

// NewDeploymentActionView converts a domain action to the wire-view value
// DeploymentView.Action holds, using the same total, bijective mapping table
// DeploymentActionInput.Domain() reads in the other direction.
func NewDeploymentActionView(a domain.DeploymentAction) DeploymentActionInput {
	return DeploymentActionInput(DeploymentActionView(a))
}

// TransitionView is the OpenAPI Transition data object.
type TransitionView struct {
	ID                         domain.TransitionID
	SourceAuthorityID          domain.AuthorityID
	TargetAuthorityID          *domain.AuthorityID
	Mode                       domain.TransitionMode
	State                      TransitionStateView
	ExternalTransitionComplete bool
	CAPublicationClosed        bool
	Impacts                    []ImpactView
	Version                    domain.Version
	CreatedAt                  domain.Instant
}
