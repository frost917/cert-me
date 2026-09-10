package contract

import (
	"fmt"

	"cert-me/internal/domain"
)

// This file is TransitionService's command/result contract
// (docs/backend-implementation.md §3): Create, SetTarget, ConfirmDeployment,
// Complete.
//
// NOTE on a documentation/OpenAPI disagreement, reported per the task
// instructions rather than silently resolved: domain.TransitionState (see
// internal/domain/transition.go) is reported/target_set/completed, while
// api/openapi.json's Transition.state enum is
// in_progress/externally_completed/closed, and domain.DeploymentAction is
// trust_added/cert_key_replaced/trust_removed while OpenAPI's
// Deployment/DeploymentInput.action enum is
// trust_added/certificate_installed/trust_removed. Views below expose the
// OpenAPI wire values directly (TransitionStateView, DeploymentActionInput/
// View) with an explicit mapping to the domain enum, so the HTTP surface
// matches api/openapi.json exactly; the mapping tables are the one place
// that mismatch is bridged.

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

// DeploymentActionInput mirrors the OpenAPI DeploymentInput/Deployment
// action enum, which spells the certificate-installed case differently from
// domain.DeploymentAction (see the file-level NOTE above).
type DeploymentActionInput string

const (
	DeploymentActionInputTrustAdded           DeploymentActionInput = "trust_added"
	DeploymentActionInputCertificateInstalled DeploymentActionInput = "certificate_installed"
	DeploymentActionInputTrustRemoved         DeploymentActionInput = "trust_removed"
)

var deploymentActionToDomain = map[DeploymentActionInput]domain.DeploymentAction{
	DeploymentActionInputTrustAdded:           domain.DeploymentActionTrustAdded,
	DeploymentActionInputCertificateInstalled: domain.DeploymentActionCertReplaced,
	DeploymentActionInputTrustRemoved:         domain.DeploymentActionTrustRemoved,
}

var domainToDeploymentAction = func() map[domain.DeploymentAction]DeploymentActionInput {
	out := make(map[domain.DeploymentAction]DeploymentActionInput, len(deploymentActionToDomain))
	for wire, d := range deploymentActionToDomain {
		out[d] = wire
	}
	return out
}()

func (a DeploymentActionInput) Domain() (domain.DeploymentAction, error) {
	action, ok := deploymentActionToDomain[a]
	if !ok {
		return "", fmt.Errorf("%w: unsupported deployment action %q", domain.ErrInvalidValue, string(a))
	}
	return action, nil
}

// DeploymentActionView renders a domain action back to its wire form.
func DeploymentActionView(a domain.DeploymentAction) string {
	return string(domainToDeploymentAction[a])
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

// TransitionStateView mirrors OpenAPI's Transition.state enum.
type TransitionStateView string

const (
	TransitionStateViewInProgress          TransitionStateView = "in_progress"
	TransitionStateViewExternallyCompleted TransitionStateView = "externally_completed"
	TransitionStateViewClosed              TransitionStateView = "closed"
)

// DeploymentView is the OpenAPI Deployment data object.
type DeploymentView struct {
	ID            string // deployment_confirmations has no dedicated typed ID in domain
	TargetLabel   string
	CertificateID *domain.CertificateID
	Action        domain.DeploymentAction
	ConfirmedAt   domain.Instant
	ConfirmedBy   domain.AccountID
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
