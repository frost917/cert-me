package contract

import (
	"cert-me/internal/domain"
)

// AuthorityView is the OpenAPI Authority data object.
//
// The schema also carries a "crl" field ($ref CRLStatus), but no CRLStatus
// Go type exists yet anywhere in internal/app/contract -- views.go (owned by
// another developer, out of this file's scope) has no CRLStatusView, and
// CRLStatus is shared across Authority and the CRL/Query services' own
// tables, so it is not this file's call to add one. The field is omitted
// here rather than guessed at; see the round's report for the escalation.
type AuthorityView struct {
	ID                    domain.AuthorityID
	Kind                  domain.AuthorityKind
	Name                  string
	ManagementParentID    *domain.AuthorityID
	IssuanceState         domain.IssuanceState
	IssuanceCertificateID *domain.CertificateID
	KeyGenerationID       domain.CAKeyGenerationID
	KeyAvailable          bool
	Affected              bool
	NotAfter              domain.Instant
	ArchivedAt            *domain.Instant
	Version               domain.Version
	CreatedAt             domain.Instant
}

// AuthorityCreateCommand is the JSON decode target for the OpenAPI
// AuthorityCreate schema. It has no target id field: Create makes a new
// Authority rather than acting on an existing path id
// (backend-implementation.md §3: "Create는 idempotency" -- the retry key
// lives on MutationMeta, not here).
type AuthorityCreateCommand struct {
	Kind              string             `json:"kind"`
	Name              string             `json:"name"`
	ParentAuthorityID domain.AuthorityID `json:"parent_authority_id,omitempty"`
	Subject           SubjectInput       `json:"subject"`
	KeyAlgorithm      string             `json:"key_algorithm,omitempty"`
	Validity          *ValidityInput     `json:"validity,omitempty"`
}

// DomainKind converts and validates the kind field.
func (c AuthorityCreateCommand) DomainKind() (domain.AuthorityKind, error) {
	kind := domain.AuthorityKind(c.Kind)
	if err := kind.Validate(); err != nil {
		return "", err
	}
	// AuthorityCreate's own enum is root/intermediate only; bootstrap is a
	// separate, internal-only authority kind that this public command must
	// never be able to select.
	if kind == domain.AuthorityKindBootstrap {
		return "", NewAppError(ErrorKindValidation, "invalid_kind", "kind must be root or intermediate")
	}
	return kind, nil
}

// DomainKeyAlgorithm converts the optional key_algorithm, returning the
// product default when the field was omitted.
func (c AuthorityCreateCommand) DomainKeyAlgorithm() (domain.KeyAlgorithm, error) {
	if c.KeyAlgorithm == "" {
		return domain.DefaultKeyAlgorithm, nil
	}
	alg := domain.KeyAlgorithm(c.KeyAlgorithm)
	if err := alg.Validate(); err != nil {
		return "", err
	}
	return alg, nil
}

// DomainSubject converts and validates the subject field.
func (c AuthorityCreateCommand) DomainSubject() (domain.Subject, error) {
	return c.Subject.Domain()
}

const maxCreateAuthorityNameLength = 255

// Validate mirrors the AuthorityCreate schema's required set (kind, name,
// subject) and its description's cross-field rule: intermediate requires
// parent_authority_id, root forbids it.
func (c AuthorityCreateCommand) Validate() error {
	kind, err := c.DomainKind()
	if err != nil {
		return err
	}
	if c.Name == "" || len(c.Name) > maxCreateAuthorityNameLength {
		return NewAppError(ErrorKindValidation, "invalid_name", "name must be 1..255 characters")
	}
	switch kind {
	case domain.AuthorityKindIntermediate:
		if _, err := domain.ParseAuthorityID(string(c.ParentAuthorityID)); err != nil {
			return NewAppError(ErrorKindValidation, "invalid_parent_authority_id", "intermediate authority requires a valid parent_authority_id")
		}
	case domain.AuthorityKindRoot:
		if c.ParentAuthorityID != "" {
			return NewAppError(ErrorKindValidation, "unexpected_parent_authority_id", "root authority must not have a parent_authority_id")
		}
	}
	if _, err := c.DomainSubject(); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_subject", "subject is invalid")
	}
	if _, err := c.DomainKeyAlgorithm(); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_key_algorithm", "key_algorithm is unsupported")
	}
	if c.Validity != nil {
		if _, err := c.Validity.Domain(); err != nil {
			return NewAppError(ErrorKindValidation, "invalid_validity", "validity must have a positive value and a supported unit")
		}
	}
	return nil
}

// AuthorityRenameCommand is the JSON decode target for the OpenAPI NamePatch
// schema. AuthorityID is the URL path target: it is tagged json:"-" so a
// request body can never override which authority is renamed
// (backend-implementation.md §3: "JSON decoder는 이 필드를 받지 않고 핸들러가
// 검증된 path에서 채운다").
type AuthorityRenameCommand struct {
	AuthorityID domain.AuthorityID `json:"-"`
	Name        string             `json:"name"`
}

func (c AuthorityRenameCommand) Validate() error {
	if _, err := domain.ParseAuthorityID(string(c.AuthorityID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_authority_id", "authority id must be a uuid")
	}
	if c.Name == "" || len(c.Name) > maxCreateAuthorityNameLength {
		return NewAppError(ErrorKindValidation, "invalid_name", "name must be 1..255 characters")
	}
	return nil
}

// AuthoritySetIssuanceStateCommand is the JSON decode target for the OpenAPI
// IssuanceState schema.
type AuthoritySetIssuanceStateCommand struct {
	AuthorityID domain.AuthorityID `json:"-"`
	State       string             `json:"state"`
}

// DomainState converts and validates the state field. The IssuanceState
// schema's own enum is enabled/stopped only -- inventory is a storage-side
// initial state a client can never request directly.
func (c AuthoritySetIssuanceStateCommand) DomainState() (domain.IssuanceState, error) {
	state := domain.IssuanceState(c.State)
	switch state {
	case domain.IssuanceStateEnabled, domain.IssuanceStateStopped:
		return state, nil
	default:
		return "", NewAppError(ErrorKindValidation, "invalid_state", "state must be enabled or stopped")
	}
}

func (c AuthoritySetIssuanceStateCommand) Validate() error {
	if _, err := domain.ParseAuthorityID(string(c.AuthorityID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_authority_id", "authority id must be a uuid")
	}
	if _, err := c.DomainState(); err != nil {
		return err
	}
	return nil
}

const maxJustificationLength = 4096

// AuthorityDestroyKeyCommand is the JSON decode target for the OpenAPI
// KeyDestruction schema.
type AuthorityDestroyKeyCommand struct {
	AuthorityID     domain.AuthorityID       `json:"-"`
	KeyGenerationID domain.CAKeyGenerationID `json:"key_generation_id"`
	Justification   string                   `json:"justification"`
}

func (c AuthorityDestroyKeyCommand) Validate() error {
	if _, err := domain.ParseAuthorityID(string(c.AuthorityID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_authority_id", "authority id must be a uuid")
	}
	if _, err := domain.ParseCAKeyGenerationID(string(c.KeyGenerationID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_key_generation_id", "key_generation_id must be a uuid")
	}
	if len(c.Justification) > maxJustificationLength {
		return NewAppError(ErrorKindValidation, "invalid_justification", "justification must be at most 4096 characters")
	}
	return nil
}

// AuthorityArchiveCommand carries only the path target: the OpenAPI archive
// request bodies are empty, but Archive still acts on one authority, so it
// cannot reuse the fieldless EmptyCommand.
type AuthorityArchiveCommand struct {
	AuthorityID domain.AuthorityID `json:"-"`
}

func (c AuthorityArchiveCommand) Validate() error {
	if _, err := domain.ParseAuthorityID(string(c.AuthorityID)); err != nil {
		return NewAppError(ErrorKindValidation, "invalid_authority_id", "authority id must be a uuid")
	}
	return nil
}
