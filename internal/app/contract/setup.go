package contract

import (
	"fmt"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// SetupStage mirrors the OpenAPI Setup.setup_stage enum. It has no domain
// package home because installation progress is an app-layer concept, not a
// PKI or identity value type.
type SetupStage string

const (
	SetupStageAccountRequired SetupStage = "account_required"
	SetupStagePKIRequired     SetupStage = "pki_required"
	SetupStageComplete        SetupStage = "complete"
)

func (s SetupStage) Validate() error {
	switch s {
	case SetupStageAccountRequired, SetupStagePKIRequired, SetupStageComplete:
		return nil
	default:
		return fmt.Errorf("%w: unsupported setup stage %q", domain.ErrInvalidValue, string(s))
	}
}

// SetupView is the OpenAPI Setup data object.
type SetupView struct {
	SetupStage     SetupStage
	BootstrapHTTPS bool
}

// AccountView is the OpenAPI Account data object.
type AccountView struct {
	ID            domain.AccountID
	LoginName     string
	State         domain.AccountState
	IsGlobalAdmin bool
	Version       domain.Version
}

const (
	loginNameMinLength = 3
	loginNameMaxLength = 64
)

// SetupCreateAdminCommand is the JSON decode target for the OpenAPI
// Credentials schema, used once while installation has no admin yet. The
// caller is anonymous at this point (backend-implementation.md §3: "최초
// 생성은 익명"), so there is no path/target id to reject.
type SetupCreateAdminCommand struct {
	LoginName string `json:"login_name"`
	// Password is a secret.Input, never a plain string, per doc rule 5. The
	// command owns it; the caller Closes it after the service returns.
	Password *secret.Input `json:"-"`
}

func isLoginNameChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '.' || c == '_' || c == '-':
		return true
	default:
		return false
	}
}

// Validate enforces the Credentials schema's login_name pattern
// (^[A-Za-z0-9._-]{3,64}$) and password length (12..128), matching the
// OpenAPI required set exactly.
func (c SetupCreateAdminCommand) Validate() error {
	if len(c.LoginName) < loginNameMinLength || len(c.LoginName) > loginNameMaxLength {
		return NewAppError(ErrorKindValidation, "invalid_login_name", "login_name must be 3..64 characters")
	}
	for i := 0; i < len(c.LoginName); i++ {
		if !isLoginNameChar(c.LoginName[i]) {
			return NewAppError(ErrorKindValidation, "invalid_login_name", "login_name must match [A-Za-z0-9._-]")
		}
	}
	if c.Password == nil {
		return NewAppError(ErrorKindValidation, "invalid_password", "password is required")
	}
	if n := c.Password.Len(); n < 12 || n > 128 {
		return NewAppError(ErrorKindValidation, "invalid_password", "password must be 12..128 characters")
	}
	return nil
}

// SetupCompleteCommand carries no client fields: completing setup only
// requires the Settings version in MutationMeta.ExpectedVersion
// (backend-implementation.md §3: "Complete는 Settings version 필수"). It is
// its own named type, not the shared EmptyCommand, so a future field cannot
// be added to one setup method and silently apply to every other empty
// command in the codebase.
type SetupCompleteCommand struct{}

func (SetupCompleteCommand) Validate() error { return nil }
