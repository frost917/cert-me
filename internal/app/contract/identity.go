package contract

import (
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

const (
	tokenMinLength = 32
	tokenMaxLength = 256
)

// LoginView is the OpenAPI Login data object. CSRFToken is a secret.Input
// even though the schema does not mark it writeOnly: it is a bearer-style
// value that must reach the client exactly once through a dedicated
// Use-callback response writer, never through a general json.Marshal of the
// surrounding result (backend-implementation.md §6: "Login/CSRF/DownloadLink/
// ResetLink처럼 원문을 반드시 전달하는 결과는 해당 필드만 secret.Input으로 보유").
type LoginView struct {
	Account           AccountView
	IdleExpiresAt     domain.Instant
	AbsoluteExpiresAt domain.Instant
	CSRFToken         *secret.Input
}

// SessionView is the OpenAPI Session data object, returned by Authenticate
// alongside the Principal the session was validated into.
type SessionView struct {
	Account           AccountView
	IdleExpiresAt     domain.Instant
	AbsoluteExpiresAt domain.Instant
}

// CSRFView is the OpenAPI CSRF data object.
type CSRFView struct {
	CSRFToken *secret.Input
}

// ResetLinkView is the internal-only result of BeginReset
// (backend-implementation.md §3: "ResetLink는 URL(secret.Input), ExpiresAt,
// TokenID, AccountID이고... 새 공개 HTTP API를 만들지 않는다"). It never
// crosses the public HTTP surface; local CLI renders it.
type ResetLinkView struct {
	URL       *secret.Input
	ExpiresAt domain.Instant
	TokenID   domain.ResetTokenID
	AccountID domain.AccountID
}

// AuthenticateResult pairs the validated session view with the Principal
// minted from it, matching the table's "Authenticate(sessionToken) →
// Principal/Session".
type AuthenticateResult struct {
	Principal Principal
	Session   SessionView
}

// LogoutResult is empty: the table lists Logout's result as "없음". A named
// type still satisfies the method-signature convention in §3 rather than
// dropping the return value.
type LogoutResult struct{}

// IdentityLoginCommand is the JSON decode target for the OpenAPI Credentials
// schema on the pre-auth login path (backend-implementation.md §3: "Login...
// 세션 인증 대신 pre-auth 검증 경로").
type IdentityLoginCommand struct {
	LoginName string `json:"login_name"`
	// Password is never a plain string, per doc rule 5.
	Password *secret.Input `json:"-"`
}

// Validate mirrors the Credentials schema's required fields and length
// limits, identical to SetupCreateAdminCommand's shape but kept as its own
// type per the naming convention (one command type per service method).
func (c IdentityLoginCommand) Validate() error {
	if len(c.LoginName) < loginNameMinLength || len(c.LoginName) > loginNameMaxLength {
		return NewAppError(ErrorKindValidation, "invalid_login_name", "login_name must be 3..64 characters").WithField("login_name", c.LoginName)
	}
	for i := 0; i < len(c.LoginName); i++ {
		if !isLoginNameChar(c.LoginName[i]) {
			return NewAppError(ErrorKindValidation, "invalid_login_name", "login_name must match [A-Za-z0-9._-]").WithField("login_name", c.LoginName)
		}
	}
	if c.Password == nil {
		return NewAppError(ErrorKindValidation, "invalid_password", "password is required")
	}
	// Character count, not byte count: see secretCharacterLen's doc comment
	// in setup.go (F3 -- OpenAPI minLength/maxLength counts characters).
	n, err := secretCharacterLen(c.Password)
	if err != nil {
		return WrapAppError(ErrorKindValidation, "invalid_password", "password could not be read", err)
	}
	if n < passwordMinLength || n > passwordMaxLength {
		return NewAppError(ErrorKindValidation, "invalid_password", "password must be 12..128 characters")
	}
	return nil
}

// IdentityLogoutCommand carries no client fields; the session to end is
// resolved by the adapter from the authenticated Principal, not from a body.
type IdentityLogoutCommand struct{}

func (IdentityLogoutCommand) Validate() error { return nil }

// IdentityAuthenticateCommand carries the raw session cookie value. It is
// never JSON: the adapter reads the cookie and hands it in as a secret so a
// bearer-shaped token is never accidentally logged with the request body.
type IdentityAuthenticateCommand struct {
	SessionToken *secret.Input `json:"-"`
}

// Validate applies the same bearer-token length bounds used elsewhere
// (tokens are 32..256 characters, matching CSRF/PasswordReset in the OpenAPI
// document) so an obviously malformed cookie is rejected before a lookup.
func (c IdentityAuthenticateCommand) Validate() error {
	if c.SessionToken == nil {
		return NewAppError(ErrorKindAuth, "session_token_required", "a session token is required")
	}
	// SessionToken is a bearer cookie value, not a JSON string property on
	// any OpenAPI schema (it never crosses the wire as a body field), so its
	// length bound is intentionally left as a byte count rather than
	// switched to secretCharacterLen along with the three JSON-schema
	// secrets F3 covers.
	if n := c.SessionToken.Len(); n < tokenMinLength || n > tokenMaxLength {
		return NewAppError(ErrorKindAuth, "invalid_session_token", "session token has an invalid length")
	}
	return nil
}

// IdentityBeginResetCommand is local-only (backend-implementation.md §3:
// "BeginReset은 local 전용"). AccountID is filled by the local CLI adapter
// from its own argument, never JSON, so it is tagged json:"-" like every
// other server-filled target id.
type IdentityBeginResetCommand struct {
	AccountID domain.AccountID `json:"-"`
}

// Validate re-parses the id so a caller cannot hand in an unvalidated string
// even from a trusted local path.
func (c IdentityBeginResetCommand) Validate() error {
	if _, err := domain.ParseAccountID(string(c.AccountID)); err != nil {
		return WrapAppError(ErrorKindValidation, "invalid_account_id", "account_id must be a uuid", err)
	}
	return nil
}

// IdentityCompleteResetCommand is the JSON decode target for the OpenAPI
// PasswordReset schema. Both fields are writeOnly secrets in the schema, so
// neither ever has a JSON tag; the adapter reads the raw body once to build
// each secret.Input and hands the command in already populated, per doc rule
// 5 ("Secrets... json:"-". Never a plain string").
type IdentityCompleteResetCommand struct {
	ResetToken  *secret.Input `json:"-"`
	NewPassword *secret.Input `json:"-"`
}

// Validate applies the PasswordReset schema's length bounds: reset_token
// 32..256, new_password 12..128.
func (c IdentityCompleteResetCommand) Validate() error {
	if c.ResetToken == nil {
		return NewAppError(ErrorKindValidation, "reset_token_required", "reset_token is required")
	}
	// reset_token is a PasswordReset schema string property, so its
	// minLength/maxLength counts characters too (F3).
	tokenLen, err := secretCharacterLen(c.ResetToken)
	if err != nil {
		return WrapAppError(ErrorKindValidation, "invalid_reset_token", "reset_token could not be read", err)
	}
	if tokenLen < tokenMinLength || tokenLen > tokenMaxLength {
		return NewAppError(ErrorKindValidation, "invalid_reset_token", "reset_token has an invalid length")
	}
	if c.NewPassword == nil {
		return NewAppError(ErrorKindValidation, "new_password_required", "new_password is required")
	}
	passwordLen, err := secretCharacterLen(c.NewPassword)
	if err != nil {
		return WrapAppError(ErrorKindValidation, "invalid_new_password", "new_password could not be read", err)
	}
	if passwordLen < passwordMinLength || passwordLen > passwordMaxLength {
		return NewAppError(ErrorKindValidation, "invalid_new_password", "new_password must be 12..128 characters")
	}
	return nil
}

// CompleteResetResult is empty: the table lists CompleteReset's result as
// "없음".
type CompleteResetResult struct{}

// IdentityIssueCSRFCommand carries no client fields.
type IdentityIssueCSRFCommand struct{}

func (IdentityIssueCSRFCommand) Validate() error { return nil }
