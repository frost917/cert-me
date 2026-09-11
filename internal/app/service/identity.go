// identity.go implements IdentityService (docs/backend-implementation.md §3
// "IdentityService | Login: Credentials → Login; Logout: Empty → 없음;
// Authenticate(sessionToken) → Principal/Session; BeginReset(accountID) →
// ResetLink; CompleteReset: PasswordReset → 없음; IssueCSRF → CSRF |
// BeginReset은 local 전용. Login/CompleteReset은 세션 인증 대신 pre-auth
// 검증 경로").
//
// Login and CompleteReset are the two pre-auth flows: preauth.go's
// requirePreAuthAdmission/recordPreAuthFailure/lockAccountByLoginName carry
// the throttle and the "no stale clock" rule, and this file only calls into
// them (docs/backend-implementation.md §8's "로그인"/"재설정 완료" rows fix
// the rest of each commit's boundary). Logout and Authenticate instead go
// through auth.go's requireCurrentAuth/SessionIdleTimeout, the same as every
// other admin-mutating service.
package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// IdentityDeps is IdentityService's dependency set (docs/backend-
// implementation.md §5 "Setup/Identity | PasswordHasher, TokenCodec").
// Unlike SetupDeps, both are actually used here: PasswordHasher verifies
// Login/CompleteReset credentials, TokenCodec mints session/CSRF/reset-link
// bearer tokens.
type IdentityDeps struct {
	CommonDeps
	PasswordHasher port.PasswordHasher
	TokenCodec     port.TokenCodec
}

// Validate reports the first missing dependency, common or Identity-specific.
func (d IdentityDeps) Validate() error {
	if err := d.CommonDeps.Validate(); err != nil {
		return err
	}
	return firstMissing(
		required{"PasswordHasher", d.PasswordHasher == nil},
		required{"TokenCodec", d.TokenCodec == nil},
	)
}

// IdentityService implements the session/credential methods.
type IdentityService struct {
	deps IdentityDeps
}

// NewIdentityService constructs the service, failing fast on a missing
// dependency rather than at the first request.
func NewIdentityService(deps IdentityDeps) (*IdentityService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &IdentityService{deps: deps}, nil
}

// toAccountView projects a domain.Account into the OpenAPI Account shape.
// LoginName is the normalized (lowercased) form: domain.Account carries no
// separate display-case field even though data-model.md's accounts row
// lists both login_name and normalized_login_name columns -- see the
// report, this is a B01 domain gap outside this developer's assigned files.
func toAccountView(account domain.Account) contract.AccountView {
	return contract.AccountView{
		ID:            account.ID(),
		LoginName:     account.NormalizedLoginName(),
		State:         account.State(),
		IsGlobalAdmin: account.IsGlobalAdmin(),
		Version:       account.Version(),
	}
}

// appendAccountAudit records one account/session/setup-level audit event.
// Unlike issuance/distribution's PKI events, these are never CA-scoped:
// there is no authority relation to build a scope from, so scopes is always
// nil. §14.6's "빈 scope로 저장하지 않는다" rule is about a PKI event whose
// scope was dropped by mistake; it does not apply to an event that is
// simply not about any CA in the first place.
func appendAccountAudit(ctx context.Context, tx port.TxStores, ids port.IDGenerator, now domain.Instant, meta contract.RequestMeta, actorKind contract.AuditActorKind, actorID, action, targetType, targetID string) error {
	event := port.AuditEvent{
		ID:         ids.NewUUID(),
		OccurredAt: now,
		ActorKind:  actorKind,
		ActorID:    actorID,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		ClientIP:   clientIP(meta),
		Result:     contract.AuditResultSuccess,
		Details:    contract.AuditDetails{SchemaVersion: 1},
	}
	if err := tx.Audit().Append(ctx, event, nil); err != nil {
		return storeError(err, "identity_audit_failed", "could not record the audit event")
	}
	return nil
}

// invalidCredentialsError is Login's single rejection spelling, deliberately
// identical whether the login name is unknown, the password is wrong, or
// the account changed underneath the request -- a client must not be able
// to distinguish "no such account" from "wrong password" from the response.
func invalidCredentialsError() error {
	return contract.NewAppError(contract.ErrorKindAuth, "invalid_credentials", "login name or password is incorrect")
}

// dummyPasswordHash is what Login verifies an unknown login name against,
// so PasswordHasher.Verify runs the same profile at the same cost whether
// or not the name resolves to a real account (docs/architecture.md "없는
// 계정은 같은 프로필의 dummy hash 비교를 사용하되 같은 실행 예산을
// 적용한다"). It is not derived from any real credential and nothing will
// ever match it.
var dummyPasswordHash = mustDummyPasswordHash()

func mustDummyPasswordHash() domain.PasswordHash {
	h, err := domain.NewPasswordHash("$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		// Unreachable: the literal above is a non-empty string.
		panic(err)
	}
	return h
}

// loginAttemptFacts is what Login's outside-the-transaction preparation
// resolves against an unlocked read: the hash to verify against (real or
// dummy) plus enough of the account row (id, version) for the commit to
// detect whether it moved before trusting the verify result.
type loginAttemptFacts struct {
	found           bool
	accountID       domain.AccountID
	preparedVersion domain.Version
	hashToVerify    domain.PasswordHash
}

// resolveLoginAttempt is Login's unlocked preparation read.
func (s *IdentityService) resolveLoginAttempt(ctx context.Context, normalized string) (loginAttemptFacts, error) {
	var facts loginAttemptFacts
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		account, err := tx.Accounts().FindAccountByLoginName(ctx, normalized)
		switch {
		case errors.Is(err, port.ErrNotFound):
			facts = loginAttemptFacts{found: false, hashToVerify: dummyPasswordHash}
			return nil
		case err != nil:
			return storeError(err, "identity_login_account_lookup_failed", "could not look up the account")
		}
		facts = loginAttemptFacts{
			found:           true,
			accountID:       account.ID(),
			preparedVersion: account.Version(),
			hashToVerify:    account.PasswordHash(),
		}
		return nil
	})
	return facts, err
}

// Login authenticates a login_name/password pair and starts a new session
// (docs/backend-implementation.md §8 "로그인" row). Credential verification
// happens OUTSIDE the transaction against a snapshot read; the commit
// re-locks the account and re-checks that nothing moved since -- U02's
// scenario, a reset committing in between, is caught by the version
// comparison and by Account.CanLogin() below, not by re-verifying the
// password a second time.
func (s *IdentityService) Login(ctx context.Context, meta contract.MutationMeta, cmd contract.IdentityLoginCommand) (contract.LoginView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.LoginView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.LoginView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	normalized := domain.NormalizeLoginName(cmd.LoginName)
	subjects := loginSubjects(normalized, meta.RequestMeta)

	// §6/architecture.md: admission is checked BEFORE the KDF verify below,
	// and a rejection here is never counted as a failed attempt.
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		return requirePreAuthAdmission(ctx, tx, subjects, s.deps.Clock)
	}); err != nil {
		return contract.LoginView{}, err
	}

	facts, err := s.resolveLoginAttempt(ctx, normalized)
	if err != nil {
		return contract.LoginView{}, err
	}
	// §8: the password comparison happens OUTSIDE the transaction, against
	// whichever hash resolveLoginAttempt found -- real or dummy, same cost.
	verified, err := s.deps.PasswordHasher.Verify(ctx, cmd.Password, facts.hashToVerify)
	if err != nil {
		return contract.LoginView{}, storeError(err, "identity_password_verify_failed", "could not verify the password")
	}

	// The session token is minted here, outside the transaction (§8: "새
	// 세션 난수 준비"), only when the outside check already looks like a
	// success -- an attempt that is already known to fail never needs one.
	// It may still go unused if the commit's re-check rejects it (U02); the
	// deferred Close is the safety net for that path, mirroring
	// distribution.go's `defer prep.bundle.Close()` idiom.
	var (
		rawSession  *secret.Input
		sessionHash domain.TokenHash
	)
	if facts.found && verified {
		rawSession, sessionHash, err = s.deps.TokenCodec.NewToken(ctx)
		if err != nil {
			return contract.LoginView{}, storeError(err, "identity_session_token_failed", "could not mint a session token")
		}
	}
	defer rawSession.Close()

	// rejected carries a rejection that must still commit a side effect
	// (the failure counter): §4 requires the callback below to return nil
	// in that case, so the counter's write is not rolled back along with
	// the rejection itself, and return this local variable only after
	// Write has actually committed it.
	var rejected error
	var result contract.LoginView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		// Authoritative re-check: a concurrent request may have pushed this
		// subject over the threshold since the read-only probe above. This
		// rejection needs nothing to survive rollback (no attempt was
		// recorded), so it returns directly.
		if err := requirePreAuthAdmission(ctx, tx, subjects, s.deps.Clock); err != nil {
			return err
		}

		account, now, ok, err := lockAccountByLoginName(ctx, tx, normalized, s.deps.Clock)
		if err != nil {
			return err
		}
		// §8 "계정/자격 증명 version 재확인": if the account did not exist,
		// resolves to a different row than prep saw, or moved to a new
		// version since prep read it, the outside verify result cannot be
		// trusted -- reject rather than act on stale material. A BeginReset
		// committing between prep and here (U02) always bumps the account's
		// version, so it is caught here regardless of what CanLogin would
		// separately say.
		if !ok || account.ID() != facts.accountID || account.Version() != facts.preparedVersion || !verified {
			if err := recordPreAuthFailure(ctx, tx, subjects, s.deps.Clock); err != nil {
				return err
			}
			rejected = invalidCredentialsError()
			return nil
		}
		if err := account.CanLogin(); err != nil {
			// A state rejection (reset_pending/disabled) is not a guessed
			// password, so it is not counted against the throttle.
			return contract.FromDomainError(err)
		}

		sessionID, err := domain.ParseSessionID(s.deps.IDs.NewUUID())
		if err != nil {
			return contract.FromDomainError(err)
		}
		policy := domain.DefaultSessionPolicy()
		session, err := domain.NewSessionState(domain.SessionStateFacts{
			ID:                sessionID,
			AccountID:         account.ID(),
			TokenHash:         sessionHash,
			AuthEpoch:         account.AuthEpoch(),
			LastSeenAt:        now,
			AbsoluteExpiresAt: policy.AbsoluteExpiresAt(now),
		})
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Accounts().InsertSession(ctx, session); err != nil {
			return storeError(err, "identity_session_store_failed", "could not store the new session")
		}

		if err := appendAccountAudit(ctx, tx, s.deps.IDs, now, meta.RequestMeta,
			contract.AuditActorAccount, string(account.ID()), "identity.login", "account", string(account.ID())); err != nil {
			return err
		}

		// CSRF is minted last, once nothing else in this commit can still
		// fail: contract.LoginView has no field to persist its hash against
		// (no domain.SessionState field, no port method for one -- see the
		// report), so it can only ever be minted and handed back, never
		// verified server-side later. Minting it last means a failure
		// anywhere above never leaves an unused CSRF secret to clean up.
		csrfRaw, _, err := s.deps.TokenCodec.NewToken(ctx)
		if err != nil {
			return storeError(err, "identity_csrf_token_failed", "could not mint a csrf token")
		}

		result = contract.LoginView{
			Account:           toAccountView(account),
			IdleExpiresAt:     now.Add(policy.IdleTimeout()),
			AbsoluteExpiresAt: session.AbsoluteExpiresAt(),
			CSRFToken:         csrfRaw,
		}
		return nil
	})
	if err != nil {
		return contract.LoginView{}, err
	}
	if rejected != nil {
		return contract.LoginView{}, rejected
	}
	return result, nil
}

// Logout ends the caller's own session (docs/backend-implementation.md §3
// "Logout: Empty → 없음"). It requires a live admin session
// (api/openapi.json "/api/v1/auth/logout" post uses the default
// SessionCookie security).
func (s *IdentityService) Logout(ctx context.Context, meta contract.MutationMeta, cmd contract.IdentityLogoutCommand) (contract.LogoutResult, error) {
	if err := cmd.Validate(); err != nil {
		return contract.LogoutResult{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.LogoutResult{}, contract.NewAppError(contract.ErrorKindForbidden, "identity_logout_requires_admin",
			"logging out requires an administrator session")
	}
	if err := ctx.Err(); err != nil {
		return contract.LogoutResult{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionIdentityLogout, port.NewAuthorizationScope()); err != nil {
			return err
		}
		if err := tx.Accounts().DeleteSession(ctx, meta.Principal.SessionID()); err != nil {
			return storeError(err, "identity_logout_session_delete_failed", "could not end the session")
		}
		return appendAccountAudit(ctx, tx, s.deps.IDs, s.deps.Clock.Now(), meta.RequestMeta,
			contract.AuditActorAccount, string(meta.Principal.AccountID()), "identity.logout", "account", string(meta.Principal.AccountID()))
	})
	if err != nil {
		return contract.LogoutResult{}, err
	}
	return contract.LogoutResult{}, nil
}

// Authenticate validates a raw session cookie and mints the Principal every
// other service call is authorized under (docs/backend-implementation.md §3
// "Authenticate(sessionToken) → Principal/Session"). Unlike Login/
// CompleteReset it is not a pre-auth flow with a throttle: a session token
// is an unguessable 32-byte bearer value, not a low-entropy credential a
// human chose, so it is not in preauth.go's fixed subject set (see the
// report). It performs a real Write because a successful validation also
// extends the session's idle window (AccountRepository.SaveSession's own
// doc comment: "the idle-expiry refresh SessionState.Touch produces on
// each authenticated request").
func (s *IdentityService) Authenticate(ctx context.Context, meta contract.RequestMeta, cmd contract.IdentityAuthenticateCommand) (contract.AuthenticateResult, error) {
	if err := cmd.Validate(); err != nil {
		return contract.AuthenticateResult{}, err
	}

	var result contract.AuthenticateResult
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		hash, err := s.deps.TokenCodec.Hash(ctx, cmd.SessionToken)
		if err != nil {
			return storeError(err, "identity_session_token_hash_failed", "could not hash the session token")
		}
		found, err := tx.Accounts().FindSessionByHash(ctx, hash)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindAuth, "session_not_found", "this session no longer exists")
			}
			return storeError(err, "identity_session_lookup_failed", "could not look up the session")
		}
		// Locks the row for the authoritative re-check, mirroring
		// AccountRepository.GetSessionForUpdate's own doc comment on this
		// two-step unlocked-then-locked shape.
		locked, err := tx.Accounts().GetSessionForUpdate(ctx, found.ID())
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindAuth, "session_not_found", "this session no longer exists")
			}
			return storeError(err, "identity_session_lookup_failed", "could not look up the session")
		}
		account, err := tx.Accounts().GetAccountForUpdate(ctx, locked.AccountID())
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindAuth, "account_not_found",
					"the account this session belongs to no longer exists")
			}
			return storeError(err, "identity_account_read_failed", "could not read the account")
		}
		// The clock is read only now, with both rows locked -- the same
		// rule requireCurrentAuth (auth.go) and lockAccountByLoginName
		// (preauth.go) already follow.
		now := s.deps.Clock.Now()
		if err := locked.ValidateAt(now, SessionIdleTimeout, domain.SessionAccountFacts{
			AccountID: account.ID(),
			State:     account.State(),
			AuthEpoch: account.AuthEpoch(),
		}); err != nil {
			return authError(err)
		}

		touched := locked.Touch(now)
		if err := tx.Accounts().SaveSession(ctx, touched); err != nil {
			return storeError(err, "identity_session_touch_failed", "could not extend the session")
		}

		principal, err := contract.NewAdminPrincipal(contract.AdminPrincipalFacts{
			AccountID: account.ID(),
			SessionID: touched.ID(),
			AuthEpoch: account.AuthEpoch(),
		})
		if err != nil {
			return contract.FromDomainError(err)
		}
		policy := domain.DefaultSessionPolicy()
		result = contract.AuthenticateResult{
			Principal: principal,
			Session: contract.SessionView{
				Account:           toAccountView(account),
				IdleExpiresAt:     now.Add(policy.IdleTimeout()),
				AbsoluteExpiresAt: touched.AbsoluteExpiresAt(),
			},
		}
		return nil
	})
	if err != nil {
		return contract.AuthenticateResult{}, err
	}
	return result, nil
}

// resetLinkPath is the public reset page route api/openapi.json declares
// ("/reset-password/{token}"), never prefixed with /api/v1.
const resetLinkPath = "/reset-password/"

// buildResetLinkURL concatenates the validated service URL with the fixed
// public page path and the raw token, entirely inside raw's Use callback so
// the token's plaintext bytes are read but never retained past the copy
// (internal/secret's non-retention contract). service_url is used exactly
// as Settings stores it (architecture.md: "요청 Host 헤더로 복구·다운로드
// 링크를 구성하지 않는다"), not the request's own Host header.
func buildResetLinkURL(serviceURL string, raw *secret.Input) (*secret.Input, error) {
	base := serviceURL
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	if base == "" {
		return nil, contract.NewAppError(contract.ErrorKindConflict, "identity_reset_link_service_url_not_configured",
			"service settings must be configured before a reset link can be built")
	}
	var built *secret.Input
	err := raw.Use(func(b []byte) error {
		combined := make([]byte, 0, len(base)+len(resetLinkPath)+len(b))
		combined = append(combined, base...)
		combined = append(combined, resetLinkPath...)
		combined = append(combined, b...)
		built = secret.New(combined)
		return nil
	})
	if err != nil {
		return nil, storeError(err, "identity_reset_token_read_failed", "could not read the freshly minted reset token")
	}
	return built, nil
}

// BeginReset issues a fresh one-time password-reset link for accountID
// (docs/backend-implementation.md §3 "BeginReset은 local 전용";
// docs/architecture.md's CLI-driven reset flow). Its caller is an internal
// principal minted by the local adapter specifically for this operation --
// never an admin session -- so it is checked directly against
// Principal.Can, not through the generic Authorizer: there is no CA scope
// here for AuthorizationScope to carry, and port's
// actionInternalOperations table (services.go) pairs only
// ActionTLSBootstrap/ActionTLSReconcile to their InternalOperations, not
// ActionIdentityBeginReset to InternalOperationResetBegin, even though the
// latter constant exists in contract/meta.go. That gap is outside this
// developer's assigned files (port/services.go); see the report.
func (s *IdentityService) BeginReset(ctx context.Context, meta contract.MutationMeta, cmd contract.IdentityBeginResetCommand) (contract.ResetLinkView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.ResetLinkView{}, err
	}
	if !meta.Principal.IsInternal() || !meta.Principal.Can(contract.InternalOperationResetBegin) {
		return contract.ResetLinkView{}, contract.NewAppError(contract.ErrorKindForbidden, "identity_begin_reset_requires_internal_operation",
			"beginning a password reset requires the local reset_begin operation")
	}
	if err := ctx.Err(); err != nil {
		return contract.ResetLinkView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	rawToken, tokenHash, err := s.deps.TokenCodec.NewToken(ctx)
	if err != nil {
		return contract.ResetLinkView{}, storeError(err, "identity_reset_token_mint_failed", "could not mint a reset token")
	}
	// Unconditional safety net, mirroring distribution.go's
	// `defer prep.bundle.Close()`: Close is idempotent, and every path below
	// either consumes raw into the returned URL or returns before that.
	defer rawToken.Close()

	var (
		url     *secret.Input
		keepURL bool
	)
	defer func() {
		if !keepURL {
			url.Close()
		}
	}()

	var result contract.ResetLinkView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		settings, err := tx.Installation().GetSettings(ctx)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindConflict, "identity_reset_link_service_url_not_configured",
				"service settings must be configured before a reset link can be built")
		} else if err != nil {
			return storeError(err, "identity_reset_settings_read_failed", "could not read the service settings")
		}
		snap, err := DecodeSettingsV1(settings)
		if err != nil {
			return err
		}

		account, err := tx.Accounts().GetAccountForUpdate(ctx, cmd.AccountID)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "identity_reset_account_not_found", "account does not exist").
					WithField("account_id", string(cmd.AccountID))
			}
			return storeError(err, "identity_reset_account_read_failed", "could not read the account")
		}
		originalVersion := account.Version()

		outcome, err := account.BeginReset()
		if err != nil {
			return contract.FromDomainError(err)
		}
		now := s.deps.Clock.Now()

		if err := tx.Accounts().SaveAccount(ctx, outcome.Account, originalVersion); err != nil {
			return storeError(err, "identity_reset_account_save_failed", "could not update the account")
		}
		if outcome.SessionsInvalidated {
			if err := tx.Accounts().DeleteAllSessions(ctx, account.ID()); err != nil {
				return storeError(err, "identity_reset_sessions_invalidate_failed", "could not invalidate existing sessions")
			}
		}
		// architecture.md "재발급 시... 기존 미사용 재설정 링크를 모두
		// 무효화": any earlier outstanding token for this account is
		// superseded, whether this is the first BeginReset or a reissue.
		if err := tx.Accounts().InvalidateResetTokens(ctx, account.ID(), now); err != nil {
			return storeError(err, "identity_reset_tokens_invalidate_failed", "could not invalidate outstanding reset links")
		}

		resetTokenID, err := domain.ParseResetTokenID(s.deps.IDs.NewUUID())
		if err != nil {
			return contract.FromDomainError(err)
		}
		// The token is issued under the account's NEW epoch (post-
		// BeginReset): CanConsume checks the token's epoch against the
		// account's current one at consumption time, and the account's own
		// epoch has already moved past whatever it was before this call.
		token, err := domain.IssueAdminResetToken(resetTokenID, account.ID(), tokenHash, outcome.Account.AuthEpoch(), now, domain.DefaultResetPolicy())
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Accounts().InsertResetToken(ctx, token); err != nil {
			return storeError(err, "identity_reset_token_store_failed", "could not store the reset token")
		}

		builtURL, err := buildResetLinkURL(snap.ServiceURL, rawToken)
		if err != nil {
			return err
		}
		url = builtURL

		if err := appendAccountAudit(ctx, tx, s.deps.IDs, now, meta.RequestMeta,
			contract.AuditActorCLI, "", "identity.begin_reset", "account", string(account.ID())); err != nil {
			return err
		}

		result = contract.ResetLinkView{URL: url, ExpiresAt: token.ExpiresAt(), TokenID: resetTokenID, AccountID: account.ID()}
		return nil
	})
	if err != nil {
		return contract.ResetLinkView{}, err
	}
	keepURL = true
	return result, nil
}

// resetIPOnlySubject is the throttle subject set used when a presented
// reset token does not resolve to any account at all: resetSubjects
// (preauth.go) needs a real domain.AccountID to build its account-scoped
// half, which does not exist for a token nobody ever issued, so only the
// IP-scoped half applies. Built with the same rateLimitKindResetIP kind
// preauth.go's own resetSubjects uses, so both paths land in the same
// bucket for a given client.
func resetIPOnlySubject(meta contract.RequestMeta) []preAuthSubject {
	return []preAuthSubject{
		{Kind: rateLimitKindResetIP, Hash: domain.NewFingerprint([]byte(clientIP(meta)))},
	}
}

// resolveResetSubjects is CompleteReset's unlocked preparation read: it
// hashes nothing expensive, only resolving which throttle subjects this
// attempt counts against and whether a real account was found at all
// (which gates whether the new password is worth hashing).
func (s *IdentityService) resolveResetSubjects(ctx context.Context, tokenHash domain.TokenHash, meta contract.RequestMeta) ([]preAuthSubject, bool, error) {
	var (
		subjects []preAuthSubject
		known    bool
	)
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		tokenRow, err := tx.Accounts().GetResetToken(ctx, tokenHash)
		switch {
		case errors.Is(err, port.ErrNotFound):
			subjects = resetIPOnlySubject(meta)
			return nil
		case err != nil:
			return storeError(err, "identity_reset_token_lookup_failed", "could not look up the reset token")
		}
		subjects = resetSubjects(tokenRow.AccountID(), meta)
		known = true
		return nil
	})
	return subjects, known, err
}

// authErrorFromPolicy remaps a domain.PolicyError into an auth-kind
// AppError, the reset-token counterpart of auth.go's authError: a consumed,
// invalidated, expired or mismatched token is a rejected credential (401),
// not a validation or conflict response.
func authErrorFromPolicy(err error) error {
	var policy *domain.PolicyError
	if errors.As(err, &policy) {
		return contract.WrapAppError(contract.ErrorKindAuth, policy.Code, policy.Detail, err)
	}
	return contract.WrapAppError(contract.ErrorKindAuth, "reset_rejected", "this reset request could not be completed", err)
}

// rejectReset records the failed-attempt counter and stores the generic
// "no such token" rejection into *rejected, used when GetResetToken itself
// finds nothing. Per §4, a rejection that must still commit a side effect
// (the failure counter) cannot be returned as the Write callback's own
// error -- that would roll the counter back along with it -- so this
// returns nil (letting the commit proceed) and hands the rejection back
// through the pointer instead; the caller returns *rejected only after
// Write has actually committed. It still returns a real error when
// recordPreAuthFailure itself fails to write, which correctly rolls back
// (nothing else in this commit has happened yet).
func rejectReset(ctx context.Context, tx port.TxStores, subjects []preAuthSubject, clock port.Clock, rejected *error) error {
	if err := recordPreAuthFailure(ctx, tx, subjects, clock); err != nil {
		return err
	}
	*rejected = contract.NewAppError(contract.ErrorKindAuth, "invalid_reset_token", "reset token is invalid or has expired")
	return nil
}

// rejectResetWithCause is rejectReset's counterpart for a token that WAS
// found but failed CanConsume/Consume (already consumed, invalidated,
// expired, or the account moved epoch/state since) -- the specific policy
// error is preserved via authErrorFromPolicy rather than collapsed to the
// generic message above. Same nil-return-plus-pointer shape as rejectReset.
func rejectResetWithCause(ctx context.Context, tx port.TxStores, subjects []preAuthSubject, clock port.Clock, cause error, rejected *error) error {
	if err := recordPreAuthFailure(ctx, tx, subjects, clock); err != nil {
		return err
	}
	*rejected = authErrorFromPolicy(cause)
	return nil
}

// CompleteReset consumes a one-time reset token and sets a new password
// (docs/backend-implementation.md §8 "재설정 완료" row). The new password
// is hashed OUTSIDE the transaction, but only once the token has resolved
// to a real account during preparation -- there is no point spending an
// Argon2id pass on a password nobody will ever store. The commit re-reads
// the token and account fresh and lets AdminResetToken.Consume decide:
// U03's "token consumed exactly once" falls directly out of that re-read
// running inside the UnitOfWork's serialized Write, the same mechanism
// that gives U01 its single winner.
func (s *IdentityService) CompleteReset(ctx context.Context, meta contract.MutationMeta, cmd contract.IdentityCompleteResetCommand) (contract.CompleteResetResult, error) {
	if err := cmd.Validate(); err != nil {
		return contract.CompleteResetResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.CompleteResetResult{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	tokenHash, err := s.deps.TokenCodec.Hash(ctx, cmd.ResetToken)
	if err != nil {
		return contract.CompleteResetResult{}, storeError(err, "identity_reset_token_hash_failed", "could not hash the reset token")
	}

	subjects, accountKnown, err := s.resolveResetSubjects(ctx, tokenHash, meta.RequestMeta)
	if err != nil {
		return contract.CompleteResetResult{}, err
	}

	// architecture.md/§6: admission before any KDF work.
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		return requirePreAuthAdmission(ctx, tx, subjects, s.deps.Clock)
	}); err != nil {
		return contract.CompleteResetResult{}, err
	}

	var newHash domain.PasswordHash
	if accountKnown {
		newHash, err = s.deps.PasswordHasher.Hash(ctx, cmd.NewPassword)
		if err != nil {
			return contract.CompleteResetResult{}, storeError(err, "identity_new_password_hash_failed", "could not hash the new password")
		}
	}

	// rejected is the same local-variable pattern Login uses: a rejection
	// that must still commit the failure counter cannot be the callback's
	// own returned error (§4), so it is captured here and returned only
	// after Write has committed nil.
	var rejected error
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requirePreAuthAdmission(ctx, tx, subjects, s.deps.Clock); err != nil {
			return err
		}

		tokenRow, err := tx.Accounts().GetResetToken(ctx, tokenHash)
		if errors.Is(err, port.ErrNotFound) {
			return rejectReset(ctx, tx, subjects, s.deps.Clock, &rejected)
		} else if err != nil {
			return storeError(err, "identity_reset_token_read_failed", "could not read the reset token")
		}
		if !accountKnown {
			// Defensive: GetResetToken just found a row, so the unlocked
			// preparation read should have too. Reached only if the two
			// disagree, in which case the pre-computed newHash was never
			// produced and there is nothing safe to complete with.
			return rejectReset(ctx, tx, subjects, s.deps.Clock, &rejected)
		}

		account, err := tx.Accounts().GetAccountForUpdate(ctx, tokenRow.AccountID())
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return rejectReset(ctx, tx, subjects, s.deps.Clock, &rejected)
			}
			return storeError(err, "identity_reset_account_read_failed", "could not read the account")
		}
		originalVersion := account.Version()
		now := s.deps.Clock.Now()

		// Consume re-checks CanConsume itself (one-shot: already-consumed,
		// invalidated, expired, or account/epoch mismatch all fail here).
		// This is the exact re-check a second, racing CompleteReset call
		// against the same token fails at -- U03.
		consumedToken, err := tokenRow.Consume(now, domain.ResetTokenAccountFacts{
			AccountID: account.ID(), State: account.State(), AuthEpoch: account.AuthEpoch(),
		})
		if err != nil {
			return rejectResetWithCause(ctx, tx, subjects, s.deps.Clock, err, &rejected)
		}

		outcome, err := account.CompleteReset(newHash)
		if err != nil {
			return rejectResetWithCause(ctx, tx, subjects, s.deps.Clock, err, &rejected)
		}

		if err := tx.Accounts().SaveResetToken(ctx, consumedToken); err != nil {
			return storeError(err, "identity_reset_token_save_failed", "could not record the token consumption")
		}
		if err := tx.Accounts().SaveAccount(ctx, outcome.Account, originalVersion); err != nil {
			return storeError(err, "identity_reset_account_save_failed", "could not update the account")
		}
		if outcome.SessionsInvalidated {
			if err := tx.Accounts().DeleteAllSessions(ctx, account.ID()); err != nil {
				return storeError(err, "identity_reset_sessions_invalidate_failed", "could not invalidate existing sessions")
			}
		}
		if err := tx.Accounts().InvalidateResetTokens(ctx, account.ID(), now); err != nil {
			return storeError(err, "identity_reset_tokens_invalidate_failed", "could not invalidate outstanding reset links")
		}

		return appendAccountAudit(ctx, tx, s.deps.IDs, now, meta.RequestMeta,
			contract.AuditActorAccount, string(account.ID()), "identity.complete_reset", "account", string(account.ID()))
	})
	if err != nil {
		return contract.CompleteResetResult{}, err
	}
	if rejected != nil {
		return contract.CompleteResetResult{}, rejected
	}
	return contract.CompleteResetResult{}, nil
}

// IssueCSRF mints a fresh anti-CSRF bearer token (docs/backend-
// implementation.md §3 "IssueCSRF → CSRF"; api/openapi.json "/api/v1/auth/
// csrf" get: "security": [], "may use current session or pre-auth nonce
// cookie. Never grants setup authorization"). It performs no store write at
// all: there is nowhere to persist the token's hash for later verification
// -- domain.SessionState carries no CSRF field and no port method exists
// for one, the same gap noted on Login's CSRFToken field -- so this can
// only mint and hand back a value, exactly as far as the existing contract
// supports. See the report.
func (s *IdentityService) IssueCSRF(ctx context.Context, meta contract.RequestMeta, cmd contract.IdentityIssueCSRFCommand) (contract.CSRFView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.CSRFView{}, err
	}
	if meta.Principal.IsAdmin() {
		// A caller presenting an existing admin session still needs it to
		// be live; an anonymous caller (pre-auth nonce case) has nothing to
		// re-check here at all. There is no Write on either path, so this
		// probe is the final answer, not preparation for a later commit --
		// legitimate because, unlike every mutating method in this package,
		// issuing a CSRF token has no persisted effect for a second check
		// to guard.
		if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
			return requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock)
		}); err != nil {
			return contract.CSRFView{}, err
		}
	}
	raw, _, err := s.deps.TokenCodec.NewToken(ctx)
	if err != nil {
		return contract.CSRFView{}, storeError(err, "identity_csrf_token_failed", "could not mint a csrf token")
	}
	return contract.CSRFView{CSRFToken: raw}, nil
}
