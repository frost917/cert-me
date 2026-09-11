// setup.go implements SetupService (docs/backend-implementation.md §3
// "SetupService | Status: Empty → Setup; CreateAdmin: Credentials → Account;
// Complete: Empty → Setup | 최초 생성은 익명, Complete는 Settings version
// 필수. 설치 상태를 내부에서 확인").
//
// §8's "최초 관리자" row fixes the commit boundary CreateAdmin follows: the
// password policy check and hash happen OUTSIDE the transaction, and the
// single Write re-confirms the installation is still unset, creates the
// account, advances the setup stage and appends the audit event together.
// Because the singleton installation row is what the Write re-checks under
// lock, and porttest/every real UnitOfWork serializes Write callbacks, U01's
// "first admin creation race succeeds exactly once" falls out of that lock
// rather than needing a second, separate mechanism.
package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// SetupDeps is SetupService's dependency set. docs/backend-implementation.md
// §5 lists "Setup/Identity | PasswordHasher, TokenCodec" as one combined row,
// but §5 also says "서비스별로 필요한 것만 XDeps에 둔다": none of Status,
// CreateAdmin or Complete mint or verify a bearer token (CreateAdmin only
// hashes the new administrator's password; Complete only advances the
// installation stage under a session IdentityService already validated), so
// TokenCodec is not held here. This is a deliberate narrowing of the
// combined row, not an oversight -- see the report.
type SetupDeps struct {
	CommonDeps
	PasswordHasher port.PasswordHasher
}

// Validate reports the first missing dependency, common or Setup-specific.
func (d SetupDeps) Validate() error {
	if err := d.CommonDeps.Validate(); err != nil {
		return err
	}
	return firstMissing(required{"PasswordHasher", d.PasswordHasher == nil})
}

// SetupService implements the installation-progress methods.
type SetupService struct {
	deps SetupDeps
}

// NewSetupService constructs the service, failing fast on a missing
// dependency rather than at the first request.
func NewSetupService(deps SetupDeps) (*SetupService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &SetupService{deps: deps}, nil
}

// loadInstallation reads the singleton installation row and maps its
// absence to an explicit error. A real deployment's migration always seeds
// this fixed-PK=1 row before the app serves a single request
// (docs/data-model.md "installation" row), so ErrNotFound here means the
// deployment itself is not initialized -- it is not treated as "fresh
// install, default to account_required", which would silently paper over a
// genuine operational fault the same way an unresolved Settings row must
// not be defaulted (§14.8).
func loadInstallation(ctx context.Context, tx port.TxStores) (port.Installation, error) {
	inst, err := tx.Installation().GetForUpdate(ctx)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return port.Installation{}, contract.NewAppError(contract.ErrorKindUnavailable, "installation_not_initialized",
				"the installation row has not been initialized")
		}
		return port.Installation{}, storeError(err, "installation_read_failed", "could not read the installation state")
	}
	return inst, nil
}

// toSetupView projects the port-level Installation row into the OpenAPI
// Setup shape. BootstrapHTTPS is inferred from whether an active TLS
// version has ever been recorded: port.Installation.ActiveTLSVersionID's own
// doc comment defines "empty" as "before any HTTPS version is active", which
// is exactly the bootstrap-certificate condition Setup.bootstrap_https
// names. There is no dedicated boolean column or documented ServiceMode
// enum to read this from instead -- see the report, this mapping is this
// developer's inference from the one line of port documentation available,
// not a confirmed product decision.
func toSetupView(inst port.Installation) contract.SetupView {
	return contract.SetupView{
		SetupStage:     contract.SetupStage(inst.SetupStage),
		BootstrapHTTPS: inst.ActiveTLSVersionID == "",
	}
}

// Status reports the current installation progress. It is reachable
// anonymously (api/openapi.json "/api/v1/setup" get: "security": []), so
// there is no principal check and no Authorizer call -- every caller,
// authenticated or not, sees the same setup stage.
func (s *SetupService) Status(ctx context.Context, meta contract.RequestMeta, cmd contract.EmptyCommand) (contract.SetupView, error) {
	var view contract.SetupView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		inst, err := loadInstallation(ctx, tx)
		if err != nil {
			return err
		}
		view = toSetupView(inst)
		return nil
	})
	if err != nil {
		return contract.SetupView{}, err
	}
	return view, nil
}

// CreateAdmin creates the first administrator account
// (docs/backend-implementation.md §8 "최초 관리자" row). It is reachable
// anonymously; the installation itself is what gates it, checked and
// advanced under its own row lock inside the single Write below.
func (s *SetupService) CreateAdmin(ctx context.Context, meta contract.MutationMeta, cmd contract.SetupCreateAdminCommand) (contract.AccountView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.AccountView{}, err
	}
	// §10: a request already canceled before any work started must produce
	// no external effect -- not even a password hash.
	if err := ctx.Err(); err != nil {
		return contract.AccountView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	// §8: the password hash is prepared OUTSIDE the transaction. There is no
	// per-attempt rate limit for this bootstrap step -- preauth.go's fixed
	// subject kinds do not include one, and this file must not widen that
	// contract itself (see the report for why one was not invented here).
	hash, err := s.deps.PasswordHasher.Hash(ctx, cmd.Password)
	if err != nil {
		return contract.AccountView{}, storeError(err, "setup_password_hash_failed", "could not hash the administrator password")
	}

	normalized := domain.NormalizeLoginName(cmd.LoginName)
	accountID, err := domain.ParseAccountID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.AccountView{}, contract.FromDomainError(err)
	}
	account, err := domain.NewAccount(domain.AccountFacts{
		ID:                  accountID,
		NormalizedLoginName: normalized,
		PasswordHash:        hash,
		State:               domain.AccountStateActive,
		AuthEpoch:           0,
		IsGlobalAdmin:       true,
	})
	if err != nil {
		return contract.AccountView{}, contract.FromDomainError(err)
	}

	var result contract.AccountView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		// "installation 미설정 재확인": re-read the installation row under
		// its own lock. Two concurrent CreateAdmin calls -- U01 -- are
		// serialized here by the UnitOfWork itself; whichever commits first
		// advances setup_stage, so the second one's own GetForUpdate sees
		// the change and this check rejects it, however different its own
		// chosen login name was.
		inst, err := loadInstallation(ctx, tx)
		if err != nil {
			return err
		}
		if inst.SetupStage != port.SetupStageAccountRequired || inst.FirstAdminID != "" {
			return contract.NewAppError(contract.ErrorKindConflict, "setup_already_has_admin",
				"an administrator account already exists")
		}

		if err := tx.Accounts().InsertAccount(ctx, account); err != nil {
			if errors.Is(err, port.ErrDuplicate) {
				return contract.NewAppError(contract.ErrorKindConflict, "setup_login_name_taken",
					"this login name is already in use")
			}
			return storeError(err, "setup_account_store_failed", "could not store the new administrator account")
		}

		// port.Installation is a plain struct with no domain transition to
		// bump its own Version; the app owns advancing the optimistic-lock
		// token itself, preserving the version just read as expectedVersion
		// (docs/backend-implementation.md §5).
		originalVersion := inst.Version
		inst.FirstAdminID = accountID
		inst.SetupStage = port.SetupStagePKIRequired
		inst.Version = inst.Version.Next()
		if err := tx.Installation().Save(ctx, inst, originalVersion); err != nil {
			return storeError(err, "setup_installation_save_failed", "could not advance the installation stage")
		}

		now := s.deps.Clock.Now()
		if err := appendAccountAudit(ctx, tx, s.deps.IDs, now, meta.RequestMeta,
			contract.AuditActorAccount, string(accountID), "setup.create_admin", "account", string(accountID)); err != nil {
			return err
		}

		result = toAccountView(account)
		return nil
	})
	if err != nil {
		return contract.AccountView{}, err
	}
	return result, nil
}

// Complete advances installation past pki_required once an administrator
// has finished configuring PKI settings. It requires a live admin session
// (api/openapi.json "/api/v1/setup/complete" post has the default
// SessionCookie security) and the Settings version the client last saw
// (§3 "Complete는 Settings version 필수"), so a Settings change nobody has
// looked at yet cannot be silently finalized underneath the operator.
func (s *SetupService) Complete(ctx context.Context, meta contract.MutationMeta, cmd contract.SetupCompleteCommand) (contract.SetupView, error) {
	if !meta.Principal.IsAdmin() {
		return contract.SetupView{}, contract.NewAppError(contract.ErrorKindForbidden, "setup_complete_requires_admin",
			"completing setup requires an administrator session")
	}
	expectedSettingsVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.SetupView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.SetupView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	var view contract.SetupView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionSetupComplete, port.NewAuthorizationScope()); err != nil {
			return err
		}

		inst, err := loadInstallation(ctx, tx)
		if err != nil {
			return err
		}
		if inst.SetupStage == port.SetupStageComplete {
			// Idempotent: finishing an already-complete setup just reports
			// current state instead of erroring -- Complete carries no
			// idempotency key of its own to replay through the request-store
			// mechanism, so this is the natural, cheap alternative.
			view = toSetupView(inst)
			return nil
		}
		if inst.SetupStage != port.SetupStagePKIRequired {
			// Unreachable in practice: requireCurrentAuth above already
			// requires a live admin session, which cannot exist before
			// CreateAdmin has run and advanced past account_required.
			// Guarded anyway rather than assumed.
			return contract.NewAppError(contract.ErrorKindConflict, "setup_not_ready_to_complete",
				"the installation has not reached the pki_required stage")
		}

		settings, err := tx.Installation().GetSettings(ctx)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindConflict, "setup_settings_not_configured",
				"service settings must be configured before completing setup")
		} else if err != nil {
			return storeError(err, "setup_settings_read_failed", "could not read the service settings")
		}
		if settings.Version != expectedSettingsVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "setup_settings_version_mismatch",
				"the service settings changed since this request was prepared")
		}

		originalVersion := inst.Version
		inst.SetupStage = port.SetupStageComplete
		inst.Version = inst.Version.Next()
		if err := tx.Installation().Save(ctx, inst, originalVersion); err != nil {
			return storeError(err, "setup_installation_save_failed", "could not complete the installation")
		}

		now := s.deps.Clock.Now()
		if err := appendAccountAudit(ctx, tx, s.deps.IDs, now, meta.RequestMeta,
			contract.AuditActorAccount, string(meta.Principal.AccountID()), "setup.complete", "installation", "installation"); err != nil {
			return err
		}

		view = toSetupView(inst)
		return nil
	})
	if err != nil {
		return contract.SetupView{}, err
	}
	return view, nil
}
