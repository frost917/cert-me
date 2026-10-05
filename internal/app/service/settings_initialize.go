package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// Initialize creates the installation's first complete Settings snapshot.
// URL syntax and service-address constraints are checked before opening the
// transaction; the commit re-checks current authentication, authorization,
// setup stage, row absence, and the active TLS URL before writing settings
// and its audit event together.
func (s *SettingsService) Initialize(ctx context.Context, meta contract.MutationMeta, cmd contract.SettingsInitializeCommand) (contract.SettingsView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.SettingsView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.SettingsView{}, contract.NewAppError(contract.ErrorKindForbidden, "settings_requires_admin",
			"initializing settings requires an administrator session")
	}
	if err := ctx.Err(); err != nil {
		return contract.SettingsView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	snapshot, err := settingsInitializeSnapshot(cmd)
	if err != nil {
		return contract.SettingsView{}, err
	}
	encoded, err := EncodeSettingsV1(snapshot)
	if err != nil {
		return contract.SettingsView{}, err
	}
	if err := s.deps.URLValidator.Validate(ctx, snapshot.ServiceURL); err != nil {
		return contract.SettingsView{}, contract.WrapAppError(contract.ErrorKindValidation, "settings_service_url_invalid",
			"service_url is not a usable service address", err)
	}

	var result contract.SettingsView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionSettingsUpdate, port.NewAuthorizationScope()); err != nil {
			return err
		}

		installation, err := tx.Installation().GetForUpdate(ctx)
		if errors.Is(err, port.ErrNotFound) {
			return storeError(err, "settings_installation_read_failed", "could not read installation state")
		}
		if err != nil {
			return storeError(err, "settings_installation_read_failed", "could not read installation state")
		}
		if installation.SetupStage != port.SetupStagePKIRequired {
			return contract.NewAppError(contract.ErrorKindConflict, "setup_settings_unavailable",
				"initial settings can only be created during the pki_required stage")
		}

		_, err = tx.Installation().GetSettings(ctx)
		if err == nil {
			return settingsAlreadyConfiguredError()
		}
		if !errors.Is(err, port.ErrNotFound) {
			return storeError(err, "settings_read_failed", "could not read settings")
		}

		if err := requireServiceURLMatchesActiveTLS(ctx, tx, snapshot.ServiceURL); err != nil {
			return err
		}

		const initialVersion domain.Version = 1
		if err := tx.Installation().SaveSettings(ctx, port.Settings{
			SchemaVersion: settingsSchemaVersionV1,
			SettingsJSON:  encoded,
			Version:       initialVersion,
			UpdatedBy:     meta.Principal.AccountID(),
		}, 0); err != nil {
			// SaveSettings' expectedVersion=0 insert path reports a concurrent
			// winner as ErrVersionConflict on SQL adapters and ErrDuplicate on
			// adapters that expose the underlying unique-key result directly.
			if errors.Is(err, port.ErrVersionConflict) || errors.Is(err, port.ErrDuplicate) {
				return settingsAlreadyConfiguredError()
			}
			return storeError(err, "settings_save_failed", "could not initialize settings")
		}

		now := s.deps.Clock.Now()
		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "settings.update",
			TargetType: "settings",
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: settingsSchemaVersionV1, Fields: map[string]string{"operation": "initialize"}},
		}
		if err := tx.Audit().Append(ctx, event, settingsScope()); err != nil {
			return storeError(err, "settings_audit_failed", "could not record the settings audit event")
		}

		result = toSettingsView(snapshot, initialVersion)
		return nil
	})
	if err != nil {
		return contract.SettingsView{}, err
	}
	return result, nil
}

func settingsInitializeSnapshot(cmd contract.SettingsInitializeCommand) (SettingsV1, error) {
	leafValidity, err := cmd.LeafValidity.Domain()
	if err != nil {
		return SettingsV1{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity", "leaf_validity is invalid", err)
	}
	rootValidity, err := cmd.RootValidity.Domain()
	if err != nil {
		return SettingsV1{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity", "root_validity is invalid", err)
	}
	intermediateValidity, err := cmd.IntermediateValidity.Domain()
	if err != nil {
		return SettingsV1{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity", "intermediate_validity is invalid", err)
	}
	return SettingsV1{
		ServiceURL:             *cmd.ServiceURL,
		LeafValidity:           leafValidity,
		RootValidity:           rootValidity,
		IntermediateValidity:   intermediateValidity,
		RotateEvery:            *cmd.RotateEvery,
		PrivateDeliverySeconds: *cmd.PrivateDeliverySeconds,
		PublicLinkSeconds:      *cmd.PublicLinkSeconds,
		CRLIntervalSeconds:     *cmd.CRLIntervalSeconds,
		CRLValiditySeconds:     *cmd.CRLValiditySeconds,
		AuditRetentionDays:     *cmd.AuditRetentionDays,
	}, nil
}

func settingsAlreadyConfiguredError() error {
	return contract.NewAppError(contract.ErrorKindConflict, "settings_already_configured",
		"installation settings are already configured; read the current settings before retrying")
}
