// SettingsService implements the Get/Update pair
// (docs/backend-implementation.md §3 SettingsService row). Get is a plain
// authorized read; Update is the write side of the settings_json v1 codec
// settings.go already owns for reads -- this file is the one place that
// calls EncodeSettingsV1, per §14.8's "공통 typed codec을 만들어 B03 읽기와
// B04 쓰기가 공유한다".
package service

import (
	"context"
	"errors"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// SettingsDeps is SettingsService's dependency set: CommonDeps plus the two
// additions docs/backend-implementation.md §5's assembly table names for
// Settings ("URLValidator, 현재 TLS 공개 스냅샷 조회"). There is no separate
// port interface for the second one: TLSRepository (already part of every
// TxStores) is the current TLS public snapshot, and reading it through the
// same transaction as the rest of Update keeps the check inside the single
// commit rather than adding a second injected dependency that could read a
// different snapshot than the Write itself locks.
type SettingsDeps struct {
	CommonDeps
	URLValidator port.URLValidator
}

// Validate reports the first missing dependency, common or Settings-specific.
func (d SettingsDeps) Validate() error {
	if err := d.CommonDeps.Validate(); err != nil {
		return err
	}
	return firstMissing(
		required{"URLValidator", d.URLValidator == nil},
	)
}

// SettingsService implements SettingsService.Get/Update
// (docs/backend-implementation.md §3).
type SettingsService struct {
	deps SettingsDeps
}

// NewSettingsService constructs the service, failing fast on a missing
// dependency rather than at the first request.
func NewSettingsService(deps SettingsDeps) (*SettingsService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &SettingsService{deps: deps}, nil
}

// settingsAuditTargetID is the fixed target id for every settings audit
// event, matching the fixed PK=1 service_settings row
// (docs/data-model.md "고정 PK=1").
const settingsAuditTargetID = "1"

// settingsScope is UNRESOLVED, not decided. §14.6 states, in general terms,
// "현재 MVP도 scope를 비워 저장하지 않는다" -- no stored audit event should
// carry an empty scope. Settings has no authority relation at all
// (service_settings is the fixed PK=1 installation-wide row,
// docs/data-model.md; there is no CA-scoped administrator in the current
// MVP role model to derive one from either, data-model.md "미래 역할
// 테이블을 미리 빈 상태로 구현하지 않는다"), so there is no stored relation
// this function could read to produce a non-empty scope without inventing
// one (e.g. enumerating every Root authority would be a guess, not a read of
// an actual relation Settings has to that event).
//
// This developer is not resolving that tension by picking an answer here:
// §14.6's own text is about leaf download/delivery events, which always
// have a real management authority, and nothing in the docs says what a
// non-authority-scoped admin action's stored scope should be. Update below
// still calls Audit().Append (dropping the audit row entirely to dodge the
// question would itself be an undocumented product decision, and a worse
// one), but with this function's empty result -- which is why this is
// flagged as a **blocking open question for the planning team**, not a
// settled design choice, in this round's report. Do not read the empty
// return as this developer's answer to what the correct scope is.
func settingsScope() []domain.AuthorityID { return nil }

// Get returns the current settings snapshot. It is a plain authorized read:
// no idempotency, no version requirement (docs/backend-implementation.md §3
// "Get → Settings").
func (s *SettingsService) Get(ctx context.Context, meta contract.RequestMeta, cmd contract.SettingsGetCommand) (contract.SettingsView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.SettingsView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.SettingsView{}, contract.NewAppError(contract.ErrorKindForbidden, "settings_requires_admin",
			"reading settings requires an administrator session")
	}

	var view contract.SettingsView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionSettingsGet, port.NewAuthorizationScope(settingsScope()...)); err != nil {
			return err
		}
		settings, err := tx.Installation().GetSettings(ctx)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindConflict, "settings_not_configured",
				"installation settings have not been initialized")
		} else if err != nil {
			return storeError(err, "settings_read_failed", "could not read settings")
		}
		v1, err := DecodeSettingsV1(settings)
		if err != nil {
			return err
		}
		view = toSettingsView(v1, settings.Version)
		return nil
	})
	if err != nil {
		return contract.SettingsView{}, err
	}
	return view, nil
}

// preparedSettingsUpdate is what Update resolves before opening its Write:
// the merged, fully-validated snapshot to encode and, when service_url is
// changing, the active TLS version's own validated_service_url to compare
// it against. Neither half is authoritative -- the Write re-reads and
// re-checks both under lock.
type preparedSettingsUpdate struct {
	merged          SettingsV1
	encoded         []byte
	checkServiceURL bool
	newServiceURL   string
}

// Update applies a partial SettingsPatch to the stored snapshot
// (docs/backend-implementation.md §3 "Update: SettingsPatch → Settings";
// §3 "Update에 version 필수, 이전 링크/계보 설정 불변"). The only store touched
// is the fixed service_settings row: nothing here reads or writes a
// delivery, grant, series or certificate row, so an update can never retroactively
// change an already-issued certificate's embedded policy or an
// already-created download link's expiry (U04).
func (s *SettingsService) Update(ctx context.Context, meta contract.MutationMeta, cmd contract.SettingsUpdateCommand) (contract.SettingsView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.SettingsView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.SettingsView{}, contract.NewAppError(contract.ErrorKindForbidden, "settings_requires_admin",
			"updating settings requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.SettingsView{}, err
	}

	// §6: the network-reachability half of URLValidator, and the merge
	// itself, happen outside the transaction; the Write below only
	// re-confirms the version and, when service_url changed, the active TLS
	// snapshot, then stores.
	prep, err := s.prepareUpdate(ctx, cmd)
	if err != nil {
		return contract.SettingsView{}, err
	}

	var result contract.SettingsView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionSettingsUpdate, port.NewAuthorizationScope(settingsScope()...)); err != nil {
			return err
		}

		settings, err := tx.Installation().GetSettings(ctx)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindConflict, "settings_not_configured",
				"installation settings have not been initialized")
		} else if err != nil {
			return storeError(err, "settings_read_failed", "could not read settings")
		}
		if settings.Version != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "settings_version_conflict",
				"settings have changed since this request was prepared")
		}

		// The Settings schema's own description fixes this: "URL must match
		// active operational TLS certificate or be changed through CLI
		// recovery." The active TLS version can change between prepareUpdate
		// and this lock, so it is re-read here rather than trusting the
		// snapshot prepareUpdate saw.
		if prep.checkServiceURL {
			if err := requireServiceURLMatchesActiveTLS(ctx, tx, prep.newServiceURL); err != nil {
				return err
			}
		}

		finalVersion := expectedVersion.Next()
		if err := tx.Installation().SaveSettings(ctx, port.Settings{
			SchemaVersion: settingsSchemaVersionV1,
			SettingsJSON:  prep.encoded,
			Version:       finalVersion,
			UpdatedBy:     meta.Principal.AccountID(),
		}, expectedVersion); err != nil {
			return storeError(err, "settings_save_failed", "could not save settings")
		}

		now := s.deps.Clock.Now()
		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "settings.update",
			TargetType: "settings",
			TargetID:   settingsAuditTargetID,
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, settingsScope()); err != nil {
			return storeError(err, "settings_audit_failed", "could not record the settings audit event")
		}

		result = toSettingsView(prep.merged, finalVersion)
		return nil
	})
	if err != nil {
		return contract.SettingsView{}, err
	}
	return result, nil
}

// prepareUpdate reads the current snapshot, merges cmd's patch fields over
// it, validates and encodes the result, and -- when service_url is part of
// the patch -- runs the well-formed/reachable half of the check
// (URLValidator) and captures the active TLS snapshot's own
// validated_service_url for the Write to re-confirm under lock.
func (s *SettingsService) prepareUpdate(ctx context.Context, cmd contract.SettingsUpdateCommand) (preparedSettingsUpdate, error) {
	var current SettingsV1
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		settings, err := tx.Installation().GetSettings(ctx)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindConflict, "settings_not_configured",
				"installation settings have not been initialized")
		} else if err != nil {
			return storeError(err, "settings_read_failed", "could not read settings")
		}
		v1, err := DecodeSettingsV1(settings)
		if err != nil {
			return err
		}
		current = v1
		return nil
	})
	if err != nil {
		return preparedSettingsUpdate{}, err
	}

	merged, err := applySettingsPatch(current, cmd)
	if err != nil {
		return preparedSettingsUpdate{}, err
	}

	prep := preparedSettingsUpdate{merged: merged}
	if cmd.ServiceURL != nil {
		if err := s.deps.URLValidator.Validate(ctx, *cmd.ServiceURL); err != nil {
			return preparedSettingsUpdate{}, contract.WrapAppError(contract.ErrorKindValidation, "settings_service_url_invalid",
				"service_url is not a usable service address", err)
		}
		prep.checkServiceURL = true
		prep.newServiceURL = *cmd.ServiceURL
	}

	encoded, err := EncodeSettingsV1(merged)
	if err != nil {
		return preparedSettingsUpdate{}, err
	}
	prep.encoded = encoded
	return prep, nil
}

// requireServiceURLMatchesActiveTLS enforces the Settings schema's
// description ("URL must match active operational TLS certificate or be
// changed through CLI recovery"): the normal administrative API can only
// set service_url to whatever the currently active TLS version was itself
// validated against, never to a different address -- that requires the
// separate CLI recovery path, which is out of this service's scope.
//
// A fresh installation with no TLS history yet, or one whose active version
// carries no validated_service_url (the bootstrap exception,
// domain.NewTLSVersion's "bootstrap allows empty service URL"), has nothing
// to compare against; this developer's reading is that the cross-check is
// then skipped rather than refused, since there is no operational TLS
// certificate yet for the new URL to disagree with. Flagged for the lead:
// the doc settles the comparison itself but not this no-active-TLS-yet edge
// case.
func requireServiceURLMatchesActiveTLS(ctx context.Context, tx port.TxStores, newServiceURL string) error {
	active, err := tx.TLS().GetActiveForUpdate(ctx)
	if errors.Is(err, port.ErrNotFound) {
		return nil
	}
	if err != nil {
		return storeError(err, "settings_tls_active_read_failed", "could not read the active TLS version")
	}
	version, err := tx.TLS().GetVersion(ctx, active.CandidateVersionID())
	if err != nil {
		return storeError(err, "settings_tls_version_read_failed", "could not read the active TLS version's snapshot")
	}
	activeURL := version.ValidatedServiceURL()
	if activeURL == "" {
		return nil
	}
	if activeURL != newServiceURL {
		return contract.NewAppError(contract.ErrorKindConflict, "settings_service_url_locked_to_active_tls",
			"service_url must match the active operational TLS certificate; use CLI recovery to change it")
	}
	return nil
}

// applySettingsPatch overlays cmd's present fields onto current, producing
// the fully-resolved snapshot §14.8 requires Encode to receive ("저장 시
// 기본값을 모두 해석해 완전한 snapshot을 저장한다"). Fields cmd omitted keep
// current's value untouched.
func applySettingsPatch(current SettingsV1, cmd contract.SettingsUpdateCommand) (SettingsV1, error) {
	merged := current
	if cmd.ServiceURL != nil {
		merged.ServiceURL = *cmd.ServiceURL
	}
	if cmd.LeafValidity != nil {
		v, err := cmd.LeafValidity.Domain()
		if err != nil {
			return SettingsV1{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity", "leaf_validity is invalid", err)
		}
		merged.LeafValidity = v
	}
	if cmd.RootValidity != nil {
		v, err := cmd.RootValidity.Domain()
		if err != nil {
			return SettingsV1{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity", "root_validity is invalid", err)
		}
		merged.RootValidity = v
	}
	if cmd.IntermediateValidity != nil {
		v, err := cmd.IntermediateValidity.Domain()
		if err != nil {
			return SettingsV1{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity", "intermediate_validity is invalid", err)
		}
		merged.IntermediateValidity = v
	}
	if cmd.RotateEvery != nil {
		merged.RotateEvery = *cmd.RotateEvery
	}
	if cmd.PrivateDeliverySeconds != nil {
		merged.PrivateDeliverySeconds = *cmd.PrivateDeliverySeconds
	}
	if cmd.PublicLinkSeconds != nil {
		merged.PublicLinkSeconds = *cmd.PublicLinkSeconds
	}
	if cmd.CRLIntervalSeconds != nil {
		merged.CRLIntervalSeconds = *cmd.CRLIntervalSeconds
	}
	if cmd.CRLValiditySeconds != nil {
		merged.CRLValiditySeconds = *cmd.CRLValiditySeconds
	}
	if cmd.AuditRetentionDays != nil {
		merged.AuditRetentionDays = *cmd.AuditRetentionDays
	}
	return merged, nil
}

// toSettingsView projects a resolved SettingsV1 plus its stored version into
// the OpenAPI Settings response shape.
func toSettingsView(v SettingsV1, version domain.Version) contract.SettingsView {
	return contract.SettingsView{
		ServiceURL:              v.ServiceURL,
		LeafValidity:            v.LeafValidity,
		RootValidity:            v.RootValidity,
		IntermediateValidity:    v.IntermediateValidity,
		RotateEvery:             v.RotateEvery,
		PrivateDeliveryLifetime: domain.NewDuration(secondsToDuration(v.PrivateDeliverySeconds)),
		PublicLinkLifetime:      domain.NewDuration(secondsToDuration(v.PublicLinkSeconds)),
		CRLInterval:             domain.NewDuration(secondsToDuration(v.CRLIntervalSeconds)),
		CRLValidity:             domain.NewDuration(secondsToDuration(v.CRLValiditySeconds)),
		AuditRetentionDays:      v.AuditRetentionDays,
		Version:                 version,
	}
}

// secondsToDuration converts a stored seconds-count field into a
// time.Duration for the domain.Duration wrapper SettingsView carries.
func secondsToDuration(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}
