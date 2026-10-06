package service

import (
	"context"
	"errors"
	"strconv"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// UpdateSeries changes the operator-facing name and policy for future
// certificates. It does not modify the current certificate, delivery, or key
// generation's renewal count.
func (s *IssuanceService) UpdateSeries(ctx context.Context, meta contract.MutationMeta, cmd contract.IssuanceUpdateSeriesCommand) (contract.LeafSeriesView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.LeafSeriesView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.LeafSeriesView{}, contract.NewAppError(contract.ErrorKindForbidden, "issuance_requires_admin",
			"updating a certificate series requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.LeafSeriesView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.LeafSeriesView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	var result contract.LeafSeriesView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, cmd.SeriesID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "series_not_found", "series does not exist").
				WithField("series_id", string(cmd.SeriesID))
		} else if err != nil {
			return storeError(err, "issuance_series_read_failed", "could not read the series")
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionIssuanceUpdateSeries,
			port.NewAuthorizationScope(snapshot.Series.ManagementAuthorityID())); err != nil {
			return err
		}
		if snapshot.Series.IsArchived() {
			return contract.NewAppError(contract.ErrorKindConflict, "series_archived", "series is archived")
		}
		if snapshot.Series.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "version_mismatch", "series has moved on since expected_version was read")
		}

		updated := snapshot.Series
		changedFields := make(map[string]string, 3)
		if cmd.Name != nil {
			updated, err = updated.Rename(*cmd.Name)
			if err != nil {
				return contract.FromDomainError(err)
			}
			if updated.Name() != snapshot.Series.Name() {
				changedFields["name"] = updated.Name()
			}
		}
		policy := updated.Policy()
		originalPolicy := policy
		if cmd.Validity != nil {
			policy.CertificateValidity, err = cmd.Validity.Domain()
			if err != nil {
				return contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity",
					"validity must have a positive value and a supported unit", err)
			}
			if policy.CertificateValidity != originalPolicy.CertificateValidity {
				changedFields["validity"] = strconv.Itoa(policy.CertificateValidity.Value()) + " " + string(policy.CertificateValidity.Unit())
			}
		}
		if cmd.RotateEvery != nil {
			policy.RotateEvery = *cmd.RotateEvery
			if policy.RotateEvery != originalPolicy.RotateEvery {
				changedFields["rotate_every"] = strconv.Itoa(policy.RotateEvery)
			}
		}
		if policy != updated.Policy() {
			updated, err = updated.ChangePolicy(policy)
			if err != nil {
				return contract.FromDomainError(err)
			}
		}

		if updated.Version() != snapshot.Series.Version() {
			if err := tx.PKI().SaveSeries(ctx, updated, expectedVersion); err != nil {
				return storeError(err, "issuance_series_save_failed", "could not update the series")
			}
			if err := appendSeriesAudit(ctx, tx, s.deps.IDs, s.deps.Clock.Now(), meta, "issuance.series.updated",
				updated.ID(), snapshot.Series.ManagementAuthorityID(), changedFields); err != nil {
				return err
			}
		}
		snapshot.Series = updated
		result = toSeriesView(snapshot)
		return nil
	})
	if err != nil {
		return contract.LeafSeriesView{}, err
	}
	return result, nil
}

// ArchiveSeries hides an item from active management lists while preserving
// its certificates, deliveries, revocations, and audit history.
func (s *IssuanceService) ArchiveSeries(ctx context.Context, meta contract.MutationMeta, cmd contract.IssuanceArchiveSeriesCommand) (contract.LeafSeriesView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.LeafSeriesView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.LeafSeriesView{}, contract.NewAppError(contract.ErrorKindForbidden, "issuance_requires_admin",
			"archiving a certificate series requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.LeafSeriesView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.LeafSeriesView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	var result contract.LeafSeriesView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, cmd.SeriesID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "series_not_found", "series does not exist").
				WithField("series_id", string(cmd.SeriesID))
		} else if err != nil {
			return storeError(err, "issuance_series_read_failed", "could not read the series")
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionIssuanceArchiveSeries,
			port.NewAuthorizationScope(snapshot.Series.ManagementAuthorityID())); err != nil {
			return err
		}
		if snapshot.Series.IsArchived() {
			return contract.NewAppError(contract.ErrorKindConflict, "series_archived", "series is already archived")
		}
		if snapshot.Series.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "version_mismatch", "series has moved on since expected_version was read")
		}
		now := s.deps.Clock.Now()
		archived, err := snapshot.Series.Archive(now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.PKI().SaveSeries(ctx, archived, expectedVersion); err != nil {
			return storeError(err, "issuance_series_save_failed", "could not archive the series")
		}
		if err := appendSeriesAudit(ctx, tx, s.deps.IDs, now, meta, "issuance.series.archived",
			archived.ID(), archived.ManagementAuthorityID(), map[string]string{}); err != nil {
			return err
		}
		snapshot.Series = archived
		result = toSeriesView(snapshot)
		return nil
	})
	if err != nil {
		return contract.LeafSeriesView{}, err
	}
	return result, nil
}

func appendSeriesAudit(
	ctx context.Context,
	tx port.TxStores,
	ids port.IDGenerator,
	now domain.Instant,
	meta contract.MutationMeta,
	action string,
	seriesID domain.SeriesID,
	managementAuthorityID domain.AuthorityID,
	fields map[string]string,
) error {
	event := port.AuditEvent{
		ID: ids.NewUUID(), OccurredAt: now, ActorKind: contract.AuditActorAccount,
		ActorID: string(meta.Principal.AccountID()), Action: action,
		TargetType: "leaf_series", TargetID: string(seriesID), ClientIP: clientIP(meta.RequestMeta),
		Result:  contract.AuditResultSuccess,
		Details: contract.AuditDetails{SchemaVersion: 1, Fields: fields},
	}
	if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(managementAuthorityID)); err != nil {
		return storeError(err, "issuance_series_audit_failed", "could not record the series change")
	}
	return nil
}
