package service

import (
	"context"
	"errors"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func TestIssuanceSeriesMutationsRejectMissingVersionAndNonAdmin(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*issuanceFixture, contract.MutationMeta, domain.SeriesID) error
	}{
		{
			name: "update",
			call: func(f *issuanceFixture, meta contract.MutationMeta, id domain.SeriesID) error {
				name := "changed"
				_, err := f.svc.UpdateSeries(context.Background(), meta, contract.IssuanceUpdateSeriesCommand{SeriesID: id, Name: &name})
				return err
			},
		},
		{
			name: "archive",
			call: func(f *issuanceFixture, meta contract.MutationMeta, id domain.SeriesID) error {
				_, err := f.svc.ArchiveSeries(context.Background(), meta, contract.IssuanceArchiveSeriesCommand{SeriesID: id})
				return err
			},
		},
	} {
		t.Run(tc.name+" requires version", func(t *testing.T) {
			f := newIssuanceFixture(t)
			issued := issueReissueSource(t, f)
			meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: issuanceAdminPrincipal(t)}}
			err := tc.call(f, meta, issued.SeriesID)
			assertSeriesFailure(t, err, contract.ErrorKindConflict, "version_required")
		})

		t.Run(tc.name+" requires administrator", func(t *testing.T) {
			f := newIssuanceFixture(t)
			issued := issueReissueSource(t, f)
			version := currentSeriesSnapshot(t, f.store, issued.SeriesID).Series.Version()
			meta := seriesMutationMeta(t, version)
			meta.Principal = contract.AnonymousPrincipal()
			err := tc.call(f, meta, issued.SeriesID)
			assertSeriesFailure(t, err, contract.ErrorKindForbidden, "issuance_requires_admin")
		})

		t.Run(tc.name+" requires scope permission", func(t *testing.T) {
			f := newIssuanceFixture(t)
			issued := issueReissueSource(t, f)
			snapshot := currentSeriesSnapshot(t, f.store, issued.SeriesID)
			f.authorizer.allow = false
			err := tc.call(f, seriesMutationMeta(t, snapshot.Series.Version()), issued.SeriesID)
			assertSeriesFailure(t, err, contract.ErrorKindForbidden, "not_authorized")
			after := currentSeriesSnapshot(t, f.store, issued.SeriesID)
			if after.Series.Version() != snapshot.Series.Version() || after.Series.IsArchived() {
				t.Fatalf("series changed after denied scope request: %+v", after.Series)
			}
		})
	}
}

func TestIssuanceSeriesMutationsRequireCurrentSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*issuanceFixture, contract.MutationMeta, domain.SeriesID) error
	}{
		{
			name: "update",
			call: func(f *issuanceFixture, meta contract.MutationMeta, id domain.SeriesID) error {
				name := "changed"
				_, err := f.svc.UpdateSeries(context.Background(), meta, contract.IssuanceUpdateSeriesCommand{SeriesID: id, Name: &name})
				return err
			},
		},
		{
			name: "archive",
			call: func(f *issuanceFixture, meta contract.MutationMeta, id domain.SeriesID) error {
				_, err := f.svc.ArchiveSeries(context.Background(), meta, contract.IssuanceArchiveSeriesCommand{SeriesID: id})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			issued := issueReissueSource(t, f)
			snapshot := currentSeriesSnapshot(t, f.store, issued.SeriesID)
			meta := seriesMutationMeta(t, snapshot.Series.Version())
			if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
				return tx.Accounts().DeleteAllSessions(context.Background(), issuanceTestAdminAccountID)
			}); err != nil {
				t.Fatalf("invalidate admin sessions: %v", err)
			}

			err := tc.call(f, meta, issued.SeriesID)
			var appErr *contract.AppError
			if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth {
				t.Fatalf("mutation with invalidated session error = %v, want auth failure", err)
			}
			after := currentSeriesSnapshot(t, f.store, issued.SeriesID)
			if after.Series.Version() != snapshot.Series.Version() || after.Series.IsArchived() {
				t.Fatalf("series changed after invalidated-session request: %+v", after.Series)
			}
		})
	}
}

func TestIssuanceSeriesRepositoryAndAuditFailuresRollBackMutations(t *testing.T) {
	for _, tc := range []struct {
		name     string
		getErr   error
		saveErr  error
		auditErr error
		wantCode string
	}{
		{name: "series read", getErr: errors.New("injected series read failure"), wantCode: "issuance_series_read_failed"},
		{name: "series save", saveErr: errors.New("injected series save failure"), wantCode: "issuance_series_save_failed"},
		{name: "audit append", auditErr: errors.New("injected series audit failure"), wantCode: "issuance_series_audit_failed"},
		{name: "archive save", saveErr: errors.New("injected series save failure"), wantCode: "issuance_series_save_failed"},
		{name: "archive audit", auditErr: errors.New("injected series audit failure"), wantCode: "issuance_series_audit_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			issued := issueReissueSource(t, f)
			before := currentSeriesSnapshot(t, f.store, issued.SeriesID)
			beforeAuditEvents := len(f.store.AuditEvents())
			name := "changed"
			f.svc.deps.UnitOfWork = seriesFailureUnitOfWork{
				inner: f.store, getSeriesErr: tc.getErr, saveSeriesErr: tc.saveErr, auditErr: tc.auditErr,
			}
			var err error
			if tc.name == "archive save" || tc.name == "archive audit" {
				_, err = f.svc.ArchiveSeries(context.Background(), seriesMutationMeta(t, before.Series.Version()),
					contract.IssuanceArchiveSeriesCommand{SeriesID: issued.SeriesID})
			} else {
				_, err = f.svc.UpdateSeries(context.Background(), seriesMutationMeta(t, before.Series.Version()),
					contract.IssuanceUpdateSeriesCommand{SeriesID: issued.SeriesID, Name: &name})
			}
			assertSeriesFailure(t, err, contract.ErrorKindUnavailable, tc.wantCode)

			after := currentSeriesSnapshot(t, f.store, issued.SeriesID)
			if after.Series.Version() != before.Series.Version() || after.Series.Name() != before.Series.Name() || after.Series.IsArchived() {
				t.Fatalf("series changed after %s: name=%q version=%d archived=%v", tc.name, after.Series.Name(), after.Series.Version(), after.Series.IsArchived())
			}
			if got := len(f.store.AuditEvents()); got != beforeAuditEvents {
				t.Fatalf("audit event count after %s = %d, want unchanged %d", tc.name, got, beforeAuditEvents)
			}
		})
	}
}

func TestIssuanceArchiveSeriesRejectsStaleVersion(t *testing.T) {
	f := newIssuanceFixture(t)
	issued := issueReissueSource(t, f)
	before := currentSeriesSnapshot(t, f.store, issued.SeriesID)
	name := "moved on"
	if _, err := f.svc.UpdateSeries(context.Background(), seriesMutationMeta(t, before.Series.Version()),
		contract.IssuanceUpdateSeriesCommand{SeriesID: issued.SeriesID, Name: &name}); err != nil {
		t.Fatalf("UpdateSeries: %v", err)
	}
	_, err := f.svc.ArchiveSeries(context.Background(), seriesMutationMeta(t, before.Series.Version()),
		contract.IssuanceArchiveSeriesCommand{SeriesID: issued.SeriesID})
	assertSeriesFailure(t, err, contract.ErrorKindConflict, "version_mismatch")
	after := currentSeriesSnapshot(t, f.store, issued.SeriesID)
	if after.Series.IsArchived() || after.Series.Name() != name || after.Series.Version() != before.Series.Version().Next() {
		t.Fatalf("series changed after stale archive request: %+v", after.Series)
	}
}

func assertSeriesFailure(t *testing.T, err error, kind contract.ErrorKind, code string) {
	t.Helper()
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != kind || appErr.Code() != code {
		t.Fatalf("error = %v, want %s/%s", err, kind, code)
	}
}

type seriesFailureUnitOfWork struct {
	inner         port.UnitOfWork
	getSeriesErr  error
	saveSeriesErr error
	auditErr      error
}

func (u seriesFailureUnitOfWork) Write(ctx context.Context, callback func(port.TxStores) error) error {
	return u.inner.Write(ctx, func(tx port.TxStores) error {
		return callback(seriesFailureTxStores{
			TxStores: tx,
			pki: seriesFailurePKIRepository{
				PKIRepository: tx.PKI(), getSeriesErr: u.getSeriesErr, saveSeriesErr: u.saveSeriesErr,
			},
			audit: seriesFailureAuditRepository{AuditRepository: tx.Audit(), fail: u.auditErr},
		})
	})
}

type seriesFailureTxStores struct {
	port.TxStores
	pki   port.PKIRepository
	audit port.AuditRepository
}

func (tx seriesFailureTxStores) PKI() port.PKIRepository     { return tx.pki }
func (tx seriesFailureTxStores) Audit() port.AuditRepository { return tx.audit }

type seriesFailurePKIRepository struct {
	port.PKIRepository
	getSeriesErr  error
	saveSeriesErr error
}

func (r seriesFailurePKIRepository) GetSeriesForUpdate(ctx context.Context, id domain.SeriesID) (port.SeriesSnapshot, error) {
	if r.getSeriesErr != nil {
		return port.SeriesSnapshot{}, r.getSeriesErr
	}
	return r.PKIRepository.GetSeriesForUpdate(ctx, id)
}

func (r seriesFailurePKIRepository) SaveSeries(ctx context.Context, series domain.LeafSeries, expected domain.Version) error {
	if r.saveSeriesErr != nil {
		return r.saveSeriesErr
	}
	return r.PKIRepository.SaveSeries(ctx, series, expected)
}

type seriesFailureAuditRepository struct {
	port.AuditRepository
	fail error
}

func (r seriesFailureAuditRepository) Append(ctx context.Context, event port.AuditEvent, scope port.AuditScope) error {
	if r.fail != nil {
		return r.fail
	}
	return r.AuditRepository.Append(ctx, event, scope)
}
