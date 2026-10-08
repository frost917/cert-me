package service

import (
	"context"
	"errors"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type countingQueryReadStore struct {
	port.ReadStore
	calls int
}

func (s *countingQueryReadStore) Read(ctx context.Context, callback func(port.TxStores) error) error {
	s.calls++
	return s.ReadStore.Read(ctx, callback)
}

func TestQueryServiceAuthorityQueriesIncludeCRLStatusInSameRead(t *testing.T) {
	f := newQueryFixture(t)
	readStore := &countingQueryReadStore{ReadStore: f.store}
	svc, err := NewQueryService(CommonDeps{
		UnitOfWork: f.store,
		ReadStore:  readStore,
		Authorizer: f.authorizer,
		Clock:      f.clock,
		IDs:        f.ids,
	})
	if err != nil {
		t.Fatalf("new query service: %v", err)
	}

	t.Run("get", func(t *testing.T) {
		view, err := svc.GetAuthority(context.Background(), f.meta(), contract.AuthorityGetQuery{AuthorityID: f.authorityID})
		if err != nil {
			t.Fatalf("GetAuthority: %v", err)
		}
		if view.CRL == nil {
			t.Error("GetAuthority omitted the authority's persisted CRL status")
		} else if view.CRL.PublicationState != domain.PublicationStateActive {
			t.Errorf("GetAuthority CRL publication state = %q, want %q", view.CRL.PublicationState, domain.PublicationStateActive)
		}
		if readStore.calls != 1 {
			t.Errorf("GetAuthority opened %d read snapshots, want one shared read for authority and CRL status", readStore.calls)
		}
	})

	t.Run("list", func(t *testing.T) {
		readStore.calls = 0
		page, err := svc.ListAuthorities(context.Background(), f.meta(), contract.AuthorityListQuery{})
		if err != nil {
			t.Fatalf("ListAuthorities: %v", err)
		}
		if len(page.Items) != 1 {
			t.Fatalf("ListAuthorities returned %d rows, want one fixture authority", len(page.Items))
		}
		if page.Items[0].CRL == nil {
			t.Error("ListAuthorities omitted the authority's persisted CRL status")
		} else if page.Items[0].CRL.PublicationState != domain.PublicationStateActive {
			t.Errorf("ListAuthorities CRL publication state = %q, want %q", page.Items[0].CRL.PublicationState, domain.PublicationStateActive)
		}
		if readStore.calls != 1 {
			t.Errorf("ListAuthorities opened %d read snapshots, want one shared read for authority and CRL status", readStore.calls)
		}
	})
}

func TestToSeriesViewReportsPersistedArchiveTimestamp(t *testing.T) {
	validity, err := domain.NewCalendarValidity(1, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("new validity: %v", err)
	}
	archivedAt := domain.InstantFromUnixMicro(1_800_000_000_000_000)
	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID:                    "11111111-1111-4111-8111-111111111111",
		Name:                  "archived-series",
		Purpose:               domain.SeriesPurposeDistributed,
		ManagementAuthorityID: "22222222-2222-4222-8222-222222222222",
		Policy:                domain.SeriesPolicy{RotateEvery: 3, CertificateValidity: validity},
		Version:               1,
		ArchivedAt:            archivedAt,
	})
	if err != nil {
		t.Fatalf("new archived series: %v", err)
	}

	view := toSeriesView(port.SeriesSnapshot{Series: series})
	if view.ArchivedAt == nil {
		t.Fatal("series view omitted the persisted archive timestamp")
	}
	if !view.ArchivedAt.Equal(archivedAt) {
		t.Fatalf("series archived_at = %s, want %s", view.ArchivedAt, archivedAt)
	}
}

func TestToSeriesViewIncludesPersistedTimestampDeliveryAndArchive(t *testing.T) {
	validity, err := domain.NewCalendarValidity(1, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("new validity: %v", err)
	}
	createdAt := domain.InstantFromUnixMicro(1_700_000_000_000_000)
	archivedAt := domain.InstantFromUnixMicro(1_800_000_000_000_000)
	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID:                    "11111111-1111-4111-8111-111111111111",
		Name:                  "archived-series",
		Purpose:               domain.SeriesPurposeDistributed,
		ManagementAuthorityID: "22222222-2222-4222-8222-222222222222",
		Policy:                domain.SeriesPolicy{RotateEvery: 3, CertificateValidity: validity},
		Version:               1,
		ArchivedAt:            archivedAt,
	})
	if err != nil {
		t.Fatalf("new archived series: %v", err)
	}
	delivery, err := domain.NewDelivery(domain.DeliveryFacts{
		ID:                  "33333333-3333-4333-8333-333333333333",
		LeafKeyGenerationID: "44444444-4444-4444-8444-444444444444",
		CertificateID:       "55555555-5555-4555-8555-555555555555",
		ExpiresAt:           domain.InstantFromUnixMicro(1_900_000_000_000_000),
		State:               domain.DeliveryStatePending,
		Version:             1,
	})
	if err != nil {
		t.Fatalf("new delivery: %v", err)
	}

	snapshot := port.SeriesSnapshot{
		Series:    series,
		CreatedAt: createdAt,
		Delivery:  &delivery,
	}
	view := toSeriesView(snapshot)
	if !view.CreatedAt.Equal(createdAt) {
		t.Errorf("series created_at = %s, want %s", view.CreatedAt, createdAt)
	}
	if view.ArchivedAt == nil || !view.ArchivedAt.Equal(archivedAt) {
		t.Errorf("series archived_at = %v, want %s", view.ArchivedAt, archivedAt)
	}
	if view.Delivery == nil || view.Delivery.ID != delivery.ID() || view.Delivery.State != delivery.State() {
		t.Errorf("series delivery = %#v, want id=%q state=%q", view.Delivery, delivery.ID(), delivery.State())
	}
}

func TestToCertificateViewUsesPersistedCreatedAt(t *testing.T) {
	f := newQueryFixture(t)
	var queried port.QueriedCertificate
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		queried, err = tx.Queries().GetCertificate(context.Background(), f.leafCertID, port.QueryScope{All: true})
		return err
	}); err != nil {
		t.Fatalf("read fixture certificate: %v", err)
	}
	createdAt := domain.InstantFromUnixMicro(1_700_000_000_000_000)
	queried.CreatedAt = createdAt

	view := toCertificateView(queried, f.now)
	if !view.CreatedAt.Equal(createdAt) {
		t.Fatalf("certificate created_at = %s, want persisted %s", view.CreatedAt, createdAt)
	}
}

func TestQueryServiceAuthorityProjectionUsesStoredCreatedAtAndCRLInOneRead(t *testing.T) {
	f := newQueryFixture(t)
	var authority domain.Authority
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		queried, err := tx.Queries().GetAuthority(context.Background(), f.authorityID, port.QueryScope{All: true})
		if err != nil {
			return err
		}
		authority = queried.Authority
		return nil
	}); err != nil {
		t.Fatalf("read fixture authority: %v", err)
	}
	createdAt := domain.InstantFromUnixMicro(1_700_000_000_000_000)
	readStore := &stage4AuthorityProjectionReadStore{
		ReadStore: f.store,
		projection: port.QueriedAuthority{
			Authority: authority,
			CreatedAt: createdAt,
		},
	}
	svc, err := NewQueryService(CommonDeps{
		UnitOfWork: f.store,
		ReadStore:  readStore,
		Authorizer: f.authorizer,
		Clock:      f.clock,
		IDs:        f.ids,
	})
	if err != nil {
		t.Fatalf("new query service: %v", err)
	}

	for _, tc := range []struct {
		name string
		call func() (contract.AuthorityView, error)
	}{
		{
			name: "get",
			call: func() (contract.AuthorityView, error) {
				return svc.GetAuthority(context.Background(), f.meta(), contract.AuthorityGetQuery{AuthorityID: f.authorityID})
			},
		},
		{
			name: "list",
			call: func() (contract.AuthorityView, error) {
				page, err := svc.ListAuthorities(context.Background(), f.meta(), contract.AuthorityListQuery{})
				if err != nil {
					return contract.AuthorityView{}, err
				}
				if len(page.Items) != 1 {
					return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindValidation, "test_fixture_invalid", "expected one fixture authority")
				}
				return page.Items[0], nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readStore.calls = 0
			view, err := tc.call()
			if err != nil {
				t.Fatalf("query authority: %v", err)
			}
			if !view.CreatedAt.Equal(createdAt) {
				t.Errorf("authority created_at = %s, want persisted %s", view.CreatedAt, createdAt)
			}
			if view.CRL == nil || view.CRL.PublicationState != domain.PublicationStateActive {
				t.Errorf("authority CRL status = %#v, want active persisted status", view.CRL)
			}
			if readStore.calls != 1 {
				t.Errorf("authority query opened %d read snapshots, want one", readStore.calls)
			}
		})
	}
}

func TestQueryServiceManagedAuthorityQueriesHideBootstrapAuthority(t *testing.T) {
	f := newQueryFixture(t)
	bootstrapID := seedQueryBootstrapAuthority(t, f)

	page, err := f.svc.ListAuthorities(context.Background(), f.meta(), contract.AuthorityListQuery{
		Page: contract.PageRequest{Limit: 1},
	})
	if err != nil {
		t.Fatalf("ListAuthorities: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != f.authorityID {
		t.Fatalf("managed first page = %#v, want only root %q (bootstrap %q must not consume a page slot)", page.Items, f.authorityID, bootstrapID)
	}
	if page.NextCursor != nil {
		t.Fatalf("managed authority list has unexpected cursor %q", *page.NextCursor)
	}

	_, err = f.svc.GetAuthority(context.Background(), f.meta(), contract.AuthorityGetQuery{AuthorityID: bootstrapID})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Code() != "not_found" {
		t.Fatalf("GetAuthority(bootstrap) error = %v, want indistinguishable not_found", err)
	}
}

func seedQueryBootstrapAuthority(t *testing.T, f *queryFixture) domain.AuthorityID {
	t.Helper()
	id := domain.AuthorityID("00000000-0000-4000-8000-000000000001")
	keyGenerationID := domain.CAKeyGenerationID("00000000-0000-4000-8000-000000000002")
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:              id,
		Kind:            domain.AuthorityKindBootstrap,
		Name:            "query-bootstrap",
		IssuanceState:   domain.IssuanceStateInventory,
		KeyGenerationID: keyGenerationID,
		KeyAvailable:    true,
		Version:         1,
	})
	if err != nil {
		t.Fatalf("new bootstrap authority: %v", err)
	}
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.PKI().InsertAuthority(context.Background(), authority)
	}); err != nil {
		t.Fatalf("insert bootstrap authority: %v", err)
	}
	return id
}

type stage4AuthorityProjectionReadStore struct {
	port.ReadStore
	projection port.QueriedAuthority
	calls      int
}

func (s *stage4AuthorityProjectionReadStore) Read(ctx context.Context, callback func(port.TxStores) error) error {
	s.calls++
	return s.ReadStore.Read(ctx, func(tx port.TxStores) error {
		return callback(stage4AuthorityProjectionTx{
			TxStores: tx,
			queries: stage4AuthorityProjectionRepository{
				QueryRepository: tx.Queries(),
				projection:      s.projection,
			},
		})
	})
}

type stage4AuthorityProjectionTx struct {
	port.TxStores
	queries port.QueryRepository
}

func (tx stage4AuthorityProjectionTx) Queries() port.QueryRepository { return tx.queries }

type stage4AuthorityProjectionRepository struct {
	port.QueryRepository
	projection port.QueriedAuthority
}

func (r stage4AuthorityProjectionRepository) ListAuthorities(_ context.Context, _ contract.AuthorityListQuery, _ port.QueryScope) (contract.Page[port.QueriedAuthority], error) {
	return contract.Page[port.QueriedAuthority]{Items: []port.QueriedAuthority{r.projection}}, nil
}

func (r stage4AuthorityProjectionRepository) GetAuthority(_ context.Context, _ domain.AuthorityID, _ port.QueryScope) (port.QueriedAuthority, error) {
	return r.projection, nil
}
