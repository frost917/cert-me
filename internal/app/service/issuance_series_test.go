package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

func seriesMutationMeta(t *testing.T, version domain.Version) contract.MutationMeta {
	t.Helper()
	return contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
}

func deliveryByID(t *testing.T, store *porttest.Store, id domain.DeliveryID) domain.Delivery {
	t.Helper()
	var delivery domain.Delivery
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		delivery, err = tx.Delivery().GetDeliveryForUpdate(context.Background(), id)
		return err
	}); err != nil {
		t.Fatalf("read delivery %s: %v", id, err)
	}
	return delivery
}

func TestIssuanceUpdateSeriesChangesOnlyMutablePolicyAndName(t *testing.T) {
	f := newIssuanceFixture(t)
	issued := issueReissueSource(t, f)
	before := currentSeriesSnapshot(t, f.store, issued.SeriesID)
	if issued.Delivery == nil {
		t.Fatal("initial issuance has no delivery")
	}
	deliveryBefore := deliveryByID(t, f.store, issued.Delivery.ID)
	certificateBefore := readCertificateForSeriesTest(t, f.store, issued.CertificateID)
	name := "renamed service"
	validity := contract.ValidityInput{Value: 18, Unit: string(domain.ValidityUnitMonths)}
	rotateEvery := 7
	cmd := contract.IssuanceUpdateSeriesCommand{
		SeriesID: issued.SeriesID, Name: &name, Validity: &validity, RotateEvery: &rotateEvery,
	}

	view, err := f.svc.UpdateSeries(context.Background(), seriesMutationMeta(t, before.Series.Version()), cmd)
	if err != nil {
		t.Fatalf("UpdateSeries: %v", err)
	}
	if view.Name != name || view.Validity.Value() != validity.Value || view.Validity.Unit() != domain.ValidityUnit(validity.Unit) || view.RotateEvery != rotateEvery {
		t.Fatalf("updated series view = %+v, want requested policy/name", view)
	}
	if view.Version != before.Series.Version().Next() || view.CurrentCertificateID == nil || *view.CurrentCertificateID != issued.CertificateID ||
		view.CurrentKeyGenerationID == nil || *view.CurrentKeyGenerationID != before.CurrentKeyGeneration.ID() || view.RenewalCount != 0 {
		t.Fatalf("updated series view = %+v, history/version/count were not preserved correctly", view)
	}
	after := currentSeriesSnapshot(t, f.store, issued.SeriesID)
	if after.Series.Name() != name || after.Series.CurrentCertificateID() != issued.CertificateID ||
		after.CurrentKeyGeneration.ID() != before.CurrentKeyGeneration.ID() || after.CurrentKeyGeneration.RenewalCount() != before.CurrentKeyGeneration.RenewalCount() {
		t.Fatal("UpdateSeries changed current certificate, key generation, or renewal count")
	}
	certificateAfter := readCertificateForSeriesTest(t, f.store, issued.CertificateID)
	if !certificateAfter.Validity().NotAfter().Equal(certificateBefore.Validity().NotAfter()) {
		t.Fatal("UpdateSeries changed an already-issued certificate's validity")
	}
	deliveryAfter := deliveryByID(t, f.store, issued.Delivery.ID)
	if deliveryAfter.ID() != deliveryBefore.ID() || !deliveryAfter.ExpiresAt().Equal(deliveryBefore.ExpiresAt()) || deliveryAfter.State() != deliveryBefore.State() {
		t.Fatal("UpdateSeries changed the current delivery or its expiration")
	}
}

func TestIssuanceUpdateSeriesRejectsEmptyStaleAndUnauthorizedMutations(t *testing.T) {
	f := newIssuanceFixture(t)
	issued := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, issued.SeriesID)
	name := "first update"
	if _, err := f.svc.UpdateSeries(context.Background(), seriesMutationMeta(t, snapshot.Series.Version()), contract.IssuanceUpdateSeriesCommand{
		SeriesID: issued.SeriesID, Name: &name,
	}); err != nil {
		t.Fatalf("first UpdateSeries: %v", err)
	}

	staleName := "stale update"
	_, err := f.svc.UpdateSeries(context.Background(), seriesMutationMeta(t, snapshot.Series.Version()), contract.IssuanceUpdateSeriesCommand{
		SeriesID: issued.SeriesID, Name: &staleName,
	})
	assertIssuanceConflict(t, err, "stale series version")
	if _, err := f.svc.UpdateSeries(context.Background(), seriesMutationMeta(t, snapshot.Series.Version().Next()), contract.IssuanceUpdateSeriesCommand{SeriesID: issued.SeriesID}); err == nil {
		t.Fatal("UpdateSeries accepted an empty patch")
	}

	forbiddenPrincipal, err := contract.NewAdminPrincipal(contract.AdminPrincipalFacts{
		AccountID: issuanceTestAdminAccountID, SessionID: domain.SessionID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), AuthEpoch: 1,
	})
	if err != nil {
		t.Fatalf("other admin principal: %v", err)
	}
	f.authorizer.allow = false
	forbidden := contract.MutationMeta{
		RequestMeta: contract.RequestMeta{Principal: forbiddenPrincipal}, ExpectedVersion: contract.WithExpectedVersion(snapshot.Series.Version().Next()),
	}
	_, err = f.svc.UpdateSeries(context.Background(), forbidden, contract.IssuanceUpdateSeriesCommand{SeriesID: issued.SeriesID, Name: &staleName})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("unauthorized UpdateSeries error = %v, want forbidden", err)
	}
}

func TestIssuanceArchiveSeriesPreservesCertificatesDeliveryAndRevocations(t *testing.T) {
	f := newIssuanceFixture(t)
	issued := issueReissueSource(t, f)
	if issued.Delivery == nil {
		t.Fatal("initial issuance has no delivery")
	}
	before := currentSeriesSnapshot(t, f.store, issued.SeriesID)
	deliveryBefore := deliveryByID(t, f.store, issued.Delivery.ID)
	certificateBefore := readCertificateForSeriesTest(t, f.store, issued.CertificateID)
	issuerID := certificateBefore.IssuerCAKeyGenerationID()
	seedCRLState(t, f.store, issuerID)
	if err := f.store.Write(context.Background(), func(tx port.TxStores) error {
		_, err := applyRevocations(context.Background(), tx, []RevocationChange{{
			IssuerID: issuerID, Serial: certificateBefore.Serial(), CertificateID: certificateBefore.ID(),
			RevokedAt: testNow(), Reason: domain.RevocationReasonCessationOfOperation,
			Source: domain.RevocationSourceManual, AuthorityID: f.authorityID,
		}}, RevocationMeta{
			Request: contract.RequestMeta{Principal: issuanceAdminPrincipal(t)}, ActorKind: contract.AuditActorAccount,
			ActorID: string(issuanceTestAdminAccountID), Action: "test.archive.preserve_history", Now: testNow(), IDs: f.ids,
		})
		return err
	}); err != nil {
		t.Fatalf("seed historical revocation: %v", err)
	}

	archived, err := f.svc.ArchiveSeries(context.Background(), seriesMutationMeta(t, before.Series.Version()), contract.IssuanceArchiveSeriesCommand{SeriesID: issued.SeriesID})
	if err != nil {
		t.Fatalf("ArchiveSeries: %v", err)
	}
	if archived.ArchivedAt == nil || !archived.ArchivedAt.Equal(f.svc.deps.Clock.Now()) || archived.Version != before.Series.Version().Next() {
		t.Fatalf("archive view = %+v, want archive time and bumped version", archived)
	}
	after := currentSeriesSnapshot(t, f.store, issued.SeriesID)
	if !after.Series.IsArchived() || !after.Series.ArchivedAt().Equal(*archived.ArchivedAt) ||
		after.Series.CurrentCertificateID() != issued.CertificateID || after.CurrentKeyGeneration.ID() != before.CurrentKeyGeneration.ID() ||
		after.CurrentKeyGeneration.RenewalCount() != before.CurrentKeyGeneration.RenewalCount() {
		t.Fatal("ArchiveSeries did not preserve historical/current certificate and key-generation metadata")
	}
	if got := deliveryByID(t, f.store, issued.Delivery.ID); got.State() != deliveryBefore.State() || !got.ExpiresAt().Equal(deliveryBefore.ExpiresAt()) {
		t.Fatal("ArchiveSeries changed delivery state or expiration")
	}
	if got := readCertificateForSeriesTest(t, f.store, issued.CertificateID); !got.Validity().NotAfter().Equal(certificateBefore.Validity().NotAfter()) {
		t.Fatal("ArchiveSeries changed the immutable certificate")
	}
	assertReissueRevocation(t, f.store, issued.CertificateID, domain.RevocationReasonCessationOfOperation)

	_, err = f.svc.ArchiveSeries(context.Background(), seriesMutationMeta(t, archived.Version), contract.IssuanceArchiveSeriesCommand{SeriesID: issued.SeriesID})
	assertIssuanceConflict(t, err, "already archived series")
}

func TestIssuanceUpdateSeriesConcurrentWritersUseVersionCheck(t *testing.T) {
	f := newIssuanceFixture(t)
	issued := issueReissueSource(t, f)
	snapshot := currentSeriesSnapshot(t, f.store, issued.SeriesID)
	start := make(chan struct{})
	views := make([]contract.LeafSeriesView, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, newName := range []string{"concurrent-a", "concurrent-b"} {
		wg.Add(1)
		go func(i int, newName string) {
			defer wg.Done()
			<-start
			views[i], errs[i] = f.svc.UpdateSeries(context.Background(), seriesMutationMeta(t, snapshot.Series.Version()), contract.IssuanceUpdateSeriesCommand{
				SeriesID: issued.SeriesID, Name: &newName,
			})
		}(i, newName)
	}
	close(start)
	wg.Wait()
	successes, conflicts := 0, 0
	for _, err := range errs {
		if err == nil {
			successes++
			continue
		}
		var appErr *contract.AppError
		if errors.As(err, &appErr) && appErr.Kind() == contract.ErrorKindConflict {
			conflicts++
			continue
		}
		t.Fatalf("UpdateSeries concurrent error = %v, want conflict", err)
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent UpdateSeries successes=%d conflicts=%d, want one each (views %v)", successes, conflicts, views)
	}
}

func assertIssuanceConflict(t *testing.T, err error, label string) {
	t.Helper()
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("%s error = %v, want conflict", label, err)
	}
}

func readCertificateForSeriesTest(t *testing.T, store *porttest.Store, id domain.CertificateID) domain.Certificate {
	t.Helper()
	var cert domain.Certificate
	if err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		cert, err = tx.PKI().GetCertificate(context.Background(), id)
		return err
	}); err != nil {
		t.Fatalf("read certificate %s: %v", id, err)
	}
	return cert
}
