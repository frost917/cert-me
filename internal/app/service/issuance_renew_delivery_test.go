package service

import (
	"context"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func TestRenewPendingDeliveryReturnsConflictWithoutSigning(t *testing.T) {
	f := newIssuanceFixture(t)
	issued, err := f.svc.Issue(context.Background(), issueMutationMeta(t, issuanceTestIdempotencyKey), issueCommand(f.authorityID, "pending-delivery"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var version domain.Version
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(context.Background(), issued.SeriesID)
		if err != nil {
			return err
		}
		version = snapshot.Series.Version()
		return nil
	}); err != nil {
		t.Fatalf("read series version: %v", err)
	}

	signerCalls, keyGenerations := f.signer.calls, f.keyEngine.generateCalls
	meta := contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
		IdempotencyKey:  "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
	_, err = f.svc.Renew(context.Background(), meta, renewCommand(issued.SeriesID, issued.CertificateID))
	if err == nil {
		t.Fatal("renewing before private-key delivery completed succeeded")
	}
	appErr, ok := contract.AsAppError(err)
	if !ok {
		t.Fatalf("renew error = %T %v, want AppError", err, err)
	}
	if appErr.Kind() != contract.ErrorKindConflict || appErr.Code() != "delivery_not_available" {
		t.Fatalf("renew error = %s/%s, want conflict/delivery_not_available", appErr.Kind(), appErr.Code())
	}
	if f.signer.calls != signerCalls || f.keyEngine.generateCalls != keyGenerations {
		t.Fatalf("renew attempted signing/key generation: signer calls %d->%d, key generations %d->%d",
			signerCalls, f.signer.calls, keyGenerations, f.keyEngine.generateCalls)
	}
}
