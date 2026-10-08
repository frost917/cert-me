package service

import (
	"context"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func TestAuthorityServiceCreatesUsableRootAtFractionalClockTime(t *testing.T) {
	f := newAuthorityFixture(t)
	now := domain.NewInstant(time.Date(2026, 9, 11, 12, 0, 0, 250_000_000, time.UTC))
	f.svc.deps.Clock = fixedClock{now: now}

	root, err := f.svc.Create(context.Background(), authorityCreateMeta("abababab-abab-4bab-8bab-abababababab"), rootCreateCommand("Fractional Root"))
	if err != nil {
		t.Fatalf("create Root: %v", err)
	}
	root, err = f.svc.SetIssuanceState(context.Background(), authorityVersionMeta(root.Version), contract.AuthoritySetIssuanceStateCommand{
		AuthorityID: root.ID,
		State:       string(domain.IssuanceStateEnabled),
	})
	if err != nil {
		t.Fatalf("enable Root: %v", err)
	}

	intermediate, err := f.svc.Create(context.Background(), authorityCreateMeta("bcbcbcbc-bcbc-4cbc-8cbc-bcbcbcbcbcbc"), intermediateCreateCommand(root.ID, "Fractional Intermediate"))
	if err != nil {
		t.Fatalf("create Intermediate immediately after enabling Root: %v", err)
	}

	var rootAuthority, intermediateAuthority domain.Authority
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		rootAuthority, err = tx.PKI().GetIssuerForUpdate(context.Background(), root.ID)
		if err != nil {
			return err
		}
		intermediateAuthority, err = tx.PKI().GetIssuerForUpdate(context.Background(), intermediate.ID)
		return err
	}); err != nil {
		t.Fatalf("read created CA authorities: %v", err)
	}
	for name, authority := range map[string]domain.Authority{
		"Root":         rootAuthority,
		"Intermediate": intermediateAuthority,
	} {
		if authority.CertificateWindow().NotBefore().After(now) {
			t.Errorf("%s certificate is not valid at its creation time: not_before=%s now=%s", name,
				authority.CertificateWindow().NotBefore(), now)
		}
	}
}
