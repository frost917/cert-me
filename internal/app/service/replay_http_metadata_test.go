package service

import (
	"context"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
)

// These assertions concern transport metadata only; stored result replay must
// still recheck current authorization and never persist this transient bit.
func TestAuthorityReplaySignalsHTTPStatus(t *testing.T) {
	f := newAuthorityFixture(t)
	meta := authorityCreateMeta("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	command := rootCreateCommand("Replay Root")
	first, err := f.svc.Create(context.Background(), meta, command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.svc.Create(context.Background(), meta, command)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replayed || !second.Replayed {
		t.Fatal("only the existing result must carry replay response metadata")
	}
}

func TestIssueReplaySignalsHTTPStatus(t *testing.T) {
	f := newIssuanceFixture(t)
	meta := issueMutationMeta(t, issuanceTestIdempotencyKey)
	command := issueCommand(f.authorityID, "Replay Leaf")
	first, err := f.svc.Issue(context.Background(), meta, command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.svc.Issue(context.Background(), meta, command)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replayed || !second.Replayed {
		t.Fatal("only the existing result must carry replay response metadata")
	}
}

func TestRenewCommitReplaySignalsHTTPStatus(t *testing.T) {
	f := newIssuanceFixture(t)
	seriesID, certificateID, version := issueThenDeliver(t, f)
	meta := contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: issuanceAdminPrincipal(t)},
		IdempotencyKey:  "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
	command := renewCommand(seriesID, certificateID)
	first, err := f.svc.Renew(context.Background(), meta, command)
	if err != nil {
		t.Fatalf("first renew: %v", err)
	}
	if first.Replayed {
		t.Fatal("first renewal must not carry replay response metadata")
	}

	// Renew's public method normally finds this result in its read-only probe.
	// Call the commit path directly to cover the race where another request
	// commits after that probe but before this transaction obtains its lock.
	inputHash, err := InputHash(issuanceOperationRenew,
		map[string]string{"series_id": NormalizeUUID(string(command.SeriesID))},
		renewHashInput{SourceCertificateID: NormalizeUUID(string(command.SourceCertificateID))})
	if err != nil {
		t.Fatalf("renew input hash: %v", err)
	}
	requestKey, err := RequestKey(meta, issuanceOperationRenew)
	if err != nil {
		t.Fatalf("renew request key: %v", err)
	}
	var replay contract.IssuanceView
	err = f.store.Write(context.Background(), func(tx port.TxStores) error {
		return f.svc.commitRenew(context.Background(), tx, meta, command, requestKey,
			inputHash, version, renewPrepared{}, &replay)
	})
	if err != nil {
		t.Fatalf("commit-time renewal replay: %v", err)
	}
	if !replay.Replayed || replay.CertificateID != first.CertificateID {
		t.Fatalf("commit-time replay = %+v, want existing certificate %s and replay metadata", replay, first.CertificateID)
	}
}
