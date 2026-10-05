package service

import (
	"context"
	"testing"
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
