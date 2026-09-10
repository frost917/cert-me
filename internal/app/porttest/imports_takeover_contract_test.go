// This file is a black-box contract test for porttest.Store's import batch
// and CA takeover storage, and for the PKI compromise-marking/id-based read
// this round adds. Like pki_contract_test.go it only imports exported API
// from cert-me/internal/app/port and cert-me/internal/app/porttest -- the
// same surface a B04 ImportService in another package would use -- so it
// cannot paper over a gap by reaching into porttest's private state.
//
// docs/backend-implementation.md §13 closing paragraph: "계약 완결성 검토에는
// ... import batch/takeover 저장·조회, PKI의 키 유출 표시·ID 기반 조회도
// 포함한다." Every assertion below depending on a method this round adds
// must fail to even compile against the pre-fix code (there was no
// port.ImportRepository, no TxStores.Imports(), no
// PKIRepository.GetKeyMaterial/MarkCompromised) -- see the PR report for the
// captured "before" build failure.
package porttest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

const (
	importRequestedBy = domain.AccountID("c0000000-0000-0000-0000-000000000001")
	importBatchIDA    = domain.ImportBatchID("c0000000-0000-0000-0000-000000000002")
	importCertIDA     = domain.CertificateID("c0000000-0000-0000-0000-000000000003")

	takeoverCAGenID = domain.CAKeyGenerationID("c0000000-0000-0000-0000-000000000004")
	takeoverIDA     = domain.TakeoverID("c0000000-0000-0000-0000-000000000005")
	takeoverActorID = domain.AccountID("c0000000-0000-0000-0000-000000000006")
)

func mustFingerprint(t *testing.T, b byte) domain.Fingerprint {
	t.Helper()
	return domain.NewFingerprint([]byte{b, b, b})
}

func samplePublicManifest(t *testing.T) contract.PublicImportManifest {
	t.Helper()
	m, err := contract.NewPublicImportManifest([]contract.ImportManifestFileFacts{
		{
			FileID: "root.pem",
			Kind:   contract.ImportFileKindCertificate,
			SHA256: mustFingerprint(t, 0x10),
		},
	})
	if err != nil {
		t.Fatalf("NewPublicImportManifest: %v", err)
	}
	return m
}

// TestImportRepository_InsertGetBatch_RoundTripsManifest proves an import
// batch stored through TxStores.Imports() can be read back through
// TxStores.Imports() alone -- no reaching into porttest's internal map --
// with its server-reconstructed manifest intact.
func TestImportRepository_InsertGetBatch_RoundTripsManifest(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()
	manifest := samplePublicManifest(t)
	committedAt := domain.NewInstant(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))

	batch := port.ImportBatch{
		ID:          importBatchIDA,
		CreatedAt:   committedAt,
		RequestedBy: importRequestedBy,
		Manifest:    manifest,
		State:       port.ImportBatchStateCommitted,
		CommittedAt: committedAt,
		Result: contract.ImportResultView{
			ID:             string(importBatchIDA),
			State:          contract.ImportResultStateCommitted,
			CertificateIDs: []domain.CertificateID{importCertIDA},
		},
	}

	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.Imports().InsertBatch(ctx, batch)
	}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.Imports().GetBatch(ctx, importBatchIDA)
		if err != nil {
			return err
		}
		if got.State != port.ImportBatchStateCommitted {
			t.Fatalf("GetBatch state = %q, want committed", got.State)
		}
		if len(got.Manifest.Files) != 1 || got.Manifest.Files[0].FileID != "root.pem" {
			t.Fatalf("GetBatch manifest = %+v, want the stored root.pem file", got.Manifest)
		}
		if len(got.Result.CertificateIDs) != 1 || got.Result.CertificateIDs[0] != importCertIDA {
			t.Fatalf("GetBatch result certificate ids = %v, want [%q]", got.Result.CertificateIDs, importCertIDA)
		}
		return nil
	}); err != nil {
		t.Fatalf("GetBatch: %v", err)
	}

	// Unknown id must report ErrNotFound, not a zero-value batch.
	if err := store.Read(ctx, func(tx port.TxStores) error {
		_, err := tx.Imports().GetBatch(ctx, domain.ImportBatchID("c0000000-0000-0000-0000-0000000000ff"))
		if !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("GetBatch(unknown) err = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("GetBatch(unknown): %v", err)
	}
}

// TestImportRepository_InsertBatch_RollsBackOnCallbackError proves the new
// repository participates in the same copy-on-write rollback every other
// repository gets.
func TestImportRepository_InsertBatch_RollsBackOnCallbackError(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()
	sentinel := errors.New("callback failed")

	batch := port.ImportBatch{
		ID:          importBatchIDA,
		RequestedBy: importRequestedBy,
		Manifest:    samplePublicManifest(t),
		State:       port.ImportBatchStateFailed,
	}

	err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.Imports().InsertBatch(ctx, batch); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the callback's error", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		if _, err := tx.Imports().GetBatch(ctx, importBatchIDA); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("import batch survived rollback (err=%v)", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
}

// TestTakeoverRepository_InsertConfirm drives a takeover from pending to
// confirmed through TxStores.Imports() alone, exercising the
// GetPendingTakeoverForUpdate -> SaveTakeover optimistic-lock pair
// ConfirmTakeover needs.
func TestTakeoverRepository_InsertConfirm(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()

	evidence := contract.TakeoverEvidence{
		SchemaVersion:          1,
		IssuanceRecordsChecked: true,
		CRLRoutesChecked:       true,
	}

	pending := port.Takeover{
		ID:                   takeoverIDA,
		CAKeyGenerationID:    takeoverCAGenID,
		State:                contract.TakeoverStatePending,
		HistoryAssertion:     contract.TakeoverHistoryNoPreviousRevocations,
		PreviousMaxNumberHex: "1",
		Evidence:             evidence,
		Version:              1,
	}

	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.Imports().InsertTakeover(ctx, pending)
	}); err != nil {
		t.Fatalf("InsertTakeover: %v", err)
	}

	confirmedAt := domain.NewInstant(time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC))
	if err := store.Write(ctx, func(tx port.TxStores) error {
		locked, err := tx.Imports().GetPendingTakeoverForUpdate(ctx, takeoverCAGenID)
		if err != nil {
			return err
		}
		if locked.ID != takeoverIDA {
			t.Fatalf("GetPendingTakeoverForUpdate id = %q, want %q", locked.ID, takeoverIDA)
		}
		expectedVersion := locked.Version
		locked.State = contract.TakeoverStateConfirmed
		locked.ConfirmedBy = takeoverActorID
		locked.ConfirmedAt = confirmedAt
		locked.Version = expectedVersion + 1
		return tx.Imports().SaveTakeover(ctx, locked, expectedVersion)
	}); err != nil {
		t.Fatalf("confirm write: %v", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		if _, err := tx.Imports().GetPendingTakeoverForUpdate(ctx, takeoverCAGenID); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("GetPendingTakeoverForUpdate after confirm = %v, want ErrNotFound (no pending left)", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after confirm: %v", err)
	}

	// A stale expectedVersion must be rejected as a version conflict, not
	// silently accepted.
	if err := store.Write(ctx, func(tx port.TxStores) error {
		stale := pending
		stale.State = contract.TakeoverStateConfirmed
		return tx.Imports().SaveTakeover(ctx, stale, 1)
	}); !errors.Is(err, port.ErrVersionConflict) {
		t.Fatalf("SaveTakeover with stale version = %v, want ErrVersionConflict", err)
	}
}

// TestPKIRepository_MarkCompromised_FoundThroughCertificatesUsingKey drives
// U09's normal flow ("유출 공개키의 유효 인증서 모두 폐기",
// docs/backend-implementation.md §11) through TxStores alone: a key
// material looked up by id, marked compromised, and found again both by id
// and through the certificates that use it.
func TestPKIRepository_MarkCompromised_FoundThroughCertificatesUsingKey(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()
	keyMatID := domain.KeyMaterialID("c0000000-0000-0000-0000-000000000007")
	certID := domain.CertificateID("c0000000-0000-0000-0000-000000000008")

	if err := store.Write(ctx, func(tx port.TxStores) error {
		pki := tx.PKI()
		if err := pki.InsertKeyMaterial(ctx, port.KeyMaterial{
			ID:        keyMatID,
			PublicKey: publicKey(t, 0xAB),
			Origin:    "generated",
		}); err != nil {
			return err
		}
		w := window(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
		cert := newLeafCertificate(t, certID, 0xE1, keyMatID, "e1", w)
		return pki.InsertCertificate(ctx, cert)
	}); err != nil {
		t.Fatalf("setup write: %v", err)
	}

	// GetKeyMaterial must find it by id before compromise.
	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.PKI().GetKeyMaterial(ctx, keyMatID)
		if err != nil {
			return err
		}
		if !got.CompromisedAt.IsZero() {
			t.Fatalf("GetKeyMaterial before compromise: CompromisedAt = %v, want zero", got.CompromisedAt)
		}
		return nil
	}); err != nil {
		t.Fatalf("GetKeyMaterial before compromise: %v", err)
	}

	compromisedAt := domain.NewInstant(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.PKI().MarkCompromised(ctx, keyMatID, compromisedAt)
	}); err != nil {
		t.Fatalf("MarkCompromised: %v", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.PKI().GetKeyMaterial(ctx, keyMatID)
		if err != nil {
			return err
		}
		if !got.CompromisedAt.Equal(compromisedAt) {
			t.Fatalf("GetKeyMaterial after compromise: CompromisedAt = %v, want %v", got.CompromisedAt, compromisedAt)
		}

		certs, err := tx.PKI().ListCertificatesUsingKey(ctx, keyMatID)
		if err != nil {
			return err
		}
		if len(certs) != 1 || certs[0].ID() != certID {
			t.Fatalf("ListCertificatesUsingKey = %v, want exactly [%q]", certs, certID)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after compromise: %v", err)
	}

	// Unknown id must report ErrNotFound.
	if err := store.Read(ctx, func(tx port.TxStores) error {
		_, err := tx.PKI().GetKeyMaterial(ctx, domain.KeyMaterialID("c0000000-0000-0000-0000-0000000000fe"))
		if !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("GetKeyMaterial(unknown) = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("GetKeyMaterial(unknown): %v", err)
	}
}

// TestPKIRepository_MarkCompromised_RollsBackOnCallbackError proves
// MarkCompromised participates in the same rollback contract.
func TestPKIRepository_MarkCompromised_RollsBackOnCallbackError(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()
	keyMatID := domain.KeyMaterialID("c0000000-0000-0000-0000-000000000009")
	sentinel := errors.New("callback failed")

	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{
			ID:        keyMatID,
			PublicKey: publicKey(t, 0xAC),
			Origin:    "generated",
		})
	}); err != nil {
		t.Fatalf("setup write: %v", err)
	}

	err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.PKI().MarkCompromised(ctx, keyMatID, domain.NewInstant(time.Now())); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the callback's error", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.PKI().GetKeyMaterial(ctx, keyMatID)
		if err != nil {
			return err
		}
		if !got.CompromisedAt.IsZero() {
			t.Errorf("compromise mark survived rollback: CompromisedAt = %v, want zero", got.CompromisedAt)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
}

// A compromise cannot be walked back: a later report must not move
// compromised_at forward, because that would narrow the window in which
// certificates on this key are treated as untrustworthy.
func TestPKIRepository_MarkCompromisedKeepsTheEarliestReport(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()

	keyID := domain.KeyMaterialID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	pub, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("spki-bytes-for-compromise-test"))
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyID, PublicKey: pub, Origin: "generated"})
	}); err != nil {
		t.Fatalf("insert key material: %v", err)
	}

	early := domain.InstantFromUnixMicro(1_000_000_000)
	late := domain.InstantFromUnixMicro(2_000_000_000)

	// Report the later time first, then the earlier one: the earlier must win.
	for _, at := range []domain.Instant{late, early, late} {
		if err := store.Write(ctx, func(tx port.TxStores) error {
			return tx.PKI().MarkCompromised(ctx, keyID, at)
		}); err != nil {
			t.Fatalf("MarkCompromised(%v): %v", at, err)
		}
	}

	var got port.KeyMaterial
	if err := store.Read(ctx, func(tx port.TxStores) error {
		var readErr error
		got, readErr = tx.PKI().GetKeyMaterial(ctx, keyID)
		return readErr
	}); err != nil {
		t.Fatalf("GetKeyMaterial: %v", err)
	}
	if !got.CompromisedAt.Equal(early) {
		t.Fatalf("compromised_at is %v, want the earliest report %v", got.CompromisedAt, early)
	}
}

// sampleImportResult builds an ImportResultView exercising every mutable
// field the reviewer's [P2] finding names transitively: Items (each with a
// nested ExistingID pointer), CertificateIDs, AuthorityIDs, and the
// CommittedAt pointer.
func sampleImportResult(t *testing.T) contract.ImportResultView {
	t.Helper()
	committedAt := domain.NewInstant(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC))
	existing := importCertIDA
	return contract.ImportResultView{
		ID:          string(importBatchIDA),
		State:       contract.ImportResultStateCommitted,
		CommittedAt: &committedAt,
		Items: []contract.ImportItemView{
			{
				FileID:     "root.pem",
				SHA256:     mustFingerprint(t, 0x10),
				Kind:       contract.ImportFileKindCertificate,
				Status:     contract.ImportItemStatusDuplicate,
				ExistingID: &existing,
			},
		},
		CertificateIDs: []domain.CertificateID{importCertIDA},
		AuthorityIDs:   []domain.AuthorityID{domain.AuthorityID("c0000000-0000-0000-0000-0000000000aa")},
	}
}

// TestImportRepository_InsertBatch_MutatingCallerValueAfterInsertIsIsolated
// proves InsertBatch copies in: mutating the caller's batch (including its
// nested Manifest.Files, Result.Items[].ExistingID and Result.CommittedAt
// pointees) after Insert returns must not reach the stored row.
func TestImportRepository_InsertBatch_MutatingCallerValueAfterInsertIsIsolated(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()

	batch := port.ImportBatch{
		ID:          importBatchIDA,
		RequestedBy: importRequestedBy,
		Manifest:    samplePublicManifest(t),
		State:       port.ImportBatchStateCommitted,
		Result:      sampleImportResult(t),
	}

	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.Imports().InsertBatch(ctx, batch)
	}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	// Mutate every reachable slice/pointer on the caller's own copy.
	batch.Manifest.Files[0].FileID = "mutated.pem"
	*batch.Result.CommittedAt = domain.NewInstant(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	*batch.Result.Items[0].ExistingID = domain.CertificateID("c0000000-0000-0000-0000-0000000000ff")
	batch.Result.Items[0].FileID = "mutated-item"
	batch.Result.CertificateIDs[0] = domain.CertificateID("c0000000-0000-0000-0000-0000000000ff")
	batch.Result.AuthorityIDs[0] = domain.AuthorityID("c0000000-0000-0000-0000-0000000000ff")

	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.Imports().GetBatch(ctx, importBatchIDA)
		if err != nil {
			return err
		}
		if got.Manifest.Files[0].FileID != "root.pem" {
			t.Errorf("stored manifest file id = %q, want unaffected %q", got.Manifest.Files[0].FileID, "root.pem")
		}
		if got.Result.CommittedAt.Equal(domain.NewInstant(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))) {
			t.Errorf("stored CommittedAt was mutated through the caller's pointer")
		}
		if *got.Result.Items[0].ExistingID != importCertIDA {
			t.Errorf("stored ExistingID = %q, want unaffected %q", *got.Result.Items[0].ExistingID, importCertIDA)
		}
		if got.Result.Items[0].FileID != "root.pem" {
			t.Errorf("stored item file id = %q, want unaffected %q", got.Result.Items[0].FileID, "root.pem")
		}
		if got.Result.CertificateIDs[0] != importCertIDA {
			t.Errorf("stored certificate id = %q, want unaffected %q", got.Result.CertificateIDs[0], importCertIDA)
		}
		if got.Result.AuthorityIDs[0] != domain.AuthorityID("c0000000-0000-0000-0000-0000000000aa") {
			t.Errorf("stored authority id = %q, want unaffected", got.Result.AuthorityIDs[0])
		}
		return nil
	}); err != nil {
		t.Fatalf("read after mutation: %v", err)
	}
}

// TestImportRepository_GetBatch_MutatingReturnedValueIsIsolated proves
// GetBatch copies out: mutating a value returned by GetBatch must not
// change the stored row, whether the mutation happens through the direct
// slice/pointer fields or Result's nested ones.
func TestImportRepository_GetBatch_MutatingReturnedValueIsIsolated(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()

	batch := port.ImportBatch{
		ID:          importBatchIDA,
		RequestedBy: importRequestedBy,
		Manifest:    samplePublicManifest(t),
		State:       port.ImportBatchStateCommitted,
		Result:      sampleImportResult(t),
	}
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.Imports().InsertBatch(ctx, batch)
	}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.Imports().GetBatch(ctx, importBatchIDA)
		if err != nil {
			return err
		}
		got.Manifest.Files[0].FileID = "mutated.pem"
		*got.Result.CommittedAt = domain.NewInstant(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
		*got.Result.Items[0].ExistingID = domain.CertificateID("c0000000-0000-0000-0000-0000000000ff")
		got.Result.CertificateIDs[0] = domain.CertificateID("c0000000-0000-0000-0000-0000000000ff")
		got.Result.AuthorityIDs[0] = domain.AuthorityID("c0000000-0000-0000-0000-0000000000ff")
		return nil
	}); err != nil {
		t.Fatalf("read+mutate: %v", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.Imports().GetBatch(ctx, importBatchIDA)
		if err != nil {
			return err
		}
		if got.Manifest.Files[0].FileID != "root.pem" {
			t.Errorf("stored manifest file id = %q, want unaffected %q", got.Manifest.Files[0].FileID, "root.pem")
		}
		if got.Result.CommittedAt.Equal(domain.NewInstant(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))) {
			t.Errorf("stored CommittedAt was mutated through a previously-returned pointer")
		}
		if *got.Result.Items[0].ExistingID != importCertIDA {
			t.Errorf("stored ExistingID = %q, want unaffected %q", *got.Result.Items[0].ExistingID, importCertIDA)
		}
		if got.Result.CertificateIDs[0] != importCertIDA {
			t.Errorf("stored certificate id = %q, want unaffected %q", got.Result.CertificateIDs[0], importCertIDA)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify read: %v", err)
	}
}

// TestImportRepository_GetBatch_MutateThenRollbackLeavesStoredValueUnchanged
// reproduces the reviewer's exact scenario: commit a batch, then in a LATER
// Write call GetBatch, mutate Manifest.Files[0], and return an error so the
// callback rolls back. The originally stored value must be unchanged --
// this is B02's core rollback guarantee, and a shared slice/pointer would
// punch straight through it regardless of the rollback machinery itself.
func TestImportRepository_GetBatch_MutateThenRollbackLeavesStoredValueUnchanged(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()
	sentinel := errors.New("callback failed after mutating the fetched batch")

	batch := port.ImportBatch{
		ID:          importBatchIDA,
		RequestedBy: importRequestedBy,
		Manifest:    samplePublicManifest(t),
		State:       port.ImportBatchStateCommitted,
		Result:      sampleImportResult(t),
	}
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.Imports().InsertBatch(ctx, batch)
	}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	err := store.Write(ctx, func(tx port.TxStores) error {
		got, err := tx.Imports().GetBatch(ctx, importBatchIDA)
		if err != nil {
			return err
		}
		got.Manifest.Files[0].FileID = "mutated-during-rollback.pem"
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the callback's error", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.Imports().GetBatch(ctx, importBatchIDA)
		if err != nil {
			return err
		}
		if got.Manifest.Files[0].FileID != "root.pem" {
			t.Errorf("stored manifest file id = %q after rollback, want unaffected %q", got.Manifest.Files[0].FileID, "root.pem")
		}
		return nil
	}); err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
}

// TestTakeoverRepository_InsertTakeover_MutatingCallerValueAfterInsertIsIsolated
// proves InsertTakeover copies in Evidence.CRLSHA256Hex, the other slice
// field the reviewer named directly.
func TestTakeoverRepository_InsertTakeover_MutatingCallerValueAfterInsertIsIsolated(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()

	takeover := port.Takeover{
		ID:                   takeoverIDA,
		CAKeyGenerationID:    takeoverCAGenID,
		State:                contract.TakeoverStatePending,
		HistoryAssertion:     contract.TakeoverHistoryCRLsProvided,
		PreviousMaxNumberHex: "1",
		Evidence: contract.TakeoverEvidence{
			SchemaVersion:          1,
			CRLSHA256Hex:           []string{mustFingerprint(t, 0x20).Hex()},
			IssuanceRecordsChecked: true,
			CRLRoutesChecked:       true,
		},
		Version: 1,
	}

	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.Imports().InsertTakeover(ctx, takeover)
	}); err != nil {
		t.Fatalf("InsertTakeover: %v", err)
	}

	takeover.Evidence.CRLSHA256Hex[0] = "mutated"

	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.Imports().GetPendingTakeoverForUpdate(ctx, takeoverCAGenID)
		if err != nil {
			return err
		}
		if got.Evidence.CRLSHA256Hex[0] != mustFingerprint(t, 0x20).Hex() {
			t.Errorf("stored evidence crl_sha256[0] = %q, want unaffected", got.Evidence.CRLSHA256Hex[0])
		}
		return nil
	}); err != nil {
		t.Fatalf("read after mutation: %v", err)
	}
}

// TestTakeoverRepository_GetPendingTakeoverForUpdate_MutatingReturnedValueIsIsolated
// proves the read side copies out Evidence.CRLSHA256Hex too, and that
// SaveTakeover's own copy-in holds even across the pending->confirmed
// transition.
func TestTakeoverRepository_GetPendingTakeoverForUpdate_MutatingReturnedValueIsIsolated(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()

	takeover := port.Takeover{
		ID:                   takeoverIDA,
		CAKeyGenerationID:    takeoverCAGenID,
		State:                contract.TakeoverStatePending,
		HistoryAssertion:     contract.TakeoverHistoryCRLsProvided,
		PreviousMaxNumberHex: "1",
		Evidence: contract.TakeoverEvidence{
			SchemaVersion:          1,
			CRLSHA256Hex:           []string{mustFingerprint(t, 0x21).Hex()},
			IssuanceRecordsChecked: true,
			CRLRoutesChecked:       true,
		},
		Version: 1,
	}
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.Imports().InsertTakeover(ctx, takeover)
	}); err != nil {
		t.Fatalf("InsertTakeover: %v", err)
	}

	if err := store.Write(ctx, func(tx port.TxStores) error {
		locked, err := tx.Imports().GetPendingTakeoverForUpdate(ctx, takeoverCAGenID)
		if err != nil {
			return err
		}
		locked.Evidence.CRLSHA256Hex[0] = "mutated-in-place"
		return nil // deliberately does not Save -- proves the mutation never touched storage
	}); err != nil {
		t.Fatalf("read-mutate write: %v", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.Imports().GetPendingTakeoverForUpdate(ctx, takeoverCAGenID)
		if err != nil {
			return err
		}
		if got.Evidence.CRLSHA256Hex[0] != mustFingerprint(t, 0x21).Hex() {
			t.Errorf("stored evidence crl_sha256[0] = %q, want unaffected", got.Evidence.CRLSHA256Hex[0])
		}
		return nil
	}); err != nil {
		t.Fatalf("read after mutation: %v", err)
	}
}
