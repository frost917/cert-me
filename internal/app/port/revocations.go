package port

import (
	"context"

	"cert-me/internal/domain"
)

// RevocationRevision is the port-level projection of one
// revocation_revisions row: the append-only correction trail a Correct call
// must be paired with (docs/data-model.md "폐기 변경 시... 정정 근거를 감사
// 보존 기간과 무관하게 보존"). There is no domain object for it because it
// is a pure historical record with no transitions of its own -- once
// written it is never read back by domain logic, only by audit/query.
type RevocationRevision struct {
	RevocationID       domain.RevocationID
	RevisionNo         int
	PreviousValuesJSON []byte
	NewValuesJSON      []byte
	Justification      string
	ActorID            domain.AccountID // empty for a system/import-sourced correction
	SourceImportID     string           // empty unless the correction came from an import
}

// RevocationRepository is the storage boundary for the revocation ledger
// (docs/backend-implementation.md §4 table row "RevocationRepository";
// docs/data-model.md "폐기·CRL·기존 PKI 인수").
type RevocationRepository interface {
	// FindForUpdate locks and returns the revocation keyed by
	// (issuer, serial) -- the ledger's real key, independent of whether a
	// certificate row exists (docs/data-model.md "폐기의 기준 키는
	// issuer/serial이고 연결 여부가 효력에 영향을 주지 않는다"). It returns
	// ErrNotFound when no entry exists yet for this issuer/serial.
	FindForUpdate(ctx context.Context, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) (domain.Revocation, error)

	// Insert creates a brand-new revocation row (first assertion for this
	// issuer/serial).
	Insert(ctx context.Context, revocation domain.Revocation) error

	// Save persists revocation under the standard optimistic-lock contract
	// (see AccountRepository.SaveAccount). A single call may follow a
	// Merge and a StampChangeGeneration on the same object, so
	// revocation.Version() can already be expectedVersion+2; the store must
	// still only check WHERE version = expectedVersion and write whatever
	// final version the object carries.
	Save(ctx context.Context, revocation domain.Revocation, expectedVersion domain.Version) error

	// AppendRevision stores one correction-history row alongside a Correct
	// call, in the same commit.
	AppendRevision(ctx context.Context, revision RevocationRevision) error

	// ListByIssuer returns every revocation recorded under issuer, the CRL
	// generation snapshot input
	// (docs/backend-implementation.md §8 "CRL 생성" row: "폐기 snapshot").
	ListByIssuer(ctx context.Context, issuer domain.CAKeyGenerationID) ([]domain.Revocation, error)
}
