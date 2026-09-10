package port

import (
	"context"

	"cert-me/internal/domain"
)

// CRLDocument is the port-level projection of one crl_documents row: the
// signed, immutable CRL original (docs/data-model.md "폐기·CRL·기존 PKI
// 인수"). There is no domain object for it because the document itself is
// never transitioned once written -- CRLState is what carries the
// publication policy (monotonic number/generation) that governs whether a
// document may become the published one.
type CRLDocument struct {
	ID                domain.CRLDocumentID
	CAKeyGenerationID domain.CAKeyGenerationID
	NumberHex         domain.CRLNumber // zero for a generated-but-unpublished draft is not stored; every stored generated document carries a number
	DERSHA256         domain.Fingerprint
	DER               []byte
	ThisUpdate        domain.Instant
	NextUpdate        domain.Instant // zero for an imported document that did not carry one
	CoveredGeneration int64
	Origin            string // "generated" or "imported"
	SourceImportID    string // empty unless Origin == "imported"
}

// CRLRepository is the storage boundary for per-CA-key publication state and
// CRL document originals (docs/backend-implementation.md §4 table row
// "CRLRepository"; docs/data-model.md "폐기·CRL·기존 PKI 인수").
type CRLRepository interface {
	// GetStateForUpdate locks and returns the crl_states row for
	// caKeyGenerationID. Number reservation, generation bumps and
	// publication all require this lock, matching the shared serialization
	// point docs/data-model.md assigns this row
	// ("issuer의 crl_states 행을 직렬화 지점으로 사용"). If no row exists yet
	// for a CA key that has just been created, it returns ErrNotFound and
	// the caller creates one in the same transaction
	// (docs/data-model.md "아직 crl_states가 없는 CA는 동일 생성 트랜잭션에서
	// 먼저 만든다").
	GetStateForUpdate(ctx context.Context, caKeyGenerationID domain.CAKeyGenerationID) (domain.CRLState, error)

	// SaveState persists state under the standard optimistic-lock contract
	// (see AccountRepository.SaveAccount). It also serves as the insert path
	// for a CA key's first crl_states row: an implementation distinguishes
	// "first save" from "update" the same way SaveAuthority/SaveSeries would
	// for a row that always exists once its owning key generation does.
	SaveState(ctx context.Context, state domain.CRLState, expectedVersion domain.Version) error

	// InsertDocument stores a signed CRL original. crl_documents.der_sha256
	// is unique; a duplicate DER surfaces as a conflict error.
	InsertDocument(ctx context.Context, document CRLDocument) error

	// GetDocument returns one stored CRL document by id, for republishing a
	// document's bytes (e.g. serving the currently published CRL). It
	// returns ErrNotFound when no such document exists.
	GetDocument(ctx context.Context, id domain.CRLDocumentID) (CRLDocument, error)
}
