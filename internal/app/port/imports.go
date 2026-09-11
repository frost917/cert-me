package port

import (
	"context"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

// This file is the storage boundary §13's closing paragraph named as a gap:
// "계약 완결성 검토에는 ... import batch/takeover 저장·조회 ... 포함한다."
// ImportService.Preview/Commit/ConfirmTakeover had no repository at all to
// read/write through before this -- only a service test poking porttest's
// internal map could have exercised those flows, which §13's governing rule
// explicitly refuses to count as contract completeness.

// ImportBatchState mirrors import_batches.state
// (docs/data-model.md CHECK state IN ('previewed','committed','failed')).
type ImportBatchState string

const (
	ImportBatchStatePreviewed ImportBatchState = "previewed"
	ImportBatchStateCommitted ImportBatchState = "committed"
	ImportBatchStateFailed    ImportBatchState = "failed"
)

// ImportBatch is the port-level projection of one import_batches row
// (docs/data-model.md row: "requested_by FK, input_manifest_json, state,
// committed_at, result_json"). Manifest/Result are exactly the two
// server-reconstructed public types data-model.md line 211 names --
// "input_manifest_json은 API ImportManifest v1의 서버 재구성 결과만
// 저장한다. result_json은 ImportResult의 공개 결과 필드만 저장" -- so this
// type carries contract.PublicImportManifest/contract.ImportResultView,
// never contract.ImportMetadataInput/ImportUploadCommand or any passphrase
// (§12: "manifest는 파서가 만든 공개 Facts에서 생성하고 repository에 input
// command를 전달하지 않는다").
//
// import_batches has no version column (data-model.md's row lists none), so
// a batch is inserted already carrying its terminal outcome rather than
// updated in place -- the same reasoning PKIRepository.SaveLeafKeyGeneration
// documents for a stored entity data-model.md gives no version column to.
// The SQL CHECK constraint also allows a 'previewed' state, which this
// repository deliberately has no write path for. That was raised as an open
// question and the planning team ruled on it: "Import Preview는 batch를
// 영속화하지 않으며 write-once 결과 저장을 유지합니다. previewed enum 때문에
// 새 저장 흐름을 만들지 않습니다" (§13). Preview persists nothing, so there is
// no update-in-place path to add.
type ImportBatch struct {
	ID          domain.ImportBatchID
	CreatedAt   domain.Instant
	RequestedBy domain.AccountID
	Manifest    contract.PublicImportManifest
	State       ImportBatchState
	CommittedAt domain.Instant // zero when State != ImportBatchStateCommitted
	Result      contract.ImportResultView
}

// Takeover is the port-level projection of one ca_takeovers row
// (docs/data-model.md row: "ca_key_generation_id FK, state,
// history_assertion, previous_max_number_hex, external_issuer_stopped_at,
// confirmed_by FK nullable, confirmed_at, evidence_json"). Evidence is
// contract.TakeoverEvidence, the storage type §12 requires kept distinct
// from any input command -- see contract.TakeoverEvidence's own doc comment
// for why wire and storage shapes coincide for this one type.
//
// Unlike ImportBatch, ca_takeovers does have its own version column
// (data-model.md), so SaveTakeover below takes the standard
// expectedVersion, matching PKIRepository.SaveSeries/SaveAuthority.
type Takeover struct {
	ID                      domain.TakeoverID
	CAKeyGenerationID       domain.CAKeyGenerationID
	State                   contract.TakeoverState
	HistoryAssertion        contract.TakeoverHistoryAssertion
	PreviousMaxNumberHex    string
	ExternalIssuerStoppedAt domain.Instant
	ConfirmedBy             domain.AccountID // zero until State == TakeoverStateConfirmed
	ConfirmedAt             domain.Instant   // zero until State == TakeoverStateConfirmed
	Evidence                contract.TakeoverEvidence
	Version                 domain.Version
}

// ImportRepository is the storage boundary for import batches and CA
// takeovers.
type ImportRepository interface {
	// InsertBatch stores one completed import run: Commit's own decided
	// terminal state, the server-reconstructed manifest, and the public
	// result (docs/backend-implementation.md §8 "import" row: "단일 Write
	// 안에서 수행: ... 자료·폐기·인수·결과·작업·감사").
	InsertBatch(ctx context.Context, batch ImportBatch) error

	// GetBatch looks up an import batch by its own id -- the read
	// QueryService.GetImport needs (§13 item 5 lists ListImport/GetImport as
	// a distinct Action) and the read this contract's test proves a stored
	// manifest survives round-trip through. It returns ErrNotFound when id
	// is unknown.
	GetBatch(ctx context.Context, id domain.ImportBatchID) (ImportBatch, error)

	// InsertTakeover creates a new ca_takeovers row, normally pending
	// confirmation (docs/data-model.md "state=pending/confirmed. 기존 폐기
	// 없음·CRL 제공·과거 발급 자료 확인을 명시 기록").
	InsertTakeover(ctx context.Context, takeover Takeover) error

	// GetPendingTakeoverForUpdate locks and returns the pending takeover row
	// for caKeyGenerationID -- the read ConfirmTakeover needs before it
	// transitions pending -> confirmed (docs/storage/migrations index
	// "ix_ca_takeovers_1 ON ca_takeovers (ca_key_generation_id,state)" is
	// exactly this lookup). It returns ErrNotFound when there is no pending
	// takeover for this CA key generation.
	GetPendingTakeoverForUpdate(ctx context.Context, caKeyGenerationID domain.CAKeyGenerationID) (Takeover, error)

	// SaveTakeover persists takeover -- normally the pending -> confirmed
	// transition -- under the standard optimistic-lock contract (see
	// PKIRepository.SaveAuthority).
	SaveTakeover(ctx context.Context, takeover Takeover, expectedVersion domain.Version) error
}
