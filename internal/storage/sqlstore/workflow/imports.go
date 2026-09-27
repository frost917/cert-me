package workflow

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// ImportRepository implements port.ImportRepository on the caller's unit of
// work. JSON columns use explicit, versioned public DTOs instead of
// serializing request commands or relying on Go field names.
type ImportRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

// NewImportRepository constructs an import repository bound to executor.
func NewImportRepository(executor core.SQLExecutor, d dialect.Dialect) (*ImportRepository, error) {
	validated, err := validate(executor, d)
	if err != nil {
		return nil, err
	}
	return &ImportRepository{executor: executor, dialect: validated}, nil
}

var _ port.ImportRepository = (*ImportRepository)(nil)

func (r *ImportRepository) InsertBatch(ctx context.Context, batch port.ImportBatch) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := domain.ParseImportBatchID(string(batch.ID)); err != nil {
		return fmt.Errorf("sqlstore workflow: validate import batch: %w", err)
	}
	if _, err := domain.ParseAccountID(string(batch.RequestedBy)); err != nil {
		return fmt.Errorf("sqlstore workflow: validate import batch: %w", err)
	}
	switch batch.State {
	case port.ImportBatchStateCommitted, port.ImportBatchStateFailed:
	default:
		return fmt.Errorf("sqlstore workflow: unsupported import batch state %q", batch.State)
	}
	manifestJSON, err := encodeManifest(batch.Manifest)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: encode import manifest: %w", err)
	}
	resultJSON, err := encodeImportResult(batch.Result)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: encode import result: %w", err)
	}
	if len(resultJSON) != 0 {
		if batch.Result.ID != string(batch.ID) {
			return errors.New("sqlstore workflow: import result id does not match its batch")
		}
		wantState := contract.ImportResultStateFailed
		if batch.State == port.ImportBatchStateCommitted {
			wantState = contract.ImportResultStateCommitted
		}
		if batch.Result.State != wantState {
			return errors.New("sqlstore workflow: import result state does not match its batch")
		}
	}

	b := r.dialect.NewBuilder()
	query := "INSERT INTO import_batches (id, created_at, requested_by, input_manifest_json, state, committed_at, result_json) VALUES (" +
		b.Add(string(batch.ID)) + ", " + b.Add(batch.CreatedAt.UnixMicro()) + ", " + b.Add(string(batch.RequestedBy)) + ", " +
		b.Add(string(manifestJSON)) + ", " + b.Add(string(batch.State)) + ", " + optionalInstant(batch.CommittedAt, b) + ", " + optionalString(string(resultJSON), b) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return insertError("insert import batch", err)
	}
	return nil
}

func (r *ImportRepository) GetBatch(ctx context.Context, id domain.ImportBatchID) (port.ImportBatch, error) {
	if err := checkContext(ctx); err != nil {
		return port.ImportBatch{}, err
	}
	if _, err := domain.ParseImportBatchID(string(id)); err != nil {
		return port.ImportBatch{}, fmt.Errorf("sqlstore workflow: validate import batch id: %w", err)
	}
	b := r.dialect.NewBuilder()
	query := "SELECT id, created_at, requested_by, input_manifest_json, state, committed_at, result_json FROM import_batches WHERE id = " + b.Add(string(id))
	var rawID, requestedBy, manifestJSON, state string
	var createdAt int64
	var committedAt sql.NullInt64
	var rawResult sql.NullString
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&rawID, &createdAt, &requestedBy, &manifestJSON, &state, &committedAt, &rawResult); err != nil {
		return port.ImportBatch{}, fmt.Errorf("sqlstore workflow: get import batch: %w", missing(err))
	}
	batchID, err := domain.ParseImportBatchID(rawID)
	if err != nil {
		return port.ImportBatch{}, fmt.Errorf("sqlstore workflow: decode import batch: %w", err)
	}
	accountID, err := domain.ParseAccountID(requestedBy)
	if err != nil {
		return port.ImportBatch{}, fmt.Errorf("sqlstore workflow: decode import batch: %w", err)
	}
	manifest, err := decodeManifest([]byte(manifestJSON))
	if err != nil {
		return port.ImportBatch{}, fmt.Errorf("sqlstore workflow: decode import batch manifest: %w", err)
	}
	batchState := port.ImportBatchState(state)
	if batchState != port.ImportBatchStateCommitted && batchState != port.ImportBatchStateFailed {
		return port.ImportBatch{}, fmt.Errorf("sqlstore workflow: invalid stored import batch state %q", state)
	}
	batch := port.ImportBatch{
		ID:          batchID,
		CreatedAt:   domain.InstantFromUnixMicro(createdAt),
		RequestedBy: accountID,
		Manifest:    manifest,
		State:       batchState,
	}
	if committedAt.Valid {
		batch.CommittedAt = domain.InstantFromUnixMicro(committedAt.Int64)
	}
	if rawResult.Valid {
		batch.Result, err = decodeImportResult([]byte(rawResult.String))
		if err != nil {
			return port.ImportBatch{}, fmt.Errorf("sqlstore workflow: decode import batch result: %w", err)
		}
		if batch.Result.ID != string(batch.ID) {
			return port.ImportBatch{}, errors.New("sqlstore workflow: stored import result id does not match its batch")
		}
		wantState := contract.ImportResultStateFailed
		if batch.State == port.ImportBatchStateCommitted {
			wantState = contract.ImportResultStateCommitted
		}
		if batch.Result.State != wantState {
			return port.ImportBatch{}, errors.New("sqlstore workflow: stored import result state does not match its batch")
		}
	}
	return batch, nil
}

func (r *ImportRepository) InsertTakeover(ctx context.Context, takeover port.Takeover) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateTakeover(takeover); err != nil {
		return fmt.Errorf("sqlstore workflow: validate takeover: %w", err)
	}
	evidence, err := encodeEvidence(takeover.Evidence)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: encode takeover evidence: %w", err)
	}
	now := nowUnixMicro()
	b := r.dialect.NewBuilder()
	query := "INSERT INTO ca_takeovers (id, created_at, updated_at, version, ca_key_generation_id, state, history_assertion, previous_max_number_hex, external_issuer_stopped_at, confirmed_by, confirmed_at, evidence_json) VALUES (" +
		b.Add(string(takeover.ID)) + ", " + b.Add(now) + ", " + b.Add(now) + ", " + b.Add(int64(takeover.Version)) + ", " +
		b.Add(string(takeover.CAKeyGenerationID)) + ", " + b.Add(string(takeover.State)) + ", " + b.Add(string(takeover.HistoryAssertion)) + ", " +
		optionalString(takeover.PreviousMaxNumberHex, b) + ", " + optionalInstant(takeover.ExternalIssuerStoppedAt, b) + ", " +
		optionalString(string(takeover.ConfirmedBy), b) + ", " + optionalInstant(takeover.ConfirmedAt, b) + ", " + b.Add(string(evidence)) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return insertError("insert takeover", err)
	}
	return nil
}

func (r *ImportRepository) GetPendingTakeoverForUpdate(ctx context.Context, caKeyGenerationID domain.CAKeyGenerationID) (port.Takeover, error) {
	if err := checkContext(ctx); err != nil {
		return port.Takeover{}, err
	}
	if _, err := domain.ParseCAKeyGenerationID(string(caKeyGenerationID)); err != nil {
		return port.Takeover{}, fmt.Errorf("sqlstore workflow: validate takeover key generation id: %w", err)
	}
	b := r.dialect.NewBuilder()
	query := "SELECT id, ca_key_generation_id, state, history_assertion, previous_max_number_hex, external_issuer_stopped_at, confirmed_by, confirmed_at, evidence_json, version FROM ca_takeovers WHERE ca_key_generation_id = " +
		b.Add(string(caKeyGenerationID)) + " AND state = 'pending' ORDER BY created_at, id LIMIT 1" + r.dialect.RowLockClause()
	takeover, err := scanTakeover(r.executor.QueryRowContext(ctx, query, b.Args()...))
	if err != nil {
		return port.Takeover{}, fmt.Errorf("sqlstore workflow: get pending takeover for update: %w", missing(err))
	}
	return takeover, nil
}

func (r *ImportRepository) SaveTakeover(ctx context.Context, takeover port.Takeover, expectedVersion domain.Version) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := domain.ParseVersion(int64(expectedVersion)); err != nil {
		return fmt.Errorf("sqlstore workflow: validate expected takeover version: %w", err)
	}
	if err := validateTakeover(takeover); err != nil {
		return fmt.Errorf("sqlstore workflow: validate takeover: %w", err)
	}
	evidence, err := encodeEvidence(takeover.Evidence)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: encode takeover evidence: %w", err)
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE ca_takeovers SET updated_at = " + b.Add(nowUnixMicro()) + ", version = " + b.Add(int64(takeover.Version)) +
		", ca_key_generation_id = " + b.Add(string(takeover.CAKeyGenerationID)) + ", state = " + b.Add(string(takeover.State)) +
		", history_assertion = " + b.Add(string(takeover.HistoryAssertion)) + ", previous_max_number_hex = " + optionalString(takeover.PreviousMaxNumberHex, b) +
		", external_issuer_stopped_at = " + optionalInstant(takeover.ExternalIssuerStoppedAt, b) + ", confirmed_by = " + optionalString(string(takeover.ConfirmedBy), b) +
		", confirmed_at = " + optionalInstant(takeover.ConfirmedAt, b) + ", evidence_json = " + b.Add(string(evidence)) +
		" WHERE id = " + b.Add(string(takeover.ID)) + " AND version = " + b.Add(int64(expectedVersion))
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: save takeover: %w", err)
	}
	affected, err := rowsAffected(result, nil)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: inspect takeover save: %w", err)
	}
	if affected != 0 {
		return nil
	}
	return r.checkTakeoverVersion(ctx, takeover.ID, expectedVersion)
}

func (r *ImportRepository) checkTakeoverVersion(ctx context.Context, id domain.TakeoverID, expectedVersion domain.Version) error {
	b := r.dialect.NewBuilder()
	query := "SELECT version FROM ca_takeovers WHERE id = " + b.Add(string(id))
	var stored int64
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&stored); err != nil {
		return fmt.Errorf("sqlstore workflow: inspect takeover version: %w", missing(err))
	}
	if stored != int64(expectedVersion) {
		return port.ErrVersionConflict
	}
	// A matched no-op UPDATE may report zero affected rows on MySQL-family
	// drivers. The expected version still matched, so the save succeeded.
	return nil
}

func validateTakeover(t port.Takeover) error {
	if _, err := domain.ParseTakeoverID(string(t.ID)); err != nil {
		return err
	}
	if _, err := domain.ParseCAKeyGenerationID(string(t.CAKeyGenerationID)); err != nil {
		return err
	}
	if _, err := domain.ParseVersion(int64(t.Version)); err != nil {
		return err
	}
	switch t.State {
	case contract.TakeoverStatePending:
		if t.ConfirmedBy != "" || !t.ConfirmedAt.IsZero() {
			return errors.New("pending takeover cannot have confirmation facts")
		}
	case contract.TakeoverStateConfirmed:
		if _, err := domain.ParseAccountID(string(t.ConfirmedBy)); err != nil {
			return errors.New("confirmed takeover requires a valid confirming account")
		}
		if t.ConfirmedAt.IsZero() {
			return errors.New("confirmed takeover requires confirmed_at")
		}
	default:
		return fmt.Errorf("unsupported takeover state %q", t.State)
	}
	if err := t.HistoryAssertion.Validate(); err != nil {
		return err
	}
	if t.PreviousMaxNumberHex != "" {
		if _, err := domain.ParseCRLNumber(t.PreviousMaxNumberHex); err != nil {
			return err
		}
	}
	if err := t.Evidence.Validate(); err != nil {
		return err
	}
	return nil
}

func scanTakeover(row rowScanner) (port.Takeover, error) {
	var id, generationID, state, assertion, evidenceJSON string
	var previousMax sql.NullString
	var issuerStopped, confirmedAt sql.NullInt64
	var confirmedBy sql.NullString
	var version int64
	if err := row.Scan(&id, &generationID, &state, &assertion, &previousMax, &issuerStopped, &confirmedBy, &confirmedAt, &evidenceJSON, &version); err != nil {
		return port.Takeover{}, err
	}
	parsedID, err := domain.ParseTakeoverID(id)
	if err != nil {
		return port.Takeover{}, fmt.Errorf("invalid stored takeover id: %w", err)
	}
	parsedGenerationID, err := domain.ParseCAKeyGenerationID(generationID)
	if err != nil {
		return port.Takeover{}, fmt.Errorf("invalid stored takeover key generation id: %w", err)
	}
	parsedVersion, err := domain.ParseVersion(version)
	if err != nil {
		return port.Takeover{}, fmt.Errorf("invalid stored takeover version: %w", err)
	}
	evidence, err := decodeEvidence([]byte(evidenceJSON))
	if err != nil {
		return port.Takeover{}, fmt.Errorf("invalid stored takeover evidence: %w", err)
	}
	takeover := port.Takeover{
		ID:                parsedID,
		CAKeyGenerationID: parsedGenerationID,
		State:             contract.TakeoverState(state),
		HistoryAssertion:  contract.TakeoverHistoryAssertion(assertion),
		Evidence:          evidence,
		Version:           parsedVersion,
	}
	if previousMax.Valid {
		takeover.PreviousMaxNumberHex = previousMax.String
	}
	if issuerStopped.Valid {
		takeover.ExternalIssuerStoppedAt = domain.InstantFromUnixMicro(issuerStopped.Int64)
	}
	if confirmedBy.Valid {
		takeover.ConfirmedBy, err = domain.ParseAccountID(confirmedBy.String)
		if err != nil {
			return port.Takeover{}, fmt.Errorf("invalid stored takeover actor: %w", err)
		}
	}
	if confirmedAt.Valid {
		takeover.ConfirmedAt = domain.InstantFromUnixMicro(confirmedAt.Int64)
	}
	if err := validateTakeover(takeover); err != nil {
		return port.Takeover{}, fmt.Errorf("invalid stored takeover: %w", err)
	}
	return takeover, nil
}

type manifestJSON struct {
	SchemaVersion int                `json:"schema_version"`
	Files         []manifestFileJSON `json:"files"`
}

type manifestFileJSON struct {
	FileID              string                  `json:"file_id"`
	Kind                contract.ImportFileKind `json:"kind"`
	SHA256              string                  `json:"sha256"`
	IssuerCertificateID string                  `json:"issuer_certificate_id,omitempty"`
}

func encodeManifest(manifest contract.PublicImportManifest) ([]byte, error) {
	if manifest.SchemaVersion != 1 || len(manifest.Files) == 0 || len(manifest.Files) > 100 {
		return nil, errors.New("manifest must be ImportManifest schema version 1 with 1..100 files")
	}
	out := manifestJSON{SchemaVersion: manifest.SchemaVersion, Files: make([]manifestFileJSON, len(manifest.Files))}
	seen := make(map[string]struct{}, len(manifest.Files))
	for i, file := range manifest.Files {
		if file.FileID == "" || len(file.FileID) > 128 {
			return nil, fmt.Errorf("manifest file %d has an invalid file_id", i)
		}
		if _, exists := seen[file.FileID]; exists {
			return nil, fmt.Errorf("manifest file_id %q is duplicated", file.FileID)
		}
		seen[file.FileID] = struct{}{}
		if err := file.Kind.Validate(); err != nil {
			return nil, fmt.Errorf("manifest file %d: %w", i, err)
		}
		fingerprint, err := domain.ParseFingerprint(file.SHA256.Hex())
		if err != nil || fingerprint.IsZero() {
			return nil, fmt.Errorf("manifest file %d has an invalid sha256", i)
		}
		issuer := ""
		if file.IssuerCertificateID != "" {
			parsed, err := domain.ParseCertificateID(string(file.IssuerCertificateID))
			if err != nil {
				return nil, fmt.Errorf("manifest file %d has an invalid issuer certificate id: %w", i, err)
			}
			issuer = string(parsed)
		}
		out.Files[i] = manifestFileJSON{FileID: file.FileID, Kind: file.Kind, SHA256: fingerprint.Hex(), IssuerCertificateID: issuer}
	}
	return json.Marshal(out)
}

func decodeManifest(data []byte) (contract.PublicImportManifest, error) {
	var stored manifestJSON
	if err := decodeStrict(data, &stored); err != nil {
		return contract.PublicImportManifest{}, err
	}
	files := make([]contract.ImportManifestFileFacts, len(stored.Files))
	for i, file := range stored.Files {
		fingerprint, err := domain.ParseFingerprint(file.SHA256)
		if err != nil {
			return contract.PublicImportManifest{}, fmt.Errorf("file %d sha256: %w", i, err)
		}
		facts := contract.ImportManifestFileFacts{FileID: file.FileID, Kind: file.Kind, SHA256: fingerprint}
		if file.IssuerCertificateID != "" {
			facts.IssuerCertificateID, err = domain.ParseCertificateID(file.IssuerCertificateID)
			if err != nil {
				return contract.PublicImportManifest{}, fmt.Errorf("file %d issuer certificate id: %w", i, err)
			}
		}
		files[i] = facts
	}
	manifest := contract.PublicImportManifest{SchemaVersion: stored.SchemaVersion, Files: files}
	// Reuse the encoder's field-level and version checks without sharing its
	// encoded bytes with the returned value.
	if _, err := encodeManifest(manifest); err != nil {
		return contract.PublicImportManifest{}, err
	}
	return manifest, nil
}

type importResultJSON struct {
	ID             string                     `json:"id"`
	State          contract.ImportResultState `json:"state"`
	CommittedAt    *string                    `json:"committed_at,omitempty"`
	Items          []importItemJSON           `json:"items"`
	CertificateIDs []string                   `json:"certificate_ids"`
	AuthorityIDs   []string                   `json:"authority_ids"`
}

type importItemJSON struct {
	FileID     string                    `json:"file_id"`
	SHA256     string                    `json:"sha256,omitempty"`
	Kind       contract.ImportFileKind   `json:"kind"`
	Status     contract.ImportItemStatus `json:"status"`
	ExistingID *string                   `json:"existing_id,omitempty"`
	ErrorCode  string                    `json:"error_code,omitempty"`
}

func encodeImportResult(result contract.ImportResultView) ([]byte, error) {
	if result.ID == "" && result.State == "" && result.CommittedAt == nil && len(result.Items) == 0 && len(result.CertificateIDs) == 0 && len(result.AuthorityIDs) == 0 {
		return nil, nil // result_json is nullable for rows with no public outcome.
	}
	if _, err := domain.ParseImportBatchID(result.ID); err != nil {
		return nil, fmt.Errorf("result id: %w", err)
	}
	switch result.State {
	case contract.ImportResultStateCommitted, contract.ImportResultStateFailed:
	default:
		return nil, fmt.Errorf("unsupported result state %q", result.State)
	}
	out := importResultJSON{
		ID:             result.ID,
		State:          result.State,
		Items:          make([]importItemJSON, len(result.Items)),
		CertificateIDs: make([]string, len(result.CertificateIDs)),
		AuthorityIDs:   make([]string, len(result.AuthorityIDs)),
	}
	if result.CommittedAt != nil {
		formatted := result.CommittedAt.String()
		out.CommittedAt = &formatted
	}
	for i, item := range result.Items {
		if item.FileID == "" || len(item.FileID) > 128 {
			return nil, fmt.Errorf("result item %d has an invalid file_id", i)
		}
		if err := item.Kind.Validate(); err != nil {
			return nil, fmt.Errorf("result item %d: %w", i, err)
		}
		switch item.Status {
		case contract.ImportItemStatusNew, contract.ImportItemStatusDuplicate, contract.ImportItemStatusConflict:
		default:
			return nil, fmt.Errorf("result item %d has an invalid status", i)
		}
		stored := importItemJSON{FileID: item.FileID, Kind: item.Kind, Status: item.Status, ErrorCode: item.ErrorCode}
		if !item.SHA256.IsZero() {
			fingerprint, err := domain.ParseFingerprint(item.SHA256.Hex())
			if err != nil {
				return nil, fmt.Errorf("result item %d sha256: %w", i, err)
			}
			stored.SHA256 = fingerprint.Hex()
		}
		if item.ExistingID != nil {
			id, err := domain.ParseCertificateID(string(*item.ExistingID))
			if err != nil {
				return nil, fmt.Errorf("result item %d existing id: %w", i, err)
			}
			storedID := string(id)
			stored.ExistingID = &storedID
		}
		out.Items[i] = stored
	}
	for i, id := range result.CertificateIDs {
		parsed, err := domain.ParseCertificateID(string(id))
		if err != nil {
			return nil, fmt.Errorf("result certificate id %d: %w", i, err)
		}
		out.CertificateIDs[i] = string(parsed)
	}
	for i, id := range result.AuthorityIDs {
		parsed, err := domain.ParseAuthorityID(string(id))
		if err != nil {
			return nil, fmt.Errorf("result authority id %d: %w", i, err)
		}
		out.AuthorityIDs[i] = string(parsed)
	}
	return json.Marshal(out)
}

func decodeImportResult(data []byte) (contract.ImportResultView, error) {
	if err := requireJSONFields(data, "id", "state", "items", "certificate_ids", "authority_ids"); err != nil {
		return contract.ImportResultView{}, err
	}
	var stored importResultJSON
	if err := decodeStrict(data, &stored); err != nil {
		return contract.ImportResultView{}, err
	}
	if _, err := domain.ParseImportBatchID(stored.ID); err != nil {
		return contract.ImportResultView{}, fmt.Errorf("result id: %w", err)
	}
	result := contract.ImportResultView{ID: stored.ID, State: stored.State, Items: make([]contract.ImportItemView, len(stored.Items)), CertificateIDs: make([]domain.CertificateID, len(stored.CertificateIDs)), AuthorityIDs: make([]domain.AuthorityID, len(stored.AuthorityIDs))}
	if stored.CommittedAt != nil {
		parsed, err := time.Parse(time.RFC3339Nano, *stored.CommittedAt)
		if err != nil {
			return contract.ImportResultView{}, fmt.Errorf("result committed_at: %w", err)
		}
		instant := domain.NewInstant(parsed)
		result.CommittedAt = &instant
	}
	for i, item := range stored.Items {
		result.Items[i] = contract.ImportItemView{FileID: item.FileID, Kind: item.Kind, Status: item.Status, ErrorCode: item.ErrorCode}
		if item.SHA256 != "" {
			fingerprint, err := domain.ParseFingerprint(item.SHA256)
			if err != nil {
				return contract.ImportResultView{}, fmt.Errorf("result item %d sha256: %w", i, err)
			}
			result.Items[i].SHA256 = fingerprint
		}
		if item.ExistingID != nil {
			id, err := domain.ParseCertificateID(*item.ExistingID)
			if err != nil {
				return contract.ImportResultView{}, fmt.Errorf("result item %d existing id: %w", i, err)
			}
			result.Items[i].ExistingID = &id
		}
	}
	for i, id := range stored.CertificateIDs {
		parsed, err := domain.ParseCertificateID(id)
		if err != nil {
			return contract.ImportResultView{}, fmt.Errorf("result certificate id %d: %w", i, err)
		}
		result.CertificateIDs[i] = parsed
	}
	for i, id := range stored.AuthorityIDs {
		parsed, err := domain.ParseAuthorityID(id)
		if err != nil {
			return contract.ImportResultView{}, fmt.Errorf("result authority id %d: %w", i, err)
		}
		result.AuthorityIDs[i] = parsed
	}
	if _, err := encodeImportResult(result); err != nil {
		return contract.ImportResultView{}, err
	}
	return result, nil
}

func encodeEvidence(evidence contract.TakeoverEvidence) ([]byte, error) {
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	// Marshal from a fresh slice so callers cannot mutate the encoded value
	// after the repository returns, even if JSON encoding later changes.
	copy := contract.TakeoverEvidence{
		SchemaVersion:          evidence.SchemaVersion,
		CRLSHA256Hex:           append([]string(nil), evidence.CRLSHA256Hex...),
		IssuanceRecordsChecked: evidence.IssuanceRecordsChecked,
		CRLRoutesChecked:       evidence.CRLRoutesChecked,
	}
	if copy.CRLSHA256Hex == nil {
		copy.CRLSHA256Hex = []string{}
	}
	return json.Marshal(copy)
}

func decodeEvidence(data []byte) (contract.TakeoverEvidence, error) {
	if err := requireJSONFields(data, "schema_version", "crl_sha256", "issuance_records_checked", "crl_routes_checked"); err != nil {
		return contract.TakeoverEvidence{}, err
	}
	var stored evidenceJSON
	if err := decodeStrict(data, &stored); err != nil {
		return contract.TakeoverEvidence{}, err
	}
	if stored.CRLSHA256Hex == nil {
		return contract.TakeoverEvidence{}, errors.New("crl_sha256 must be an array")
	}
	evidence := contract.TakeoverEvidence{
		SchemaVersion:          stored.SchemaVersion,
		CRLSHA256Hex:           append([]string(nil), (*stored.CRLSHA256Hex)...),
		IssuanceRecordsChecked: stored.IssuanceRecordsChecked,
		CRLRoutesChecked:       stored.CRLRoutesChecked,
	}
	if err := evidence.Validate(); err != nil {
		return contract.TakeoverEvidence{}, err
	}
	evidence.CRLSHA256Hex = append([]string(nil), evidence.CRLSHA256Hex...)
	return evidence, nil
}

type evidenceJSON struct {
	SchemaVersion          int       `json:"schema_version"`
	CRLSHA256Hex           *[]string `json:"crl_sha256"`
	IssuanceRecordsChecked bool      `json:"issuance_records_checked"`
	CRLRoutesChecked       bool      `json:"crl_routes_checked"`
}

func decodeStrict(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func requireJSONFields(data []byte, names ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("required JSON field %q is missing or null", name)
		}
	}
	return nil
}
