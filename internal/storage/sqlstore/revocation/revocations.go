package revocation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// RevocationRepository implements port.RevocationRepository over the current
// unit-of-work executor. It never owns the transaction lifetime.
type RevocationRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

// NewRevocationRepository binds the repository to a transaction-scoped
// executor and a validated SQL dialect.
func NewRevocationRepository(executor core.SQLExecutor, d dialect.Dialect) (*RevocationRepository, error) {
	validated, err := validate(executor, d)
	if err != nil {
		return nil, err
	}
	return &RevocationRepository{executor: executor, dialect: validated}, nil
}

var _ port.RevocationRepository = (*RevocationRepository)(nil)

type revocationScanner interface {
	Scan(dest ...any) error
}

func (r *RevocationRepository) FindForUpdate(ctx context.Context, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) (domain.Revocation, error) {
	if err := checkContext(ctx); err != nil {
		return domain.Revocation{}, err
	}
	if _, err := domain.ParseCAKeyGenerationID(string(issuer)); err != nil {
		return domain.Revocation{}, failed("find revocation", err)
	}
	if serial.IsZero() {
		return domain.Revocation{}, failed("find revocation", errors.New("serial number is required"))
	}
	b := r.dialect.NewBuilder()
	query := revocationSelect + " WHERE issuer_ca_key_generation_id = " + b.Add(string(issuer)) +
		" AND serial_hex = " + b.Add(serial.Hex()) + r.dialect.RowLockClause()
	revocation, err := scanRevocation(r.executor.QueryRowContext(ctx, query, b.Args()...))
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return domain.Revocation{}, err
		}
		return domain.Revocation{}, failed("find revocation", err)
	}
	return revocation, nil
}

func (r *RevocationRepository) Insert(ctx context.Context, revocation domain.Revocation) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateRevocation(revocation); err != nil {
		return failed("insert revocation", err)
	}
	if err := r.validateCertificateLink(ctx, revocation); err != nil {
		return failed("validate revocation certificate link", err)
	}
	reason, _ := revocationReasonToDB(revocation.Reason())
	b := r.dialect.NewBuilder()
	query := "INSERT INTO revocations (id, created_at, updated_at, version, issuer_ca_key_generation_id, serial_hex, certificate_id, revoked_at, reason, source, change_generation, needs_review) VALUES (" +
		b.Add(string(revocation.ID())) + ", " + databaseNowMicros(r.dialect) + ", " + databaseNowMicros(r.dialect) + ", " +
		b.Add(revocation.Version().Int64()) + ", " + b.Add(string(revocation.IssuerID())) + ", " + b.Add(revocation.Serial().Hex()) + ", " +
		b.Add(optionalString(string(revocation.CertificateID()))) + ", " + b.Add(revocation.RevokedAt().UnixMicro()) + ", " +
		b.Add(reason) + ", " + b.Add(string(revocation.Source())) + ", " + b.Add(revocation.ChangeGeneration()) + ", " + b.Add(revocation.NeedsReview()) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrFailed("insert revocation", err)
	}
	return nil
}

func (r *RevocationRepository) Save(ctx context.Context, revocation domain.Revocation, expectedVersion domain.Version) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateRevocation(revocation); err != nil {
		return failed("save revocation", err)
	}
	if err := r.validateCertificateLink(ctx, revocation); err != nil {
		return failed("validate revocation certificate link", err)
	}
	if _, err := domain.ParseVersion(expectedVersion.Int64()); err != nil {
		return failed("save revocation", err)
	}
	if revocation.Version() <= expectedVersion {
		return failed("save revocation", errors.New("final version must advance past expected version"))
	}
	reason, _ := revocationReasonToDB(revocation.Reason())
	b := r.dialect.NewBuilder()
	query := "UPDATE revocations SET updated_at = " + databaseNowMicros(r.dialect) +
		", version = " + b.Add(revocation.Version().Int64()) +
		", certificate_id = " + b.Add(optionalString(string(revocation.CertificateID()))) +
		", revoked_at = " + b.Add(revocation.RevokedAt().UnixMicro()) +
		", reason = " + b.Add(reason) +
		", source = " + b.Add(string(revocation.Source())) +
		", change_generation = " + b.Add(revocation.ChangeGeneration()) +
		", needs_review = " + b.Add(revocation.NeedsReview()) +
		" WHERE id = " + b.Add(string(revocation.ID())) +
		" AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return duplicateOrFailed("save revocation", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return failed("read revocation update result", err)
	}
	if count != 0 {
		return nil
	}
	var exists int
	check := r.dialect.NewBuilder()
	checkQuery := "SELECT 1 FROM revocations WHERE id = " + check.Add(string(revocation.ID()))
	if err := r.executor.QueryRowContext(ctx, checkQuery, check.Args()...).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return failed("save revocation", port.ErrNotFound)
		}
		return failed("check revocation after optimistic update", err)
	}
	return failed("save revocation", port.ErrVersionConflict)
}

func (r *RevocationRepository) AppendRevision(ctx context.Context, revision port.RevocationRevision) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := domain.ParseRevocationID(string(revision.RevocationID)); err != nil {
		return failed("append revocation revision", err)
	}
	if revision.RevisionNo < 0 {
		return failed("append revocation revision", errors.New("revision number must not be negative"))
	}
	if revision.Justification == "" || !json.Valid(revision.PreviousValuesJSON) || !json.Valid(revision.NewValuesJSON) {
		return failed("append revocation revision", errors.New("revision values and justification are required"))
	}
	if revision.ActorID != "" && revision.SourceImportID != "" {
		return failed("append revocation revision", errors.New("import-sourced revision cannot also name an account actor"))
	}
	actorID := ""
	if revision.ActorID != "" {
		parsed, err := domain.ParseAccountID(string(revision.ActorID))
		if err != nil {
			return failed("append revocation revision", err)
		}
		actorID = string(parsed)
	}
	importID := ""
	if revision.SourceImportID != "" {
		parsed, err := domain.ParseImportBatchID(revision.SourceImportID)
		if err != nil {
			return failed("append revocation revision", err)
		}
		importID = string(parsed)
	}
	id, err := uuid()
	if err != nil {
		return failed("generate revocation revision id", err)
	}
	b := r.dialect.NewBuilder()
	query := "INSERT INTO revocation_revisions (id, created_at, revocation_id, revision_no, previous_values_json, new_values_json, justification, actor_id, source_import_id) VALUES (" +
		b.Add(id) + ", " + databaseNowMicros(r.dialect) + ", " + b.Add(string(revision.RevocationID)) + ", " + b.Add(int64(revision.RevisionNo)) + ", " +
		b.Add(string(revision.PreviousValuesJSON)) + ", " + b.Add(string(revision.NewValuesJSON)) + ", " + b.Add(revision.Justification) + ", " +
		b.Add(optionalString(actorID)) + ", " + b.Add(optionalString(importID)) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrFailed("append revocation revision", err)
	}
	return nil
}

func (r *RevocationRepository) ListByIssuer(ctx context.Context, issuer domain.CAKeyGenerationID) ([]domain.Revocation, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if _, err := domain.ParseCAKeyGenerationID(string(issuer)); err != nil {
		return nil, failed("list revocations", err)
	}
	b := r.dialect.NewBuilder()
	query := revocationSelect + " WHERE issuer_ca_key_generation_id = " + b.Add(string(issuer))
	rows, err := r.executor.QueryContext(ctx, query, b.Args()...)
	if err != nil {
		return nil, failed("list revocations", err)
	}
	defer rows.Close()
	out := make([]domain.Revocation, 0)
	for rows.Next() {
		revocation, err := scanRevocation(rows)
		if err != nil {
			return nil, failed("decode listed revocation", err)
		}
		out = append(out, revocation)
	}
	if err := rows.Err(); err != nil {
		return nil, failed("iterate revocations", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Serial().Compare(out[j].Serial()) < 0 })
	return out, nil
}

// validateCertificateLink enforces the cross-row invariant that a linked
// certificate has the same issuer key generation and serial as its ledger
// entry. The issuer/serial ledger remains valid with no local certificate.
func (r *RevocationRepository) validateCertificateLink(ctx context.Context, revocation domain.Revocation) error {
	if revocation.CertificateID() == "" {
		return nil
	}
	b := r.dialect.NewBuilder()
	query := "SELECT issuer_ca_key_generation_id, serial_hex FROM certificates WHERE id = " + b.Add(string(revocation.CertificateID()))
	var issuerRaw, serialRaw string
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&issuerRaw, &serialRaw); err != nil {
		return missing(err)
	}
	issuer, err := parseCAKeyGenerationID(issuerRaw)
	if err != nil {
		return err
	}
	serial, err := domain.ParseSerialNumber(serialRaw)
	if err != nil {
		return fmt.Errorf("invalid certificate serial in database: %w", err)
	}
	if issuer != revocation.IssuerID() || !serial.Equal(revocation.Serial()) {
		return errors.New("linked certificate issuer and serial do not match the revocation")
	}
	return nil
}

const revocationSelect = "SELECT id, issuer_ca_key_generation_id, serial_hex, certificate_id, revoked_at, reason, source, change_generation, needs_review, version FROM revocations"

func scanRevocation(row revocationScanner) (domain.Revocation, error) {
	var rawID, rawIssuer, serialHex, reasonRaw, sourceRaw string
	var certificateID sql.NullString
	var revokedAt, generation, version int64
	var needsReview bool
	if err := row.Scan(&rawID, &rawIssuer, &serialHex, &certificateID, &revokedAt, &reasonRaw, &sourceRaw, &generation, &needsReview, &version); err != nil {
		return domain.Revocation{}, missing(err)
	}
	id, err := parseRevocationID(rawID)
	if err != nil {
		return domain.Revocation{}, err
	}
	issuer, err := parseCAKeyGenerationID(rawIssuer)
	if err != nil {
		return domain.Revocation{}, err
	}
	serial, err := domain.ParseSerialNumber(serialHex)
	if err != nil {
		return domain.Revocation{}, fmt.Errorf("invalid serial in revocation row: %w", err)
	}
	reason, err := revocationReasonFromDB(reasonRaw)
	if err != nil {
		return domain.Revocation{}, err
	}
	var certID domain.CertificateID
	if certificateID.Valid {
		certID, err = parseCertificateID(certificateID.String)
		if err != nil {
			return domain.Revocation{}, err
		}
	}
	if _, err := domain.ParseVersion(version); err != nil {
		return domain.Revocation{}, fmt.Errorf("invalid revocation version in database: %w", err)
	}
	if generation < 0 {
		return domain.Revocation{}, errors.New("invalid revocation change generation in database")
	}
	revocation, err := domain.NewRevocation(domain.RevocationFacts{
		ID: id, IssuerID: issuer, Serial: serial, CertificateID: certID,
		RevokedAt: instantFromInt64(revokedAt), Reason: reason, Source: domain.RevocationSource(sourceRaw),
		ChangeGeneration: generation, NeedsReview: needsReview, Version: domain.Version(version),
	})
	if err != nil {
		return domain.Revocation{}, fmt.Errorf("decode revocation row: %w", err)
	}
	return revocation, nil
}

func validateRevocation(revocation domain.Revocation) error {
	if _, err := domain.ParseRevocationID(string(revocation.ID())); err != nil {
		return err
	}
	if _, err := domain.ParseCAKeyGenerationID(string(revocation.IssuerID())); err != nil {
		return err
	}
	serial, err := domain.ParseSerialNumber(revocation.Serial().Hex())
	if err != nil {
		return err
	}
	if revocation.CertificateID() != "" {
		if _, err := domain.ParseCertificateID(string(revocation.CertificateID())); err != nil {
			return err
		}
	}
	if _, err := revocationReasonToDB(revocation.Reason()); err != nil {
		return err
	}
	if err := revocation.Source().Validate(); err != nil {
		return err
	}
	if revocation.RevokedAt().IsZero() {
		return errors.New("revoked_at is required")
	}
	if revocation.ChangeGeneration() < 0 {
		return errors.New("change generation must not be negative")
	}
	if _, err := domain.ParseVersion(revocation.Version().Int64()); err != nil {
		return err
	}
	if serial.IsZero() {
		return errors.New("serial number is required")
	}
	return nil
}
