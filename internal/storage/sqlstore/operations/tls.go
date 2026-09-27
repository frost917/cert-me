package operations

import (
	"context"
	"database/sql"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// TLSRepository stores immutable validated snapshots and the durable
// activation/reconciliation ledger.
type TLSRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

var _ port.TLSRepository = (*TLSRepository)(nil)

func (r *TLSRepository) GetActiveForUpdate(ctx context.Context) (domain.TLSChange, error) {
	if err := checkContext(ctx); err != nil {
		return domain.TLSChange{}, err
	}
	b := r.builder()
	query := "SELECT active_tls_version_id FROM installation WHERE id = 1" + r.dialect.RowLockClause()
	var active sql.NullString
	if err := r.queryRow(ctx, query).Scan(&active); err != nil {
		return domain.TLSChange{}, failed("read installation TLS pointer", missing(err))
	}
	if !active.Valid {
		return domain.TLSChange{}, port.ErrNotFound
	}
	versionID, err := domain.ParseTLSVersionID(active.String)
	if err != nil {
		return domain.TLSChange{}, failed("decode active TLS pointer", err)
	}
	b = r.builder()
	change, err := scanTLSChange(r.queryRow(ctx, "SELECT previous_version_id, candidate_version_id, phase, error_code, version FROM tls_changes WHERE candidate_version_id = "+b.Add(string(versionID))+" AND phase = 'applied'"+r.dialect.RowLockClause(), b.Args()...))
	if err != nil {
		return domain.TLSChange{}, failed("read active TLS change", err)
	}
	return change, nil
}

func (r *TLSRepository) InsertVersion(ctx context.Context, version domain.TLSVersion) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := domain.ParseTLSVersionID(string(version.ID())); err != nil {
		return failed("validate TLS version id", err)
	}
	if err := version.Source().Validate(); err != nil {
		return failed("validate TLS version", err)
	}
	if len(version.LeafDER()) == 0 || version.NotAfter().IsZero() {
		return failed("validate TLS version", domain.ErrInvalidValue)
	}
	b := r.builder()
	query := "INSERT INTO tls_versions (id, created_at, source, key_material_id, managed_certificate_id, leaf_der, chain_bundle, validated_service_url, not_after) VALUES (" +
		b.Add(string(version.ID())) + "," + databaseNowMicros(r.dialect) + "," + b.Add(string(version.Source())) + "," + b.Add(string(version.KeyMaterialID())) + "," +
		b.Add(nullable(string(version.ManagedCertificateID()))) + "," + b.Add(cloneBytes(version.LeafDER())) + "," + b.Add(cloneBytes(version.ChainBundle())) + "," +
		b.Add(nullable(version.ValidatedServiceURL())) + "," + b.Add(version.NotAfter().UnixMicro()) + ")"
	_, err := r.executor.ExecContext(ctx, query, b.Args()...)
	return duplicateOrFailed("insert TLS version", err)
}

func (r *TLSRepository) GetVersion(ctx context.Context, id domain.TLSVersionID) (domain.TLSVersion, error) {
	if err := checkContext(ctx); err != nil {
		return domain.TLSVersion{}, err
	}
	b := r.builder()
	query := "SELECT id, source, key_material_id, managed_certificate_id, leaf_der, chain_bundle, validated_service_url, not_after FROM tls_versions WHERE id = " + b.Add(string(id))
	version, err := scanTLSVersion(r.queryRow(ctx, query, b.Args()...))
	if err != nil {
		return domain.TLSVersion{}, failed("read TLS version", err)
	}
	return version, nil
}

func (r *TLSRepository) ListVersions(ctx context.Context) ([]domain.TLSVersion, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	rows, err := r.executor.QueryContext(ctx, "SELECT id, source, key_material_id, managed_certificate_id, leaf_der, chain_bundle, validated_service_url, not_after FROM tls_versions ORDER BY id")
	if err != nil {
		return nil, failed("list TLS versions", err)
	}
	defer rows.Close()
	out := make([]domain.TLSVersion, 0)
	for rows.Next() {
		v, err := scanTLSVersion(rows)
		if err != nil {
			return nil, failed("decode TLS version", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, failed("iterate TLS versions", err)
	}
	return out, nil
}

func (r *TLSRepository) SaveChange(ctx context.Context, change domain.TLSChange, expectedVersion domain.Version) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := domain.ParseTLSVersionID(string(change.CandidateVersionID())); err != nil {
		return failed("validate TLS change candidate", err)
	}
	if change.PreviousVersionID() != "" {
		if _, err := domain.ParseTLSVersionID(string(change.PreviousVersionID())); err != nil {
			return failed("validate TLS change previous version", err)
		}
	}
	if err := change.Phase().Validate(); err != nil {
		return failed("validate TLS change phase", err)
	}
	if change.Version() < 0 || expectedVersion < 0 || len(change.ErrorCode()) > 64 {
		return failed("validate TLS change", domain.ErrInvalidValue)
	}
	b := r.builder()
	query := "UPDATE tls_changes SET updated_at = " + databaseNowMicros(r.dialect) + ", version = " + b.Add(change.Version().Int64()) +
		", previous_version_id = " + b.Add(nullable(string(change.PreviousVersionID()))) + ", phase = " + b.Add(string(change.Phase())) +
		", error_code = " + b.Add(nullable(change.ErrorCode())) + " WHERE candidate_version_id = " + b.Add(string(change.CandidateVersionID())) + " AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return duplicateOrFailed("save TLS change", err)
	}
	n, err := rowsAffected(result, nil)
	if err != nil {
		return failed("save TLS change rows affected", err)
	}
	if n > 0 {
		return nil
	}
	b = r.builder()
	var current int64
	err = r.queryRow(ctx, "SELECT version FROM tls_changes WHERE candidate_version_id = "+b.Add(string(change.CandidateVersionID())), b.Args()...).Scan(&current)
	if err == nil {
		if domain.Version(current) != expectedVersion {
			return port.ErrVersionConflict
		}
		return nil // MySQL may report zero rows for an otherwise matching update.
	}
	if err != sql.ErrNoRows {
		return failed("resolve TLS change update", err)
	}
	if expectedVersion != 0 {
		return port.ErrNotFound
	}
	b = r.builder()
	query = "INSERT INTO tls_changes (id, created_at, updated_at, version, previous_version_id, candidate_version_id, phase, error_code) VALUES (" +
		b.Add(string(change.CandidateVersionID())) + "," + databaseNowMicros(r.dialect) + "," + databaseNowMicros(r.dialect) + "," +
		b.Add(change.Version().Int64()) + "," + b.Add(nullable(string(change.PreviousVersionID()))) + "," + b.Add(string(change.CandidateVersionID())) + "," +
		b.Add(string(change.Phase())) + "," + b.Add(nullable(change.ErrorCode())) + ")"
	_, err = r.executor.ExecContext(ctx, query, b.Args()...)
	return duplicateOrFailed("insert TLS change", err)
}

func (r *TLSRepository) ClearActive(ctx context.Context, expectedVersion domain.Version, versionID domain.TLSVersionID) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	b := r.builder()
	query := "UPDATE installation SET active_tls_version_id = NULL, version = version + 1, updated_at = " + databaseNowMicros(r.dialect) +
		" WHERE id = 1 AND version = " + b.Add(expectedVersion.Int64()) + " AND active_tls_version_id = " + b.Add(string(versionID))
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return failed("clear active TLS version", err)
	}
	n, err := rowsAffected(result, nil)
	if err != nil {
		return failed("clear active TLS version rows affected", err)
	}
	if n > 0 {
		return nil
	}
	return r.resolveActiveMiss(ctx, expectedVersion, versionID)
}

func (r *TLSRepository) SetActive(ctx context.Context, expectedVersion domain.Version, versionID domain.TLSVersionID) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	b := r.builder()
	var exists bool
	query := "SELECT EXISTS (SELECT 1 FROM tls_versions v JOIN tls_changes c ON c.candidate_version_id = v.id WHERE v.id = " + b.Add(string(versionID)) + ")"
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&exists); err != nil {
		return failed("check TLS activation target", err)
	}
	if !exists {
		return port.ErrNotFound
	}
	b = r.builder()
	query = "UPDATE installation SET active_tls_version_id = " + b.Add(string(versionID)) + ", version = version + 1, updated_at = " + databaseNowMicros(r.dialect) + " WHERE id = 1 AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return failed("set active TLS version", err)
	}
	n, err := rowsAffected(result, nil)
	if err != nil {
		return failed("set active TLS version rows affected", err)
	}
	if n > 0 {
		return nil
	}
	return r.resolveInstallationVersion(ctx, expectedVersion)
}

func (r *TLSRepository) resolveActiveMiss(ctx context.Context, expectedVersion domain.Version, versionID domain.TLSVersionID) error {
	b := r.builder()
	var current sql.NullString
	var version int64
	if err := r.queryRow(ctx, "SELECT active_tls_version_id, version FROM installation WHERE id = 1", b.Args()...).Scan(&current, &version); err != nil {
		return missing(err)
	}
	if domain.Version(version) != expectedVersion {
		return port.ErrVersionConflict
	}
	if !current.Valid || current.String != string(versionID) {
		return port.ErrVersionConflict
	}
	return nil
}

func (r *TLSRepository) resolveInstallationVersion(ctx context.Context, expectedVersion domain.Version) error {
	b := r.builder()
	var current int64
	if err := r.queryRow(ctx, "SELECT version FROM installation WHERE id = 1", b.Args()...).Scan(&current); err != nil {
		return missing(err)
	}
	if domain.Version(current) != expectedVersion {
		return port.ErrVersionConflict
	}
	return nil
}

func scanTLSVersion(row rowScanner) (domain.TLSVersion, error) {
	var id, source, keyID string
	var managed sql.NullString
	var leaf, chain []byte
	var serviceURL sql.NullString
	var notAfter int64
	if err := row.Scan(&id, &source, &keyID, &managed, &leaf, &chain, &serviceURL, &notAfter); err != nil {
		return domain.TLSVersion{}, missing(err)
	}
	parsedID, err := domain.ParseTLSVersionID(id)
	if err != nil {
		return domain.TLSVersion{}, err
	}
	parsedKey, err := domain.ParseKeyMaterialID(keyID)
	if err != nil {
		return domain.TLSVersion{}, err
	}
	facts := domain.TLSVersionFacts{ID: parsedID, Source: domain.TLSSource(source), KeyMaterialID: parsedKey, LeafDER: cloneBytes(leaf), ChainBundle: cloneBytes(chain), NotAfter: domain.InstantFromUnixMicro(notAfter)}
	if managed.Valid {
		facts.ManagedCertificateID, err = domain.ParseCertificateID(managed.String)
		if err != nil {
			return domain.TLSVersion{}, err
		}
	}
	if serviceURL.Valid {
		facts.ValidatedServiceURL = serviceURL.String
	}
	v, err := domain.NewTLSVersion(facts)
	if err != nil {
		return domain.TLSVersion{}, fmt.Errorf("decode TLS version: %w", err)
	}
	return v, nil
}

func scanTLSChange(row rowScanner) (domain.TLSChange, error) {
	var previous, candidate, phase string
	var errorCode sql.NullString
	var version int64
	if err := row.Scan(&previous, &candidate, &phase, &errorCode, &version); err != nil {
		return domain.TLSChange{}, missing(err)
	}
	if version < 0 {
		return domain.TLSChange{}, fmt.Errorf("TLS change version is negative")
	}
	facts := domain.TLSChangeFacts{CandidateVersionID: domain.TLSVersionID(candidate), Phase: domain.TLSChangePhase(phase), Version: domain.Version(version)}
	if previous != "" {
		facts.PreviousVersionID = domain.TLSVersionID(previous)
	}
	if errorCode.Valid {
		facts.ErrorCode = errorCode.String
	}
	// Validation is only persisted implicitly: reaching any phase beyond
	// prepared proves the candidate passed candidate validation.
	facts.Validated = facts.Phase != domain.TLSChangePhasePrepared
	change, err := domain.NewTLSChange(facts)
	if err != nil {
		return domain.TLSChange{}, fmt.Errorf("decode TLS change: %w", err)
	}
	return change, nil
}
