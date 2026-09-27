// Package identity implements SQL-backed identity and installation
// repositories. Each repository is bound to the caller's transaction-scoped
// executor; methods never open, commit, or roll back a transaction.
package identity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	sqlite "modernc.org/sqlite"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// Repositories contains the concrete adapters over one SQL executor. Keep the
// executor transaction-scoped: do not retain a Repositories value after its
// owning UnitOfWork callback returns.
type Repositories struct {
	Accounts     *AccountRepository
	Installation *InstallationRepository
}

// New constructs identity repositories over executor and d. The dialect is
// validated again so a zero-value or otherwise unsupported Dialect cannot
// accidentally issue SQL with unnumbered PostgreSQL parameters.
func New(executor core.SQLExecutor, d dialect.Dialect) (*Repositories, error) {
	if executor == nil {
		return nil, errors.New("sqlstore identity: SQL executor is required")
	}
	validated, err := dialect.New(d.Kind())
	if err != nil {
		return nil, fmt.Errorf("sqlstore identity: %w", err)
	}
	return &Repositories{
		Accounts:     &AccountRepository{executor: executor, dialect: validated},
		Installation: &InstallationRepository{executor: executor, dialect: validated},
	}, nil
}

// AccountRepository implements port.AccountRepository.
type AccountRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

// InstallationRepository implements port.InstallationRepository.
type InstallationRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

var (
	_ port.AccountRepository      = (*AccountRepository)(nil)
	_ port.InstallationRepository = (*InstallationRepository)(nil)
)

// storageError preserves errors.Is/errors.As for internal callers while
// keeping driver messages (which may contain bound identifiers or values)
// out of ordinary error strings.
type storageError struct {
	op  string
	err error
}

func (e *storageError) Error() string { return "sqlstore identity: " + e.op }
func (e *storageError) Unwrap() error { return e.err }

func failed(op string, err error) error {
	if err == nil {
		return nil
	}
	return &storageError{op: op, err: err}
}

func validContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("sqlstore identity: context is required")
	}
	if err := ctx.Err(); err != nil {
		return failed("operation canceled", err)
	}
	return nil
}

func isDuplicate(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return true
	}
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return true
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		// SQLite extended result codes distinguish duplicate keys from other
		// constraints such as CHECK and foreign-key violations.
		switch sqliteErr.Code() {
		case 1555, 2067: // SQLITE_CONSTRAINT_PRIMARYKEY / UNIQUE
			return true
		}
	}
	return false
}

func duplicateOrFailed(op string, err error) error {
	if isDuplicate(err) {
		return failed(op, port.ErrDuplicate)
	}
	return failed(op, err)
}

func versionConflictOrFailed(op string, err error) error {
	if isDuplicate(err) {
		return failed(op, port.ErrVersionConflict)
	}
	return failed(op, err)
}

func lockSuffix(d dialect.Dialect) string {
	if d.Kind() == config.SQLite {
		// SQLite's writer transaction is opened with _txlock=immediate. It
		// serializes write-side row changes without SELECT FOR UPDATE syntax.
		return ""
	}
	return " FOR UPDATE"
}

func optionalID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

func optionalInstant(instant domain.Instant) any {
	if instant.IsZero() {
		return nil
	}
	return instant.UnixMicro()
}

func instantFromNullable(value sql.NullInt64) domain.Instant {
	if !value.Valid {
		return domain.Instant{}
	}
	return domain.InstantFromUnixMicro(value.Int64)
}

func nowUnixMicro() int64 { return time.Now().UTC().UnixMicro() }

func randomUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func accountFromRow(row rowScanner) (domain.Account, error) {
	var id, normalized, passwordHash, state string
	var epoch, version int64
	var globalAdmin bool
	if err := row.Scan(&id, &normalized, &passwordHash, &state, &epoch, &globalAdmin, &version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Account{}, port.ErrNotFound
		}
		return domain.Account{}, failed("read account row", err)
	}
	parsedID, err := domain.ParseAccountID(id)
	if err != nil {
		return domain.Account{}, failed("decode account row", err)
	}
	hash, err := domain.NewPasswordHash(passwordHash)
	if err != nil {
		return domain.Account{}, failed("decode account row", err)
	}
	authEpoch, err := domain.ParseAuthEpoch(epoch)
	if err != nil {
		return domain.Account{}, failed("decode account row", err)
	}
	parsedVersion, err := domain.ParseVersion(version)
	if err != nil {
		return domain.Account{}, failed("decode account row", err)
	}
	account, err := domain.NewAccount(domain.AccountFacts{
		ID:                  parsedID,
		NormalizedLoginName: normalized,
		PasswordHash:        hash,
		State:               domain.AccountState(state),
		AuthEpoch:           authEpoch,
		IsGlobalAdmin:       globalAdmin,
		Version:             parsedVersion,
	})
	if err != nil {
		return domain.Account{}, failed("decode account row", err)
	}
	return account, nil
}

func resetTokenFromRow(row rowScanner) (domain.AdminResetToken, error) {
	var id, accountID, tokenHash string
	var epoch, issuedAt, expiresAt int64
	var consumedAt, invalidatedAt sql.NullInt64
	if err := row.Scan(&id, &accountID, &tokenHash, &epoch, &issuedAt, &expiresAt, &consumedAt, &invalidatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AdminResetToken{}, port.ErrNotFound
		}
		return domain.AdminResetToken{}, failed("read reset token row", err)
	}
	parsedID, err := domain.ParseResetTokenID(id)
	if err != nil {
		return domain.AdminResetToken{}, failed("decode reset token row", err)
	}
	parsedAccountID, err := domain.ParseAccountID(accountID)
	if err != nil {
		return domain.AdminResetToken{}, failed("decode reset token row", err)
	}
	parsedHash, err := domain.ParseTokenHash(tokenHash)
	if err != nil {
		return domain.AdminResetToken{}, failed("decode reset token row", err)
	}
	parsedEpoch, err := domain.ParseAuthEpoch(epoch)
	if err != nil {
		return domain.AdminResetToken{}, failed("decode reset token row", err)
	}
	token, err := domain.NewAdminResetToken(domain.AdminResetTokenFacts{
		ID:            parsedID,
		AccountID:     parsedAccountID,
		TokenHash:     parsedHash,
		AuthEpoch:     parsedEpoch,
		IssuedAt:      domain.InstantFromUnixMicro(issuedAt),
		ExpiresAt:     domain.InstantFromUnixMicro(expiresAt),
		ConsumedAt:    instantFromNullable(consumedAt),
		InvalidatedAt: instantFromNullable(invalidatedAt),
	})
	if err != nil {
		return domain.AdminResetToken{}, failed("decode reset token row", err)
	}
	return token, nil
}

const accountColumns = "id, normalized_login_name, password_hash, state, auth_epoch, is_global_admin, version"

// GetAccountForUpdate reads and locks an account in the caller's write
// transaction. SQLite obtains the equivalent serialization from its
// immediate writer transaction.
func (r *AccountRepository) GetAccountForUpdate(ctx context.Context, id domain.AccountID) (domain.Account, error) {
	if err := validContext(ctx); err != nil {
		return domain.Account{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT " + accountColumns + " FROM accounts WHERE id = " + b.Add(string(id)) + lockSuffix(r.dialect)
	return accountFromRow(r.executor.QueryRowContext(ctx, query, b.Args()...))
}

// FindAccountByLoginName performs an exact lookup of the already-normalized
// login value. DDL gives normalized_login_name byte-comparison semantics for
// all four supported databases.
func (r *AccountRepository) FindAccountByLoginName(ctx context.Context, normalizedLoginName string) (domain.Account, error) {
	if err := validContext(ctx); err != nil {
		return domain.Account{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT " + accountColumns + " FROM accounts WHERE normalized_login_name = " + b.Add(normalizedLoginName)
	return accountFromRow(r.executor.QueryRowContext(ctx, query, b.Args()...))
}

// InsertAccount writes the supplied canonical login value to both login_name
// and normalized_login_name. The current Account domain object intentionally
// exposes only its normalized value; there is no separate display-name field.
func (r *AccountRepository) InsertAccount(ctx context.Context, account domain.Account) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	now := nowUnixMicro()
	b := r.dialect.NewBuilder()
	query := "INSERT INTO accounts (id, created_at, updated_at, version, login_name, normalized_login_name, password_hash, state, auth_epoch, is_global_admin) VALUES (" + strings.Join([]string{
		b.Add(string(account.ID())), b.Add(now), b.Add(now), b.Add(account.Version().Int64()),
		b.Add(account.NormalizedLoginName()), b.Add(account.NormalizedLoginName()), b.Add(account.PasswordHash().Encoded()),
		b.Add(account.State().String()), b.Add(account.AuthEpoch().Int64()), b.Add(account.IsGlobalAdmin()),
	}, ", ") + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrFailed("insert account", err)
	}
	return nil
}

func (r *AccountRepository) SaveAccount(ctx context.Context, account domain.Account, expectedVersion domain.Version) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE accounts SET updated_at = " + b.Add(nowUnixMicro()) +
		", normalized_login_name = " + b.Add(account.NormalizedLoginName()) +
		", password_hash = " + b.Add(account.PasswordHash().Encoded()) +
		", state = " + b.Add(account.State().String()) +
		", auth_epoch = " + b.Add(account.AuthEpoch().Int64()) +
		", is_global_admin = " + b.Add(account.IsGlobalAdmin()) +
		", version = " + b.Add(account.Version().Int64()) +
		" WHERE id = " + b.Add(string(account.ID())) + " AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return duplicateOrFailed("save account", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return failed("save account", err)
	}
	if rows > 0 {
		return nil
	}
	return r.resolveVersionMiss(ctx, "accounts", string(account.ID()), expectedVersion, "save account")
}

// resolveVersionMiss distinguishes a missing row from an optimistic-lock
// mismatch and treats a matched no-op update as success (MySQL reports zero
// affected rows for some no-op updates).
func (r *AccountRepository) resolveVersionMiss(ctx context.Context, table, id string, expected domain.Version, op string) error {
	b := r.dialect.NewBuilder()
	var current int64
	query := "SELECT version FROM " + table + " WHERE id = " + b.Add(id)
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return port.ErrNotFound
		}
		return failed(op, err)
	}
	if current != expected.Int64() {
		return failed(op, port.ErrVersionConflict)
	}
	return nil
}

func (r *AccountRepository) GetResetToken(ctx context.Context, tokenHash domain.TokenHash) (domain.AdminResetToken, error) {
	if err := validContext(ctx); err != nil {
		return domain.AdminResetToken{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT id, account_id, token_hash, auth_epoch, created_at, expires_at, consumed_at, invalidated_at FROM password_reset_tokens WHERE token_hash = " + b.Add(tokenHash.Hex()) + lockSuffix(r.dialect)
	return resetTokenFromRow(r.executor.QueryRowContext(ctx, query, b.Args()...))
}

func (r *AccountRepository) InsertResetToken(ctx context.Context, token domain.AdminResetToken) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "INSERT INTO password_reset_tokens (id, created_at, token_hash, account_id, auth_epoch, expires_at, consumed_at, invalidated_at) VALUES (" + strings.Join([]string{
		b.Add(string(token.ID())), b.Add(token.IssuedAt().UnixMicro()), b.Add(token.TokenHash().Hex()),
		b.Add(string(token.AccountID())), b.Add(token.AuthEpoch().Int64()), b.Add(token.ExpiresAt().UnixMicro()),
		b.Add(optionalInstant(token.ConsumedAt())), b.Add(optionalInstant(token.InvalidatedAt())),
	}, ", ") + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrFailed("insert reset token", err)
	}
	return nil
}

func (r *AccountRepository) SaveResetToken(ctx context.Context, token domain.AdminResetToken) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE password_reset_tokens SET consumed_at = " + b.Add(optionalInstant(token.ConsumedAt())) +
		", invalidated_at = " + b.Add(optionalInstant(token.InvalidatedAt())) +
		" WHERE id = " + b.Add(string(token.ID()))
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return failed("save reset token", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return failed("save reset token", err)
	}
	if rows > 0 {
		return nil
	}
	check := r.dialect.NewBuilder()
	var one int
	query = "SELECT 1 FROM password_reset_tokens WHERE id = " + check.Add(string(token.ID()))
	if err := r.executor.QueryRowContext(ctx, query, check.Args()...).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return port.ErrNotFound
		}
		return failed("check reset token after save", err)
	}
	return nil
}

func (r *AccountRepository) InvalidateResetTokens(ctx context.Context, accountID domain.AccountID, now domain.Instant) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE password_reset_tokens SET invalidated_at = " + b.Add(now.UnixMicro()) +
		" WHERE account_id = " + b.Add(string(accountID)) + " AND consumed_at IS NULL AND invalidated_at IS NULL"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return failed("invalidate reset tokens", err)
	}
	return nil
}

func (r *AccountRepository) GetRateLimit(ctx context.Context, kind string, subjectHash domain.Fingerprint, windowStart domain.Instant) (port.RateLimitRecord, error) {
	if err := validContext(ctx); err != nil {
		return port.RateLimitRecord{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT kind, subject_hash, window_start, failure_count, blocked_until FROM auth_rate_limits WHERE kind = " + b.Add(kind) +
		" AND subject_hash = " + b.Add(subjectHash.Hex()) + " AND window_start = " + b.Add(windowStart.UnixMicro())
	var storedKind, storedHash string
	var start, failures int64
	var blocked sql.NullInt64
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&storedKind, &storedHash, &start, &failures, &blocked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return port.RateLimitRecord{}, port.ErrNotFound
		}
		return port.RateLimitRecord{}, failed("read rate limit", err)
	}
	fingerprint, err := domain.ParseFingerprint(storedHash)
	if err != nil {
		return port.RateLimitRecord{}, failed("decode rate limit row", err)
	}
	return port.RateLimitRecord{
		Kind:         storedKind,
		SubjectHash:  fingerprint,
		WindowStart:  domain.InstantFromUnixMicro(start),
		FailureCount: int(failures),
		BlockedUntil: instantFromNullable(blocked),
	}, nil
}

func (r *AccountRepository) SaveRateLimit(ctx context.Context, record port.RateLimitRecord) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	id, err := randomUUID()
	if err != nil {
		return failed("create rate-limit identifier", err)
	}
	b := r.dialect.NewBuilder()
	query := "INSERT INTO auth_rate_limits (id, created_at, kind, subject_hash, window_start, failure_count, blocked_until) VALUES (" + strings.Join([]string{
		b.Add(id), b.Add(nowUnixMicro()), b.Add(record.Kind), b.Add(record.SubjectHash.Hex()),
		b.Add(record.WindowStart.UnixMicro()), b.Add(record.FailureCount), b.Add(optionalInstant(record.BlockedUntil)),
	}, ", ") + ")"
	if r.dialect.Kind() == config.Postgres || r.dialect.Kind() == config.SQLite {
		query += " ON CONFLICT (kind, subject_hash, window_start) DO UPDATE SET failure_count = excluded.failure_count, blocked_until = excluded.blocked_until"
	} else {
		query += " ON DUPLICATE KEY UPDATE failure_count = VALUES(failure_count), blocked_until = VALUES(blocked_until)"
	}
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return failed("save rate limit", err)
	}
	return nil
}

func (r *InstallationRepository) GetForUpdate(ctx context.Context) (port.Installation, error) {
	if err := validContext(ctx); err != nil {
		return port.Installation{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT setup_stage, first_admin_id, active_encryption_generation_id, active_tls_version_id, service_mode, version FROM installation WHERE id = " + b.Add(1) + lockSuffix(r.dialect)
	var stage, encryptionID, serviceMode string
	var firstAdminID, tlsID sql.NullString
	var version int64
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&stage, &firstAdminID, &encryptionID, &tlsID, &serviceMode, &version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return port.Installation{}, port.ErrNotFound
		}
		return port.Installation{}, failed("read installation", err)
	}
	parsedVersion, err := domain.ParseVersion(version)
	if err != nil {
		return port.Installation{}, failed("decode installation row", err)
	}
	return port.Installation{
		SetupStage:                   port.SetupStage(stage),
		FirstAdminID:                 domain.AccountID(firstAdminID.String),
		ActiveEncryptionGenerationID: encryptionID,
		ActiveTLSVersionID:           domain.TLSVersionID(tlsID.String),
		ServiceMode:                  serviceMode,
		Version:                      parsedVersion,
	}, nil
}

func (r *InstallationRepository) Save(ctx context.Context, installation port.Installation, expectedVersion domain.Version) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE installation SET setup_stage = " + b.Add(string(installation.SetupStage)) +
		", first_admin_id = " + b.Add(optionalID(string(installation.FirstAdminID))) +
		", active_encryption_generation_id = " + b.Add(installation.ActiveEncryptionGenerationID) +
		", active_tls_version_id = " + b.Add(optionalID(string(installation.ActiveTLSVersionID))) +
		", service_mode = " + b.Add(installation.ServiceMode) +
		", updated_at = " + b.Add(nowUnixMicro()) +
		", version = " + b.Add(installation.Version.Int64()) +
		" WHERE id = " + b.Add(1) + " AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return failed("save installation", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return failed("save installation", err)
	}
	if rows > 0 {
		return nil
	}
	check := r.dialect.NewBuilder()
	var current int64
	checkQuery := "SELECT version FROM installation WHERE id = " + check.Add(1)
	if err := r.executor.QueryRowContext(ctx, checkQuery, check.Args()...).Scan(&current); err == nil {
		if current != expectedVersion.Int64() {
			return failed("save installation", port.ErrVersionConflict)
		}
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return failed("check installation version", err)
	}
	if expectedVersion != 0 {
		return port.ErrNotFound
	}
	return r.insertInstallation(ctx, installation)
}

func (r *InstallationRepository) insertInstallation(ctx context.Context, installation port.Installation) error {
	b := r.dialect.NewBuilder()
	query := "INSERT INTO installation (id, setup_stage, first_admin_id, active_encryption_generation_id, active_tls_version_id, service_mode, updated_at, version) VALUES (" + strings.Join([]string{
		b.Add(1), b.Add(string(installation.SetupStage)), b.Add(optionalID(string(installation.FirstAdminID))),
		b.Add(installation.ActiveEncryptionGenerationID), b.Add(optionalID(string(installation.ActiveTLSVersionID))),
		b.Add(installation.ServiceMode), b.Add(nowUnixMicro()), b.Add(installation.Version.Int64()),
	}, ", ") + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return versionConflictOrFailed("insert installation", err)
	}
	return nil
}

func (r *InstallationRepository) GetSettings(ctx context.Context) (port.Settings, error) {
	if err := validContext(ctx); err != nil {
		return port.Settings{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT schema_version, settings_json, version, updated_by FROM service_settings WHERE id = " + b.Add(1)
	var schemaVersion, version int64
	var settingsJSON []byte
	var updatedBy sql.NullString
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&schemaVersion, &settingsJSON, &version, &updatedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return port.Settings{}, port.ErrNotFound
		}
		return port.Settings{}, failed("read service settings", err)
	}
	parsedVersion, err := domain.ParseVersion(version)
	if err != nil {
		return port.Settings{}, failed("decode service settings", err)
	}
	return port.Settings{
		SchemaVersion: int(schemaVersion),
		SettingsJSON:  append([]byte(nil), settingsJSON...),
		Version:       parsedVersion,
		UpdatedBy:     domain.AccountID(updatedBy.String),
	}, nil
}

func (r *InstallationRepository) SaveSettings(ctx context.Context, settings port.Settings, expectedVersion domain.Version) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE service_settings SET schema_version = " + b.Add(settings.SchemaVersion) +
		", settings_json = " + b.Add(string(append([]byte(nil), settings.SettingsJSON...))) +
		", updated_at = " + b.Add(nowUnixMicro()) +
		", version = " + b.Add(settings.Version.Int64()) +
		", updated_by = " + b.Add(optionalID(string(settings.UpdatedBy))) +
		" WHERE id = " + b.Add(1) + " AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return failed("save service settings", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return failed("save service settings", err)
	}
	if rows > 0 {
		return nil
	}
	check := r.dialect.NewBuilder()
	var current int64
	checkQuery := "SELECT version FROM service_settings WHERE id = " + check.Add(1)
	if err := r.executor.QueryRowContext(ctx, checkQuery, check.Args()...).Scan(&current); err == nil {
		if current != expectedVersion.Int64() {
			return failed("save service settings", port.ErrVersionConflict)
		}
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return failed("check service settings version", err)
	}
	if expectedVersion != 0 {
		return port.ErrNotFound
	}
	return r.insertSettings(ctx, settings)
}

func (r *InstallationRepository) insertSettings(ctx context.Context, settings port.Settings) error {
	b := r.dialect.NewBuilder()
	query := "INSERT INTO service_settings (id, schema_version, settings_json, updated_at, version, updated_by) VALUES (" + strings.Join([]string{
		b.Add(1), b.Add(settings.SchemaVersion), b.Add(string(append([]byte(nil), settings.SettingsJSON...))),
		b.Add(nowUnixMicro()), b.Add(settings.Version.Int64()), b.Add(optionalID(string(settings.UpdatedBy))),
	}, ", ") + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return versionConflictOrFailed("insert service settings", err)
	}
	return nil
}
