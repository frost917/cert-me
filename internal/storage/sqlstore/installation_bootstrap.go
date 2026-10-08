package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/domain"
	"cert-me/internal/storage/connection"
	"cert-me/internal/storage/executionlock"
	"cert-me/internal/storage/sqlstore/dialect"
)

var (
	// ErrRecoveryRequired means installation metadata is absent while business
	// rows already exist. Startup must stop and follow the documented recovery
	// path instead of treating the database as a fresh installation.
	ErrRecoveryRequired = errors.New("sqlstore: recovery required")

	// ErrInitialInstallationCommitUnknown means the initial installation write
	// may have committed. Callers must fail closed and reconcile from storage.
	ErrInitialInstallationCommitUnknown = errors.New("sqlstore: initial installation commit outcome unknown")

	// ErrInvalidInitialInstallation means the bootstrap inputs are inconsistent.
	ErrInvalidInitialInstallation = errors.New("sqlstore: invalid initial installation")
)

// InitialInstallation is the startup state needed to initialize the storage
// key ring and decide whether the service may proceed.
type InitialInstallation struct {
	ActiveEncryptionGenerationID string
	ServiceMode                  string
}

// initialInstallationBusinessTables lists every business table created by
// the current migrations except installation itself. schema_migrations is
// excluded because its rows only record the schema applied to an empty store.
var initialInstallationBusinessTables = [...]string{
	"accounts",
	"audit_event_scopes",
	"audit_events",
	"auth_rate_limits",
	"authorities",
	"ca_certificates",
	"ca_key_generations",
	"ca_takeovers",
	"ca_transitions",
	"certificate_sans",
	"certificates",
	"crl_documents",
	"crl_states",
	"deployment_confirmations",
	"download_tokens",
	"encryption_generations",
	"encryption_verifier",
	"import_batches",
	"jobs",
	"key_deliveries",
	"key_materials",
	"leaf_certificates",
	"leaf_key_generations",
	"leaf_series",
	"maintenance_crl_requirements",
	"maintenance_runs",
	"operation_requests",
	"password_reset_tokens",
	"private_key_secrets",
	"revocation_revisions",
	"revocations",
	"service_settings",
	"sessions",
	"tls_changes",
	"tls_versions",
	"transition_impacts",
}

// EnsureInitialInstallation reads the installation row or creates it for a
// genuinely empty schema. The caller must already hold the execution lock for
// this database, and for database-scoped locks it must be the same pinned
// writer connection owned by db.
func EnsureInitialInstallation(
	ctx context.Context,
	db *connection.DB,
	kind config.DatabaseKind,
	lock *executionlock.Lock,
	generationID string,
	verifier domain.EncryptedSecret,
	now time.Time,
) (result InitialInstallation, created bool, err error) {
	if ctx == nil || db == nil || lock == nil {
		return InitialInstallation{}, false, ErrInvalidInitialInstallation
	}
	if _, parseErr := domain.ParseKeyMaterialID(generationID); parseErr != nil ||
		verifier.IsZero() ||
		verifier.OwnerKeyID() != domain.StoreVerifierOwnerKeyID ||
		verifier.Purpose() != domain.SecretPurposeStoreVerifier ||
		verifier.EncryptionGenerationID() != generationID {
		return InitialInstallation{}, false, ErrInvalidInitialInstallation
	}

	writer := db.WriterConn()
	if writer == nil {
		return InitialInstallation{}, false, fmt.Errorf("sqlstore: initial installation: %w", connection.ErrClosed)
	}
	d, err := dialect.New(kind)
	if err != nil {
		return InitialInstallation{}, false, fmt.Errorf("sqlstore: initial installation: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return InitialInstallation{}, false, err
	}
	if err := lock.Check(ctx); err != nil {
		return InitialInstallation{}, false, fmt.Errorf("sqlstore: check execution lock before initial installation: %w", err)
	}

	var txOptions *sql.TxOptions
	if kind != config.SQLite {
		txOptions = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := writer.BeginTx(ctx, txOptions)
	if err != nil {
		return InitialInstallation{}, false, fmt.Errorf("sqlstore: begin initial installation transaction: %w", err)
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		finished = true
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackFailure := fmt.Errorf("sqlstore: roll back initial installation transaction: %w", rollbackErr)
			if err == nil {
				err = rollbackFailure
			} else {
				err = errors.Join(err, rollbackFailure)
			}
		}
	}()

	stores, err := NewTxStores(tx, d)
	if err != nil {
		return InitialInstallation{}, false, fmt.Errorf("sqlstore: create initial installation repositories: %w", err)
	}
	installation, readErr := stores.Installation().GetForUpdate(ctx)
	switch {
	case readErr == nil:
		result = InitialInstallation{
			ActiveEncryptionGenerationID: installation.ActiveEncryptionGenerationID,
			ServiceMode:                  installation.ServiceMode,
		}
	case errors.Is(readErr, port.ErrNotFound):
		if err := ensureBusinessTablesEmpty(ctx, tx, d); err != nil {
			return InitialInstallation{}, false, err
		}
		if err := ctx.Err(); err != nil {
			return InitialInstallation{}, false, err
		}
		if err := insertInitialGeneration(ctx, tx, d, generationID, now.UTC().UnixMicro()); err != nil {
			return InitialInstallation{}, false, err
		}
		if err := ctx.Err(); err != nil {
			return InitialInstallation{}, false, err
		}
		if err := stores.Secrets().SaveVerifier(ctx, verifier); err != nil {
			return InitialInstallation{}, false, fmt.Errorf("sqlstore: save initial encryption verifier: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return InitialInstallation{}, false, err
		}
		installation = port.Installation{
			SetupStage:                   port.SetupStageAccountRequired,
			ActiveEncryptionGenerationID: generationID,
			ServiceMode:                  "starting",
		}
		if err := stores.Installation().Save(ctx, installation, 0); err != nil {
			return InitialInstallation{}, false, fmt.Errorf("sqlstore: save initial installation row: %w", err)
		}
		result = InitialInstallation{
			ActiveEncryptionGenerationID: generationID,
			ServiceMode:                  installation.ServiceMode,
		}
		created = true
	default:
		return InitialInstallation{}, false, fmt.Errorf("sqlstore: read initial installation row: %w", readErr)
	}

	if err := ctx.Err(); err != nil {
		return InitialInstallation{}, false, err
	}
	if err := lock.Check(ctx); err != nil {
		return InitialInstallation{}, false, fmt.Errorf("sqlstore: check execution lock before committing initial installation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		finished = true // Commit consumes the transaction even when it fails.
		if created {
			return InitialInstallation{}, false, errors.Join(
				port.ErrCommitUnknown,
				ErrInitialInstallationCommitUnknown,
				fmt.Errorf("sqlstore: commit initial installation transaction: %w", err),
			)
		}
		return InitialInstallation{}, false, fmt.Errorf("sqlstore: commit initial installation read transaction: %w", err)
	}
	finished = true

	if err := ctx.Err(); err != nil {
		return result, created, err
	}
	if err := lock.Check(ctx); err != nil {
		return result, created, fmt.Errorf("sqlstore: check execution lock after initial installation: %w", err)
	}
	return result, created, nil
}

func ensureBusinessTablesEmpty(ctx context.Context, tx *sql.Tx, d dialect.Dialect) error {
	for _, table := range initialInstallationBusinessTables {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := d.NewBuilder()
		query := "SELECT EXISTS (SELECT 1 FROM " + table + " LIMIT " + b.Add(1) + ")"
		var hasRows bool
		if err := tx.QueryRowContext(ctx, query, b.Args()...).Scan(&hasRows); err != nil {
			return fmt.Errorf("sqlstore: inspect existing %s rows before initial installation: %w", table, err)
		}
		if hasRows {
			return ErrRecoveryRequired
		}
	}
	return nil
}

func insertInitialGeneration(ctx context.Context, tx *sql.Tx, d dialect.Dialect, generationID string, createdAt int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b := d.NewBuilder()
	query := "INSERT INTO encryption_generations (id, created_at, activated_at, retired_at) VALUES (" +
		b.Add(generationID) + ", " + b.Add(createdAt) + ", " + b.Add(createdAt) + ", NULL)"
	if _, err := tx.ExecContext(ctx, query, b.Args()...); err != nil {
		return fmt.Errorf("sqlstore: insert initial encryption generation: %w", err)
	}
	return nil
}
