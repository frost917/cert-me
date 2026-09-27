package delivery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// SecretRepository stores ciphertext as opaque bytes. It never decodes or
// otherwise interprets the ciphertext payload.
type SecretRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

// NewSecretRepository binds the repository to the caller's executor and SQL dialect.
func NewSecretRepository(executor core.SQLExecutor, d dialect.Dialect) (*SecretRepository, error) {
	if err := validate(executor, d); err != nil {
		return nil, err
	}
	return &SecretRepository{executor: executor, dialect: d}, nil
}

var _ port.SecretRepository = (*SecretRepository)(nil)

func (r *SecretRepository) GetEncrypted(ctx context.Context, keyID domain.KeyMaterialID, purpose domain.SecretPurpose) (domain.EncryptedSecret, error) {
	if err := checkContext(ctx); err != nil {
		return domain.EncryptedSecret{}, err
	}
	if err := validateSecretPurpose(purpose); err != nil {
		return domain.EncryptedSecret{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT key_material_id, purpose, format_version, encryption_generation_id, nonce, ciphertext FROM private_key_secrets WHERE key_material_id = " + b.Add(string(keyID)) + " AND purpose = " + b.Add(string(purpose))
	secret, err := scanSecret(r.executor.QueryRowContext(ctx, query, b.Args()...))
	if err != nil {
		return domain.EncryptedSecret{}, fmt.Errorf("sqlstore secret: get encrypted value: %w", notFound(err))
	}
	return secret, nil
}

func (r *SecretRepository) InsertEncrypted(ctx context.Context, secret domain.EncryptedSecret) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateStoredSecret(secret); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "INSERT INTO private_key_secrets (key_material_id, purpose, encryption_generation_id, format_version, nonce, ciphertext) VALUES (" +
		b.Add(string(secret.OwnerKeyID())) + ", " + b.Add(string(secret.Purpose())) + ", " + b.Add(secret.EncryptionGenerationID()) + ", " +
		b.Add(secret.FormatVersion()) + ", " + b.Add(secret.Nonce()) + ", " + b.Add(secret.Ciphertext()) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrWrap("sqlstore secret: insert encrypted value", err)
	}
	return nil
}

func (r *SecretRepository) Delete(ctx context.Context, keyID domain.KeyMaterialID, purpose domain.SecretPurpose) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateSecretPurpose(purpose); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "DELETE FROM private_key_secrets WHERE key_material_id = " + b.Add(string(keyID)) + " AND purpose = " + b.Add(string(purpose))
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return fmt.Errorf("sqlstore secret: delete encrypted value: %w", err)
	}
	return nil
}

func (r *SecretRepository) ListEncrypted(ctx context.Context) ([]domain.EncryptedSecret, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	rows, err := r.executor.QueryContext(ctx, "SELECT key_material_id, purpose, format_version, encryption_generation_id, nonce, ciphertext FROM private_key_secrets ORDER BY key_material_id")
	if err != nil {
		return nil, fmt.Errorf("sqlstore secret: list encrypted values: %w", err)
	}
	defer rows.Close()
	out := make([]domain.EncryptedSecret, 0)
	for rows.Next() {
		secret, err := scanSecret(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlstore secret: scan encrypted value: %w", err)
		}
		out = append(out, secret)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore secret: list encrypted values: %w", err)
	}
	return out, nil
}

func (r *SecretRepository) ReplaceEncrypted(ctx context.Context, secret domain.EncryptedSecret) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateStoredSecret(secret); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE private_key_secrets SET purpose = " + b.Add(string(secret.Purpose())) + ", encryption_generation_id = " + b.Add(secret.EncryptionGenerationID()) +
		", format_version = " + b.Add(secret.FormatVersion()) + ", nonce = " + b.Add(secret.Nonce()) + ", ciphertext = " + b.Add(secret.Ciphertext()) +
		" WHERE key_material_id = " + b.Add(string(secret.OwnerKeyID())) + " AND purpose = " + b.Add(string(secret.Purpose()))
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return fmt.Errorf("sqlstore secret: replace encrypted value: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore secret: inspect replace result: %w", err)
	}
	if changed == 0 {
		return r.secretNotFound(ctx, secret.OwnerKeyID(), secret.Purpose())
	}
	return nil
}

func (r *SecretRepository) GetVerifier(ctx context.Context) (domain.EncryptedSecret, error) {
	if err := checkContext(ctx); err != nil {
		return domain.EncryptedSecret{}, err
	}
	var generation string
	var format int64
	var nonce, ciphertext []byte
	if err := r.executor.QueryRowContext(ctx, "SELECT encryption_generation_id, format_version, nonce, ciphertext FROM encryption_verifier WHERE id = 1").Scan(&generation, &format, &nonce, &ciphertext); err != nil {
		return domain.EncryptedSecret{}, fmt.Errorf("sqlstore secret: get verifier: %w", notFound(err))
	}
	version, err := secretFormatVersion(format)
	if err != nil {
		return domain.EncryptedSecret{}, err
	}
	return domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID:             domain.StoreVerifierOwnerKeyID,
		Purpose:                domain.SecretPurposeStoreVerifier,
		FormatVersion:          version,
		EncryptionGenerationID: generation,
		Nonce:                  nonce,
		Ciphertext:             ciphertext,
	})
}

func (r *SecretRepository) SaveVerifier(ctx context.Context, verifier domain.EncryptedSecret) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if verifier.IsZero() || verifier.Purpose() != domain.SecretPurposeStoreVerifier || verifier.OwnerKeyID() != domain.StoreVerifierOwnerKeyID {
		return errors.New("sqlstore secret: verifier must use the reserved owner, purpose, and ciphertext")
	}
	b := r.dialect.NewBuilder()
	insertGeneration := b.Add(verifier.EncryptionGenerationID())
	insertFormat := b.Add(verifier.FormatVersion())
	insertNonce := b.Add(verifier.Nonce())
	insertCiphertext := b.Add(verifier.Ciphertext())
	updateGeneration := b.Add(verifier.EncryptionGenerationID())
	updateFormat := b.Add(verifier.FormatVersion())
	updateNonce := b.Add(verifier.Nonce())
	updateCiphertext := b.Add(verifier.Ciphertext())
	values := "encryption_generation_id = " + updateGeneration + ", format_version = " + updateFormat +
		", nonce = " + updateNonce + ", ciphertext = " + updateCiphertext
	var query string
	switch r.dialect.Kind() {
	case config.Postgres, config.SQLite:
		query = "INSERT INTO encryption_verifier (id, encryption_generation_id, format_version, nonce, ciphertext) VALUES (1, " +
			insertGeneration + ", " + insertFormat + ", " + insertNonce + ", " + insertCiphertext +
			") ON CONFLICT (id) DO UPDATE SET " + values
	case config.MySQL, config.MariaDB:
		query = "INSERT INTO encryption_verifier (id, encryption_generation_id, format_version, nonce, ciphertext) VALUES (1, " +
			insertGeneration + ", " + insertFormat + ", " + insertNonce + ", " + insertCiphertext +
			") ON DUPLICATE KEY UPDATE " + values
	default:
		return fmt.Errorf("sqlstore secret: unsupported dialect %q", r.dialect.Kind())
	}
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return fmt.Errorf("sqlstore secret: save verifier: %w", err)
	}
	return nil
}

func (r *SecretRepository) secretNotFound(ctx context.Context, keyID domain.KeyMaterialID, purpose domain.SecretPurpose) error {
	b := r.dialect.NewBuilder()
	query := "SELECT 1 FROM private_key_secrets WHERE key_material_id = " + b.Add(string(keyID)) + " AND purpose = " + b.Add(string(purpose))
	var one int
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return port.ErrNotFound
		}
		return fmt.Errorf("sqlstore secret: check encrypted value: %w", err)
	}
	return nil
}

func scanSecret(row interface{ Scan(...any) error }) (domain.EncryptedSecret, error) {
	var keyID, purpose, generation string
	var format int64
	var nonce, ciphertext []byte
	if err := row.Scan(&keyID, &purpose, &format, &generation, &nonce, &ciphertext); err != nil {
		return domain.EncryptedSecret{}, err
	}
	version, err := secretFormatVersion(format)
	if err != nil {
		return domain.EncryptedSecret{}, err
	}
	return domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID:             domain.KeyMaterialID(keyID),
		Purpose:                domain.SecretPurpose(purpose),
		FormatVersion:          version,
		EncryptionGenerationID: generation,
		Nonce:                  nonce,
		Ciphertext:             ciphertext,
	})
}

func secretFormatVersion(format int64) (int, error) {
	if format <= 0 || int64(int(format)) != format {
		return 0, fmt.Errorf("sqlstore secret: invalid stored format version %d", format)
	}
	return int(format), nil
}

func validateStoredSecret(secret domain.EncryptedSecret) error {
	if secret.IsZero() {
		return errors.New("sqlstore secret: encrypted value is required")
	}
	if secret.Purpose() == domain.SecretPurposeStoreVerifier {
		return errors.New("sqlstore secret: verifier must use the verifier repository methods")
	}
	return validateSecretPurpose(secret.Purpose())
}

func validateSecretPurpose(purpose domain.SecretPurpose) error {
	if err := purpose.Validate(); err != nil {
		return fmt.Errorf("sqlstore secret: %w", err)
	}
	if purpose == domain.SecretPurposeStoreVerifier {
		return errors.New("sqlstore secret: verifier must use the verifier repository methods")
	}
	return nil
}
