package delivery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// GetGrantForUpdate locks the row while the caller validates and consumes or
// invalidates it in the same transaction. The raw bearer token is never read.
func (r *DeliveryRepository) GetGrantForUpdate(ctx context.Context, tokenHash domain.TokenHash) (domain.DownloadGrant, error) {
	if err := checkContext(ctx); err != nil {
		return domain.DownloadGrant{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT id, token_hash, purpose, certificate_id, key_delivery_id, expires_at, consumed_at, invalidated_at, created_by FROM download_tokens WHERE token_hash = " + b.Add(tokenHash.Hex()) + r.dialect.RowLockClause()
	grant, err := scanGrant(r.executor.QueryRowContext(ctx, query, b.Args()...))
	if err != nil {
		return domain.DownloadGrant{}, fmt.Errorf("sqlstore delivery: get grant for update: %w", notFound(err))
	}
	return grant, nil
}

// InsertGrant stores the grant and its actual account creator. The required
// created_by FK is never filled with a synthetic or system-wide identity.
func (r *DeliveryRepository) InsertGrant(ctx context.Context, grant domain.DownloadGrant) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if grant.CreatedByAccountID() == "" {
		return errors.New("sqlstore delivery: grant creator is required")
	}
	b := r.dialect.NewBuilder()
	query := "INSERT INTO download_tokens (id, created_at, token_hash, purpose, certificate_id, key_delivery_id, expires_at, consumed_at, invalidated_at, created_by) VALUES (" +
		b.Add(string(grant.ID())) + ", " + b.Add(databaseNowMicros()) + ", " + b.Add(grant.TokenHash().Hex()) + ", " +
		b.Add(string(grant.Purpose())) + ", " + b.Add(string(grant.CertificateID())) + ", " + nullableString(string(grant.DeliveryID()), b) + ", " +
		b.Add(grant.ExpiresAt().UnixMicro()) + ", " + nullableInstant(grant.ConsumedAt(), b) + ", " + nullableInstant(grant.InvalidatedAt(), b) + ", " +
		b.Add(string(grant.CreatedByAccountID())) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrWrap("sqlstore delivery: insert grant", err)
	}
	return nil
}

// SaveGrant uses the terminal timestamps as a portable compare-and-set token.
// download_tokens has no version column: under the supported lifecycle each
// issued grant starts at Version 1 and may make one transition to Version 2.
func (r *DeliveryRepository) SaveGrant(ctx context.Context, grant domain.DownloadGrant, expectedVersion domain.Version) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if expectedVersion == 1 {
		if grant.Version() != 2 || !isValidGrantTerminalState(grant) {
			return fmt.Errorf("sqlstore delivery: invalid grant transition from version %d", expectedVersion)
		}
		b := r.dialect.NewBuilder()
		query := "UPDATE download_tokens SET consumed_at = " + nullableInstant(grant.ConsumedAt(), b) + ", invalidated_at = " + nullableInstant(grant.InvalidatedAt(), b) +
			" WHERE id = " + b.Add(string(grant.ID())) + " AND consumed_at IS NULL AND invalidated_at IS NULL"
		result, err := r.executor.ExecContext(ctx, query, b.Args()...)
		if err != nil {
			return fmt.Errorf("sqlstore delivery: save grant: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlstore delivery: inspect grant save result: %w", err)
		}
		if changed > 0 {
			return nil
		}
		current, err := r.getGrantByID(ctx, grant.ID())
		if err != nil {
			return err
		}
		if current.Version() != expectedVersion {
			return port.ErrVersionConflict
		}
		if sameGrant(current, grant) {
			return nil
		}
		return port.ErrVersionConflict
	}
	if expectedVersion == 2 && grant.Version() == 2 {
		current, err := r.getGrantByID(ctx, grant.ID())
		if err != nil {
			return err
		}
		if current.Version() != expectedVersion {
			return port.ErrVersionConflict
		}
		if sameGrant(current, grant) {
			return nil
		}
		return port.ErrVersionConflict
	}
	return port.ErrVersionConflict
}

func (r *DeliveryRepository) InvalidatePrivateGrants(ctx context.Context, deliveryID domain.DeliveryID, now domain.Instant) error {
	return r.invalidateGrants(ctx, "purpose = 'leaf_private' AND key_delivery_id = ", string(deliveryID), now)
}

func (r *DeliveryRepository) InvalidatePublicGrants(ctx context.Context, certificateID domain.CertificateID, now domain.Instant) error {
	return r.invalidateGrants(ctx, "purpose = 'leaf_public' AND certificate_id = ", string(certificateID), now)
}

func (r *DeliveryRepository) InvalidateAllPublicGrants(ctx context.Context, now domain.Instant) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE download_tokens SET invalidated_at = " + b.Add(now.UnixMicro()) + " WHERE purpose = 'leaf_public' AND consumed_at IS NULL AND invalidated_at IS NULL"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return fmt.Errorf("sqlstore delivery: invalidate public grants: %w", err)
	}
	return nil
}

func (r *DeliveryRepository) invalidateGrants(ctx context.Context, predicate string, value string, now domain.Instant) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE download_tokens SET invalidated_at = " + b.Add(now.UnixMicro()) + " WHERE " + predicate + b.Add(value) + " AND consumed_at IS NULL AND invalidated_at IS NULL"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return fmt.Errorf("sqlstore delivery: invalidate grants: %w", err)
	}
	return nil
}

func (r *DeliveryRepository) getGrantByID(ctx context.Context, id domain.GrantID) (domain.DownloadGrant, error) {
	b := r.dialect.NewBuilder()
	query := "SELECT id, token_hash, purpose, certificate_id, key_delivery_id, expires_at, consumed_at, invalidated_at, created_by FROM download_tokens WHERE id = " + b.Add(string(id))
	grant, err := scanGrant(r.executor.QueryRowContext(ctx, query, b.Args()...))
	if err != nil {
		return domain.DownloadGrant{}, fmt.Errorf("sqlstore delivery: get grant: %w", notFound(err))
	}
	return grant, nil
}

func scanGrant(row interface{ Scan(...any) error }) (domain.DownloadGrant, error) {
	var id, tokenHash, purpose, certificateID, createdBy string
	var deliveryID sql.NullString
	var expiresAt int64
	var consumedAt, invalidatedAt sql.NullInt64
	if err := row.Scan(&id, &tokenHash, &purpose, &certificateID, &deliveryID, &expiresAt, &consumedAt, &invalidatedAt, &createdBy); err != nil {
		return domain.DownloadGrant{}, err
	}
	if consumedAt.Valid && invalidatedAt.Valid {
		return domain.DownloadGrant{}, errors.New("sqlstore delivery: grant is both consumed and invalidated")
	}
	grantID, err := domain.ParseGrantID(id)
	if err != nil {
		return domain.DownloadGrant{}, err
	}
	parsedHash, err := domain.ParseTokenHash(tokenHash)
	if err != nil {
		return domain.DownloadGrant{}, err
	}
	parsedCertificateID, err := domain.ParseCertificateID(certificateID)
	if err != nil {
		return domain.DownloadGrant{}, err
	}
	parsedCreatedBy, err := domain.ParseAccountID(createdBy)
	if err != nil {
		return domain.DownloadGrant{}, err
	}
	var parsedDeliveryID domain.DeliveryID
	if deliveryID.Valid {
		parsedDeliveryID, err = domain.ParseDeliveryID(deliveryID.String)
		if err != nil {
			return domain.DownloadGrant{}, err
		}
	}
	var consumed, invalidated domain.Instant
	version := domain.Version(1)
	if consumedAt.Valid {
		consumed = domain.InstantFromUnixMicro(consumedAt.Int64)
		version = 2
	}
	if invalidatedAt.Valid {
		invalidated = domain.InstantFromUnixMicro(invalidatedAt.Int64)
		version = 2
	}
	return domain.NewDownloadGrant(domain.DownloadGrantFacts{
		ID:            grantID,
		TokenHash:     parsedHash,
		Purpose:       domain.GrantPurpose(purpose),
		CertificateID: parsedCertificateID,
		DeliveryID:    parsedDeliveryID,
		CreatedBy:     parsedCreatedBy,
		ExpiresAt:     domain.InstantFromUnixMicro(expiresAt),
		ConsumedAt:    consumed,
		InvalidatedAt: invalidated,
		Version:       version,
	})
}

func isValidGrantTerminalState(grant domain.DownloadGrant) bool {
	consumed := !grant.ConsumedAt().IsZero()
	invalidated := !grant.InvalidatedAt().IsZero()
	return consumed != invalidated
}

func sameGrant(left, right domain.DownloadGrant) bool {
	return left.ID() == right.ID() && left.TokenHash().Equal(right.TokenHash()) &&
		left.Purpose() == right.Purpose() && left.CertificateID() == right.CertificateID() &&
		left.DeliveryID() == right.DeliveryID() && left.ExpiresAt().Equal(right.ExpiresAt()) &&
		left.CreatedByAccountID() == right.CreatedByAccountID() &&
		left.ConsumedAt().Equal(right.ConsumedAt()) && left.InvalidatedAt().Equal(right.InvalidatedAt()) &&
		left.Version() == right.Version()
}
