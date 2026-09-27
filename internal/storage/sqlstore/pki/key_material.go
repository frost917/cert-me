package pki

import (
	"context"
	"database/sql"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func (r *Repository) readKeyMaterial(ctx context.Context, where string, args ...any) (port.KeyMaterial, error) {
	query := "SELECT id, spki_sha256, spki_der, algorithm, origin, compromised_at FROM key_materials WHERE " + where
	var rawID, rawHash, algorithm, origin string
	var spki []byte
	var compromised sql.NullInt64
	if err := r.queryRow(ctx, query, args...).Scan(&rawID, &rawHash, &spki, &algorithm, &origin, &compromised); err != nil {
		return port.KeyMaterial{}, missing(err)
	}
	if err := validateNullableTimestamp("key material compromised_at", compromised); err != nil {
		return port.KeyMaterial{}, err
	}
	id, err := parseKeyMaterialID(rawID)
	if err != nil {
		return port.KeyMaterial{}, err
	}
	fingerprint, err := domain.ParseFingerprint(rawHash)
	if err != nil {
		return port.KeyMaterial{}, fmt.Errorf("invalid SPKI fingerprint in database: %w", err)
	}
	publicKey, err := domain.NewPublicKey(domain.KeyAlgorithm(algorithm), spki)
	if err != nil {
		return port.KeyMaterial{}, fmt.Errorf("invalid public key in database: %w", err)
	}
	if !fingerprint.Equal(publicKey.Fingerprint()) {
		return port.KeyMaterial{}, fmt.Errorf("pki: stored SPKI fingerprint does not match SPKI DER")
	}
	if origin != "generated" && origin != "imported" {
		return port.KeyMaterial{}, fmt.Errorf("pki: unsupported key material origin %q", origin)
	}
	return port.KeyMaterial{ID: id, PublicKey: publicKey, Origin: origin, CompromisedAt: instantFromNullable(compromised)}, nil
}

func (r *Repository) FindKeyBySPKI(ctx context.Context, spkiSHA256 domain.Fingerprint) (port.KeyMaterial, error) {
	b := r.builder()
	return r.readKeyMaterial(ctx, "spki_sha256 = "+b.Add(spkiSHA256.Hex()), b.Args()...)
}

func (r *Repository) GetKeyMaterial(ctx context.Context, id domain.KeyMaterialID) (port.KeyMaterial, error) {
	b := r.builder()
	return r.readKeyMaterial(ctx, "id = "+b.Add(string(id)), b.Args()...)
}

func (r *Repository) InsertKeyMaterial(ctx context.Context, material port.KeyMaterial) error {
	if _, err := domain.ParseKeyMaterialID(string(material.ID)); err != nil {
		return fmt.Errorf("pki: invalid key material id: %w", err)
	}
	if material.PublicKey.IsZero() {
		return fmt.Errorf("pki: public key is required")
	}
	if err := material.PublicKey.Algorithm().Validate(); err != nil {
		return fmt.Errorf("pki: invalid public key algorithm: %w", err)
	}
	if material.Origin != "generated" && material.Origin != "imported" {
		return fmt.Errorf("pki: invalid key material origin %q", material.Origin)
	}
	spki := material.PublicKey.SPKIDER()
	fingerprint := material.PublicKey.Fingerprint()
	if material.CompromisedAt.IsZero() {
		// NULL is the canonical absence marker.
	} else if material.CompromisedAt.UnixMicro() == 0 {
		return fmt.Errorf("pki: compromised timestamp must be nonzero")
	}
	b := r.builder()
	query := "INSERT INTO key_materials (id, created_at, spki_sha256, spki_der, algorithm, parameters_json, origin, compromised_at) VALUES (" +
		b.Add(string(material.ID)) + "," + r.databaseNowMicros() + "," + b.Add(fingerprint.Hex()) + "," + b.Add(spki) + "," +
		b.Add(material.PublicKey.Algorithm().String()) + "," + b.Add("{}") + "," + b.Add(material.Origin) + "," +
		b.Add(nullableInstant(material.CompromisedAt)) + ")"
	_, err := r.exec.ExecContext(ctx, query, b.Args()...)
	return mapWriteError("pki: insert key material", err)
}

func (r *Repository) MarkCompromised(ctx context.Context, id domain.KeyMaterialID, compromisedAt domain.Instant) error {
	if compromisedAt.IsZero() {
		return fmt.Errorf("pki: compromised timestamp must be nonzero")
	}
	b := r.builder()
	query := "UPDATE key_materials SET compromised_at = " + b.Add(compromisedAt.UnixMicro()) +
		" WHERE id = " + b.Add(string(id)) + " AND (compromised_at IS NULL OR compromised_at > " + b.Add(compromisedAt.UnixMicro()) + ")"
	if _, err := r.exec.ExecContext(ctx, query, b.Args()...); err != nil {
		return mapWriteError("pki: mark key material compromised", err)
	}
	exists, err := r.rowExists(ctx, "key_materials", "id", string(id))
	if err != nil {
		return fmt.Errorf("pki: check key material after compromise update: %w", err)
	}
	if !exists {
		return port.ErrNotFound
	}
	return nil
}
