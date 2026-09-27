package pki

import (
	"context"
	"database/sql"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type authorityRow struct {
	id                    domain.AuthorityID
	kind                  domain.AuthorityKind
	name                  string
	parentID              domain.AuthorityID
	issuanceState         domain.IssuanceState
	issuanceCertificateID domain.CertificateID
	archivedAt            domain.Instant
	version               domain.Version
}

func (r *Repository) readAuthorityRow(ctx context.Context, id domain.AuthorityID, lock bool) (authorityRow, error) {
	b := r.builder()
	p := b.Add(string(id))
	query := "SELECT id, kind, name, management_parent_id, issuance_state, issuance_certificate_id, archived_at, version FROM authorities WHERE id = " + p
	if lock {
		query += r.lockSuffix()
	}
	var rawID, kind, parent, state, issuanceCertificate sql.NullString
	var archived, version sql.NullInt64
	var name string
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawID, &kind, &name, &parent, &state, &issuanceCertificate, &archived, &version); err != nil {
		return authorityRow{}, missing(err)
	}
	if err := validateNullableTimestamp("authority archived_at", archived); err != nil {
		return authorityRow{}, err
	}
	if version.Int64 < 0 {
		return authorityRow{}, fmt.Errorf("pki: authority version is negative")
	}
	parsedID, err := parseAuthorityID(rawID.String)
	if err != nil {
		return authorityRow{}, err
	}
	var parsedParent domain.AuthorityID
	if parent.Valid {
		parsedParent, err = parseAuthorityID(parent.String)
		if err != nil {
			return authorityRow{}, err
		}
	}
	var parsedIssuanceCertificate domain.CertificateID
	if issuanceCertificate.Valid {
		parsedIssuanceCertificate, err = parseCertificateID(issuanceCertificate.String)
		if err != nil {
			return authorityRow{}, err
		}
	}
	return authorityRow{
		id:                    parsedID,
		kind:                  domain.AuthorityKind(kind.String),
		name:                  name,
		parentID:              parsedParent,
		issuanceState:         domain.IssuanceState(state.String),
		issuanceCertificateID: parsedIssuanceCertificate,
		archivedAt:            instantFromNullable(archived),
		version:               domain.Version(version.Int64),
	}, nil
}

func (r *Repository) readKeyGenerationForAuthority(ctx context.Context, authority authorityRow, lock bool) (port.CAKeyGeneration, error) {
	var query string
	var args []any
	if authority.issuanceCertificateID != "" {
		b := r.builder()
		p1 := b.Add(string(authority.issuanceCertificateID))
		p2 := b.Add(string(authority.id))
		query = "SELECT id, authority_id, key_material_id, generation_no, key_destroyed_at FROM ca_key_generations WHERE id = (SELECT cc.ca_key_generation_id FROM ca_certificates cc WHERE cc.certificate_id = " + p1 + ") AND authority_id = " + p2
		args = b.Args()
	} else {
		b := r.builder()
		p := b.Add(string(authority.id))
		query = "SELECT id, authority_id, key_material_id, generation_no, key_destroyed_at FROM ca_key_generations WHERE authority_id = " + p + " ORDER BY generation_no DESC LIMIT 1"
		args = b.Args()
	}
	if lock {
		query += r.lockSuffix()
	}
	var rawID, rawAuthority, rawKey string
	var generationNo int64
	var destroyed sql.NullInt64
	if err := r.queryRow(ctx, query, args...).Scan(&rawID, &rawAuthority, &rawKey, &generationNo, &destroyed); err != nil {
		return port.CAKeyGeneration{}, missing(err)
	}
	if err := validateNullableTimestamp("CA key destroyed_at", destroyed); err != nil {
		return port.CAKeyGeneration{}, err
	}
	if generationNo < 0 {
		return port.CAKeyGeneration{}, fmt.Errorf("pki: CA key generation number is negative")
	}
	id, err := parseCAKeyGenerationID(rawID)
	if err != nil {
		return port.CAKeyGeneration{}, err
	}
	ownerID, err := parseAuthorityID(rawAuthority)
	if err != nil {
		return port.CAKeyGeneration{}, err
	}
	keyID, err := parseKeyMaterialID(rawKey)
	if err != nil {
		return port.CAKeyGeneration{}, err
	}
	if ownerID != authority.id {
		return port.CAKeyGeneration{}, fmt.Errorf("pki: CA key generation %s belongs to unexpected authority %s", id, ownerID)
	}
	return port.CAKeyGeneration{ID: id, AuthorityID: ownerID, KeyMaterialID: keyID, GenerationNo: int(generationNo), KeyDestroyedAt: instantFromNullable(destroyed)}, nil
}

func (r *Repository) loadAuthority(ctx context.Context, id domain.AuthorityID, lock bool) (domain.Authority, error) {
	a, err := r.readAuthorityRow(ctx, id, lock)
	if err != nil {
		return domain.Authority{}, err
	}
	generation, err := r.readKeyGenerationForAuthority(ctx, a, lock)
	if err != nil {
		if err == port.ErrNotFound {
			return domain.Authority{}, fmt.Errorf("pki: authority %s has no CA key generation: %w", a.id, err)
		}
		return domain.Authority{}, err
	}
	keyAvailable := generation.KeyDestroyedAt.IsZero()
	return r.authorityFromFacts(ctx, a, generation, keyAvailable)
}

// certificateWindow is loaded separately to keep the selected row locking
// limited to the authority and its current CA key generation.
func (r *Repository) authorityFromFacts(ctx context.Context, a authorityRow, generation port.CAKeyGeneration, keyAvailable bool) (domain.Authority, error) {
	var window domain.ValidityWindow
	if a.issuanceCertificateID != "" {
		b := r.builder()
		p := b.Add(string(a.issuanceCertificateID))
		var notBefore, notAfter int64
		if err := r.queryRow(ctx, "SELECT not_before, not_after FROM certificates WHERE id = "+p, b.Args()...).Scan(&notBefore, &notAfter); err != nil {
			return domain.Authority{}, fmt.Errorf("pki: read authority certificate window: %w", missing(err))
		}
		var err error
		window, err = domain.NewValidityWindow(instantFromInt64(notBefore), instantFromInt64(notAfter))
		if err != nil {
			return domain.Authority{}, fmt.Errorf("pki: invalid authority certificate window: %w", err)
		}
	}
	pendingTakeover, err := r.pendingTakeover(ctx, generation.ID)
	if err != nil {
		return domain.Authority{}, err
	}
	affected, err := r.hasEmergencyImpact(ctx, a.id)
	if err != nil {
		return domain.Authority{}, err
	}
	return domain.NewAuthority(domain.AuthorityFacts{
		ID: a.id, Kind: a.kind, Name: a.name, ManagementParentID: a.parentID,
		IssuanceState: a.issuanceState, IssuanceCertificateID: a.issuanceCertificateID,
		KeyGenerationID: generation.ID, KeyAvailable: keyAvailable, Affected: affected,
		PendingTakeover: pendingTakeover, CertificateWindow: window,
		ArchivedAt: a.archivedAt, Version: a.version,
	})
}

func (r *Repository) pendingTakeover(ctx context.Context, generationID domain.CAKeyGenerationID) (bool, error) {
	b := r.builder()
	p := b.Add(string(generationID))
	var exists bool
	err := r.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM ca_takeovers WHERE ca_key_generation_id = "+p+" AND state = 'pending')", b.Args()...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("pki: read takeover state: %w", err)
	}
	return exists, nil
}

// An emergency transition affects its source and every management descendant
// until that transition closes. The recursive set walks from the authority
// toward its ancestors, while UNION prevents corrupt cycles from looping.
func (r *Repository) hasEmergencyImpact(ctx context.Context, authorityID domain.AuthorityID) (bool, error) {
	b := r.builder()
	p := b.Add(string(authorityID))
	query := "WITH RECURSIVE ancestors(id, parent_id) AS (" +
		"SELECT id, management_parent_id FROM authorities WHERE id = " + p +
		" UNION SELECT a.id, a.management_parent_id FROM authorities a JOIN ancestors x ON x.parent_id = a.id" +
		") SELECT EXISTS (SELECT 1 FROM ca_transitions t JOIN ancestors a ON a.id = t.source_authority_id WHERE t.mode = 'emergency' AND t.state <> 'closed')"
	var exists bool
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&exists); err != nil {
		return false, fmt.Errorf("pki: read emergency impact: %w", err)
	}
	return exists, nil
}

func (r *Repository) GetIssuerForUpdate(ctx context.Context, authorityID domain.AuthorityID) (domain.Authority, error) {
	a, err := r.readAuthorityRow(ctx, authorityID, true)
	if err != nil {
		return domain.Authority{}, err
	}
	generation, err := r.readKeyGenerationForAuthority(ctx, a, true)
	if err != nil {
		return domain.Authority{}, err
	}
	return r.authorityFromFacts(ctx, a, generation, generation.KeyDestroyedAt.IsZero())
}

func (r *Repository) InsertAuthority(ctx context.Context, authority domain.Authority) error {
	if err := validateAuthority(authority); err != nil {
		return fmt.Errorf("pki: invalid authority: %w", err)
	}
	b := r.builder()
	query := "INSERT INTO authorities (id, created_at, updated_at, version, kind, name, management_parent_id, issuance_state, issuance_certificate_id, archived_at) VALUES (" +
		b.Add(string(authority.ID())) + "," + r.databaseNowMicros() + "," + r.databaseNowMicros() + "," + b.Add(authority.Version().Int64()) + "," +
		b.Add(string(authority.Kind())) + "," + b.Add(authority.Name()) + "," + b.Add(nullableString(string(authority.ManagementParentID()))) + "," +
		b.Add(string(authority.IssuanceState())) + "," + b.Add(nullableString(string(authority.IssuanceCertificateID()))) + "," +
		b.Add(nullableInstant(authority.ArchivedAt())) + ")"
	_, err := r.exec.ExecContext(ctx, query, b.Args()...)
	return mapWriteError("pki: insert authority", err)
}

func (r *Repository) InsertKeyGeneration(ctx context.Context, generation port.CAKeyGeneration) error {
	if _, err := domain.ParseCAKeyGenerationID(string(generation.ID)); err != nil {
		return fmt.Errorf("pki: invalid CA key generation id: %w", err)
	}
	if _, err := domain.ParseAuthorityID(string(generation.AuthorityID)); err != nil {
		return fmt.Errorf("pki: invalid CA key generation authority id: %w", err)
	}
	if _, err := domain.ParseKeyMaterialID(string(generation.KeyMaterialID)); err != nil {
		return fmt.Errorf("pki: invalid CA key generation key material id: %w", err)
	}
	if generation.GenerationNo < 0 {
		return fmt.Errorf("pki: CA key generation number must not be negative")
	}
	b := r.builder()
	query := "INSERT INTO ca_key_generations (id, created_at, authority_id, key_material_id, generation_no, key_destroyed_at) VALUES (" +
		b.Add(string(generation.ID)) + "," + r.databaseNowMicros() + "," + b.Add(string(generation.AuthorityID)) + "," +
		b.Add(string(generation.KeyMaterialID)) + "," + b.Add(generation.GenerationNo) + "," + b.Add(nullableInstant(generation.KeyDestroyedAt)) + ")"
	_, err := r.exec.ExecContext(ctx, query, b.Args()...)
	return mapWriteError("pki: insert CA key generation", err)
}

func (r *Repository) SaveAuthority(ctx context.Context, authority domain.Authority, expectedVersion domain.Version) error {
	if err := validateAuthority(authority); err != nil {
		return fmt.Errorf("pki: invalid authority: %w", err)
	}
	b := r.builder()
	query := "UPDATE authorities SET updated_at = " + r.databaseNowMicros() + ", version = " + b.Add(authority.Version().Int64()) +
		", kind = " + b.Add(string(authority.Kind())) + ", name = " + b.Add(authority.Name()) +
		", management_parent_id = " + b.Add(nullableString(string(authority.ManagementParentID()))) +
		", issuance_state = " + b.Add(string(authority.IssuanceState())) +
		", issuance_certificate_id = " + b.Add(nullableString(string(authority.IssuanceCertificateID()))) +
		", archived_at = " + b.Add(nullableInstant(authority.ArchivedAt())) +
		" WHERE id = " + b.Add(string(authority.ID())) + " AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.exec.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return mapWriteError("pki: save authority", err)
	}
	n, err := rowsAffected(result, nil)
	if err != nil {
		return fmt.Errorf("pki: save authority rows affected: %w", err)
	}
	if n != 0 {
		return nil
	}
	if err := r.optimisticUpdateMiss(ctx, "authorities", string(authority.ID()), expectedVersion); err != nil {
		return fmt.Errorf("pki: check authority after optimistic update: %w", err)
	}
	return nil
}

func (r *Repository) SaveCAKeyGeneration(ctx context.Context, generation port.CAKeyGeneration) error {
	b := r.builder()
	p := b.Add(string(generation.ID))
	query := "SELECT key_destroyed_at FROM ca_key_generations WHERE id = " + p
	if r.lockSuffix() != "" {
		query += r.lockSuffix()
	}
	var previous sql.NullInt64
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&previous); err != nil {
		return missing(err)
	}
	if err := validateNullableTimestamp("CA key destroyed_at", previous); err != nil {
		return err
	}
	if previous.Valid && generation.KeyDestroyedAt.IsZero() {
		return domain.ErrConflict
	}
	b = r.builder()
	query = "UPDATE ca_key_generations SET key_destroyed_at = " + b.Add(nullableInstant(generation.KeyDestroyedAt)) + " WHERE id = " + b.Add(string(generation.ID))
	_, err := r.exec.ExecContext(ctx, query, b.Args()...)
	return mapWriteError("pki: save CA key generation", err)
}

func (r *Repository) GetCAKeyGeneration(ctx context.Context, id domain.CAKeyGenerationID) (port.CAKeyGeneration, error) {
	b := r.builder()
	p := b.Add(string(id))
	var rawID, rawAuthority, rawKey string
	var generationNo int64
	var destroyed sql.NullInt64
	err := r.queryRow(ctx, "SELECT id, authority_id, key_material_id, generation_no, key_destroyed_at FROM ca_key_generations WHERE id = "+p, b.Args()...).Scan(&rawID, &rawAuthority, &rawKey, &generationNo, &destroyed)
	if err != nil {
		return port.CAKeyGeneration{}, missing(err)
	}
	if err := validateNullableTimestamp("CA key destroyed_at", destroyed); err != nil {
		return port.CAKeyGeneration{}, err
	}
	if generationNo < 0 {
		return port.CAKeyGeneration{}, fmt.Errorf("pki: CA key generation number is negative")
	}
	parsedID, err := parseCAKeyGenerationID(rawID)
	if err != nil {
		return port.CAKeyGeneration{}, err
	}
	authorityID, err := parseAuthorityID(rawAuthority)
	if err != nil {
		return port.CAKeyGeneration{}, err
	}
	keyID, err := parseKeyMaterialID(rawKey)
	if err != nil {
		return port.CAKeyGeneration{}, err
	}
	return port.CAKeyGeneration{ID: parsedID, AuthorityID: authorityID, KeyMaterialID: keyID, GenerationNo: int(generationNo), KeyDestroyedAt: instantFromNullable(destroyed)}, nil
}
