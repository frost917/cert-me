package pki

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

const ValidityPolicySchemaVersion = 1

// ValidityPolicyJSONV1 is the versioned JSON shape stored in
// leaf_series.validity_policy_json. QueryRepository and replay code can use
// the corresponding codec below rather than depending on domain's private
// representation.
type ValidityPolicyJSONV1 struct {
	SchemaVersion int                   `json:"schema_version"`
	RotateEvery   int                   `json:"rotate_every"`
	Validity      ValidityPolicyValueV1 `json:"validity"`
}

// ValidityPolicyValueV1 carries calendar meaning without reducing the policy
// to a fixed duration.
type ValidityPolicyValueV1 struct {
	Value int    `json:"value"`
	Unit  string `json:"unit"`
}

func EncodeValidityPolicyV1(policy domain.SeriesPolicy) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(ValidityPolicyJSONV1{
		SchemaVersion: ValidityPolicySchemaVersion,
		RotateEvery:   policy.RotateEvery,
		Validity:      ValidityPolicyValueV1{Value: policy.CertificateValidity.Value(), Unit: string(policy.CertificateValidity.Unit())},
	})
}

func DecodeValidityPolicyV1(raw []byte) (domain.SeriesPolicy, error) {
	var stored ValidityPolicyJSONV1
	if err := decodeJSONStrict(raw, &stored); err != nil {
		return domain.SeriesPolicy{}, fmt.Errorf("invalid series validity policy JSON: %w", err)
	}
	if stored.SchemaVersion != ValidityPolicySchemaVersion {
		return domain.SeriesPolicy{}, fmt.Errorf("unsupported series validity policy schema version %d", stored.SchemaVersion)
	}
	validity, err := domain.NewCalendarValidity(stored.Validity.Value, domain.ValidityUnit(stored.Validity.Unit))
	if err != nil {
		return domain.SeriesPolicy{}, fmt.Errorf("invalid series validity policy: %w", err)
	}
	policy := domain.SeriesPolicy{RotateEvery: stored.RotateEvery, CertificateValidity: validity}
	if err := policy.Validate(); err != nil {
		return domain.SeriesPolicy{}, fmt.Errorf("invalid series policy: %w", err)
	}
	return policy, nil
}

func (r *Repository) GetSeriesForUpdate(ctx context.Context, seriesID domain.SeriesID) (port.SeriesSnapshot, error) {
	b := r.builder()
	p := b.Add(string(seriesID))
	query := "SELECT id, name, purpose, management_authority_id, current_certificate_id, current_key_generation_id, validity_policy_json, version, archived_at FROM leaf_series WHERE id = " + p + r.lockSuffix()
	var rawID, purpose, rawAuthority sql.NullString
	var name, policyJSON string
	var currentCertificate, currentGeneration sql.NullString
	var version int64
	var archived sql.NullInt64
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawID, &name, &purpose, &rawAuthority, &currentCertificate, &currentGeneration, &policyJSON, &version, &archived); err != nil {
		return port.SeriesSnapshot{}, missing(err)
	}
	if err := validateNullableTimestamp("series archived_at", archived); err != nil {
		return port.SeriesSnapshot{}, err
	}
	if version < 0 {
		return port.SeriesSnapshot{}, fmt.Errorf("pki: series version is negative")
	}
	id, err := parseSeriesID(rawID.String)
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	authorityID, err := parseAuthorityID(rawAuthority.String)
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	var certificateID domain.CertificateID
	if currentCertificate.Valid {
		certificateID, err = parseCertificateID(currentCertificate.String)
		if err != nil {
			return port.SeriesSnapshot{}, err
		}
	}
	var generationID domain.LeafKeyGenerationID
	if currentGeneration.Valid {
		generationID, err = parseLeafKeyGenerationID(currentGeneration.String)
		if err != nil {
			return port.SeriesSnapshot{}, err
		}
	}
	if (certificateID == "") != (generationID == "") {
		return port.SeriesSnapshot{}, fmt.Errorf("pki: series current certificate and key generation must be set together")
	}
	if certificateID != "" {
		if err := r.validateCurrentSeriesPair(ctx, id, certificateID, generationID); err != nil {
			return port.SeriesSnapshot{}, err
		}
	}
	policy, err := DecodeValidityPolicyV1([]byte(policyJSON))
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	archivedAt := instantFromNullable(archived)
	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID: id, Name: name, Purpose: domain.SeriesPurpose(purpose.String),
		ManagementAuthorityID: authorityID, CurrentCertificateID: certificateID,
		CurrentKeyGenerationID: generationID, Policy: policy,
		Version: domain.Version(version), ArchivedAt: archivedAt,
	})
	if err != nil {
		return port.SeriesSnapshot{}, fmt.Errorf("pki: decode leaf series: %w", err)
	}
	snapshot := port.SeriesSnapshot{Series: series}
	if generationID == "" {
		return snapshot, nil
	}
	genBuilder := r.builder()
	genIDP := genBuilder.Add(string(generationID))
	genQuery := "SELECT id, series_id, key_material_id, generation_no, renewal_count, prior_history_unknown, custody FROM leaf_key_generations WHERE id = " + genIDP + r.lockSuffix()
	var rawGenID, rawSeries, rawKey, custody string
	var generationNo, renewalCount int64
	var priorHistoryUnknown bool
	if err := r.queryRow(ctx, genQuery, genBuilder.Args()...).Scan(&rawGenID, &rawSeries, &rawKey, &generationNo, &renewalCount, &priorHistoryUnknown, &custody); err != nil {
		return port.SeriesSnapshot{}, missing(err)
	}
	parsedGenID, err := parseLeafKeyGenerationID(rawGenID)
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	ownerSeriesID, err := parseSeriesID(rawSeries)
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	if ownerSeriesID != id {
		return port.SeriesSnapshot{}, fmt.Errorf("pki: current leaf key generation belongs to a different series")
	}
	keyID, err := parseKeyMaterialID(rawKey)
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	generation, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
		ID: parsedGenID, SeriesID: ownerSeriesID, KeyMaterialID: keyID,
		GenerationNo: int(generationNo), RenewalCount: int(renewalCount),
		PriorHistoryUnknown: priorHistoryUnknown, Custody: domain.KeyCustody(custody),
	})
	if err != nil {
		return port.SeriesSnapshot{}, fmt.Errorf("pki: decode current leaf key generation: %w", err)
	}
	snapshot.CurrentKeyGeneration = generation
	return snapshot, nil
}

func (r *Repository) InsertLeafKeyGeneration(ctx context.Context, generation domain.LeafKeyGeneration) error {
	if err := validateLeafKeyGeneration(generation); err != nil {
		return fmt.Errorf("pki: invalid leaf key generation: %w", err)
	}
	b := r.builder()
	query := "INSERT INTO leaf_key_generations (id, created_at, series_id, key_material_id, generation_no, renewal_count, prior_history_unknown, custody) VALUES (" +
		b.Add(string(generation.ID())) + "," + r.databaseNowMicros() + "," + b.Add(string(generation.SeriesID())) + "," +
		b.Add(string(generation.KeyMaterialID())) + "," + b.Add(generation.GenerationNo()) + "," + b.Add(generation.RenewalCount()) + "," +
		b.Add(generation.PriorHistoryUnknown()) + "," + b.Add(string(generation.Custody())) + ")"
	_, err := r.exec.ExecContext(ctx, query, b.Args()...)
	return mapWriteError("pki: insert leaf key generation", err)
}

func (r *Repository) SaveLeafKeyGeneration(ctx context.Context, generation domain.LeafKeyGeneration) error {
	b := r.builder()
	query := "UPDATE leaf_key_generations SET renewal_count = " + b.Add(generation.RenewalCount()) + " WHERE id = " + b.Add(string(generation.ID()))
	result, err := r.exec.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return mapWriteError("pki: save leaf key generation", err)
	}
	n, err := rowsAffected(result, nil)
	if err != nil {
		return fmt.Errorf("pki: save leaf key generation rows affected: %w", err)
	}
	if n != 0 {
		return nil
	}
	exists, err := r.rowExists(ctx, "leaf_key_generations", "id", string(generation.ID()))
	if err != nil {
		return fmt.Errorf("pki: check leaf key generation after update: %w", err)
	}
	if !exists {
		return port.ErrNotFound
	}
	return nil
}

func (r *Repository) InsertSeries(ctx context.Context, series domain.LeafSeries) error {
	if err := validateSeries(series); err != nil {
		return fmt.Errorf("pki: invalid series: %w", err)
	}
	if series.CurrentCertificateID() != "" || series.CurrentKeyGenerationID() != "" {
		return fmt.Errorf("pki: a new series must be inserted without current certificate or key generation; use SaveSeries after inserting its leaf history")
	}
	policy, err := EncodeValidityPolicyV1(series.Policy())
	if err != nil {
		return fmt.Errorf("pki: encode series validity policy: %w", err)
	}
	b := r.builder()
	query := "INSERT INTO leaf_series (id, created_at, updated_at, version, name, purpose, management_authority_id, current_certificate_id, current_key_generation_id, validity_policy_json, rotate_every, archived_at) VALUES (" +
		b.Add(string(series.ID())) + "," + r.databaseNowMicros() + "," + r.databaseNowMicros() + "," + b.Add(series.Version().Int64()) + "," +
		b.Add(series.Name()) + "," + b.Add(string(series.Purpose())) + "," + b.Add(string(series.ManagementAuthorityID())) + "," +
		b.Add(nullableString(string(series.CurrentCertificateID()))) + "," + b.Add(nullableString(string(series.CurrentKeyGenerationID()))) + "," +
		b.Add(string(policy)) + "," + b.Add(series.Policy().RotateEvery) + "," + b.Add(nullableInstant(series.ArchivedAt())) + ")"
	_, err = r.exec.ExecContext(ctx, query, b.Args()...)
	return mapWriteError("pki: insert series", err)
}

func (r *Repository) SaveSeries(ctx context.Context, series domain.LeafSeries, expectedVersion domain.Version) error {
	if err := validateSeries(series); err != nil {
		return fmt.Errorf("pki: invalid series: %w", err)
	}
	policy, err := EncodeValidityPolicyV1(series.Policy())
	if err != nil {
		return fmt.Errorf("pki: encode series validity policy: %w", err)
	}
	if (series.CurrentCertificateID() == "") != (series.CurrentKeyGenerationID() == "") {
		return fmt.Errorf("pki: series current certificate and key generation must be set together")
	}
	if series.CurrentCertificateID() != "" {
		if err := r.validateCurrentSeriesPair(ctx, series.ID(), series.CurrentCertificateID(), series.CurrentKeyGenerationID()); err != nil {
			return err
		}
	}
	b := r.builder()
	query := "UPDATE leaf_series SET updated_at = " + r.databaseNowMicros() + ", version = " + b.Add(series.Version().Int64()) +
		", name = " + b.Add(series.Name()) + ", purpose = " + b.Add(string(series.Purpose())) +
		", management_authority_id = " + b.Add(string(series.ManagementAuthorityID())) +
		", current_certificate_id = " + b.Add(nullableString(string(series.CurrentCertificateID()))) +
		", current_key_generation_id = " + b.Add(nullableString(string(series.CurrentKeyGenerationID()))) +
		", validity_policy_json = " + b.Add(string(policy)) + ", rotate_every = " + b.Add(series.Policy().RotateEvery) +
		", archived_at = " + b.Add(nullableInstant(series.ArchivedAt())) + " WHERE id = " + b.Add(string(series.ID())) + " AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.exec.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return mapWriteError("pki: save series", err)
	}
	n, err := rowsAffected(result, nil)
	if err != nil {
		return fmt.Errorf("pki: save series rows affected: %w", err)
	}
	if n != 0 {
		return nil
	}
	if err := r.optimisticUpdateMiss(ctx, "leaf_series", string(series.ID()), expectedVersion); err != nil {
		return fmt.Errorf("pki: check series after optimistic update: %w", err)
	}
	return nil
}

func (r *Repository) validateCurrentSeriesPair(ctx context.Context, seriesID domain.SeriesID, certificateID domain.CertificateID, generationID domain.LeafKeyGenerationID) error {
	exists, err := r.rowExists(ctx, "leaf_series", "id", string(seriesID))
	if err != nil {
		return fmt.Errorf("pki: check series before validating its current certificate: %w", err)
	}
	if !exists {
		return port.ErrNotFound
	}
	b := r.builder()
	query := "SELECT COUNT(*) FROM leaf_certificates lc JOIN leaf_key_generations g ON g.id = lc.leaf_key_generation_id WHERE lc.certificate_id = " + b.Add(string(certificateID)) +
		" AND lc.series_id = " + b.Add(string(seriesID)) + " AND lc.leaf_key_generation_id = " + b.Add(string(generationID)) + " AND g.series_id = lc.series_id"
	var count int
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&count); err != nil {
		return fmt.Errorf("pki: validate current series certificate and generation: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("pki: series current certificate and key generation do not match its leaf history")
	}
	return nil
}
