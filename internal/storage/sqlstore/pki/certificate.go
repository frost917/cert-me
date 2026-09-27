package pki

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

const (
	// CertificateMetadataSchemaVersion is the version written to
	// certificates.extensions_json by this adapter.
	CertificateMetadataSchemaVersion = 1
)

// CertificateSubjectJSONV1 is the stable JSON representation of the subject
// projection stored in certificates.subject_json.
type CertificateSubjectJSONV1 struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
}

// CertificateExtensionsJSONV1 contains typed metadata not represented by
// certificate_sans or the public key row. SAN values remain in their own
// ordered table; the key algorithm is owned by key_materials.
type CertificateExtensionsJSONV1 struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Profile       string `json:"profile,omitempty"`
}

func EncodeCertificateSubjectV1(subject domain.Subject) ([]byte, error) {
	return json.Marshal(CertificateSubjectJSONV1{
		CommonName: subject.CommonName(), Organization: subject.Organization(),
		OrganizationalUnit: subject.OrganizationalUnit(), Country: subject.Country(),
	})
}

func DecodeCertificateSubjectV1(raw []byte) (domain.Subject, error) {
	var stored CertificateSubjectJSONV1
	if err := decodeJSONStrict(raw, &stored); err != nil {
		return domain.Subject{}, fmt.Errorf("invalid certificate subject JSON: %w", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{
		CommonName: stored.CommonName, Organization: stored.Organization,
		OrganizationalUnit: stored.OrganizationalUnit, Country: stored.Country,
	})
	if err != nil {
		return domain.Subject{}, fmt.Errorf("invalid certificate subject: %w", err)
	}
	return subject, nil
}

func EncodeCertificateExtensionsV1(kind domain.CertificateKind, profile domain.CertificateProfile) ([]byte, error) {
	if err := kind.Validate(); err != nil {
		return nil, err
	}
	if kind == domain.CertificateKindLeaf {
		if err := profile.Validate(); err != nil {
			return nil, err
		}
	} else if profile != "" {
		return nil, fmt.Errorf("CA certificate cannot carry leaf profile %q", profile)
	}
	return json.Marshal(CertificateExtensionsJSONV1{
		SchemaVersion: CertificateMetadataSchemaVersion, Kind: string(kind), Profile: string(profile),
	})
}

func DecodeCertificateExtensionsV1(raw []byte) (CertificateExtensionsJSONV1, error) {
	var stored CertificateExtensionsJSONV1
	if err := decodeJSONStrict(raw, &stored); err != nil {
		return CertificateExtensionsJSONV1{}, fmt.Errorf("invalid certificate extension metadata JSON: %w", err)
	}
	if stored.SchemaVersion != CertificateMetadataSchemaVersion {
		return CertificateExtensionsJSONV1{}, fmt.Errorf("unsupported certificate metadata schema version %d", stored.SchemaVersion)
	}
	kind := domain.CertificateKind(stored.Kind)
	if err := kind.Validate(); err != nil {
		return CertificateExtensionsJSONV1{}, err
	}
	if kind == domain.CertificateKindLeaf {
		if err := domain.CertificateProfile(stored.Profile).Validate(); err != nil {
			return CertificateExtensionsJSONV1{}, err
		}
	} else if stored.Profile != "" {
		return CertificateExtensionsJSONV1{}, fmt.Errorf("CA certificate has leaf profile metadata")
	}
	return stored, nil
}

type certificateDBRow struct {
	id             string
	derHash        string
	der            []byte
	keyID          string
	issuerID       string
	serial         string
	notBefore      int64
	notAfter       int64
	subjectJSON    string
	extensionsJSON string
	origin         string
	createdBy      sql.NullString
	algorithm      string
}

func (r *Repository) readCertificate(ctx context.Context, query string, args ...any) (domain.Certificate, error) {
	var row certificateDBRow
	if err := r.queryRow(ctx, query, args...).Scan(
		&row.id, &row.derHash, &row.der, &row.keyID, &row.issuerID, &row.serial,
		&row.notBefore, &row.notAfter, &row.subjectJSON, &row.extensionsJSON,
		&row.origin, &row.createdBy, &row.algorithm,
	); err != nil {
		return domain.Certificate{}, missing(err)
	}
	return r.certificateFromRow(ctx, row)
}

func (r *Repository) certificateFromRow(ctx context.Context, row certificateDBRow) (domain.Certificate, error) {
	id, err := parseCertificateID(row.id)
	if err != nil {
		return domain.Certificate{}, err
	}
	keyID, err := parseKeyMaterialID(row.keyID)
	if err != nil {
		return domain.Certificate{}, err
	}
	issuerID, err := parseCAKeyGenerationID(row.issuerID)
	if err != nil {
		return domain.Certificate{}, err
	}
	serial, err := domain.ParseSerialNumber(row.serial)
	if err != nil {
		return domain.Certificate{}, fmt.Errorf("invalid certificate serial in database: %w", err)
	}
	fingerprint, err := domain.ParseFingerprint(row.derHash)
	if err != nil {
		return domain.Certificate{}, fmt.Errorf("invalid certificate fingerprint in database: %w", err)
	}
	if !fingerprint.Equal(domain.NewFingerprint(row.der)) {
		return domain.Certificate{}, fmt.Errorf("pki: stored certificate DER fingerprint does not match DER")
	}
	window, err := domain.NewValidityWindow(instantFromInt64(row.notBefore), instantFromInt64(row.notAfter))
	if err != nil {
		return domain.Certificate{}, fmt.Errorf("invalid certificate validity in database: %w", err)
	}
	subject, err := DecodeCertificateSubjectV1([]byte(row.subjectJSON))
	if err != nil {
		return domain.Certificate{}, err
	}
	metadata, err := DecodeCertificateExtensionsV1([]byte(row.extensionsJSON))
	if err != nil {
		return domain.Certificate{}, err
	}
	algorithm := domain.KeyAlgorithm(row.algorithm)
	if err := algorithm.Validate(); err != nil {
		return domain.Certificate{}, fmt.Errorf("invalid certificate key algorithm in database: %w", err)
	}
	var createdBy domain.AccountID
	if row.createdBy.Valid {
		createdBy, err = domain.ParseAccountID(row.createdBy.String)
		if err != nil {
			return domain.Certificate{}, fmt.Errorf("invalid certificate creator id in database: %w", err)
		}
	}
	sans, err := r.readCertificateSANs(ctx, id)
	if err != nil {
		return domain.Certificate{}, err
	}
	leaf, ca, err := r.certificateSubtypes(ctx, id)
	if err != nil {
		return domain.Certificate{}, err
	}
	if leaf == ca {
		return domain.Certificate{}, fmt.Errorf("pki: certificate %s must have exactly one subtype", id)
	}
	kind := domain.CertificateKindCA
	if leaf {
		kind = domain.CertificateKindLeaf
	}
	if metadata.Kind != string(kind) {
		return domain.Certificate{}, fmt.Errorf("pki: certificate %s metadata disagrees with its subtype", id)
	}
	if leaf {
		bootstrapSeries, err := r.certificateUsesBootstrapSeries(ctx, id)
		if err != nil {
			return domain.Certificate{}, err
		}
		for _, san := range sans {
			if san.Type() == domain.SANTypeDNS && san.Value() == "cert-me" && !bootstrapSeries {
				return domain.Certificate{}, fmt.Errorf("pki: bootstrap-only SAN appears on a non-bootstrap certificate")
			}
		}
	} else {
		for _, san := range sans {
			if san.Type() == domain.SANTypeDNS && san.Value() == "cert-me" {
				return domain.Certificate{}, fmt.Errorf("pki: bootstrap-only SAN appears on a CA certificate")
			}
		}
	}
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID: id, DER: row.der, KeyMaterialID: keyID, IssuerCAKeyGenerationID: issuerID,
		Serial: serial, Validity: window, Subject: subject, SANs: sans,
		Kind: kind, Profile: domain.CertificateProfile(metadata.Profile),
		KeyAlgorithm: algorithm, Origin: domain.CertificateOrigin(row.origin),
		CreatedByAccountID: createdBy,
	})
	if err != nil {
		return domain.Certificate{}, fmt.Errorf("pki: decode certificate %s: %w", id, err)
	}
	return cert, nil
}

func (r *Repository) certificateUsesBootstrapSeries(ctx context.Context, id domain.CertificateID) (bool, error) {
	b := r.builder()
	query := "SELECT s.purpose FROM leaf_certificates lc JOIN leaf_series s ON s.id = lc.series_id WHERE lc.certificate_id = " + b.Add(string(id))
	var purpose string
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&purpose); err != nil {
		return false, fmt.Errorf("pki: read leaf certificate series purpose: %w", missing(err))
	}
	return domain.SeriesPurpose(purpose) == domain.SeriesPurposeBootstrapTLS, nil
}

func (r *Repository) certificateSubtypes(ctx context.Context, id domain.CertificateID) (leaf, ca bool, err error) {
	// The same ID appears twice, so add it twice for both numbered and
	// question-mark dialects.
	b2 := r.builder()
	query := "SELECT EXISTS (SELECT 1 FROM leaf_certificates WHERE certificate_id = " + b2.Add(string(id)) + "), EXISTS (SELECT 1 FROM ca_certificates WHERE certificate_id = " + b2.Add(string(id)) + ")"
	err = r.queryRow(ctx, query, b2.Args()...).Scan(&leaf, &ca)
	return leaf, ca, err
}

func (r *Repository) readCertificateSANs(ctx context.Context, certificateID domain.CertificateID) ([]domain.SAN, error) {
	b := r.builder()
	p := b.Add(string(certificateID))
	rows, err := r.exec.QueryContext(ctx, "SELECT position, type, normalized_value, normalized_value_hash FROM certificate_sans WHERE certificate_id = "+p+" ORDER BY position", b.Args()...)
	if err != nil {
		return nil, fmt.Errorf("pki: list certificate SANs: %w", err)
	}
	defer rows.Close()
	sans := make([]domain.SAN, 0)
	for rows.Next() {
		var position int64
		var kind, value, hash string
		if err := rows.Scan(&position, &kind, &value, &hash); err != nil {
			return nil, fmt.Errorf("pki: scan certificate SAN: %w", err)
		}
		if position != int64(len(sans)) {
			return nil, fmt.Errorf("pki: certificate SAN positions are not contiguous")
		}
		san, err := newStoredSAN(domain.SANType(kind), value)
		if err != nil {
			return nil, fmt.Errorf("pki: invalid stored SAN: %w", err)
		}
		if san.Value() != value {
			return nil, fmt.Errorf("pki: stored SAN value is not normalized")
		}
		h := sha256.Sum256([]byte(value))
		if hash != hex.EncodeToString(h[:]) {
			return nil, fmt.Errorf("pki: stored SAN hash does not match value")
		}
		sans = append(sans, san)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pki: iterate certificate SANs: %w", err)
	}
	return sans, nil
}

func newStoredSAN(kind domain.SANType, value string) (domain.SAN, error) {
	if kind == domain.SANTypeDNS && value == "cert-me" {
		return domain.NewBootstrapDNSNameSAN()
	}
	return domain.NewSAN(kind, value)
}

func (r *Repository) certificateSelect(where string, args ...any) (string, []any) {
	query := "SELECT c.id, c.der_sha256, c.der, c.key_material_id, c.issuer_ca_key_generation_id, c.serial_hex, c.not_before, c.not_after, c.subject_json, c.extensions_json, c.origin, c.created_by, km.algorithm FROM certificates c JOIN key_materials km ON km.id = c.key_material_id WHERE " + where
	return query, args
}

func (r *Repository) GetCertificate(ctx context.Context, id domain.CertificateID) (domain.Certificate, error) {
	b := r.builder()
	query, args := r.certificateSelect("c.id = "+b.Add(string(id)), b.Args()...)
	return r.readCertificate(ctx, query, args...)
}

func (r *Repository) FindCertificateByDER(ctx context.Context, derSHA256 domain.Fingerprint) (domain.Certificate, error) {
	b := r.builder()
	query, args := r.certificateSelect("c.der_sha256 = "+b.Add(derSHA256.Hex()), b.Args()...)
	return r.readCertificate(ctx, query, args...)
}

func (r *Repository) FindCertificateByIssuerSerial(ctx context.Context, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) (domain.Certificate, error) {
	b := r.builder()
	query, args := r.certificateSelect("c.issuer_ca_key_generation_id = "+b.Add(string(issuer))+" AND c.serial_hex = "+b.Add(serial.Hex()), b.Args()...)
	return r.readCertificate(ctx, query, args...)
}

func (r *Repository) SerialExists(ctx context.Context, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) (bool, error) {
	b := r.builder()
	pIssuer, pSerial := b.Add(string(issuer)), b.Add(serial.Hex())
	query := "SELECT EXISTS (SELECT 1 FROM certificates WHERE issuer_ca_key_generation_id = " + pIssuer + " AND serial_hex = " + pSerial +
		" UNION ALL SELECT 1 FROM revocations WHERE issuer_ca_key_generation_id = " + pIssuer + " AND serial_hex = " + pSerial + ")"
	// Question-mark placeholder dialects require the repeated filter values in
	// the matching argument positions; Builder emits $1/$2 for PostgreSQL.
	args := b.Args()
	if r.dialect.Kind() != "postgres" {
		args = append(args, string(issuer), serial.Hex())
	}
	var exists bool
	if err := r.queryRow(ctx, query, args...).Scan(&exists); err != nil {
		return false, fmt.Errorf("pki: check serial use: %w", err)
	}
	return exists, nil
}

func (r *Repository) InsertCertificate(ctx context.Context, certificate domain.Certificate) error {
	if err := validateCertificate(certificate); err != nil {
		return fmt.Errorf("pki: invalid certificate: %w", err)
	}
	b := r.builder()
	var keyAlgorithm string
	if err := r.queryRow(ctx, "SELECT algorithm FROM key_materials WHERE id = "+b.Add(string(certificate.KeyMaterialID())), b.Args()...).Scan(&keyAlgorithm); err != nil {
		return fmt.Errorf("pki: read certificate key material: %w", missing(err))
	}
	if keyAlgorithm != certificate.KeyAlgorithm().String() {
		return fmt.Errorf("pki: certificate key algorithm does not match key material")
	}
	subject, err := EncodeCertificateSubjectV1(certificate.Subject())
	if err != nil {
		return fmt.Errorf("pki: encode certificate subject: %w", err)
	}
	metadata, err := EncodeCertificateExtensionsV1(certificate.Kind(), certificate.Profile())
	if err != nil {
		return fmt.Errorf("pki: encode certificate metadata: %w", err)
	}
	der := certificate.DER()
	b = r.builder()
	query := "INSERT INTO certificates (id, created_at, der_sha256, der, key_material_id, issuer_ca_key_generation_id, serial_hex, not_before, not_after, subject_json, extensions_json, origin, created_by) VALUES (" +
		b.Add(string(certificate.ID())) + "," + r.databaseNowMicros() + "," +
		b.Add(domain.NewFingerprint(der).Hex()) + "," + b.Add(der) + "," + b.Add(string(certificate.KeyMaterialID())) + "," +
		b.Add(string(certificate.IssuerCAKeyGenerationID())) + "," + b.Add(certificate.Serial().Hex()) + "," +
		b.Add(certificate.Validity().NotBefore().UnixMicro()) + "," + b.Add(certificate.Validity().NotAfter().UnixMicro()) + "," +
		b.Add(string(subject)) + "," + b.Add(string(metadata)) + "," + b.Add(string(certificate.Origin())) + "," +
		b.Add(nullableString(string(certificate.CreatedByAccountID()))) + ")"
	if _, err := r.exec.ExecContext(ctx, query, b.Args()...); err != nil {
		return mapWriteError("pki: insert certificate", err)
	}
	for index, san := range certificate.SANs() {
		value := san.Value()
		hash := sha256.Sum256([]byte(value))
		b = r.builder()
		query = "INSERT INTO certificate_sans (certificate_id, position, type, normalized_value, normalized_value_hash) VALUES (" +
			b.Add(string(certificate.ID())) + "," + b.Add(index) + "," + b.Add(string(san.Type())) + "," +
			b.Add(value) + "," + b.Add(hex.EncodeToString(hash[:])) + ")"
		if _, err := r.exec.ExecContext(ctx, query, b.Args()...); err != nil {
			return mapWriteError("pki: insert certificate SAN", err)
		}
	}
	return nil
}

func (r *Repository) readCertificates(ctx context.Context, query string, args ...any) ([]domain.Certificate, error) {
	rows, err := r.exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pki: query certificates: %w", err)
	}
	databaseRows := make([]certificateDBRow, 0)
	for rows.Next() {
		var row certificateDBRow
		if err := rows.Scan(&row.id, &row.derHash, &row.der, &row.keyID, &row.issuerID, &row.serial,
			&row.notBefore, &row.notAfter, &row.subjectJSON, &row.extensionsJSON, &row.origin, &row.createdBy, &row.algorithm); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("pki: scan certificate row: %w", err)
		}
		databaseRows = append(databaseRows, row)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("pki: iterate certificates: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("pki: close certificate rows: %w", err)
	}
	certificates := make([]domain.Certificate, 0, len(databaseRows))
	for _, row := range databaseRows {
		certificate, err := r.certificateFromRow(ctx, row)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

const certificateColumns = "c.id, c.der_sha256, c.der, c.key_material_id, c.issuer_ca_key_generation_id, c.serial_hex, c.not_before, c.not_after, c.subject_json, c.extensions_json, c.origin, c.created_by, km.algorithm"

func (r *Repository) ListCertificatesByIssuer(ctx context.Context, issuer domain.CAKeyGenerationID) ([]domain.Certificate, error) {
	b := r.builder()
	p := b.Add(string(issuer))
	query := "SELECT " + certificateColumns + " FROM certificates c JOIN key_materials km ON km.id = c.key_material_id WHERE c.issuer_ca_key_generation_id = " + p + " ORDER BY c.id"
	return r.readCertificates(ctx, query, b.Args()...)
}

func (r *Repository) ListCACertificates(ctx context.Context) ([]domain.Certificate, error) {
	query := "SELECT " + certificateColumns + " FROM certificates c JOIN key_materials km ON km.id = c.key_material_id JOIN ca_certificates cc ON cc.certificate_id = c.id ORDER BY c.id"
	return r.readCertificates(ctx, query)
}

func (r *Repository) ListCertificatesUsingKey(ctx context.Context, keyMaterialID domain.KeyMaterialID) ([]domain.Certificate, error) {
	b := r.builder()
	p := b.Add(string(keyMaterialID))
	query := "SELECT " + certificateColumns + " FROM certificates c JOIN key_materials km ON km.id = c.key_material_id WHERE c.key_material_id = " + p + " ORDER BY c.id"
	return r.readCertificates(ctx, query, b.Args()...)
}

func (r *Repository) GetLeafCertificateRecord(ctx context.Context, certificateID domain.CertificateID) (port.LeafCertificateRecord, error) {
	b := r.builder()
	p := b.Add(string(certificateID))
	var rawCertificate, rawSeries, rawGeneration, rawIssuer string
	var rawPrevious sql.NullString
	var operation, policy string
	var renewalCount int64
	query := "SELECT certificate_id, series_id, leaf_key_generation_id, issuer_ca_certificate_id, previous_certificate_id, operation, renewal_count_at_issue, policy_snapshot_json FROM leaf_certificates WHERE certificate_id = " + p
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawCertificate, &rawSeries, &rawGeneration, &rawIssuer, &rawPrevious, &operation, &renewalCount, &policy); err != nil {
		return port.LeafCertificateRecord{}, missing(err)
	}
	parsedCertificate, err := parseCertificateID(rawCertificate)
	if err != nil {
		return port.LeafCertificateRecord{}, err
	}
	seriesID, err := parseSeriesID(rawSeries)
	if err != nil {
		return port.LeafCertificateRecord{}, err
	}
	generationID, err := parseLeafKeyGenerationID(rawGeneration)
	if err != nil {
		return port.LeafCertificateRecord{}, err
	}
	issuerID, err := parseCertificateID(rawIssuer)
	if err != nil {
		return port.LeafCertificateRecord{}, err
	}
	var previousID domain.CertificateID
	if rawPrevious.Valid {
		previousID, err = parseCertificateID(rawPrevious.String)
		if err != nil {
			return port.LeafCertificateRecord{}, err
		}
	}
	return port.LeafCertificateRecord{CertificateID: parsedCertificate, SeriesID: seriesID, LeafKeyGenerationID: generationID,
		IssuerCACertificateID: issuerID, PreviousCertificateID: previousID, Operation: operation,
		RenewalCountAtIssue: int(renewalCount), PolicySnapshotJSON: []byte(policy)}, nil
}

func (r *Repository) GetCACertificateRecord(ctx context.Context, certificateID domain.CertificateID) (port.CACertificateRecord, error) {
	b := r.builder()
	p := b.Add(string(certificateID))
	var rawCertificate, rawGeneration string
	var rawIssuer sql.NullString
	query := "SELECT certificate_id, ca_key_generation_id, issuer_ca_certificate_id FROM ca_certificates WHERE certificate_id = " + p
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawCertificate, &rawGeneration, &rawIssuer); err != nil {
		return port.CACertificateRecord{}, missing(err)
	}
	parsedCertificate, err := parseCertificateID(rawCertificate)
	if err != nil {
		return port.CACertificateRecord{}, err
	}
	generationID, err := parseCAKeyGenerationID(rawGeneration)
	if err != nil {
		return port.CACertificateRecord{}, err
	}
	var issuerID domain.CertificateID
	if rawIssuer.Valid {
		issuerID, err = parseCertificateID(rawIssuer.String)
		if err != nil {
			return port.CACertificateRecord{}, err
		}
	}
	return port.CACertificateRecord{CertificateID: parsedCertificate, CAKeyGenerationID: generationID, IssuerCACertificateID: issuerID}, nil
}

func (r *Repository) InsertLeafCertificateRecord(ctx context.Context, record port.LeafCertificateRecord) error {
	for label, raw := range map[string]string{
		"certificate": string(record.CertificateID), "series": string(record.SeriesID),
		"leaf generation": string(record.LeafKeyGenerationID), "issuer certificate": string(record.IssuerCACertificateID),
	} {
		if raw == "" {
			return fmt.Errorf("pki: %s id is required for leaf certificate record", label)
		}
	}
	if _, err := domain.ParseCertificateID(string(record.CertificateID)); err != nil {
		return err
	}
	if _, err := domain.ParseSeriesID(string(record.SeriesID)); err != nil {
		return err
	}
	if _, err := domain.ParseLeafKeyGenerationID(string(record.LeafKeyGenerationID)); err != nil {
		return err
	}
	if _, err := domain.ParseCertificateID(string(record.IssuerCACertificateID)); err != nil {
		return err
	}
	if record.PreviousCertificateID != "" {
		if _, err := domain.ParseCertificateID(string(record.PreviousCertificateID)); err != nil {
			return err
		}
	}
	if record.Operation != port.CertificateOperationInitial && record.Operation != port.CertificateOperationRenew &&
		record.Operation != port.CertificateOperationRekey && record.Operation != port.CertificateOperationMigrate &&
		record.Operation != port.CertificateOperationEmergency && record.Operation != port.CertificateOperationImport {
		return fmt.Errorf("pki: unsupported leaf certificate operation %q", record.Operation)
	}
	if record.RenewalCountAtIssue < 0 || len(record.PolicySnapshotJSON) == 0 {
		return fmt.Errorf("pki: invalid leaf certificate policy snapshot or renewal count")
	}
	snapshot, err := DecodeLeafCertificatePolicySnapshotV1(record.PolicySnapshotJSON)
	if err != nil {
		return err
	}
	if err := r.validateLeafCertificateRecord(ctx, record); err != nil {
		return err
	}
	certificate, err := r.readCertificateSANs(ctx, record.CertificateID)
	if err != nil {
		return err
	}
	if len(snapshot.SANs) != len(certificate) {
		return fmt.Errorf("pki: leaf policy snapshot SANs do not match the certificate")
	}
	for i, san := range snapshot.SANs {
		if domain.SANType(san.Type) != certificate[i].Type() || san.Value != certificate[i].Value() {
			return fmt.Errorf("pki: leaf policy snapshot SANs do not match the certificate")
		}
	}
	leaf, ca, err := r.certificateSubtypes(ctx, record.CertificateID)
	if err != nil {
		return fmt.Errorf("pki: check existing certificate subtype: %w", err)
	}
	if leaf || ca {
		return fmt.Errorf("pki: certificate subtype already exists: %w", port.ErrDuplicate)
	}
	b := r.builder()
	query := "INSERT INTO leaf_certificates (certificate_id, series_id, leaf_key_generation_id, issuer_ca_certificate_id, previous_certificate_id, operation, renewal_count_at_issue, policy_snapshot_json) VALUES (" +
		b.Add(string(record.CertificateID)) + "," + b.Add(string(record.SeriesID)) + "," + b.Add(string(record.LeafKeyGenerationID)) + "," +
		b.Add(string(record.IssuerCACertificateID)) + "," + b.Add(nullableString(string(record.PreviousCertificateID))) + "," +
		b.Add(record.Operation) + "," + b.Add(record.RenewalCountAtIssue) + "," + b.Add(string(record.PolicySnapshotJSON)) + ")"
	_, err = r.exec.ExecContext(ctx, query, b.Args()...)
	return mapWriteError("pki: insert leaf certificate record", err)
}

func (r *Repository) validateLeafCertificateRecord(ctx context.Context, record port.LeafCertificateRecord) error {
	// Enforce that the row exactly specializes a Leaf whose key generation,
	// series and signing certificate agree with the referenced records.
	b := r.builder()
	query := "SELECT c.key_material_id, c.issuer_ca_key_generation_id, c.extensions_json, g.series_id, g.key_material_id, cc.ca_key_generation_id FROM certificates c JOIN leaf_key_generations g ON g.id = " + b.Add(string(record.LeafKeyGenerationID)) + " JOIN ca_certificates cc ON cc.certificate_id = " + b.Add(string(record.IssuerCACertificateID)) + " WHERE c.id = " + b.Add(string(record.CertificateID))
	var certKey, issuerGeneration, extensions, generationSeries, generationKey, caGeneration string
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&certKey, &issuerGeneration, &extensions, &generationSeries, &generationKey, &caGeneration); err != nil {
		return fmt.Errorf("pki: validate leaf certificate relations: %w", missing(err))
	}
	metadata, err := DecodeCertificateExtensionsV1([]byte(extensions))
	if err != nil {
		return err
	}
	if metadata.Kind != string(domain.CertificateKindLeaf) {
		return fmt.Errorf("pki: leaf subtype requires a leaf certificate")
	}
	snapshot, err := DecodeLeafCertificatePolicySnapshotV1(record.PolicySnapshotJSON)
	if err != nil {
		return err
	}
	if snapshot.Profile != metadata.Profile {
		return fmt.Errorf("pki: leaf policy snapshot profile does not match certificate")
	}
	bootstrapSeries, err := r.seriesUsesBootstrapPurpose(ctx, record.SeriesID)
	if err != nil {
		return err
	}
	for _, san := range snapshot.SANs {
		if san.Type == string(domain.SANTypeDNS) && san.Value == "cert-me" && !bootstrapSeries {
			return fmt.Errorf("pki: bootstrap-only SAN is not allowed on this leaf series")
		}
	}
	if generationSeries != string(record.SeriesID) || generationKey != certKey {
		return fmt.Errorf("pki: leaf subtype series or key material does not match certificate")
	}
	if issuerGeneration != caGeneration {
		return fmt.Errorf("pki: leaf subtype issuer certificate does not match certificate issuer key generation")
	}
	if record.PreviousCertificateID != "" {
		b = r.builder()
		query = "SELECT COUNT(*) FROM leaf_certificates WHERE certificate_id = " + b.Add(string(record.PreviousCertificateID)) + " AND series_id = " + b.Add(string(record.SeriesID))
		var count int
		if err := r.queryRow(ctx, query, b.Args()...).Scan(&count); err != nil {
			return fmt.Errorf("pki: validate previous leaf certificate: %w", err)
		}
		if count == 0 {
			return fmt.Errorf("pki: previous certificate must belong to the same leaf series")
		}
	}
	return nil
}

func (r *Repository) seriesUsesBootstrapPurpose(ctx context.Context, id domain.SeriesID) (bool, error) {
	b := r.builder()
	query := "SELECT purpose FROM leaf_series WHERE id = " + b.Add(string(id))
	var purpose string
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&purpose); err != nil {
		return false, fmt.Errorf("pki: read leaf series purpose: %w", missing(err))
	}
	return domain.SeriesPurpose(purpose) == domain.SeriesPurposeBootstrapTLS, nil
}

func (r *Repository) InsertCACertificateRecord(ctx context.Context, record port.CACertificateRecord) error {
	if _, err := domain.ParseCertificateID(string(record.CertificateID)); err != nil {
		return err
	}
	if _, err := domain.ParseCAKeyGenerationID(string(record.CAKeyGenerationID)); err != nil {
		return err
	}
	if record.IssuerCACertificateID != "" {
		if _, err := domain.ParseCertificateID(string(record.IssuerCACertificateID)); err != nil {
			return err
		}
	}
	if err := r.validateCACertificateRecord(ctx, record); err != nil {
		return err
	}
	leaf, ca, err := r.certificateSubtypes(ctx, record.CertificateID)
	if err != nil {
		return fmt.Errorf("pki: check existing certificate subtype: %w", err)
	}
	if leaf || ca {
		return fmt.Errorf("pki: certificate subtype already exists: %w", port.ErrDuplicate)
	}
	b := r.builder()
	query := "INSERT INTO ca_certificates (certificate_id, ca_key_generation_id, issuer_ca_certificate_id) VALUES (" +
		b.Add(string(record.CertificateID)) + "," + b.Add(string(record.CAKeyGenerationID)) + "," +
		b.Add(nullableString(string(record.IssuerCACertificateID))) + ")"
	_, err = r.exec.ExecContext(ctx, query, b.Args()...)
	return mapWriteError("pki: insert CA certificate record", err)
}

func (r *Repository) validateCACertificateRecord(ctx context.Context, record port.CACertificateRecord) error {
	b := r.builder()
	query := "SELECT c.key_material_id, c.issuer_ca_key_generation_id, c.extensions_json, g.key_material_id FROM certificates c JOIN ca_key_generations g ON g.id = " + b.Add(string(record.CAKeyGenerationID)) + " WHERE c.id = " + b.Add(string(record.CertificateID))
	var certificateKey, issuerGeneration, extensions, generationKey string
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&certificateKey, &issuerGeneration, &extensions, &generationKey); err != nil {
		return fmt.Errorf("pki: validate CA certificate relations: %w", missing(err))
	}
	metadata, err := DecodeCertificateExtensionsV1([]byte(extensions))
	if err != nil {
		return err
	}
	if metadata.Kind != string(domain.CertificateKindCA) {
		return fmt.Errorf("pki: CA subtype requires a CA certificate")
	}
	if certificateKey != generationKey {
		return fmt.Errorf("pki: CA certificate subject key does not match its key generation")
	}
	if record.IssuerCACertificateID == "" {
		if issuerGeneration != string(record.CAKeyGenerationID) {
			return fmt.Errorf("pki: self-signed CA certificate must be issued by its own key generation")
		}
		return nil
	}
	b = r.builder()
	query = "SELECT ca_key_generation_id FROM ca_certificates WHERE certificate_id = " + b.Add(string(record.IssuerCACertificateID))
	var issuerCAKeyGeneration string
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&issuerCAKeyGeneration); err != nil {
		return fmt.Errorf("pki: validate CA issuer certificate: %w", missing(err))
	}
	if issuerGeneration != issuerCAKeyGeneration {
		return fmt.Errorf("pki: CA certificate issuer key generation does not match issuer certificate")
	}
	return nil
}
