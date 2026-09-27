package revocation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// CRLRepository implements port.CRLRepository over the caller's
// transaction-scoped executor. Number fields remain minimal hexadecimal
// strings in SQL; conversion to machine-sized integers is deliberately absent.
type CRLRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

// NewCRLRepository binds the repository to a transaction-scoped executor and
// a validated SQL dialect.
func NewCRLRepository(executor core.SQLExecutor, d dialect.Dialect) (*CRLRepository, error) {
	validated, err := validate(executor, d)
	if err != nil {
		return nil, err
	}
	return &CRLRepository{executor: executor, dialect: validated}, nil
}

var _ port.CRLRepository = (*CRLRepository)(nil)

func (r *CRLRepository) GetStateForUpdate(ctx context.Context, caKeyGenerationID domain.CAKeyGenerationID) (domain.CRLState, error) {
	if err := checkContext(ctx); err != nil {
		return domain.CRLState{}, err
	}
	if _, err := domain.ParseCAKeyGenerationID(string(caKeyGenerationID)); err != nil {
		return domain.CRLState{}, failed("get CRL state", err)
	}
	state, err := r.readState(ctx, caKeyGenerationID, true)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return domain.CRLState{}, err
		}
		return domain.CRLState{}, failed("get CRL state", err)
	}
	return state, nil
}

func (r *CRLRepository) readState(ctx context.Context, caKeyGenerationID domain.CAKeyGenerationID, lock bool) (domain.CRLState, error) {
	b := r.dialect.NewBuilder()
	query := "SELECT ca_key_generation_id, max_reserved_number_hex, revocation_generation, published_crl_id, next_publish_at, publication_state, signing_ca_certificate_id, version FROM crl_states WHERE ca_key_generation_id = " + b.Add(string(caKeyGenerationID))
	if lock {
		query += r.dialect.RowLockClause()
	}
	var rawID, maxNumberHex, publicationState string
	var rawPublishedID, rawSigningCertificateID sql.NullString
	var revocationGeneration, version int64
	var nextPublishAt sql.NullInt64
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(
		&rawID, &maxNumberHex, &revocationGeneration, &rawPublishedID, &nextPublishAt,
		&publicationState, &rawSigningCertificateID, &version,
	); err != nil {
		return domain.CRLState{}, missing(err)
	}
	id, err := parseCAKeyGenerationID(rawID)
	if err != nil {
		return domain.CRLState{}, err
	}
	maxNumber, err := parseCRLNumber(maxNumberHex)
	if err != nil {
		return domain.CRLState{}, err
	}
	parsedVersion, err := domain.ParseVersion(version)
	if err != nil {
		return domain.CRLState{}, fmt.Errorf("invalid CRL state version in database: %w", err)
	}
	var publishedID domain.CRLDocumentID
	var publishedNumber domain.CRLNumber
	var publishedGeneration int64
	if rawPublishedID.Valid {
		publishedID, err = parseCRLDocumentID(rawPublishedID.String)
		if err != nil {
			return domain.CRLState{}, err
		}
		// Fetch the immutable document separately. A LEFT JOIN followed by
		// FOR UPDATE is not legal for PostgreSQL's nullable side, and the
		// state row is the publication serialization point in every dialect.
		document, err := r.readDocument(ctx, publishedID)
		if err != nil {
			return domain.CRLState{}, fmt.Errorf("read published CRL document: %w", err)
		}
		if document.CAKeyGenerationID != id || document.Origin != "generated" || document.NumberHex.IsZero() {
			return domain.CRLState{}, errors.New("published CRL document is inconsistent with its state")
		}
		publishedNumber = document.NumberHex
		publishedGeneration = document.CoveredGeneration
	}
	var signingCertificateID domain.CertificateID
	if rawSigningCertificateID.Valid {
		signingCertificateID, err = parseCertificateID(rawSigningCertificateID.String)
		if err != nil {
			return domain.CRLState{}, err
		}
	}
	state, err := domain.NewCRLState(domain.CRLStateFacts{
		CAKeyGenerationID: id, MaxReservedNumber: maxNumber,
		RevocationGeneration: revocationGeneration, PublishedDocumentID: publishedID,
		PublishedNumber: publishedNumber, PublishedGeneration: publishedGeneration,
		NextPublishAt: instantFromNullable(nextPublishAt), PublicationState: domain.PublicationState(publicationState),
		SigningCACertificateID: signingCertificateID, Version: parsedVersion,
	})
	if err != nil {
		return domain.CRLState{}, fmt.Errorf("decode CRL state: %w", err)
	}
	if maxNumber.Compare(publishedNumber) < 0 || publishedGeneration > revocationGeneration {
		return domain.CRLState{}, errors.New("published CRL exceeds the reserved number or current generation")
	}
	return state, nil
}

func (r *CRLRepository) SaveState(ctx context.Context, state domain.CRLState, expectedVersion domain.Version) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateState(state); err != nil {
		return failed("save CRL state", err)
	}
	if _, err := domain.ParseVersion(expectedVersion.Int64()); err != nil {
		return failed("save CRL state", err)
	}
	if err := r.validatePublishedDocument(ctx, state); err != nil {
		return failed("save CRL state", err)
	}

	// An initial state is the only version-zero save. A changed state loaded
	// from version zero carries a later final version and follows the UPDATE
	// path below, as required by optimistic locking.
	if expectedVersion == 0 && state.Version() == 0 {
		if err := r.insertState(ctx, state); err != nil {
			if isDuplicate(err) {
				return failed("insert CRL state", port.ErrVersionConflict)
			}
			return failed("insert CRL state", err)
		}
		return nil
	}
	if state.Version() <= expectedVersion {
		return failed("save CRL state", errors.New("final version must advance past expected version"))
	}
	current, err := r.readState(ctx, state.CAKeyGenerationID(), true)
	if err != nil {
		return failed("read CRL state before save", err)
	}
	if current.Version() != expectedVersion {
		return failed("save CRL state", port.ErrVersionConflict)
	}
	if err := monotonicState(current, state); err != nil {
		return failed("save CRL state", err)
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE crl_states SET max_reserved_number_hex = " + b.Add(crlNumberForStorage(state.MaxReservedNumber())) +
		", revocation_generation = " + b.Add(state.RevocationGeneration()) +
		", published_crl_id = " + b.Add(optionalString(string(state.PublishedDocumentID()))) +
		", next_publish_at = " + b.Add(optionalInstant(state.NextPublishAt())) +
		", publication_state = " + b.Add(string(state.PublicationState())) +
		", signing_ca_certificate_id = " + b.Add(optionalString(string(state.SigningCACertificateID()))) +
		", updated_at = " + databaseNowMicros(r.dialect) +
		", version = " + b.Add(state.Version().Int64()) +
		" WHERE ca_key_generation_id = " + b.Add(string(state.CAKeyGenerationID())) +
		" AND version = " + b.Add(expectedVersion.Int64())
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return duplicateOrFailed("update CRL state", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return failed("read CRL state update result", err)
	}
	if changed == 0 {
		return failed("update CRL state", port.ErrVersionConflict)
	}
	return nil
}

func (r *CRLRepository) insertState(ctx context.Context, state domain.CRLState) error {
	b := r.dialect.NewBuilder()
	query := "INSERT INTO crl_states (ca_key_generation_id, max_reserved_number_hex, revocation_generation, published_crl_id, next_publish_at, publication_state, signing_ca_certificate_id, updated_at, version) VALUES (" +
		b.Add(string(state.CAKeyGenerationID())) + ", " + b.Add(crlNumberForStorage(state.MaxReservedNumber())) + ", " +
		b.Add(state.RevocationGeneration()) + ", " + b.Add(optionalString(string(state.PublishedDocumentID()))) + ", " +
		b.Add(optionalInstant(state.NextPublishAt())) + ", " + b.Add(string(state.PublicationState())) + ", " +
		b.Add(optionalString(string(state.SigningCACertificateID()))) + ", " + databaseNowMicros(r.dialect) + ", " +
		b.Add(state.Version().Int64()) + ")"
	_, err := r.executor.ExecContext(ctx, query, b.Args()...)
	return err
}

func validateState(state domain.CRLState) error {
	if _, err := domain.ParseCAKeyGenerationID(string(state.CAKeyGenerationID())); err != nil {
		return err
	}
	if _, err := domain.ParseVersion(state.Version().Int64()); err != nil {
		return err
	}
	if _, err := domain.ParseCRLNumber(crlNumberForStorage(state.MaxReservedNumber())); err != nil {
		return err
	}
	if state.RevocationGeneration() < 0 || state.PublishedGeneration() < 0 {
		return errors.New("CRL generations must not be negative")
	}
	if state.PublishedGeneration() > state.RevocationGeneration() || state.MaxReservedNumber().Compare(state.PublishedNumber()) < 0 {
		return errors.New("published CRL exceeds the reserved number or current generation")
	}
	if err := state.PublicationState().Validate(); err != nil {
		return err
	}
	if state.PublishedDocumentID() != "" {
		if _, err := domain.ParseCRLDocumentID(string(state.PublishedDocumentID())); err != nil {
			return err
		}
		if state.PublishedNumber().IsZero() {
			return errors.New("published CRL number is required")
		}
		if _, err := domain.ParseCRLNumber(state.PublishedNumber().Hex()); err != nil {
			return err
		}
	} else if state.PublishedNumber().Big().Sign() != 0 || state.PublishedGeneration() != 0 {
		return errors.New("published number and generation require a published document")
	}
	if state.SigningCACertificateID() != "" {
		if _, err := domain.ParseCertificateID(string(state.SigningCACertificateID())); err != nil {
			return err
		}
	}
	return nil
}

func (r *CRLRepository) validatePublishedDocument(ctx context.Context, state domain.CRLState) error {
	if state.PublishedDocumentID() == "" {
		return nil
	}
	document, err := r.readDocument(ctx, state.PublishedDocumentID())
	if err != nil {
		return fmt.Errorf("read published CRL document: %w", err)
	}
	if document.CAKeyGenerationID != state.CAKeyGenerationID() || document.Origin != "generated" ||
		document.NumberHex.IsZero() || document.NumberHex.Compare(state.PublishedNumber()) != 0 ||
		document.CoveredGeneration != state.PublishedGeneration() {
		return errors.New("published CRL document does not match the CRL state")
	}
	if state.MaxReservedNumber().Compare(state.PublishedNumber()) < 0 {
		return errors.New("reserved CRL number is below the published number")
	}
	return nil
}

func monotonicState(previous, next domain.CRLState) error {
	if next.MaxReservedNumber().Compare(previous.MaxReservedNumber()) < 0 {
		return errors.New("maximum reserved CRL number cannot decrease")
	}
	if next.RevocationGeneration() < previous.RevocationGeneration() {
		return errors.New("revocation generation cannot decrease")
	}
	if next.RevocationGeneration()-previous.RevocationGeneration() > 1 {
		return errors.New("revocation generation advances at most once per transaction")
	}
	publicationRank := func(state domain.PublicationState) int {
		switch state {
		case domain.PublicationStateInactive:
			return 0
		case domain.PublicationStateActive:
			return 1
		case domain.PublicationStateClosed:
			return 2
		default:
			return -1
		}
	}
	if publicationRank(next.PublicationState()) < publicationRank(previous.PublicationState()) {
		return errors.New("CRL publication state cannot regress")
	}
	previousID, nextID := previous.PublishedDocumentID(), next.PublishedDocumentID()
	if previousID != "" {
		if nextID == "" {
			return errors.New("published CRL document cannot be cleared")
		}
		if next.PublishedNumber().Compare(previous.PublishedNumber()) < 0 || next.PublishedGeneration() < previous.PublishedGeneration() {
			return errors.New("published CRL number and generation cannot decrease")
		}
		if nextID != previousID && next.PublishedNumber().Compare(previous.PublishedNumber()) <= 0 {
			return errors.New("a replacement published CRL must have a higher number")
		}
	}
	if previous.PublicationState() == domain.PublicationStateClosed &&
		(nextID != previousID || next.NextPublishAt() != previous.NextPublishAt() || next.SigningCACertificateID() != previous.SigningCACertificateID()) {
		return errors.New("closed CRL publication facts cannot change")
	}
	return nil
}

func (r *CRLRepository) InsertDocument(ctx context.Context, document port.CRLDocument) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateDocument(document); err != nil {
		return failed("insert CRL document", err)
	}
	number := optionalString(document.NumberHex.Hex())
	var nextUpdate any
	var coveredGeneration any
	if document.Origin == "generated" {
		nextUpdate = document.NextUpdate.UnixMicro()
		coveredGeneration = document.CoveredGeneration
	}
	b := r.dialect.NewBuilder()
	query := "INSERT INTO crl_documents (id, created_at, ca_key_generation_id, number_hex, der_sha256, der, this_update, next_update, covered_generation, origin, source_import_id) VALUES (" +
		b.Add(string(document.ID)) + ", " + databaseNowMicros(r.dialect) + ", " + b.Add(string(document.CAKeyGenerationID)) + ", " +
		b.Add(number) + ", " + b.Add(document.DERSHA256.Hex()) + ", " + b.Add(document.DER) + ", " +
		b.Add(document.ThisUpdate.UnixMicro()) + ", " + b.Add(nextUpdate) + ", " + b.Add(coveredGeneration) + ", " +
		b.Add(document.Origin) + ", " + b.Add(optionalString(document.SourceImportID)) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrFailed("insert CRL document", err)
	}
	return nil
}

func validateDocument(document port.CRLDocument) error {
	if _, err := domain.ParseCRLDocumentID(string(document.ID)); err != nil {
		return err
	}
	if _, err := domain.ParseCAKeyGenerationID(string(document.CAKeyGenerationID)); err != nil {
		return err
	}
	if document.Origin != "generated" && document.Origin != "imported" {
		return fmt.Errorf("unsupported CRL document origin %q", document.Origin)
	}
	if document.CoveredGeneration < 0 {
		return errors.New("covered generation must not be negative")
	}
	if document.ThisUpdate.IsZero() {
		return errors.New("CRL thisUpdate is required")
	}
	if len(document.DER) == 0 || document.DERSHA256.IsZero() || !document.DERSHA256.Equal(domain.NewFingerprint(document.DER)) {
		return errors.New("CRL DER and its SHA-256 fingerprint must match")
	}
	if document.NumberHex.Hex() != "" {
		if _, err := domain.ParseCRLNumber(document.NumberHex.Hex()); err != nil {
			return err
		}
	}
	if document.NextUpdate.IsZero() {
		if document.Origin == "generated" {
			return errors.New("generated CRL nextUpdate is required")
		}
	} else if !document.ThisUpdate.Before(document.NextUpdate) {
		return errors.New("CRL nextUpdate must follow thisUpdate")
	}
	if document.Origin == "generated" {
		if document.NumberHex.IsZero() {
			return errors.New("generated CRL number is required")
		}
		if document.CoveredGeneration < 0 {
			return errors.New("covered generation must not be negative")
		}
		if document.SourceImportID != "" {
			return errors.New("generated CRL cannot reference an import batch")
		}
	} else if document.SourceImportID != "" {
		if _, err := domain.ParseImportBatchID(document.SourceImportID); err != nil {
			return err
		}
	}
	return nil
}

func (r *CRLRepository) GetDocument(ctx context.Context, id domain.CRLDocumentID) (port.CRLDocument, error) {
	if err := checkContext(ctx); err != nil {
		return port.CRLDocument{}, err
	}
	if _, err := domain.ParseCRLDocumentID(string(id)); err != nil {
		return port.CRLDocument{}, failed("get CRL document", err)
	}
	document, err := r.readDocument(ctx, id)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return port.CRLDocument{}, err
		}
		return port.CRLDocument{}, failed("get CRL document", err)
	}
	return document, nil
}

func (r *CRLRepository) readDocument(ctx context.Context, id domain.CRLDocumentID) (port.CRLDocument, error) {
	b := r.dialect.NewBuilder()
	query := "SELECT id, ca_key_generation_id, number_hex, der_sha256, der, this_update, next_update, covered_generation, origin, source_import_id FROM crl_documents WHERE id = " + b.Add(string(id))
	var rawID, rawCAID, derHash, origin string
	var numberHex, sourceImportID sql.NullString
	var der []byte
	var thisUpdate int64
	var nextUpdate, coveredGeneration sql.NullInt64
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(
		&rawID, &rawCAID, &numberHex, &derHash, &der, &thisUpdate, &nextUpdate,
		&coveredGeneration, &origin, &sourceImportID,
	); err != nil {
		return port.CRLDocument{}, missing(err)
	}
	parsedID, err := parseCRLDocumentID(rawID)
	if err != nil {
		return port.CRLDocument{}, err
	}
	caID, err := parseCAKeyGenerationID(rawCAID)
	if err != nil {
		return port.CRLDocument{}, err
	}
	var number domain.CRLNumber
	if numberHex.Valid {
		number, err = parseCRLNumber(numberHex.String)
		if err != nil {
			return port.CRLDocument{}, err
		}
	}
	fingerprint, err := domain.ParseFingerprint(derHash)
	if err != nil {
		return port.CRLDocument{}, fmt.Errorf("invalid CRL DER fingerprint in database: %w", err)
	}
	if !fingerprint.Equal(domain.NewFingerprint(der)) {
		return port.CRLDocument{}, errors.New("stored CRL DER fingerprint does not match DER")
	}
	if len(der) == 0 {
		return port.CRLDocument{}, errors.New("stored CRL DER is empty")
	}
	var parsedSourceImportID string
	if sourceImportID.Valid {
		parsed, err := domain.ParseImportBatchID(sourceImportID.String)
		if err != nil {
			return port.CRLDocument{}, fmt.Errorf("invalid CRL import batch id in database: %w", err)
		}
		parsedSourceImportID = string(parsed)
	}
	document := port.CRLDocument{
		ID: parsedID, CAKeyGenerationID: caID, NumberHex: number, DERSHA256: fingerprint,
		DER: append([]byte(nil), der...), ThisUpdate: instantFromInt64(thisUpdate),
		NextUpdate: instantFromNullable(nextUpdate), Origin: origin, SourceImportID: parsedSourceImportID,
	}
	if coveredGeneration.Valid {
		document.CoveredGeneration = coveredGeneration.Int64
	}
	if document.Origin != "generated" && document.Origin != "imported" {
		return port.CRLDocument{}, fmt.Errorf("unknown CRL origin in database %q", document.Origin)
	}
	if document.ThisUpdate.IsZero() {
		return port.CRLDocument{}, errors.New("stored CRL thisUpdate is missing")
	}
	if document.Origin == "generated" {
		if numberHex.Valid == false || !nextUpdate.Valid || !coveredGeneration.Valid || number.IsZero() {
			return port.CRLDocument{}, errors.New("generated CRL row lacks required publication facts")
		}
		if sourceImportID.Valid {
			return port.CRLDocument{}, errors.New("generated CRL row references an import batch")
		}
		if coveredGeneration.Int64 < 0 || !document.ThisUpdate.Before(document.NextUpdate) {
			return port.CRLDocument{}, errors.New("generated CRL row has invalid generation or validity window")
		}
	} else if sourceImportID.Valid && parsedSourceImportID == "" {
		return port.CRLDocument{}, errors.New("invalid imported CRL source")
	}
	return document, nil
}
