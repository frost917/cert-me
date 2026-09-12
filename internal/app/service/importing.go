// importing.go implements ImportService's Preview/Commit/
// AttachSigningKey/ConfirmTakeover paths. Import preparation is kept outside
// the write transaction while the final relationship, conflict and custody
// checks are repeated inside the commit (docs/backend-implementation.md §15.2
// and docs/pki-import.md).
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// ImportDeps is ImportService's dependency set: CommonDeps plus the import
// parsing, chain/CRL verification and key-encryption ports named by the B04
// import contract.
type ImportDeps struct {
	CommonDeps
	PKIParser      port.PKIParser
	ChainValidator port.ChainValidator
	CRLVerifier    port.CRLVerifier
	KeyEngine      port.KeyEngine
}

// Validate reports the first missing dependency, common or Import-specific.
func (d ImportDeps) Validate() error {
	if err := d.CommonDeps.Validate(); err != nil {
		return err
	}
	return firstMissing(
		required{"PKIParser", d.PKIParser == nil},
		required{"ChainValidator", d.ChainValidator == nil},
		required{"CRLVerifier", d.CRLVerifier == nil},
		required{"KeyEngine", d.KeyEngine == nil},
	)
}

// ImportService implements Preview, Commit and ConfirmTakeover.
type ImportService struct {
	deps ImportDeps
}

// NewImportService constructs the service, failing fast on a missing
// dependency rather than at the first request.
func NewImportService(deps ImportDeps) (*ImportService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &ImportService{deps: deps}, nil
}

const (
	importOperationCommit = "import.commit"
)

// ---- shared file preparation (transaction-free, §8 "import" row: "파싱·해제·
// 체인 검증·키 암호화"는 트랜잭션 밖) ----

// parsedImportFile is one uploaded file's parser output, computed outside any
// transaction. Certificate, CRL and CA-key material remain explicitly typed;
// relationships and storage identifiers are assigned by the app layer.
type parsedImportFile struct {
	// FileName is the unique logical item key used for same-batch references.
	// A certificate file may contain several certificates, so those items get
	// generated keys while UploadFileName remains the public multipart name.
	FileName            string
	UploadFileName      string
	Kind                contract.ImportFileKind
	Cert                port.ParsedCertificateFacts
	CRL                 port.ParsedCRLFacts
	KeyData             []byte
	Passphrase          *secret.Input
	DERSHA256           domain.Fingerprint
	IssuerCertificateID domain.CertificateID // metadata hint, zero if not given
}

// errImportFileKindUnsupported remains the common validation shape for an
// artifact whose parsed facts cannot be connected unambiguously.
func errImportFileKindUnsupported(fileName string, detail string) error {
	return contract.NewAppError(contract.ErrorKindValidation, "import_file_kind_unsupported", detail).
		WithField("file_name", fileName)
}

// parseFiles runs public artifact parsing (§8's out-of-transaction "파싱").
// CA-key parsing is deliberately deferred until the app has resolved the
// certificate public key it must match; the raw key bytes/passphrase remain
// request-owned and are never persisted.
func (s *ImportService) parseFiles(ctx context.Context, cmd contract.ImportUploadCommand) ([]parsedImportFile, error) {
	byName := make(map[string][]byte, len(cmd.Files))
	for _, f := range cmd.Files {
		byName[f.FileName] = f.Data
	}
	out := make([]parsedImportFile, 0, len(cmd.Metadata.Files))
	for metadataIndex, m := range cmd.Metadata.Files {
		data := byName[m.FileName]
		switch m.Kind {
		case contract.ImportFileKindCertificate:
			bundle, err := s.deps.PKIParser.ParseCertificateBundle(ctx, port.CertificateBundleInput{Data: data})
			if err != nil {
				return nil, contract.WrapAppError(contract.ErrorKindValidation, "import_certificate_parse_failed",
					"could not parse the uploaded certificate", err).WithField("file_name", m.FileName)
			}
			if len(bundle.Certificates) == 0 {
				return nil, errImportFileKindUnsupported(m.FileName,
					"the certificate upload entry contains no certificate")
			}
			for certificateIndex, certificate := range bundle.Certificates {
				if err := validateParsedCertificateFacts(certificate); err != nil {
					return nil, contract.WrapAppError(contract.ErrorKindValidation, "import_certificate_facts_invalid",
						"the certificate parser returned inconsistent public facts", err).WithField("file_name", m.FileName)
				}
				fileName := m.FileName
				if len(bundle.Certificates) > 1 {
					fileName = fmt.Sprintf("\x00%d\x00%d", metadataIndex, certificateIndex)
				}
				out = append(out, parsedImportFile{
					FileName:            fileName,
					UploadFileName:      m.FileName,
					Kind:                m.Kind,
					Cert:                certificate,
					DERSHA256:           domain.NewFingerprint(certificate.DER),
					IssuerCertificateID: m.IssuerCertificateID,
				})
			}
		case contract.ImportFileKindCRL:
			crl, err := s.deps.PKIParser.ParseCRL(ctx, port.CRLInput{Data: data})
			if err != nil {
				return nil, contract.WrapAppError(contract.ErrorKindValidation, "import_crl_parse_failed",
					"could not parse the uploaded CRL", err).WithField("file_name", m.FileName)
			}
			if len(crl.DER) == 0 {
				return nil, errImportFileKindUnsupported(m.FileName, "the parsed CRL has no signed DER")
			}
			if crl.ThisUpdate.IsZero() {
				return nil, errImportFileKindUnsupported(m.FileName, "the parsed CRL has no this_update timestamp")
			}
			out = append(out, parsedImportFile{
				FileName:            m.FileName,
				UploadFileName:      m.FileName,
				Kind:                m.Kind,
				CRL:                 crl,
				DERSHA256:           domain.NewFingerprint(crl.DER),
				IssuerCertificateID: m.IssuerCertificateID,
			})
		case contract.ImportFileKindCAKey:
			if len(data) == 0 {
				return nil, contract.NewAppError(contract.ErrorKindValidation, "import_ca_key_empty", "the uploaded CA key is empty").WithField("file_name", m.FileName)
			}
			out = append(out, parsedImportFile{
				FileName:            m.FileName,
				UploadFileName:      m.FileName,
				Kind:                m.Kind,
				KeyData:             data,
				Passphrase:          m.Passphrase,
				IssuerCertificateID: m.IssuerCertificateID,
			})
		default:
			return nil, errImportFileKindUnsupported(m.FileName, "the import file kind is unsupported")
		}
		if len(out) > 100 {
			return nil, contract.NewAppError(contract.ErrorKindValidation, "import_files_expanded_too_many",
				"the certificate bundle expands to more than 100 logical import items")
		}
	}
	return out, nil
}

func validateParsedCertificateFacts(facts port.ParsedCertificateFacts) error {
	if len(facts.DER) == 0 {
		return fmt.Errorf("certificate DER must not be empty")
	}
	if facts.PublicKey.IsZero() {
		return fmt.Errorf("certificate public key must not be empty")
	}
	if !facts.SPKIFingerprint.Equal(facts.PublicKey.Fingerprint()) {
		return fmt.Errorf("certificate SPKI fingerprint does not match the public key")
	}
	if facts.KeyAlgorithm != facts.PublicKey.Algorithm() {
		return fmt.Errorf("certificate key algorithm does not match the public key")
	}
	if err := facts.Kind.Validate(); err != nil {
		return err
	}
	return nil
}

// ---- current-state resolution (§8 "import" row: 현재 중복/충돌 ... 재확인은
// 단일 Write 안. Preview runs the identical function against a read snapshot;
// Commit runs it again inside its own Write, per §13 "미리보기 후 반영 시에도
// 현재 DB를 기준으로 중복·충돌·체인 검증을 다시 수행한다" -- U10's "preview 이후
// 충돌 재검사". ----

// importResolution is one file's resolved outcome against the CURRENT store
// state (or, for a same-batch issuer, against a sibling file's own
// resolution).
type importResolution struct {
	FileName       string
	UploadFileName string
	Kind           contract.ImportFileKind
	Cert           port.ParsedCertificateFacts
	CRL            port.ParsedCRLFacts
	DERSHA256      domain.Fingerprint
	Status         contract.ImportItemStatus
	ErrorCode      string

	ExistingCertificateID domain.CertificateID // set when Status == Duplicate and an existing row matched directly
	DuplicateOfFileName   string               // set when Status == Duplicate because an EARLIER file in this same batch has the identical DER

	SelfSigned                  bool
	IssuerBatchFileName         string               // resolved issuer is another New file in this batch
	IssuerExistingCertificateID domain.CertificateID // resolved issuer is an already-stored certificate

	// CompromisedKeyMaterialID is set when this certificate's public key
	// matches a stored key_material row already flagged compromised, with NO
	// other certificate currently using it (docs/certificate-lifecycle.md
	// "개인키 유출 | 같은 키를 사용하는 유효 인증서 모두 폐기" -- U09 applied to
	// a certificate Import is registering for the first time under an
	// already-known-bad key).
	CompromisedKeyMaterialID domain.KeyMaterialID
	CompromisedAt            domain.Instant
	ExistingKeyMaterialID    domain.KeyMaterialID
	KeyTargetBatchFileName   string
}

type importedKeyCandidate struct {
	FileName      string
	Certificate   port.ParsedCertificateFacts
	CertificateID domain.CertificateID
}

type preparedImportKey struct {
	FileName              string
	TargetBatchFileName   string
	ExistingCertificateID domain.CertificateID
	KeyMaterialID         domain.KeyMaterialID
	Purpose               domain.SecretPurpose
	Validated             port.ValidatedCAKeyInput
	Generated             port.GeneratedKey
}

func closePreparedImportKeys(keys map[string]preparedImportKey) {
	for _, key := range keys {
		if key.Validated.PrivateKey != nil {
			_ = key.Validated.PrivateKey.Close()
		}
	}
}

func preparedKeyForTarget(keys map[string]preparedImportKey, targetFileName string) (preparedImportKey, bool) {
	for _, key := range keys {
		if key.TargetBatchFileName == targetFileName {
			return key, true
		}
	}
	return preparedImportKey{}, false
}

// prepareImportKeys resolves and validates every CA key before Commit's
// write. A key is tried against the public keys of same-batch CA certificates
// first, then stored CA certificates; this makes file order irrelevant while
// retaining the parser's exact-public-key check. The returned key material id
// is either the already-known orphan identity or a fresh id reserved for the
// batch. No secret is persisted here and no encryption is performed here.
func (s *ImportService) prepareImportKeys(ctx context.Context, files []parsedImportFile) (map[string]preparedImportKey, error) {
	prepared := map[string]preparedImportKey{}
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		stored, err := tx.PKI().ListCACertificates(ctx)
		if err != nil {
			return storeError(err, "import_ca_certificates_lookup_failed", "could not list stored CA certificates")
		}
		for _, file := range files {
			if file.Kind != contract.ImportFileKindCAKey {
				continue
			}
			candidates, err := s.importKeyCandidates(ctx, tx, file, files, stored)
			if err != nil {
				return err
			}
			if len(candidates) == 0 {
				return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_target_unresolved",
					"the CA key could not be matched to a bundled or stored CA certificate").WithField("file_name", file.FileName)
			}

			var selected port.ValidatedCAKeyInput
			var selectedCandidate importedKeyCandidate
			matches := 0
			for _, candidate := range candidates {
				validated, parseErr := s.deps.PKIParser.ParseCAKey(ctx, port.CAKeyInput{
					Data:              file.KeyData,
					Passphrase:        file.Passphrase,
					ExpectedPublicKey: candidate.Certificate.PublicKey,
				})
				if parseErr != nil {
					continue
				}
				if validated.PrivateKey == nil || !validated.PublicKey.Equal(candidate.Certificate.PublicKey) {
					if validated.PrivateKey != nil {
						_ = validated.PrivateKey.Close()
					}
					continue
				}
				if selected.PrivateKey != nil {
					_ = selected.PrivateKey.Close()
					_ = validated.PrivateKey.Close()
					return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_target_ambiguous",
						"the CA key matches more than one certificate").WithField("file_name", file.FileName)
				}
				selected = validated
				selectedCandidate = candidate
				matches++
			}
			if matches == 0 {
				return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_mismatch",
					"the uploaded CA key does not match any candidate CA certificate").WithField("file_name", file.FileName)
			}

			keyMaterialID, targetBatch, err := s.resolvePreparedKeyIdentity(ctx, tx, files, selectedCandidate)
			if err != nil {
				_ = selected.PrivateKey.Close()
				return err
			}
			purpose := domain.SecretPurposeCASigning
			if selectedCandidate.CertificateID != "" {
				certificate, readErr := tx.PKI().GetCertificate(ctx, selectedCandidate.CertificateID)
				if readErr != nil {
					_ = selected.PrivateKey.Close()
					return storeError(readErr, "import_ca_key_certificate_read_failed", "could not re-read the existing CA certificate")
				}
				generationID, generationErr := certificateKeyGeneration(ctx, tx, certificate)
				if generationErr != nil {
					_ = selected.PrivateKey.Close()
					return generationErr
				}
				generation, generationErr := tx.PKI().GetCAKeyGeneration(ctx, generationID)
				if generationErr != nil {
					_ = selected.PrivateKey.Close()
					return storeError(generationErr, "import_ca_key_generation_read_failed", "could not read the existing CA key generation")
				}
				authority, authorityErr := tx.PKI().GetIssuerForUpdate(ctx, generation.AuthorityID)
				if authorityErr != nil {
					_ = selected.PrivateKey.Close()
					return storeError(authorityErr, "import_ca_key_authority_read_failed", "could not read the existing CA authority")
				}
				purpose = caSecretPurpose(authority)
			}
			entry := preparedImportKey{
				FileName:              file.FileName,
				TargetBatchFileName:   targetBatch,
				ExistingCertificateID: selectedCandidate.CertificateID,
				KeyMaterialID:         keyMaterialID,
				Purpose:               purpose,
				Validated:             selected,
			}
			if index := fileIndexByName(files, file.FileName); index >= 0 {
				files[index].DERSHA256 = selected.PublicKey.Fingerprint()
			}
			prepared[file.FileName] = entry
		}
		return nil
	})
	if err != nil {
		closePreparedImportKeys(prepared)
		return nil, err
	}
	return prepared, nil
}

// encryptPreparedImportKeys turns the already-validated CA key inputs into
// server-encrypted secrets after idempotency replay and manifest checks have
// passed. Keeping this separate lets the idempotency hash use the verified
// public SPKI without ever hashing the private-key upload bytes.
func (s *ImportService) encryptPreparedImportKeys(ctx context.Context, prepared map[string]preparedImportKey) error {
	names := make([]string, 0, len(prepared))
	for name := range prepared {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		key := prepared[name]
		generated, err := s.deps.KeyEngine.ImportCA(ctx, key.Validated, port.KeySpec{
			KeyMaterialID: key.KeyMaterialID,
			Algorithm:     key.Validated.Algorithm,
			Purpose:       key.Purpose,
		})
		if err != nil {
			return contract.WrapAppError(contract.ErrorKindUnavailable, "import_ca_key_encrypt_failed",
				"could not encrypt the imported CA key", err).WithField("file_name", name)
		}
		if !generated.PublicKey.Equal(key.Validated.PublicKey) ||
			generated.EncryptedSecret.OwnerKeyID() != key.KeyMaterialID ||
			generated.EncryptedSecret.Purpose() != key.Purpose {
			return contract.NewAppError(contract.ErrorKindUnavailable, "import_ca_key_result_mismatch",
				"the CA key encryption result did not preserve its verified identity").WithField("file_name", name)
		}
		key.Generated = generated
		prepared[name] = key
	}
	return nil
}

func (s *ImportService) resolvePreparedKeyIdentity(ctx context.Context, tx port.TxStores, files []parsedImportFile, candidate importedKeyCandidate) (domain.KeyMaterialID, string, error) {
	if candidate.CertificateID != "" {
		certificate, err := tx.PKI().GetCertificate(ctx, candidate.CertificateID)
		if err != nil {
			return "", "", storeError(err, "import_ca_key_certificate_read_failed", "could not re-read the CA certificate")
		}
		generationID, err := certificateKeyGeneration(ctx, tx, certificate)
		if err != nil {
			return "", "", err
		}
		generation, err := tx.PKI().GetCAKeyGeneration(ctx, generationID)
		if err != nil {
			return "", "", storeError(err, "import_ca_key_generation_read_failed", "could not read the CA key generation")
		}
		if !generation.KeyDestroyedAt.IsZero() {
			return "", "", contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_destroyed",
				"a destroyed CA key cannot be attached")
		}
		material, err := tx.PKI().GetKeyMaterial(ctx, certificate.KeyMaterialID())
		if err != nil {
			return "", "", storeError(err, "import_ca_key_material_read_failed", "could not read the existing CA key material")
		}
		if !material.CompromisedAt.IsZero() {
			return "", "", contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_compromised",
				"a compromised CA key cannot be attached")
		}
		return certificate.KeyMaterialID(), "", nil
	}

	if candidate.FileName == "" {
		return "", "", contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_target_unresolved",
			"the CA key target has no certificate")
	}
	// A same-batch CA certificate can reuse an orphaned public-key identity,
	// but never a key already used by another stored certificate. This keeps
	// the key_material SPKI uniqueness rule intact without creating a second
	// identity for the same key.
	key, err := tx.PKI().FindKeyBySPKI(ctx, candidate.Certificate.SPKIFingerprint)
	if err == nil {
		certificates, listErr := tx.PKI().ListCertificatesUsingKey(ctx, key.ID)
		if listErr != nil {
			return "", "", storeError(listErr, "import_ca_key_usage_lookup_failed", "could not inspect existing CA key usage")
		}
		if len(certificates) > 0 {
			return "", "", contract.NewAppError(contract.ErrorKindConflict, "import_duplicate_public_key",
				"the imported CA key public key is already used by a stored certificate")
		}
		if !key.CompromisedAt.IsZero() {
			return "", "", contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_compromised",
				"a compromised CA key cannot be attached")
		}
		return key.ID, candidate.FileName, nil
	}
	if !errors.Is(err, port.ErrNotFound) {
		return "", "", storeError(err, "import_ca_key_lookup_failed", "could not inspect the imported CA key identity")
	}
	keyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
	if err != nil {
		return "", "", contract.FromDomainError(err)
	}
	return keyMaterialID, candidate.FileName, nil
}

func certificateKeyGeneration(ctx context.Context, tx port.TxStores, certificate domain.Certificate) (domain.CAKeyGenerationID, error) {
	record, err := tx.PKI().GetCACertificateRecord(ctx, certificate.ID())
	if err != nil {
		return "", storeError(err, "import_ca_certificate_record_read_failed", "could not read the CA certificate record")
	}
	return record.CAKeyGenerationID, nil
}

func fileIndexByName(files []parsedImportFile, name string) int {
	for i := range files {
		if files[i].FileName == name {
			return i
		}
	}
	return -1
}

func (s *ImportService) importKeyCandidates(ctx context.Context, tx port.TxStores, file parsedImportFile, files []parsedImportFile, stored []domain.Certificate) ([]importedKeyCandidate, error) {
	if file.IssuerCertificateID != "" {
		certificate, err := tx.PKI().GetCertificate(ctx, file.IssuerCertificateID)
		if errors.Is(err, port.ErrNotFound) {
			return nil, contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_certificate_not_found",
				"the CA key's issuer_certificate_id does not exist")
		}
		if err != nil {
			return nil, storeError(err, "import_ca_key_certificate_read_failed", "could not read the CA certificate named by the key")
		}
		if certificate.Kind() != domain.CertificateKindCA {
			return nil, contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_certificate_not_ca",
				"a CA key must be attached to a CA certificate")
		}
		facts, err := parsedFactsFromStoredCertificate(ctx, tx, certificate)
		if err != nil {
			return nil, err
		}
		return []importedKeyCandidate{{CertificateID: certificate.ID(), Certificate: facts}}, nil
	}

	batch := make([]importedKeyCandidate, 0)
	seenBatchDER := make(map[string]struct{})
	for _, candidate := range files {
		if candidate.Kind == contract.ImportFileKindCertificate && candidate.Cert.Kind == domain.CertificateKindCA {
			derHash := domain.NewFingerprint(candidate.Cert.DER).Hex()
			if _, seen := seenBatchDER[derHash]; seen {
				continue
			}
			seenBatchDER[derHash] = struct{}{}
			// If this bundled certificate is already stored, the key belongs to
			// that existing certificate and must use the attach path below. This
			// also handles an exact-DER certificate plus key in one re-submission.
			existing, err := tx.PKI().FindCertificateByDER(ctx, domain.NewFingerprint(candidate.Cert.DER))
			if err == nil && existing.Kind() == domain.CertificateKindCA {
				facts, factsErr := parsedFactsFromStoredCertificate(ctx, tx, existing)
				if factsErr != nil {
					return nil, factsErr
				}
				batch = append(batch, importedKeyCandidate{CertificateID: existing.ID(), Certificate: facts})
				continue
			}
			if err != nil && !errors.Is(err, port.ErrNotFound) {
				return nil, storeError(err, "import_ca_key_certificate_lookup_failed", "could not check whether the bundled CA certificate already exists")
			}
			batch = append(batch, importedKeyCandidate{FileName: candidate.FileName, Certificate: candidate.Cert})
		}
	}
	if len(batch) > 0 {
		return batch, nil
	}
	out := make([]importedKeyCandidate, 0, len(stored))
	for _, certificate := range stored {
		facts, err := parsedFactsFromStoredCertificate(ctx, tx, certificate)
		if err != nil {
			return nil, err
		}
		out = append(out, importedKeyCandidate{CertificateID: certificate.ID(), Certificate: facts})
	}
	return out, nil
}

func parsedFactsFromStoredCertificate(ctx context.Context, tx port.TxStores, certificate domain.Certificate) (port.ParsedCertificateFacts, error) {
	material, err := tx.PKI().GetKeyMaterial(ctx, certificate.KeyMaterialID())
	if err != nil {
		return port.ParsedCertificateFacts{}, storeError(err, "import_certificate_key_material_read_failed", "could not read the certificate public key")
	}
	return port.ParsedCertificateFacts{
		DER:             certificate.DER(),
		PublicKey:       material.PublicKey,
		SPKIFingerprint: material.PublicKey.Fingerprint(),
		KeyAlgorithm:    certificate.KeyAlgorithm(),
		Serial:          certificate.Serial(),
		Validity:        certificate.Validity(),
		Subject:         certificate.Subject(),
		SANs:            certificate.SANs(),
		Kind:            certificate.Kind(),
		Profile:         certificate.Profile(),
		IssuerSubject:   certificate.Subject(),
	}, nil
}

// resolveImportItems classifies every parsed file against the store read
// through tx: exact-DER duplicate, public-key conflict (against an existing
// certificate OR another file in this same batch), or new with a resolved
// issuer. It performs no writes.
func (s *ImportService) resolveImportItems(ctx context.Context, tx port.TxStores, files []parsedImportFile) ([]importResolution, error) {
	out := make([]importResolution, len(files))
	firstByDER := map[string]int{}

	for i, f := range files {
		r := importResolution{FileName: f.FileName, UploadFileName: f.UploadFileName, Kind: f.Kind, Cert: f.Cert, CRL: f.CRL, DERSHA256: f.DERSHA256}
		if f.Kind != contract.ImportFileKindCertificate {
			// CA keys and CRLs are resolved after certificate facts are
			// classified, because their issuer/key relationships are not
			// properties the parser may invent.
			r.Status = contract.ImportItemStatusNew
			out[i] = r
			continue
		}

		// Exact-duplicate re-registration always wins over any other check
		// (docs/pki-import.md "완전히 동일한 인증서 재등록은 위 동일 항목
		// 처리로 우선 판정한다"), whether the duplicate is an earlier file in
		// THIS batch or an already-stored certificate.
		if firstIdx, dup := firstByDER[f.DERSHA256.Hex()]; dup {
			r.Status = contract.ImportItemStatusDuplicate
			r.DuplicateOfFileName = files[firstIdx].FileName
			out[i] = r
			continue
		}
		firstByDER[f.DERSHA256.Hex()] = i

		existingCert, err := tx.PKI().FindCertificateByDER(ctx, f.DERSHA256)
		switch {
		case err == nil:
			r.Status = contract.ImportItemStatusDuplicate
			r.ExistingCertificateID = existingCert.ID()
			out[i] = r
			continue
		case errors.Is(err, port.ErrNotFound):
			// genuinely new so far
		default:
			return nil, storeError(err, "import_certificate_lookup_failed", "could not check for an existing certificate")
		}

		if conflict := s.resolvePublicKey(ctx, tx, files, out, i, &r); conflict {
			out[i] = r
			continue
		}

		s.resolveIssuer(ctx, tx, files, out, i, &r)
		out[i] = r
	}
	return out, nil
}

// resolveImportAuxiliaryItems connects CA-key and CRL artifacts only after
// certificate facts are available. A relationship is accepted only when the
// issuer subject/AKI and the verifier agree; a name or file order alone never
// establishes the connection.
func (s *ImportService) resolveImportAuxiliaryItems(ctx context.Context, tx port.TxStores, files []parsedImportFile, out []importResolution, prepared map[string]preparedImportKey) error {
	storedCACerts, err := tx.PKI().ListCACertificates(ctx)
	if err != nil {
		return storeError(err, "import_ca_certificates_lookup_failed", "could not list stored CA certificates")
	}
	for i := range out {
		r := &out[i]
		file := files[i]
		switch file.Kind {
		case contract.ImportFileKindCAKey:
			key, ok := prepared[file.FileName]
			if !ok || key.Validated.PrivateKey == nil {
				return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_unresolved",
					"the uploaded CA key was not validated").WithField("file_name", file.FileName)
			}
			r.DERSHA256 = key.Validated.PublicKey.Fingerprint()
			r.KeyTargetBatchFileName = key.TargetBatchFileName
			r.IssuerExistingCertificateID = key.ExistingCertificateID
		case contract.ImportFileKindCRL:
			candidate, batchFileName, err := s.resolveCRLIssuer(ctx, tx, file, files, out, storedCACerts)
			if err != nil {
				return err
			}
			if err := s.deps.CRLVerifier.Verify(ctx, file.CRL.DER, candidate.Certificate.DER); err != nil {
				r.Status = contract.ImportItemStatusConflict
				r.ErrorCode = "import_crl_signature_invalid"
				continue
			}
			if !file.CRL.NextUpdate.IsZero() && file.CRL.NextUpdate.IsExpiredAt(s.deps.Clock.Now()) {
				r.ErrorCode = "import_crl_expired"
			}
			if batchFileName != "" {
				r.IssuerBatchFileName = batchFileName
			} else {
				r.IssuerExistingCertificateID = candidate.CertificateID
			}
		}
	}
	return nil
}

func (s *ImportService) resolveCRLIssuer(ctx context.Context, tx port.TxStores, file parsedImportFile, files []parsedImportFile, resolved []importResolution, stored []domain.Certificate) (importedKeyCandidate, string, error) {
	if file.IssuerCertificateID != "" {
		certificate, err := tx.PKI().GetCertificate(ctx, file.IssuerCertificateID)
		if errors.Is(err, port.ErrNotFound) {
			return importedKeyCandidate{}, "", contract.NewAppError(contract.ErrorKindConflict, "import_crl_issuer_not_found",
				"the CRL issuer certificate does not exist").WithField("file_name", file.FileName)
		}
		if err != nil {
			return importedKeyCandidate{}, "", storeError(err, "import_crl_issuer_read_failed", "could not read the CRL issuer certificate")
		}
		if certificate.Kind() != domain.CertificateKindCA {
			return importedKeyCandidate{}, "", contract.NewAppError(contract.ErrorKindConflict, "import_crl_issuer_not_ca",
				"a CRL must be issued by a CA certificate").WithField("file_name", file.FileName)
		}
		facts, err := parsedFactsFromStoredCertificate(ctx, tx, certificate)
		if err != nil {
			return importedKeyCandidate{}, "", err
		}
		if !sameSubject(file.CRL.IssuerSubject, facts.Subject) || !authorityKeyIDMatches(file.CRL.AuthorityKeyID, facts.SubjectKeyID) {
			return importedKeyCandidate{}, "", contract.NewAppError(contract.ErrorKindConflict, "import_crl_issuer_mismatch",
				"the CRL issuer facts do not match issuer_certificate_id").WithField("file_name", file.FileName)
		}
		return importedKeyCandidate{CertificateID: certificate.ID(), Certificate: facts}, "", nil
	}

	batchMatches := make([]importedKeyCandidate, 0)
	batchNames := make([]string, 0)
	seenBatchMatches := make(map[string]struct{})
	fileIndexByName := make(map[string]int, len(files))
	for i, candidate := range files {
		fileIndexByName[candidate.FileName] = i
		if candidate.Kind != contract.ImportFileKindCertificate || candidate.Cert.Kind != domain.CertificateKindCA {
			continue
		}
		if !sameSubject(file.CRL.IssuerSubject, candidate.Cert.Subject) || !authorityKeyIDMatches(file.CRL.AuthorityKeyID, candidate.Cert.SubjectKeyID) {
			continue
		}
		if i >= len(resolved) || resolved[i].Status == contract.ImportItemStatusConflict {
			continue
		}

		matched := importedKeyCandidate{FileName: candidate.FileName, Certificate: candidate.Cert}
		batchName := candidate.FileName
		switch resolved[i].Status {
		case contract.ImportItemStatusDuplicate:
			if resolved[i].ExistingCertificateID != "" {
				storedCertificate, err := tx.PKI().GetCertificate(ctx, resolved[i].ExistingCertificateID)
				if err != nil {
					return importedKeyCandidate{}, "", storeError(err, "import_crl_issuer_read_failed", "could not read the duplicate CRL issuer certificate")
				}
				facts, err := parsedFactsFromStoredCertificate(ctx, tx, storedCertificate)
				if err != nil {
					return importedKeyCandidate{}, "", err
				}
				matched = importedKeyCandidate{CertificateID: storedCertificate.ID(), Certificate: facts}
				batchName = ""
			} else {
				canonicalName, ok := canonicalNewImportFileName(candidate.FileName, files, resolved, fileIndexByName)
				if !ok {
					continue
				}
				canonicalIndex := fileIndexByName[canonicalName]
				matched = importedKeyCandidate{FileName: canonicalName, Certificate: files[canonicalIndex].Cert}
				batchName = canonicalName
			}
		case contract.ImportItemStatusNew:
		default:
			continue
		}

		matchKey := string(matched.CertificateID)
		if matchKey == "" {
			matchKey = matched.FileName
		}
		if _, seen := seenBatchMatches[matchKey]; seen {
			continue
		}
		seenBatchMatches[matchKey] = struct{}{}
		batchMatches = append(batchMatches, matched)
		batchNames = append(batchNames, batchName)
	}
	if len(batchMatches) == 1 {
		return batchMatches[0], batchNames[0], nil
	}
	if len(batchMatches) > 1 {
		return importedKeyCandidate{}, "", contract.NewAppError(contract.ErrorKindConflict, "import_crl_issuer_ambiguous",
			"the CRL matches more than one bundled CA certificate").WithField("file_name", file.FileName)
	}

	storedMatches := make([]importedKeyCandidate, 0)
	for _, certificate := range stored {
		facts, err := parsedFactsFromStoredCertificate(ctx, tx, certificate)
		if err != nil {
			return importedKeyCandidate{}, "", err
		}
		if sameSubject(file.CRL.IssuerSubject, facts.Subject) && authorityKeyIDMatches(file.CRL.AuthorityKeyID, facts.SubjectKeyID) {
			storedMatches = append(storedMatches, importedKeyCandidate{CertificateID: certificate.ID(), Certificate: facts})
		}
	}
	if len(storedMatches) == 1 {
		return storedMatches[0], "", nil
	}
	if len(storedMatches) > 1 {
		return importedKeyCandidate{}, "", contract.NewAppError(contract.ErrorKindConflict, "import_crl_issuer_ambiguous",
			"the CRL matches more than one stored CA certificate").WithField("file_name", file.FileName)
	}
	return importedKeyCandidate{}, "", contract.NewAppError(contract.ErrorKindConflict, "import_crl_issuer_unresolved",
		"the CRL issuer could not be resolved from bundled or stored CA certificates").WithField("file_name", file.FileName)
}

// canonicalNewImportFileName follows an exact-DER duplicate in the same
// batch to the first logical certificate item that will actually be stored.
// A duplicate that points at an existing certificate is handled separately by
// resolveCRLIssuer; this helper only returns a New batch item.
func canonicalNewImportFileName(name string, files []parsedImportFile, resolved []importResolution, byName map[string]int) (string, bool) {
	seen := make(map[string]struct{}, len(files))
	for name != "" {
		if _, ok := seen[name]; ok {
			return "", false
		}
		seen[name] = struct{}{}
		index, ok := byName[name]
		if !ok || index >= len(resolved) {
			return "", false
		}
		item := resolved[index]
		if item.Status == contract.ImportItemStatusNew {
			return name, true
		}
		if item.Status != contract.ImportItemStatusDuplicate || item.DuplicateOfFileName == "" {
			return "", false
		}
		name = item.DuplicateOfFileName
	}
	return "", false
}

func authorityKeyIDMatches(crlAKI, subjectSKI []byte) bool {
	if len(crlAKI) == 0 {
		return true
	}
	// Older stored certificates may predate retention of the raw SKI. The
	// explicit issuer relation plus the CRL signature verifier still proves the
	// selected certificate; lack of the optional comparison fact is not itself
	// an issuer mismatch.
	if len(subjectSKI) == 0 {
		return true
	}
	return len(subjectSKI) > 0 && bytes.Equal(crlAKI, subjectSKI)
}

// resolvePublicKey checks the SPKI-duplicate rule
// (docs/pki-import.md "기존 인증서와 같은 공개키를 쓰는 다른 인증서 → '중복된
// 인증서' 팝업을 표시하고 등록 거부") against both the store and every earlier
// file in this same batch ("공개키 중복 검사는 기존 등록 항목과 같은 가져오기
// 묶음 내 항목에 적용한다"), and separately records a compromise-cascade
// target when the key is known-bad but not otherwise in conflict. It returns
// true when r was set to a conflict.
func (s *ImportService) resolvePublicKey(ctx context.Context, tx port.TxStores, files []parsedImportFile, out []importResolution, i int, r *importResolution) bool {
	existingKey, err := tx.PKI().FindKeyBySPKI(ctx, r.Cert.SPKIFingerprint)
	if err == nil {
		certs, lerr := tx.PKI().ListCertificatesUsingKey(ctx, existingKey.ID)
		if lerr != nil {
			r.Status = contract.ImportItemStatusConflict
			r.ErrorCode = "import_key_usage_lookup_failed"
			return true
		}
		if len(certs) > 0 {
			r.Status = contract.ImportItemStatusConflict
			r.ErrorCode = "import_duplicate_public_key"
			return true
		}
		if !existingKey.CompromisedAt.IsZero() {
			r.CompromisedKeyMaterialID = existingKey.ID
			r.CompromisedAt = existingKey.CompromisedAt
		}
		r.ExistingKeyMaterialID = existingKey.ID
	} else if !errors.Is(err, port.ErrNotFound) {
		r.Status = contract.ImportItemStatusConflict
		r.ErrorCode = "import_key_lookup_failed"
		return true
	}

	for j := 0; j < i; j++ {
		if out[j].Status == contract.ImportItemStatusConflict || out[j].Status == contract.ImportItemStatusDuplicate {
			continue
		}
		if files[j].Cert.SPKIFingerprint.Equal(r.Cert.SPKIFingerprint) {
			r.Status = contract.ImportItemStatusConflict
			r.ErrorCode = "import_duplicate_public_key"
			return true
		}
	}
	return false
}

// resolveIssuer resolves r's issuer: self-signed, another New file in this
// same batch (matched by subject DN), or an already-stored CA certificate
// named by metadata.IssuerCertificateID. An orphan -- no self-signature, no
// batch match, no hint -- is a conflict rather than a silently-skipped file
// (docs/pki-import.md "고립된 Intermediate·Leaf는 등록하지 않는다").
func (s *ImportService) resolveIssuer(ctx context.Context, tx port.TxStores, files []parsedImportFile, out []importResolution, i int, r *importResolution) {
	if sameSubject(r.Cert.IssuerSubject, r.Cert.Subject) {
		if r.Cert.Kind != domain.CertificateKindCA {
			r.Status = contract.ImportItemStatusConflict
			r.ErrorCode = "import_leaf_self_signed"
			return
		}
		r.SelfSigned = true
		r.Status = contract.ImportItemStatusNew
		return
	}

	matchedFileName := ""
	matchedFileIndex := -1
	matchCount := 0
	for j, other := range files {
		if j == i {
			continue
		}
		if out[j].Status == contract.ImportItemStatusConflict || out[j].Status == contract.ImportItemStatusDuplicate {
			continue
		}
		if other.Cert.Kind == domain.CertificateKindCA && sameSubject(other.Cert.Subject, r.Cert.IssuerSubject) {
			matchedFileName = other.FileName
			matchedFileIndex = j
			matchCount++
		}
	}
	if matchCount > 1 {
		r.Status = contract.ImportItemStatusConflict
		r.ErrorCode = "import_issuer_ambiguous"
		return
	}
	if matchCount == 1 {
		if code := sameBatchIssuerDepthError(r.Cert.Kind, files[matchedFileIndex].Cert); code != "" {
			r.Status = contract.ImportItemStatusConflict
			r.ErrorCode = code
			return
		}
		r.IssuerBatchFileName = matchedFileName
		r.Status = contract.ImportItemStatusNew
		return
	}

	hint := files[i].IssuerCertificateID
	if hint == "" {
		r.Status = contract.ImportItemStatusConflict
		r.ErrorCode = "import_issuer_unresolved"
		return
	}
	issuerCert, err := tx.PKI().GetCertificate(ctx, hint)
	switch {
	case errors.Is(err, port.ErrNotFound):
		r.Status = contract.ImportItemStatusConflict
		r.ErrorCode = "import_issuer_not_found"
		return
	case err != nil:
		r.Status = contract.ImportItemStatusConflict
		r.ErrorCode = "import_issuer_read_failed"
		return
	}
	if issuerCert.Kind() != domain.CertificateKindCA || !sameSubject(issuerCert.Subject(), r.Cert.IssuerSubject) {
		r.Status = contract.ImportItemStatusConflict
		r.ErrorCode = "import_issuer_mismatch"
		return
	}
	if code := s.storedIssuerDepthError(ctx, tx, r.Cert.Kind, issuerCert.ID()); code != "" {
		r.Status = contract.ImportItemStatusConflict
		r.ErrorCode = code
		return
	}
	r.IssuerExistingCertificateID = issuerCert.ID()
	r.Status = contract.ImportItemStatusNew
}

// sameBatchIssuerDepthError enforces the MVP's fixed Root -> Intermediate ->
// Leaf shape before the chain validator is called. A self-signed bundled CA
// is a Root; a non-self-signed bundled CA is an Intermediate. Importing an
// additional CA below an Intermediate or a Leaf directly below a Root is
// explicitly unsupported by docs/pki-import.md.
func sameBatchIssuerDepthError(childKind domain.CertificateKind, issuer port.ParsedCertificateFacts) string {
	issuerIsRoot := sameSubject(issuer.Subject, issuer.IssuerSubject)
	switch childKind {
	case domain.CertificateKindLeaf:
		if issuerIsRoot {
			return "import_root_direct_leaf"
		}
		return ""
	case domain.CertificateKindCA:
		if !issuerIsRoot {
			return "import_ca_chain_too_deep"
		}
		return ""
	}
	return "import_issuer_kind_invalid"
}

// storedIssuerDepthError applies the same fixed hierarchy to an issuer that
// already belongs to the database. The Authority kind is read through the
// stored CA certificate -> generation -> authority relation, never inferred
// from a client-supplied name or id.
func (s *ImportService) storedIssuerDepthError(ctx context.Context, tx port.TxStores, childKind domain.CertificateKind, issuerCertificateID domain.CertificateID) string {
	authorityID, err := s.authorityOwning(ctx, tx, issuerCertificateID)
	if err != nil {
		return "import_issuer_scope_unavailable"
	}
	authority, err := tx.PKI().GetIssuerForUpdate(ctx, authorityID)
	if err != nil {
		return "import_issuer_scope_unavailable"
	}
	switch childKind {
	case domain.CertificateKindLeaf:
		if authority.Kind() == domain.AuthorityKindRoot {
			return "import_root_direct_leaf"
		}
		if authority.Kind() != domain.AuthorityKindIntermediate {
			return "import_leaf_issuer_kind_invalid"
		}
	case domain.CertificateKindCA:
		if authority.Kind() != domain.AuthorityKindRoot {
			return "import_ca_chain_too_deep"
		}
	default:
		return "import_issuer_kind_invalid"
	}
	return ""
}

// verifyChains runs ChainValidator against every resolved New certificate,
// including a self-signed Root (with the Root itself as the trust anchor),
// walking same-batch ancestors and any stored tail up to a trusted root
// (docs/pki-import.md "이름 비교뿐 아니라 실제 서명과 CA 제약으로
// 체인을 검증한다"). now is the validated-at time: the certificate's own
// NotBefore, so an expired historical import is checked against the period it
// was actually issued in, not the current wall clock
// (docs/pki-import.md "만료 인증서는 원래 유효 시점의 서명·계층 제약을
// 검증하여 이력으로 보존한다").
func (s *ImportService) verifyChains(ctx context.Context, tx port.TxStores, files []parsedImportFile, out []importResolution) error {
	byName := make(map[string]int, len(files))
	for i, f := range files {
		byName[f.FileName] = i
	}
	for i := range out {
		r := &out[i]
		if r.Kind != contract.ImportFileKindCertificate || r.Status != contract.ImportItemStatusNew {
			continue
		}
		var chainDER [][]byte
		var err error
		if r.SelfSigned {
			chainDER = [][]byte{r.Cert.DER}
		} else {
			chainDER, err = s.buildVerificationChain(ctx, tx, files, out, byName, r)
			if err != nil {
				return err
			}
		}
		if err := s.deps.ChainValidator.Validate(ctx, r.Cert.DER, chainDER, r.Cert.Validity.NotBefore()); err != nil {
			r.Status = contract.ImportItemStatusConflict
			r.ErrorCode = "import_chain_invalid"
		}
	}
	return nil
}

func (s *ImportService) buildVerificationChain(ctx context.Context, tx port.TxStores, files []parsedImportFile, out []importResolution, byName map[string]int, r *importResolution) ([][]byte, error) {
	var chain [][]byte
	switch {
	case r.IssuerBatchFileName != "":
		cur := r.IssuerBatchFileName
		for cur != "" {
			j, ok := byName[cur]
			if !ok {
				return nil, contract.NewAppError(contract.ErrorKindUnavailable, "import_chain_batch_reference_missing",
					"a resolved same-batch issuer reference could not be found")
			}
			chain = append(chain, files[j].Cert.DER)
			anc := out[j]
			switch {
			case anc.SelfSigned:
				cur = ""
			case anc.IssuerBatchFileName != "":
				cur = anc.IssuerBatchFileName
			case anc.IssuerExistingCertificateID != "":
				rest, err := existingIssuerChainDER(ctx, tx, anc.IssuerExistingCertificateID)
				if err != nil {
					return nil, err
				}
				chain = append(chain, rest...)
				cur = ""
			default:
				cur = ""
			}
		}
	case r.IssuerExistingCertificateID != "":
		rest, err := existingIssuerChainDER(ctx, tx, r.IssuerExistingCertificateID)
		if err != nil {
			return nil, err
		}
		chain = rest
	}
	return chain, nil
}

// existingIssuerChainDER walks the ALREADY-stored issuer chain starting AT
// (and including) certID, up to and including the self-signed root, using
// the same stored-relation walk buildChainDER uses for a leaf -- but
// starting from an arbitrary CA certificate id rather than a leaf's own
// record, since Import resolves issuers by certificate id directly.
func existingIssuerChainDER(ctx context.Context, tx port.TxStores, certID domain.CertificateID) ([][]byte, error) {
	var chain [][]byte
	seen := map[domain.CertificateID]struct{}{}
	next := certID
	for depth := 0; depth < maxChainDepth; depth++ {
		if _, cycle := seen[next]; cycle {
			return nil, chainError("import_chain_cycle", "the stored issuer chain is cyclic", next)
		}
		seen[next] = struct{}{}
		cert, err := tx.PKI().GetCertificate(ctx, next)
		if err != nil {
			return nil, storeError(err, "import_chain_certificate_read_failed", "could not read a chain certificate")
		}
		chain = append(chain, cert.DER())
		record, err := tx.PKI().GetCACertificateRecord(ctx, next)
		if err != nil {
			return nil, storeError(err, "import_chain_record_read_failed", "could not read a CA certificate record")
		}
		if record.IssuerCACertificateID == "" {
			return chain, nil
		}
		next = record.IssuerCACertificateID
	}
	return nil, chainError("import_chain_too_deep", "the stored issuer chain is longer than supported", certID)
}

// ---- manifest/item projection ----

func buildManifestAndItems(out []importResolution) (contract.PublicImportManifest, []contract.ImportItemView, error) {
	files := make([]contract.ImportManifestFileFacts, len(out))
	items := make([]contract.ImportItemView, len(out))
	for i, r := range out {
		var issuerCertID domain.CertificateID
		if r.IssuerExistingCertificateID != "" {
			issuerCertID = r.IssuerExistingCertificateID
		}
		files[i] = contract.ImportManifestFileFacts{
			FileID:              r.UploadFileName,
			Kind:                r.Kind,
			SHA256:              r.DERSHA256,
			IssuerCertificateID: issuerCertID,
		}
		item := contract.ImportItemView{
			FileID:    r.UploadFileName,
			SHA256:    r.DERSHA256,
			Kind:      r.Kind,
			Status:    r.Status,
			ErrorCode: r.ErrorCode,
		}
		if r.Status == contract.ImportItemStatusDuplicate && r.ExistingCertificateID != "" {
			id := r.ExistingCertificateID
			item.ExistingID = &id
		}
		items[i] = item
	}
	manifest, err := contract.NewPublicImportManifest(files)
	if err != nil {
		return contract.PublicImportManifest{}, nil, err
	}
	return manifest, items, nil
}

func publicImportFileName(name, uploadName string) string {
	if uploadName != "" {
		return uploadName
	}
	return name
}

// ---- Preview ----

// Preview parses and resolves an upload against the CURRENT store state
// without persisting anything (docs/backend-implementation.md §13 "Import
// Preview는 batch를 영속화하지 않는다").
func (s *ImportService) Preview(ctx context.Context, meta contract.MutationMeta, cmd contract.ImportUploadCommand) (contract.ImportPreviewView, error) {
	cmd.RequireManifest = false
	if err := cmd.Validate(); err != nil {
		return contract.ImportPreviewView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.ImportPreviewView{}, contract.NewAppError(contract.ErrorKindForbidden, "import_requires_admin",
			"previewing an import requires an administrator session")
	}
	// §6: admission (auth+authorization) is checked before any expensive
	// parsing/decryption work.
	if err := s.checkAuth(ctx, meta, port.ActionImportPreview); err != nil {
		return contract.ImportPreviewView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.ImportPreviewView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	files, err := s.parseFiles(ctx, cmd)
	if err != nil {
		return contract.ImportPreviewView{}, err
	}
	preparedKeys, err := s.prepareImportKeys(ctx, files)
	if err != nil {
		return contract.ImportPreviewView{}, err
	}
	defer closePreparedImportKeys(preparedKeys)

	var result contract.ImportPreviewView
	err = s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionImportPreview, port.NewAuthorizationScope()); err != nil {
			return err
		}
		resolved, err := s.resolveImportItems(ctx, tx, files)
		if err != nil {
			return err
		}
		if err := s.verifyChains(ctx, tx, files, resolved); err != nil {
			return err
		}
		if err := s.resolveImportAuxiliaryItems(ctx, tx, files, resolved, preparedKeys); err != nil {
			return err
		}
		manifest, items, err := buildManifestAndItems(resolved)
		if err != nil {
			return err
		}
		result = contract.ImportPreviewView{Manifest: manifest, Items: items}
		return nil
	})
	if err != nil {
		return contract.ImportPreviewView{}, err
	}
	return result, nil
}

// checkAuth is the early, non-authoritative admission probe every method
// runs before its own expensive work: authenticate then authorize, in that
// order, matching requireCurrentAuth's own doc comment on why authentication
// precedes authorization and any replay probe.
func (s *ImportService) checkAuth(ctx context.Context, meta contract.MutationMeta, action port.Action) error {
	return s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		return s.deps.Authorizer.Authorize(ctx, meta.Principal, action, port.NewAuthorizationScope())
	})
}

// ---- Commit idempotency (§13 rule 6) ----

// importHashFile is one file's entry in the v1 idempotency envelope: kind,
// normalized public artifact hash and issuer linkage only -- never a
// passphrase or private-key byte (§13 rule 6 "passphrase·개인키 원문은
// 제외"). For ca_key the hash is the verified public SPKI, exactly like the
// public manifest; certificates and CRLs use their signed DER. Files are
// sorted by file id before hashing ("파일 ID 순 정렬한 공개 manifest").
type importHashFile struct {
	FileID              string `json:"file_id"`
	Kind                string `json:"kind"`
	SHA256              string `json:"sha256"`
	IssuerCertificateID string `json:"issuer_certificate_id,omitempty"`
}

// importHashTakeover is one takeover confirmation bundled with the import,
// sorted by CA fingerprint before hashing ("issuer 연결 및 CA 지문 순
// 정렬한 takeover 입력").
type importHashTakeover struct {
	CACertificateSHA256 string               `json:"ca_certificate_sha256"`
	HistoryAssertion    string               `json:"history_assertion"`
	PreviousMaxNumber   string               `json:"previous_max_number_hex"`
	ExternalStoppedAt   string               `json:"external_issuer_stopped_at"`
	Evidence            TakeoverEvidenceHash `json:"evidence"`
}

// TakeoverEvidenceHash is the hashed shape of contract.TakeoverEvidence.
type TakeoverEvidenceHash struct {
	CRLSHA256              []string `json:"crl_sha256"`
	IssuanceRecordsChecked bool     `json:"issuance_records_checked"`
	CRLRoutesChecked       bool     `json:"crl_routes_checked"`
}

type importCommitHashInput struct {
	Files     []importHashFile     `json:"files"`
	Takeovers []importHashTakeover `json:"takeovers"`
}

func commitInputHash(cmd contract.ImportUploadCommand, files []parsedImportFile) (string, error) {
	hashFiles := make([]importHashFile, 0, len(files))
	for _, f := range files {
		hashFiles = append(hashFiles, importHashFile{
			FileID:              publicImportFileName(f.FileName, f.UploadFileName),
			Kind:                string(f.Kind),
			SHA256:              NormalizeFingerprint(f.DERSHA256.Hex()),
			IssuerCertificateID: NormalizeUUID(string(f.IssuerCertificateID)),
		})
	}
	sort.Slice(hashFiles, func(i, j int) bool {
		if hashFiles[i].FileID != hashFiles[j].FileID {
			return hashFiles[i].FileID < hashFiles[j].FileID
		}
		if hashFiles[i].Kind != hashFiles[j].Kind {
			return hashFiles[i].Kind < hashFiles[j].Kind
		}
		if hashFiles[i].SHA256 != hashFiles[j].SHA256 {
			return hashFiles[i].SHA256 < hashFiles[j].SHA256
		}
		return hashFiles[i].IssuerCertificateID < hashFiles[j].IssuerCertificateID
	})

	hashTakeovers := make([]importHashTakeover, 0, len(cmd.Metadata.Takeovers))
	for _, t := range cmd.Metadata.Takeovers {
		hashTakeovers = append(hashTakeovers, importHashTakeover{
			CACertificateSHA256: NormalizeFingerprint(t.CACertificateSHA256Hex),
			HistoryAssertion:    string(t.Confirmation.HistoryAssertion),
			PreviousMaxNumber:   t.Confirmation.PreviousMaxNumberHex,
			ExternalStoppedAt:   t.Confirmation.ExternalIssuerStoppedAt,
			Evidence: TakeoverEvidenceHash{
				CRLSHA256:              normalizeCRLHashes(t.Confirmation.Evidence.CRLSHA256Hex),
				IssuanceRecordsChecked: t.Confirmation.Evidence.IssuanceRecordsChecked,
				CRLRoutesChecked:       t.Confirmation.Evidence.CRLRoutesChecked,
			},
		})
	}
	sort.Slice(hashTakeovers, func(i, j int) bool {
		return hashTakeovers[i].CACertificateSHA256 < hashTakeovers[j].CACertificateSHA256
	})

	return InputHash(importOperationCommit, map[string]string{}, importCommitHashInput{Files: hashFiles, Takeovers: hashTakeovers})
}

func normalizeCRLHashes(raw []string) []string {
	out := make([]string, len(raw))
	for i, h := range raw {
		out[i] = NormalizeFingerprint(h)
	}
	sort.Strings(out)
	return out
}

const importStoredResultSchemaVersion = 1

type storedImportResult struct {
	SchemaVersion int                       `json:"schema_version"`
	Result        contract.ImportResultView `json:"result"`
}

// ---- Commit ----

// Commit re-verifies the upload against the current store and, if nothing
// conflicts, persists every new certificate/authority in one Write
// (docs/backend-implementation.md §8 "import" row). Commit is idempotent
// (§3); a stored result is returned verbatim on replay because the batch is
// write-once (§13 "Commit의 결과 batch는 write-once로 유지한다").
func (s *ImportService) Commit(ctx context.Context, meta contract.MutationMeta, cmd contract.ImportUploadCommand) (contract.ImportResultView, error) {
	cmd.RequireManifest = true
	if err := cmd.Validate(); err != nil {
		return contract.ImportResultView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.ImportResultView{}, contract.NewAppError(contract.ErrorKindForbidden, "import_requires_admin",
			"committing an import requires an administrator session")
	}
	reqKey, err := RequestKey(meta, importOperationCommit)
	if err != nil {
		return contract.ImportResultView{}, err
	}

	// §6/§8: authenticate+authorize before any expensive parse/decryption
	// work. The idempotency hash is intentionally computed only after parsing:
	// ca_key's public manifest hash is normalized from the verified SPKI and
	// must never be derived from private-key file bytes.
	if err := s.checkAuth(ctx, meta, port.ActionImportCommit); err != nil {
		return contract.ImportResultView{}, err
	}

	files, err := s.parseFiles(ctx, cmd)
	if err != nil {
		return contract.ImportResultView{}, err
	}
	preparedKeys, err := s.prepareImportKeys(ctx, files)
	if err != nil {
		return contract.ImportResultView{}, err
	}
	defer closePreparedImportKeys(preparedKeys)
	if err := verifyPreviewManifestMatches(cmd, files); err != nil {
		return contract.ImportResultView{}, err
	}
	inputHash, err := commitInputHash(cmd, files)
	if err != nil {
		return contract.ImportResultView{}, err
	}

	// Authenticate and authorize again in the replay probe. A principal that
	// lost access while parsing must not receive an old result, and the same
	// check is repeated inside commitImport after the write lock is held.
	var result contract.ImportResultView
	found, err := s.replayCommit(ctx, reqKey, inputHash, meta.Principal, &result)
	if err != nil {
		return contract.ImportResultView{}, err
	}
	if found {
		return result, nil
	}

	if err := ctx.Err(); err != nil {
		return contract.ImportResultView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	if err := s.encryptPreparedImportKeys(ctx, preparedKeys); err != nil {
		return contract.ImportResultView{}, err
	}

	err = RunWithRetry(ctx, func() error {
		return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
			return s.commitImport(ctx, tx, meta, reqKey, inputHash, files, cmd.Metadata.Takeovers, preparedKeys, &result)
		})
	})
	if err != nil {
		return contract.ImportResultView{}, err
	}
	return result, nil
}

func (s *ImportService) replayCommit(ctx context.Context, reqKey port.OperationRequestKey, inputHash string, principal contract.Principal, result *contract.ImportResultView) (bool, error) {
	var found bool
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, principal, port.ActionImportCommit, port.NewAuthorizationScope()); err != nil {
			return err
		}
		stored, ok, err := ReplayStoredResult(ctx, tx, reqKey, inputHash)
		if err != nil || !ok {
			return err
		}
		var v storedImportResult
		if err := DecodeStoredResult(stored, &v); err != nil {
			return err
		}
		if v.SchemaVersion != importStoredResultSchemaVersion {
			return contract.NewAppError(contract.ErrorKindUnavailable, "import_stored_result_schema_unsupported",
				"a stored import result carries an unsupported schema_version")
		}
		*result = v.Result
		found = true
		return nil
	})
	return found, err
}

// verifyPreviewManifestMatches enforces that a Commit whose metadata replays
// a preview_manifest actually matches what parsing the RESENT files produces
// right now -- Commit re-uploads the same files rather than referencing a
// persisted preview (§13: Preview persists nothing), so this is the check
// that the resend is the same upload the client previewed, not a
// silently-different one riding the same preview_manifest echo.
func verifyPreviewManifestMatches(cmd contract.ImportUploadCommand, files []parsedImportFile) error {
	if cmd.Metadata.PreviewManifest == nil {
		return nil
	}
	want := make(map[string][]contract.ImportManifestFileInput, len(cmd.Metadata.PreviewManifest.Files))
	for _, f := range cmd.Metadata.PreviewManifest.Files {
		want[f.FileID] = append(want[f.FileID], f)
	}
	wantCount := 0
	for _, entries := range want {
		wantCount += len(entries)
	}
	if wantCount != len(files) {
		return contract.NewAppError(contract.ErrorKindConflict, "import_manifest_mismatch",
			"the resent files do not match the previewed manifest")
	}
	for _, f := range files {
		fileID := publicImportFileName(f.FileName, f.UploadFileName)
		entries := want[fileID]
		match := -1
		for i, expect := range entries {
			if expect.Kind == f.Kind &&
				NormalizeFingerprint(expect.SHA256Hex) == f.DERSHA256.Hex() &&
				NormalizeUUID(string(expect.IssuerCertificateID)) == NormalizeUUID(string(f.IssuerCertificateID)) {
				match = i
				break
			}
		}
		if match < 0 {
			return contract.NewAppError(contract.ErrorKindConflict, "import_manifest_mismatch",
				"the resent files do not match the previewed manifest").WithField("file_name", fileID)
		}
		want[fileID] = append(entries[:match], entries[match+1:]...)
	}
	for fileID, entries := range want {
		if len(entries) != 0 {
			return contract.NewAppError(contract.ErrorKindConflict, "import_manifest_mismatch",
				"the resent files do not match the previewed manifest").WithField("file_name", fileID)
		}
	}
	return nil
}

// commitImport is Commit's single Write: authorization, replay, then the
// authoritative resolve/verify against the just-locked store state, then
// storage.
//
// takeovers is ImportMetadataInput.Takeovers, matched to a resolved NEW CA
// item by its own DER SHA-256 (contract.ImportTakeoverConfirmationInput.
// CACertificateSHA256Hex). A matched CA is created with PendingTakeover=true
// plus a pending ca_takeovers row for ConfirmTakeover to later confirm; an
// unmatched imported CA is created with PendingTakeover=false. No doc
// settles whether every imported CA MUST carry a takeover declaration --
// see this file's report to the lead -- so an absent declaration is treated
// as the operator's choice not to gate this CA behind a takeover
// confirmation, not as a validation error.
func (s *ImportService) commitImport(ctx context.Context, tx port.TxStores, meta contract.MutationMeta, reqKey port.OperationRequestKey, inputHash string, files []parsedImportFile, takeovers []contract.ImportTakeoverConfirmationInput, preparedKeys map[string]preparedImportKey, result *contract.ImportResultView) error {
	if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
		return err
	}
	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionImportCommit, port.NewAuthorizationScope()); err != nil {
		return err
	}
	if stored, found, err := ReplayStoredResult(ctx, tx, reqKey, inputHash); err != nil {
		return err
	} else if found {
		var v storedImportResult
		if err := DecodeStoredResult(stored, &v); err != nil {
			return err
		}
		*result = v.Result
		return nil
	}

	resolved, err := s.resolveImportItems(ctx, tx, files)
	if err != nil {
		return err
	}
	if err := s.verifyChains(ctx, tx, files, resolved); err != nil {
		return err
	}
	if err := s.resolveImportAuxiliaryItems(ctx, tx, files, resolved, preparedKeys); err != nil {
		return err
	}
	for _, r := range resolved {
		if r.Status == contract.ImportItemStatusConflict {
			return contract.NewAppError(contract.ErrorKindConflict, "import_batch_conflict",
				"the import batch has one or more conflicting files and was not applied").
				WithField("file_name", r.FileName).WithField("error_code", r.ErrorCode)
		}
	}

	now := s.deps.Clock.Now()
	batchID, err := domain.ParseImportBatchID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.FromDomainError(err)
	}

	byName := make(map[string]int, len(files))
	for i, f := range files {
		byName[f.FileName] = i
	}
	authorityIDByFile := map[string]domain.AuthorityID{}
	certificateIDByFile := map[string]domain.CertificateID{}
	keyGenerationIDByFile := map[string]domain.CAKeyGenerationID{}
	var certificateIDs []domain.CertificateID
	authorityScope := map[domain.AuthorityID]struct{}{}
	var revocationChanges []RevocationChange

	takeoversByDER := make(map[string]contract.ImportTakeoverConfirmationInput, len(takeovers))
	for _, t := range takeovers {
		takeoversByDER[NormalizeFingerprint(t.CACertificateSHA256Hex)] = t
	}

	// Resolve dependency order: an item whose issuer is another same-batch
	// New item must be stored after that issuer. At most two CA levels are
	// permitted (docs/pki-import.md), so a bounded number of passes suffices;
	// any leftover after that many passes is a cycle the resolve step above
	// should already have caught, and is treated as an error rather than an
	// infinite loop.
	order, err := topologicalOrder(files, resolved)
	if err != nil {
		return err
	}

	for _, i := range order {
		r := resolved[i]
		if r.Kind == contract.ImportFileKindCAKey || r.Kind == contract.ImportFileKindCRL {
			if r.Kind == contract.ImportFileKindCAKey && r.KeyTargetBatchFileName != "" {
				// The matching CA certificate stores the encrypted key as part
				// of its own atomic insert. A same-batch key entry is therefore
				// only a manifest/result item here.
				continue
			}
			if r.Kind == contract.ImportFileKindCRL {
				changes, authorityID, err := s.insertImportedCRL(ctx, tx, files[i], r, certificateIDByFile, authorityIDByFile, keyGenerationIDByFile)
				if err != nil {
					return err
				}
				authorityScope[authorityID] = struct{}{}
				revocationChanges = append(revocationChanges, changes...)
				continue
			}
			if err := s.attachImportedExistingKey(ctx, tx, meta, now, files[i], r, preparedKeys[files[i].FileName]); err != nil {
				return err
			}
			continue
		}
		switch r.Status {
		case contract.ImportItemStatusDuplicate:
			existingID := r.ExistingCertificateID
			if existingID == "" {
				// Duplicate of an earlier file in this SAME batch: resolve to
				// whatever certificate id that earlier file ended up with.
				existingID = certificateIDByFile[r.DuplicateOfFileName]
			}
			certificateIDByFile[r.FileName] = existingID
			authID, err := s.authorityOwning(ctx, tx, existingID)
			if err != nil {
				return err
			}
			authorityScope[authID] = struct{}{}
			if r.CompromisedKeyMaterialID != "" {
				revocationChanges = append(revocationChanges, s.compromiseCascadeChange(ctx, tx, existingID, authID, r))
			}
			continue
		case contract.ImportItemStatusNew:
			var takeover *contract.ImportTakeoverConfirmationInput
			if matched, ok := takeoversByDER[r.DERSHA256.Hex()]; ok {
				takeover = &matched
			}
			var certID domain.CertificateID
			var authID domain.AuthorityID
			var keyGenID domain.CAKeyGenerationID
			if r.Cert.Kind == domain.CertificateKindLeaf {
				certID, authID, keyGenID, err = s.insertImportedLeaf(ctx, tx, files[byName[r.FileName]], r, authorityIDByFile, certificateIDByFile, keyGenerationIDByFile)
			} else {
				certID, authID, keyGenID, err = s.insertImportedAuthority(ctx, tx, meta, now, files[byName[r.FileName]], r, authorityIDByFile, certificateIDByFile, keyGenerationIDByFile, takeover, preparedKeys)
			}
			if err != nil {
				return err
			}
			certificateIDByFile[r.FileName] = certID
			authorityIDByFile[r.FileName] = authID
			keyGenerationIDByFile[r.FileName] = keyGenID
			certificateIDs = append(certificateIDs, certID)
			authorityScope[authID] = struct{}{}
			if r.CompromisedKeyMaterialID != "" {
				revocationChanges = append(revocationChanges, s.compromiseCascadeChange(ctx, tx, certID, authID, r))
			}
			if change, ok, err := s.existingRevocationHistoryChange(ctx, tx, certID, authID); err != nil {
				return err
			} else if ok {
				revocationChanges = append(revocationChanges, change)
			}
		default:
			return contract.NewAppError(contract.ErrorKindUnavailable, "import_item_unresolved",
				"an import item was left in an unresolved state").WithField("file_name", r.FileName)
		}
	}

	if len(revocationChanges) > 0 {
		if _, err := applyRevocations(ctx, tx, revocationChanges, RevocationMeta{
			Request:   meta.RequestMeta,
			ActorKind: contract.AuditActorAccount,
			ActorID:   string(meta.Principal.AccountID()),
			Action:    "import.compromise_cascade",
			Now:       now,
			IDs:       s.deps.IDs,
		}); err != nil {
			return err
		}
	}

	items := make([]contract.ImportItemView, len(resolved))
	for i, r := range resolved {
		item := contract.ImportItemView{FileID: r.UploadFileName, SHA256: r.DERSHA256, Kind: r.Kind, Status: r.Status, ErrorCode: r.ErrorCode}
		if id, ok := certificateIDByFile[r.FileName]; ok && r.Status == contract.ImportItemStatusDuplicate {
			item.ExistingID = &id
		}
		items[i] = item
	}
	authorityIDs := make([]domain.AuthorityID, 0, len(authorityScope))
	for id := range authorityScope {
		authorityIDs = append(authorityIDs, id)
	}
	sort.Slice(authorityIDs, func(i, j int) bool { return authorityIDs[i] < authorityIDs[j] })
	if len(authorityIDs) == 0 {
		return contract.NewAppError(contract.ErrorKindUnavailable, "import_scope_empty",
			"could not resolve any authority scope for this import")
	}

	resultView := contract.ImportResultView{
		ID:             string(batchID),
		State:          contract.ImportResultStateCommitted,
		CommittedAt:    &now,
		Items:          items,
		CertificateIDs: certificateIDs,
		AuthorityIDs:   authorityIDs,
	}

	manifestFiles := make([]contract.ImportManifestFileFacts, len(resolved))
	for i, r := range resolved {
		manifestFiles[i] = contract.ImportManifestFileFacts{FileID: r.UploadFileName, Kind: r.Kind, SHA256: r.DERSHA256, IssuerCertificateID: r.IssuerExistingCertificateID}
	}
	manifest, err := contract.NewPublicImportManifest(manifestFiles)
	if err != nil {
		return err
	}
	if err := tx.Imports().InsertBatch(ctx, port.ImportBatch{
		ID:          batchID,
		CreatedAt:   now,
		RequestedBy: meta.Principal.AccountID(),
		Manifest:    manifest,
		State:       port.ImportBatchStateCommitted,
		CommittedAt: now,
		Result:      resultView,
	}); err != nil {
		return storeError(err, "import_batch_store_failed", "could not store the import batch")
	}

	if err := StoreRequestResult(ctx, tx, reqKey, inputHash, storedImportResult{SchemaVersion: importStoredResultSchemaVersion, Result: resultView}); err != nil {
		return err
	}

	event := port.AuditEvent{
		ID:         s.deps.IDs.NewUUID(),
		OccurredAt: now,
		ActorKind:  contract.AuditActorAccount,
		ActorID:    string(meta.Principal.AccountID()),
		Action:     importOperationCommit,
		TargetType: "import_batch",
		TargetID:   string(batchID),
		ClientIP:   clientIP(meta.RequestMeta),
		Result:     contract.AuditResultSuccess,
		Details:    contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"certificate_count": fmt.Sprint(len(certificateIDs))}},
	}
	if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(authorityIDs...)); err != nil {
		return storeError(err, "import_audit_failed", "could not record the import audit event")
	}

	*result = resultView
	return nil
}

// AttachSigningKey connects a verified private key to the authority's
// existing CA certificate/key generation. It never creates a generation or
// changes issuance/takeover state. Parsing and encryption happen before the
// write; the authority, generation, key-material and secret conditions are
// checked again while the authority row is locked in the commit.
func (s *ImportService) AttachSigningKey(ctx context.Context, meta contract.MutationMeta, cmd contract.ImportAttachSigningKeyCommand) (contract.AuthorityView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.AuthorityView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindForbidden, "import_requires_admin",
			"attaching a CA signing key requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.AuthorityView{}, err
	}

	var expectedPublicKey domain.PublicKey
	var generationID domain.CAKeyGenerationID
	var keyMaterialID domain.KeyMaterialID
	var purpose domain.SecretPurpose
	err = s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		authority, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.AuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "import_authority_not_found", "authority does not exist")
		}
		if err != nil {
			return storeError(err, "import_authority_read_failed", "could not read the authority")
		}
		scope, err := authorityScopeFromRow(authority)
		if err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionImportAttachSigningKey, port.NewAuthorizationScope(scope)); err != nil {
			return err
		}
		if authority.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "import_authority_version_conflict", "the authority has changed since this request was prepared")
		}
		if authority.KeyAvailable() {
			return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_already_attached", "the authority already has an available signing key")
		}
		generation, err := tx.PKI().GetCAKeyGeneration(ctx, authority.KeyGenerationID())
		if err != nil {
			return storeError(err, "import_ca_key_generation_read_failed", "could not read the authority's CA key generation")
		}
		if !generation.KeyDestroyedAt.IsZero() {
			return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_destroyed", "a destroyed CA key cannot be restored")
		}
		if err := verifyImportedCAKeyTarget(ctx, tx, authority, generation); err != nil {
			return err
		}
		material, err := tx.PKI().GetKeyMaterial(ctx, generation.KeyMaterialID)
		if err != nil {
			return storeError(err, "import_ca_key_material_read_failed", "could not read the authority's public key")
		}
		if !material.CompromisedAt.IsZero() {
			return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_compromised", "a compromised CA key cannot be restored")
		}
		if _, err := tx.Secrets().GetEncrypted(ctx, generation.KeyMaterialID, caSecretPurpose(authority)); err == nil {
			return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_secret_exists", "the authority already has a stored signing secret")
		} else if !errors.Is(err, port.ErrNotFound) {
			return storeError(err, "import_ca_key_secret_read_failed", "could not inspect the authority's signing secret")
		}
		expectedPublicKey = material.PublicKey
		generationID = generation.ID
		keyMaterialID = generation.KeyMaterialID
		purpose = caSecretPurpose(authority)
		return nil
	})
	if err != nil {
		return contract.AuthorityView{}, err
	}

	validated, err := s.deps.PKIParser.ParseCAKey(ctx, port.CAKeyInput{
		Data:              cmd.Key,
		Passphrase:        cmd.Passphrase,
		ExpectedPublicKey: expectedPublicKey,
	})
	if err != nil {
		return contract.AuthorityView{}, contract.WrapAppError(contract.ErrorKindValidation, "import_ca_key_invalid",
			"the uploaded CA key could not be validated against the authority", err)
	}
	if validated.PrivateKey == nil || !validated.PublicKey.Equal(expectedPublicKey) {
		if validated.PrivateKey != nil {
			_ = validated.PrivateKey.Close()
		}
		return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindValidation, "import_ca_key_mismatch",
			"the uploaded CA key does not match the authority's public key")
	}
	defer validated.PrivateKey.Close()
	generated, err := s.deps.KeyEngine.ImportCA(ctx, validated, port.KeySpec{
		KeyMaterialID: keyMaterialID,
		Algorithm:     validated.Algorithm,
		Purpose:       purpose,
	})
	if err != nil {
		return contract.AuthorityView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "import_ca_key_encrypt_failed",
			"could not encrypt the attached CA key", err)
	}
	if !generated.PublicKey.Equal(expectedPublicKey) || generated.EncryptedSecret.OwnerKeyID() != keyMaterialID || generated.EncryptedSecret.Purpose() != purpose {
		return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindUnavailable, "import_ca_key_result_mismatch",
			"the encrypted CA key did not preserve the verified identity")
	}

	var result contract.AuthorityView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		authority, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.AuthorityID)
		if err != nil {
			return storeError(err, "import_authority_read_failed", "could not read the authority")
		}
		scope, err := authorityScopeFromRow(authority)
		if err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionImportAttachSigningKey, port.NewAuthorizationScope(scope)); err != nil {
			return err
		}
		if authority.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "import_authority_version_conflict", "the authority has changed since this request was prepared")
		}
		if authority.KeyGenerationID() != generationID || authority.KeyAvailable() {
			return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_generation_changed", "the authority's key attachment state changed during preparation")
		}
		generation, err := tx.PKI().GetCAKeyGeneration(ctx, generationID)
		if err != nil {
			return storeError(err, "import_ca_key_generation_read_failed", "could not re-read the authority's CA key generation")
		}
		if generation.KeyMaterialID != keyMaterialID || !generation.KeyDestroyedAt.IsZero() {
			return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_generation_invalid", "the authority's CA key generation changed during preparation")
		}
		if err := verifyImportedCAKeyTarget(ctx, tx, authority, generation); err != nil {
			return err
		}
		material, err := tx.PKI().GetKeyMaterial(ctx, keyMaterialID)
		if err != nil {
			return storeError(err, "import_ca_key_material_read_failed", "could not re-read the authority's public key")
		}
		if !material.PublicKey.Equal(validated.PublicKey) || !material.CompromisedAt.IsZero() {
			return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_identity_invalid", "the attached key no longer matches an uncompromised public key")
		}
		if _, err := tx.Secrets().GetEncrypted(ctx, keyMaterialID, purpose); err == nil {
			return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_secret_exists", "the authority already has a stored signing secret")
		} else if !errors.Is(err, port.ErrNotFound) {
			return storeError(err, "import_ca_key_secret_read_failed", "could not inspect the authority's signing secret")
		}
		attached, err := authority.AttachSigningKey()
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Secrets().InsertEncrypted(ctx, generated.EncryptedSecret); err != nil {
			return storeError(err, "import_ca_key_secret_store_failed", "could not store the attached CA signing secret")
		}
		if err := tx.PKI().SaveAuthority(ctx, attached, expectedVersion); err != nil {
			return storeError(err, "import_ca_key_authority_save_failed", "could not save the attached CA signing key state")
		}
		now := s.deps.Clock.Now()
		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "import.attach_signing_key",
			TargetType: "authority",
			TargetID:   string(authority.ID()),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"key_generation_id": string(generationID)}},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(scope)); err != nil {
			return storeError(err, "import_ca_key_audit_failed", "could not record the CA key attachment audit event")
		}
		result = toAuthorityView(attached, domain.Instant{})
		return nil
	})
	if err != nil {
		return contract.AuthorityView{}, err
	}
	return result, nil
}

// verifyImportedCAKeyTarget proves that an imported key is being attached to
// the authority's existing CA certificate and generation. The public-key
// parser checks the uploaded key against KeyMaterial; this second relation
// check prevents a stale authority certificate pointer or a mismatched CA
// subtype row from turning AttachSigningKey into an issuer/certificate swap.
func verifyImportedCAKeyTarget(ctx context.Context, tx port.TxStores, authority domain.Authority, generation port.CAKeyGeneration) error {
	if generation.AuthorityID != authority.ID() {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_generation_mismatch",
			"the CA key generation does not belong to the authority")
	}
	certificateID := authority.IssuanceCertificateID()
	if certificateID == "" {
		return contract.NewAppError(contract.ErrorKindUnavailable, "import_ca_certificate_missing",
			"the authority has no existing CA certificate to attach the key to")
	}
	certificate, err := tx.PKI().GetCertificate(ctx, certificateID)
	if errors.Is(err, port.ErrNotFound) {
		return contract.NewAppError(contract.ErrorKindUnavailable, "import_ca_certificate_missing",
			"the authority's existing CA certificate could not be found")
	}
	if err != nil {
		return storeError(err, "import_ca_key_certificate_read_failed", "could not read the authority's existing CA certificate")
	}
	if certificate.Kind() != domain.CertificateKindCA {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_certificate_invalid",
			"the authority's issuance certificate is not a CA certificate")
	}
	if certificate.KeyMaterialID() != generation.KeyMaterialID {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_certificate_key_mismatch",
			"the authority's CA certificate does not use the generation's key material")
	}
	record, err := tx.PKI().GetCACertificateRecord(ctx, certificate.ID())
	if errors.Is(err, port.ErrNotFound) {
		return contract.NewAppError(contract.ErrorKindUnavailable, "import_ca_certificate_record_missing",
			"the authority's CA certificate record could not be found")
	}
	if err != nil {
		return storeError(err, "import_ca_certificate_record_read_failed", "could not read the authority's CA certificate record")
	}
	if record.CertificateID != certificate.ID() || record.CAKeyGenerationID != generation.ID {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_generation_mismatch",
			"the authority's CA certificate is not attached to its current key generation")
	}
	return nil
}

func caSecretPurpose(authority domain.Authority) domain.SecretPurpose {
	if authority.Kind() == domain.AuthorityKindBootstrap {
		return domain.SecretPurposeBootstrapCA
	}
	return domain.SecretPurposeCASigning
}

// topologicalOrder orders indices so a same-batch issuer is processed before
// any file that depends on it.
func topologicalOrder(files []parsedImportFile, resolved []importResolution) ([]int, error) {
	byName := make(map[string]int, len(files))
	for i, f := range files {
		byName[f.FileName] = i
	}
	done := make([]bool, len(files))
	order := make([]int, 0, len(files))
	for pass := 0; pass < len(files)+1; pass++ {
		progressed := false
		for i, r := range resolved {
			if done[i] {
				continue
			}
			if r.Status == contract.ImportItemStatusNew {
				dependency := r.IssuerBatchFileName
				if r.Kind == contract.ImportFileKindCAKey {
					dependency = r.KeyTargetBatchFileName
				}
				if dependency != "" {
					depIdx, ok := byName[dependency]
					if !ok || !done[depIdx] {
						continue
					}
				}
			}
			if r.Status != contract.ImportItemStatusNew || r.IssuerBatchFileName == "" {
				order = append(order, i)
				done[i] = true
				progressed = true
				continue
			}
			depIdx, ok := byName[r.IssuerBatchFileName]
			if ok && done[depIdx] {
				order = append(order, i)
				done[i] = true
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	if len(order) != len(files) {
		return nil, contract.NewAppError(contract.ErrorKindUnavailable, "import_dependency_unresolved",
			"could not order the import batch by issuer dependency")
	}
	return order, nil
}

// authorityOwning resolves the Authority that owns an already-stored CA
// certificate, the same two-hop walk §14.9 fixes for signing
// (CACertificateRecord -> CAKeyGenerationID -> CAKeyGeneration.AuthorityID).
func (s *ImportService) authorityOwning(ctx context.Context, tx port.TxStores, certificateID domain.CertificateID) (domain.AuthorityID, error) {
	record, err := tx.PKI().GetCACertificateRecord(ctx, certificateID)
	if err != nil {
		return "", storeError(err, "import_ca_record_read_failed", "could not read the certificate's CA record")
	}
	generation, err := tx.PKI().GetCAKeyGeneration(ctx, record.CAKeyGenerationID)
	if err != nil {
		return "", storeError(err, "import_ca_key_generation_read_failed", "could not read the certificate's CA key generation")
	}
	return generation.AuthorityID, nil
}

func resolveImportedIssuer(ctx context.Context, tx port.TxStores, r importResolution, authorityIDByFile map[string]domain.AuthorityID, certificateIDByFile map[string]domain.CertificateID, keyGenerationIDByFile map[string]domain.CAKeyGenerationID) (domain.CertificateID, domain.AuthorityID, domain.CAKeyGenerationID, error) {
	if r.IssuerBatchFileName != "" {
		certificateID := certificateIDByFile[r.IssuerBatchFileName]
		authorityID := authorityIDByFile[r.IssuerBatchFileName]
		generationID := keyGenerationIDByFile[r.IssuerBatchFileName]
		if certificateID == "" || authorityID == "" || generationID == "" {
			return "", "", "", contract.NewAppError(contract.ErrorKindUnavailable, "import_issuer_batch_unresolved",
				"the bundled issuer was not stored before its dependent certificate")
		}
		return certificateID, authorityID, generationID, nil
	}
	if r.IssuerExistingCertificateID == "" {
		return "", "", "", contract.NewAppError(contract.ErrorKindConflict, "import_issuer_unresolved",
			"the imported certificate has no resolved CA issuer")
	}
	record, err := tx.PKI().GetCACertificateRecord(ctx, r.IssuerExistingCertificateID)
	if err != nil {
		return "", "", "", storeError(err, "import_issuer_ca_record_read_failed", "could not read the imported certificate's issuer record")
	}
	generation, err := tx.PKI().GetCAKeyGeneration(ctx, record.CAKeyGenerationID)
	if err != nil {
		return "", "", "", storeError(err, "import_issuer_ca_generation_read_failed", "could not read the imported certificate's issuer generation")
	}
	return r.IssuerExistingCertificateID, generation.AuthorityID, generation.ID, nil
}

func ensureImportedSerialAvailable(ctx context.Context, tx port.TxStores, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) error {
	if existing, err := tx.PKI().FindCertificateByIssuerSerial(ctx, issuer, serial); err == nil {
		return contract.NewAppError(contract.ErrorKindConflict, "import_serial_collision",
			"another certificate already uses this issuer and serial").WithField("certificate_id", string(existing.ID()))
	} else if !errors.Is(err, port.ErrNotFound) {
		return storeError(err, "import_serial_lookup_failed", "could not check the issuer serial namespace")
	}
	existingRevocation, err := tx.Revocations().FindForUpdate(ctx, issuer, serial)
	if errors.Is(err, port.ErrNotFound) {
		return nil
	}
	if err != nil {
		return storeError(err, "import_revocation_lookup_failed", "could not check imported revocation history")
	}
	if existingRevocation.CertificateID() != "" {
		return contract.NewAppError(contract.ErrorKindConflict, "import_serial_collision",
			"the issuer and serial already belong to a revoked certificate")
	}
	return nil
}

func (s *ImportService) insertImportedLeaf(ctx context.Context, tx port.TxStores, file parsedImportFile, r importResolution, authorityIDByFile map[string]domain.AuthorityID, certificateIDByFile map[string]domain.CertificateID, keyGenerationIDByFile map[string]domain.CAKeyGenerationID) (domain.CertificateID, domain.AuthorityID, domain.CAKeyGenerationID, error) {
	issuerCertificateID, authorityID, issuerGenerationID, err := resolveImportedIssuer(ctx, tx, r, authorityIDByFile, certificateIDByFile, keyGenerationIDByFile)
	if err != nil {
		return "", "", "", err
	}
	if err := ensureImportedSerialAvailable(ctx, tx, issuerGenerationID, r.Cert.Serial); err != nil {
		return "", "", "", err
	}

	keyMaterialID := r.ExistingKeyMaterialID
	if keyMaterialID == "" {
		keyMaterialID, err = domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
		if err != nil {
			return "", "", "", contract.FromDomainError(err)
		}
		if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyMaterialID, PublicKey: r.Cert.PublicKey, Origin: "imported"}); err != nil {
			return "", "", "", storeError(err, "import_leaf_key_material_store_failed", "could not store the imported leaf public key")
		}
	}
	certificateID, err := domain.ParseCertificateID(s.deps.IDs.NewUUID())
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	certificate, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certificateID,
		DER:                     r.Cert.DER,
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: issuerGenerationID,
		Serial:                  r.Cert.Serial,
		Validity:                r.Cert.Validity,
		Subject:                 r.Cert.Subject,
		SANs:                    r.Cert.SANs,
		Kind:                    domain.CertificateKindLeaf,
		Profile:                 r.Cert.Profile,
		KeyAlgorithm:            r.Cert.KeyAlgorithm,
		Origin:                  domain.CertificateOriginImported,
	})
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	seriesID, err := domain.ParseSeriesID(s.deps.IDs.NewUUID())
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	leafGenerationID, err := domain.ParseLeafKeyGenerationID(s.deps.IDs.NewUUID())
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	settings, err := tx.Installation().GetSettings(ctx)
	if err != nil {
		return "", "", "", storeError(err, "import_leaf_settings_read_failed", "could not read settings for the imported leaf series")
	}
	settingsV1, err := DecodeSettingsV1(settings)
	if err != nil {
		return "", "", "", err
	}
	policy := domain.SeriesPolicy{RotateEvery: settingsV1.RotateEvery, CertificateValidity: settingsV1.LeafValidity}
	leafGeneration, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
		ID:                  leafGenerationID,
		SeriesID:            seriesID,
		KeyMaterialID:       keyMaterialID,
		GenerationNo:        1,
		RenewalCount:        0,
		PriorHistoryUnknown: true,
		Custody:             domain.KeyCustodyClientHeld,
	})
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID:                     seriesID,
		Name:                   certificate.Subject().CommonName(),
		Purpose:                domain.SeriesPurposeDistributed,
		ManagementAuthorityID:  authorityID,
		CurrentCertificateID:   certificateID,
		CurrentKeyGenerationID: leafGenerationID,
		Policy:                 policy,
	})
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	if err := tx.PKI().InsertLeafKeyGeneration(ctx, leafGeneration); err != nil {
		return "", "", "", storeError(err, "import_leaf_key_generation_store_failed", "could not store the imported leaf key generation")
	}
	if err := tx.PKI().InsertCertificate(ctx, certificate); err != nil {
		return "", "", "", storeError(err, "import_certificate_store_failed", "could not store the imported certificate")
	}
	policySnapshot, err := leafPolicySnapshotJSON(certificate, policy)
	if err != nil {
		return "", "", "", err
	}
	if err := tx.PKI().InsertLeafCertificateRecord(ctx, port.LeafCertificateRecord{
		CertificateID:         certificateID,
		SeriesID:              seriesID,
		LeafKeyGenerationID:   leafGenerationID,
		IssuerCACertificateID: issuerCertificateID,
		Operation:             port.CertificateOperationImport,
		RenewalCountAtIssue:   0,
		PolicySnapshotJSON:    policySnapshot,
	}); err != nil {
		return "", "", "", storeError(err, "import_leaf_certificate_record_store_failed", "could not store the imported leaf certificate record")
	}
	if err := tx.PKI().InsertSeries(ctx, series); err != nil {
		return "", "", "", storeError(err, "import_leaf_series_store_failed", "could not store the imported leaf series")
	}
	return certificateID, authorityID, issuerGenerationID, nil
}

func (s *ImportService) insertImportedCRL(ctx context.Context, tx port.TxStores, file parsedImportFile, r importResolution, certificateIDByFile map[string]domain.CertificateID, authorityIDByFile map[string]domain.AuthorityID, keyGenerationIDByFile map[string]domain.CAKeyGenerationID) ([]RevocationChange, domain.AuthorityID, error) {
	issuerCertificateID := r.IssuerExistingCertificateID
	var authorityID domain.AuthorityID
	var issuerGenerationID domain.CAKeyGenerationID
	if r.IssuerBatchFileName != "" {
		issuerCertificateID = certificateIDByFile[r.IssuerBatchFileName]
		authorityID = authorityIDByFile[r.IssuerBatchFileName]
		issuerGenerationID = keyGenerationIDByFile[r.IssuerBatchFileName]
	} else if issuerCertificateID != "" {
		record, err := tx.PKI().GetCACertificateRecord(ctx, issuerCertificateID)
		if err != nil {
			return nil, "", storeError(err, "import_crl_issuer_record_read_failed", "could not read the CRL issuer record")
		}
		issuerGenerationID = record.CAKeyGenerationID
		generation, err := tx.PKI().GetCAKeyGeneration(ctx, issuerGenerationID)
		if err != nil {
			return nil, "", storeError(err, "import_crl_issuer_generation_read_failed", "could not read the CRL issuer generation")
		}
		authorityID = generation.AuthorityID
	}
	if issuerCertificateID == "" || authorityID == "" || issuerGenerationID == "" {
		return nil, "", contract.NewAppError(contract.ErrorKindUnavailable, "import_crl_issuer_unresolved",
			"the CRL issuer was not stored before CRL import")
	}
	state, err := tx.CRLs().GetStateForUpdate(ctx, issuerGenerationID)
	if err != nil {
		return nil, "", storeError(err, "import_crl_state_read_failed", "could not read the CRL issuer state")
	}
	documentID, err := domain.ParseCRLDocumentID(s.deps.IDs.NewUUID())
	if err != nil {
		return nil, "", contract.FromDomainError(err)
	}
	document := port.CRLDocument{
		ID:                documentID,
		CAKeyGenerationID: issuerGenerationID,
		NumberHex:         file.CRL.Number,
		DERSHA256:         r.DERSHA256,
		DER:               file.CRL.DER,
		ThisUpdate:        file.CRL.ThisUpdate,
		NextUpdate:        file.CRL.NextUpdate,
		CoveredGeneration: state.RevocationGeneration(),
		Origin:            "imported",
	}
	if err := tx.CRLs().InsertDocument(ctx, document); err != nil && !errors.Is(err, port.ErrDuplicate) {
		return nil, "", storeError(err, "import_crl_document_store_failed", "could not store the imported CRL document")
	}
	if next, changed := state.ObserveImportedNumber(file.CRL.Number); changed {
		if err := tx.CRLs().SaveState(ctx, next, state.Version()); err != nil {
			return nil, "", storeError(err, "import_crl_state_save_failed", "could not advance the CRL number floor")
		}
	}
	needsReview := !file.CRL.NextUpdate.IsZero() && file.CRL.NextUpdate.IsExpiredAt(s.deps.Clock.Now())
	changes := make([]RevocationChange, 0, len(file.CRL.Revoked))
	for _, entry := range file.CRL.Revoked {
		certificateID := domain.CertificateID("")
		if certificate, findErr := tx.PKI().FindCertificateByIssuerSerial(ctx, issuerGenerationID, entry.Serial); findErr == nil {
			certificateID = certificate.ID()
		} else if !errors.Is(findErr, port.ErrNotFound) {
			return nil, "", storeError(findErr, "import_crl_certificate_lookup_failed", "could not link an imported CRL entry")
		}
		changes = append(changes, RevocationChange{
			IssuerID:      issuerGenerationID,
			Serial:        entry.Serial,
			CertificateID: certificateID,
			RevokedAt:     entry.RevokedAt,
			Reason:        entry.Reason,
			Source:        domain.RevocationSourceImport,
			AuthorityID:   authorityID,
			NeedsReview:   needsReview,
		})
	}
	return changes, authorityID, nil
}

func (s *ImportService) attachImportedExistingKey(ctx context.Context, tx port.TxStores, meta contract.MutationMeta, now domain.Instant, file parsedImportFile, r importResolution, prepared preparedImportKey) error {
	if prepared.ExistingCertificateID == "" || prepared.Generated.EncryptedSecret.IsZero() {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_target_unresolved",
			"the CA key does not target an existing CA certificate").WithField("file_name", file.FileName)
	}
	certificate, err := tx.PKI().GetCertificate(ctx, prepared.ExistingCertificateID)
	if err != nil {
		return storeError(err, "import_ca_key_certificate_read_failed", "could not read the existing CA certificate")
	}
	generationID, err := certificateKeyGeneration(ctx, tx, certificate)
	if err != nil {
		return err
	}
	generation, err := tx.PKI().GetCAKeyGeneration(ctx, generationID)
	if err != nil {
		return storeError(err, "import_ca_key_generation_read_failed", "could not read the existing CA key generation")
	}
	authority, err := tx.PKI().GetIssuerForUpdate(ctx, generation.AuthorityID)
	if err != nil {
		return storeError(err, "import_ca_key_authority_read_failed", "could not read the authority owning the CA key")
	}
	scope, err := authorityScopeFromRow(authority)
	if err != nil {
		return err
	}
	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionImportAttachSigningKey, port.NewAuthorizationScope(scope)); err != nil {
		return err
	}
	if authority.KeyGenerationID() != generationID || authority.IssuanceCertificateID() != certificate.ID() {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_authority_mismatch",
			"the existing CA certificate is not the authority's current signing certificate")
	}
	if err := verifyImportedCAKeyTarget(ctx, tx, authority, generation); err != nil {
		return err
	}
	if generation.KeyMaterialID != prepared.KeyMaterialID || !generation.KeyDestroyedAt.IsZero() {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_generation_invalid",
			"the existing CA key generation cannot be attached")
	}
	material, err := tx.PKI().GetKeyMaterial(ctx, generation.KeyMaterialID)
	if err != nil {
		return storeError(err, "import_ca_key_material_read_failed", "could not read the existing CA key material")
	}
	if !material.PublicKey.Equal(prepared.Validated.PublicKey) || !material.CompromisedAt.IsZero() {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_identity_invalid",
			"the attached key does not match the existing uncompromised CA key material")
	}
	if authority.KeyAvailable() {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_already_attached",
			"the authority already has an available signing key")
	}
	purpose := caSecretPurpose(authority)
	if _, err := tx.Secrets().GetEncrypted(ctx, generation.KeyMaterialID, purpose); err == nil {
		return contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_secret_exists",
			"the authority already has a stored signing secret")
	} else if !errors.Is(err, port.ErrNotFound) {
		return storeError(err, "import_ca_key_secret_read_failed", "could not inspect the existing signing secret")
	}
	attached, err := authority.AttachSigningKey()
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.Secrets().InsertEncrypted(ctx, prepared.Generated.EncryptedSecret); err != nil {
		return storeError(err, "import_ca_key_secret_store_failed", "could not store the attached CA signing secret")
	}
	if err := tx.PKI().SaveAuthority(ctx, attached, authority.Version()); err != nil {
		return storeError(err, "import_ca_key_authority_save_failed", "could not attach the CA signing key")
	}
	event := port.AuditEvent{
		ID:         s.deps.IDs.NewUUID(),
		OccurredAt: now,
		ActorKind:  contract.AuditActorAccount,
		ActorID:    string(meta.Principal.AccountID()),
		Action:     "import.attach_signing_key",
		TargetType: "authority",
		TargetID:   string(authority.ID()),
		ClientIP:   clientIP(meta.RequestMeta),
		Result:     contract.AuditResultSuccess,
		Details:    contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"key_generation_id": string(generationID)}},
	}
	if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(scope)); err != nil {
		return storeError(err, "import_ca_key_audit_failed", "could not record the CA key attachment audit event")
	}
	return nil
}

// compromiseCascadeChange builds the revocation change for a certificate
// whose public key is already flagged compromised. RevokedAt is the moment
// the key was reported compromised, not commit time, matching the cascade's
// own "same compromise moment" convention elsewhere in this codebase.
func (s *ImportService) compromiseCascadeChange(ctx context.Context, tx port.TxStores, certificateID domain.CertificateID, authorityID domain.AuthorityID, r importResolution) RevocationChange {
	cert, err := tx.PKI().GetCertificate(ctx, certificateID)
	if err != nil {
		// Best effort: if the certificate cannot be re-read here, its serial
		// is unavailable and no change is produced. This should not happen
		// since it was just inserted or matched in this same transaction.
		return RevocationChange{}
	}
	return RevocationChange{
		IssuerID:      cert.IssuerCAKeyGenerationID(),
		Serial:        cert.Serial(),
		CertificateID: certificateID,
		RevokedAt:     r.CompromisedAt,
		Reason:        domain.RevocationReasonKeyCompromise,
		Source:        domain.RevocationSourceCascade,
		AuthorityID:   authorityID,
	}
}

// existingRevocationHistoryChange checks whether the ledger already carries
// a revocation for a freshly-imported certificate's own (issuer, serial) --
// a certificate-less entry from history preserved by some earlier CRL
// import/takeover, per pki-import.md "인증서 파일이 없는 항목도 보존한다": the
// certificate for a serial that was already known-revoked can arrive later.
// When found, it returns a RevocationChange carrying the EXISTING record's
// own reason/revoked_at/source and only the newly-discovered CertificateID,
// so Merge's same-facts branch backfills the link without altering the
// preserved history it is completing
// (internal/domain/revocation.go Merge's own doc comment: "A certificate
// link discovered later ... is not a conflict; it only fills in a
// previously-unknown certificate id").
func (s *ImportService) existingRevocationHistoryChange(ctx context.Context, tx port.TxStores, certificateID domain.CertificateID, authorityID domain.AuthorityID) (RevocationChange, bool, error) {
	cert, err := tx.PKI().GetCertificate(ctx, certificateID)
	if err != nil {
		return RevocationChange{}, false, storeError(err, "import_certificate_reread_failed", "could not re-read the imported certificate")
	}
	existing, err := tx.Revocations().FindForUpdate(ctx, cert.IssuerCAKeyGenerationID(), cert.Serial())
	if errors.Is(err, port.ErrNotFound) {
		return RevocationChange{}, false, nil
	} else if err != nil {
		return RevocationChange{}, false, storeError(err, "import_revocation_history_read_failed", "could not check for existing revocation history")
	}
	if existing.CertificateID() != "" {
		// Already linked to some other certificate id -- a genuine serial
		// collision, which SerialExists (not this path) is responsible for
		// catching during ordinary issuance; Import does not overwrite an
		// existing link.
		return RevocationChange{}, false, nil
	}
	return RevocationChange{
		IssuerID:      existing.IssuerID(),
		Serial:        existing.Serial(),
		CertificateID: certificateID,
		RevokedAt:     existing.RevokedAt(),
		Reason:        existing.Reason(),
		Source:        existing.Source(),
		AuthorityID:   authorityID,
	}, true, nil
}

// insertImportedAuthority stores a freshly-resolved New certificate as a new
// Authority: key material (public key only -- no private key was imported),
// a CA key generation, the certificate, its CA subtype record, and the
// authority row itself. KeyAvailable is false: this is the certificate-only,
// history/inventory import path pki-import.md names explicitly
// ("CA 인증서만 가져오는 이력 관리도 허용하되 서명·CRL 발행은 비활성화한다").
func (s *ImportService) insertImportedAuthority(
	ctx context.Context,
	tx port.TxStores,
	meta contract.MutationMeta,
	now domain.Instant,
	file parsedImportFile,
	r importResolution,
	authorityIDByFile map[string]domain.AuthorityID,
	certificateIDByFile map[string]domain.CertificateID,
	keyGenerationIDByFile map[string]domain.CAKeyGenerationID,
	takeover *contract.ImportTakeoverConfirmationInput,
	preparedKeys map[string]preparedImportKey,
) (domain.CertificateID, domain.AuthorityID, domain.CAKeyGenerationID, error) {
	certificateID, err := domain.ParseCertificateID(s.deps.IDs.NewUUID())
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	keyGenerationID, err := domain.ParseCAKeyGenerationID(s.deps.IDs.NewUUID())
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	authorityID, err := domain.ParseAuthorityID(s.deps.IDs.NewUUID())
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}

	var issuerCACertificateID domain.CertificateID
	// issuerKeyGenerationID is the CA key generation that actually SIGNED
	// this certificate -- domain.Certificate.IssuerCAKeyGenerationID's own
	// meaning (verified against certificate.go's verifySignedCertificate:
	// "issuer_ca_key_generation_id" is compared to
	// request.Plan.IssuerKeyGenerationID, the ISSUER's generation, never the
	// subject's own). For a self-signed Root that is its own freshly-minted
	// generation; for an Intermediate it is the resolved parent's.
	issuerKeyGenerationID := keyGenerationID
	var managementParentID domain.AuthorityID
	kind := domain.AuthorityKindRoot
	switch {
	case r.SelfSigned:
		// issuerCACertificateID stays empty (self-signed root); issuerKeyGenerationID stays its own.
	case r.IssuerBatchFileName != "":
		issuerCACertificateID = certificateIDByFile[r.IssuerBatchFileName]
		issuerKeyGenerationID = keyGenerationIDByFile[r.IssuerBatchFileName]
		managementParentID = authorityIDByFile[r.IssuerBatchFileName]
		kind = domain.AuthorityKindIntermediate
	case r.IssuerExistingCertificateID != "":
		issuerCACertificateID = r.IssuerExistingCertificateID
		issuerRecord, err := tx.PKI().GetCACertificateRecord(ctx, r.IssuerExistingCertificateID)
		if err != nil {
			return "", "", "", storeError(err, "import_issuer_ca_record_read_failed", "could not read the declared issuer's CA certificate record")
		}
		issuerKeyGenerationID = issuerRecord.CAKeyGenerationID
		parentAuthorityID, err := s.authorityOwning(ctx, tx, r.IssuerExistingCertificateID)
		if err != nil {
			return "", "", "", err
		}
		managementParentID = parentAuthorityID
		kind = domain.AuthorityKindIntermediate
	}
	if !r.SelfSigned {
		if err := ensureImportedSerialAvailable(ctx, tx, issuerKeyGenerationID, r.Cert.Serial); err != nil {
			return "", "", "", err
		}
	}

	// keyMaterialID normally identifies a brand-new key_materials row for
	// this certificate's public key. When resolveImportItems already found
	// this exact public key sitting in an EXISTING, orphaned (no certificate
	// using it yet) key_materials row -- the U09 compromise-cascade case --
	// that existing row is reused instead of inserting a second one, which
	// key_materials.spki_sha256's uniqueness would otherwise reject.
	preparedKey, hasPreparedKey := preparedKeyForTarget(preparedKeys, file.FileName)
	var keyMaterialID domain.KeyMaterialID
	if hasPreparedKey {
		if preparedKey.TargetBatchFileName != file.FileName {
			return "", "", "", contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_target_mismatch",
				"the prepared CA key does not target this certificate")
		}
		if !preparedKey.Validated.PublicKey.Equal(r.Cert.PublicKey) {
			return "", "", "", contract.NewAppError(contract.ErrorKindConflict, "import_ca_key_target_mismatch",
				"the prepared CA key public key does not match this certificate")
		}
		keyMaterialID = preparedKey.KeyMaterialID
		if r.ExistingKeyMaterialID == "" {
			if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyMaterialID, PublicKey: r.Cert.PublicKey, Origin: "imported"}); err != nil {
				return "", "", "", storeError(err, "import_key_material_store_failed", "could not store the imported public key")
			}
		}
	} else {
		keyMaterialID = r.ExistingKeyMaterialID
		if keyMaterialID == "" {
			id, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
			if err != nil {
				return "", "", "", contract.FromDomainError(err)
			}
			keyMaterialID = id
			if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyMaterialID, PublicKey: r.Cert.PublicKey, Origin: "imported"}); err != nil {
				return "", "", "", storeError(err, "import_key_material_store_failed", "could not store the imported public key")
			}
		}
	}
	if err := tx.PKI().InsertKeyGeneration(ctx, port.CAKeyGeneration{
		ID:            keyGenerationID,
		AuthorityID:   authorityID,
		KeyMaterialID: keyMaterialID,
		GenerationNo:  1,
	}); err != nil {
		return "", "", "", storeError(err, "import_key_generation_store_failed", "could not store the CA key generation")
	}

	certificate, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certificateID,
		DER:                     r.Cert.DER,
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: issuerKeyGenerationID,
		Serial:                  r.Cert.Serial,
		Validity:                r.Cert.Validity,
		Subject:                 r.Cert.Subject,
		SANs:                    r.Cert.SANs,
		Kind:                    domain.CertificateKindCA,
		KeyAlgorithm:            r.Cert.KeyAlgorithm,
		Origin:                  domain.CertificateOriginImported,
	})
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	if err := tx.PKI().InsertCertificate(ctx, certificate); err != nil {
		return "", "", "", storeError(err, "import_certificate_store_failed", "could not store the imported certificate")
	}
	if err := tx.PKI().InsertCACertificateRecord(ctx, port.CACertificateRecord{
		CertificateID:         certificateID,
		CAKeyGenerationID:     keyGenerationID,
		IssuerCACertificateID: issuerCACertificateID,
	}); err != nil {
		return "", "", "", storeError(err, "import_ca_certificate_record_store_failed", "could not store the CA certificate record")
	}

	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                    authorityID,
		Kind:                  kind,
		Name:                  r.Cert.Subject.CommonName(),
		ManagementParentID:    managementParentID,
		IssuanceState:         domain.IssuanceStateStopped,
		IssuanceCertificateID: certificateID,
		KeyGenerationID:       keyGenerationID,
		KeyAvailable:          hasPreparedKey,
		PendingTakeover:       takeover != nil,
		CertificateWindow:     r.Cert.Validity,
	})
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	if err := tx.PKI().InsertAuthority(ctx, authority); err != nil {
		return "", "", "", storeError(err, "import_authority_store_failed", "could not store the imported authority")
	}
	if hasPreparedKey {
		if err := tx.Secrets().InsertEncrypted(ctx, preparedKey.Generated.EncryptedSecret); err != nil {
			return "", "", "", storeError(err, "import_ca_key_secret_store_failed", "could not store the encrypted CA key")
		}
	}

	if takeover != nil {
		if err := s.insertPendingTakeover(ctx, tx, keyGenerationID, *takeover); err != nil {
			return "", "", "", err
		}
	}

	crlState, err := domain.NewCRLState(domain.CRLStateFacts{
		CAKeyGenerationID: keyGenerationID,
		PublicationState:  domain.PublicationStateInactive,
	})
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	if err := tx.CRLs().SaveState(ctx, crlState, 0); err != nil {
		return "", "", "", storeError(err, "import_crl_state_store_failed", "could not store the CRL state")
	}

	_ = meta
	return certificateID, authorityID, keyGenerationID, nil
}

// insertPendingTakeover stores the pending ca_takeovers row a freshly
// imported, PendingTakeover-flagged authority needs before ConfirmTakeover
// can ever confirm it. This is the missing link the lead's mid-task
// correction named: without it, ConfirmTakeover had no path through Commit
// that could ever produce a row for it to act on -- exactly the kind of gap
// §13's closing paragraph refuses to accept as contract completeness ("대역
// 내부 map에 직접 fixture를 넣어야만 가능한 정상 업무 흐름은 계약 완성으로
// 인정하지 않는다").
func (s *ImportService) insertPendingTakeover(ctx context.Context, tx port.TxStores, keyGenerationID domain.CAKeyGenerationID, confirmation contract.ImportTakeoverConfirmationInput) error {
	takeoverID, err := domain.ParseTakeoverID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.FromDomainError(err)
	}
	stoppedAt, err := parseRFC3339Instant(confirmation.Confirmation.ExternalIssuerStoppedAt)
	if err != nil {
		return err
	}
	if err := tx.Imports().InsertTakeover(ctx, port.Takeover{
		ID:                      takeoverID,
		CAKeyGenerationID:       keyGenerationID,
		State:                   contract.TakeoverStatePending,
		HistoryAssertion:        confirmation.Confirmation.HistoryAssertion,
		PreviousMaxNumberHex:    confirmation.Confirmation.PreviousMaxNumberHex,
		ExternalIssuerStoppedAt: stoppedAt,
		Evidence:                confirmation.Confirmation.Evidence,
	}); err != nil {
		return storeError(err, "import_takeover_store_failed", "could not store the pending takeover")
	}
	return nil
}

// ---- ConfirmTakeover ----

// parseRFC3339Instant parses an RFC3339 timestamp into domain.Instant.
// contract.ImportConfirmTakeoverCommand.Validate has already checked the
// string parses (via its own unexported parser), so a failure here would be
// a server-side inconsistency rather than a client input error.
func parseRFC3339Instant(raw string) (domain.Instant, error) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return domain.Instant{}, contract.WrapAppError(contract.ErrorKindValidation, "external_issuer_stopped_at_invalid",
			"external_issuer_stopped_at must be an RFC3339 timestamp", err)
	}
	return domain.NewInstant(t), nil
}

// ConfirmTakeover records an administrator's confirmed takeover evidence for
// a pending import takeover, flipping both the ca_takeovers row and the
// Authority's pending gate in the same Write (docs/backend-implementation.md
// §3 "ConfirmTakeover: TakeoverInput → Takeover"). The transition does not
// enable issuance or attach a key; it only records the explicit evidence that
// clears the pending-takeover admission check. §3 requires the Authority's
// version as a defensive optimistic-lock guard against the authority having
// changed since the caller last reviewed it.
func (s *ImportService) ConfirmTakeover(ctx context.Context, meta contract.MutationMeta, cmd contract.ImportConfirmTakeoverCommand) (contract.TakeoverView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TakeoverView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.TakeoverView{}, contract.NewAppError(contract.ErrorKindForbidden, "import_requires_admin",
			"confirming a takeover requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.TakeoverView{}, err
	}
	stoppedAt, err := parseRFC3339Instant(cmd.ExternalIssuerStoppedAt)
	if err != nil {
		return contract.TakeoverView{}, err
	}

	var result contract.TakeoverView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		generation, err := tx.PKI().GetCAKeyGeneration(ctx, cmd.CAKeyGenerationID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "takeover_ca_key_generation_not_found",
				"the named CA key generation does not exist")
		} else if err != nil {
			return storeError(err, "takeover_ca_key_generation_read_failed", "could not read the CA key generation")
		}
		authority, err := tx.PKI().GetIssuerForUpdate(ctx, generation.AuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "takeover_authority_not_found",
				"the authority owning this CA key generation does not exist")
		} else if err != nil {
			return storeError(err, "takeover_authority_read_failed", "could not read the owning authority")
		}
		scope, err := authorityScopeFromRow(authority)
		if err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionImportConfirmTakeover, port.NewAuthorizationScope(scope)); err != nil {
			return err
		}
		if authority.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "takeover_authority_version_conflict",
				"the authority has changed since this request was prepared")
		}

		pending, err := tx.Imports().GetPendingTakeoverForUpdate(ctx, cmd.CAKeyGenerationID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "takeover_not_pending",
				"there is no pending takeover for this CA key generation")
		} else if err != nil {
			return storeError(err, "takeover_read_failed", "could not read the pending takeover")
		}

		now := s.deps.Clock.Now()
		confirmed := pending
		confirmed.State = contract.TakeoverStateConfirmed
		confirmed.HistoryAssertion = cmd.HistoryAssertion
		confirmed.PreviousMaxNumberHex = cmd.PreviousMaxNumberHex
		confirmed.ExternalIssuerStoppedAt = stoppedAt
		confirmed.Evidence = cmd.Evidence
		confirmed.ConfirmedBy = meta.Principal.AccountID()
		confirmed.ConfirmedAt = now
		if err := tx.Imports().SaveTakeover(ctx, confirmed, pending.Version); err != nil {
			return storeError(err, "takeover_save_failed", "could not save the confirmed takeover")
		}
		confirmedAuthority, err := authority.ConfirmTakeover()
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.PKI().SaveAuthority(ctx, confirmedAuthority, expectedVersion); err != nil {
			return storeError(err, "takeover_authority_save_failed", "could not clear the authority's pending takeover gate")
		}

		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "import.confirm_takeover",
			TargetType: "takeover",
			TargetID:   string(confirmed.ID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(scope)); err != nil {
			return storeError(err, "takeover_audit_failed", "could not record the takeover confirmation audit event")
		}

		confirmedAt := confirmed.ConfirmedAt
		result = contract.TakeoverView{
			ID:                string(confirmed.ID),
			CAKeyGenerationID: confirmed.CAKeyGenerationID,
			State:             confirmed.State,
			ConfirmedAt:       &confirmedAt,
			Version:           confirmed.Version,
		}
		return nil
	})
	if err != nil {
		return contract.TakeoverView{}, err
	}
	return result, nil
}
