// importing.go implements ImportService's Preview/Commit/ConfirmTakeover
// (docs/backend-implementation.md §3 ImportService row: "Preview: ImportUpload
// → ImportPreview; Commit: ImportUpload → ImportResult; AttachSigningKey:
// SigningKeyUpload → Authority; ConfirmTakeover: TakeoverInput → Takeover").
//
// AttachSigningKey is deliberately NOT implemented here, for the same reason
// authority.go leaves DestroyKey/Archive out: it is a missing-CAPABILITY gap
// in internal/domain, not a product-decision gap, and internal/domain is
// outside this developer's assigned files (importing.go, importing_test.go
// only).
//
// AttachSigningKey must flip an EXISTING authority's KeyAvailable from false
// to true (and point it at a freshly attached CA key generation) -- exactly
// the same shape of change DestroyKey needs for KeyDestroyedAt. domain.
// Authority's keyAvailable/keyGenerationID fields are private and the only
// way to produce a changed copy is through one of its existing transition
// methods (StopIssuance/Enable/Rename/CanDestroyKey's still-missing
// counterpart) -- there is no AttachSigningKey-shaped transition on
// domain.Authority today. Reassembling one through AuthorityFacts would be
// exactly the workaround docs/backend-implementation.md §5 forbids
// ("생성자에 Facts를 다시 조립하는 방식을 업무 전이의 대체 수단으로 사용하지
// 않는다"): it would bypass whatever invariants a real transition method is
// supposed to enforce (e.g. that the authority is not archived, that it does
// not already have a live key). Flagged for the lead alongside authority.go's
// own DestroyKey/Archive gaps -- all three want the same kind of fix, a new
// domain.Authority transition (or two) that mutates key custody/lifecycle
// fields under an explicit invariant check.
//
// Commit's own certificate-import path is also scoped down from the full
// pki-import.md surface, each cut documented at its own decision point below
// rather than restated here:
//   - ca_key and crl-kind files are rejected outright (see
//     errImportFileKindUnsupported's doc comment): attaching a fresh CA key to
//     a fresh CA certificate uploaded in the very same batch has no documented
//     linkage mechanism (metadata.IssuerCertificateID can only name an
//     ALREADY-stored certificate, since a same-batch id does not exist yet to
//     reference), and merging CRL-derived revocations requires verifying the
//     CRL's signature against the issuing CA's public key, which no port in
//     this codebase does (ChainValidator verifies a LEAF-to-root chain,
//     CRLSigner only signs). Both are reported to the lead rather than
//     invented.
//   - Leaf-kind certificates are rejected: registering one requires creating
//     a LeafSeries/LeafKeyGeneration pair (renewal_count starting at 0, per
//     pki-import.md), a materially separate subsystem this round does not
//     build. Only CA-kind (Root/Intermediate) certificates are accepted.
package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// ImportDeps is ImportService's dependency set: CommonDeps plus the three
// import-specific dependencies docs/backend-implementation.md §5 names
// ("Import: PKIParser, ChainValidator, KeyEngine"). KeyEngine is required at
// construction, matching AuthorityDeps' ProfileValidator precedent, even
// though the certificate-only path this round implements never calls it --
// it is the dependency AttachSigningKey (and a future ca_key Commit path)
// will need, and the docs table names it as belonging to this service, so it
// is validated non-nil rather than dropped.
type ImportDeps struct {
	CommonDeps
	PKIParser      port.PKIParser
	ChainValidator port.ChainValidator
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
// transaction. Only certificate-kind files carry Cert; ca_key/crl files are
// rejected before this point (see errImportFileKindUnsupported).
type parsedImportFile struct {
	FileName            string
	Kind                contract.ImportFileKind
	Cert                port.ParsedCertificateFacts
	DERSHA256           domain.Fingerprint
	IssuerCertificateID domain.CertificateID // metadata hint, zero if not given
}

// errImportFileKindUnsupported is returned for any ca_key or crl file, and
// for a leaf-kind certificate file. See this file's top-level doc comment for
// why each is out of this round's scope rather than guessed at.
func errImportFileKindUnsupported(fileName string, detail string) error {
	return contract.NewAppError(contract.ErrorKindValidation, "import_file_kind_unsupported", detail).
		WithField("file_name", fileName)
}

// parseFiles runs the PKIParser calls (§8's out-of-transaction "파싱"). It
// does not touch the store and does not depend on any DB state, so it runs
// once per Preview/Commit call regardless of how many times the surrounding
// Write is retried.
func (s *ImportService) parseFiles(ctx context.Context, cmd contract.ImportUploadCommand) ([]parsedImportFile, error) {
	byName := make(map[string][]byte, len(cmd.Files))
	for _, f := range cmd.Files {
		byName[f.FileName] = f.Data
	}
	out := make([]parsedImportFile, 0, len(cmd.Metadata.Files))
	for _, m := range cmd.Metadata.Files {
		if m.Kind != contract.ImportFileKindCertificate {
			return nil, errImportFileKindUnsupported(m.FileName,
				"ca_key and crl import files are not yet supported by this service")
		}
		data := byName[m.FileName]
		bundle, err := s.deps.PKIParser.ParseCertificateBundle(ctx, port.CertificateBundleInput{Data: data})
		if err != nil {
			return nil, contract.WrapAppError(contract.ErrorKindValidation, "import_certificate_parse_failed",
				"could not parse the uploaded certificate", err).WithField("file_name", m.FileName)
		}
		if len(bundle.Certificates) != 1 {
			return nil, errImportFileKindUnsupported(m.FileName,
				"each certificate file must contain exactly one certificate")
		}
		facts := bundle.Certificates[0]
		if facts.Kind != domain.CertificateKindCA {
			return nil, errImportFileKindUnsupported(m.FileName,
				"leaf certificate import is not yet supported by this service")
		}
		out = append(out, parsedImportFile{
			FileName:            m.FileName,
			Kind:                m.Kind,
			Cert:                facts,
			DERSHA256:           domain.NewFingerprint(facts.DER),
			IssuerCertificateID: m.IssuerCertificateID,
		})
	}
	return out, nil
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
	FileName  string
	Cert      port.ParsedCertificateFacts
	DERSHA256 domain.Fingerprint
	Status    contract.ImportItemStatus
	ErrorCode string

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
}

// resolveImportItems classifies every parsed file against the store read
// through tx: exact-DER duplicate, public-key conflict (against an existing
// certificate OR another file in this same batch), or new with a resolved
// issuer. It performs no writes.
func (s *ImportService) resolveImportItems(ctx context.Context, tx port.TxStores, files []parsedImportFile) ([]importResolution, error) {
	out := make([]importResolution, len(files))
	firstByDER := map[string]int{}

	for i, f := range files {
		r := importResolution{FileName: f.FileName, Cert: f.Cert, DERSHA256: f.DERSHA256}

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
		r.SelfSigned = true
		r.Status = contract.ImportItemStatusNew
		return
	}

	matchedFileName := ""
	matchCount := 0
	for j, other := range files {
		if j == i {
			continue
		}
		if out[j].Status == contract.ImportItemStatusConflict || out[j].Status == contract.ImportItemStatusDuplicate {
			continue
		}
		if sameSubject(other.Cert.Subject, r.Cert.IssuerSubject) {
			matchedFileName = other.FileName
			matchCount++
		}
	}
	if matchCount > 1 {
		r.Status = contract.ImportItemStatusConflict
		r.ErrorCode = "import_issuer_ambiguous"
		return
	}
	if matchCount == 1 {
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
	r.IssuerExistingCertificateID = issuerCert.ID()
	r.Status = contract.ImportItemStatusNew
}

// verifyChains runs ChainValidator against every resolved New, non-self-
// signed item, walking same-batch ancestors and any stored tail up to a
// trusted root (docs/pki-import.md "이름 비교뿐 아니라 실제 서명과 CA 제약으로
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
		if r.Status != contract.ImportItemStatusNew || r.SelfSigned {
			continue
		}
		chainDER, err := s.buildVerificationChain(ctx, tx, files, out, byName, r)
		if err != nil {
			return err
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
			FileID:              r.FileName,
			Kind:                contract.ImportFileKindCertificate,
			SHA256:              r.DERSHA256,
			IssuerCertificateID: issuerCertID,
		}
		item := contract.ImportItemView{
			FileID:    r.FileName,
			SHA256:    r.DERSHA256,
			Kind:      contract.ImportFileKindCertificate,
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
// original-file SHA-256 and issuer linkage only -- never a passphrase or
// private-key byte (§13 rule 6 "passphrase·개인키 원문은 제외"). Files are
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

func commitInputHash(cmd contract.ImportUploadCommand) (string, error) {
	hashFiles := make([]importHashFile, 0, len(cmd.Metadata.Files))
	byName := make(map[string]contract.ImportFileMetadataInput, len(cmd.Metadata.Files))
	for _, m := range cmd.Metadata.Files {
		byName[m.FileName] = m
	}
	for _, f := range cmd.Files {
		m, ok := byName[f.FileName]
		if !ok {
			continue
		}
		hashFiles = append(hashFiles, importHashFile{
			FileID:              m.FileName,
			Kind:                string(m.Kind),
			SHA256:              NormalizeFingerprint(domain.NewFingerprint(f.Data).Hex()),
			IssuerCertificateID: NormalizeUUID(string(m.IssuerCertificateID)),
		})
	}
	sort.Slice(hashFiles, func(i, j int) bool { return hashFiles[i].FileID < hashFiles[j].FileID })

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
	inputHash, err := commitInputHash(cmd)
	if err != nil {
		return contract.ImportResultView{}, err
	}
	reqKey, err := RequestKey(meta, importOperationCommit)
	if err != nil {
		return contract.ImportResultView{}, err
	}

	// §6/§8: authenticate+authorize and probe for a stored result BEFORE the
	// expensive parse. §8 "현재 인증/권한이 없는 요청은 기존 결과도 받지
	// 못한다" is enforced inside this same read: requireCurrentAuth and
	// Authorize both run before ReplayStoredResult.
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

	files, err := s.parseFiles(ctx, cmd)
	if err != nil {
		return contract.ImportResultView{}, err
	}
	if err := verifyPreviewManifestMatches(cmd, files); err != nil {
		return contract.ImportResultView{}, err
	}

	err = RunWithRetry(ctx, func() error {
		return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
			return s.commitImport(ctx, tx, meta, reqKey, inputHash, files, cmd.Metadata.Takeovers, &result)
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
	want := make(map[string]contract.ImportManifestFileInput, len(cmd.Metadata.PreviewManifest.Files))
	for _, f := range cmd.Metadata.PreviewManifest.Files {
		want[f.FileID] = f
	}
	if len(want) != len(files) {
		return contract.NewAppError(contract.ErrorKindConflict, "import_manifest_mismatch",
			"the resent files do not match the previewed manifest")
	}
	for _, f := range files {
		expect, ok := want[f.FileName]
		if !ok {
			return contract.NewAppError(contract.ErrorKindConflict, "import_manifest_mismatch",
				"the resent files do not match the previewed manifest").WithField("file_name", f.FileName)
		}
		if expect.Kind != f.Kind || expect.SHA256Hex != f.DERSHA256.Hex() {
			return contract.NewAppError(contract.ErrorKindConflict, "import_manifest_mismatch",
				"the resent file's content does not match the previewed manifest").WithField("file_name", f.FileName)
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
func (s *ImportService) commitImport(ctx context.Context, tx port.TxStores, meta contract.MutationMeta, reqKey port.OperationRequestKey, inputHash string, files []parsedImportFile, takeovers []contract.ImportTakeoverConfirmationInput, result *contract.ImportResultView) error {
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
			certID, authID, keyGenID, err := s.insertImportedAuthority(ctx, tx, meta, now, files[byName[r.FileName]], r, authorityIDByFile, certificateIDByFile, keyGenerationIDByFile, takeover)
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
		item := contract.ImportItemView{FileID: r.FileName, SHA256: r.DERSHA256, Kind: contract.ImportFileKindCertificate, Status: r.Status}
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
		manifestFiles[i] = contract.ImportManifestFileFacts{FileID: r.FileName, Kind: contract.ImportFileKindCertificate, SHA256: r.DERSHA256}
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
	if err := tx.Audit().Append(ctx, event, authorityIDs); err != nil {
		return storeError(err, "import_audit_failed", "could not record the import audit event")
	}

	*result = resultView
	return nil
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

	// keyMaterialID normally identifies a brand-new key_materials row for
	// this certificate's public key. When resolveImportItems already found
	// this exact public key sitting in an EXISTING, orphaned (no certificate
	// using it yet) key_materials row -- the U09 compromise-cascade case --
	// that existing row is reused instead of inserting a second one, which
	// key_materials.spki_sha256's uniqueness would otherwise reject.
	keyMaterialID := r.CompromisedKeyMaterialID
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
		KeyAvailable:          false,
		PendingTakeover:       takeover != nil,
		CertificateWindow:     r.Cert.Validity,
	})
	if err != nil {
		return "", "", "", contract.FromDomainError(err)
	}
	if err := tx.PKI().InsertAuthority(ctx, authority); err != nil {
		return "", "", "", storeError(err, "import_authority_store_failed", "could not store the imported authority")
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
// a pending import takeover, flipping the ca_takeovers row from pending to
// confirmed (docs/backend-implementation.md §3 "ConfirmTakeover: TakeoverInput
// → Takeover"). It does not mutate the imported Authority itself: pki-import
// exposes this transition solely through the ca_takeovers row's own state,
// which is what CanIssue's TakeoverConfirmed context field is meant to be
// checked against (see this file's own top comment for the AttachSigningKey
// gap, a genuinely different, still-blocked transition). §3 requires the
// Authority's version regardless, as a defensive optimistic-lock guard
// against the authority having changed since the caller last reviewed it --
// it is checked but never itself saved with a bumped version here, since
// nothing on domain.Authority changes in this method.
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
		if err := tx.Audit().Append(ctx, event, []domain.AuthorityID{scope}); err != nil {
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
