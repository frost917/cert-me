package contract

import (
	"bytes"
	"encoding/json"
	"fmt"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// This file is ImportService's command/result contract
// (docs/backend-implementation.md §3, §12): Preview, Commit,
// AttachSigningKey, ConfirmTakeover.
//
// §12 fixes the shape: "ImportService는 typed ImportMetadata 입력과 별도의
// PublicImportManifest/TakeoverEvidence 저장 타입을 사용한다. manifest는
// 파서가 만든 공개 Facts에서 생성하고 repository에 input command를 전달하지
// 않는다." So this file keeps two families of type: the *Input wire types
// that Preview/Commit decode (ImportMetadataInput and friends, which may
// carry a per-file passphrase secret), and the storage/result types
// (PublicImportManifest, TakeoverEvidence, ImportManifestFileFacts) that a
// service builds from a parser's public facts and that never embed a
// passphrase or an input command.

// ImportFileKind mirrors the OpenAPI file kind enum shared by
// ImportFileMetadata/ImportManifestFile/ImportItem.
type ImportFileKind string

const (
	ImportFileKindCertificate ImportFileKind = "certificate"
	ImportFileKindCRL         ImportFileKind = "crl"
	ImportFileKindCAKey       ImportFileKind = "ca_key"
)

func (k ImportFileKind) Validate() error {
	switch k {
	case ImportFileKindCertificate, ImportFileKindCRL, ImportFileKindCAKey:
		return nil
	default:
		return fmt.Errorf("%w: unsupported import file kind %q", domain.ErrInvalidValue, string(k))
	}
}

const (
	maxImportFileNameLength     = 128
	maxImportFiles              = 100
	importManifestSchemaVersion = 1
)

// UploadedFile is one raw file from the multipart ImportUpload.files array.
// It owns its bytes; the service releases them (by letting the command go
// out of scope) once Preview/Commit has parsed and either discarded or
// re-encrypted whatever they contain. A file's bytes are never themselves a
// secret.Input: they are ordinary certificate/CRL/CA-key material whose
// sensitive part, if any (an encrypted private key), is protected by the
// per-file Passphrase below, not by wrapping the whole file.
type UploadedFile struct {
	FileName string
	Data     []byte
}

// ImportFileMetadataInput mirrors one entry of the OpenAPI
// ImportFileMetadata array. Passphrase is a secret and is never a plain
// string field on this type: UnmarshalJSON below is the one point where the
// wire's plaintext passphrase field is read and immediately wrapped, so no
// exported field ever holds it as a string.
type ImportFileMetadataInput struct {
	FileName            string
	Kind                ImportFileKind
	IssuerCertificateID domain.CertificateID // zero if not applicable
	Passphrase          *secret.Input
}

// importFileMetadataWire is the literal wire shape, used only inside
// UnmarshalJSON/MarshalJSON so the exported type above never has a string
// passphrase field a caller could accidentally log or re-marshal.
type importFileMetadataWire struct {
	FileName            string `json:"file_name"`
	Kind                string `json:"kind"`
	IssuerCertificateID string `json:"issuer_certificate_id,omitempty"`
	Passphrase          string `json:"passphrase,omitempty"`
}

func (m *ImportFileMetadataInput) UnmarshalJSON(data []byte) error {
	var wire importFileMetadataWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return err
	}
	m.FileName = wire.FileName
	m.Kind = ImportFileKind(wire.Kind)
	m.IssuerCertificateID = domain.CertificateID(wire.IssuerCertificateID)
	if wire.Passphrase != "" {
		m.Passphrase = secret.FromString(wire.Passphrase)
	}
	// wire is a local copy on the stack; there is no persistent buffer to
	// zero here, unlike the []byte case ReadAll guards against.
	return nil
}

// MarshalJSON refuses: this type carries a secret.Input, and the house rule
// (backend-implementation.md §6, §10) is that a value holding a secret is
// never round-tripped through a plain json.Marshal of the surrounding
// command.
func (m ImportFileMetadataInput) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("%w: import file metadata carries a secret and is not serializable", domain.ErrNotPermitted)
}

// ImportTakeoverConfirmationInput mirrors one entry of ImportMetadata's
// takeovers array: which imported CA certificate (by content hash) a
// bundled TakeoverInput confirms.
type ImportTakeoverConfirmationInput struct {
	CACertificateSHA256Hex string        `json:"ca_certificate_sha256"`
	Confirmation           TakeoverInput `json:"confirmation"`
}

// CACertificateSHA256 parses the hex digest. Called after Validate.
func (t ImportTakeoverConfirmationInput) CACertificateSHA256() (domain.Fingerprint, error) {
	return domain.ParseFingerprint(t.CACertificateSHA256Hex)
}

// ImportPreviewManifestInput mirrors the OpenAPI ImportManifest schema when
// it appears as *input* on ImportMetadata.preview_manifest (Commit replays
// the manifest Preview returned). It is intentionally the same shape as the
// storage-side PublicImportManifest below, but kept as a distinct type per
// §12: input is never handed to a repository as-is.
type ImportPreviewManifestInput struct {
	SchemaVersion int                       `json:"schema_version"`
	Files         []ImportManifestFileInput `json:"files"`
}

type ImportManifestFileInput struct {
	FileID              string               `json:"file_id"`
	Kind                ImportFileKind       `json:"kind"`
	SHA256Hex           string               `json:"sha256"`
	IssuerCertificateID domain.CertificateID `json:"issuer_certificate_id,omitempty"`
}

// ImportMetadataInput mirrors the OpenAPI ImportMetadata schema: the
// per-file kind/issuer/passphrase map, the optional replayed preview
// manifest (required for Commit, optional for Preview per the OpenAPI
// description), and any takeover confirmations bundled with this import.
type ImportMetadataInput struct {
	SchemaVersion   int                               `json:"schema_version"`
	Files           []ImportFileMetadataInput         `json:"files"`
	PreviewManifest *ImportPreviewManifestInput       `json:"preview_manifest,omitempty"`
	Takeovers       []ImportTakeoverConfirmationInput `json:"takeovers,omitempty"`
}

func (m ImportMetadataInput) validate(requireManifest bool) error {
	if m.SchemaVersion != importManifestSchemaVersion {
		return NewAppError(ErrorKindValidation, "import_schema_version_unsupported", "metadata schema_version must be 1")
	}
	if len(m.Files) == 0 || len(m.Files) > maxImportFiles {
		return NewAppError(ErrorKindValidation, "import_files_required", "metadata.files must have between 1 and 100 entries")
	}
	seenNames := make(map[string]struct{}, len(m.Files))
	for i, f := range m.Files {
		if f.FileName == "" || len(f.FileName) > maxImportFileNameLength {
			return NewAppError(ErrorKindValidation, "import_file_name_invalid", fmt.Sprintf("files[%d].file_name must be 1..128 characters", i))
		}
		if _, dup := seenNames[f.FileName]; dup {
			return NewAppError(ErrorKindValidation, "import_file_name_duplicate", fmt.Sprintf("files[%d].file_name is duplicated", i))
		}
		seenNames[f.FileName] = struct{}{}
		if err := f.Kind.Validate(); err != nil {
			return FromDomainError(err)
		}
		if f.IssuerCertificateID != "" {
			if _, err := domain.ParseCertificateID(string(f.IssuerCertificateID)); err != nil {
				return FromDomainError(err)
			}
		}
	}
	if requireManifest && m.PreviewManifest == nil {
		return NewAppError(ErrorKindValidation, "import_preview_manifest_required", "commit requires the preview_manifest returned by preview")
	}
	if len(m.Takeovers) > maxImportFiles {
		return NewAppError(ErrorKindValidation, "import_takeovers_too_many", "takeovers must have at most 100 entries")
	}
	for i, tk := range m.Takeovers {
		if _, err := domain.ParseFingerprint(tk.CACertificateSHA256Hex); err != nil {
			return NewAppError(ErrorKindValidation, "import_takeover_hash_invalid", fmt.Sprintf("takeovers[%d].ca_certificate_sha256 must be a sha-256 hex digest", i))
		}
		if err := tk.Confirmation.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ImportUploadCommand is the OpenAPI ImportUpload schema and is shared by
// both Preview and Commit (§3: "Preview: ImportUpload → ImportPreview;
// Commit: ImportUpload → ImportResult"). RequireManifest distinguishes them:
// Commit requires metadata.preview_manifest, Preview does not.
type ImportUploadCommand struct {
	Files           []UploadedFile
	Metadata        ImportMetadataInput
	RequireManifest bool
}

// Validate enforces every OpenAPI-required field plus the file/metadata
// consistency the ImportUpload description calls for: same count, no
// duplicate names, and metadata's file_name set must exactly match the
// uploaded files.
func (c ImportUploadCommand) Validate() error {
	if len(c.Files) == 0 || len(c.Files) > maxImportFiles {
		return NewAppError(ErrorKindValidation, "import_files_required", "files must have between 1 and 100 entries")
	}
	uploaded := make(map[string]struct{}, len(c.Files))
	for i, f := range c.Files {
		if f.FileName == "" {
			return NewAppError(ErrorKindValidation, "import_file_name_invalid", fmt.Sprintf("files[%d] must have a name", i))
		}
		if _, dup := uploaded[f.FileName]; dup {
			return NewAppError(ErrorKindValidation, "import_file_name_duplicate", fmt.Sprintf("files[%d] duplicates an earlier file name", i))
		}
		uploaded[f.FileName] = struct{}{}
	}
	if err := c.Metadata.validate(c.RequireManifest); err != nil {
		return err
	}
	for _, m := range c.Metadata.Files {
		if _, ok := uploaded[m.FileName]; !ok {
			return NewAppError(ErrorKindValidation, "import_metadata_file_unmatched",
				fmt.Sprintf("metadata references file_name %q that was not uploaded", m.FileName))
		}
	}
	return nil
}

// ImportManifestFileFacts is one file's public, parser-produced fact: the
// content hash a parser computed from bytes it already validated, never a
// value copied straight from the request. §12: "manifest는 파서가 만든 공개
// Facts에서 생성"; the OpenAPI description underscores the same point for
// the sha256 field ("never a private-key file digest").
type ImportManifestFileFacts struct {
	FileID              string
	Kind                ImportFileKind
	SHA256              domain.Fingerprint
	IssuerCertificateID domain.CertificateID
}

// PublicImportManifest is the storage/result type for the OpenAPI
// ImportManifest schema. It is built by NewPublicImportManifest from parser
// facts; nothing in this package constructs one directly from
// ImportMetadataInput or ImportUploadCommand.
type PublicImportManifest struct {
	SchemaVersion int
	Files         []ImportManifestFileFacts
}

// NewPublicImportManifest validates and copies parser-produced facts into
// the manifest a repository may persist and Preview/Commit may echo back.
func NewPublicImportManifest(files []ImportManifestFileFacts) (PublicImportManifest, error) {
	if len(files) == 0 || len(files) > maxImportFiles {
		return PublicImportManifest{}, NewAppError(ErrorKindValidation, "import_manifest_files_invalid", "manifest must have between 1 and 100 files")
	}
	out := make([]ImportManifestFileFacts, len(files))
	copy(out, files)
	return PublicImportManifest{SchemaVersion: importManifestSchemaVersion, Files: out}, nil
}

// ImportItemView is the OpenAPI ImportItem data object.
type ImportItemView struct {
	FileID     string
	SHA256     domain.Fingerprint
	Kind       ImportFileKind
	Status     ImportItemStatus
	ExistingID *domain.CertificateID
	ErrorCode  string
}

// ImportItemStatus mirrors the OpenAPI ImportItem.status enum.
type ImportItemStatus string

const (
	ImportItemStatusNew       ImportItemStatus = "new"
	ImportItemStatusDuplicate ImportItemStatus = "duplicate"
	ImportItemStatusConflict  ImportItemStatus = "conflict"
)

// ImportPreviewView is the OpenAPI ImportPreview data object.
type ImportPreviewView struct {
	Manifest PublicImportManifest
	Items    []ImportItemView
}

// ImportResultState mirrors the OpenAPI ImportResult.state enum.
type ImportResultState string

const (
	ImportResultStateCommitted ImportResultState = "committed"
	ImportResultStateFailed    ImportResultState = "failed"
)

// ImportResultView is the OpenAPI ImportResult data object.
type ImportResultView struct {
	// ID is the import run id. domain has no dedicated ImportID type (it is
	// not in the identifier list in internal/domain/values.go §2), so this
	// stays a plain uuid string rather than borrowing an unrelated ID type.
	ID             string
	State          ImportResultState
	CommittedAt    *domain.Instant
	Items          []ImportItemView
	CertificateIDs []domain.CertificateID
	AuthorityIDs   []domain.AuthorityID
}

// ImportAttachSigningKeyCommand is the OpenAPI SigningKeyUpload schema.
// AuthorityID is the path target; §3 requires the Authority version for
// both of import's CA-mutating methods (this and ConfirmTakeover).
type ImportAttachSigningKeyCommand struct {
	AuthorityID domain.AuthorityID `json:"-"`
	Key         []byte             `json:"-"`
	Passphrase  *secret.Input      `json:"-"`
}

func (c ImportAttachSigningKeyCommand) Validate() error {
	if _, err := domain.ParseAuthorityID(string(c.AuthorityID)); err != nil {
		return FromDomainError(err)
	}
	if len(c.Key) == 0 {
		return NewAppError(ErrorKindValidation, "signing_key_required", "key must not be empty")
	}
	return nil
}

// TakeoverHistoryAssertion mirrors the OpenAPI TakeoverInput.history_assertion
// enum.
type TakeoverHistoryAssertion string

const (
	TakeoverHistoryCRLsProvided          TakeoverHistoryAssertion = "crls_provided"
	TakeoverHistoryNoPreviousRevocations TakeoverHistoryAssertion = "no_previous_revocations"
)

func (a TakeoverHistoryAssertion) Validate() error {
	switch a {
	case TakeoverHistoryCRLsProvided, TakeoverHistoryNoPreviousRevocations:
		return nil
	default:
		return fmt.Errorf("%w: unsupported takeover history assertion %q", domain.ErrInvalidValue, string(a))
	}
}

// TakeoverEvidence is both the OpenAPI TakeoverEvidence wire schema and the
// storage type of the same name §12 requires kept distinct from the input
// command: unlike ImportFileMetadata, every field here is already a public
// assertion (schema_version, CRL digests, and two booleans), so the wire
// and storage shapes are identical and this one type serves both roles
// without smuggling any secret or command-only field into storage.
type TakeoverEvidence struct {
	SchemaVersion          int      `json:"schema_version"`
	CRLSHA256Hex           []string `json:"crl_sha256"`
	IssuanceRecordsChecked bool     `json:"issuance_records_checked"`
	CRLRoutesChecked       bool     `json:"crl_routes_checked"`
}

func (e TakeoverEvidence) Validate() error {
	if e.SchemaVersion != importManifestSchemaVersion {
		return NewAppError(ErrorKindValidation, "takeover_evidence_schema_version_unsupported", "evidence.schema_version must be 1")
	}
	if len(e.CRLSHA256Hex) > maxImportFiles {
		return NewAppError(ErrorKindValidation, "takeover_evidence_crl_sha256_too_many", "evidence.crl_sha256 must have at most 100 entries")
	}
	for i, h := range e.CRLSHA256Hex {
		if _, err := domain.ParseFingerprint(h); err != nil {
			return NewAppError(ErrorKindValidation, "takeover_evidence_crl_sha256_invalid", fmt.Sprintf("evidence.crl_sha256[%d] must be a sha-256 hex digest", i))
		}
	}
	if !e.IssuanceRecordsChecked || !e.CRLRoutesChecked {
		return NewAppError(ErrorKindValidation, "takeover_evidence_incomplete", "both issuance_records_checked and crl_routes_checked must be true to confirm takeover")
	}
	return nil
}

// TakeoverInput is the OpenAPI TakeoverInput schema, both ConfirmTakeover's
// command body and the shape embedded in ImportMetadata.takeovers.
// CAKeyGenerationID is the path target for ConfirmTakeover; when TakeoverInput
// appears nested inside ImportMetadata it is left zero and unused.
type TakeoverInput struct {
	CAKeyGenerationID       domain.CAKeyGenerationID `json:"-"`
	HistoryAssertion        TakeoverHistoryAssertion `json:"history_assertion"`
	PreviousMaxNumberHex    string                   `json:"previous_max_number_hex"`
	ExternalIssuerStoppedAt string                   `json:"external_issuer_stopped_at"`
	Evidence                TakeoverEvidence         `json:"evidence"`
}

// Validate checks the fields that are always required by the
// TakeoverInput schema. It does not require CAKeyGenerationID to be set,
// since this type is reused, unset, inside ImportMetadata.takeovers; the
// top-level ConfirmTakeover command validates that separately.
func (t TakeoverInput) Validate() error {
	if err := t.HistoryAssertion.Validate(); err != nil {
		return FromDomainError(err)
	}
	if _, err := domain.ParseCRLNumber(t.PreviousMaxNumberHex); err != nil {
		return FromDomainError(err)
	}
	if _, err := parseRFC3339(t.ExternalIssuerStoppedAt); err != nil {
		return NewAppError(ErrorKindValidation, "external_issuer_stopped_at_invalid", "external_issuer_stopped_at must be an RFC3339 timestamp")
	}
	if err := t.Evidence.Validate(); err != nil {
		return err
	}
	return nil
}

// ImportConfirmTakeoverCommand wraps TakeoverInput with its path target
// filled in, so ConfirmTakeover's own Validate also enforces the id.
type ImportConfirmTakeoverCommand struct {
	TakeoverInput
}

func (c ImportConfirmTakeoverCommand) Validate() error {
	if _, err := domain.ParseCAKeyGenerationID(string(c.CAKeyGenerationID)); err != nil {
		return FromDomainError(err)
	}
	return c.TakeoverInput.Validate()
}

// TakeoverState mirrors the OpenAPI Takeover.state enum.
type TakeoverState string

const (
	TakeoverStatePending   TakeoverState = "pending"
	TakeoverStateConfirmed TakeoverState = "confirmed"
)

// TakeoverView is the OpenAPI Takeover data object.
type TakeoverView struct {
	// ID is the takeover record's own uuid (no domain.TakeoverID type
	// exists; see the ImportResultView.ID comment above for why this stays
	// a plain string).
	ID                string
	CAKeyGenerationID domain.CAKeyGenerationID
	State             TakeoverState
	ConfirmedAt       *domain.Instant
	Version           domain.Version
}
