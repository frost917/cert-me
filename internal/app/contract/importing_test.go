package contract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

const testAuthorityID = "00000000-0000-4000-8000-000000000004"
const testCAKeyGenID = "00000000-0000-4000-8000-000000000005"

func validImportMetadata() ImportMetadataInput {
	return ImportMetadataInput{
		SchemaVersion: 1,
		Files: []ImportFileMetadataInput{
			{FileName: "leaf.pem", Kind: ImportFileKindCertificate},
		},
	}
}

func TestImportFileMetadataInput_UnmarshalWrapsPassphraseAsSecret(t *testing.T) {
	body := `{"file_name":"key.pem","kind":"ca_key","passphrase":"super-secret-pass"}`
	var m ImportFileMetadataInput
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	defer m.Passphrase.Close()
	if m.Passphrase == nil {
		t.Fatal("expected passphrase to be wrapped as a secret.Input")
	}
	if m.Passphrase.Len() != len("super-secret-pass") {
		t.Fatalf("expected wrapped passphrase to preserve length, got %d", m.Passphrase.Len())
	}
}

func TestImportFileMetadataInput_DecodeRejectsUnknownField(t *testing.T) {
	body := `{"file_name":"key.pem","kind":"ca_key","bogus_field":"x"}`
	var m ImportFileMetadataInput
	if err := json.Unmarshal([]byte(body), &m); err == nil {
		t.Fatal("expected an unknown field to be rejected")
	}
}

func TestImportFileMetadataInput_MarshalRefusesToSerialize(t *testing.T) {
	m := ImportFileMetadataInput{FileName: "key.pem", Kind: ImportFileKindCAKey, Passphrase: secret.FromString("x")}
	defer m.Passphrase.Close()
	if _, err := json.Marshal(m); err == nil {
		t.Fatal("expected MarshalJSON to refuse serialization of a passphrase-carrying value")
	}
}

func TestImportFileMetadataInput_SecretNeverLeaksThroughRendering(t *testing.T) {
	const plaintext = "super-secret-import-passphrase"
	body := `{"file_name":"key.pem","kind":"ca_key","passphrase":"` + plaintext + `"}`
	var m ImportFileMetadataInput
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	defer m.Passphrase.Close()

	rendered := fmt.Sprintf("%v", m)
	if strings.Contains(rendered, plaintext) {
		t.Fatalf("passphrase leaked through %%v rendering: %s", rendered)
	}
	if _, err := json.Marshal(m); err == nil {
		t.Fatal("expected marshal to fail rather than risk leaking the passphrase")
	}
}

func TestImportUploadCommand_ValidateRequiresMatchingFileNames(t *testing.T) {
	cmd := ImportUploadCommand{
		Files:    []UploadedFile{{FileName: "leaf.pem", Data: []byte("data")}},
		Metadata: validImportMetadata(),
	}
	if err := cmd.Validate(); err != nil {
		t.Fatalf("expected matching file names to validate, got %v", err)
	}

	mismatched := cmd
	mismatched.Metadata.Files[0].FileName = "other.pem"
	if err := mismatched.Validate(); err == nil {
		t.Fatal("expected a metadata file name with no matching upload to be rejected")
	}
}

func TestImportUploadCommand_ValidateRejectsDuplicateFileNames(t *testing.T) {
	cmd := ImportUploadCommand{
		Files: []UploadedFile{
			{FileName: "leaf.pem", Data: []byte("a")},
			{FileName: "leaf.pem", Data: []byte("b")},
		},
		Metadata: validImportMetadata(),
	}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected duplicate uploaded file names to be rejected")
	}
}

func TestImportUploadCommand_CommitRequiresPreviewManifest(t *testing.T) {
	cmd := ImportUploadCommand{
		Files:           []UploadedFile{{FileName: "leaf.pem", Data: []byte("data")}},
		Metadata:        validImportMetadata(),
		RequireManifest: true,
	}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected commit without a preview_manifest to be rejected")
	}

	cmd.Metadata.PreviewManifest = &ImportPreviewManifestInput{
		SchemaVersion: 1,
		Files: []ImportManifestFileInput{
			{FileID: "leaf.pem", Kind: ImportFileKindCertificate, SHA256Hex: strings.Repeat("a", 64)},
		},
	}
	if err := cmd.Validate(); err != nil {
		t.Fatalf("expected commit with preview_manifest to validate, got %v", err)
	}
}

func TestImportUploadCommand_ValidateRejectsBadSchemaVersion(t *testing.T) {
	cmd := ImportUploadCommand{
		Files:    []UploadedFile{{FileName: "leaf.pem", Data: []byte("data")}},
		Metadata: ImportMetadataInput{SchemaVersion: 2, Files: validImportMetadata().Files},
	}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected unsupported schema_version to be rejected")
	}
}

func TestImportAttachSigningKeyCommand_ValidateRejectsForeignAuthorityID(t *testing.T) {
	cmd := ImportAttachSigningKeyCommand{AuthorityID: "not-a-uuid", Key: []byte("key-bytes")}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected malformed authority id to be rejected")
	}
}

func TestImportAttachSigningKeyCommand_ValidateRequiresKeyBytes(t *testing.T) {
	cmd := ImportAttachSigningKeyCommand{AuthorityID: domain.AuthorityID(testAuthorityID)}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected missing key bytes to be rejected")
	}
}

func TestImportAttachSigningKeyCommand_PassphraseNeverLeaks(t *testing.T) {
	const plaintext = "super-secret-signing-key-passphrase"
	pw := secret.FromString(plaintext)
	defer pw.Close()
	cmd := ImportAttachSigningKeyCommand{
		AuthorityID: domain.AuthorityID(testAuthorityID),
		Key:         []byte("key-bytes"),
		Passphrase:  pw,
	}
	rendered := fmt.Sprintf("%v", cmd)
	if strings.Contains(rendered, plaintext) {
		t.Fatalf("passphrase leaked through %%v rendering: %s", rendered)
	}
	if _, err := json.Marshal(pw); err == nil {
		t.Fatal("expected marshalling the passphrase secret directly to error")
	}
}

func validTakeoverInput() TakeoverInput {
	return TakeoverInput{
		CAKeyGenerationID:       domain.CAKeyGenerationID(testCAKeyGenID),
		HistoryAssertion:        TakeoverHistoryNoPreviousRevocations,
		PreviousMaxNumberHex:    "1",
		ExternalIssuerStoppedAt: "2025-01-01T00:00:00Z",
		Evidence: TakeoverEvidence{
			SchemaVersion:          1,
			IssuanceRecordsChecked: true,
			CRLRoutesChecked:       true,
		},
	}
}

func TestImportConfirmTakeoverCommand_ValidateRequiredFields(t *testing.T) {
	valid := ImportConfirmTakeoverCommand{TakeoverInput: validTakeoverInput()}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid takeover to pass, got %v", err)
	}

	badID := ImportConfirmTakeoverCommand{TakeoverInput: validTakeoverInput()}
	badID.CAKeyGenerationID = "not-a-uuid"
	if err := badID.Validate(); err == nil {
		t.Fatal("expected malformed ca key generation id to be rejected")
	}

	badAssertion := ImportConfirmTakeoverCommand{TakeoverInput: validTakeoverInput()}
	badAssertion.HistoryAssertion = "not_a_real_assertion"
	if err := badAssertion.Validate(); err == nil {
		t.Fatal("expected unknown history_assertion to be rejected")
	}

	incompleteEvidence := ImportConfirmTakeoverCommand{TakeoverInput: validTakeoverInput()}
	incompleteEvidence.Evidence.CRLRoutesChecked = false
	if err := incompleteEvidence.Validate(); err == nil {
		t.Fatal("expected incomplete evidence to be rejected")
	}

	badTime := ImportConfirmTakeoverCommand{TakeoverInput: validTakeoverInput()}
	badTime.ExternalIssuerStoppedAt = "not-a-time"
	if err := badTime.Validate(); err == nil {
		t.Fatal("expected malformed external_issuer_stopped_at to be rejected")
	}
}

func TestNewPublicImportManifest_ValidatesFileCount(t *testing.T) {
	if _, err := NewPublicImportManifest(nil); err == nil {
		t.Fatal("expected an empty manifest to be rejected")
	}
	facts := []ImportManifestFileFacts{{FileID: "leaf.pem", Kind: ImportFileKindCertificate, SHA256: domain.NewFingerprint([]byte("data"))}}
	manifest, err := NewPublicImportManifest(facts)
	if err != nil {
		t.Fatalf("expected a well-formed manifest to be accepted: %v", err)
	}
	if manifest.SchemaVersion != importManifestSchemaVersion {
		t.Fatalf("expected schema version %d, got %d", importManifestSchemaVersion, manifest.SchemaVersion)
	}
}
