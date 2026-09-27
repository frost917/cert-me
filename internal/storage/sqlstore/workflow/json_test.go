package workflow

import (
	"strings"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

func TestManifestEncodingUsesVersionedPublicShapeAndCopiesFiles(t *testing.T) {
	manifest := contract.PublicImportManifest{
		SchemaVersion: 1,
		Files: []contract.ImportManifestFileFacts{{
			FileID: "root.pem", Kind: contract.ImportFileKindCertificate,
			SHA256: domain.NewFingerprint([]byte("root certificate")),
		}},
	}
	encoded, err := encodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if text := string(encoded); !strings.Contains(text, `"schema_version":1`) || !strings.Contains(text, `"file_id":"root.pem"`) || strings.Contains(text, "SchemaVersion") {
		t.Fatalf("manifest JSON has the wrong public shape: %s", text)
	}
	manifest.Files[0].FileID = "mutated.pem"
	decoded, err := decodeManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.Files[0].FileID; got != "root.pem" {
		t.Fatalf("decoded file id = %q, want original value", got)
	}
	decoded.Files[0].FileID = "changed-after-read.pem"
	if got := decoded.Files[0].FileID; got != "changed-after-read.pem" {
		t.Fatalf("decoded value mutation was not local: %q", got)
	}
}

func TestManifestDecoderRejectsUnknownAndUnsupportedVersion(t *testing.T) {
	for _, input := range []string{
		`{"schema_version":1,"files":[],"metadata":{"passphrase":"secret"}}`,
		`{"schema_version":2,"files":[{"file_id":"root.pem","kind":"certificate","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`,
	} {
		if _, err := decodeManifest([]byte(input)); err == nil {
			t.Fatalf("decodeManifest(%s) succeeded, want schema rejection", input)
		}
	}
}

func TestImportResultRoundTripCopiesNestedMutableValues(t *testing.T) {
	now := domain.NewInstant(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC))
	existing := domain.CertificateID("c0000000-0000-0000-0000-000000000003")
	wantTime, wantExisting := now, existing
	result := contract.ImportResultView{
		ID:          "c0000000-0000-0000-0000-000000000002",
		State:       contract.ImportResultStateCommitted,
		CommittedAt: &now,
		Items: []contract.ImportItemView{{
			FileID: "root.pem", SHA256: domain.NewFingerprint([]byte("root certificate")),
			Kind: contract.ImportFileKindCertificate, Status: contract.ImportItemStatusDuplicate, ExistingID: &existing,
		}},
		CertificateIDs: []domain.CertificateID{existing},
		AuthorityIDs:   []domain.AuthorityID{"c0000000-0000-0000-0000-000000000004"},
	}
	encoded, err := encodeImportResult(result)
	if err != nil {
		t.Fatal(err)
	}
	result.Items[0].FileID = "mutated.pem"
	*result.Items[0].ExistingID = "c0000000-0000-0000-0000-000000000005"
	result.CertificateIDs[0] = "c0000000-0000-0000-0000-000000000006"
	*result.CommittedAt = domain.InstantFromUnixMicro(99)

	decoded, err := decodeImportResult(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Items[0].FileID != "root.pem" || *decoded.Items[0].ExistingID != wantExisting || decoded.CertificateIDs[0] != wantExisting || !decoded.CommittedAt.Equal(wantTime) {
		t.Fatalf("decoded result did not preserve the encoded snapshot: %+v", decoded)
	}
	decoded.Items[0].FileID = "changed-after-read.pem"
	*decoded.Items[0].ExistingID = "c0000000-0000-0000-0000-000000000007"
	if decoded.Items[0].FileID != "changed-after-read.pem" || *decoded.Items[0].ExistingID != "c0000000-0000-0000-0000-000000000007" {
		t.Fatal("mutating decoded result did not affect the returned value")
	}
}

func TestTakeoverEvidenceStrictVersionedRoundTrip(t *testing.T) {
	evidence := contract.TakeoverEvidence{
		SchemaVersion: 1, CRLSHA256Hex: []string{domain.NewFingerprint([]byte("crl")).Hex()},
		IssuanceRecordsChecked: true, CRLRoutesChecked: true,
	}
	encoded, err := encodeEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.CRLSHA256Hex[0] = strings.Repeat("0", 64)
	decoded, err := decodeEvidence(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := decoded.CRLSHA256Hex[0], domain.NewFingerprint([]byte("crl")).Hex(); got != want {
		t.Fatalf("decoded evidence digest = %q, want %q", got, want)
	}
	if _, err := decodeEvidence([]byte(`{"schema_version":1,"crl_sha256":[],"issuance_records_checked":true,"crl_routes_checked":true,"passphrase":"x"}`)); err == nil {
		t.Fatal("decodeEvidence accepted an unknown field")
	}
}
