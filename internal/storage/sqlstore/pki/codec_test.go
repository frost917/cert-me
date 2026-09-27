package pki

import (
	"bytes"
	"testing"

	"cert-me/internal/domain"
)

func TestValidityPolicyJSONV1RoundTrip(t *testing.T) {
	validity, err := domain.NewCalendarValidity(18, domain.ValidityUnitMonths)
	if err != nil {
		t.Fatal(err)
	}
	policy := domain.SeriesPolicy{RotateEvery: 4, CertificateValidity: validity}
	raw, err := EncodeValidityPolicyV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"rotate_every":4,"validity":{"value":18,"unit":"months"}}`
	if !bytes.Equal(raw, []byte(want)) {
		t.Fatalf("encoded policy = %s, want %s", raw, want)
	}
	decoded, err := DecodeValidityPolicyV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RotateEvery != policy.RotateEvery || decoded.CertificateValidity.Value() != 18 || decoded.CertificateValidity.Unit() != domain.ValidityUnitMonths {
		t.Fatalf("decoded policy = %#v, want rotate_every=%d and 18 months", decoded, policy.RotateEvery)
	}
}

func TestVersionedJSONRejectsUnknownFields(t *testing.T) {
	if _, err := DecodeValidityPolicyV1([]byte(`{"schema_version":1,"rotate_every":3,"validity":{"value":1,"unit":"years"},"unexpected":true}`)); err == nil {
		t.Fatal("DecodeValidityPolicyV1 accepted an unknown field")
	}
	if _, err := DecodeCertificateExtensionsV1([]byte(`{"schema_version":1,"kind":"leaf","profile":"server_tls","unexpected":true}`)); err == nil {
		t.Fatal("DecodeCertificateExtensionsV1 accepted an unknown field")
	}
}

func TestCertificateMetadataJSONV1RoundTrip(t *testing.T) {
	subject, err := domain.NewSubject(domain.SubjectFacts{
		CommonName: "service.example.internal", Organization: "Example", Country: "KR",
	})
	if err != nil {
		t.Fatal(err)
	}
	subjectJSON, err := EncodeCertificateSubjectV1(subject)
	if err != nil {
		t.Fatal(err)
	}
	decodedSubject, err := DecodeCertificateSubjectV1(subjectJSON)
	if err != nil {
		t.Fatal(err)
	}
	if decodedSubject.CommonName() != subject.CommonName() || decodedSubject.Organization() != subject.Organization() || decodedSubject.Country() != subject.Country() {
		t.Fatalf("decoded subject = %#v, want original subject", decodedSubject)
	}

	metadataJSON, err := EncodeCertificateExtensionsV1(domain.CertificateKindLeaf, domain.CertificateProfileServerTLS)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := DecodeCertificateExtensionsV1(metadataJSON)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SchemaVersion != CertificateMetadataSchemaVersion || metadata.Kind != string(domain.CertificateKindLeaf) || metadata.Profile != string(domain.CertificateProfileServerTLS) {
		t.Fatalf("decoded metadata = %#v", metadata)
	}
}

func TestLeafCertificatePolicySnapshotV1ValidatesSanAndProfile(t *testing.T) {
	valid := []byte(`{"schema_version":1,"profile":"server_tls","sans":[{"type":"dns","value":"service.example.internal"}],"validity":{"value":1,"unit":"years"},"rotate_every":3}`)
	snapshot, err := DecodeLeafCertificatePolicySnapshotV1(valid)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Profile != string(domain.CertificateProfileServerTLS) || len(snapshot.SANs) != 1 {
		t.Fatalf("decoded snapshot = %#v", snapshot)
	}
	bootstrapOnlyProfile := []byte(`{"schema_version":1,"profile":"client_mtls","sans":[{"type":"dns","value":"cert-me"}],"validity":{"value":1,"unit":"years"},"rotate_every":3}`)
	if _, err := DecodeLeafCertificatePolicySnapshotV1(bootstrapOnlyProfile); err == nil {
		t.Fatal("policy snapshot accepted the bootstrap-only SAN with client_mtls")
	}
}
