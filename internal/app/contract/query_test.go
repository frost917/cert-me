package contract

import (
	"testing"
	"time"

	"cert-me/internal/domain"
)

func TestAuthorityGetQuery_ValidateRejectsForeignID(t *testing.T) {
	q := AuthorityGetQuery{AuthorityID: "not-a-uuid"}
	if err := q.Validate(); err == nil {
		t.Fatal("expected malformed authority id to be rejected")
	}
}

func TestAuthorityListQuery_ValidateBoundsLimit(t *testing.T) {
	tooBig := AuthorityListQuery{Page: PageRequest{Limit: 500}}
	if err := tooBig.Validate(); err == nil {
		t.Fatal("expected an over-limit page request to be rejected")
	}
	negative := AuthorityListQuery{Page: PageRequest{Limit: -1}}
	if err := negative.Validate(); err == nil {
		t.Fatal("expected a negative limit to be rejected")
	}
	defaulted := AuthorityListQuery{}
	if err := defaulted.Validate(); err != nil {
		t.Fatalf("expected a zero-value page request to default cleanly: %v", err)
	}
}

func TestAuthorityListQuery_ValidateBoundsSearchLength(t *testing.T) {
	long := make([]byte, maxSearchLength+1)
	for i := range long {
		long[i] = 'a'
	}
	q := AuthorityListQuery{Search: string(long)}
	if err := q.Validate(); err == nil {
		t.Fatal("expected an over-length search term to be rejected")
	}
}

func TestCertificateListQuery_ValidateRejectsForeignAuthorityFilter(t *testing.T) {
	bad := domain.AuthorityID("not-a-uuid")
	q := CertificateListQuery{AuthorityID: &bad}
	if err := q.Validate(); err == nil {
		t.Fatal("expected malformed authority id filter to be rejected")
	}
}

func TestRevocationListQuery_ValidateRejectsMalformedSerial(t *testing.T) {
	q := RevocationListQuery{SerialHex: "not-hex!"}
	if err := q.Validate(); err == nil {
		t.Fatal("expected malformed serial_hex to be rejected")
	}
	ok := RevocationListQuery{SerialHex: "1a"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("expected valid serial_hex to pass, got %v", err)
	}
}

func TestAuditFilter_ValidateRejectsInvertedRange(t *testing.T) {
	from := domain.NewInstant(mustParseTime(t, "2025-06-01T00:00:00Z"))
	until := domain.NewInstant(mustParseTime(t, "2025-01-01T00:00:00Z"))
	f := AuditFilter{From: &from, Until: &until}
	if err := f.validate(); err == nil {
		t.Fatal("expected until before from to be rejected")
	}
}

func TestAuditFilter_ValidateRejectsUnknownResult(t *testing.T) {
	bad := AuditResultFilter("not_a_result")
	f := AuditFilter{Result: &bad}
	if err := f.validate(); err == nil {
		t.Fatal("expected unknown result value to be rejected")
	}
}

func TestAuditExportQuery_ValidateRejectsUnknownFormat(t *testing.T) {
	q := AuditExportQuery{Format: "yaml"}
	if err := q.Validate(); err == nil {
		t.Fatal("expected unsupported export format to be rejected")
	}
	ok := AuditExportQuery{Format: AuditExportFormatCSV}
	if err := ok.Validate(); err != nil {
		t.Fatalf("expected csv format to validate, got %v", err)
	}
}

func TestGetCRLStatusQuery_ValidateRejectsForeignID(t *testing.T) {
	q := GetCRLStatusQuery{CAKeyGenerationID: "not-a-uuid"}
	if err := q.Validate(); err == nil {
		t.Fatal("expected malformed ca key generation id to be rejected")
	}
}

func TestReadPublicCAQuery_ValidateRejectsForeignID(t *testing.T) {
	q := ReadPublicCAQuery{AuthorityID: "not-a-uuid"}
	if err := q.Validate(); err == nil {
		t.Fatal("expected malformed authority id to be rejected")
	}
}

func TestImportGetQuery_ValidateRejectsMalformedID(t *testing.T) {
	q := ImportGetQuery{ImportID: "short"}
	if err := q.Validate(); err == nil {
		t.Fatal("expected malformed import id to be rejected")
	}
}

func mustParseTime(t *testing.T, raw string) time.Time {
	t.Helper()
	tm, err := parseRFC3339(raw)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	return tm
}
