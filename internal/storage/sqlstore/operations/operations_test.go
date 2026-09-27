package operations

import (
	"encoding/json"
	"strings"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/dialect"
)

func TestAuditDetailsUsesStrictV1JSONAndCopiesFields(t *testing.T) {
	input := contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"action": "rotate"}}
	encoded, err := encodeAuditDetails(input)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"schema_version":1,"fields":{"action":"rotate"}}`; got != want {
		t.Fatalf("encoded audit details = %s, want %s", got, want)
	}
	decoded, err := decodeAuditDetails(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Fields["action"] = "changed"
	if input.Fields["action"] != "rotate" {
		t.Fatal("decode result shares mutable fields with input")
	}
	if _, err := decodeAuditDetails([]byte(`{"schema_version":2,"fields":{}}`)); err == nil {
		t.Fatal("unsupported audit details version was accepted")
	}
	if _, err := decodeAuditDetails([]byte(`{"schema_version":1,"fields":{},"private":true}`)); err == nil {
		t.Fatal("unknown audit details field was accepted")
	}
}

func TestAuditScopePredicateRequiresEveryStoredAuthority(t *testing.T) {
	d, err := dialect.New(config.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	repo := &QueryRepository{dialect: d}
	scope := port.QueryScope{AuthorityIDs: []domain.AuthorityID{
		"a0000000-0000-4000-8000-000000000001",
		"a0000000-0000-4000-8000-000000000002",
	}}
	filter := contract.AuditFilter{Action: "Authority.Archive"}
	b := d.NewBuilder()
	predicate := repo.auditPredicate(b, filter, scope)
	if !strings.Contains(predicate, `a.scope_kind = 'authorities'`) || !strings.Contains(predicate, "NOT EXISTS") || !strings.Contains(predicate, "a.action = $3") {
		t.Fatalf("audit predicate does not enforce typed all-scope visibility and filters: %s", predicate)
	}
	if got, want := len(b.Args()), 3; got != want {
		t.Fatalf("predicate arguments = %d, want %d", got, want)
	}
}

func TestAuditScopePredicateDeniesZeroScopeAndAllowsInstallationForAll(t *testing.T) {
	d, err := dialect.New(config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	repo := &QueryRepository{dialect: d}
	if got := repo.auditPredicate(d.NewBuilder(), contract.AuditFilter{}, port.QueryScope{}); !strings.Contains(got, "1 = 0") {
		t.Fatalf("zero-value scope predicate = %s, want deny-all", got)
	}
	all := repo.auditPredicate(d.NewBuilder(), contract.AuditFilter{}, port.QueryScope{All: true})
	if !strings.Contains(all, "1 = 1") {
		t.Fatalf("all-scope predicate = %s, want allow-all", all)
	}
	public := repo.auditPredicate(d.NewBuilder(), contract.AuditFilter{}, port.QueryScope{All: true, Public: true})
	if !strings.Contains(public, "1 = 0") {
		t.Fatalf("public predicate = %s, want deny-all", public)
	}
}

func TestCloneAuditViewCopiesNestedMutableValues(t *testing.T) {
	view := contract.AuditEventView{AuthorityIDs: []domain.AuthorityID{"a0000000-0000-4000-8000-000000000001"}, Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"k": "v"}}}
	clone := cloneAuditView(view)
	clone.AuthorityIDs[0] = "a0000000-0000-4000-8000-000000000002"
	clone.Details.Fields["k"] = "changed"
	if view.AuthorityIDs[0] == clone.AuthorityIDs[0] || view.Details.Fields["k"] == clone.Details.Fields["k"] {
		t.Fatal("audit view clone shares mutable nested values")
	}
}

func TestMaintenanceRunDetailsMustBeValidJSON(t *testing.T) {
	run := port.MaintenanceRun{
		ID:        domain.JobID("a0000000-0000-4000-8000-000000000001"),
		CreatedAt: domain.InstantFromUnixMicro(1), UpdatedAt: domain.InstantFromUnixMicro(1),
		StartedAt: domain.InstantFromUnixMicro(1), Kind: contract.MaintenanceKindRestoreFinalize,
		Phase: contract.MaintenancePhaseStarted, DetailsJSON: []byte(`{"schema_version":1}`),
	}
	if err := validateMaintenanceRun(run); err != nil {
		t.Fatalf("valid run: %v", err)
	}
	run.DetailsJSON = []byte("not json")
	if err := validateMaintenanceRun(run); err == nil {
		t.Fatal("invalid run details JSON was accepted")
	}
}

func TestAuditDetailsJSONRoundTripsWithStandardJSON(t *testing.T) {
	details := contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"count": "2"}}
	encoded, err := encodeAuditDetails(details)
	if err != nil {
		t.Fatal(err)
	}
	var check map[string]any
	if err := json.Unmarshal(encoded, &check); err != nil {
		t.Fatal(err)
	}
	if check["schema_version"] != float64(1) {
		t.Fatalf("schema version missing from JSON: %s", encoded)
	}
}
