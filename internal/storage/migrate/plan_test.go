package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"cert-me/internal/config"
)

func TestReviewedStatementScannerKeepsQuotedSemicolons(t *testing.T) {
	input := []byte("-- file header\nCREATE TABLE sample (value TEXT CHECK (value <> 'a;b'));\n/* separator ; */\nCREATE INDEX sample_value ON sample (value);")
	parts, err := splitReviewedStatements(input, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 {
		t.Fatalf("got %d statement parts, want 2", len(parts))
	}
	if !strings.Contains(parts[0].sql, "'a;b'") || !strings.HasPrefix(parts[1].sql, "/* separator ; */") {
		t.Fatalf("statement ranges lost SQL bytes: %#v", parts)
	}
	for _, part := range parts {
		sum := sha256.Sum256(input[part.start:part.end])
		if part.checksum != hex.EncodeToString(sum[:]) {
			t.Fatalf("step %s checksum does not match its byte range", part.id)
		}
	}
}

func TestReviewedStatementScannerRejectsUnterminatedTokens(t *testing.T) {
	for _, input := range []string{
		"CREATE TABLE sample (value TEXT CHECK (value = 'unfinished));",
		"CREATE TABLE sample (value TEXT); /* unfinished",
		"CREATE TABLE sample (`unfinished TEXT);",
	} {
		if _, err := splitReviewedStatements([]byte(input), 1); err == nil {
			t.Fatalf("accepted unterminated SQL: %q", input)
		}
	}
}

func TestEmbeddedMigrationPlanIsCompleteForEveryDialect(t *testing.T) {
	for _, kind := range []config.DatabaseKind{config.SQLite, config.Postgres, config.MySQL, config.MariaDB} {
		plan, err := loadPlan(kind)
		if err != nil {
			t.Fatalf("load %s plan: %v", kind, err)
		}
		if len(plan.files) != targetVersion+1 || len(plan.full) != targetVersion+1 {
			t.Fatalf("%s plan has incomplete version coverage", kind)
		}
		for version, file := range plan.files {
			if file.version != version || file.name == "" || file.checksum == "" || len(file.steps) == 0 {
				t.Fatalf("%s plan version %d is incomplete", kind, version)
			}
			for order, step := range file.steps {
				invalidRange := step.start < 0 || step.end < step.start
				if step.handler == "" {
					invalidRange = invalidRange || step.end == step.start
				} else if step.sql != "" || step.start != step.end {
					invalidRange = true
				}
				if step.order != order+1 || step.id == "" || step.checksum == "" || invalidRange {
					t.Fatalf("%s plan version %d step %d has invalid range metadata", kind, version, order+1)
				}
			}
		}
	}
}

func TestAuditScopeBackfillIsItsOwnVersionedStep(t *testing.T) {
	plan, err := loadPlan(config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	file := plan.files[auditScopeBackfillVersion]
	step, ok := dataHandlerStep(file)
	if !ok || step.handler != auditScopeBackfillHandlerID {
		t.Fatalf("version %d lacks the named backfill handler step", auditScopeBackfillVersion)
	}
	if step.order != len(file.steps) || step.start != step.end || step.sql != "" || step.checksum != handlerStepChecksum(step.handler) {
		t.Fatalf("handler step metadata is not stable: %#v", step)
	}
	if !reflect.DeepEqual(step.before, step.after) {
		t.Fatal("data handler step unexpectedly changes the structural catalog")
	}
	if _, ok := dataHandlerStep(plan.files[auditScopeRequiredVersion]); ok {
		t.Fatal("version 009 must remain SQL-only and fail on unresolved rows")
	}
}

func TestStructuralCatalogDetectsConstraintChanges(t *testing.T) {
	statement := `CREATE TABLE sample (
		id INTEGER NOT NULL,
		value TEXT,
		PRIMARY KEY (id),
		CHECK (length(value) <= 20)
	)`
	tokens, err := lexSQL(statement)
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseCreateTable(tokens, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	actual := want
	actual.constraints = cloneConstraints(want.constraints)
	actual.constraints[1].expression = "length(value)<=21"
	if sameTable(actual, want, config.SQLite) {
		t.Fatal("catalog accepted a modified CHECK constraint")
	}
	actual = want
	actual.columns = append([]columnShape(nil), want.columns...)
	actual.columns[1].nullable = false
	if sameTable(actual, want, config.SQLite) {
		t.Fatal("catalog accepted a modified column nullability")
	}
}

func TestPostgresCheckNormalizationRemovesOnlyKnownImplicitCasts(t *testing.T) {
	want := normalizeCheck("state IN ('active','disabled')", config.Postgres)
	got := normalizeCheck("((state)::text = ANY ((ARRAY['active'::character varying,'disabled'::character varying])::text[]))", config.Postgres)
	if got != want {
		t.Fatalf("normalized PostgreSQL checks differ: got %q, want %q", got, want)
	}
	changed := normalizeCheck("state IN ('active','removed')", config.Postgres)
	if changed == want {
		t.Fatal("normalization erased a changed CHECK literal")
	}
	wantNotIn := normalizeCheck("state NOT IN ('pending','expired')", config.Postgres)
	gotNotIn := normalizeCheck("((state)::text <> ALL ((ARRAY['pending'::character varying,'expired'::character varying])::text[]))", config.Postgres)
	if gotNotIn != wantNotIn {
		t.Fatalf("normalized PostgreSQL NOT IN checks differ: got %q, want %q", gotNotIn, wantNotIn)
	}
}
