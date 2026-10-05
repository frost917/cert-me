package migrate

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"cert-me/internal/config"
	"cert-me/internal/secret"
	"cert-me/internal/storage/connection"
)

func TestMySQLCatalogCheckNormalizationMatchesRoundTrippedExpression(t *testing.T) {
	want := normalizeCheck("state IN ('applying','applied','failed')", config.MySQL)
	for name, expression := range map[string]string{
		"charset introducers":    "((`state` IN (_utf8mb4'applying',_utf8mb4'applied',_utf8mb4'failed'))) ",
		"escaped catalog quotes": "((`state` IN (_utf8mb4\\'applying\\',_utf8mb4\\'applied\\',_utf8mb4\\'failed\\'))) ",
	} {
		t.Run(name, func(t *testing.T) {
			got := normalizeCheck(expression, config.MySQL)
			if got != want {
				t.Fatalf("normalized MySQL check differs: got %q, want %q", got, want)
			}
		})
	}
}

func TestMySQLCatalogCheckNormalizationIsNarrow(t *testing.T) {
	want := normalizeCheck("state IN ('applying','applied','failed')", config.MySQL)
	for name, changed := range map[string]string{
		"changed literal":                     "state IN ('applying','applied','removed')",
		"changed literal with charset marker": "state IN (_utf8mb4'applying',_utf8mb4'applied',_utf8mb4'removed')",
		"changed charset marker":              "state IN (_latin1'applying',_latin1'applied',_latin1'failed')",
		"changed escaped charset marker":      "state IN (_latin1\\'applying\\',_latin1\\'applied\\',_latin1\\'failed\\')",
	} {
		t.Run(name, func(t *testing.T) {
			if got := normalizeCheck(changed, config.MySQL); got == want {
				t.Fatalf("normalization erased %s", name)
			}
		})
	}
	if got := normalizeCheck("value = 'octet_length(_utf8mb4)'", config.MySQL); got != "value='octet_length(_utf8mb4)'" {
		t.Fatalf("normalization changed a quoted literal: got %q", got)
	}
	if got := normalizeCheck("value = _utf8mb4 + 1", config.MySQL); got == normalizeCheck("value = 1", config.MySQL) {
		t.Fatal("normalization erased a charset marker that did not prefix a literal")
	}
}

func TestOctetLengthCatalogNormalizationIsLimitedToMySQLDialects(t *testing.T) {
	want := "length(name)<=128"
	for _, kind := range []config.DatabaseKind{config.MySQL, config.MariaDB} {
		if got := normalizeCheck("octet_length(name) <= 128", kind); got != want {
			t.Errorf("%s normalized CHECK = %q, want %q", kind, got, want)
		}
		if got := normalizeCheck("octet_length(name) <= 129", kind); got == want {
			t.Errorf("%s normalization erased a changed CHECK bound", kind)
		}
	}
	for _, kind := range []config.DatabaseKind{config.Postgres, config.SQLite} {
		if got := normalizeCheck("octet_length(name) <= 128", kind); got == want {
			t.Errorf("%s normalization changed octet_length semantics", kind)
		}
	}
	if got := normalizeCheck("value = 'octet_length(name)'", config.MariaDB); got != "value='octet_length(name)'" {
		t.Fatalf("MariaDB normalization changed a quoted function name: got %q", got)
	}
}

func TestMySQLCatalogCheckNormalizationRemovesOnlyAtomicPredicateGrouping(t *testing.T) {
	want := normalizeCheck("(kind = 'intermediate' AND management_parent_id IS NOT NULL) OR (kind IN ('root','bootstrap') AND management_parent_id IS NULL)", config.MySQL)
	got := normalizeCheck("((kind='intermediate') AND (management_parent_id IS NOT NULL)) OR ((kind IN ('root','bootstrap')) AND (management_parent_id IS NULL))", config.MySQL)
	if got != want {
		t.Fatalf("normalized MySQL predicate grouping differs: got %q, want %q", got, want)
	}

	left := normalizeCheck("a = 1 AND (b = 2 OR c = 3)", config.MySQL)
	right := normalizeCheck("(a = 1 AND b = 2) OR c = 3", config.MySQL)
	if left == right {
		t.Fatal("normalization erased parentheses that change AND/OR grouping")
	}

	if got := normalizeCheck("value = '(a=1 OR b=2)'", config.MySQL); got != "value='(a=1 OR b=2)'" {
		t.Fatalf("normalization changed parentheses inside a string literal: got %q", got)
	}
	if got := normalizeCheck("value = lower(name)", config.MySQL); got != "value=lower(name)" {
		t.Fatalf("normalization changed function-call parentheses: got %q", got)
	}
}

func TestPostgresCatalogCheckNormalizationRemovesOnlyAtomicPredicateGrouping(t *testing.T) {
	want := normalizeCheck("(state = 'active' AND role = 'admin') OR (state = 'disabled' AND role = 'reader')", config.Postgres)
	got := normalizeCheck("((state = 'active') AND (role = 'admin')) OR ((state = 'disabled') AND (role = 'reader'))", config.Postgres)
	if got != want {
		t.Fatalf("normalized PostgreSQL predicate grouping differs: got %q, want %q", got, want)
	}
	left := normalizeCheck("a = 1 AND (b = 2 OR c = 3)", config.Postgres)
	right := normalizeCheck("(a = 1 AND b = 2) OR c = 3", config.Postgres)
	if left == right {
		t.Fatal("PostgreSQL normalization erased parentheses that change AND/OR grouping")
	}
}

func TestMySQLCatalogCheckNormalizationMatchesRegexFunctionRoundTrip(t *testing.T) {
	want := mysqlCatalogTable(columnShape{name: "serial_hex", typeName: "varchar", length: "40", nullable: false, charset: "ascii", collation: "ascii_bin"})
	want.constraints = []constraintShape{{kind: "check", expression: "serial_hex REGEXP '^[0-9a-f]+$'"}}
	actual := want
	actual.constraints = []constraintShape{{kind: "check", expression: "REGEXP_LIKE(serial_hex, '^[0-9a-f]+$')"}}
	if !sameTable(actual, want, config.MySQL) {
		t.Fatal("MySQL catalog did not normalize the REGEXP function round-trip")
	}
	for name, changed := range map[string]string{
		"changed pattern":  "REGEXP_LIKE(serial_hex, '^[0-9a-f]*$')",
		"extra match mode": "REGEXP_LIKE(serial_hex, '^[0-9a-f]+$', 'i')",
	} {
		t.Run(name, func(t *testing.T) {
			changedTable := want
			changedTable.constraints = []constraintShape{{kind: "check", expression: changed}}
			if sameTable(changedTable, want, config.MySQL) {
				t.Fatalf("normalization erased %s", name)
			}
		})
	}
	mariaExpected := want
	mariaExpected.constraints[0].expression = "serial_hex REGEXP '^[0-9a-f]+$'"
	mariaActual := mariaExpected
	mariaActual.constraints = []constraintShape{{kind: "check", expression: "REGEXP_LIKE(serial_hex, '^[0-9a-f]+$')"}}
	if sameTable(mariaActual, mariaExpected, config.MariaDB) {
		t.Fatal("MySQL REGEXP alias normalization was applied to MariaDB")
	}
}

func TestPostgresCheckNormalizationDoesNotRewriteCastLikeLiteralText(t *testing.T) {
	castLikeLiteral := normalizeCheck("state = 'root::text'", config.Postgres)
	plainLiteral := normalizeCheck("state = 'root'", config.Postgres)
	if castLikeLiteral == plainLiteral {
		t.Fatal("PostgreSQL normalization erased cast-like text inside a string literal")
	}

	arrayLikeLiteral := normalizeCheck("payload = 'state=any(array[active])'", config.Postgres)
	inLikeLiteral := normalizeCheck("payload = 'statein(active)'", config.Postgres)
	if arrayLikeLiteral == inLikeLiteral {
		t.Fatal("PostgreSQL normalization rewrote array-membership text inside a string literal")
	}
}

func TestMariaDBCatalogCheckComparisonPreservesLogicalPrecedence(t *testing.T) {
	columns := []columnShape{
		{name: "kind", typeName: "varchar", length: "32", nullable: false, charset: "ascii", collation: "ascii_bin"},
		{name: "management_parent_id", typeName: "varchar", length: "36", nullable: true, charset: "ascii", collation: "ascii_bin"},
	}
	expected := mysqlCatalogTable(columns[0])
	expected.columns = columns
	expected.constraints = []constraintShape{{kind: "check", expression: "(kind='intermediate' AND management_parent_id IS NOT NULL) OR (kind IN ('root','bootstrap') AND management_parent_id IS NULL)"}}
	actual := expected
	actual.constraints = []constraintShape{{kind: "check", expression: "kind='intermediate' AND management_parent_id IS NOT NULL OR kind IN ('root','bootstrap') AND management_parent_id IS NULL"}}
	if !sameTable(actual, expected, config.MariaDB) {
		t.Fatalf("MariaDB catalog dropped only precedence-redundant grouping: actual=%q expected=%q", actual.constraints[0].expression, expected.constraints[0].expression)
	}

	left := expected
	left.columns = []columnShape{{name: "a", typeName: "integer"}, {name: "b", typeName: "integer"}, {name: "c", typeName: "integer"}}
	left.constraints = []constraintShape{{kind: "check", expression: "a = 1 AND (b = 2 OR c = 3)"}}
	right := left
	right.constraints = []constraintShape{{kind: "check", expression: "(a = 1 AND b = 2) OR c = 3"}}
	if sameTable(left, right, config.MariaDB) {
		t.Fatal("MariaDB comparison erased parentheses that change boolean precedence")
	}
}

func TestMariaDBNullableNULLDefaultMatchesAbsentDefaultOnlyWhenNullable(t *testing.T) {
	wantNullable := mysqlCatalogTable(columnShape{name: "value", typeName: "varchar", length: "20", nullable: true, charset: "ascii", collation: "ascii_bin"})
	gotNullable := wantNullable
	gotNullable.columns = append([]columnShape(nil), wantNullable.columns...)
	gotNullable.columns[0].defaultSQL = "null"
	if !sameTable(gotNullable, wantNullable, config.MariaDB) {
		t.Fatal("MariaDB nullable NULL catalog default did not match an absent default")
	}

	wantRequired := mysqlCatalogTable(columnShape{name: "value", typeName: "varchar", length: "20", nullable: false, charset: "ascii", collation: "ascii_bin"})
	gotRequired := wantRequired
	gotRequired.columns = append([]columnShape(nil), wantRequired.columns...)
	gotRequired.columns[0].defaultSQL = "null"
	if sameTable(gotRequired, wantRequired, config.MariaDB) {
		t.Fatal("MariaDB NULL default on a non-nullable column was normalized away")
	}
	if sameTable(gotNullable, wantNullable, config.MySQL) {
		t.Fatal("MySQL NULL default was normalized as MariaDB catalog metadata")
	}
	gotNullable.columns[0].defaultSQL = "'NULL'"
	if sameTable(gotNullable, wantNullable, config.MariaDB) {
		t.Fatal("MariaDB quoted NULL literal was normalized as a SQL NULL default")
	}
}

func mysqlCatalogTable(column columnShape) tableShape {
	return tableShape{
		name: "sample", columns: []columnShape{column},
		engine: "innodb", charset: "utf8mb4", collation: "utf8mb4_bin",
	}
}

func TestExternalMigrationCatalogPrefixDiagnostic(t *testing.T) {
	for _, kind := range []config.DatabaseKind{config.Postgres, config.MySQL, config.MariaDB} {
		t.Run(string(kind), func(t *testing.T) {
			database, ok := migrationDiagnosticDatabase(t, kind)
			if !ok {
				t.Skip("disposable external database is not configured")
			}
			if database.Password != nil {
				defer database.Password.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			handle, err := connection.Open(ctx, database, connection.Options{})
			if err != nil {
				t.Fatal("could not open disposable database for catalog diagnostics")
			}
			defer func() {
				if err := handle.Close(); err != nil {
					t.Errorf("close disposable database: %v", err)
				}
			}()
			if kind == config.MariaDB {
				rows, err := handle.ReadDB().QueryContext(ctx, `SELECT column_name FROM information_schema.columns
					WHERE table_schema='information_schema' AND table_name='check_constraints' ORDER BY ordinal_position`)
				if err != nil {
					t.Fatalf("read MariaDB CHECK_CONSTRAINTS columns: %v", err)
				}
				var columns []string
				for rows.Next() {
					var column string
					if err := rows.Scan(&column); err != nil {
						rows.Close()
						t.Fatalf("scan MariaDB CHECK_CONSTRAINTS column: %v", err)
					}
					columns = append(columns, column)
				}
				if err := rows.Err(); err != nil {
					rows.Close()
					t.Fatalf("iterate MariaDB CHECK_CONSTRAINTS columns: %v", err)
				}
				rows.Close()
				t.Logf("MariaDB CHECK_CONSTRAINTS columns=%v", columns)
				rows, err = handle.ReadDB().QueryContext(ctx, `SELECT constraint_name, check_clause FROM information_schema.check_constraints
					WHERE constraint_schema=DATABASE() AND table_name='authorities' ORDER BY constraint_name`)
				if err == nil {
					for rows.Next() {
						var name, clause string
						if scanErr := rows.Scan(&name, &clause); scanErr != nil {
							break
						}
						t.Logf("MariaDB raw authority CHECK name=%s clause=%q", name, clause)
					}
					rows.Close()
				}
			}

			plan, err := loadPlan(kind)
			if err != nil {
				t.Fatalf("load %s migration plan: %v", kind, err)
			}
			actual, err := readCatalog(ctx, handle.ReadDB(), kind)
			if err != nil {
				t.Fatalf("read %s catalog failed: %v", kind, err)
			}
			matches := matchingCatalogPhases(actual, plan, kind)
			entries, journalErr := readJournal(ctx, handle.WriterConn())
			if journalErr != nil {
				t.Logf("journal unavailable; catalog matches=%v", matches)
			} else {
				maxApplied := -1
				hasIncomplete := false
				for _, entry := range entries {
					if entry.state == "applied" && entry.version > maxApplied {
						maxApplied = entry.version
					} else if entry.state != "applied" {
						hasIncomplete = true
					}
				}
				var journal []string
				for _, entry := range entries {
					journal = append(journal, fmt.Sprintf("v%d:%s:%d", entry.version, entry.state, entry.lastStep))
					if entry.state == "applied" {
						if entry.version != maxApplied || hasIncomplete {
							continue
						}
						differences := catalogDifferences(actual, plan.full[entry.version], kind)
						if len(differences) != 0 {
							t.Logf("applied journal prefix v%d differs: %v", entry.version, differences)
						}
						continue
					}
					if entry.version <= 0 || entry.version > targetVersion {
						t.Logf("incomplete journal version is outside the diagnostic range: %d", entry.version)
						continue
					}
					phase, expected := closestVersionPhase(actual, plan, entry.version, kind)
					t.Logf("incomplete journal v%d last_step=%d closest=%s differences=%v", entry.version, entry.lastStep, phase, catalogDifferences(actual, expected, kind))
					t.Logf("catalog versus full-v%d expected=%v", entry.version, catalogDifferences(actual, plan.full[entry.version], kind))
					if entry.lastStep < len(plan.files[entry.version].steps) {
						next := plan.files[entry.version].steps[entry.lastStep]
						t.Logf("catalog versus next step v%d.%d after=%v", entry.version, next.order, catalogDifferences(actual, next.after, kind))
					}
				}
				t.Logf("catalog matches=%v journal=%v", matches, journal)
			}
			if len(matches) == 0 {
				phase, expected := closestCatalogPhase(actual, plan, kind)
				t.Logf("closest catalog phase=%s differences=%v", phase, catalogDifferences(actual, expected, kind))
			}
		})
	}
}

func TestExternalPostgresCatalogExcludesIntrinsicNotNullConstraints(t *testing.T) {
	databaseName := os.Getenv("CERTME_CATALOG_TEST_POSTGRES_DATABASE")
	if databaseName == "" {
		t.Skip("dedicated PostgreSQL catalog database is not configured")
	}
	database, ok := migrationDiagnosticDatabase(t, config.Postgres)
	if !ok {
		t.Skip("disposable PostgreSQL database connection is not configured")
	}
	defer database.Password.Close()
	database.DatabaseName = databaseName
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := connection.Open(ctx, database, connection.Options{})
	if err != nil {
		t.Fatal("could not open dedicated PostgreSQL catalog database")
	}
	defer func() {
		if err := handle.Close(); err != nil {
			t.Errorf("close dedicated PostgreSQL catalog database: %v", err)
		}
	}()

	actual, err := readCatalog(ctx, handle.ReadDB(), config.Postgres)
	if err != nil {
		t.Fatalf("read dedicated PostgreSQL catalog: %v", err)
	}
	plan, err := loadPlan(config.Postgres)
	if err != nil {
		t.Fatalf("load PostgreSQL migration plan: %v", err)
	}
	got, ok := actual.tables["schema_migrations"]
	if !ok {
		t.Fatal("dedicated PostgreSQL catalog has no schema_migrations table")
	}
	want := plan.full[0].tables["schema_migrations"]
	if !sameTable(got, want, config.Postgres) {
		t.Fatalf("intrinsic NOT NULL constraints changed the reviewed schema_migrations shape: got %d constraints, want %d", len(got.constraints), len(want.constraints))
	}
}

func TestExternalPostgresMigrationStepCatalogDiagnostic(t *testing.T) {
	database, ok := migrationDiagnosticDatabase(t, config.Postgres)
	if !ok {
		t.Skip("disposable PostgreSQL database is not configured")
	}
	defer database.Password.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := connection.Open(ctx, database, connection.Options{})
	if err != nil {
		t.Fatal("could not open disposable PostgreSQL database")
	}
	defer handle.Close()
	plan, err := loadPlan(config.Postgres)
	if err != nil {
		t.Fatalf("load PostgreSQL migration plan: %v", err)
	}
	step := plan.files[3].steps[0]
	tx, err := handle.WriterConn().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin diagnostic transaction: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, step.sql); err != nil {
		t.Fatalf("execute PostgreSQL v3 step1 in rollback-only diagnostic transaction: %v", err)
	}
	actual, err := readCatalog(ctx, tx, config.Postgres)
	if err != nil {
		t.Fatalf("read PostgreSQL step catalog: %v", err)
	}
	if !catalogMatches(actual, step.after, config.Postgres) {
		t.Logf("PostgreSQL v3 step1 catalog differences: %v", catalogDifferences(actual, step.after, config.Postgres))
	}
}

func TestExternalMariaDBCatalogKeepsCheckConstraintsOnTheirTable(t *testing.T) {
	database, ok := migrationDiagnosticDatabase(t, config.MariaDB)
	if !ok {
		t.Skip("disposable MariaDB database is not configured")
	}
	defer database.Password.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := connection.Open(ctx, database, connection.Options{})
	if err != nil {
		t.Fatal("could not open disposable MariaDB database")
	}
	defer func() {
		if err := handle.Close(); err != nil {
			t.Errorf("close disposable MariaDB database: %v", err)
		}
	}()

	actual, err := readCatalog(ctx, handle.ReadDB(), config.MariaDB)
	if err != nil {
		t.Fatalf("read MariaDB catalog: %v", err)
	}
	got, ok := actual.tables["accounts"]
	if !ok {
		t.Skip("MariaDB test database does not yet contain the accounts table")
	}
	plan, err := loadPlan(config.MariaDB)
	if err != nil {
		t.Fatalf("load MariaDB migration plan: %v", err)
	}
	want := plan.full[1].tables["accounts"]
	if !sameTable(got, want, config.MariaDB) {
		t.Fatalf("MariaDB joined CHECK constraints across tables: got %d constraints, want %d", len(got.constraints), len(want.constraints))
	}
}

func migrationDiagnosticDatabase(t *testing.T, kind config.DatabaseKind) (config.Database, bool) {
	t.Helper()
	prefix := "CERTME_RUNTIME_TEST_" + strings.ToUpper(string(kind)) + "_"
	fields := []string{"HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD"}
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		value, ok := os.LookupEnv(prefix + field)
		if !ok || value == "" {
			return config.Database{}, false
		}
		values[field] = value
	}
	port, err := strconv.ParseUint(values["PORT"], 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("%s diagnostic database port is invalid", kind)
	}
	return config.Database{
		Kind: kind, Host: values["HOST"], Port: uint16(port), DatabaseName: values["DATABASE"],
		Username: values["USERNAME"], Password: secret.FromString(values["PASSWORD"]),
	}, true
}

func matchingCatalogPhases(actual schema, plan *migrationPlan, kind config.DatabaseKind) []string {
	var matches []string
	for version, expected := range plan.full {
		if catalogMatches(actual, expected, kind) {
			matches = append(matches, fmt.Sprintf("full-v%d", version))
		}
	}
	for version, file := range plan.files {
		for _, step := range file.steps {
			if catalogMatches(actual, step.before, kind) {
				matches = append(matches, fmt.Sprintf("v%d-step%d-before", version, step.order))
			}
			if catalogMatches(actual, step.after, kind) {
				matches = append(matches, fmt.Sprintf("v%d-step%d-after", version, step.order))
			}
		}
	}
	return matches
}

func closestCatalogPhase(actual schema, plan *migrationPlan, kind config.DatabaseKind) (string, schema) {
	phase := "full-v0"
	closest := plan.full[0]
	closestCount := len(catalogDifferences(actual, closest, kind))
	consider := func(name string, expected schema) {
		count := len(catalogDifferences(actual, expected, kind))
		if count < closestCount {
			phase, closest, closestCount = name, expected, count
		}
	}
	for version, expected := range plan.full {
		consider(fmt.Sprintf("full-v%d", version), expected)
	}
	for version, file := range plan.files {
		for _, step := range file.steps {
			consider(fmt.Sprintf("v%d-step%d-before", version, step.order), step.before)
			consider(fmt.Sprintf("v%d-step%d-after", version, step.order), step.after)
		}
	}
	return phase, closest
}

func closestVersionPhase(actual schema, plan *migrationPlan, version int, kind config.DatabaseKind) (string, schema) {
	previousVersion := version - 1
	if previousVersion < 0 {
		previousVersion = 0
	}
	phase := fmt.Sprintf("full-v%d", previousVersion)
	closest := plan.full[previousVersion]
	closestCount := len(catalogDifferences(actual, closest, kind))
	for _, step := range plan.files[version].steps {
		for _, candidate := range []struct {
			name     string
			expected schema
		}{
			{name: fmt.Sprintf("v%d-step%d-before", version, step.order), expected: step.before},
			{name: fmt.Sprintf("v%d-step%d-after", version, step.order), expected: step.after},
		} {
			count := len(catalogDifferences(actual, candidate.expected, kind))
			if count < closestCount {
				phase, closest, closestCount = candidate.name, candidate.expected, count
			}
		}
	}
	return phase, closest
}

func catalogDifferences(actual, expected schema, kind config.DatabaseKind) []string {
	var differences []string
	if len(actual.unknown) != 0 {
		differences = append(differences, fmt.Sprintf("unknown=%v", actual.unknown))
	}
	for name, want := range expected.tables {
		got, ok := actual.tables[name]
		if !ok {
			differences = append(differences, "missing table "+name)
			continue
		}
		differences = append(differences, tableDifferences(got, want, kind)...)
	}
	for name := range actual.tables {
		if _, ok := expected.tables[name]; !ok {
			got := actual.tables[name]
			differences = append(differences, fmt.Sprintf("unexpected table %s columns=%d constraints=%d options=%s/%s/%s", name, len(got.columns), len(got.constraints), got.engine, got.charset, got.collation))
		}
	}
	if !matchIndexes(actual, expected, kind) {
		gotIndexes, wantIndexes := make(map[string]int), make(map[string]int)
		for _, index := range actual.indexes {
			gotIndexes[indexKey(index.table, index.unique, index.partial, index.columns, index.orders, index.collations)]++
		}
		for _, table := range expected.tables {
			for _, constraint := range table.constraints {
				if constraint.kind != "primary" && constraint.kind != "unique" {
					continue
				}
				orders, collations := make([]string, len(constraint.columns)), make([]string, len(constraint.columns))
				for i, columnName := range constraint.columns {
					orders[i] = "asc"
					column, _ := findColumn(table, columnName)
					collations[i] = column.collation
				}
				wantIndexes[indexKey(table.name, true, false, constraint.columns, orders, collations)]++
			}
		}
		for _, index := range expected.indexes {
			wantIndexes[indexKey(index.table, index.unique, index.partial, index.columns, index.orders, index.collations)]++
		}
		for key, count := range wantIndexes {
			if gotIndexes[key] < count {
				differences = append(differences, "missing index "+key)
			}
		}
		for key, count := range gotIndexes {
			if wantIndexes[key] < count {
				differences = append(differences, "unexpected index "+key)
			}
		}
	}
	return differences
}

func tableDifferences(actual, expected tableShape, kind config.DatabaseKind) []string {
	var differences []string
	if len(actual.columns) != len(expected.columns) || len(actual.constraints) != len(expected.constraints) {
		differences = append(differences, fmt.Sprintf("table %s column-count=%d/%d constraint-count=%d/%d", expected.name, len(actual.columns), len(expected.columns), len(actual.constraints), len(expected.constraints)))
	}
	if kind == config.MySQL || kind == config.MariaDB {
		if actual.engine != expected.engine || actual.charset != expected.charset || actual.collation != expected.collation {
			differences = append(differences, fmt.Sprintf("table %s options actual=%s/%s/%s expected=%s/%s/%s", expected.name, actual.engine, actual.charset, actual.collation, expected.engine, expected.charset, expected.collation))
		}
	}
	for i := 0; i < len(actual.columns) && i < len(expected.columns); i++ {
		got, want := actual.columns[i], expected.columns[i]
		gotDefault := normalizeCatalogDefault(got.defaultSQL, got.nullable, kind)
		if got.name != want.name || got.typeName != want.typeName || canonicalLength(got.length) != canonicalLength(want.length) || got.nullable != want.nullable || gotDefault != want.defaultSQL || got.collation != want.collation || (kind == config.MySQL || kind == config.MariaDB) && got.charset != want.charset {
			differences = append(differences, fmt.Sprintf("table %s column %s actual=%#v expected=%#v", expected.name, got.name, got, want))
		}
	}
	gotConstraints := make(map[string]int)
	for _, constraint := range actual.constraints {
		gotConstraints[constraintKey(normalizeConstraint(constraint, kind))]++
	}
	for _, constraint := range expected.constraints {
		key := constraintKey(normalizeConstraint(constraint, kind))
		if gotConstraints[key] == 0 {
			differences = append(differences, fmt.Sprintf("table %s missing constraint %s", expected.name, key))
		} else {
			gotConstraints[key]--
		}
	}
	for key, count := range gotConstraints {
		for i := 0; i < count; i++ {
			differences = append(differences, fmt.Sprintf("table %s unexpected constraint %s", expected.name, key))
		}
	}
	sort.Strings(differences)
	return differences
}
