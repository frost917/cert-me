package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"reflect"
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
			if got := normalizeCheck(expression, config.MySQL); got != want {
				t.Fatalf("normalized MySQL check differs: got %q, want %q", got, want)
			}
		})
	}
}

func TestMySQLCatalogCheckNormalizationPreservesKnownCharsetIntroducers(t *testing.T) {
	want := normalizeCheck("purpose IN ('ca_signing','leaf_delivery')", config.MySQL)
	got := normalizeCheck("(`purpose` IN (_ascii\\'ca_signing\\',_ascii\\'leaf_delivery\\'))", config.MySQL)
	if got != want {
		t.Fatalf("normalized MySQL ASCII check differs: got %q, want %q", got, want)
	}
	for _, marker := range []string{"_latin1", "_binary"} {
		changed := normalizeCheck("purpose IN ("+marker+"\\'ca_signing\\',"+marker+"\\'leaf_delivery\\')", config.MySQL)
		if changed == want {
			t.Fatalf("normalization erased unknown charset marker %q", marker)
		}
	}
	if got := normalizeCheck("purpose = _ascii\\'café\\'", config.MySQL); got == normalizeCheck("purpose = 'café'", config.MySQL) {
		t.Fatal("normalization accepted non-ASCII bytes under the _ascii introducer")
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
	actualMaria := mariaExpected
	actualMaria.constraints = []constraintShape{{kind: "check", expression: "REGEXP_LIKE(serial_hex, '^[0-9a-f]+$')"}}
	if sameTable(actualMaria, mariaExpected, config.MariaDB) {
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
	integerCast := normalizeCheck("version::integer >= 0", config.Postgres)
	plainInteger := normalizeCheck("version >= 0", config.Postgres)
	if integerCast == plainInteger {
		t.Fatal("PostgreSQL normalization removed a numeric cast that can change comparison semantics")
	}
}

func TestPostgresBetweenNormalizationMatchesOnlyExpandedInclusiveBounds(t *testing.T) {
	want := normalizeCheck("length(serial_hex) BETWEEN 1 AND 40", config.Postgres)
	got := normalizeCheck("length(serial_hex) >= 1 AND length(serial_hex) <= 40", config.Postgres)
	if got != want {
		t.Fatalf("normalized PostgreSQL BETWEEN checks differ: got %q, want %q", got, want)
	}
	for name, changed := range map[string]string{
		"changed lower bound": "length(serial_hex) >= 0 AND length(serial_hex) <= 40",
		"changed upper bound": "length(serial_hex) >= 1 AND length(serial_hex) <= 41",
	} {
		t.Run(name, func(t *testing.T) {
			if normalizeCheck(changed, config.Postgres) == want {
				t.Fatalf("normalization erased %s", name)
			}
		})
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
		t.Fatal("MariaDB catalog did not normalize precedence-redundant grouping")
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

func TestMariaDBBooleanDefaultZeroMatchesFalseOnlyForBooleanColumns(t *testing.T) {
	want := mysqlCatalogTable(columnShape{name: "needs_review", typeName: "boolean", nullable: false, defaultSQL: "false"})
	got := want
	got.columns = append([]columnShape(nil), want.columns...)
	got.columns[0].defaultSQL = "0"
	for _, kind := range []config.DatabaseKind{config.MySQL, config.MariaDB} {
		if !sameTable(got, want, kind) {
			t.Errorf("%s numeric boolean default 0 did not match reviewed FALSE", kind)
		}
	}
	for name, column := range map[string]columnShape{
		"numeric default differs":     {name: "needs_review", typeName: "boolean", nullable: false, defaultSQL: "1"},
		"quoted zero is not boolean":  {name: "needs_review", typeName: "boolean", nullable: false, defaultSQL: "'0'"},
		"integer zero is not boolean": {name: "needs_review", typeName: "integer", nullable: false, defaultSQL: "0"},
	} {
		t.Run(name, func(t *testing.T) {
			changed := mysqlCatalogTable(column)
			if sameTable(changed, want, config.MariaDB) || sameTable(changed, want, config.MySQL) {
				t.Fatal("normalization accepted a changed or non-boolean default")
			}
		})
	}
}

func mysqlCatalogTable(column columnShape) tableShape {
	return tableShape{
		name: "sample", columns: []columnShape{column},
		engine: "innodb", charset: "utf8mb4", collation: "utf8mb4_bin",
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
	if !sameTable(got, plan.full[0].tables["schema_migrations"], config.Postgres) {
		t.Fatalf("intrinsic NOT NULL constraints changed reviewed schema_migrations shape: got %d constraints, want %d", len(got.constraints), len(plan.full[0].tables["schema_migrations"].constraints))
	}
}

func TestExternalPostgresCatalogPreservesCompositeForeignKeyOrder(t *testing.T) {
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
	tx, err := handle.WriterConn().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin composite-key catalog fixture transaction: %v", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Errorf("rollback composite-key catalog fixture: %v", err)
		}
	}()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	parentTable := "catalog_probe_parent_" + suffix
	childTable := "catalog_probe_child_" + suffix
	foreignKey := "catalog_probe_fk_" + suffix
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE TABLE public.%s (
		first_id BIGINT NOT NULL,
		second_id BIGINT NOT NULL,
		PRIMARY KEY (first_id, second_id)
	)`, parentTable)); err != nil {
		t.Fatalf("create composite-key catalog parent fixture: %v", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE TABLE public.%s (
		local_first BIGINT NOT NULL,
		local_second BIGINT NOT NULL,
		CONSTRAINT %s FOREIGN KEY (local_first, local_second)
		REFERENCES public.%s (second_id, first_id)
	)`, childTable, foreignKey, parentTable)); err != nil {
		t.Fatalf("create reordered composite foreign-key catalog fixture: %v", err)
	}
	actual, err := readCatalog(ctx, tx, config.Postgres)
	if err != nil {
		t.Fatalf("read PostgreSQL composite-key fixture catalog: %v", err)
	}
	child, ok := actual.tables[childTable]
	if !ok {
		t.Fatal("PostgreSQL catalog omitted the child fixture table")
	}
	for _, constraint := range child.constraints {
		if constraint.kind != "foreign" {
			continue
		}
		if !reflect.DeepEqual(constraint.columns, []string{"local_first", "local_second"}) ||
			!reflect.DeepEqual(constraint.refColumns, []string{"second_id", "first_id"}) || constraint.reference != parentTable {
			t.Fatalf("PostgreSQL composite foreign-key order = %#v", constraint)
		}
		return
	}
	t.Fatal("PostgreSQL catalog omitted the composite foreign-key constraint")
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
	if !sameTable(got, plan.full[1].tables["accounts"], config.MariaDB) {
		t.Fatalf("MariaDB joined CHECK constraints across tables: got %d constraints, want %d", len(got.constraints), len(plan.full[1].tables["accounts"].constraints))
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
