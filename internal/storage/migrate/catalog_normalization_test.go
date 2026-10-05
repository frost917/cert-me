package migrate

import (
	"testing"

	"cert-me/internal/config"
)

func TestMySQLCatalogCheckNormalizationMatchesRoundTrippedExpression(t *testing.T) {
	want := normalizeCheck("state IN ('applying','applied','failed')", config.MySQL)
	got := normalizeCheck("((`state` IN (_utf8mb4'applying',_utf8mb4'applied',_utf8mb4'failed'))) ", config.MySQL)
	if got != want {
		t.Fatalf("normalized MySQL check differs: got %q, want %q", got, want)
	}
}

func TestMySQLCatalogCheckNormalizationIsNarrow(t *testing.T) {
	want := normalizeCheck("state IN ('applying','applied','failed')", config.MySQL)
	for name, changed := range map[string]string{
		"changed literal":        "state IN ('applying','applied','removed')",
		"changed charset marker": "state IN (_latin1'applying',_latin1'applied',_latin1'failed')",
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
}

func mysqlCatalogTable(column columnShape) tableShape {
	return tableShape{
		name: "sample", columns: []columnShape{column},
		engine: "innodb", charset: "utf8mb4", collation: "utf8mb4_bin",
	}
}
