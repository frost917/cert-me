// Package dialect contains small, deterministic SQL differences shared by
// repository adapters.
package dialect

import (
	"fmt"

	"cert-me/internal/config"
)

// Dialect describes placeholder syntax for one supported SQL driver.
// Identifiers remain compile-time constants in repository code; this type
// only builds value placeholders and arguments.
type Dialect struct {
	kind config.DatabaseKind
}

// New validates and returns a dialect for a supported database kind.
func New(kind config.DatabaseKind) (Dialect, error) {
	switch kind {
	case config.SQLite, config.Postgres, config.MySQL, config.MariaDB:
		return Dialect{kind: kind}, nil
	default:
		return Dialect{}, fmt.Errorf("unsupported SQL dialect %q", kind)
	}
}

// Kind returns the validated database kind.
func (d Dialect) Kind() config.DatabaseKind { return d.kind }

// IsSQLite reports whether d uses SQLite's database-level write reservation
// instead of row-level SELECT FOR UPDATE locking.
func (d Dialect) IsSQLite() bool { return d.kind == config.SQLite }

// RowLockClause returns the SQL suffix for locking a selected row. SQLite
// serializes writes through BEGIN IMMEDIATE and has no SELECT FOR UPDATE.
func (d Dialect) RowLockClause() string {
	if d.IsSQLite() {
		return ""
	}
	return " FOR UPDATE"
}

// Placeholder returns a one-based positional parameter marker. PostgreSQL
// uses numbered markers; SQLite, MySQL, and MariaDB use question marks.
func (d Dialect) Placeholder(index int) string {
	if index < 1 {
		panic("SQL placeholder index must be positive")
	}
	if d.kind == config.Postgres {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

// Builder assigns placeholders in the same order as its Args. Create one
// Builder per statement and append every bound value through Add.
type Builder struct {
	dialect Dialect
	args    []any
}

// NewBuilder creates an empty parameter builder for d.
func (d Dialect) NewBuilder() *Builder { return &Builder{dialect: d} }

// Add appends value and returns its SQL placeholder.
func (b *Builder) Add(value any) string {
	b.args = append(b.args, value)
	return b.dialect.Placeholder(len(b.args))
}

// Args returns a copy of the accumulated values for one SQL statement.
func (b *Builder) Args() []any { return append([]any(nil), b.args...) }
