package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"cert-me/internal/config"
)

type catalogQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

var ErrCatalogUnrecognized = errors.New("unrecognized physical schema catalog")

func catalogFailure(err error) error {
	if errors.Is(err, ErrCatalogUnrecognized) {
		return migrationError(StateIncompatible, "migration_incompatible", ErrIncompatible)
	}
	return migrationError(StateUnavailable, "migration_catalog_unavailable", err)
}

func unrecognizedCatalog(reason string) error {
	return fmt.Errorf("%w: %s", ErrCatalogUnrecognized, reason)
}

func readCatalog(ctx context.Context, conn catalogQueryer, kind config.DatabaseKind) (schema, error) {
	switch kind {
	case config.SQLite:
		return readSQLiteCatalog(ctx, conn)
	case config.Postgres:
		return readPostgresCatalog(ctx, conn)
	case config.MySQL, config.MariaDB:
		return readMySQLCatalog(ctx, conn)
	default:
		return schema{}, errors.New("unsupported database kind")
	}
}

func readSQLiteCatalog(ctx context.Context, conn catalogQueryer) (schema, error) {
	actual := emptySchema()
	type definition struct {
		typ  string
		name string
		sql  sql.NullString
	}
	var definitions []definition
	rows, err := conn.QueryContext(ctx, `SELECT type, name, sql FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		return schema{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item definition
		if err := rows.Scan(&item.typ, &item.name, &item.sql); err != nil {
			return schema{}, err
		}
		definitions = append(definitions, item)
	}
	if err := rows.Err(); err != nil {
		return schema{}, err
	}
	rows.Close()
	for _, item := range definitions {
		switch item.typ {
		case "table":
			if !item.sql.Valid {
				return schema{}, unrecognizedCatalog("table definition is unavailable")
			}
			tokens, err := lexSQL(item.sql.String)
			if err != nil {
				return schema{}, unrecognizedCatalog("table definition cannot be parsed")
			}
			table, err := parseCreateTable(tokens, "sqlite")
			if err != nil || table.name != strings.ToLower(item.name) {
				return schema{}, unrecognizedCatalog("table structure is outside the reviewed catalog")
			}
			actual.tables[table.name] = table
		case "index":
			// Index shape is read from PRAGMA below, which includes indexes
			// backing primary and unique constraints.
		default:
			actual.unknown = append(actual.unknown, strings.ToLower(item.typ)+":"+strings.ToLower(item.name))
		}
	}
	for tableName := range actual.tables {
		quotedTable := `"` + strings.ReplaceAll(tableName, `"`, `""`) + `"`
		indexRows, err := conn.QueryContext(ctx, "PRAGMA index_list("+quotedTable+")")
		if err != nil {
			return schema{}, err
		}
		type indexMeta struct {
			name    string
			unique  bool
			partial bool
		}
		var indexes []indexMeta
		for indexRows.Next() {
			var sequence, unique, partial int
			var name, origin string
			if err := indexRows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
				indexRows.Close()
				return schema{}, err
			}
			indexes = append(indexes, indexMeta{name: name, unique: unique != 0, partial: partial != 0})
		}
		if err := indexRows.Err(); err != nil {
			indexRows.Close()
			return schema{}, err
		}
		indexRows.Close()
		for _, metadata := range indexes {
			quotedIndex := `"` + strings.ReplaceAll(metadata.name, `"`, `""`) + `"`
			columnsRows, err := conn.QueryContext(ctx, "PRAGMA index_xinfo("+quotedIndex+")")
			if err != nil {
				return schema{}, err
			}
			index := indexShape{name: strings.ToLower(metadata.name), table: tableName, unique: metadata.unique, partial: metadata.partial}
			for columnsRows.Next() {
				var sequence, columnID, descending, key int
				var column, collation sql.NullString
				if err := columnsRows.Scan(&sequence, &columnID, &column, &descending, &collation, &key); err != nil {
					columnsRows.Close()
					return schema{}, err
				}
				if key == 0 {
					continue
				}
				if sequence != len(index.columns) {
					columnsRows.Close()
					return schema{}, unrecognizedCatalog("invalid index key sequence")
				}
				if !column.Valid {
					if metadata.unique {
						columnsRows.Close()
						return schema{}, unrecognizedCatalog("unique expression index is outside the reviewed catalog")
					}
					index.columns = append(index.columns, "<expression>")
				} else {
					index.columns = append(index.columns, strings.ToLower(column.String))
				}
				order := "asc"
				if descending != 0 {
					order = "desc"
				}
				index.orders = append(index.orders, order)
				if collation.Valid {
					index.collations = append(index.collations, strings.ToLower(collation.String))
				} else {
					index.collations = append(index.collations, "")
				}
			}
			if err := columnsRows.Err(); err != nil {
				columnsRows.Close()
				return schema{}, err
			}
			columnsRows.Close()
			actual.indexes[tableName+"\x00"+index.name] = index
		}
	}
	return actual, nil
}

func readPostgresCatalog(ctx context.Context, conn catalogQueryer) (schema, error) {
	actual := emptySchema()
	rows, err := conn.QueryContext(ctx, `SELECT table_name, table_type FROM information_schema.tables
		WHERE table_schema = 'public' ORDER BY table_name`)
	if err != nil {
		return schema{}, err
	}
	for rows.Next() {
		var name, tableType string
		if err := rows.Scan(&name, &tableType); err != nil {
			rows.Close()
			return schema{}, err
		}
		if tableType != "BASE TABLE" {
			actual.unknown = append(actual.unknown, "view:"+strings.ToLower(name))
			continue
		}
		actual.tables[strings.ToLower(name)] = tableShape{name: strings.ToLower(name)}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return schema{}, err
	}
	rows.Close()

	rows, err = conn.QueryContext(ctx, `SELECT table_name, column_name, data_type,
		character_maximum_length, is_nullable, column_default, ordinal_position, collation_name
		FROM information_schema.columns WHERE table_schema = 'public'
		ORDER BY table_name, ordinal_position`)
	if err != nil {
		return schema{}, err
	}
	for rows.Next() {
		var tableName, columnName, dataType, nullable string
		var length sql.NullInt64
		var defaultValue, collation sql.NullString
		var ordinal int
		if err := rows.Scan(&tableName, &columnName, &dataType, &length, &nullable, &defaultValue, &ordinal, &collation); err != nil {
			rows.Close()
			return schema{}, err
		}
		table, ok := actual.tables[strings.ToLower(tableName)]
		if !ok || ordinal != len(table.columns)+1 {
			rows.Close()
			return schema{}, unrecognizedCatalog("invalid PostgreSQL column order")
		}
		column := columnShape{name: strings.ToLower(columnName), typeName: canonicalType(dataType, string(config.Postgres)), nullable: nullable == "YES"}
		if length.Valid && column.typeName == "varchar" {
			column.length = fmt.Sprint(length.Int64)
		}
		if defaultValue.Valid {
			column.defaultSQL = normalizeCatalogExpression(defaultValue.String)
		}
		if collation.Valid {
			column.collation = collation.String
		} else if column.typeName == "varchar" || column.typeName == "text" {
			column.collation = "default"
		}
		if column.typeName == "" {
			rows.Close()
			return schema{}, unrecognizedCatalog("unknown PostgreSQL column type")
		}
		table.columns = append(table.columns, column)
		actual.tables[table.name] = table
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return schema{}, err
	}
	rows.Close()

	if err := readPostgresConstraints(ctx, conn, &actual); err != nil {
		return schema{}, err
	}
	if err := readPostgresIndexes(ctx, conn, &actual); err != nil {
		return schema{}, err
	}
	return actual, nil
}

func readPostgresConstraints(ctx context.Context, conn catalogQueryer, actual *schema) error {
	rows, err := conn.QueryContext(ctx, `SELECT tc.table_name, tc.constraint_name, tc.constraint_type,
		kcu.column_name, kcu.ordinal_position, kcu.referenced_table_name, kcu.referenced_column_name,
		rc.delete_rule, rc.update_rule, cc.check_clause
		FROM information_schema.table_constraints tc
		LEFT JOIN information_schema.key_column_usage kcu
		  ON kcu.constraint_catalog = tc.constraint_catalog AND kcu.constraint_schema = tc.constraint_schema
		 AND kcu.constraint_name = tc.constraint_name AND kcu.table_name = tc.table_name
		LEFT JOIN information_schema.referential_constraints rc
		  ON rc.constraint_catalog = tc.constraint_catalog AND rc.constraint_schema = tc.constraint_schema
		 AND rc.constraint_name = tc.constraint_name
		LEFT JOIN information_schema.check_constraints cc
		  ON cc.constraint_catalog = tc.constraint_catalog AND cc.constraint_schema = tc.constraint_schema
		 AND cc.constraint_name = tc.constraint_name
		WHERE tc.table_schema = 'public' ORDER BY tc.table_name, tc.constraint_name, kcu.ordinal_position`)
	if err != nil {
		return err
	}
	defer rows.Close()
	indices := make(map[string]int)
	for rows.Next() {
		var tableName, constraintName, constraintType string
		var column, referenceTable, referenceColumn, deleteRule, updateRule, checkClause sql.NullString
		var ordinal sql.NullInt64
		if err := rows.Scan(&tableName, &constraintName, &constraintType, &column, &ordinal, &referenceTable, &referenceColumn, &deleteRule, &updateRule, &checkClause); err != nil {
			return err
		}
		tableName = strings.ToLower(tableName)
		table, ok := actual.tables[tableName]
		if !ok {
			return unrecognizedCatalog("constraint references an unknown table")
		}
		key := tableName + "\x00" + constraintName
		index, exists := indices[key]
		if !exists {
			constraint := constraintShape{kind: postgresConstraintKind(constraintType)}
			if constraint.kind == "" {
				return unrecognizedCatalog("unknown PostgreSQL constraint type")
			}
			if checkClause.Valid {
				constraint.expression = normalizeCatalogExpression(checkClause.String)
			}
			if referenceTable.Valid {
				constraint.reference = strings.ToLower(referenceTable.String)
			}
			if deleteRule.Valid {
				constraint.deleteRule = normalizeRule(deleteRule.String)
			}
			if updateRule.Valid {
				constraint.updateRule = normalizeRule(updateRule.String)
			}
			table.constraints = append(table.constraints, constraint)
			index = len(table.constraints) - 1
			indices[key] = index
		}
		constraint := table.constraints[index]
		if column.Valid {
			if ordinal.Valid && ordinal.Int64 != int64(len(constraint.columns)+1) {
				return unrecognizedCatalog("invalid PostgreSQL constraint column order")
			}
			constraint.columns = append(constraint.columns, strings.ToLower(column.String))
		}
		if referenceColumn.Valid {
			constraint.refColumns = append(constraint.refColumns, strings.ToLower(referenceColumn.String))
		}
		table.constraints[index] = constraint
		actual.tables[tableName] = table
	}
	return rows.Err()
}

func postgresConstraintKind(kind string) string {
	switch kind {
	case "PRIMARY KEY":
		return "primary"
	case "UNIQUE":
		return "unique"
	case "FOREIGN KEY":
		return "foreign"
	case "CHECK":
		return "check"
	default:
		return ""
	}
}

func readPostgresIndexes(ctx context.Context, conn catalogQueryer, actual *schema) error {
	rows, err := conn.QueryContext(ctx, `SELECT i.relname, t.relname, pg_get_indexdef(i.oid), x.indisunique
		FROM pg_class i JOIN pg_index x ON x.indexrelid = i.oid
		JOIN pg_class t ON t.oid = x.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE n.nspname = 'public' AND t.relkind = 'r' ORDER BY t.relname, i.relname`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, tableName, definition string
		var unique bool
		if err := rows.Scan(&name, &tableName, &definition, &unique); err != nil {
			return err
		}
		tokens, err := lexSQL(definition)
		if err != nil {
			if unique {
				return unrecognizedCatalog("unique index definition cannot be parsed")
			}
			actual.indexes[strings.ToLower(name)] = indexShape{
				name: strings.ToLower(name), table: strings.ToLower(tableName),
				columns: []string{"<expression>"}, orders: []string{"asc"}, collations: []string{""},
			}
			continue
		}
		index, err := parseCreateIndex(tokens)
		if err != nil {
			if unique {
				return unrecognizedCatalog("unique index definition is outside the reviewed catalog")
			}
			actual.indexes[strings.ToLower(name)] = indexShape{
				name: strings.ToLower(name), table: strings.ToLower(tableName),
				columns: []string{"<expression>"}, orders: []string{"asc"}, collations: []string{""},
			}
			continue
		}
		index.name = strings.ToLower(name)
		index.table = strings.ToLower(tableName)
		table, ok := actual.tables[index.table]
		if !ok {
			return unrecognizedCatalog("index references an unknown PostgreSQL table")
		}
		for i, columnName := range index.columns {
			column, found := findColumn(table, columnName)
			if !found {
				return unrecognizedCatalog("index references an unknown PostgreSQL column")
			}
			if index.collations[i] == "" {
				index.collations[i] = column.collation
			}
		}
		actual.indexes[index.name] = index
	}
	return rows.Err()
}

func readMySQLCatalog(ctx context.Context, conn catalogQueryer) (schema, error) {
	actual := emptySchema()
	rows, err := conn.QueryContext(ctx, `SELECT table_name, table_type, engine, table_collation
		FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name`)
	if err != nil {
		return schema{}, err
	}
	for rows.Next() {
		var name, tableType string
		var engine, collation sql.NullString
		if err := rows.Scan(&name, &tableType, &engine, &collation); err != nil {
			rows.Close()
			return schema{}, err
		}
		name = strings.ToLower(name)
		if tableType != "BASE TABLE" {
			actual.unknown = append(actual.unknown, "view:"+name)
			continue
		}
		table := tableShape{name: name, engine: strings.ToLower(engine.String), collation: strings.ToLower(collation.String)}
		if dot := strings.IndexByte(table.collation, '_'); dot > 0 {
			table.charset = table.collation[:dot]
		}
		actual.tables[name] = table
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return schema{}, err
	}
	rows.Close()

	rows, err = conn.QueryContext(ctx, `SELECT table_name, column_name, data_type, column_type,
		character_maximum_length, is_nullable, column_default, ordinal_position,
		character_set_name, collation_name
		FROM information_schema.columns WHERE table_schema = DATABASE()
		ORDER BY table_name, ordinal_position`)
	if err != nil {
		return schema{}, err
	}
	for rows.Next() {
		var tableName, columnName, dataType, columnType, nullable string
		var length sql.NullInt64
		var defaultValue, charset, collation sql.NullString
		var ordinal int
		if err := rows.Scan(&tableName, &columnName, &dataType, &columnType, &length, &nullable, &defaultValue, &ordinal, &charset, &collation); err != nil {
			rows.Close()
			return schema{}, err
		}
		tableName = strings.ToLower(tableName)
		table, ok := actual.tables[tableName]
		if !ok || ordinal != len(table.columns)+1 {
			rows.Close()
			return schema{}, unrecognizedCatalog("invalid MySQL column order")
		}
		canonical := canonicalType(dataType, "mysql")
		if strings.EqualFold(dataType, "tinyint") && strings.EqualFold(columnType, "tinyint(1)") {
			canonical = "boolean"
		}
		column := columnShape{name: strings.ToLower(columnName), typeName: canonical, nullable: nullable == "YES"}
		if length.Valid && canonical == "varchar" {
			column.length = fmt.Sprint(length.Int64)
		}
		if defaultValue.Valid {
			column.defaultSQL = normalizeCatalogExpression(defaultValue.String)
		}
		if charset.Valid {
			column.charset = strings.ToLower(charset.String)
		}
		if collation.Valid {
			column.collation = strings.ToLower(collation.String)
		}
		if strings.Contains(strings.ToLower(columnType), "unsigned") {
			column.typeName += " unsigned"
		}
		if column.typeName == "" {
			rows.Close()
			return schema{}, unrecognizedCatalog("unknown MySQL column type")
		}
		table.columns = append(table.columns, column)
		actual.tables[table.name] = table
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return schema{}, err
	}
	rows.Close()
	if err := readMySQLConstraints(ctx, conn, &actual); err != nil {
		return schema{}, err
	}
	if err := readMySQLIndexes(ctx, conn, &actual); err != nil {
		return schema{}, err
	}
	return actual, nil
}

func readMySQLConstraints(ctx context.Context, conn catalogQueryer, actual *schema) error {
	rows, err := conn.QueryContext(ctx, `SELECT tc.table_name, tc.constraint_name, tc.constraint_type,
		kcu.column_name, kcu.ordinal_position, kcu.referenced_table_name, kcu.referenced_column_name,
		rc.delete_rule, rc.update_rule, cc.check_clause
		FROM information_schema.table_constraints tc
	LEFT JOIN information_schema.key_column_usage kcu
	  ON kcu.constraint_schema=tc.constraint_schema AND kcu.constraint_name=tc.constraint_name AND kcu.table_name=tc.table_name
	LEFT JOIN information_schema.referential_constraints rc
	  ON rc.constraint_schema=tc.constraint_schema AND rc.constraint_name=tc.constraint_name AND rc.table_name=tc.table_name
	LEFT JOIN information_schema.check_constraints cc
	  ON cc.constraint_schema=tc.constraint_schema AND cc.constraint_name=tc.constraint_name
	WHERE tc.constraint_schema=DATABASE() ORDER BY tc.table_name, tc.constraint_name, kcu.ordinal_position`)
	if err != nil {
		return err
	}
	defer rows.Close()
	indices := make(map[string]int)
	for rows.Next() {
		var tableName, constraintName, constraintType string
		var column, referenceTable, referenceColumn, deleteRule, updateRule, checkClause sql.NullString
		var ordinal sql.NullInt64
		if err := rows.Scan(&tableName, &constraintName, &constraintType, &column, &ordinal, &referenceTable, &referenceColumn, &deleteRule, &updateRule, &checkClause); err != nil {
			return err
		}
		tableName = strings.ToLower(tableName)
		table, ok := actual.tables[tableName]
		if !ok {
			return unrecognizedCatalog("constraint references an unknown table")
		}
		key := tableName + "\x00" + constraintName
		index, exists := indices[key]
		if !exists {
			constraint := constraintShape{kind: mysqlConstraintKind(constraintType)}
			if constraint.kind == "" {
				return unrecognizedCatalog("unknown MySQL constraint type")
			}
			if checkClause.Valid {
				constraint.expression = normalizeCatalogExpression(checkClause.String)
			}
			if referenceTable.Valid {
				constraint.reference = strings.ToLower(referenceTable.String)
			}
			if deleteRule.Valid {
				constraint.deleteRule = normalizeRule(deleteRule.String)
			}
			if updateRule.Valid {
				constraint.updateRule = normalizeRule(updateRule.String)
			}
			table.constraints = append(table.constraints, constraint)
			index = len(table.constraints) - 1
			indices[key] = index
		}
		constraint := table.constraints[index]
		if column.Valid {
			if ordinal.Valid && ordinal.Int64 != int64(len(constraint.columns)+1) {
				return unrecognizedCatalog("invalid MySQL constraint column order")
			}
			constraint.columns = append(constraint.columns, strings.ToLower(column.String))
		}
		if referenceColumn.Valid {
			constraint.refColumns = append(constraint.refColumns, strings.ToLower(referenceColumn.String))
		}
		table.constraints[index] = constraint
		actual.tables[tableName] = table
	}
	return rows.Err()
}

func mysqlConstraintKind(kind string) string {
	switch kind {
	case "PRIMARY KEY":
		return "primary"
	case "UNIQUE":
		return "unique"
	case "FOREIGN KEY":
		return "foreign"
	case "CHECK":
		return "check"
	default:
		return ""
	}
}

func readMySQLIndexes(ctx context.Context, conn catalogQueryer, actual *schema) error {
	rows, err := conn.QueryContext(ctx, `SELECT table_name, index_name, non_unique, seq_in_index,
		column_name, collation FROM information_schema.statistics
		WHERE table_schema=DATABASE() ORDER BY table_name, index_name, seq_in_index`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tableName, name string
		var nonUnique, sequence int
		var column, sortDirection sql.NullString
		if err := rows.Scan(&tableName, &name, &nonUnique, &sequence, &column, &sortDirection); err != nil {
			return err
		}
		key := strings.ToLower(tableName) + "\x00" + strings.ToLower(name)
		index, exists := actual.indexes[key]
		if !exists {
			index = indexShape{name: strings.ToLower(name), table: strings.ToLower(tableName), unique: nonUnique == 0}
			actual.indexes[key] = index
		}
		if sequence != len(index.columns)+1 {
			return unrecognizedCatalog("invalid MySQL index column order")
		}
		if !column.Valid {
			if nonUnique == 0 {
				return unrecognizedCatalog("unique functional index is outside the reviewed catalog")
			}
			index.columns = append(index.columns, "<expression>")
			index.orders = append(index.orders, "asc")
			index.collations = append(index.collations, "")
			actual.indexes[key] = index
			continue
		}
		index.columns = append(index.columns, strings.ToLower(column.String))
		order := "asc"
		if sortDirection.Valid && strings.EqualFold(sortDirection.String, "D") {
			order = "desc"
		} else if sortDirection.Valid && !strings.EqualFold(sortDirection.String, "A") {
			return unrecognizedCatalog("unknown MySQL index ordering")
		}
		index.orders = append(index.orders, order)
		table, ok := actual.tables[index.table]
		if !ok {
			return unrecognizedCatalog("index references an unknown MySQL table")
		}
		columnShape, found := findColumn(table, strings.ToLower(column.String))
		if !found {
			return unrecognizedCatalog("index references an unknown MySQL column")
		}
		index.collations = append(index.collations, columnShape.collation)
		actual.indexes[key] = index
	}
	return rows.Err()
}

func normalizeRule(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func normalizeCatalogExpression(value string) string {
	tokens, err := lexSQL(value)
	if err != nil {
		return strings.ToLower(strings.Join(strings.Fields(value), " "))
	}
	return normalizeExpression(tokens)
}

func catalogMatches(actual, expected schema, kind config.DatabaseKind) bool {
	if len(actual.unknown) != 0 || len(actual.tables) != len(expected.tables) {
		return false
	}
	for name, want := range expected.tables {
		got, ok := actual.tables[name]
		if !ok || !sameTable(got, want, kind) {
			return false
		}
	}
	return matchIndexes(actual, expected, kind)
}

func sameTable(actual, expected tableShape, kind config.DatabaseKind) bool {
	if len(actual.columns) != len(expected.columns) || len(actual.constraints) != len(expected.constraints) {
		return false
	}
	if kind == config.MySQL || kind == config.MariaDB {
		if actual.engine != "innodb" || expected.engine != "innodb" || actual.charset != "utf8mb4" || actual.collation != "utf8mb4_bin" {
			return false
		}
	}
	for i, want := range expected.columns {
		got := actual.columns[i]
		if got.name != want.name || got.typeName != want.typeName || canonicalLength(got.length) != canonicalLength(want.length) || got.nullable != want.nullable || got.defaultSQL != want.defaultSQL {
			return false
		}
		if got.collation != want.collation {
			return false
		}
		if (kind == config.MySQL || kind == config.MariaDB) && got.charset != want.charset {
			return false
		}
	}
	wantConstraints := make([]string, 0, len(expected.constraints))
	gotConstraints := make([]string, 0, len(actual.constraints))
	for _, constraint := range expected.constraints {
		wantConstraints = append(wantConstraints, constraintKey(normalizeConstraint(constraint, kind)))
	}
	for _, constraint := range actual.constraints {
		gotConstraints = append(gotConstraints, constraintKey(normalizeConstraint(constraint, kind)))
	}
	sort.Strings(wantConstraints)
	sort.Strings(gotConstraints)
	for i := range wantConstraints {
		if wantConstraints[i] != gotConstraints[i] {
			return false
		}
	}
	return true
}

func normalizeConstraint(value constraintShape, kind config.DatabaseKind) constraintShape {
	value.deleteRule = normalizeRule(value.deleteRule)
	value.updateRule = normalizeRule(value.updateRule)
	if value.kind == "foreign" {
		if value.deleteRule == "restrict" {
			value.deleteRule = "no action"
		}
		if value.updateRule == "restrict" {
			value.updateRule = "no action"
		}
	}
	if value.kind == "check" {
		value.expression = normalizeCheck(value.expression, kind)
	}
	return value
}

func normalizeCheck(expression string, kind config.DatabaseKind) string {
	expression = normalizeCatalogExpression(expression)
	if kind != config.Postgres {
		return expression
	}
	// PostgreSQL's catalog adds semantically redundant casts to text/varchar
	// expressions. Removing only those documented implicit casts preserves the
	// expression operators, literals, and grouping for exact comparison.
	for _, suffix := range []string{"::text[]", "::charactervarying[]", "::text", "::charactervarying", "::varchar", "::bigint", "::integer", "::boolean"} {
		expression = strings.ReplaceAll(expression, suffix, "")
	}
	identifierParens := regexp.MustCompile(`\(([a-z_][a-z0-9_]*)\)`)
	for identifierParens.MatchString(expression) {
		expression = identifierParens.ReplaceAllString(expression, "$1")
	}
	numericParens := regexp.MustCompile(`\(([0-9]+)\)`)
	for numericParens.MatchString(expression) {
		expression = numericParens.ReplaceAllString(expression, "$1")
	}
	arrayMembership := regexp.MustCompile(`([a-z_][a-z0-9_]*)=any\(\(*array\[(.*?)\]\)*\)`)
	expression = arrayMembership.ReplaceAllString(expression, "${1}in(${2})")
	arrayNonMembership := regexp.MustCompile(`([a-z_][a-z0-9_]*)(?:<>|!=)all\(\(*array\[(.*?)\]\)*\)`)
	expression = arrayNonMembership.ReplaceAllString(expression, "${1}notin(${2})")
	return expression
}

func matchIndexes(actual, expected schema, kind config.DatabaseKind) bool {
	want := make(map[string]int)
	got := make(map[string]int)
	for _, table := range expected.tables {
		for _, constraint := range table.constraints {
			if constraint.kind == "primary" || constraint.kind == "unique" {
				if kind == config.SQLite && isSQLiteRowIDPrimary(table, constraint) {
					continue
				}
				orders := make([]string, len(constraint.columns))
				collations := make([]string, len(constraint.columns))
				for i, columnName := range constraint.columns {
					orders[i] = "asc"
					column, _ := findColumn(table, columnName)
					collations[i] = column.collation
					if kind == config.SQLite && collations[i] == "" {
						collations[i] = "binary"
					}
				}
				want[indexKey(table.name, true, false, constraint.columns, orders, collations)]++
			}
		}
	}
	for _, index := range expected.indexes {
		want[indexKey(index.table, index.unique, index.partial, index.columns, index.orders, index.collations)]++
	}
	for _, index := range actual.indexes {
		got[indexKey(index.table, index.unique, index.partial, index.columns, index.orders, index.collations)]++
	}
	for key, count := range want {
		if got[key] < count {
			return false
		}
	}
	for key, count := range got {
		if count <= want[key] {
			continue
		}
		if strings.HasPrefix(key, "0|") { // only non-unique helper indexes are tolerated
			continue
		}
		return false
	}
	return true
}

func indexKey(table string, unique, partial bool, columns, orders, collations []string) string {
	flag := "0"
	if unique {
		flag = "1"
	}
	partialFlag := "0"
	if partial {
		partialFlag = "1"
	}
	return flag + "|" + table + "|" + partialFlag + "|" + strings.Join(columns, ",") + "|" + strings.Join(orders, ",") + "|" + strings.Join(collations, ",")
}

func isSQLiteRowIDPrimary(table tableShape, constraint constraintShape) bool {
	if constraint.kind != "primary" || len(constraint.columns) != 1 {
		return false
	}
	column, ok := findColumn(table, constraint.columns[0])
	return ok && column.typeName == "integer" && column.length == ""
}

func foreignKeyCheckOK(ctx context.Context, conn catalogQueryer, kind config.DatabaseKind) (bool, error) {
	if kind != config.SQLite {
		return true, nil
	}
	rows, err := conn.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	if rows.Next() {
		return false, nil
	}
	return rows.Err() == nil, rows.Err()
}
