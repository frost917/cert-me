package migrate

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"cert-me/internal/config"
)

type columnShape struct {
	name       string
	typeName   string
	length     string
	nullable   bool
	defaultSQL string
	charset    string
	collation  string
}

type constraintShape struct {
	kind       string
	columns    []string
	reference  string
	refColumns []string
	deleteRule string
	updateRule string
	expression string
}

type tableShape struct {
	name        string
	columns     []columnShape
	constraints []constraintShape
	engine      string
	charset     string
	collation   string
}

type indexShape struct {
	name       string
	table      string
	unique     bool
	partial    bool
	columns    []string
	orders     []string
	collations []string
}

type schema struct {
	tables  map[string]tableShape
	indexes map[string]indexShape
	unknown []string
}

func emptySchema() schema {
	return schema{tables: make(map[string]tableShape), indexes: make(map[string]indexShape)}
}

func cloneSchema(input schema) schema {
	copy := emptySchema()
	for key, table := range input.tables {
		table.columns = append([]columnShape(nil), table.columns...)
		table.constraints = cloneConstraints(table.constraints)
		copy.tables[key] = table
	}
	for key, index := range input.indexes {
		index.columns = append([]string(nil), index.columns...)
		index.orders = append([]string(nil), index.orders...)
		index.collations = append([]string(nil), index.collations...)
		copy.indexes[key] = index
	}
	copy.unknown = append([]string(nil), input.unknown...)
	return copy
}

func cloneConstraints(input []constraintShape) []constraintShape {
	output := make([]constraintShape, len(input))
	for i, constraint := range input {
		constraint.columns = append([]string(nil), constraint.columns...)
		constraint.refColumns = append([]string(nil), constraint.refColumns...)
		output[i] = constraint
	}
	return output
}

type sqlToken struct {
	text string
	kind byte
}

func lexSQL(input string) ([]sqlToken, error) {
	var tokens []sqlToken
	for i := 0; i < len(input); {
		ch := input[i]
		if ch <= ' ' {
			i++
			continue
		}
		if ch == '-' && i+1 < len(input) && input[i+1] == '-' {
			i += 2
			for i < len(input) && input[i] != '\n' && input[i] != '\r' {
				i++
			}
			continue
		}
		if ch == '/' && i+1 < len(input) && input[i+1] == '*' {
			i += 2
			found := false
			for i+1 < len(input) {
				if input[i] == '*' && input[i+1] == '/' {
					i += 2
					found = true
					break
				}
				i++
			}
			if !found {
				return nil, errors.New("unterminated SQL comment")
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			closing := ch
			kind := byte('i')
			if ch == '\'' {
				kind = 's'
			}
			var value strings.Builder
			i++
			closed := false
			for i < len(input) {
				if input[i] == closing {
					if i+1 < len(input) && input[i+1] == closing {
						value.WriteByte(closing)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				if kind == 's' && input[i] == '\\' && i+1 < len(input) {
					value.WriteByte(input[i+1])
					i += 2
					continue
				}
				value.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, errors.New("unterminated SQL quote")
			}
			tokens = append(tokens, sqlToken{text: value.String(), kind: kind})
			continue
		}
		if isWordByte(ch) {
			start := i
			for i < len(input) && isWordByte(input[i]) {
				i++
			}
			tokens = append(tokens, sqlToken{text: input[start:i], kind: 'w'})
			continue
		}
		if i+1 < len(input) && isPairOperator(input[i:i+2]) {
			tokens = append(tokens, sqlToken{text: input[i : i+2], kind: 'o'})
			i += 2
			continue
		}
		tokens = append(tokens, sqlToken{text: string(ch), kind: 'p'})
		i++
	}
	return tokens, nil
}

func isWordByte(ch byte) bool {
	return ch == '_' || ch == '$' || ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

func isPairOperator(value string) bool {
	switch value {
	case "<=", ">=", "<>", "!=", "||", "::":
		return true
	default:
		return false
	}
}

func applyDDL(current schema, statement string, kind config.DatabaseKind) (schema, error) {
	tokens, err := lexSQL(statement)
	if err != nil || len(tokens) == 0 {
		return current, errors.New("invalid SQL statement")
	}
	dialect := string(kind)
	next := cloneSchema(current)
	switch {
	case keyword(tokens, 0, "CREATE") && keyword(tokens, 1, "TABLE"):
		table, err := parseCreateTable(tokens, dialect)
		if err != nil {
			return current, err
		}
		if _, exists := next.tables[table.name]; exists {
			return current, fmt.Errorf("duplicate table")
		}
		next.tables[table.name] = table
	case keyword(tokens, 0, "CREATE") && (keyword(tokens, 1, "INDEX") || keyword(tokens, 1, "UNIQUE")):
		index, err := parseCreateIndex(tokens)
		if err != nil {
			return current, err
		}
		if _, exists := next.indexes[index.name]; exists {
			return current, errors.New("duplicate index")
		}
		table, ok := next.tables[index.table]
		if !ok {
			return current, errors.New("index target is not in reviewed plan")
		}
		if len(index.orders) != len(index.columns) {
			return current, errors.New("index order metadata is incomplete")
		}
		for i, columnName := range index.columns {
			column, found := findColumn(table, columnName)
			if !found {
				return current, errors.New("index refers to an unknown column")
			}
			if index.collations[i] == "" {
				index.collations[i] = column.collation
				if kind == config.SQLite && index.collations[i] == "" {
					index.collations[i] = "binary"
				}
			}
		}
		next.indexes[index.name] = index
	case keyword(tokens, 0, "ALTER") && keyword(tokens, 1, "TABLE"):
		tableName, nextPos := identifier(tokens, 2)
		if tableName == "" || nextPos >= len(tokens) {
			return current, errors.New("unsupported ALTER statement")
		}
		table, exists := next.tables[tableName]
		if !exists {
			return current, errors.New("ALTER target is not in reviewed plan")
		}
		switch {
		case keyword(tokens, nextPos, "ADD"):
			clauses := splitTopLevel(tokens[nextPos+1:], ",")
			for _, clause := range clauses {
				if keyword(clause, 0, "ADD") {
					clause = clause[1:]
				}
				if len(clause) == 0 {
					return current, errors.New("empty ALTER ADD clause")
				}
				if keyword(clause, 0, "COLUMN") {
					column, constraints, err := parseColumn(clause[1:], dialect)
					if err != nil {
						return current, err
					}
					if _, found := findColumn(table, column.name); found {
						return current, errors.New("duplicate column")
					}
					applyColumnDefaults(&table, &column, dialect)
					table.columns = append(table.columns, column)
					for _, constraint := range constraints {
						if addConstraint(&table, constraint) != nil {
							return current, errors.New("duplicate constraint")
						}
					}
					continue
				}
				if keyword(clause, 0, "CONSTRAINT") || keyword(clause, 0, "FOREIGN") || keyword(clause, 0, "CHECK") || keyword(clause, 0, "PRIMARY") || keyword(clause, 0, "UNIQUE") {
					constraint, err := parseTableConstraint(clause, dialect)
					if err != nil || addConstraint(&table, constraint) != nil {
						return current, errors.New("unsupported or duplicate ALTER constraint")
					}
					continue
				}
				return current, errors.New("unsupported ALTER ADD clause")
			}
		case keyword(tokens, nextPos, "ALTER"):
			pos := nextPos + 1
			if keyword(tokens, pos, "COLUMN") {
				pos++
			}
			columnName, afterName := identifier(tokens, pos)
			if columnName == "" || !keyword(tokens, afterName, "SET") || !keyword(tokens, afterName+1, "NOT") || !keyword(tokens, afterName+2, "NULL") || afterName+3 != len(tokens) {
				return current, errors.New("unsupported ALTER COLUMN clause")
			}
			found := false
			for i := range table.columns {
				if table.columns[i].name == columnName {
					table.columns[i].nullable = false
					found = true
					break
				}
			}
			if !found {
				return current, errors.New("ALTER COLUMN target is unknown")
			}
		case keyword(tokens, nextPos, "MODIFY"):
			pos := nextPos + 1
			if keyword(tokens, pos, "COLUMN") {
				pos++
			}
			column, _, err := parseColumn(tokens[pos:], dialect)
			if err != nil {
				return current, err
			}
			found := false
			for i := range table.columns {
				if table.columns[i].name == column.name {
					if column.charset == "" {
						column.charset = table.columns[i].charset
					}
					if column.collation == "" {
						column.collation = table.columns[i].collation
					}
					applyColumnDefaults(&table, &column, dialect)
					table.columns[i] = column
					found = true
					break
				}
			}
			if !found {
				return current, errors.New("MODIFY target is unknown")
			}
		default:
			return current, errors.New("unsupported ALTER action")
		}
		next.tables[tableName] = table
	default:
		return current, errors.New("unsupported migration statement")
	}
	return next, nil
}

func parseCreateTable(tokens []sqlToken, dialect string) (tableShape, error) {
	name, pos := identifier(tokens, 2)
	if name == "" || !tokenIs(tokens, pos, "(") {
		return tableShape{}, errors.New("malformed CREATE TABLE")
	}
	close := matchingParen(tokens, pos)
	if close < 0 {
		return tableShape{}, errors.New("malformed CREATE TABLE body")
	}
	table := tableShape{name: name}
	for _, part := range splitTopLevel(tokens[pos+1:close], ",") {
		if len(part) == 0 {
			return tableShape{}, errors.New("empty table definition")
		}
		if isConstraintStart(part) {
			constraint, err := parseTableConstraint(part, dialect)
			if err != nil {
				return tableShape{}, err
			}
			table.constraints = append(table.constraints, constraint)
			continue
		}
		column, constraints, err := parseColumn(part, dialect)
		if err != nil {
			return tableShape{}, err
		}
		table.columns = append(table.columns, column)
		table.constraints = append(table.constraints, constraints...)
	}
	if len(table.columns) == 0 {
		return tableShape{}, errors.New("table has no columns")
	}
	for i := close + 1; i < len(tokens); i++ {
		if keyword(tokens, i, "ENGINE") && tokenIs(tokens, i+1, "=") && i+2 < len(tokens) {
			table.engine = normalizeIdentifier(tokens[i+2])
		}
		if keyword(tokens, i, "CHARACTER") && keyword(tokens, i+1, "SET") {
			valuePos := i + 2
			if tokenIs(tokens, valuePos, "=") {
				valuePos++
			}
			if valuePos < len(tokens) {
				table.charset = normalizeIdentifier(tokens[valuePos])
			}
		}
		if keyword(tokens, i, "COLLATE") {
			valuePos := i + 1
			if tokenIs(tokens, valuePos, "=") {
				valuePos++
			}
			if valuePos < len(tokens) {
				table.collation = normalizeIdentifier(tokens[valuePos])
			}
		}
	}
	if dialect == "mysql" || dialect == "mariadb" {
		if table.engine == "" {
			return tableShape{}, errors.New("MySQL migration table has no engine")
		}
	}
	for i := range table.columns {
		applyColumnDefaults(&table, &table.columns[i], dialect)
	}
	return table, nil
}

func applyColumnDefaults(table *tableShape, column *columnShape, dialect string) {
	if dialect == "mysql" || dialect == "mariadb" {
		if (column.typeName == "varchar" || column.typeName == "text") && column.charset == "" {
			column.charset = table.charset
		}
		if (column.typeName == "varchar" || column.typeName == "text") && column.collation == "" {
			column.collation = table.collation
		}
	} else if dialect == "sqlite" {
		if (column.typeName == "text" || column.typeName == "varchar") && column.collation == "" {
			column.collation = "binary"
		}
	} else if dialect == "postgres" {
		if (column.typeName == "text" || column.typeName == "varchar") && column.collation == "" {
			column.collation = "default"
		}
	}
}

func parseColumn(tokens []sqlToken, dialect string) (columnShape, []constraintShape, error) {
	name, pos := identifier(tokens, 0)
	if name == "" || pos >= len(tokens) {
		return columnShape{}, nil, errors.New("malformed column")
	}
	column := columnShape{name: name, nullable: true}
	typeName := strings.ToLower(tokens[pos].text)
	if tokens[pos].kind == 's' || isPunctuation(tokens[pos].text) {
		return columnShape{}, nil, errors.New("malformed column type")
	}
	pos++
	if tokenIs(tokens, pos, "(") {
		end := matchingParen(tokens, pos)
		if end < 0 {
			return columnShape{}, nil, errors.New("malformed column type length")
		}
		var params []string
		for _, token := range tokens[pos+1 : end] {
			params = append(params, strings.ToLower(token.text))
		}
		column.length = strings.Join(params, "")
		pos = end + 1
	}
	if typeName == "double" && keyword(tokens, pos, "PRECISION") {
		typeName = "double precision"
		pos++
	}
	column.typeName = canonicalType(typeName, dialect)
	if column.typeName == "" {
		return columnShape{}, nil, errors.New("unsupported column type")
	}
	var constraints []constraintShape
	for ; pos < len(tokens); pos++ {
		switch {
		case keyword(tokens, pos, "NOT") && keyword(tokens, pos+1, "NULL"):
			column.nullable = false
			pos++
		case keyword(tokens, pos, "NULL"):
			column.nullable = true
		case keyword(tokens, pos, "DEFAULT"):
			start := pos + 1
			end := start
			depth := 0
			for end < len(tokens) {
				if depth == 0 && (keyword(tokens, end, "NOT") || keyword(tokens, end, "NULL") || keyword(tokens, end, "COLLATE") || keyword(tokens, end, "CHARACTER")) {
					break
				}
				if tokenIs(tokens, end, "(") {
					depth++
				} else if tokenIs(tokens, end, ")") {
					depth--
				}
				end++
			}
			column.defaultSQL = normalizeExpression(tokens[start:end])
			pos = end - 1
		case keyword(tokens, pos, "COLLATE") && pos+1 < len(tokens):
			column.collation = normalizeIdentifier(tokens[pos+1])
			pos++
		case keyword(tokens, pos, "CHARACTER") && keyword(tokens, pos+1, "SET") && pos+2 < len(tokens):
			column.charset = normalizeIdentifier(tokens[pos+2])
			pos += 2
		case keyword(tokens, pos, "CONSTRAINT") || keyword(tokens, pos, "CHECK"):
			end := len(tokens)
			if keyword(tokens, pos, "CHECK") {
				if !tokenIs(tokens, pos+1, "(") {
					return columnShape{}, nil, errors.New("malformed inline CHECK")
				}
				if close := matchingParen(tokens, pos+1); close >= 0 {
					end = close + 1
				}
			} else if !keyword(tokens, pos+2, "CHECK") || !tokenIs(tokens, pos+3, "(") {
				return columnShape{}, nil, errors.New("unsupported inline column constraint")
			} else if close := matchingParen(tokens, pos+3); close >= 0 {
				end = close + 1
			}
			constraint, err := parseTableConstraint(tokens[pos:end], dialect)
			if err != nil {
				return columnShape{}, nil, err
			}
			constraints = append(constraints, constraint)
			pos = end - 1
		case keyword(tokens, pos, "PRIMARY"), keyword(tokens, pos, "UNIQUE"), keyword(tokens, pos, "REFERENCES"):
			return columnShape{}, nil, errors.New("unsupported inline key constraint")
		}
	}
	return column, constraints, nil
}

func canonicalType(value, dialect string) string {
	switch strings.ToLower(value) {
	case "varchar", "character varying":
		return "varchar"
	case "text", "longtext":
		return "text"
	case "integer":
		return "integer"
	case "int":
		if dialect == "sqlite" {
			return "int"
		}
		return "integer"
	case "bigint":
		return "bigint"
	case "boolean", "bool":
		return "boolean"
	case "bytea", "blob", "longblob":
		return "binary"
	default:
		return ""
	}
}

func parseTableConstraint(tokens []sqlToken, dialect string) (constraintShape, error) {
	if len(tokens) == 0 {
		return constraintShape{}, errors.New("empty constraint")
	}
	pos := 0
	if keyword(tokens, pos, "CONSTRAINT") {
		pos += 2
	}
	switch {
	case keyword(tokens, pos, "PRIMARY") && keyword(tokens, pos+1, "KEY"):
		columns, _, err := parseColumnList(tokens, pos+2)
		return constraintShape{kind: "primary", columns: columns}, err
	case keyword(tokens, pos, "UNIQUE"):
		pos++
		if keyword(tokens, pos, "KEY") || keyword(tokens, pos, "INDEX") {
			pos++
			if !tokenIs(tokens, pos, "(") {
				pos++ // optional index name
			}
		}
		columns, _, err := parseColumnList(tokens, pos)
		return constraintShape{kind: "unique", columns: columns}, err
	case keyword(tokens, pos, "FOREIGN") && keyword(tokens, pos+1, "KEY"):
		columns, next, err := parseColumnList(tokens, pos+2)
		if err != nil || !keyword(tokens, next, "REFERENCES") {
			return constraintShape{}, errors.New("malformed foreign key")
		}
		reference, next := identifier(tokens, next+1)
		if reference == "" {
			return constraintShape{}, errors.New("malformed foreign key target")
		}
		refColumns, next, err := parseColumnList(tokens, next)
		if err != nil {
			return constraintShape{}, err
		}
		constraint := constraintShape{kind: "foreign", columns: columns, reference: reference, refColumns: refColumns, deleteRule: "no action", updateRule: "no action"}
		for i := next; i+1 < len(tokens); i++ {
			if keyword(tokens, i, "ON") && keyword(tokens, i+1, "DELETE") {
				constraint.deleteRule, i = parseReferentialAction(tokens, i+2)
			}
			if keyword(tokens, i, "ON") && keyword(tokens, i+1, "UPDATE") {
				constraint.updateRule, i = parseReferentialAction(tokens, i+2)
			}
		}
		return constraint, nil
	case keyword(tokens, pos, "CHECK"):
		if !tokenIs(tokens, pos+1, "(") {
			return constraintShape{}, errors.New("malformed CHECK")
		}
		end := matchingParen(tokens, pos+1)
		if end < 0 || end != len(tokens)-1 {
			return constraintShape{}, errors.New("malformed CHECK expression")
		}
		return constraintShape{kind: "check", expression: normalizeExpression(tokens[pos+2 : end])}, nil
	default:
		return constraintShape{}, fmt.Errorf("unsupported table constraint for %s", dialect)
	}
}

func addConstraint(table *tableShape, constraint constraintShape) error {
	for _, prior := range table.constraints {
		if sameConstraint(prior, constraint) {
			return errors.New("duplicate constraint")
		}
	}
	table.constraints = append(table.constraints, constraint)
	return nil
}

func parseReferentialAction(tokens []sqlToken, pos int) (string, int) {
	if keyword(tokens, pos, "NO") && keyword(tokens, pos+1, "ACTION") {
		return "no action", pos + 1
	}
	if keyword(tokens, pos, "SET") && (keyword(tokens, pos+1, "NULL") || keyword(tokens, pos+1, "DEFAULT")) {
		return "set " + strings.ToLower(tokens[pos+1].text), pos + 1
	}
	if keyword(tokens, pos, "CASCADE") {
		return "cascade", pos
	}
	if keyword(tokens, pos, "RESTRICT") {
		return "restrict", pos
	}
	return "no action", pos - 1
}

func parseColumnList(tokens []sqlToken, pos int) ([]string, int, error) {
	if !tokenIs(tokens, pos, "(") {
		return nil, pos, errors.New("missing column list")
	}
	end := matchingParen(tokens, pos)
	if end < 0 {
		return nil, pos, errors.New("unclosed column list")
	}
	var columns []string
	for _, part := range splitTopLevel(tokens[pos+1:end], ",") {
		name, next := identifier(part, 0)
		if name == "" || next != len(part) {
			return nil, pos, errors.New("unsupported index expression")
		}
		columns = append(columns, name)
	}
	return columns, end + 1, nil
}

func parseCreateIndex(tokens []sqlToken) (indexShape, error) {
	pos := 1
	index := indexShape{}
	if keyword(tokens, pos, "UNIQUE") {
		index.unique = true
		pos++
	}
	if !keyword(tokens, pos, "INDEX") {
		return indexShape{}, errors.New("malformed CREATE INDEX")
	}
	pos++
	if keyword(tokens, pos, "IF") {
		return indexShape{}, errors.New("conditional index DDL is not reviewed")
	}
	index.name, pos = identifier(tokens, pos)
	if index.name == "" || !keyword(tokens, pos, "ON") {
		return indexShape{}, errors.New("malformed CREATE INDEX target")
	}
	index.table, pos = identifier(tokens, pos+1)
	if index.table == "" {
		return indexShape{}, errors.New("malformed CREATE INDEX table")
	}
	if keyword(tokens, pos, "USING") {
		pos += 2 // access method, currently btree in the reviewed plan
	}
	columns, orders, collations, end, err := parseIndexKeys(tokens, pos)
	if err != nil || len(columns) == 0 {
		return indexShape{}, errors.New("malformed CREATE INDEX columns")
	}
	index.columns = columns
	index.orders = orders
	index.collations = collations
	if end != len(tokens) {
		return indexShape{}, errors.New("unsupported index options")
	}
	return index, nil
}

func parseIndexKeys(tokens []sqlToken, pos int) ([]string, []string, []string, int, error) {
	if !tokenIs(tokens, pos, "(") {
		return nil, nil, nil, pos, errors.New("missing index key list")
	}
	end := matchingParen(tokens, pos)
	if end < 0 {
		return nil, nil, nil, pos, errors.New("unclosed index key list")
	}
	var columns, orders, collations []string
	for _, part := range splitTopLevel(tokens[pos+1:end], ",") {
		name, next := identifier(part, 0)
		if name == "" {
			return nil, nil, nil, pos, errors.New("unsupported index expression")
		}
		order := "asc"
		collation := ""
		for next < len(part) {
			if keyword(part, next, "COLLATE") && next+1 < len(part) {
				collation, next = identifier(part, next+1)
				if collation == "" {
					return nil, nil, nil, pos, errors.New("invalid index collation")
				}
				continue
			}
			if keyword(part, next, "ASC") || keyword(part, next, "DESC") {
				order = strings.ToLower(part[next].text)
				next++
				continue
			}
			return nil, nil, nil, pos, errors.New("unsupported index key option")
		}
		columns = append(columns, name)
		orders = append(orders, order)
		collations = append(collations, collation)
	}
	return columns, orders, collations, end + 1, nil
}

func findColumn(table tableShape, name string) (columnShape, bool) {
	for _, column := range table.columns {
		if column.name == name {
			return column, true
		}
	}
	return columnShape{}, false
}

func isConstraintStart(tokens []sqlToken) bool {
	pos := 0
	if keyword(tokens, 0, "CONSTRAINT") {
		pos = 2
	}
	return keyword(tokens, pos, "PRIMARY") || keyword(tokens, pos, "UNIQUE") || keyword(tokens, pos, "FOREIGN") || keyword(tokens, pos, "CHECK")
}

func sameConstraint(a, b constraintShape) bool {
	return constraintKey(a) == constraintKey(b)
}

func constraintKey(value constraintShape) string {
	return strings.Join([]string{value.kind, strings.Join(value.columns, ","), value.reference, strings.Join(value.refColumns, ","), value.deleteRule, value.updateRule, value.expression}, "|")
}

func normalizeExpression(tokens []sqlToken) string {
	var output strings.Builder
	for _, token := range tokens {
		if token.kind == 'w' {
			output.WriteString(strings.ToLower(token.text))
		} else if token.kind == 'i' {
			output.WriteString(strings.ToLower(token.text))
		} else if token.kind == 's' {
			output.WriteByte('\'')
			output.WriteString(strings.ReplaceAll(token.text, "'", "''"))
			output.WriteByte('\'')
		} else {
			output.WriteString(token.text)
		}
	}
	return stripOuterParens(output.String())
}

func stripOuterParens(expression string) string {
	for strings.HasPrefix(expression, "(") && strings.HasSuffix(expression, ")") {
		depth := 0
		outer := true
		for i, ch := range expression {
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
				if depth == 0 && i != len(expression)-1 {
					outer = false
					break
				}
			}
		}
		if !outer {
			break
		}
		expression = expression[1 : len(expression)-1]
	}
	return expression
}

func splitTopLevel(tokens []sqlToken, delimiter string) [][]sqlToken {
	var output [][]sqlToken
	start, depth := 0, 0
	for i, token := range tokens {
		if token.text == "(" {
			depth++
		} else if token.text == ")" {
			depth--
		} else if token.text == delimiter && depth == 0 {
			output = append(output, tokens[start:i])
			start = i + 1
		}
	}
	if start < len(tokens) {
		output = append(output, tokens[start:])
	}
	return output
}

func matchingParen(tokens []sqlToken, open int) int {
	if open < 0 || open >= len(tokens) || tokens[open].text != "(" {
		return -1
	}
	depth := 0
	for i := open; i < len(tokens); i++ {
		if tokens[i].text == "(" {
			depth++
		} else if tokens[i].text == ")" {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func identifier(tokens []sqlToken, pos int) (string, int) {
	if pos < 0 || pos >= len(tokens) || tokens[pos].kind == 's' || isPunctuation(tokens[pos].text) {
		return "", pos
	}
	name := strings.ToLower(tokens[pos].text)
	pos++
	if tokenIs(tokens, pos, ".") {
		next, after := identifier(tokens, pos+1)
		if next == "" {
			return "", pos
		}
		return next, after
	}
	return name, pos
}

func normalizeIdentifier(token sqlToken) string {
	if token.kind == 'i' {
		return token.text
	}
	return strings.ToLower(token.text)
}

func keyword(tokens []sqlToken, pos int, word string) bool {
	return pos >= 0 && pos < len(tokens) && tokens[pos].kind != 's' && strings.EqualFold(tokens[pos].text, word)
}

func tokenIs(tokens []sqlToken, pos int, value string) bool {
	return pos >= 0 && pos < len(tokens) && tokens[pos].text == value
}

func isPunctuation(value string) bool {
	switch value {
	case "(", ")", "[", "]", ",", ".", "=", ";", "+", "-", "*", "/", "<", ">", "<=", ">=", "<>", "!=", "::":
		return true
	default:
		return false
	}
}

func canonicalLength(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	for i, part := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
		if err == nil {
			parts[i] = strconv.FormatUint(n, 10)
		}
	}
	return strings.Join(parts, ",")
}
