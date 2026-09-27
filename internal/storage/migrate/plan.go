package migrate

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"

	"cert-me/internal/config"
	"cert-me/internal/storage/migrations"
)

const targetVersion = 10

const auditScopeBackfillVersion = 8
const auditScopeRequiredVersion = 9

//go:embed reviewed_steps.json
var reviewedStepFS embed.FS

type reviewedStep = statementPart

type migrationFile struct {
	version  int
	name     string
	path     string
	checksum string
	data     []byte
	steps    []reviewedStep
}

type migrationPlan struct {
	kind  config.DatabaseKind
	files []migrationFile
	full  []schema
}

func loadPlan(kind config.DatabaseKind) (*migrationPlan, error) {
	dir, err := directoryFor(kind)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		SchemaVersion int               `json:"schema_version"`
		Files         map[string]string `json:"files"`
	}
	var reviewed struct {
		SchemaVersion int                 `json:"schema_version"`
		Steps         map[string][]string `json:"steps"`
	}
	raw, err := migrations.Files.ReadFile("manifest.json")
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.SchemaVersion != targetVersion {
		return nil, errors.New("invalid embedded migration manifest")
	}
	if len(manifest.Files) != 4*(targetVersion+1) {
		return nil, errors.New("embedded migration manifest does not match the reviewed version range")
	}
	stepData, err := reviewedStepFS.ReadFile("reviewed_steps.json")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(stepData, &reviewed); err != nil || reviewed.SchemaVersion != 1 || len(reviewed.Steps) != len(manifest.Files) {
		return nil, errors.New("invalid reviewed migration step manifest")
	}

	plan := &migrationPlan{kind: kind, files: make([]migrationFile, targetVersion+1), full: make([]schema, targetVersion+1)}
	var expected schema
	for version := 0; version <= targetVersion; version++ {
		prefix := fmt.Sprintf("internal/storage/migrations/%s/%03d_", dir, version)
		filePath := ""
		for candidate := range manifest.Files {
			if strings.HasPrefix(candidate, prefix) && strings.HasSuffix(candidate, ".sql") {
				if filePath != "" {
					return nil, errors.New("duplicate embedded migration version")
				}
				filePath = candidate
			}
		}
		if filePath == "" {
			return nil, errors.New("missing embedded migration version")
		}
		relative := strings.TrimPrefix(filePath, "internal/storage/migrations/")
		data, readErr := migrations.Files.ReadFile(relative)
		if readErr != nil {
			return nil, readErr
		}
		sum := sha256.Sum256(data)
		checksum := hex.EncodeToString(sum[:])
		if checksum != manifest.Files[filePath] {
			return nil, errors.New("embedded migration checksum mismatch")
		}
		statements, scanErr := splitReviewedStatements(data, version)
		if scanErr != nil || len(statements) == 0 {
			return nil, errors.New("invalid embedded migration statements")
		}
		reviewedChecksums, ok := reviewed.Steps[filePath]
		if !ok || len(reviewedChecksums) != len(statements) {
			return nil, errors.New("reviewed migration step count mismatch")
		}
		for index, statement := range statements {
			if statement.checksum != reviewedChecksums[index] {
				return nil, errors.New("reviewed migration step checksum mismatch")
			}
		}
		file := migrationFile{
			version: version, name: strings.TrimSuffix(path.Base(relative), ".sql"),
			path: relative, checksum: checksum, data: append([]byte(nil), data...),
		}
		for _, statement := range statements {
			before := cloneSchema(expected)
			next, applyErr := applyDDL(expected, statement.sql, kind)
			if applyErr != nil {
				return nil, fmt.Errorf("invalid reviewed migration plan: version %d step %d", version, statement.order)
			}
			expected = next
			statement.before = before
			statement.after = cloneSchema(expected)
			file.steps = append(file.steps, statement)
		}
		if version == auditScopeBackfillVersion {
			before := cloneSchema(expected)
			order := len(file.steps) + 1
			handler := auditScopeBackfillHandlerID
			file.steps = append(file.steps, statementPart{
				id:    fmt.Sprintf("%03d.%03d:%s", version, order, handler),
				order: order, start: len(data), end: len(data),
				checksum: handlerStepChecksum(handler), handler: handler,
				before: before, after: cloneSchema(expected),
			})
		}
		plan.files[version] = file
		plan.full[version] = cloneSchema(expected)
	}
	return plan, nil
}

func directoryFor(kind config.DatabaseKind) (string, error) {
	switch kind {
	case config.SQLite:
		return "sqlite", nil
	case config.Postgres:
		return "postgres", nil
	case config.MySQL:
		return "mysql", nil
	case config.MariaDB:
		return "mariadb", nil
	default:
		return "", errors.New("unsupported database kind")
	}
}

type statementPart struct {
	id                    string
	order                 int
	start                 int
	end                   int
	sql                   string
	checksum              string
	handler               string
	requiresEncryptionKey bool
	before                schema
	after                 schema
}

// splitReviewedStatements splits only at SQL lexical statement boundaries.
// The returned ranges are exact byte ranges in the embedded migration file.
func splitReviewedStatements(data []byte, version int) ([]statementPart, error) {
	const (
		normal = iota
		singleQuote
		doubleQuote
		backtick
		bracket
		lineComment
		blockComment
	)
	state := normal
	start, order := 0, 0
	hasSQL := false
	parts := make([]statementPart, 0, 8)
	appendPart := func(end int) {
		if !hasSQL {
			return
		}
		raw := string(data[start:end])
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		order++
		sum := sha256.Sum256(data[start:end])
		parts = append(parts, statementPart{
			id: fmt.Sprintf("%03d.%03d", version, order), order: order,
			start: start, end: end, sql: trimmed, checksum: hex.EncodeToString(sum[:]),
		})
	}
	for i := 0; i < len(data); i++ {
		ch := data[i]
		switch state {
		case normal:
			switch {
			case ch == '-' && i+1 < len(data) && data[i+1] == '-':
				state = lineComment
				i++
			case ch == '/' && i+1 < len(data) && data[i+1] == '*':
				state = blockComment
				i++
			case ch == '\'':
				hasSQL = true
				state = singleQuote
			case ch == '"':
				hasSQL = true
				state = doubleQuote
			case ch == '`':
				hasSQL = true
				state = backtick
			case ch == '[':
				hasSQL = true
				state = bracket
			case ch == ';':
				appendPart(i)
				start, hasSQL = i+1, false
			default:
				if ch > ' ' {
					hasSQL = true
				}
			}
		case singleQuote:
			if ch == '\\' && i+1 < len(data) {
				i++
			} else if ch == '\'' {
				if i+1 < len(data) && data[i+1] == '\'' {
					i++
				} else {
					state = normal
				}
			}
		case doubleQuote:
			if ch == '"' {
				if i+1 < len(data) && data[i+1] == '"' {
					i++
				} else {
					state = normal
				}
			}
		case backtick:
			if ch == '`' {
				if i+1 < len(data) && data[i+1] == '`' {
					i++
				} else {
					state = normal
				}
			}
		case bracket:
			if ch == ']' {
				state = normal
			}
		case lineComment:
			if ch == '\n' || ch == '\r' {
				state = normal
			}
		case blockComment:
			if ch == '*' && i+1 < len(data) && data[i+1] == '/' {
				state = normal
				i++
			}
		}
	}
	if state == singleQuote || state == doubleQuote || state == backtick || state == bracket || state == blockComment {
		return nil, errors.New("unterminated SQL token")
	}
	appendPart(len(data))
	return parts, nil
}
