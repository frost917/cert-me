package operations

import (
	"context"
	"strings"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// QueryRepository is the non-locking, typed and permission-scoped read side.
type QueryRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

var _ port.QueryRepository = (*QueryRepository)(nil)

func (r *QueryRepository) validateScope(scope port.QueryScope) error {
	seen := make(map[domain.AuthorityID]struct{}, len(scope.AuthorityIDs))
	for _, id := range scope.AuthorityIDs {
		parsed, err := domain.ParseAuthorityID(string(id))
		if err != nil {
			return err
		}
		if _, ok := seen[parsed]; ok {
			return domain.ErrInvalidValue
		}
		seen[parsed] = struct{}{}
	}
	return nil
}

func (r *QueryRepository) authorityScope(b *dialect.Builder, scope port.QueryScope, column string) string {
	if scope.Public {
		return "1 = 0"
	}
	if scope.All {
		return "1 = 1"
	}
	if len(scope.AuthorityIDs) == 0 {
		return "1 = 0"
	}
	parts := make([]string, 0, len(scope.AuthorityIDs))
	for _, id := range scope.AuthorityIDs {
		parts = append(parts, b.Add(string(id)))
	}
	return column + " IN (" + strings.Join(parts, ",") + ")"
}

func (r *QueryRepository) visible(scope port.QueryScope) bool { return scope.All && !scope.Public }

func (r *QueryRepository) contains(b *dialect.Builder, expression, value string) string {
	if value == "" {
		return ""
	}
	needle := b.Add(strings.ToLower(value))
	switch string(r.dialect.Kind()) {
	case "postgres":
		return "POSITION(" + needle + " IN LOWER(" + expression + ")) > 0"
	case "mysql", "mariadb":
		return "LOCATE(" + needle + ", LOWER(" + expression + ")) > 0"
	default:
		return "INSTR(LOWER(" + expression + "), " + needle + ") > 0"
	}
}

func pageSize(page contract.PageRequest) int {
	if page.Limit == 0 {
		return 50
	}
	return page.Limit
}

func addPageClause(b *dialect.Builder, conditions *[]string, idColumn string, page contract.PageRequest) (int, string) {
	limit := pageSize(page)
	if page.Cursor != "" {
		*conditions = append(*conditions, idColumn+" > "+b.Add(page.Cursor))
	}
	return limit, " ORDER BY " + idColumn + " LIMIT " + b.Add(limit+1)
}

func (r *QueryRepository) selectIDs(ctx context.Context, query string, args []any, limit int) ([]string, *string, error) {
	rows, err := r.executor.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, failed("select query ids", err)
	}
	defer rows.Close()
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, nil, failed("read query id", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, failed("iterate query ids", err)
	}
	var next *string
	if len(ids) > limit {
		cursor := ids[limit-1]
		next = &cursor
		ids = ids[:limit]
	}
	return ids, next, nil
}

func appendCondition(conditions *[]string, condition string) {
	if condition != "" {
		*conditions = append(*conditions, condition)
	}
}
func joinConditions(conditions []string) string {
	if len(conditions) == 0 {
		return "1 = 1"
	}
	return strings.Join(conditions, " AND ")
}
func pageResult[T any](items []T, next *string) contract.Page[T] {
	return contract.Page[T]{Items: items, NextCursor: next}
}
