package pki

import (
	"context"
	"fmt"

	"cert-me/internal/domain"
)

func (r *Repository) ListAffectedDescendants(ctx context.Context, authorityID domain.AuthorityID) ([]domain.Authority, error) {
	b := r.builder()
	p := b.Add(string(authorityID))
	root := b.Add(string(authorityID))
	query := "WITH RECURSIVE descendants(id) AS (" +
		"SELECT id FROM authorities WHERE management_parent_id = " + p +
		" UNION SELECT a.id FROM authorities a JOIN descendants d ON a.management_parent_id = d.id" +
		") SELECT id FROM descendants WHERE id <> " + root + " ORDER BY id"
	rows, err := r.exec.QueryContext(ctx, query, b.Args()...)
	if err != nil {
		return nil, fmt.Errorf("pki: list authority descendants: %w", err)
	}
	ids := make([]domain.AuthorityID, 0)
	for rows.Next() {
		var rawID string
		if err := rows.Scan(&rawID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("pki: scan authority descendant: %w", err)
		}
		id, err := parseAuthorityID(rawID)
		if err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("pki: iterate authority descendants: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("pki: close authority descendants: %w", err)
	}
	authorities := make([]domain.Authority, 0, len(ids))
	for _, id := range ids {
		authority, err := r.loadAuthority(ctx, id, false)
		if err != nil {
			return nil, err
		}
		authorities = append(authorities, authority)
	}
	return authorities, nil
}
