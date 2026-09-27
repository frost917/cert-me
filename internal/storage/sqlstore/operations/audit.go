package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// AuditRepository appends typed, explicitly scoped events and prunes only the
// event/scope rows selected by the retention batch.
type AuditRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

var _ port.AuditRepository = (*AuditRepository)(nil)

func (r *AuditRepository) Append(ctx context.Context, event port.AuditEvent, scope port.AuditScope) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := scope.Validate(); err != nil {
		return failed("validate audit scope", err)
	}
	if err := validateAuditEvent(event); err != nil {
		return failed("validate audit event", err)
	}
	for _, authorityID := range scope.AuthorityIDs() {
		if _, err := domain.ParseAuthorityID(string(authorityID)); err != nil {
			return failed("validate audit authority scope", err)
		}
	}
	details, err := encodeAuditDetails(event.Details)
	if err != nil {
		return failed("encode audit details", err)
	}
	b := r.builder()
	query := "INSERT INTO audit_events (id, created_at, occurred_at, actor_kind, actor_id, token_id, action, target_type, target_id, client_ip, result, details_json, scope_kind) VALUES (" +
		b.Add(event.ID) + "," + databaseNowMicros(r.dialect) + "," + b.Add(event.OccurredAt.UnixMicro()) + "," + b.Add(string(event.ActorKind)) + "," +
		b.Add(nullable(event.ActorID)) + "," + b.Add(nullable(event.TokenID)) + "," + b.Add(event.Action) + "," + b.Add(event.TargetType) + "," +
		b.Add(nullable(event.TargetID)) + "," + b.Add(nullable(event.ClientIP)) + "," + b.Add(string(event.Result)) + "," + b.Add(string(details)) + "," + b.Add(string(scope.Kind())) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrFailed("append audit event", err)
	}
	for _, authorityID := range scope.AuthorityIDs() {
		b = r.builder()
		query := "INSERT INTO audit_event_scopes (event_id, authority_id) VALUES (" + b.Add(event.ID) + "," + b.Add(string(authorityID)) + ")"
		if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
			return duplicateOrFailed("append audit scope", err)
		}
	}
	return nil
}

func (r *AuditRepository) DeleteBefore(ctx context.Context, cutoff domain.Instant, limit int) (int, error) {
	if err := checkContext(ctx); err != nil {
		return 0, err
	}
	if limit <= 0 {
		return 0, nil
	}
	if cutoff.IsZero() {
		return 0, failed("validate audit cutoff", domain.ErrInvalidValue)
	}
	b := r.builder()
	query := "SELECT id FROM audit_events WHERE occurred_at < " + b.Add(cutoff.UnixMicro()) + " ORDER BY occurred_at, id LIMIT " + b.Add(limit)
	rows, err := r.executor.QueryContext(ctx, query, b.Args()...)
	if err != nil {
		return 0, failed("select audit retention batch", err)
	}
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, failed("read audit retention batch", err)
		}
		if _, err := domain.ParseJobID(id); err != nil {
			_ = rows.Close()
			return 0, failed("decode audit retention id", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, failed("iterate audit retention batch", err)
	}
	if err := rows.Close(); err != nil {
		return 0, failed("close audit retention batch", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	deleteIDs := func(table, column string) error {
		b := r.builder()
		placeholders := make([]string, len(ids))
		for i, id := range ids {
			placeholders[i] = b.Add(id)
		}
		_, err := r.executor.ExecContext(ctx, "DELETE FROM "+table+" WHERE "+column+" IN ("+strings.Join(placeholders, ",")+")", b.Args()...)
		return err
	}
	if err := deleteIDs("audit_event_scopes", "event_id"); err != nil {
		return 0, failed("delete audit scopes", err)
	}
	if err := deleteIDs("audit_events", "id"); err != nil {
		return 0, failed("delete audit events", err)
	}
	return len(ids), nil
}

type auditDetailsJSON struct {
	SchemaVersion int               `json:"schema_version"`
	Fields        map[string]string `json:"fields"`
}

func encodeAuditDetails(details contract.AuditDetails) ([]byte, error) {
	if details.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported audit details schema version %d", details.SchemaVersion)
	}
	fields := make(map[string]string, len(details.Fields))
	for key, value := range details.Fields {
		if key == "" {
			return nil, domain.ErrInvalidValue
		}
		fields[key] = value
	}
	return json.Marshal(auditDetailsJSON{SchemaVersion: 1, Fields: fields})
}

func decodeAuditDetails(raw []byte) (contract.AuditDetails, error) {
	var stored auditDetailsJSON
	if err := decodeJSONStrict(raw, &stored); err != nil {
		return contract.AuditDetails{}, err
	}
	if stored.SchemaVersion != 1 || stored.Fields == nil {
		return contract.AuditDetails{}, fmt.Errorf("invalid audit details schema")
	}
	for key := range stored.Fields {
		if key == "" {
			return contract.AuditDetails{}, domain.ErrInvalidValue
		}
	}
	return contract.AuditDetails{SchemaVersion: stored.SchemaVersion, Fields: cloneStringMap(stored.Fields)}, nil
}

func validateAuditEvent(event port.AuditEvent) error {
	if _, err := domain.ParseJobID(event.ID); err != nil {
		return err
	}
	if event.OccurredAt.IsZero() || len(event.Action) == 0 || len(event.Action) > 64 || len(event.TargetType) == 0 || len(event.TargetType) > 64 || len(event.ActorID) > 36 || len(event.TokenID) > 36 || len(event.TargetID) > 36 || len(event.ClientIP) > 64 {
		return domain.ErrInvalidValue
	}
	switch event.ActorKind {
	case contract.AuditActorAccount:
		if _, err := domain.ParseAccountID(event.ActorID); err != nil {
			return err
		}
	case contract.AuditActorDownloadToken:
		if _, err := domain.ParseGrantID(event.ActorID); err != nil {
			return err
		}
	case contract.AuditActorCLI, contract.AuditActorSystem, contract.AuditActorAnonymous:
	default:
		return fmt.Errorf("unsupported audit actor kind %q", event.ActorKind)
	}
	if event.TokenID != "" {
		if _, err := domain.ParseGrantID(event.TokenID); err != nil {
			return err
		}
	}
	switch event.Result {
	case contract.AuditResultSuccess, contract.AuditResultFailure:
	default:
		return fmt.Errorf("unsupported audit result %q", event.Result)
	}
	return nil
}

func decodeJSONStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
