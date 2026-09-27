package operations

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/dialect"
	"cert-me/internal/storage/sqlstore/pki"
)

func (r *QueryRepository) auditPredicate(b *dialect.Builder, filter contract.AuditFilter, scope port.QueryScope) string {
	conditions := make([]string, 0, 9)
	switch {
	case scope.Public:
		conditions = append(conditions, "1 = 0")
	case scope.All:
		conditions = append(conditions, "1 = 1")
	case len(scope.AuthorityIDs) == 0:
		conditions = append(conditions, "1 = 0")
	default:
		allowed := make([]string, 0, len(scope.AuthorityIDs))
		for _, id := range scope.AuthorityIDs {
			allowed = append(allowed, b.Add(string(id)))
		}
		// Installation-wide events are invisible to a CA-restricted scope.
		// Multi-scope records are visible only if every stored scope is allowed.
		conditions = append(conditions, "a.scope_kind = 'authorities' AND EXISTS (SELECT 1 FROM audit_event_scopes s WHERE s.event_id = a.id) AND NOT EXISTS (SELECT 1 FROM audit_event_scopes s WHERE s.event_id = a.id AND s.authority_id NOT IN ("+strings.Join(allowed, ",")+"))")
	}
	if filter.From != nil {
		conditions = append(conditions, "a.occurred_at >= "+b.Add(filter.From.UnixMicro()))
	}
	if filter.Until != nil {
		conditions = append(conditions, "a.occurred_at <= "+b.Add(filter.Until.UnixMicro()))
	}
	if filter.AccountID != nil {
		conditions = append(conditions, "a.actor_kind = 'account' AND a.actor_id = "+b.Add(string(*filter.AccountID)))
	}
	if filter.AuthorityID != nil {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM audit_event_scopes fs WHERE fs.event_id = a.id AND fs.authority_id = "+b.Add(string(*filter.AuthorityID))+")")
	}
	if filter.CertificateID != nil {
		conditions = append(conditions, "a.target_id = "+b.Add(string(*filter.CertificateID)))
	}
	if filter.Action != "" {
		conditions = append(conditions, "a.action = "+b.Add(filter.Action))
	}
	if filter.ClientIP != "" {
		conditions = append(conditions, "a.client_ip = "+b.Add(filter.ClientIP))
	}
	if filter.Result != nil {
		conditions = append(conditions, "a.result = "+b.Add(string(*filter.Result)))
	}
	return joinConditions(conditions)
}

func (r *QueryRepository) auditIDs(ctx context.Context, filter contract.AuditFilter, scope port.QueryScope, page *contract.PageRequest) ([]string, *string, error) {
	b := r.builder()
	conditions := []string{r.auditPredicate(b, filter, scope)}
	tail := " ORDER BY a.id"
	var limit int
	if page != nil {
		limit, tail = addPageClause(b, &conditions, "a.id", *page)
	}
	query := "SELECT a.id FROM audit_events a WHERE " + joinConditions(conditions) + tail
	if page == nil {
		rows, err := r.executor.QueryContext(ctx, query, b.Args()...)
		if err != nil {
			return nil, nil, failed("select audit export ids", err)
		}
		defer rows.Close()
		ids := make([]string, 0)
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, nil, failed("read audit export id", err)
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return nil, nil, failed("iterate audit export ids", err)
		}
		return ids, nil, nil
	}
	return r.selectIDs(ctx, query, b.Args(), limit)
}

func (r *QueryRepository) auditEvent(ctx context.Context, id string) (contract.AuditEventView, error) {
	b := r.builder()
	query := `SELECT id,occurred_at,actor_kind,actor_id,token_id,action,target_type,target_id,client_ip,result,details_json,scope_kind FROM audit_events WHERE id = ` + b.Add(id)
	var rawID, actorKind, action, targetType, result, details, scopeKind string
	var occurred int64
	var actorID, tokenID, targetID, clientIP sql.NullString
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawID, &occurred, &actorKind, &actorID, &tokenID, &action, &targetType, &targetID, &clientIP, &result, &details, &scopeKind); err != nil {
		return contract.AuditEventView{}, missing(err)
	}
	if _, err := domain.ParseJobID(rawID); err != nil {
		return contract.AuditEventView{}, err
	}
	view := contract.AuditEventView{ID: rawID, OccurredAt: domain.InstantFromUnixMicro(occurred), ActorKind: contract.AuditActorKind(actorKind), Action: action, TargetType: targetType, Result: contract.AuditResult(result)}
	if actorID.Valid {
		view.ActorID = actorID.String
	}
	if tokenID.Valid {
		view.TokenID = tokenID.String
	}
	if targetID.Valid {
		view.TargetID = targetID.String
	}
	if clientIP.Valid {
		view.ClientIP = clientIP.String
	}
	if view.OccurredAt.IsZero() {
		return contract.AuditEventView{}, fmt.Errorf("audit event has zero occurred_at")
	}
	switch view.ActorKind {
	case contract.AuditActorAccount, contract.AuditActorDownloadToken, contract.AuditActorCLI, contract.AuditActorSystem, contract.AuditActorAnonymous:
	default:
		return contract.AuditEventView{}, fmt.Errorf("invalid audit actor kind")
	}
	switch view.Result {
	case contract.AuditResultSuccess, contract.AuditResultFailure:
	default:
		return contract.AuditEventView{}, fmt.Errorf("invalid audit result")
	}
	detailsValue, err := decodeAuditDetails([]byte(details))
	if err != nil {
		return contract.AuditEventView{}, fmt.Errorf("decode audit details: %w", err)
	}
	view.Details = detailsValue
	b = r.builder()
	rows, err := r.executor.QueryContext(ctx, "SELECT authority_id FROM audit_event_scopes WHERE event_id = "+b.Add(rawID)+" ORDER BY authority_id", b.Args()...)
	if err != nil {
		return contract.AuditEventView{}, err
	}
	defer rows.Close()
	view.AuthorityIDs = make([]domain.AuthorityID, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return contract.AuditEventView{}, err
		}
		id, err := domain.ParseAuthorityID(raw)
		if err != nil {
			return contract.AuditEventView{}, err
		}
		view.AuthorityIDs = append(view.AuthorityIDs, id)
	}
	if err := rows.Err(); err != nil {
		return contract.AuditEventView{}, err
	}
	switch scopeKind {
	case string(port.AuditScopeInstallation):
		if len(view.AuthorityIDs) != 0 {
			return contract.AuditEventView{}, fmt.Errorf("installation audit event has authority scopes")
		}
	case string(port.AuditScopeAuthorities):
		if len(view.AuthorityIDs) == 0 {
			return contract.AuditEventView{}, fmt.Errorf("authority audit event has no authority scopes")
		}
	default:
		return contract.AuditEventView{}, fmt.Errorf("invalid audit scope kind")
	}
	return cloneAuditView(view), nil
}

func (r *QueryRepository) ListAudit(ctx context.Context, query contract.AuditListQuery, scope port.QueryScope) (contract.Page[contract.AuditEventView], error) {
	if err := checkContext(ctx); err != nil {
		return contract.Page[contract.AuditEventView]{}, err
	}
	if err := query.Validate(); err != nil {
		return contract.Page[contract.AuditEventView]{}, failed("validate audit list", err)
	}
	if err := r.validateScope(scope); err != nil {
		return contract.Page[contract.AuditEventView]{}, failed("validate audit scope", err)
	}
	ids, next, err := r.auditIDs(ctx, query.Filter, scope, &query.Page)
	if err != nil {
		return contract.Page[contract.AuditEventView]{}, err
	}
	items := make([]contract.AuditEventView, 0, len(ids))
	for _, id := range ids {
		event, e := r.auditEvent(ctx, id)
		if e != nil {
			return contract.Page[contract.AuditEventView]{}, failed("read audit event", e)
		}
		items = append(items, event)
	}
	return pageResult(items, next), nil
}

func (r *QueryRepository) IterateAudit(ctx context.Context, query contract.AuditExportQuery, scope port.QueryScope) (contract.AuditEventIterator, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := query.Validate(); err != nil {
		return nil, failed("validate audit export", err)
	}
	if err := r.validateScope(scope); err != nil {
		return nil, failed("validate audit scope", err)
	}
	ids, _, err := r.auditIDs(ctx, query.Filter, scope, nil)
	if err != nil {
		return nil, err
	}
	return &auditSQLIterator{repo: r, ctx: ctx, ids: append([]string(nil), ids...)}, nil
}

type auditSQLIterator struct {
	repo   *QueryRepository
	ctx    context.Context
	ids    []string
	index  int
	event  contract.AuditEventView
	err    error
	closed bool
}

func (it *auditSQLIterator) Next(ctxDone <-chan struct{}) bool {
	if it.closed || it.err != nil {
		return false
	}
	select {
	case <-ctxDone:
		return false
	default:
	}
	if it.ctx != nil {
		if err := it.ctx.Err(); err != nil {
			it.err = err
			return false
		}
	}
	if it.index >= len(it.ids) {
		return false
	}
	event, err := it.repo.auditEvent(it.ctx, it.ids[it.index])
	if err != nil {
		it.err = err
		return false
	}
	it.event = cloneAuditView(event)
	it.index++
	return true
}
func (it *auditSQLIterator) Event() contract.AuditEventView { return cloneAuditView(it.event) }
func (it *auditSQLIterator) Err() error                     { return it.err }
func (it *auditSQLIterator) Close() error {
	it.closed = true
	it.ids = nil
	it.event = contract.AuditEventView{}
	return nil
}

func cloneAuditView(in contract.AuditEventView) contract.AuditEventView {
	out := in
	out.AuthorityIDs = append([]domain.AuthorityID(nil), in.AuthorityIDs...)
	out.Details.Fields = cloneStringMap(in.Details.Fields)
	return out
}

func (r *QueryRepository) GetCRLStatus(ctx context.Context, id domain.CAKeyGenerationID, scope port.QueryScope) (domain.CRLState, error) {
	if err := checkContext(ctx); err != nil {
		return domain.CRLState{}, err
	}
	if err := r.validateScope(scope); err != nil {
		return domain.CRLState{}, failed("validate CRL scope", err)
	}
	b := r.builder()
	var exists bool
	query := "SELECT EXISTS (SELECT 1 FROM crl_states s JOIN ca_key_generations cg ON cg.id = s.ca_key_generation_id WHERE s.ca_key_generation_id = " + b.Add(string(id)) + " AND " + r.authorityScope(b, scope, "cg.authority_id") + ")"
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&exists); err != nil {
		return domain.CRLState{}, failed("check CRL status scope", err)
	}
	if !exists {
		return domain.CRLState{}, port.ErrNotFound
	}
	b = r.builder()
	query = `SELECT s.ca_key_generation_id,s.max_reserved_number_hex,s.revocation_generation,s.published_crl_id,s.next_publish_at,s.publication_state,s.signing_ca_certificate_id,s.version FROM crl_states s WHERE s.ca_key_generation_id = ` + b.Add(string(id))
	var rawID, maxHex, state string
	var revGeneration, version int64
	var published, signing sql.NullString
	var next sql.NullInt64
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawID, &maxHex, &revGeneration, &published, &next, &state, &signing, &version); err != nil {
		return domain.CRLState{}, failed("read CRL status", missing(err))
	}
	parsedID, err := domain.ParseCAKeyGenerationID(rawID)
	if err != nil {
		return domain.CRLState{}, failed("decode CRL status", err)
	}
	maxNumber, err := domain.ParseCRLNumber(maxHex)
	if err != nil {
		return domain.CRLState{}, failed("decode CRL status", err)
	}
	var publishedID domain.CRLDocumentID
	var publishedNumber domain.CRLNumber
	var publishedGeneration int64
	if published.Valid {
		publishedID, err = domain.ParseCRLDocumentID(published.String)
		if err != nil {
			return domain.CRLState{}, failed("decode CRL status", err)
		}
		b = r.builder()
		var docCA, origin string
		var covered sql.NullInt64
		var numberHex sql.NullString
		err = r.queryRow(ctx, "SELECT ca_key_generation_id,number_hex,covered_generation,origin FROM crl_documents WHERE id = "+b.Add(published.String), b.Args()...).Scan(&docCA, &numberHex, &covered, &origin)
		if err != nil {
			return domain.CRLState{}, failed("read published CRL status", missing(err))
		}
		if docCA != rawID || origin != "generated" || !numberHex.Valid || !covered.Valid {
			return domain.CRLState{}, failed("decode published CRL status", fmt.Errorf("published CRL document is inconsistent"))
		}
		publishedNumber, err = domain.ParseCRLNumber(numberHex.String)
		if err != nil {
			return domain.CRLState{}, failed("decode published CRL status", err)
		}
		publishedGeneration = covered.Int64
	}
	var signingID domain.CertificateID
	if signing.Valid {
		signingID, err = domain.ParseCertificateID(signing.String)
		if err != nil {
			return domain.CRLState{}, failed("decode CRL status", err)
		}
	}
	if revGeneration < 0 || version < 0 {
		return domain.CRLState{}, failed("decode CRL status", fmt.Errorf("negative CRL counter"))
	}
	facts := domain.CRLStateFacts{CAKeyGenerationID: parsedID, MaxReservedNumber: maxNumber, RevocationGeneration: revGeneration, PublishedDocumentID: publishedID, PublishedNumber: publishedNumber, PublishedGeneration: publishedGeneration, PublicationState: domain.PublicationState(state), SigningCACertificateID: signingID, Version: domain.Version(version)}
	if next.Valid {
		facts.NextPublishAt = domain.InstantFromUnixMicro(next.Int64)
	}
	value, err := domain.NewCRLState(facts)
	if err != nil {
		return domain.CRLState{}, failed("decode CRL status", err)
	}
	if maxNumber.Compare(publishedNumber) < 0 || publishedGeneration > revGeneration {
		return domain.CRLState{}, failed("decode CRL status", fmt.Errorf("published CRL is ahead of current state"))
	}
	return value, nil
}

func (r *QueryRepository) ReadPublicCA(ctx context.Context, authorityID domain.AuthorityID, scope port.QueryScope) (domain.Certificate, error) {
	if err := checkContext(ctx); err != nil {
		return domain.Certificate{}, err
	}
	if err := r.validateScope(scope); err != nil {
		return domain.Certificate{}, failed("validate public CA scope", err)
	}
	if !scope.Public && !scope.All {
		allowed := false
		for _, id := range scope.AuthorityIDs {
			if id == authorityID {
				allowed = true
				break
			}
		}
		if !allowed {
			return domain.Certificate{}, port.ErrNotFound
		}
	}
	b := r.builder()
	var raw sql.NullString
	query := "SELECT issuance_certificate_id FROM authorities WHERE id = " + b.Add(string(authorityID))
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&raw); err != nil {
		return domain.Certificate{}, failed("read public CA authority", missing(err))
	}
	if !raw.Valid {
		return domain.Certificate{}, port.ErrNotFound
	}
	certificateID, err := domain.ParseCertificateID(raw.String)
	if err != nil {
		return domain.Certificate{}, failed("decode public CA id", err)
	}
	certificate, err := pki.New(r.executor, r.dialect).GetCertificate(ctx, certificateID)
	if err != nil {
		return domain.Certificate{}, failed("read public CA certificate", err)
	}
	if certificate.Kind() != domain.CertificateKindCA {
		return domain.Certificate{}, failed("read public CA certificate", fmt.Errorf("authority issuance certificate is not a CA certificate"))
	}
	return certificate, nil
}
