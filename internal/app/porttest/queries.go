package porttest

import (
	"context"
	"sort"
	"strings"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// queryRepo is the in-memory port.QueryRepository: the non-locking, paged,
// permission-scoped read side QueryService is built against (see
// port/queries.go for why it is its own interface).
//
// Two properties this double must actually have, because the service tests
// assert on them rather than on a real SQL plan:
//
//   - Ordering is total and deterministic. Every list sorts by the entity's
//     own id, so a page boundary is reproducible and a cursor means exactly
//     "the last id already returned". A map-iteration order would make paged
//     tests flaky and would hide off-by-one cursor bugs.
//   - The scope filter is applied BEFORE paging, never after. Filtering a
//     fetched page would return short pages and a cursor that silently
//     skips rows -- the very defect port.QueryRepository's doc warns about.
type queryRepo struct{ s *state }

var _ port.QueryRepository = queryRepo{}

// ---- scope ----

// visible reports whether a row owned by authorityID is within scope.
func (r queryRepo) visible(scope port.QueryScope, authorityID domain.AuthorityID) bool {
	if scope.All {
		return true
	}
	for _, id := range scope.AuthorityIDs {
		if id == authorityID {
			return true
		}
	}
	return false
}

// visibleAll reports whether EVERY scope of a multi-scope row is within the
// reader's scope. §14.6 fixes this as the rule for audit events: "복수
// scope는 모든 관련 범위의 권한을 요구하므로". A row stored with no scopes
// at all is not visible to a narrowed reader, because an empty stored scope
// is a defect the same section forbids ("현재 MVP도 scope를 비워 저장하지
// 않는다") rather than a wildcard.
func (r queryRepo) visibleAll(scope port.QueryScope, authorityIDs []domain.AuthorityID) bool {
	if scope.All {
		return true
	}
	if len(authorityIDs) == 0 {
		return false
	}
	for _, id := range authorityIDs {
		if !r.visible(scope, id) {
			return false
		}
	}
	return true
}

// certificateAuthority resolves the management authority a certificate is
// scoped under, from stored subtype rows only: a leaf through its series'
// ManagementAuthorityID, a CA certificate through its key generation's
// AuthorityID. This is the management relation, never the historical
// issuance chain (§14.6 "관리 관계와 혼용하지 않는다"). A certificate with
// neither subtype row resolves to "" and is therefore invisible to any
// narrowed reader.
func (r queryRepo) certificateAuthority(id domain.CertificateID) domain.AuthorityID {
	if leaf, ok := r.s.leafCertRecords[id]; ok {
		if series, ok := r.s.series[leaf.SeriesID]; ok {
			return series.ManagementAuthorityID()
		}
		return ""
	}
	if ca, ok := r.s.caCertRecords[id]; ok {
		if gen, ok := r.s.caKeyGenerations[ca.CAKeyGenerationID]; ok {
			return gen.AuthorityID
		}
	}
	return ""
}

// issuerAuthority resolves the authority owning a CA key generation, which
// is how a revocation ledger row (keyed by issuer/serial) is scoped.
func (r queryRepo) issuerAuthority(issuer domain.CAKeyGenerationID) domain.AuthorityID {
	if gen, ok := r.s.caKeyGenerations[issuer]; ok {
		return gen.AuthorityID
	}
	return ""
}

// ---- paging ----

// paginate applies the cursor and limit to an already-sorted, already-
// filtered slice. keyOf must return the same total-ordering key the slice is
// sorted by. The cursor is that key, exclusive.
func paginate[T any](items []T, page contract.PageRequest, keyOf func(T) string) contract.Page[T] {
	limit := page.Limit
	if limit <= 0 {
		limit = 50
	}
	if page.Cursor != "" {
		cut := 0
		for cut < len(items) && keyOf(items[cut]) <= page.Cursor {
			cut++
		}
		items = items[cut:]
	}
	if len(items) > limit {
		items = items[:limit]
		last := keyOf(items[len(items)-1])
		out := make([]T, len(items))
		copy(out, items)
		return contract.Page[T]{Items: out, NextCursor: &last}
	}
	out := make([]T, len(items))
	copy(out, items)
	return contract.Page[T]{Items: out}
}

// matchesSearch is the substring match the OpenAPI `q` parameter describes.
// It is case-insensitive so a test's expectation does not depend on how a
// name happened to be capitalized.
func matchesSearch(search, value string) bool {
	if search == "" {
		return true
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(search))
}

// ---- authorities ----

func (r queryRepo) ListAuthorities(_ context.Context, query contract.AuthorityListQuery, scope port.QueryScope) (contract.Page[domain.Authority], error) {
	var items []domain.Authority
	for id, a := range r.s.authorities {
		if !r.visible(scope, id) || !matchesSearch(query.Search, a.Name()) {
			continue
		}
		items = append(items, a)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID() < items[j].ID() })
	return paginate(items, query.Page, func(a domain.Authority) string { return string(a.ID()) }), nil
}

func (r queryRepo) GetAuthority(_ context.Context, id domain.AuthorityID, scope port.QueryScope) (domain.Authority, error) {
	a, ok := r.s.authorities[id]
	// Out of scope is reported as not-found, so a reader cannot probe for
	// the existence of a range it may not see.
	if !ok || !r.visible(scope, id) {
		return domain.Authority{}, port.ErrNotFound
	}
	return a, nil
}

// ---- series ----

func (r queryRepo) ListSeries(_ context.Context, query contract.SeriesListQuery, scope port.QueryScope) (contract.Page[port.SeriesSnapshot], error) {
	var items []port.SeriesSnapshot
	for _, s := range r.s.series {
		if !r.visible(scope, s.ManagementAuthorityID()) || !matchesSearch(query.Search, s.Name()) {
			continue
		}
		if query.AuthorityID != nil && s.ManagementAuthorityID() != *query.AuthorityID {
			continue
		}
		items = append(items, port.SeriesSnapshot{
			Series:               s,
			CurrentKeyGeneration: r.s.leafKeyGenerations[s.CurrentKeyGenerationID()],
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Series.ID() < items[j].Series.ID() })
	return paginate(items, query.Page, func(s port.SeriesSnapshot) string { return string(s.Series.ID()) }), nil
}

func (r queryRepo) GetSeries(_ context.Context, id domain.SeriesID, scope port.QueryScope) (port.SeriesSnapshot, error) {
	s, ok := r.s.series[id]
	if !ok || !r.visible(scope, s.ManagementAuthorityID()) {
		return port.SeriesSnapshot{}, port.ErrNotFound
	}
	return port.SeriesSnapshot{
		Series:               s,
		CurrentKeyGeneration: r.s.leafKeyGenerations[s.CurrentKeyGenerationID()],
	}, nil
}

// ---- certificates ----

// queried assembles the stored relations contract.CertificateView needs.
// Expired is deliberately absent: it is time-derived and the service
// computes it against a clock it reads itself.
func (r queryRepo) queried(c domain.Certificate) port.QueriedCertificate {
	out := port.QueriedCertificate{Certificate: c}
	if leaf, ok := r.s.leafCertRecords[c.ID()]; ok {
		seriesID := leaf.SeriesID
		out.SeriesID = &seriesID
	}
	if _, ok := r.s.revocations[revocationKey{issuer: c.IssuerCAKeyGenerationID(), serial: c.Serial().Hex()}]; ok {
		out.Revoked = true
	}
	for key := range r.s.impacts {
		if key.certificateID == c.ID() {
			out.Affected = true
			break
		}
	}
	for _, d := range r.s.deliveries {
		if d.CertificateID() == c.ID() {
			delivery := d
			out.Delivery = &delivery
			break
		}
	}
	return out
}

func (r queryRepo) ListCertificates(_ context.Context, query contract.CertificateListQuery, scope port.QueryScope) (contract.Page[port.QueriedCertificate], error) {
	var items []port.QueriedCertificate
	for id, c := range r.s.certificates {
		authorityID := r.certificateAuthority(id)
		if !r.visible(scope, authorityID) {
			continue
		}
		if query.AuthorityID != nil && authorityID != *query.AuthorityID {
			continue
		}
		if !matchesSearch(query.Search, c.Subject().CommonName()) {
			continue
		}
		if query.ExpiresBefore != nil && !c.Validity().NotAfter().Before(*query.ExpiresBefore) {
			continue
		}
		item := r.queried(c)
		if query.Revoked != nil && item.Revoked != *query.Revoked {
			continue
		}
		if query.Affected != nil && item.Affected != *query.Affected {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Certificate.ID() < items[j].Certificate.ID() })
	return paginate(items, query.Page, func(c port.QueriedCertificate) string { return string(c.Certificate.ID()) }), nil
}

func (r queryRepo) GetCertificate(_ context.Context, id domain.CertificateID, scope port.QueryScope) (port.QueriedCertificate, error) {
	c, ok := r.s.certificates[id]
	if !ok || !r.visible(scope, r.certificateAuthority(id)) {
		return port.QueriedCertificate{}, port.ErrNotFound
	}
	return r.queried(c), nil
}

// ---- revocations ----

func (r queryRepo) ListRevocations(_ context.Context, query contract.RevocationListQuery, scope port.QueryScope) (contract.Page[domain.Revocation], error) {
	var items []domain.Revocation
	for key, rev := range r.s.revocations {
		authorityID := r.issuerAuthority(key.issuer)
		if !r.visible(scope, authorityID) {
			continue
		}
		if query.AuthorityID != nil && authorityID != *query.AuthorityID {
			continue
		}
		if query.SerialHex != "" && !strings.EqualFold(rev.Serial().Hex(), query.SerialHex) {
			continue
		}
		if !matchesSearch(query.Search, rev.Serial().Hex()) {
			continue
		}
		items = append(items, rev)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID() < items[j].ID() })
	return paginate(items, query.Page, func(rev domain.Revocation) string { return string(rev.ID()) }), nil
}

func (r queryRepo) GetRevocation(_ context.Context, id domain.RevocationID, scope port.QueryScope) (domain.Revocation, error) {
	for key, rev := range r.s.revocations {
		if rev.ID() != id {
			continue
		}
		if !r.visible(scope, r.issuerAuthority(key.issuer)) {
			return domain.Revocation{}, port.ErrNotFound
		}
		return rev, nil
	}
	return domain.Revocation{}, port.ErrNotFound
}

// ---- transitions ----

// transitionScopes is the set of authorities one transition is scoped
// under. A transition genuinely involves several CAs, which is the case
// §14.6 keeps the multi-scope audit rule for; the target is included only
// once it has actually been chosen.
func transitionScopes(t domain.Transition) []domain.AuthorityID {
	scopes := []domain.AuthorityID{t.SourceAuthorityID()}
	if target := t.TargetAuthorityID(); target != "" && target != t.SourceAuthorityID() {
		scopes = append(scopes, target)
	}
	return scopes
}

func (r queryRepo) ListTransitions(_ context.Context, query contract.TransitionListQuery, scope port.QueryScope) (contract.Page[domain.Transition], error) {
	var items []domain.Transition
	for _, t := range r.s.transitions {
		if !r.visibleAll(scope, transitionScopes(t)) || !matchesSearch(query.Search, t.Reason()) {
			continue
		}
		items = append(items, t)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID() < items[j].ID() })
	return paginate(items, query.Page, func(t domain.Transition) string { return string(t.ID()) }), nil
}

func (r queryRepo) GetTransition(_ context.Context, id domain.TransitionID, scope port.QueryScope) (port.QueriedTransition, error) {
	t, ok := r.s.transitions[id]
	if !ok || !r.visibleAll(scope, transitionScopes(t)) {
		return port.QueriedTransition{}, port.ErrNotFound
	}
	out := port.QueriedTransition{Transition: t}
	for key, impact := range r.s.impacts {
		if key.transitionID == id {
			out.Impacts = append(out.Impacts, impact)
		}
	}
	sort.Slice(out.Impacts, func(i, j int) bool {
		return out.Impacts[i].CertificateID() < out.Impacts[j].CertificateID()
	})
	return out, nil
}

// ---- imports ----

// Import batches carry no authority of their own -- port.ImportBatch has no
// AuthorityID field, because an import run can bring in material for several
// authorities at once and the batch is installation-level bookkeeping. They
// are therefore visible to any reader that is not restricted to the public
// path, the same treatment jobs get.
func (r queryRepo) ListImports(_ context.Context, query contract.ImportListQuery, scope port.QueryScope) (contract.Page[port.ImportBatch], error) {
	if scope.Public {
		return contract.Page[port.ImportBatch]{}, nil
	}
	var items []port.ImportBatch
	for _, b := range r.s.importBatches {
		items = append(items, cloneImportBatch(b))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return paginate(items, query.Page, func(b port.ImportBatch) string { return string(b.ID) }), nil
}

func (r queryRepo) GetImport(_ context.Context, id domain.ImportBatchID, scope port.QueryScope) (port.ImportBatch, error) {
	if scope.Public {
		return port.ImportBatch{}, port.ErrNotFound
	}
	b, ok := r.s.importBatches[id]
	if !ok {
		return port.ImportBatch{}, port.ErrNotFound
	}
	return cloneImportBatch(b), nil
}

// ---- jobs ----

func (r queryRepo) ListJobs(_ context.Context, query contract.JobListQuery, scope port.QueryScope) (contract.Page[port.Job], error) {
	if scope.Public {
		return contract.Page[port.Job]{}, nil
	}
	var items []port.Job
	for _, j := range r.s.jobs {
		items = append(items, cloneJob(j))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return paginate(items, query.Page, func(j port.Job) string { return string(j.ID) }), nil
}

func (r queryRepo) GetJob(_ context.Context, id domain.JobID, scope port.QueryScope) (port.Job, error) {
	if scope.Public {
		return port.Job{}, port.ErrNotFound
	}
	j, ok := r.s.jobs[id]
	if !ok {
		return port.Job{}, port.ErrNotFound
	}
	return cloneJob(j), nil
}

// ---- audit ----

// auditMatches applies contract.AuditFilter to one stored row.
func auditMatches(filter contract.AuditFilter, row auditRow) bool {
	e := row.event
	if filter.From != nil && e.OccurredAt.Before(*filter.From) {
		return false
	}
	if filter.Until != nil && filter.Until.Before(e.OccurredAt) {
		return false
	}
	if filter.AccountID != nil && (e.ActorKind != contract.AuditActorAccount || e.ActorID != string(*filter.AccountID)) {
		return false
	}
	if filter.AuthorityID != nil {
		found := false
		for _, id := range row.scopes {
			if id == *filter.AuthorityID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if filter.CertificateID != nil && e.TargetID != string(*filter.CertificateID) {
		return false
	}
	if filter.Action != "" && e.Action != filter.Action {
		return false
	}
	if filter.ClientIP != "" && e.ClientIP != filter.ClientIP {
		return false
	}
	if filter.Result != nil && e.Result != contract.AuditResult(*filter.Result) {
		return false
	}
	return true
}

// auditVisible applies the typed audit scope rule. Installation events are
// visible only to the installation-wide query scope; authority events require
// every stored authority relation to be within the reader's scope.
func (r queryRepo) auditVisible(scope port.QueryScope, row auditRow) bool {
	switch row.scopeKind {
	case port.AuditScopeInstallation:
		return scope.All
	case port.AuditScopeAuthorities:
		return r.visibleAll(scope, row.scopes)
	default:
		return false
	}
}

// auditViews returns every stored event matching filter and visible under
// scope, ordered by id.
func (r queryRepo) auditViews(filter contract.AuditFilter, scope port.QueryScope) []contract.AuditEventView {
	var items []contract.AuditEventView
	for _, row := range r.s.auditEvents {
		if !r.auditVisible(scope, row) || !auditMatches(filter, row) {
			continue
		}
		items = append(items, auditEventView(row))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

// auditEventView joins a stored event back together with its scope rows,
// which port.AuditEvent deliberately does not carry.
func auditEventView(row auditRow) contract.AuditEventView {
	scopes := make([]domain.AuthorityID, len(row.scopes))
	copy(scopes, row.scopes)
	fields := map[string]string{}
	for k, v := range row.event.Details.Fields {
		fields[k] = v
	}
	return contract.AuditEventView{
		ID:         row.event.ID,
		OccurredAt: row.event.OccurredAt,
		ActorKind:  row.event.ActorKind,
		ActorID:    row.event.ActorID,
		TokenID:    row.event.TokenID,
		Action:     row.event.Action,
		TargetType: row.event.TargetType,
		TargetID:   row.event.TargetID,
		ClientIP:   row.event.ClientIP,
		Result:     row.event.Result,
		Details: contract.AuditDetails{
			SchemaVersion: row.event.Details.SchemaVersion,
			Fields:        fields,
		},
		AuthorityIDs: scopes,
	}
}

func (r queryRepo) ListAudit(_ context.Context, query contract.AuditListQuery, scope port.QueryScope) (contract.Page[contract.AuditEventView], error) {
	items := r.auditViews(query.Filter, scope)
	return paginate(items, query.Page, func(e contract.AuditEventView) string { return e.ID }), nil
}

func (r queryRepo) IterateAudit(_ context.Context, query contract.AuditExportQuery, scope port.QueryScope) (contract.AuditEventIterator, error) {
	return &auditIterator{items: r.auditViews(query.Filter, scope)}, nil
}

// auditIterator is the export stream. It is a snapshot taken at call time,
// which is what the surrounding ReadStore.Read already guarantees anyway.
type auditIterator struct {
	items  []contract.AuditEventView
	index  int
	closed bool
}

func (it *auditIterator) Next(ctxDone <-chan struct{}) bool {
	if it.closed {
		return false
	}
	// An export can be long; honour cancellation between rows the same way a
	// streaming SQL cursor would.
	select {
	case <-ctxDone:
		return false
	default:
	}
	if it.index >= len(it.items) {
		return false
	}
	it.index++
	return true
}

func (it *auditIterator) Event() contract.AuditEventView {
	if it.index == 0 || it.index > len(it.items) {
		return contract.AuditEventView{}
	}
	return it.items[it.index-1]
}

func (it *auditIterator) Err() error { return nil }

func (it *auditIterator) Close() error {
	it.closed = true
	return nil
}

// ---- CRL / public CA ----

func (r queryRepo) GetCRLStatus(_ context.Context, caKeyGenerationID domain.CAKeyGenerationID, scope port.QueryScope) (domain.CRLState, error) {
	state, ok := r.s.crlStates[caKeyGenerationID]
	if !ok || !r.visible(scope, r.issuerAuthority(caKeyGenerationID)) {
		return domain.CRLState{}, port.ErrNotFound
	}
	return state, nil
}

// ReadPublicCA serves public material: the authority's current issuance CA
// certificate. This is the one method an anonymous reader reaches, so a
// scope with Public set is accepted here and nowhere else.
func (r queryRepo) ReadPublicCA(_ context.Context, authorityID domain.AuthorityID, scope port.QueryScope) (domain.Certificate, error) {
	if !scope.Public && !r.visible(scope, authorityID) {
		return domain.Certificate{}, port.ErrNotFound
	}
	authority, ok := r.s.authorities[authorityID]
	if !ok {
		return domain.Certificate{}, port.ErrNotFound
	}
	certificateID := authority.IssuanceCertificateID()
	if certificateID == "" {
		return domain.Certificate{}, port.ErrNotFound
	}
	certificate, ok := r.s.certificates[certificateID]
	if !ok {
		return domain.Certificate{}, port.ErrNotFound
	}
	return certificate, nil
}
