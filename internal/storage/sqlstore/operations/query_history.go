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
)

func (r *QueryRepository) loadRevocation(ctx context.Context, id domain.RevocationID) (domain.Revocation, error) {
	b := r.builder()
	query := `SELECT id,issuer_ca_key_generation_id,serial_hex,certificate_id,revoked_at,reason,source,change_generation,version FROM revocations WHERE id = ` + b.Add(string(id))
	var rawID, rawIssuer, serial, reason, source string
	var certificate sql.NullString
	var revokedAt, generation, version int64
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawID, &rawIssuer, &serial, &certificate, &revokedAt, &reason, &source, &generation, &version); err != nil {
		return domain.Revocation{}, missing(err)
	}
	parsedID, err := domain.ParseRevocationID(rawID)
	if err != nil {
		return domain.Revocation{}, err
	}
	issuer, err := domain.ParseCAKeyGenerationID(rawIssuer)
	if err != nil {
		return domain.Revocation{}, err
	}
	serialNo, err := domain.ParseSerialNumber(serial)
	if err != nil {
		return domain.Revocation{}, err
	}
	var certificateID domain.CertificateID
	if certificate.Valid {
		certificateID, err = domain.ParseCertificateID(certificate.String)
		if err != nil {
			return domain.Revocation{}, err
		}
	}
	if generation < 0 || version < 0 {
		return domain.Revocation{}, fmt.Errorf("revocation has invalid version or generation")
	}
	return domain.NewRevocation(domain.RevocationFacts{ID: parsedID, IssuerID: issuer, Serial: serialNo, CertificateID: certificateID, RevokedAt: domain.InstantFromUnixMicro(revokedAt), Reason: domain.RevocationReason(reason), Source: domain.RevocationSource(source), ChangeGeneration: generation, Version: domain.Version(version)})
}

func (r *QueryRepository) ListRevocations(ctx context.Context, query contract.RevocationListQuery, scope port.QueryScope) (contract.Page[domain.Revocation], error) {
	if err := checkContext(ctx); err != nil {
		return contract.Page[domain.Revocation]{}, err
	}
	if err := query.Validate(); err != nil {
		return contract.Page[domain.Revocation]{}, failed("validate revocation list", err)
	}
	if err := r.validateScope(scope); err != nil {
		return contract.Page[domain.Revocation]{}, failed("validate revocation scope", err)
	}
	b := r.builder()
	conditions := []string{r.authorityScope(b, scope, "cg.authority_id")}
	appendCondition(&conditions, r.contains(b, "r.serial_hex", query.Search))
	if query.AuthorityID != nil {
		conditions = append(conditions, "cg.authority_id = "+b.Add(string(*query.AuthorityID)))
	}
	if query.SerialHex != "" {
		conditions = append(conditions, "LOWER(r.serial_hex) = LOWER("+b.Add(query.SerialHex)+")")
	}
	limit, tail := addPageClause(b, &conditions, "r.id", query.Page)
	ids, next, err := r.selectIDs(ctx, "SELECT r.id FROM revocations r JOIN ca_key_generations cg ON cg.id = r.issuer_ca_key_generation_id WHERE "+joinConditions(conditions)+tail, b.Args(), limit)
	if err != nil {
		return contract.Page[domain.Revocation]{}, err
	}
	items := make([]domain.Revocation, 0, len(ids))
	for _, raw := range ids {
		id, e := domain.ParseRevocationID(raw)
		if e != nil {
			return contract.Page[domain.Revocation]{}, failed("decode revocation id", e)
		}
		value, e := r.loadRevocation(ctx, id)
		if e != nil {
			return contract.Page[domain.Revocation]{}, failed("read revocation", e)
		}
		items = append(items, value)
	}
	return pageResult(items, next), nil
}

func (r *QueryRepository) GetRevocation(ctx context.Context, id domain.RevocationID, scope port.QueryScope) (domain.Revocation, error) {
	if err := checkContext(ctx); err != nil {
		return domain.Revocation{}, err
	}
	if err := r.validateScope(scope); err != nil {
		return domain.Revocation{}, failed("validate revocation scope", err)
	}
	b := r.builder()
	conditions := []string{"r.id = " + b.Add(string(id)), r.authorityScope(b, scope, "cg.authority_id")}
	var exists bool
	query := "SELECT EXISTS (SELECT 1 FROM revocations r JOIN ca_key_generations cg ON cg.id = r.issuer_ca_key_generation_id WHERE " + joinConditions(conditions) + ")"
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&exists); err != nil {
		return domain.Revocation{}, failed("check revocation scope", err)
	}
	if !exists {
		return domain.Revocation{}, port.ErrNotFound
	}
	value, err := r.loadRevocation(ctx, id)
	if err != nil {
		return domain.Revocation{}, failed("read revocation", err)
	}
	return value, nil
}

func (r *QueryRepository) transitionScopePredicate(b *dialect.Builder, scope port.QueryScope) string {
	if scope.Public {
		return "1 = 0"
	}
	if scope.All {
		return "1 = 1"
	}
	if len(scope.AuthorityIDs) == 0 {
		return "1 = 0"
	}
	source := make([]string, 0, len(scope.AuthorityIDs))
	for _, id := range scope.AuthorityIDs {
		source = append(source, b.Add(string(id)))
	}
	target := make([]string, 0, len(scope.AuthorityIDs))
	for _, id := range scope.AuthorityIDs {
		target = append(target, b.Add(string(id)))
	}
	return `(t.source_authority_id IN (` + strings.Join(source, ",") + `) AND (t.target_authority_id IS NULL OR t.target_authority_id IN (` + strings.Join(target, ",") + `)))`
}

func (r *QueryRepository) loadTransition(ctx context.Context, id domain.TransitionID) (domain.Transition, error) {
	b := r.builder()
	query := `SELECT id,source_authority_id,target_authority_id,mode,state,reported_by,reported_at,reason,version FROM ca_transitions WHERE id = ` + b.Add(string(id))
	var rawID, source, mode, state, reportedBy, reason string
	var target sql.NullString
	var reportedAt, version int64
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawID, &source, &target, &mode, &state, &reportedBy, &reportedAt, &reason, &version); err != nil {
		return domain.Transition{}, missing(err)
	}
	parsedID, err := domain.ParseTransitionID(rawID)
	if err != nil {
		return domain.Transition{}, err
	}
	sourceID, err := domain.ParseAuthorityID(source)
	if err != nil {
		return domain.Transition{}, err
	}
	actor, err := domain.ParseAccountID(reportedBy)
	if err != nil {
		return domain.Transition{}, err
	}
	var targetID domain.AuthorityID
	if target.Valid {
		targetID, err = domain.ParseAuthorityID(target.String)
		if err != nil {
			return domain.Transition{}, err
		}
	}
	if version < 0 {
		return domain.Transition{}, fmt.Errorf("transition version is negative")
	}
	return domain.NewTransition(domain.TransitionFacts{ID: parsedID, SourceAuthorityID: sourceID, TargetAuthorityID: targetID, Mode: domain.TransitionMode(mode), State: domain.TransitionState(state), ReportedBy: actor, ReportedAt: domain.InstantFromUnixMicro(reportedAt), Reason: reason, Version: domain.Version(version)})
}

func (r *QueryRepository) ListTransitions(ctx context.Context, query contract.TransitionListQuery, scope port.QueryScope) (contract.Page[domain.Transition], error) {
	if err := checkContext(ctx); err != nil {
		return contract.Page[domain.Transition]{}, err
	}
	if err := query.Validate(); err != nil {
		return contract.Page[domain.Transition]{}, failed("validate transition list", err)
	}
	if err := r.validateScope(scope); err != nil {
		return contract.Page[domain.Transition]{}, failed("validate transition scope", err)
	}
	b := r.builder()
	conditions := []string{r.transitionScopePredicate(b, scope)}
	appendCondition(&conditions, r.contains(b, "t.reason", query.Search))
	limit, tail := addPageClause(b, &conditions, "t.id", query.Page)
	ids, next, err := r.selectIDs(ctx, "SELECT t.id FROM ca_transitions t WHERE "+joinConditions(conditions)+tail, b.Args(), limit)
	if err != nil {
		return contract.Page[domain.Transition]{}, err
	}
	items := make([]domain.Transition, 0, len(ids))
	for _, raw := range ids {
		id, e := domain.ParseTransitionID(raw)
		if e != nil {
			return contract.Page[domain.Transition]{}, failed("decode transition id", e)
		}
		value, e := r.loadTransition(ctx, id)
		if e != nil {
			return contract.Page[domain.Transition]{}, failed("read transition", e)
		}
		items = append(items, value)
	}
	return pageResult(items, next), nil
}

func (r *QueryRepository) GetTransition(ctx context.Context, id domain.TransitionID, scope port.QueryScope) (port.QueriedTransition, error) {
	if err := checkContext(ctx); err != nil {
		return port.QueriedTransition{}, err
	}
	if err := r.validateScope(scope); err != nil {
		return port.QueriedTransition{}, failed("validate transition scope", err)
	}
	b := r.builder()
	conditions := []string{"t.id = " + b.Add(string(id)), r.transitionScopePredicate(b, scope)}
	var exists bool
	query := "SELECT EXISTS (SELECT 1 FROM ca_transitions t WHERE " + joinConditions(conditions) + ")"
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&exists); err != nil {
		return port.QueriedTransition{}, failed("check transition scope", err)
	}
	if !exists {
		return port.QueriedTransition{}, port.ErrNotFound
	}
	transition, err := r.loadTransition(ctx, id)
	if err != nil {
		return port.QueriedTransition{}, failed("read transition", err)
	}
	b = r.builder()
	rows, err := r.executor.QueryContext(ctx, "SELECT certificate_id,replacement_certificate_id,reissued_at FROM transition_impacts WHERE transition_id = "+b.Add(string(id))+" ORDER BY certificate_id", b.Args()...)
	if err != nil {
		return port.QueriedTransition{}, failed("list transition impacts", err)
	}
	defer rows.Close()
	out := port.QueriedTransition{Transition: transition, Impacts: make([]domain.TransitionImpact, 0)}
	for rows.Next() {
		var rawCertificate string
		var replacement sql.NullString
		var reissued sql.NullInt64
		if err := rows.Scan(&rawCertificate, &replacement, &reissued); err != nil {
			return port.QueriedTransition{}, failed("decode transition impact", err)
		}
		certificateID, e := domain.ParseCertificateID(rawCertificate)
		if e != nil {
			return port.QueriedTransition{}, failed("decode transition impact", e)
		}
		facts := domain.TransitionImpactFacts{TransitionID: id, CertificateID: certificateID}
		if replacement.Valid {
			facts.ReplacementCertificateID, e = domain.ParseCertificateID(replacement.String)
			if e != nil {
				return port.QueriedTransition{}, failed("decode transition impact", e)
			}
		}
		if reissued.Valid {
			facts.ReissuedAt = domain.InstantFromUnixMicro(reissued.Int64)
		}
		impact, e := domain.NewTransitionImpact(facts)
		if e != nil {
			return port.QueriedTransition{}, failed("decode transition impact", e)
		}
		out.Impacts = append(out.Impacts, impact)
	}
	if err := rows.Err(); err != nil {
		return port.QueriedTransition{}, failed("iterate transition impacts", err)
	}
	return out, nil
}
