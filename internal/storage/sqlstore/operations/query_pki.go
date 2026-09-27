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

const authorityPathCTE = `WITH RECURSIVE authority_path(root_id, id, parent_id) AS (
 SELECT id, id, management_parent_id FROM authorities
 UNION
 SELECT p.root_id, a.id, a.management_parent_id FROM authorities a JOIN authority_path p ON p.parent_id = a.id
) `

func (r *QueryRepository) loadAuthority(ctx context.Context, id domain.AuthorityID) (domain.Authority, error) {
	b := r.builder()
	query := authorityPathCTE + `SELECT a.id, a.kind, a.name, a.management_parent_id, a.issuance_state,
 a.issuance_certificate_id, a.archived_at, a.version, cg.id, cg.authority_id, cg.key_material_id,
 cg.generation_no, cg.key_destroyed_at, c.not_before, c.not_after,
 EXISTS (SELECT 1 FROM ca_takeovers tk WHERE tk.ca_key_generation_id = cg.id AND tk.state = 'pending'),
 EXISTS (SELECT 1 FROM authority_path ap JOIN ca_transitions tr ON tr.source_authority_id = ap.id
        WHERE ap.root_id = a.id AND tr.mode = 'emergency' AND tr.state <> 'closed')
 FROM authorities a
 LEFT JOIN ca_key_generations cg ON cg.id = CASE WHEN a.issuance_certificate_id IS NOT NULL
   THEN (SELECT cc.ca_key_generation_id FROM ca_certificates cc WHERE cc.certificate_id = a.issuance_certificate_id)
   ELSE (SELECT cg2.id FROM ca_key_generations cg2 WHERE cg2.authority_id = a.id ORDER BY cg2.generation_no DESC LIMIT 1) END
 LEFT JOIN certificates c ON c.id = a.issuance_certificate_id
 WHERE a.id = ` + b.Add(string(id))
	var rawID, kind, name, state string
	var parent, issuanceCert, rawGenID, genAuthority, rawKey sql.NullString
	var archived, destroyed, notBefore, notAfter sql.NullInt64
	var version, generationNo sql.NullInt64
	var pending, affected bool
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawID, &kind, &name, &parent, &state, &issuanceCert, &archived, &version, &rawGenID, &genAuthority, &rawKey, &generationNo, &destroyed, &notBefore, &notAfter, &pending, &affected); err != nil {
		return domain.Authority{}, missing(err)
	}
	if (archived.Valid && archived.Int64 == 0) || (destroyed.Valid && destroyed.Int64 == 0) {
		return domain.Authority{}, fmt.Errorf("authority contains a reserved zero timestamp")
	}
	if !rawGenID.Valid || !genAuthority.Valid || !rawKey.Valid || !generationNo.Valid {
		return domain.Authority{}, fmt.Errorf("authority row has no CA key generation")
	}
	parsedID, err := domain.ParseAuthorityID(rawID)
	if err != nil {
		return domain.Authority{}, err
	}
	genID, err := domain.ParseCAKeyGenerationID(rawGenID.String)
	if err != nil {
		return domain.Authority{}, err
	}
	if _, err := domain.ParseKeyMaterialID(rawKey.String); err != nil {
		return domain.Authority{}, err
	}
	ownerID, err := domain.ParseAuthorityID(genAuthority.String)
	if err != nil {
		return domain.Authority{}, err
	}
	if ownerID != parsedID {
		return domain.Authority{}, fmt.Errorf("authority key generation belongs to another authority")
	}
	var parentID domain.AuthorityID
	if parent.Valid {
		parentID, err = domain.ParseAuthorityID(parent.String)
		if err != nil {
			return domain.Authority{}, err
		}
	}
	var issuanceID domain.CertificateID
	if issuanceCert.Valid {
		issuanceID, err = domain.ParseCertificateID(issuanceCert.String)
		if err != nil {
			return domain.Authority{}, err
		}
	}
	if version.Int64 < 0 || generationNo.Int64 < 0 {
		return domain.Authority{}, fmt.Errorf("authority has invalid version or key generation")
	}
	var window domain.ValidityWindow
	if notBefore.Valid || notAfter.Valid {
		if !notBefore.Valid || !notAfter.Valid {
			return domain.Authority{}, fmt.Errorf("authority certificate has incomplete validity window")
		}
		if notBefore.Int64 == 0 || notAfter.Int64 == 0 {
			return domain.Authority{}, fmt.Errorf("authority certificate has a reserved zero timestamp")
		}
		window, err = domain.NewValidityWindow(domain.InstantFromUnixMicro(notBefore.Int64), domain.InstantFromUnixMicro(notAfter.Int64))
		if err != nil {
			return domain.Authority{}, err
		}
	}
	facts := domain.AuthorityFacts{ID: parsedID, Kind: domain.AuthorityKind(kind), Name: name, ManagementParentID: parentID,
		IssuanceState: domain.IssuanceState(state), IssuanceCertificateID: issuanceID, KeyGenerationID: genID,
		KeyAvailable: !destroyed.Valid, Affected: affected, PendingTakeover: pending, CertificateWindow: window,
		Version: domain.Version(version.Int64)}
	if archived.Valid {
		facts.ArchivedAt = domain.InstantFromUnixMicro(archived.Int64)
	}
	return domain.NewAuthority(facts)
}

func (r *QueryRepository) ListAuthorities(ctx context.Context, query contract.AuthorityListQuery, scope port.QueryScope) (contract.Page[domain.Authority], error) {
	if err := checkContext(ctx); err != nil {
		return contract.Page[domain.Authority]{}, err
	}
	if err := query.Validate(); err != nil {
		return contract.Page[domain.Authority]{}, failed("validate authority list", err)
	}
	if err := r.validateScope(scope); err != nil {
		return contract.Page[domain.Authority]{}, failed("validate authority scope", err)
	}
	b := r.builder()
	conditions := []string{r.authorityScope(b, scope, "a.id")}
	appendCondition(&conditions, r.contains(b, "a.name", query.Search))
	limit, tail := addPageClause(b, &conditions, "a.id", query.Page)
	ids, next, err := r.selectIDs(ctx, "SELECT a.id FROM authorities a WHERE "+joinConditions(conditions)+tail, b.Args(), limit)
	if err != nil {
		return contract.Page[domain.Authority]{}, err
	}
	items := make([]domain.Authority, 0, len(ids))
	for _, raw := range ids {
		id, e := domain.ParseAuthorityID(raw)
		if e != nil {
			return contract.Page[domain.Authority]{}, failed("decode authority id", e)
		}
		a, e := r.loadAuthority(ctx, id)
		if e != nil {
			return contract.Page[domain.Authority]{}, failed("read authority", e)
		}
		items = append(items, a)
	}
	return pageResult(items, next), nil
}

func (r *QueryRepository) GetAuthority(ctx context.Context, id domain.AuthorityID, scope port.QueryScope) (domain.Authority, error) {
	if err := checkContext(ctx); err != nil {
		return domain.Authority{}, err
	}
	if err := r.validateScope(scope); err != nil {
		return domain.Authority{}, failed("validate authority scope", err)
	}
	b := r.builder()
	where := []string{"a.id = " + b.Add(string(id)), r.authorityScope(b, scope, "a.id")}
	var exists bool
	if err := r.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM authorities a WHERE "+joinConditions(where)+")", b.Args()...).Scan(&exists); err != nil {
		return domain.Authority{}, failed("check authority scope", err)
	}
	if !exists {
		return domain.Authority{}, port.ErrNotFound
	}
	a, err := r.loadAuthority(ctx, id)
	if err != nil {
		return domain.Authority{}, failed("read authority", err)
	}
	return a, nil
}

func (r *QueryRepository) loadSeries(ctx context.Context, id domain.SeriesID) (port.SeriesSnapshot, error) {
	b := r.builder()
	query := `SELECT id,name,purpose,management_authority_id,current_certificate_id,current_key_generation_id,validity_policy_json,version,archived_at FROM leaf_series WHERE id = ` + b.Add(string(id))
	var rawID, name, purpose, authorityID, policy string
	var certificateID, generationID sql.NullString
	var version int64
	var archived sql.NullInt64
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&rawID, &name, &purpose, &authorityID, &certificateID, &generationID, &policy, &version, &archived); err != nil {
		return port.SeriesSnapshot{}, missing(err)
	}
	if archived.Valid && archived.Int64 == 0 {
		return port.SeriesSnapshot{}, fmt.Errorf("series contains a reserved zero archived_at timestamp")
	}
	parsedID, err := domain.ParseSeriesID(rawID)
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	parsedAuthority, err := domain.ParseAuthorityID(authorityID)
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	var currentCert domain.CertificateID
	if certificateID.Valid {
		currentCert, err = domain.ParseCertificateID(certificateID.String)
		if err != nil {
			return port.SeriesSnapshot{}, err
		}
	}
	var currentGen domain.LeafKeyGenerationID
	if generationID.Valid {
		currentGen, err = domain.ParseLeafKeyGenerationID(generationID.String)
		if err != nil {
			return port.SeriesSnapshot{}, err
		}
	}
	if (currentCert == "") != (currentGen == "") {
		return port.SeriesSnapshot{}, fmt.Errorf("series current certificate and key generation disagree")
	}
	if version < 0 {
		return port.SeriesSnapshot{}, fmt.Errorf("series version is negative")
	}
	policyValue, err := pki.DecodeValidityPolicyV1([]byte(policy))
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	facts := domain.LeafSeriesFacts{ID: parsedID, Name: name, Purpose: domain.SeriesPurpose(purpose), ManagementAuthorityID: parsedAuthority,
		CurrentCertificateID: currentCert, CurrentKeyGenerationID: currentGen, Policy: policyValue, Version: domain.Version(version)}
	if archived.Valid {
		facts.ArchivedAt = domain.InstantFromUnixMicro(archived.Int64)
	}
	series, err := domain.NewLeafSeries(facts)
	if err != nil {
		return port.SeriesSnapshot{}, err
	}
	snapshot := port.SeriesSnapshot{Series: series}
	if currentGen != "" {
		b = r.builder()
		var genID, owner, keyID, custody string
		var genNo, renewal int64
		var unknown bool
		if err := r.queryRow(ctx, "SELECT id,series_id,key_material_id,generation_no,renewal_count,prior_history_unknown,custody FROM leaf_key_generations WHERE id = "+b.Add(string(currentGen)), b.Args()...).Scan(&genID, &owner, &keyID, &genNo, &renewal, &unknown, &custody); err != nil {
			return port.SeriesSnapshot{}, missing(err)
		}
		parsedGen, err := domain.ParseLeafKeyGenerationID(genID)
		if err != nil {
			return port.SeriesSnapshot{}, err
		}
		parsedOwner, err := domain.ParseSeriesID(owner)
		if err != nil {
			return port.SeriesSnapshot{}, err
		}
		parsedKey, err := domain.ParseKeyMaterialID(keyID)
		if err != nil {
			return port.SeriesSnapshot{}, err
		}
		if parsedGen != currentGen || parsedOwner != parsedID || genNo > int64(^uint(0)>>1) || renewal > int64(^uint(0)>>1) {
			return port.SeriesSnapshot{}, fmt.Errorf("series current key generation is inconsistent")
		}
		key, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{ID: parsedGen, SeriesID: parsedOwner, KeyMaterialID: parsedKey, GenerationNo: int(genNo), RenewalCount: int(renewal), PriorHistoryUnknown: unknown, Custody: domain.KeyCustody(custody)})
		if err != nil {
			return port.SeriesSnapshot{}, err
		}
		b = r.builder()
		var exists bool
		err = r.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM leaf_certificates WHERE series_id = "+b.Add(string(parsedID))+" AND certificate_id = "+b.Add(string(currentCert))+" AND leaf_key_generation_id = "+b.Add(string(currentGen))+")", b.Args()...).Scan(&exists)
		if err != nil {
			return port.SeriesSnapshot{}, err
		}
		if !exists {
			return port.SeriesSnapshot{}, fmt.Errorf("series current certificate and key generation are inconsistent")
		}
		snapshot.CurrentKeyGeneration = key
	}
	return snapshot, nil
}

func (r *QueryRepository) ListSeries(ctx context.Context, query contract.SeriesListQuery, scope port.QueryScope) (contract.Page[port.SeriesSnapshot], error) {
	if err := checkContext(ctx); err != nil {
		return contract.Page[port.SeriesSnapshot]{}, err
	}
	if err := query.Validate(); err != nil {
		return contract.Page[port.SeriesSnapshot]{}, failed("validate series list", err)
	}
	if err := r.validateScope(scope); err != nil {
		return contract.Page[port.SeriesSnapshot]{}, failed("validate series scope", err)
	}
	b := r.builder()
	conditions := []string{r.authorityScope(b, scope, "s.management_authority_id")}
	appendCondition(&conditions, r.contains(b, "s.name", query.Search))
	if query.AuthorityID != nil {
		conditions = append(conditions, "s.management_authority_id = "+b.Add(string(*query.AuthorityID)))
	}
	limit, tail := addPageClause(b, &conditions, "s.id", query.Page)
	ids, next, err := r.selectIDs(ctx, "SELECT s.id FROM leaf_series s WHERE "+joinConditions(conditions)+tail, b.Args(), limit)
	if err != nil {
		return contract.Page[port.SeriesSnapshot]{}, err
	}
	items := make([]port.SeriesSnapshot, 0, len(ids))
	for _, raw := range ids {
		id, e := domain.ParseSeriesID(raw)
		if e != nil {
			return contract.Page[port.SeriesSnapshot]{}, failed("decode series id", e)
		}
		item, e := r.loadSeries(ctx, id)
		if e != nil {
			return contract.Page[port.SeriesSnapshot]{}, failed("read series", e)
		}
		items = append(items, item)
	}
	return pageResult(items, next), nil
}

func (r *QueryRepository) GetSeries(ctx context.Context, id domain.SeriesID, scope port.QueryScope) (port.SeriesSnapshot, error) {
	if err := checkContext(ctx); err != nil {
		return port.SeriesSnapshot{}, err
	}
	if err := r.validateScope(scope); err != nil {
		return port.SeriesSnapshot{}, failed("validate series scope", err)
	}
	b := r.builder()
	var exists bool
	query := "SELECT EXISTS (SELECT 1 FROM leaf_series s WHERE s.id = " + b.Add(string(id)) + " AND " + r.authorityScope(b, scope, "s.management_authority_id") + ")"
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&exists); err != nil {
		return port.SeriesSnapshot{}, failed("check series scope", err)
	}
	if !exists {
		return port.SeriesSnapshot{}, port.ErrNotFound
	}
	item, err := r.loadSeries(ctx, id)
	if err != nil {
		return port.SeriesSnapshot{}, failed("read series", err)
	}
	return item, nil
}

func effectiveAuthorities(scope port.QueryScope, filter *domain.AuthorityID) ([]domain.AuthorityID, bool) {
	if scope.Public {
		return nil, false
	}
	if scope.All {
		if filter == nil {
			return nil, true
		}
		return []domain.AuthorityID{*filter}, false
	}
	if len(scope.AuthorityIDs) == 0 {
		return nil, false
	}
	if filter == nil {
		return append([]domain.AuthorityID(nil), scope.AuthorityIDs...), false
	}
	for _, id := range scope.AuthorityIDs {
		if id == *filter {
			return []domain.AuthorityID{id}, false
		}
	}
	return nil, false
}

func (r *QueryRepository) certificateScopePredicate(b *dialect.Builder, scope port.QueryScope, filter *domain.AuthorityID) string {
	ids, unrestricted := effectiveAuthorities(scope, filter)
	if unrestricted {
		return "1 = 1"
	}
	if len(ids) == 0 {
		return "1 = 0"
	}
	leafArgs := make([]string, 0, len(ids))
	caArgs := make([]string, 0, len(ids))
	for _, id := range ids {
		leafArgs = append(leafArgs, b.Add(string(id)))
	}
	for _, id := range ids {
		caArgs = append(caArgs, b.Add(string(id)))
	}
	return `(EXISTS (SELECT 1 FROM leaf_certificates lc JOIN leaf_series s ON s.id = lc.series_id WHERE lc.certificate_id = c.id AND s.management_authority_id IN (` + strings.Join(leafArgs, ",") + `)) OR EXISTS (SELECT 1 FROM ca_certificates cc JOIN ca_key_generations cg ON cg.id = cc.ca_key_generation_id WHERE cc.certificate_id = c.id AND cg.authority_id IN (` + strings.Join(caArgs, ",") + `)))`
}

func (r *QueryRepository) subjectCommonNameExpr() string {
	switch string(r.dialect.Kind()) {
	case "postgres":
		return `(c.subject_json::jsonb ->> 'common_name')`
	case "mysql", "mariadb":
		return `JSON_UNQUOTE(JSON_EXTRACT(c.subject_json,'$.common_name'))`
	default:
		return `json_extract(c.subject_json,'$.common_name')`
	}
}

func (r *QueryRepository) queriedCertificate(ctx context.Context, id domain.CertificateID) (port.QueriedCertificate, error) {
	certificate, err := pki.New(r.executor, r.dialect).GetCertificate(ctx, id)
	if err != nil {
		return port.QueriedCertificate{}, err
	}
	out := port.QueriedCertificate{Certificate: certificate}
	b := r.builder()
	var leaf, ca bool
	query := `SELECT EXISTS (SELECT 1 FROM leaf_certificates WHERE certificate_id = ` + b.Add(string(id)) + `), EXISTS (SELECT 1 FROM ca_certificates WHERE certificate_id = ` + b.Add(string(id)) + `)`
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&leaf, &ca); err != nil {
		return port.QueriedCertificate{}, err
	}
	if leaf == ca {
		return port.QueriedCertificate{}, fmt.Errorf("certificate subtype is missing or ambiguous")
	}
	if leaf {
		b = r.builder()
		var raw string
		if err := r.queryRow(ctx, "SELECT series_id FROM leaf_certificates WHERE certificate_id = "+b.Add(string(id)), b.Args()...).Scan(&raw); err != nil {
			return port.QueriedCertificate{}, err
		}
		seriesID, err := domain.ParseSeriesID(raw)
		if err != nil {
			return port.QueriedCertificate{}, err
		}
		out.SeriesID = &seriesID
	}
	b = r.builder()
	if err := r.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM revocations WHERE issuer_ca_key_generation_id = "+b.Add(string(certificate.IssuerCAKeyGenerationID()))+" AND serial_hex = "+b.Add(certificate.Serial().Hex())+")", b.Args()...).Scan(&out.Revoked); err != nil {
		return port.QueriedCertificate{}, err
	}
	b = r.builder()
	if err := r.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM transition_impacts WHERE certificate_id = "+b.Add(string(id))+")", b.Args()...).Scan(&out.Affected); err != nil {
		return port.QueriedCertificate{}, err
	}
	b = r.builder()
	var deliveryID, generationID, certID, state string
	var expires int64
	var consumed, finished sql.NullInt64
	var failure sql.NullString
	var version int64
	err = r.queryRow(ctx, "SELECT id,leaf_key_generation_id,certificate_id,expires_at,state,consumed_at,finished_at,failure_code,version FROM key_deliveries WHERE certificate_id = "+b.Add(string(id)), b.Args()...).Scan(&deliveryID, &generationID, &certID, &expires, &state, &consumed, &finished, &failure, &version)
	if err == nil {
		did, e := domain.ParseDeliveryID(deliveryID)
		if e != nil {
			return port.QueriedCertificate{}, e
		}
		gid, e := domain.ParseLeafKeyGenerationID(generationID)
		if e != nil {
			return port.QueriedCertificate{}, e
		}
		cid, e := domain.ParseCertificateID(certID)
		if e != nil {
			return port.QueriedCertificate{}, e
		}
		facts := domain.DeliveryFacts{ID: did, LeafKeyGenerationID: gid, CertificateID: cid, ExpiresAt: domain.InstantFromUnixMicro(expires), State: domain.DeliveryState(state), Version: domain.Version(version)}
		if consumed.Valid {
			facts.ConsumedAt = domain.InstantFromUnixMicro(consumed.Int64)
		}
		if finished.Valid {
			facts.FinishedAt = domain.InstantFromUnixMicro(finished.Int64)
		}
		if failure.Valid {
			facts.FailureCode = failure.String
		}
		delivery, e := domain.NewDelivery(facts)
		if e != nil {
			return port.QueriedCertificate{}, e
		}
		out.Delivery = &delivery
	} else if err != sql.ErrNoRows {
		return port.QueriedCertificate{}, err
	}
	return out, nil
}

func (r *QueryRepository) ListCertificates(ctx context.Context, query contract.CertificateListQuery, scope port.QueryScope) (contract.Page[port.QueriedCertificate], error) {
	if err := checkContext(ctx); err != nil {
		return contract.Page[port.QueriedCertificate]{}, err
	}
	if err := query.Validate(); err != nil {
		return contract.Page[port.QueriedCertificate]{}, failed("validate certificate list", err)
	}
	if err := r.validateScope(scope); err != nil {
		return contract.Page[port.QueriedCertificate]{}, failed("validate certificate scope", err)
	}
	b := r.builder()
	conditions := []string{r.certificateScopePredicate(b, scope, query.AuthorityID)}
	appendCondition(&conditions, r.contains(b, r.subjectCommonNameExpr(), query.Search))
	if query.ExpiresBefore != nil {
		conditions = append(conditions, "c.not_after < "+b.Add(query.ExpiresBefore.UnixMicro()))
	}
	if query.Revoked != nil {
		expr := "EXISTS (SELECT 1 FROM revocations rv WHERE rv.issuer_ca_key_generation_id = c.issuer_ca_key_generation_id AND rv.serial_hex = c.serial_hex)"
		if !*query.Revoked {
			expr = "NOT " + expr
		}
		conditions = append(conditions, expr)
	}
	if query.Affected != nil {
		expr := "EXISTS (SELECT 1 FROM transition_impacts ti WHERE ti.certificate_id = c.id)"
		if !*query.Affected {
			expr = "NOT " + expr
		}
		conditions = append(conditions, expr)
	}
	limit, tail := addPageClause(b, &conditions, "c.id", query.Page)
	ids, next, err := r.selectIDs(ctx, "SELECT c.id FROM certificates c WHERE "+joinConditions(conditions)+tail, b.Args(), limit)
	if err != nil {
		return contract.Page[port.QueriedCertificate]{}, err
	}
	items := make([]port.QueriedCertificate, 0, len(ids))
	for _, raw := range ids {
		id, e := domain.ParseCertificateID(raw)
		if e != nil {
			return contract.Page[port.QueriedCertificate]{}, failed("decode certificate id", e)
		}
		item, e := r.queriedCertificate(ctx, id)
		if e != nil {
			return contract.Page[port.QueriedCertificate]{}, failed("read certificate", e)
		}
		items = append(items, item)
	}
	return pageResult(items, next), nil
}

func (r *QueryRepository) GetCertificate(ctx context.Context, id domain.CertificateID, scope port.QueryScope) (port.QueriedCertificate, error) {
	if err := checkContext(ctx); err != nil {
		return port.QueriedCertificate{}, err
	}
	if err := r.validateScope(scope); err != nil {
		return port.QueriedCertificate{}, failed("validate certificate scope", err)
	}
	b := r.builder()
	idPlaceholder := b.Add(string(id))
	predicate := r.certificateScopePredicate(b, scope, nil)
	query := "SELECT EXISTS (SELECT 1 FROM certificates c WHERE c.id = " + idPlaceholder + " AND " + predicate + ")"
	var exists bool
	if err := r.queryRow(ctx, query, b.Args()...).Scan(&exists); err != nil {
		return port.QueriedCertificate{}, failed("check certificate scope", err)
	}
	if !exists {
		return port.QueriedCertificate{}, port.ErrNotFound
	}
	out, err := r.queriedCertificate(ctx, id)
	if err != nil {
		return port.QueriedCertificate{}, failed("read certificate", err)
	}
	return out, nil
}
