// query.go implements QueryService (docs/backend-implementation.md §3 table
// row "QueryService"): List/Get for Authority, Series, Certificate,
// Revocation, Transition, Import, Job; ListAudit/ExportAudit; GetCRLStatus;
// ReadPublicCA.
//
// §5 lists Query's only dependencies as "ReadStore, Authorizer" -- both
// already part of CommonDeps -- so this file needs no dedicated XDeps type,
// unlike SettingsDeps/etc.
//
// Every method here follows §3's "검색·상세마다 권한 재확인": Validate the
// command, gate on the principal, then inside ONE ReadStore.Read re-check
// the session (requireCurrentAuth) and re-authorize (Authorizer.Authorize)
// before touching the store, exactly like settings_service.go's Get. Nothing
// here ever opens a Write -- a query answers a question, it never commits
// (§4 "사전 준비용 읽기 결과는 commit 권한이 아니다").
//
// port.QueryRepository (queries.go) owns permission filtering and paging;
// this file's only jobs per its own doc comment are (1) building the
// port.QueryScope from the principal -- never from a caller-supplied id
// (§2) -- and (2) mapping the returned stored records onto contract views,
// computing every time-derived field (Expired, Pending) against a clock
// read inside this same Read, never carried in as an argument.
package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// QueryService implements every method port.QueryRepository backs
// (docs/backend-implementation.md §3).
type QueryService struct {
	deps CommonDeps
}

// NewQueryService constructs the service, failing fast on a missing
// dependency (§5 "필수 의존성이 nil이면 시작 시 실패한다").
func NewQueryService(deps CommonDeps) (*QueryService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &QueryService{deps: deps}, nil
}

// ---- admin gate, scope and not-found helpers shared by every method ----

// errCodeQueryRequiresAdmin is the one code every admin-only query method
// (all but ReadPublicCA) reports when a non-admin principal calls it.
const errCodeQueryRequiresAdmin = "query_requires_admin"

// requireAdminPrincipal is §2's "MVP Authorization은 전체 관리자만 허용한다"
// applied to the read side: every method here except ReadPublicCA (the one
// documented anonymous/public exception -- see port.QueryScope's own doc
// comment on its Public field) requires an admin session, matching the
// static gate every other service in this package uses before opening its
// transaction (e.g. SettingsService.Get).
func requireAdminPrincipal(principal contract.Principal) error {
	if principal.IsAdmin() {
		return nil
	}
	return contract.NewAppError(contract.ErrorKindForbidden, errCodeQueryRequiresAdmin,
		"this query requires an administrator session")
}

// adminScope is the port.QueryScope every admin-gated method passes to the
// store: MVP Authorization has exactly one non-public role, the global
// administrator, and port.QueryScope's own doc comment names All as
// precisely that case ("MVP Authorization allows only the global
// administrator, which is the case this represents"). It is never built
// from a caller-supplied AuthorityID (§2).
func adminScope() port.QueryScope { return port.QueryScope{All: true} }

// publicCAScope is ReadPublicCA's scope selection: an admin session sees
// exactly what adminScope grants everywhere else, and every other principal
// (anonymous, in practice -- this is the one path a request without a
// session reaches, per port.QueryRepository.ReadPublicCA's own doc comment)
// is treated as the public reader the CA certificate is genuinely served to.
func publicCAScope(principal contract.Principal) port.QueryScope {
	if principal.IsAdmin() {
		return adminScope()
	}
	return port.QueryScope{Public: true}
}

// queryNotFound renders api-contract.md's fixed 404 mapping ("404 |
// not_found ... | 대상 없음") for a Get whose id does not exist, or exists
// but is outside the caller's scope -- both cases are made to look
// identical to the caller (port.QueryRepository.GetAuthority's own doc
// comment: "a caller cannot probe for the existence of a range it may not
// see"), so detail must never say which one applies.
//
// Kind is Validation: no value in contract.ErrorKind (contract/errors.go)
// means "no such resource" on its own, and that file's own doc comment
// says the status-code mapping is the adapter's to own, keyed off Code()
// rather than Kind() alone -- so Validation, the same fallback
// contract.FromDomainError itself defaults to, is used here rather than
// inventing a meaning for one of the other five kinds.
func queryNotFound(resource, detail string) error {
	return contract.NewAppError(contract.ErrorKindValidation, "not_found", detail).WithField("resource", resource)
}

// crlPending applies certificate-lifecycle.md's rule ("CRL 발행 실패 시 폐기
// 상태는 유지하고 발행 작업을 재시도한다. 성공 전에는 'CRL 반영 대기/실패'를
// 표시한다") to the two generation counters domain.CRLState already tracks:
// a change is reflected once a published document's generation has caught
// up to it, so anything past that is still "pending" the next publish.
func crlPending(changeGeneration, publishedGeneration int64) bool {
	return changeGeneration > publishedGeneration
}

// ---- Authority ----

func (s *QueryService) ListAuthorities(ctx context.Context, meta contract.RequestMeta, query contract.AuthorityListQuery) (contract.Page[contract.AuthorityView], error) {
	if err := query.Validate(); err != nil {
		return contract.Page[contract.AuthorityView]{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.Page[contract.AuthorityView]{}, err
	}
	var page contract.Page[contract.AuthorityView]
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryListAuthority, port.NewAuthorizationScope()); err != nil {
			return err
		}
		raw, err := tx.Queries().ListAuthorities(ctx, query, adminScope())
		if err != nil {
			return storeError(err, "query_authorities_list_failed", "could not list authorities")
		}
		items := make([]contract.AuthorityView, len(raw.Items))
		for i, a := range raw.Items {
			// CreatedAt zero: authorities carries no created_at column
			// (data-model.md's row lists none), the same gap
			// toAuthorityView's own doc comment already documents.
			items[i] = toAuthorityView(a, domain.Instant{})
		}
		page = contract.Page[contract.AuthorityView]{Items: items, NextCursor: raw.NextCursor}
		return nil
	})
	if err != nil {
		return contract.Page[contract.AuthorityView]{}, err
	}
	return page, nil
}

func (s *QueryService) GetAuthority(ctx context.Context, meta contract.RequestMeta, query contract.AuthorityGetQuery) (contract.AuthorityView, error) {
	if err := query.Validate(); err != nil {
		return contract.AuthorityView{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.AuthorityView{}, err
	}
	var view contract.AuthorityView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryGetAuthority, port.NewAuthorizationScope()); err != nil {
			return err
		}
		a, err := tx.Queries().GetAuthority(ctx, query.AuthorityID, adminScope())
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("authority", "authority not found")
		} else if err != nil {
			return storeError(err, "query_authority_read_failed", "could not read the authority")
		}
		view = toAuthorityView(a, domain.Instant{})
		return nil
	})
	if err != nil {
		return contract.AuthorityView{}, err
	}
	return view, nil
}

// ---- Series ----

// toSeriesView projects a port.SeriesSnapshot into the OpenAPI LeafSeries
// shape.
//
// Two fields are left at their zero value, both flagged for the lead:
//   - CreatedAt: leaf_series carries no created_at column
//     (data-model.md's row lists none) and domain.LeafSeries exposes no
//     accessor for one, the same class of gap toAuthorityView's own doc
//     comment already documents for authorities.
//   - Delivery: the OpenAPI LeafSeries.delivery field would be the series'
//     current key generation's delivery record, but port.DeliveryRepository
//     (delivery.go) offers no non-locking lookup by leaf_key_generation_id
//     or series id -- only GetDeliveryForUpdate(deliveryID), which both
//     locks (wrong for a query) and requires an id this method has no way
//     to obtain. This is a genuine port gap, not a decision made here.
//   - ArchivedAt: domain.LeafSeries exposes IsArchived() but no accessor for
//     the underlying instant, so an archived series cannot report when.
func toSeriesView(snapshot port.SeriesSnapshot) contract.LeafSeriesView {
	series := snapshot.Series
	policy := series.Policy()
	view := contract.LeafSeriesView{
		ID:                    series.ID(),
		Name:                  series.Name(),
		Purpose:               series.Purpose(),
		ManagementAuthorityID: series.ManagementAuthorityID(),
		Validity:              policy.CertificateValidity,
		RotateEvery:           policy.RotateEvery,
		Version:               series.Version(),
		CreatedAt:             domain.Instant{},
	}
	if certID := series.CurrentCertificateID(); certID != "" {
		view.CurrentCertificateID = &certID
	}
	if kgID := series.CurrentKeyGenerationID(); kgID != "" {
		view.CurrentKeyGenerationID = &kgID
		view.RenewalCount = int64(snapshot.CurrentKeyGeneration.RenewalCount())
		view.PriorHistoryUnknown = snapshot.CurrentKeyGeneration.PriorHistoryUnknown()
	}
	return view
}

func (s *QueryService) ListSeries(ctx context.Context, meta contract.RequestMeta, query contract.SeriesListQuery) (contract.Page[contract.LeafSeriesView], error) {
	if err := query.Validate(); err != nil {
		return contract.Page[contract.LeafSeriesView]{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.Page[contract.LeafSeriesView]{}, err
	}
	var page contract.Page[contract.LeafSeriesView]
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryListSeries, port.NewAuthorizationScope()); err != nil {
			return err
		}
		raw, err := tx.Queries().ListSeries(ctx, query, adminScope())
		if err != nil {
			return storeError(err, "query_series_list_failed", "could not list leaf series")
		}
		items := make([]contract.LeafSeriesView, len(raw.Items))
		for i, snap := range raw.Items {
			items[i] = toSeriesView(snap)
		}
		page = contract.Page[contract.LeafSeriesView]{Items: items, NextCursor: raw.NextCursor}
		return nil
	})
	if err != nil {
		return contract.Page[contract.LeafSeriesView]{}, err
	}
	return page, nil
}

func (s *QueryService) GetSeries(ctx context.Context, meta contract.RequestMeta, query contract.SeriesGetQuery) (contract.LeafSeriesView, error) {
	if err := query.Validate(); err != nil {
		return contract.LeafSeriesView{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.LeafSeriesView{}, err
	}
	var view contract.LeafSeriesView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryGetSeries, port.NewAuthorizationScope()); err != nil {
			return err
		}
		snap, err := tx.Queries().GetSeries(ctx, query.SeriesID, adminScope())
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("series", "series not found")
		} else if err != nil {
			return storeError(err, "query_series_read_failed", "could not read the series")
		}
		view = toSeriesView(snap)
		return nil
	})
	if err != nil {
		return contract.LeafSeriesView{}, err
	}
	return view, nil
}

// ---- Certificate ----

// toCertificateView projects a port.QueriedCertificate into the OpenAPI
// Certificate shape. now is read by the caller inside its own Read, never
// threaded in from outside it (the stale-clock rule every Expired/Pending
// computation in this file follows).
//
// CreatedAt is left at its zero value: the certificates table carries no
// created_at column (data-model.md's row lists der_sha256, der,
// key_material_id, issuer_ca_key_generation_id, serial_hex, not_before,
// not_after, subject_json, extensions_json, origin, created_by -- nothing
// else), domain.Certificate exposes no such accessor, and
// port.QueriedCertificate does not carry one either. Certificate schema
// lists created_at as REQUIRED, unlike Revocation's optional one, so this is
// flagged as a blocking gap for the lead, the same class as AuthorityView's
// already-documented one.
func toCertificateView(qc port.QueriedCertificate, now domain.Instant) contract.CertificateView {
	c := qc.Certificate
	view := contract.CertificateView{
		ID:                      c.ID(),
		DERSHA256:               domain.NewFingerprint(c.DER()),
		KeyMaterialID:           c.KeyMaterialID(),
		IssuerCAKeyGenerationID: c.IssuerCAKeyGenerationID(),
		Serial:                  c.Serial(),
		NotBefore:               c.Validity().NotBefore(),
		NotAfter:                c.Validity().NotAfter(),
		Subject:                 contract.NewSubjectView(c.Subject()),
		SANs:                    contract.NewSANViews(c.SANs()),
		Origin:                  contract.CertificateOrigin(c.Origin()),
		SeriesID:                qc.SeriesID,
		Revoked:                 qc.Revoked,
		Affected:                qc.Affected,
		Expired:                 c.IsExpiredAt(now),
		CreatedAt:               domain.Instant{},
	}
	if qc.Delivery != nil {
		view.Delivery = toDeliveryView(*qc.Delivery)
	}
	return view
}

func (s *QueryService) ListCertificates(ctx context.Context, meta contract.RequestMeta, query contract.CertificateListQuery) (contract.Page[contract.CertificateView], error) {
	if err := query.Validate(); err != nil {
		return contract.Page[contract.CertificateView]{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.Page[contract.CertificateView]{}, err
	}
	var page contract.Page[contract.CertificateView]
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryListCertificate, port.NewAuthorizationScope()); err != nil {
			return err
		}
		raw, err := tx.Queries().ListCertificates(ctx, query, adminScope())
		if err != nil {
			return storeError(err, "query_certificates_list_failed", "could not list certificates")
		}
		now := s.deps.Clock.Now()
		items := make([]contract.CertificateView, len(raw.Items))
		for i, qc := range raw.Items {
			items[i] = toCertificateView(qc, now)
		}
		page = contract.Page[contract.CertificateView]{Items: items, NextCursor: raw.NextCursor}
		return nil
	})
	if err != nil {
		return contract.Page[contract.CertificateView]{}, err
	}
	return page, nil
}

func (s *QueryService) GetCertificate(ctx context.Context, meta contract.RequestMeta, query contract.CertificateGetQuery) (contract.CertificateView, error) {
	if err := query.Validate(); err != nil {
		return contract.CertificateView{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.CertificateView{}, err
	}
	var view contract.CertificateView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryGetCertificate, port.NewAuthorizationScope()); err != nil {
			return err
		}
		qc, err := tx.Queries().GetCertificate(ctx, query.CertificateID, adminScope())
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("certificate", "certificate not found")
		} else if err != nil {
			return storeError(err, "query_certificate_read_failed", "could not read the certificate")
		}
		view = toCertificateView(qc, s.deps.Clock.Now())
		return nil
	})
	if err != nil {
		return contract.CertificateView{}, err
	}
	return view, nil
}

// ---- Revocation ----

// toRevocationView projects a domain.Revocation plus its issuer's CRLPending
// flag (computed by the caller from a CRLState read in the same
// transaction, per crlPending's doc comment) into the OpenAPI shape.
//
// CreatedAt is left at its zero value: domain.Revocation exposes no
// accessor for one. Unlike Certificate/LeafSeries, Revocation.created_at is
// NOT in the OpenAPI required set, so this is a minor, not blocking, gap.
func toRevocationView(r domain.Revocation, pending bool) contract.RevocationView {
	view := contract.RevocationView{
		ID:               r.ID(),
		IssuerID:         r.IssuerID(),
		Serial:           r.Serial(),
		RevokedAt:        r.RevokedAt(),
		Reason:           r.Reason(),
		Source:           r.Source(),
		ChangeGeneration: r.ChangeGeneration(),
		CRLPending:       pending,
		Version:          r.Version(),
		CreatedAt:        domain.Instant{},
	}
	if certID := r.CertificateID(); certID != "" {
		view.CertificateID = &certID
	}
	return view
}

// issuerPublishedGeneration reads issuer's current published CRL generation
// through the same non-locking query path GetCRLStatus uses, for
// CRLPending's computation. It is not part of port.QueryRepository's own
// ListRevocations/GetRevocation results (unlike QueriedCertificate, which
// was purpose-built to avoid exactly this kind of per-row follow-up read --
// see its own doc comment), so this is a second store call; ListRevocations
// below memoizes it per issuer within one page to avoid repeating it for
// every row sharing an issuer.
func issuerPublishedGeneration(ctx context.Context, tx port.TxStores, issuer domain.CAKeyGenerationID) (int64, error) {
	state, err := tx.Queries().GetCRLStatus(ctx, issuer, adminScope())
	if err != nil {
		return 0, storeError(err, "query_revocation_crl_state_read_failed", "could not read the issuer's CRL state")
	}
	return state.PublishedGeneration(), nil
}

func (s *QueryService) ListRevocations(ctx context.Context, meta contract.RequestMeta, query contract.RevocationListQuery) (contract.Page[contract.RevocationView], error) {
	if err := query.Validate(); err != nil {
		return contract.Page[contract.RevocationView]{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.Page[contract.RevocationView]{}, err
	}
	var page contract.Page[contract.RevocationView]
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryListRevocation, port.NewAuthorizationScope()); err != nil {
			return err
		}
		raw, err := tx.Queries().ListRevocations(ctx, query, adminScope())
		if err != nil {
			return storeError(err, "query_revocations_list_failed", "could not list revocations")
		}
		published := map[domain.CAKeyGenerationID]int64{}
		items := make([]contract.RevocationView, len(raw.Items))
		for i, r := range raw.Items {
			gen, ok := published[r.IssuerID()]
			if !ok {
				gen, err = issuerPublishedGeneration(ctx, tx, r.IssuerID())
				if err != nil {
					return err
				}
				published[r.IssuerID()] = gen
			}
			items[i] = toRevocationView(r, crlPending(r.ChangeGeneration(), gen))
		}
		page = contract.Page[contract.RevocationView]{Items: items, NextCursor: raw.NextCursor}
		return nil
	})
	if err != nil {
		return contract.Page[contract.RevocationView]{}, err
	}
	return page, nil
}

func (s *QueryService) GetRevocation(ctx context.Context, meta contract.RequestMeta, query contract.RevocationGetQuery) (contract.RevocationView, error) {
	if err := query.Validate(); err != nil {
		return contract.RevocationView{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.RevocationView{}, err
	}
	var view contract.RevocationView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryGetRevocation, port.NewAuthorizationScope()); err != nil {
			return err
		}
		r, err := tx.Queries().GetRevocation(ctx, query.RevocationID, adminScope())
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("revocation", "revocation not found")
		} else if err != nil {
			return storeError(err, "query_revocation_read_failed", "could not read the revocation")
		}
		gen, err := issuerPublishedGeneration(ctx, tx, r.IssuerID())
		if err != nil {
			return err
		}
		view = toRevocationView(r, crlPending(r.ChangeGeneration(), gen))
		return nil
	})
	if err != nil {
		return contract.RevocationView{}, err
	}
	return view, nil
}

// ---- Transition ----

func (s *QueryService) ListTransitions(ctx context.Context, meta contract.RequestMeta, query contract.TransitionListQuery) (contract.Page[contract.TransitionView], error) {
	if err := query.Validate(); err != nil {
		return contract.Page[contract.TransitionView]{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.Page[contract.TransitionView]{}, err
	}
	var page contract.Page[contract.TransitionView]
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryListTransition, port.NewAuthorizationScope()); err != nil {
			return err
		}
		raw, err := tx.Queries().ListTransitions(ctx, query, adminScope())
		if err != nil {
			return storeError(err, "query_transitions_list_failed", "could not list transitions")
		}
		// The OpenAPI Transition list item is the same full shape as Get's
		// (both $ref the same Transition schema), so each row needs its own
		// impacts. port.QueryRepository.ListTransitions does not bundle them
		// the way QueriedCertificate bundles Revoked/Affected/Delivery for
		// Certificate -- unlike GetTransition, which returns them for free
		// via QueriedTransition -- so this is a genuine per-row follow-up
		// read; toTransitionView (transition.go) already does exactly this
		// non-locking read and is reused here rather than duplicated.
		// Flagged for the lead as the same class of gap ListRevocations'
		// issuerPublishedGeneration works around above.
		items := make([]contract.TransitionView, len(raw.Items))
		for i, t := range raw.Items {
			view, err := toTransitionView(ctx, tx, t)
			if err != nil {
				return err
			}
			items[i] = view
		}
		page = contract.Page[contract.TransitionView]{Items: items, NextCursor: raw.NextCursor}
		return nil
	})
	if err != nil {
		return contract.Page[contract.TransitionView]{}, err
	}
	return page, nil
}

func (s *QueryService) GetTransition(ctx context.Context, meta contract.RequestMeta, query contract.TransitionGetQuery) (contract.TransitionView, error) {
	if err := query.Validate(); err != nil {
		return contract.TransitionView{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.TransitionView{}, err
	}
	var view contract.TransitionView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryGetTransition, port.NewAuthorizationScope()); err != nil {
			return err
		}
		queried, err := tx.Queries().GetTransition(ctx, query.TransitionID, adminScope())
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("transition", "transition not found")
		} else if err != nil {
			return storeError(err, "query_transition_read_failed", "could not read the transition")
		}
		// toTransitionView re-reads impacts itself; queried.Impacts is
		// unused here (a small, harmless double-read within the one
		// transaction, not a correctness issue) so Get shares its mapping
		// with List instead of duplicating toTransitionView's logic.
		v, err := toTransitionView(ctx, tx, queried.Transition)
		if err != nil {
			return err
		}
		view = v
		return nil
	})
	if err != nil {
		return contract.TransitionView{}, err
	}
	return view, nil
}

// ---- Import ----

func (s *QueryService) ListImports(ctx context.Context, meta contract.RequestMeta, query contract.ImportListQuery) (contract.Page[contract.ImportResultView], error) {
	if err := query.Validate(); err != nil {
		return contract.Page[contract.ImportResultView]{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.Page[contract.ImportResultView]{}, err
	}
	var page contract.Page[contract.ImportResultView]
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryListImport, port.NewAuthorizationScope()); err != nil {
			return err
		}
		raw, err := tx.Queries().ListImports(ctx, query, adminScope())
		if err != nil {
			return storeError(err, "query_imports_list_failed", "could not list import batches")
		}
		items := make([]contract.ImportResultView, len(raw.Items))
		for i, b := range raw.Items {
			// b.Result is already the exact OpenAPI ImportResult shape,
			// built once at commit time (importing.go's commitImport);
			// there is nothing left to project.
			items[i] = b.Result
		}
		page = contract.Page[contract.ImportResultView]{Items: items, NextCursor: raw.NextCursor}
		return nil
	})
	if err != nil {
		return contract.Page[contract.ImportResultView]{}, err
	}
	return page, nil
}

func (s *QueryService) GetImport(ctx context.Context, meta contract.RequestMeta, query contract.ImportGetQuery) (contract.ImportResultView, error) {
	if err := query.Validate(); err != nil {
		return contract.ImportResultView{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.ImportResultView{}, err
	}
	id, err := domain.ParseImportBatchID(query.ImportID)
	if err != nil {
		return contract.ImportResultView{}, contract.FromDomainError(err)
	}
	var view contract.ImportResultView
	err = s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryGetImport, port.NewAuthorizationScope()); err != nil {
			return err
		}
		b, err := tx.Queries().GetImport(ctx, id, adminScope())
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("import", "import batch not found")
		} else if err != nil {
			return storeError(err, "query_import_read_failed", "could not read the import batch")
		}
		view = b.Result
		return nil
	})
	if err != nil {
		return contract.ImportResultView{}, err
	}
	return view, nil
}

// ---- Job ----

// toJobView projects a port.Job into the OpenAPI Job shape. Payload/
// PayloadVersion/DedupKey/LeaseUntil are deliberately never exposed
// (port.Job's own field set is a superset of the public schema).
func toJobView(j port.Job) contract.JobView {
	return contract.JobView{
		ID:            j.ID,
		Kind:          j.Kind,
		State:         j.State,
		LastErrorCode: j.LastErrorCode,
		AvailableAt:   j.AvailableAt,
		AttemptCount:  j.AttemptCount,
		Version:       j.Version,
	}
}

func (s *QueryService) ListJobs(ctx context.Context, meta contract.RequestMeta, query contract.JobListQuery) (contract.Page[contract.JobView], error) {
	if err := query.Validate(); err != nil {
		return contract.Page[contract.JobView]{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.Page[contract.JobView]{}, err
	}
	var page contract.Page[contract.JobView]
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryListJob, port.NewAuthorizationScope()); err != nil {
			return err
		}
		raw, err := tx.Queries().ListJobs(ctx, query, adminScope())
		if err != nil {
			return storeError(err, "query_jobs_list_failed", "could not list jobs")
		}
		items := make([]contract.JobView, len(raw.Items))
		for i, j := range raw.Items {
			items[i] = toJobView(j)
		}
		page = contract.Page[contract.JobView]{Items: items, NextCursor: raw.NextCursor}
		return nil
	})
	if err != nil {
		return contract.Page[contract.JobView]{}, err
	}
	return page, nil
}

func (s *QueryService) GetJob(ctx context.Context, meta contract.RequestMeta, query contract.JobGetQuery) (contract.JobView, error) {
	if err := query.Validate(); err != nil {
		return contract.JobView{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.JobView{}, err
	}
	var view contract.JobView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryGetJob, port.NewAuthorizationScope()); err != nil {
			return err
		}
		j, err := tx.Queries().GetJob(ctx, query.JobID, adminScope())
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("job", "job not found")
		} else if err != nil {
			return storeError(err, "query_job_read_failed", "could not read the job")
		}
		view = toJobView(j)
		return nil
	})
	if err != nil {
		return contract.JobView{}, err
	}
	return view, nil
}

// ---- Audit ----

func (s *QueryService) ListAudit(ctx context.Context, meta contract.RequestMeta, query contract.AuditListQuery) (contract.Page[contract.AuditEventView], error) {
	if err := query.Validate(); err != nil {
		return contract.Page[contract.AuditEventView]{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.Page[contract.AuditEventView]{}, err
	}
	var page contract.Page[contract.AuditEventView]
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryListAudit, port.NewAuthorizationScope()); err != nil {
			return err
		}
		// ListAudit already returns contract.AuditEventView (port/queries.go's
		// one documented exception to "return stored records, not views"),
		// so there is nothing left to map.
		raw, err := tx.Queries().ListAudit(ctx, query, adminScope())
		if err != nil {
			return storeError(err, "query_audit_list_failed", "could not list audit events")
		}
		page = raw
		return nil
	})
	if err != nil {
		return contract.Page[contract.AuditEventView]{}, err
	}
	return page, nil
}

// ExportAudit applies query's filter under the identical scope ListAudit
// uses (§3 "감사 export는 QueryService가 같은 권한 필터를 적용한 iterator를
// 반환") and hands the resulting iterator to consume before returning.
//
// It takes a callback rather than returning contract.AuditEventIterator
// directly because port.ReadStore.Read's only shape is
// func(context.Context, func(TxStores) error) error -- there is no channel
// for a value to escape the callback and outlive the transaction it was
// read under. port.QueryRepository.IterateAudit's own doc comment notes
// "the caller owns Close"; the only place that Close can safely run without
// risking a cursor that outlives its transaction is inside this same Read,
// so the export is driven to completion (or the caller's own early return)
// entirely within it. This shapes the eventual HTTP/CLI adapter: it must
// pass in a writer-driving callback (streaming JSON/CSV as it iterates),
// not receive a bare iterator to hold across a request. Flagged for the
// lead as a design consequence of the fixed ReadStore.Read signature, not a
// product-behavior guess.
func (s *QueryService) ExportAudit(ctx context.Context, meta contract.RequestMeta, query contract.AuditExportQuery, consume func(contract.AuditEventIterator) error) error {
	if err := query.Validate(); err != nil {
		return err
	}
	if consume == nil {
		return contract.NewAppError(contract.ErrorKindValidation, "audit_export_consumer_missing",
			"an audit export requires a consumer to drain the stream")
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return err
	}
	return s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryExportAudit, port.NewAuthorizationScope()); err != nil {
			return err
		}
		it, err := tx.Queries().IterateAudit(ctx, query, adminScope())
		if err != nil {
			return storeError(err, "query_audit_export_failed", "could not open the audit export stream")
		}
		defer it.Close()
		return consume(it)
	})
}

// ---- CRL status ----

// toCRLStatusView projects a domain.CRLState plus the two facts it does not
// itself carry -- the published document's next_update (crl_documents, read
// separately since CRLState only remembers the document's id) and the CRL
// publish job's last_error_code (jobs, since crl_states has no such column:
// data-model.md's row lists ca_key_generation_id, max_reserved_number_hex,
// revocation_generation, published_crl_id, next_publish_at,
// publication_state, signing_ca_certificate_id, version -- nothing else) --
// into the OpenAPI CRLStatus shape.
//
// Expired uses domain.Instant.IsExpiredAt, the project-wide "now >=
// expires_at" rule already codified there, against next_update: a CRL is
// itself only valid until next_update, mirroring how Certificate.Expired
// uses the same method against its own NotAfter.
//
// Pending reuses crlPending's doc-cited definition at the CA level: the
// published document has not yet caught up to the latest revocation
// generation.
func toCRLStatusView(state domain.CRLState, nextUpdate *domain.Instant, lastErrorCode string, now domain.Instant) contract.CRLStatusView {
	view := contract.CRLStatusView{
		RevocationGeneration: state.RevocationGeneration(),
		PublicationState:     state.PublicationState(),
		Pending:              crlPending(state.RevocationGeneration(), state.PublishedGeneration()),
		LastErrorCode:        lastErrorCode,
		Version:              state.Version(),
	}
	if number := state.PublishedNumber(); !number.IsZero() {
		view.Number = &number
		generation := state.PublishedGeneration()
		view.CoveredGeneration = &generation
	}
	if next := state.NextPublishAt(); !next.IsZero() {
		view.NextPublishAt = &next
	}
	if nextUpdate != nil {
		view.NextUpdate = nextUpdate
		view.Expired = nextUpdate.IsExpiredAt(now)
	}
	return view
}

func (s *QueryService) GetCRLStatus(ctx context.Context, meta contract.RequestMeta, query contract.GetCRLStatusQuery) (contract.CRLStatusView, error) {
	if err := query.Validate(); err != nil {
		return contract.CRLStatusView{}, err
	}
	if err := requireAdminPrincipal(meta.Principal); err != nil {
		return contract.CRLStatusView{}, err
	}
	var view contract.CRLStatusView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryGetCRLStatus, port.NewAuthorizationScope()); err != nil {
			return err
		}
		state, err := tx.Queries().GetCRLStatus(ctx, query.CAKeyGenerationID, adminScope())
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("crl_status", "CRL status not found for this CA key generation")
		} else if err != nil {
			return storeError(err, "query_crl_status_read_failed", "could not read the CRL status")
		}

		var nextUpdate *domain.Instant
		if publishedID := state.PublishedDocumentID(); publishedID != "" {
			doc, err := tx.CRLs().GetDocument(ctx, publishedID)
			if err != nil {
				return storeError(err, "query_crl_document_read_failed", "could not read the published CRL document")
			}
			if !doc.NextUpdate.IsZero() {
				next := doc.NextUpdate
				nextUpdate = &next
			}
		}

		lastErrorCode := ""
		job, err := tx.Jobs().GetByDedupKey(ctx, CRLDedupKey(query.CAKeyGenerationID))
		if err == nil {
			lastErrorCode = job.LastErrorCode
		} else if !errors.Is(err, port.ErrNotFound) {
			return storeError(err, "query_crl_job_read_failed", "could not read the CRL publication job")
		}

		view = toCRLStatusView(state, nextUpdate, lastErrorCode, s.deps.Clock.Now())
		return nil
	})
	if err != nil {
		return contract.CRLStatusView{}, err
	}
	return view, nil
}

// ---- Public CA ----

// ReadPublicCA returns an authority's current issuance CA certificate
// unmapped: the /pki/ca-certificates/{id}/... routes serve PEM/DER, not a
// JSON view, so there is no wire shape to project onto here (unlike every
// other method in this file) -- the HTTP adapter encodes the returned
// domain.Certificate's DER directly.
//
// Unlike every other method here, this one does NOT gate on
// meta.Principal.IsAdmin(): it is port.QueryRepository.ReadPublicCA's one
// documented exception, reachable from a request with no session at all
// (port/queries.go's own doc comment). requireCurrentAuth and Authorize are
// still called uniformly with every other method (§3 "검색·상세마다 권한
// 재확인"; requireCurrentAuth is a no-op for a non-admin principal, and the
// concrete Authorizer implementation is what is expected to special-case
// this one Action for an anonymous principal, per port.Authorizer's own doc
// comment that MVP's admin-only restriction is a policy the interface does
// not itself encode).
func (s *QueryService) ReadPublicCA(ctx context.Context, meta contract.RequestMeta, query contract.ReadPublicCAQuery) (domain.Certificate, error) {
	if err := query.Validate(); err != nil {
		return domain.Certificate{}, err
	}
	var certificate domain.Certificate
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryReadPublicCA, port.NewAuthorizationScope()); err != nil {
			return err
		}
		c, err := tx.Queries().ReadPublicCA(ctx, query.AuthorityID, publicCAScope(meta.Principal))
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("authority", "authority has no public CA certificate")
		} else if err != nil {
			return storeError(err, "query_public_ca_read_failed", "could not read the public CA certificate")
		}
		certificate = c
		return nil
	})
	if err != nil {
		return domain.Certificate{}, err
	}
	return certificate, nil
}
