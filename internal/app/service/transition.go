// transition.go implements TransitionService (docs/backend-implementation.md
// §3 TransitionService row): Create, SetTarget, ConfirmDeployment, Complete
// -- plus Close, described below.
//
// §5 is explicit that Revocation/Transition need "추가 외부 I/O 없음" beyond
// the shared app-internal applyRevocations function (revocations.go) -- there
// is no separate TransitionDeps signing/crypto dependency, only CommonDeps.
//
// §13 ruling 1 fixes the state machine this file wires up:
// in_progress -> externally_completed -> closed, with the successor
// authority expressed by a nullable TargetAuthorityID rather than a
// dedicated "target set" state. domain/transition.go already implements
// SetTarget/ConfirmDeployment/Complete/Close and the two Facts structs the
// ruling names (TransitionClosureFacts, TransitionTerminationFacts); this
// file's job is to gather those facts from stored relations and call them.
//
// Complete reads TransitionClosureFacts from two sources, both now backed by
// real port methods added for this file (TransitionRepository.
// ListImpacts existed already; ListDeploymentConfirmations was added
// alongside this file once the lead confirmed the earlier report that no
// production-reachable method could read confirmations back):
//   - AllImpactsAddressed: every ListImpacts row is either resolved
//     (RecordReplacement ran) or its underlying certificate has since
//     expired (domain.TransitionClosureFacts' own doc comment: "explicitly
//     acknowledged as not needing one (e.g. already expired)" -- there is no
//     separate acknowledgment flag anywhere in the schema, so "already
//     expired" is read directly off the certificate's own validity window,
//     which is the one case the doc names).
//   - ManualDeploymentConfirmed: true once ListDeploymentConfirmations
//     returns at least one row for this transition, regardless of which
//     DeploymentAction it recorded. No doc distinguishes certificate_installed/
//     trust_added/trust_removed for THIS purpose (the distinction §13
//     ruling 2 draws is about what certificate_installed implies for key
//     reuse, not about which actions count toward "the deployment was
//     confirmed") -- flagged for the lead as a judgment call, not a literal
//     reading of a settled rule.
//
// Close is the separate domain transition §13 ruling 1 requires
// ("closed는 원본 CA의 게시 종료 조건까지 충족한 상태이며 Complete만으로
// 추정하지 않는다... CRL 종료와 연결하는 별도 도메인 전이가 필요하다") and is
// NOT one of §3's four TransitionService methods -- there is no OpenAPI
// schema or table row for it. Placement decision (naming/file-split is the
// dev team's call per the lead's own framing): it lives here, as a fifth
// TransitionService method, because it is fundamentally a transition-row
// state change and every other transition-row mutation already lives in
// this file. Its input is TransitionCloseCommand, a package-local type
// rather than a new contract.TransitionCloseCommand: contract/transition.go
// is outside this developer's assigned files (transition.go/
// transition_test.go/crl.go/crl_test.go only), and adding a client-facing
// wire schema for an operation with no OpenAPI entry is a product-surface
// decision this developer is not positioned to make -- the same restraint
// §3's own CRLPublishCommand shows for a worker-only trigger, just one layer
// further out (that command at least got a home in contract/crl.go already;
// this one has no such precedent to extend, so it stays local). For the same
// reason, Close authorizes against its own port.ActionTransitionClose: §13
// ruling 5 declares one Action per operation, and Complete and Close are
// different operations on different preconditions, so sharing Complete's
// action would leave an Authorizer unable to tell them apart the moment the
// role model stops being admin-only. The constant was added by the lead
// alongside this service; the command type below stays local because a new
// wire schema is a product-surface decision, which the action name is not.
//
// Close is gated to an administrator, not to an internal/worker principal:
// unlike CRLService.Publish (explicitly "worker/maintenance 전용" per §3),
// no doc names an automatic or worker-triggered path that closes a
// transition, and every other CA-retirement action in this codebase is
// consistently an explicit administrator act (certificate-lifecycle.md on
// key destruction: "전체 관리자가 명시적으로 파기할 수 있다"). Close only
// READS whether the source authority's CRLState has already reached
// PublicationStateClosed -- it does not itself call domain.CRLState.Close
// (whose own CRLClosureFacts -- AllCoveredCertificatesExpired,
// FinalCRLCoversLastExpiry -- are gathered from the CA/leaf domain area, its
// own doc comment says "which this file must not define"). Nothing in §3's
// CRLService or MaintenanceService method tables names the entry point that
// calls CRLState.Close either, so that trigger is a separate, not-yet-
// implemented piece of work belonging to whichever service ends up owning
// CA retirement (Authority's future DestroyKey, or Maintenance) -- outside
// this developer's assigned files. Close here is honest about that: it
// reflects whatever CRLState.PublicationState currently says, and returns
// transition_publication_not_ended (via domain.Transition.Close's own
// policy error) until something else closes the CRL state first.
package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// TransitionDeps is TransitionService's dependency set: CommonDeps only,
// per §5's "추가 외부 I/O 없음; app 내부 revocationChanges 공통 함수"
// (applyRevocations, defined in revocations.go and shared with Distribution/
// Import/RevocationService).
type TransitionDeps struct {
	CommonDeps
}

// Validate reports the first missing dependency.
func (d TransitionDeps) Validate() error {
	return d.CommonDeps.Validate()
}

// TransitionService implements the Create/SetTarget/ConfirmDeployment
// methods (docs/backend-implementation.md §3 TransitionService row). See the
// package-level doc comment above for why Complete is not here.
type TransitionService struct {
	deps TransitionDeps
}

// NewTransitionService constructs the service, failing fast on a missing
// dependency rather than at the first request.
func NewTransitionService(deps TransitionDeps) (*TransitionService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &TransitionService{deps: deps}, nil
}

// transitionScope is §14.6's multi-scope audit/authorization rule applied to
// a transition: "전환으로 여러 CA가 관련된 작업은 기존 복수 scope 감사
// 규칙을 적용한다". A transition always names a source authority and,
// once SetTarget has run, a target authority too -- both are genuinely
// relevant CAs for this event, unlike a plain leaf event's single management
// scope (§14.6 forbids replicating an ancestor there, but that rule is about
// a SINGLE leaf's own management chain, not a transition's two named CAs).
func transitionScope(t domain.Transition) []domain.AuthorityID {
	scope := []domain.AuthorityID{t.SourceAuthorityID()}
	if target := t.TargetAuthorityID(); target != "" {
		scope = append(scope, target)
	}
	return scope
}

// toTransitionView projects a domain.Transition plus its stored impacts into
// the OpenAPI response shape. CreatedAt is t.ReportedAt(): unlike
// AuthorityView's CreatedAt gap (authority.go's own documented finding),
// ca_transitions genuinely has a reported_at column, so there is nothing
// missing here.
func toTransitionView(ctx context.Context, tx port.TxStores, t domain.Transition) (contract.TransitionView, error) {
	impacts, err := tx.Transitions().ListImpacts(ctx, t.ID())
	if err != nil {
		return contract.TransitionView{}, storeError(err, "transition_impacts_read_failed",
			"could not read the transition's impact list")
	}
	view := contract.TransitionView{
		ID:                         t.ID(),
		SourceAuthorityID:          t.SourceAuthorityID(),
		Mode:                       t.Mode(),
		State:                      contract.TransitionStateViewOf(t.State()),
		ExternalTransitionComplete: t.IsExternallyCompleted() || t.IsClosed(),
		CAPublicationClosed:        t.IsClosed(),
		Impacts:                    toImpactViews(impacts),
		Version:                    t.Version(),
		CreatedAt:                  t.ReportedAt(),
	}
	if target := t.TargetAuthorityID(); target != "" {
		view.TargetAuthorityID = &target
	}
	return view, nil
}

func toImpactViews(impacts []domain.TransitionImpact) []contract.ImpactView {
	if len(impacts) == 0 {
		return nil
	}
	out := make([]contract.ImpactView, 0, len(impacts))
	for _, imp := range impacts {
		v := contract.ImpactView{CertificateID: imp.CertificateID()}
		if imp.IsResolved() {
			replacement := imp.ReplacementCertificateID()
			reissuedAt := imp.ReissuedAt()
			v.ReplacementCertificateID = &replacement
			v.ReissuedAt = &reissuedAt
		}
		out = append(out, v)
	}
	return out
}

// ---- Create ----

// Create reports a normal or emergency CA transition
// (docs/backend-implementation.md §3 "Create: TransitionCreate → Transition";
// §8 "긴급 전환" row). There is no out-of-transaction preparation: unlike
// Authority/Issuance Create, nothing here signs or generates a key, so the
// entire operation -- reading the affected rows, stopping issuance,
// recording impacts, the parent revocation, inserting the transition row --
// fits in the single Write §4 requires, with no expensive work to shield
// from a retry.
//
// Table's own split: "긴급 Create는 차단·영향·부모 폐기 함께 반영한다" names
// three EMERGENCY-only additions layered on top of a baseline every mode
// performs (stop the source's own issuance, create the transition row,
// audit) -- certificate-lifecycle.md's "정상 CA 교체" section requires the
// stop for a normal transition too ("기존 CA는 신규 발급 중지 상태로
// 전환한다"), but explicitly forbids the other two for normal mode ("기존
// 인증서를 정상 교체만을 이유로 즉시 폐기하지 않는다"; no impact-list
// language appears outside the "CA 키 유출 시 긴급 처리" section).
func (s *TransitionService) Create(ctx context.Context, meta contract.MutationMeta, cmd contract.TransitionCreateCommand) (contract.TransitionView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TransitionView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.TransitionView{}, contract.NewAppError(contract.ErrorKindForbidden, "transition_requires_admin",
			"reporting a CA transition requires an administrator session")
	}
	mode, err := cmd.Mode.Domain()
	if err != nil {
		return contract.TransitionView{}, err
	}

	var result contract.TransitionView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}

		source, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.SourceAuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "transition_source_not_found",
				"source authority does not exist").WithField("authority_id", string(cmd.SourceAuthorityID))
		} else if err != nil {
			return storeError(err, "transition_source_read_failed", "could not read the source authority")
		}

		var target domain.Authority
		if cmd.TargetAuthorityID != "" {
			target, err = tx.PKI().GetIssuerForUpdate(ctx, cmd.TargetAuthorityID)
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "transition_target_not_found",
					"target authority does not exist").WithField("authority_id", string(cmd.TargetAuthorityID))
			} else if err != nil {
				return storeError(err, "transition_target_read_failed", "could not read the target authority")
			}
		}

		// §2/§14.6: scope is built from the rows just read, never trusted
		// directly off the command, even though the two agree here by
		// construction (existence has just been confirmed).
		scope := []domain.AuthorityID{source.ID()}
		if target.ID() != "" {
			scope = append(scope, target.ID())
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTransitionCreate, port.NewAuthorizationScope(scope...)); err != nil {
			return err
		}

		now := s.deps.Clock.Now()

		touchedAuthorities := []domain.AuthorityID{source.ID()}
		if _, _, err := stopIssuanceIfEnabled(ctx, tx, source); err != nil {
			return err
		}

		var impactCertificateIDs []domain.CertificateID
		if mode == domain.TransitionModeEmergency {
			touched, leafIDs, err := emergencyBlockAndImpact(ctx, tx, source)
			if err != nil {
				return err
			}
			touchedAuthorities = append(touchedAuthorities, touched...)
			impactCertificateIDs = leafIDs

			if source.Kind() == domain.AuthorityKindIntermediate {
				parentScope, err := revokeUnderParent(ctx, tx, s.deps.IDs, meta, source, now)
				if err != nil {
					return err
				}
				if parentScope != "" {
					touchedAuthorities = append(touchedAuthorities, parentScope)
				}
			}
		}

		transitionID, err := domain.ParseTransitionID(s.deps.IDs.NewUUID())
		if err != nil {
			return contract.FromDomainError(err)
		}
		transition, err := domain.NewTransition(domain.TransitionFacts{
			ID:                transitionID,
			SourceAuthorityID: source.ID(),
			TargetAuthorityID: cmd.TargetAuthorityID,
			Mode:              mode,
			State:             domain.TransitionStateInProgress,
			ReportedBy:        meta.Principal.AccountID(),
			ReportedAt:        now,
			Reason:            cmd.Reason,
		})
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Transitions().Insert(ctx, transition); err != nil {
			return storeError(err, "transition_store_failed", "could not store the transition")
		}
		if err := recordImpacts(ctx, tx, transitionID, impactCertificateIDs); err != nil {
			return err
		}

		if target.ID() != "" {
			touchedAuthorities = append(touchedAuthorities, target.ID())
		}

		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "transition.create",
			TargetType: "transition",
			TargetID:   string(transitionID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{
				"mode": string(mode),
			}},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(dedupAuthorityIDs(touchedAuthorities)...)); err != nil {
			return storeError(err, "transition_audit_failed", "could not record the transition audit event")
		}

		view, err := toTransitionView(ctx, tx, transition)
		if err != nil {
			return err
		}
		result = view
		return nil
	})
	if err != nil {
		return contract.TransitionView{}, err
	}
	return result, nil
}

// stopIssuanceIfEnabled stops authority's issuance if, and only if, it is
// currently enabled. An authority that is already stopped, still inventory,
// or archived has nothing further to stop -- there is no documented
// requirement that a transition report be refused just because an
// administrator already stopped issuance manually before reporting it
// (judgment call, flagged in the report), so this is a no-op rather than an
// error in every other case.
func stopIssuanceIfEnabled(ctx context.Context, tx port.TxStores, authority domain.Authority) (domain.Authority, bool, error) {
	if authority.IsArchived() || authority.IssuanceState() != domain.IssuanceStateEnabled {
		return authority, false, nil
	}
	next, err := authority.StopIssuance()
	if err != nil {
		return domain.Authority{}, false, contract.FromDomainError(err)
	}
	if err := tx.PKI().SaveAuthority(ctx, next, authority.Version()); err != nil {
		return domain.Authority{}, false, storeError(err, "transition_authority_stop_failed",
			"could not stop the authority's issuance")
	}
	return next, true, nil
}

// emergencyBlockAndImpact performs the two EMERGENCY-only additions
// data-model.md's ListAffectedDescendants doc comment ties together --
// "the set an emergency transition marks affected/stops issuance for" --
// and returns every authority this touched besides source itself, for the
// caller's audit scope:
//
//  1. Stop issuance for every managed descendant CA (data-model.md "긴급
//     신고 트랜잭션은 source 및 관리 하위 CA 발급을 차단"). PKIRepository.
//     ListAffectedDescendants already returns exactly that closure; only
//     currently-enabled ones are actually stopped (stopIssuanceIfEnabled).
//  2. Record a TransitionImpact for every LEAF certificate managed by
//     source or by one of those descendants -- never a revocation
//     (certificate-lifecycle.md "하위 Leaf는 'CA 유출 영향'으로 표시하며
//     자동으로 개별 CRL 항목을 추가하지 않는다"; planning.md "상위 영향이
//     자동 개별 폐기로 표시되지 않는다").
//
// Judgment call flagged for the lead: certificate-lifecycle.md's only worked
// impact-list example is an Intermediate-source report impacting its OWN
// leaves. Whether a Root-source report's single transition_id should ALSO
// enumerate impacts for every descendant Intermediate's leaves (as
// implemented here) or leave that to separate, later per-Intermediate
// reports is not settled by any doc this developer found. This
// implementation takes the broader reading because ListAffectedDescendants's
// own doc comment ties the descendant set to "an emergency transition marks
// affected/stops issuance for" (singular transition, plural authorities),
// but a narrower reading (impacts only ever cover source's own leaves) is
// equally defensible from the text and was not chosen without flagging it.
func emergencyBlockAndImpact(ctx context.Context, tx port.TxStores, source domain.Authority) ([]domain.AuthorityID, []domain.CertificateID, error) {
	descendants, err := tx.PKI().ListAffectedDescendants(ctx, source.ID())
	if err != nil {
		return nil, nil, storeError(err, "transition_descendants_read_failed", "could not list the source authority's managed descendants")
	}

	affected := make([]domain.Authority, 0, len(descendants)+1)
	affected = append(affected, source)
	touched := make([]domain.AuthorityID, 0, len(descendants))
	for _, d := range descendants {
		if _, _, err := stopIssuanceIfEnabled(ctx, tx, d); err != nil {
			return nil, nil, err
		}
		affected = append(affected, d)
		touched = append(touched, d.ID())
	}

	// The impact ROWS themselves are inserted by the caller once the
	// transition's own id exists (Create inserts the transition row after
	// this function returns, per §8's "source 하위 발급 중지·영향 목록·전환
	// 생성" ordering); this function only gathers WHICH certificate ids the
	// caller must record impacts for.
	var leafCertificateIDs []domain.CertificateID
	for _, a := range affected {
		leafIDs, err := collectLeafCertificateIDs(ctx, tx, a.ID())
		if err != nil {
			return nil, nil, err
		}
		leafCertificateIDs = append(leafCertificateIDs, leafIDs...)
	}
	return touched, leafCertificateIDs, nil
}

// collectLeafCertificateIDs walks every page of QueryRepository.ListCertificates
// for authorityID and returns the leaf (non-CA) certificate ids among them.
// QueryScope{All: true} is used because Create has already authorized the
// caller as the global administrator above this call (§2 MVP note: "MVP
// Authorization은 전체 관리자만 허용한다") -- this is not a second,
// independent access decision, just a repository call reused as a listing
// tool. Rule 1 of QueryRepository's own doc comment ("이 인터페이스는 아무
// 것도 잠그지 않는다") is fine here: nothing this function returns gates a
// later write decision by itself -- it only decides which certificates get an
// (unresolved) impact row, which is idempotent to repeat and carries no
// version of its own.
func collectLeafCertificateIDs(ctx context.Context, tx port.TxStores, authorityID domain.AuthorityID) ([]domain.CertificateID, error) {
	var out []domain.CertificateID
	cursor := ""
	for {
		page, err := tx.Queries().ListCertificates(ctx, contract.CertificateListQuery{
			AuthorityID: &authorityID,
			Page:        contract.PageRequest{Cursor: cursor, Limit: 200},
		}, port.QueryScope{All: true})
		if err != nil {
			return nil, storeError(err, "transition_impact_certificates_read_failed",
				"could not list certificates for the affected authority")
		}
		for _, item := range page.Items {
			if item.SeriesID != nil {
				out = append(out, item.Certificate.ID())
			}
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	return out, nil
}

// recordImpacts records an unresolved TransitionImpact for every certificate
// id, once the transition row (and therefore its id) exists.
func recordImpacts(ctx context.Context, tx port.TxStores, transitionID domain.TransitionID, certificateIDs []domain.CertificateID) error {
	for _, certID := range certificateIDs {
		impact, err := domain.NewTransitionImpact(domain.TransitionImpactFacts{
			TransitionID:  transitionID,
			CertificateID: certID,
		})
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Transitions().AddImpact(ctx, impact); err != nil {
			return storeError(err, "transition_impact_store_failed", "could not record a transition impact")
		}
	}
	return nil
}

// revokeUnderParent is §5/§8's "Intermediate라면 부모 폐기": when the
// compromised source is an Intermediate, its own CA certificate is revoked
// under the issuer that actually signed it, via the shared applyRevocations
// function every other revoking caller uses (§5 "app 내부 revocationChanges
// 공통 함수"). It returns the parent authority id touched, for the caller's
// audit scope, or "" if nothing was revoked (should not happen for a
// well-formed Intermediate, but the caller only appends a non-empty value).
//
// Classification of reason/source, since certificate-lifecycle.md names the
// reason (caCompromise) but not the source enum value: this revocation is
// system-derived from the emergency report, not a direct single-serial
// "revoke this exact record" call the way RevocationService.Revoke is --
// it is the SAME kind of automatic, policy-driven side effect §14.1 defines
// "cascade" to mean ("cascade는 시스템 정책에 따른 파생 폐기를 포함한다"),
// just triggered by a transition report instead of a delivery failure. §14.1's
// key_compromise restriction ("실제 키 유출 신고만 key_compromise를 사용")
// does not apply here: the reason used is ca_compromise, not key_compromise.
func revokeUnderParent(ctx context.Context, tx port.TxStores, ids port.IDGenerator, meta contract.MutationMeta, source domain.Authority, now domain.Instant) (domain.AuthorityID, error) {
	sourceCertID := source.IssuanceCertificateID()
	sourceCert, err := tx.PKI().GetCertificate(ctx, sourceCertID)
	if err != nil {
		return "", storeError(err, "transition_source_certificate_read_failed", "could not read the source authority's own certificate")
	}
	sourceRecord, err := tx.PKI().GetCACertificateRecord(ctx, sourceCertID)
	if err != nil {
		return "", storeError(err, "transition_source_ca_record_read_failed", "could not read the source authority's CA certificate record")
	}
	parentCertID := sourceRecord.IssuerCACertificateID
	if parentCertID == "" {
		return "", contract.NewAppError(contract.ErrorKindUnavailable, "transition_source_has_no_issuer",
			"an intermediate authority's own certificate must have an issuer to revoke it under")
	}
	parentRecord, err := tx.PKI().GetCACertificateRecord(ctx, parentCertID)
	if err != nil {
		return "", storeError(err, "transition_parent_ca_record_read_failed", "could not read the parent CA certificate record")
	}
	parentGeneration, err := tx.PKI().GetCAKeyGeneration(ctx, parentRecord.CAKeyGenerationID)
	if err != nil {
		return "", storeError(err, "transition_parent_key_generation_read_failed", "could not read the parent CA key generation")
	}

	change := RevocationChange{
		IssuerID:      parentRecord.CAKeyGenerationID,
		Serial:        sourceCert.Serial(),
		CertificateID: sourceCertID,
		RevokedAt:     now,
		Reason:        domain.RevocationReasonCACompromise,
		Source:        domain.RevocationSourceCascade,
		AuthorityID:   parentGeneration.AuthorityID,
	}
	revMeta := RevocationMeta{
		Request:   meta.RequestMeta,
		ActorKind: contract.AuditActorAccount,
		ActorID:   string(meta.Principal.AccountID()),
		Action:    "transition.emergency_parent_revoke",
		Now:       now,
		IDs:       ids,
	}
	if _, err := applyRevocations(ctx, tx, []RevocationChange{change}, revMeta); err != nil {
		return "", err
	}
	return parentGeneration.AuthorityID, nil
}

// dedupAuthorityIDs preserves order but drops repeats, so an audit scope
// list never carries the same authority twice (source appearing both as
// itself and, degenerate case, as its own "descendant").
func dedupAuthorityIDs(ids []domain.AuthorityID) []domain.AuthorityID {
	seen := make(map[domain.AuthorityID]bool, len(ids))
	out := make([]domain.AuthorityID, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// ---- SetTarget ----

// SetTarget records or replaces the successor authority while the
// transition is in_progress (docs/backend-implementation.md §3 "SetTarget:
// TransitionPatch → Transition"; §13 ruling 1 "SetTarget은 in_progress 안에서
// 수행한다"). "기존 전환 명령은 Transition version 필수" applies here.
func (s *TransitionService) SetTarget(ctx context.Context, meta contract.MutationMeta, cmd contract.TransitionSetTargetCommand) (contract.TransitionView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TransitionView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.TransitionView{}, contract.NewAppError(contract.ErrorKindForbidden, "transition_requires_admin",
			"changing a transition's target requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.TransitionView{}, err
	}

	var result contract.TransitionView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		t, err := tx.Transitions().GetForUpdate(ctx, cmd.TransitionID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "transition_not_found", "transition does not exist").
				WithField("transition_id", string(cmd.TransitionID))
		} else if err != nil {
			return storeError(err, "transition_read_failed", "could not read the transition")
		}

		target, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.TargetAuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "transition_target_not_found",
				"target authority does not exist").WithField("authority_id", string(cmd.TargetAuthorityID))
		} else if err != nil {
			return storeError(err, "transition_target_read_failed", "could not read the target authority")
		}

		scope := append(transitionScope(t), target.ID())
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTransitionSetTarget, port.NewAuthorizationScope(scope...)); err != nil {
			return err
		}
		if t.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "transition_version_conflict",
				"transition has changed since this request was prepared")
		}

		now := s.deps.Clock.Now()
		next, err := t.SetTarget(target.ID(), now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Transitions().Save(ctx, next, expectedVersion); err != nil {
			return storeError(err, "transition_save_failed", "could not save the transition")
		}

		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "transition.set_target",
			TargetType: "transition",
			TargetID:   string(cmd.TransitionID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(dedupAuthorityIDs(transitionScope(next))...)); err != nil {
			return storeError(err, "transition_audit_failed", "could not record the set-target audit event")
		}

		view, err := toTransitionView(ctx, tx, next)
		if err != nil {
			return err
		}
		result = view
		return nil
	})
	if err != nil {
		return contract.TransitionView{}, err
	}
	return result, nil
}

// ---- ConfirmDeployment ----

// ConfirmDeployment appends one manual, operator-entered deployment
// confirmation (docs/backend-implementation.md §3 "ConfirmDeployment:
// DeploymentInput → Deployment"). domain.Transition.ConfirmDeployment only
// VALIDATES that a confirmation may be recorded right now (in_progress) --
// it returns no new Transition value and bumps no version, because the
// confirmation row itself is the fact being recorded, not a change to the
// transition row (backend-implementation.md §2 "수동 확인 보존": confirmations
// are appended, never folded into the transition's own state). The
// transition is therefore not re-saved here. "기존 전환 명령은 Transition
// version 필수" is still honored as a precondition check against the locked
// row, so a caller acting on a stale view is rejected the same way SetTarget
// rejects one.
func (s *TransitionService) ConfirmDeployment(ctx context.Context, meta contract.MutationMeta, cmd contract.TransitionConfirmDeploymentCommand) (contract.DeploymentView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.DeploymentView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.DeploymentView{}, contract.NewAppError(contract.ErrorKindForbidden, "transition_requires_admin",
			"confirming a transition deployment requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.DeploymentView{}, err
	}
	action, err := cmd.Action.Domain()
	if err != nil {
		return contract.DeploymentView{}, err
	}

	var result contract.DeploymentView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		t, err := tx.Transitions().GetForUpdate(ctx, cmd.TransitionID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "transition_not_found", "transition does not exist").
				WithField("transition_id", string(cmd.TransitionID))
		} else if err != nil {
			return storeError(err, "transition_read_failed", "could not read the transition")
		}

		scope := transitionScope(t)
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTransitionConfirmDeployment, port.NewAuthorizationScope(scope...)); err != nil {
			return err
		}
		if t.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "transition_version_conflict",
				"transition has changed since this request was prepared")
		}

		now := s.deps.Clock.Now()
		if err := t.ConfirmDeployment(now); err != nil {
			return contract.FromDomainError(err)
		}

		confirmation, err := domain.NewDeploymentConfirmation(domain.DeploymentConfirmationFacts{
			TransitionID:  cmd.TransitionID,
			CertificateID: cmd.CertificateID,
			TargetLabel:   cmd.TargetLabel,
			Action:        action,
			ConfirmedBy:   meta.Principal.AccountID(),
			ConfirmedAt:   now,
		})
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Transitions().AddDeploymentConfirmation(ctx, confirmation); err != nil {
			return storeError(err, "transition_confirmation_store_failed", "could not record the deployment confirmation")
		}

		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "transition.confirm_deployment",
			TargetType: "transition",
			TargetID:   string(cmd.TransitionID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{
				"action": string(action),
			}},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(dedupAuthorityIDs(scope)...)); err != nil {
			return storeError(err, "transition_audit_failed", "could not record the confirm-deployment audit event")
		}

		// DeploymentView.ID: domain.DeploymentConfirmation carries no stored id
		// of its own (see contract/transition.go's DeploymentView doc comment
		// -- "deployment_confirmations has no dedicated typed ID in domain").
		// Nothing else in this response is used as a lookup key (there is no
		// GetDeployment method anywhere), so a freshly minted id is used purely
		// as a display/reference value, not a persisted identifier.
		view := contract.DeploymentView{
			ID:          s.deps.IDs.NewUUID(),
			TargetLabel: confirmation.TargetLabel(),
			Action:      contract.NewDeploymentActionView(confirmation.Action()),
			ConfirmedAt: confirmation.ConfirmedAt(),
			ConfirmedBy: confirmation.ConfirmedBy(),
		}
		if certID := confirmation.CertificateID(); certID != "" {
			view.CertificateID = &certID
		}
		result = view
		return nil
	})
	if err != nil {
		return contract.DeploymentView{}, err
	}
	return result, nil
}

// ---- Complete ----

// gatherClosureFacts builds domain.TransitionClosureFacts from stored
// relations, as Complete requires (§13 ruling 1 "Complete는 기존 영향 처리·
// 수동 외부 배포 확인 조건을 검사해 externally_completed로 옮긴다"). now is
// the same instant Complete reads for its own transition, so "already
// expired" is judged against the commit's own moment, not a preparation
// timestamp -- there is no preparation phase here to be stale against, but
// the rule is applied uniformly regardless.
func gatherClosureFacts(ctx context.Context, tx port.TxStores, transitionID domain.TransitionID, now domain.Instant) (domain.TransitionClosureFacts, error) {
	impacts, err := tx.Transitions().ListImpacts(ctx, transitionID)
	if err != nil {
		return domain.TransitionClosureFacts{}, storeError(err, "transition_impacts_read_failed",
			"could not read the transition's impact list")
	}
	allAddressed := true
	for _, imp := range impacts {
		if imp.IsResolved() {
			continue
		}
		cert, err := tx.PKI().GetCertificate(ctx, imp.CertificateID())
		if errors.Is(err, port.ErrNotFound) {
			// No certificate row exists for this impact any more -- nothing
			// left to reissue or wait out. Not a case any doc names
			// explicitly (this codebase never deletes a certificate row),
			// so this is a defensive fallback rather than a documented rule.
			continue
		} else if err != nil {
			return domain.TransitionClosureFacts{}, storeError(err, "transition_impact_certificate_read_failed",
				"could not read an impacted certificate")
		}
		if !cert.IsExpiredAt(now) {
			allAddressed = false
			break
		}
	}

	confirmations, err := tx.Transitions().ListDeploymentConfirmations(ctx, transitionID)
	if err != nil {
		return domain.TransitionClosureFacts{}, storeError(err, "transition_confirmations_read_failed",
			"could not read the transition's deployment confirmations")
	}
	return domain.TransitionClosureFacts{
		AllImpactsAddressed:       allAddressed,
		ManualDeploymentConfirmed: len(confirmations) > 0,
	}, nil
}

// Complete moves a transition from in_progress to externally_completed
// (docs/backend-implementation.md §3 "Complete: Empty → Transition"; §13
// ruling 1). "기존 전환 명령은 Transition version 필수" applies here like
// SetTarget/ConfirmDeployment.
func (s *TransitionService) Complete(ctx context.Context, meta contract.MutationMeta, cmd contract.TransitionCompleteCommand) (contract.TransitionView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TransitionView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.TransitionView{}, contract.NewAppError(contract.ErrorKindForbidden, "transition_requires_admin",
			"completing a transition requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.TransitionView{}, err
	}

	var result contract.TransitionView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		t, err := tx.Transitions().GetForUpdate(ctx, cmd.TransitionID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "transition_not_found", "transition does not exist").
				WithField("transition_id", string(cmd.TransitionID))
		} else if err != nil {
			return storeError(err, "transition_read_failed", "could not read the transition")
		}

		scope := transitionScope(t)
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTransitionComplete, port.NewAuthorizationScope(scope...)); err != nil {
			return err
		}
		if t.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "transition_version_conflict",
				"transition has changed since this request was prepared")
		}

		now := s.deps.Clock.Now()
		facts, err := gatherClosureFacts(ctx, tx, t.ID(), now)
		if err != nil {
			return err
		}
		next, err := t.Complete(facts, now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Transitions().Save(ctx, next, expectedVersion); err != nil {
			return storeError(err, "transition_save_failed", "could not save the transition")
		}

		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "transition.complete",
			TargetType: "transition",
			TargetID:   string(cmd.TransitionID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(dedupAuthorityIDs(scope)...)); err != nil {
			return storeError(err, "transition_audit_failed", "could not record the complete audit event")
		}

		view, err := toTransitionView(ctx, tx, next)
		if err != nil {
			return err
		}
		result = view
		return nil
	})
	if err != nil {
		return contract.TransitionView{}, err
	}
	return result, nil
}

// ---- Close ----

// TransitionCloseCommand is Close's input. See this file's package doc
// comment for why it is a package-local type rather than a new
// contract.TransitionCloseCommand.
type TransitionCloseCommand struct {
	TransitionID domain.TransitionID
}

// Close moves a transition from externally_completed to the terminal closed
// state once the source authority's own CRL publication has ended (§13
// ruling 1). See this file's package doc comment for why this method exists
// outside §3's table, why it is admin-gated, and why it only READS
// CRLState.PublicationState rather than triggering CRLState.Close itself.
func (s *TransitionService) Close(ctx context.Context, meta contract.MutationMeta, cmd TransitionCloseCommand) (contract.TransitionView, error) {
	if _, err := domain.ParseTransitionID(string(cmd.TransitionID)); err != nil {
		return contract.TransitionView{}, contract.FromDomainError(err)
	}
	if !meta.Principal.IsAdmin() {
		return contract.TransitionView{}, contract.NewAppError(contract.ErrorKindForbidden, "transition_requires_admin",
			"closing a transition requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.TransitionView{}, err
	}

	var result contract.TransitionView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		t, err := tx.Transitions().GetForUpdate(ctx, cmd.TransitionID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "transition_not_found", "transition does not exist").
				WithField("transition_id", string(cmd.TransitionID))
		} else if err != nil {
			return storeError(err, "transition_read_failed", "could not read the transition")
		}

		scope := transitionScope(t)
		// Reused action: see package doc comment.
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTransitionClose, port.NewAuthorizationScope(scope...)); err != nil {
			return err
		}
		if t.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "transition_version_conflict",
				"transition has changed since this request was prepared")
		}

		source, err := tx.PKI().GetIssuerForUpdate(ctx, t.SourceAuthorityID())
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindUnavailable, "transition_source_missing",
				"the transition's source authority could not be found")
		} else if err != nil {
			return storeError(err, "transition_source_read_failed", "could not read the source authority")
		}
		state, err := tx.CRLs().GetStateForUpdate(ctx, source.KeyGenerationID())
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindUnavailable, "transition_source_crl_state_missing",
				"the source authority has no CRL state")
		} else if err != nil {
			return storeError(err, "transition_source_crl_state_read_failed", "could not read the source authority's CRL state")
		}

		now := s.deps.Clock.Now()
		facts := domain.TransitionTerminationFacts{
			SourceCAPublicationEnded: state.PublicationState() == domain.PublicationStateClosed,
		}
		next, err := t.Close(facts, now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Transitions().Save(ctx, next, expectedVersion); err != nil {
			return storeError(err, "transition_save_failed", "could not save the transition")
		}

		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "transition.close",
			TargetType: "transition",
			TargetID:   string(cmd.TransitionID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(dedupAuthorityIDs(append(scope, source.ID()))...)); err != nil {
			return storeError(err, "transition_audit_failed", "could not record the close audit event")
		}

		view, err := toTransitionView(ctx, tx, next)
		if err != nil {
			return err
		}
		result = view
		return nil
	})
	if err != nil {
		return contract.TransitionView{}, err
	}
	return result, nil
}
