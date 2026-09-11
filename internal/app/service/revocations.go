package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// JobKindCRLPublish is the jobs.kind value for "this CA key's CRL needs to
// be regenerated and published". The concrete kind/dedup_key spellings are
// not fixed by any document -- docs/data-model.md only requires that CRL
// demand is merged per CA key through a unique dedup_key -- so they are an
// implementation choice made once here rather than per caller.
const JobKindCRLPublish = "crl_publish"

// crlPublishPayloadVersion is payload_version for the JSON below. It changes
// only when the payload's shape changes.
const crlPublishPayloadVersion = 1

// crlPublishPayload is what a CRL demand carries: the revocation generation
// that must be covered. The worker merges demands per dedup key, so a later
// demand with a higher generation supersedes an earlier one.
type crlPublishPayload struct {
	RequiredGeneration int64 `json:"required_generation"`
}

// CRLDedupKey is the jobs.dedup_key for one CA key's CRL work.
func CRLDedupKey(issuer domain.CAKeyGenerationID) string {
	return JobKindCRLPublish + ":" + string(issuer)
}

// RevocationChange is one asserted revocation: the ledger is keyed by
// (issuer CA key generation, serial), so a change never needs a certificate
// row to exist (docs/data-model.md "폐기의 기준 키는 issuer/serial이고 연결
// 여부가 효력에 영향을 주지 않는다").
type RevocationChange struct {
	IssuerID      domain.CAKeyGenerationID
	Serial        domain.SerialNumber
	CertificateID domain.CertificateID // zero when no local certificate row is known
	RevokedAt     domain.Instant
	Reason        domain.RevocationReason
	Source        domain.RevocationSource
	// AuthorityID is the scope the resulting audit event is visible under.
	// It is taken from the authority row the caller read in this same
	// transaction, never from a client-supplied id
	// (docs/backend-implementation.md §2).
	AuthorityID domain.AuthorityID
}

// RevocationMeta is the audit identity and clock one applyRevocations batch
// is recorded under. Every caller (Distribution's transfer failure and
// expiry, Transition's parent-CA revocation, Import's CRL merge,
// RevocationService) supplies its own Action so the trail still names the
// operation that produced the change.
type RevocationMeta struct {
	Request   contract.RequestMeta
	ActorKind contract.AuditActorKind
	ActorID   string
	TokenID   string
	Action    string
	Now       domain.Instant
	IDs       port.IDGenerator
}

func (m RevocationMeta) validate() error {
	if m.Action == "" {
		return contract.NewAppError(contract.ErrorKindValidation, "revocation_audit_action_missing",
			"an applyRevocations batch must name the action it is recorded under")
	}
	if m.Now.IsZero() {
		return contract.NewAppError(contract.ErrorKindValidation, "revocation_now_missing",
			"an applyRevocations batch requires the current time")
	}
	if m.IDs == nil {
		return contract.NewAppError(contract.ErrorKindValidation, "revocation_ids_missing",
			"an applyRevocations batch requires an id generator")
	}
	return nil
}

// RevocationOutcome reports what a batch actually changed. Callers use
// Changed to decide whether a follow-up (a CRL wait, a response field) is
// warranted; an all-no-op batch reports zero and left the store untouched.
type RevocationOutcome struct {
	// Changed counts the revocation rows that were inserted or modified.
	Changed int
	// Generations is the new revocation generation per issuer, recorded
	// only for issuers that actually changed.
	Generations map[domain.CAKeyGenerationID]int64
}

// applyRevocations merges a batch of asserted revocations, bumps each
// touched issuer's generation exactly once, stamps that one generation onto
// every changed row, records the CRL demand and appends the audit trail --
// all inside the caller's transaction
// (docs/backend-implementation.md §5 "app 내부 applyRevocations(ctx, tx,
// changes, meta) ... 자체 트랜잭션을 열지 않는다").
//
// Rules this function owns, so that the four callers cannot drift apart:
//   - generation is computed once per issuer per batch, under that issuer's
//     CRLState lock, and every changed row of that issuer gets the same
//     number ("여러 항목은 issuer별 generation을 한 번 증가시키고 같은
//     generation을 부여할 수 있다").
//   - A Merge reporting changed=false is neither stamped nor saved, and if
//     an issuer's whole batch is unchanged its generation is not bumped and
//     no CRL demand is recorded ("batch 전체가 무변경이면 issuer generation과
//     CRL 작업 요구도 증가시키지 않는다").
//   - expectedVersion is the version first read from the store, never the
//     object's final version, because Merge followed by
//     StampChangeGeneration advances version twice for a single Save (§5
//     "app은 DB에서 읽은 최초 version을 expectedVersion으로 보존하고 최종
//     객체를 한 번 Save한다").
func applyRevocations(ctx context.Context, tx port.TxStores, changes []RevocationChange, meta RevocationMeta) (RevocationOutcome, error) {
	outcome := RevocationOutcome{Generations: map[domain.CAKeyGenerationID]int64{}}
	if len(changes) == 0 {
		return outcome, nil
	}
	if err := meta.validate(); err != nil {
		return RevocationOutcome{}, err
	}

	byIssuer, order, err := groupByIssuer(changes)
	if err != nil {
		return RevocationOutcome{}, err
	}

	for _, issuer := range order {
		changed, generation, err := applyIssuerBatch(ctx, tx, issuer, byIssuer[issuer], meta)
		if err != nil {
			return RevocationOutcome{}, err
		}
		if changed == 0 {
			continue
		}
		outcome.Changed += changed
		outcome.Generations[issuer] = generation
	}
	return outcome, nil
}

// groupByIssuer buckets a batch per issuer and returns a deterministic
// issuer order, so two identical batches lock CRLState rows in the same
// sequence and cannot deadlock against each other under a real database.
func groupByIssuer(changes []RevocationChange) (map[domain.CAKeyGenerationID][]RevocationChange, []domain.CAKeyGenerationID, error) {
	byIssuer := map[domain.CAKeyGenerationID][]RevocationChange{}
	for _, change := range changes {
		if _, err := domain.ParseCAKeyGenerationID(string(change.IssuerID)); err != nil {
			return nil, nil, contract.FromDomainError(err)
		}
		if change.Serial.IsZero() {
			return nil, nil, contract.NewAppError(contract.ErrorKindValidation, "revocation_serial_missing",
				"a revocation change must carry a serial")
		}
		byIssuer[change.IssuerID] = append(byIssuer[change.IssuerID], change)
	}
	order := make([]domain.CAKeyGenerationID, 0, len(byIssuer))
	for issuer := range byIssuer {
		order = append(order, issuer)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	return byIssuer, order, nil
}

// applyIssuerBatch resolves one issuer's changes into final Revocation
// objects first, and only then -- if anything actually changed -- bumps the
// generation and writes. Deciding before writing is what makes the
// "no change means no generation bump" rule hold without needing to undo a
// bump afterwards.
func applyIssuerBatch(ctx context.Context, tx port.TxStores, issuer domain.CAKeyGenerationID, changes []RevocationChange, meta RevocationMeta) (int, int64, error) {
	state, err := tx.CRLs().GetStateForUpdate(ctx, issuer)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return 0, 0, contract.WrapAppError(contract.ErrorKindValidation, "revocation_issuer_unknown",
				"the issuing CA key has no CRL state", err).WithField("issuer", string(issuer))
		}
		return 0, 0, storeError(err, "revocation_crl_state_read_failed", "could not read the issuer CRL state")
	}

	pending := make([]pendingRevocation, 0, len(changes))
	for _, change := range changes {
		resolved, ok, err := resolveChange(ctx, tx, change, meta)
		if err != nil {
			return 0, 0, err
		}
		if !ok {
			continue
		}
		pending = append(pending, resolved)
	}
	if len(pending) == 0 {
		return 0, 0, nil
	}

	// expectedVersion is the version the row actually held in the store,
	// captured before the in-memory bump advances it.
	stateVersion := state.Version()
	state = state.BumpRevocationGeneration()
	generation := state.RevocationGeneration()

	for _, item := range pending {
		stamped, err := item.revocation.StampChangeGeneration(generation)
		if err != nil {
			return 0, 0, contract.FromDomainError(err)
		}
		if item.isNew {
			if err := tx.Revocations().Insert(ctx, stamped); err != nil {
				return 0, 0, storeError(err, "revocation_insert_failed", "could not record the revocation")
			}
		} else if err := tx.Revocations().Save(ctx, stamped, item.expectedVersion); err != nil {
			return 0, 0, storeError(err, "revocation_save_failed", "could not update the revocation")
		}
		if err := appendRevocationAudit(ctx, tx, stamped, item.change, meta); err != nil {
			return 0, 0, err
		}
	}

	if err := tx.CRLs().SaveState(ctx, state, stateVersion); err != nil {
		return 0, 0, storeError(err, "revocation_crl_state_save_failed", "could not update the issuer CRL state")
	}
	if err := recordCRLDemand(ctx, tx, issuer, generation); err != nil {
		return 0, 0, err
	}
	return len(pending), generation, nil
}

// pendingRevocation is one resolved change held back until the batch is
// known to be non-empty.
type pendingRevocation struct {
	change          RevocationChange
	revocation      domain.Revocation
	expectedVersion domain.Version
	isNew           bool
}

// resolveChange turns one asserted change into the object that would be
// stored, reporting ok=false for a merge that changed nothing.
func resolveChange(ctx context.Context, tx port.TxStores, change RevocationChange, meta RevocationMeta) (pendingRevocation, bool, error) {
	facts := domain.RevocationFacts{
		IssuerID:      change.IssuerID,
		Serial:        change.Serial,
		CertificateID: change.CertificateID,
		RevokedAt:     change.RevokedAt,
		Reason:        change.Reason,
		Source:        change.Source,
	}

	existing, err := tx.Revocations().FindForUpdate(ctx, change.IssuerID, change.Serial)
	switch {
	case err == nil:
		merged, changed, mergeErr := existing.Merge(facts)
		if mergeErr != nil {
			return pendingRevocation{}, false, contract.FromDomainError(mergeErr)
		}
		if !changed {
			return pendingRevocation{}, false, nil
		}
		return pendingRevocation{
			change:          change,
			revocation:      merged,
			expectedVersion: existing.Version(),
			isNew:           false,
		}, true, nil
	case errors.Is(err, port.ErrNotFound):
		id, parseErr := domain.ParseRevocationID(meta.IDs.NewUUID())
		if parseErr != nil {
			return pendingRevocation{}, false, contract.FromDomainError(parseErr)
		}
		facts.ID = id
		created, newErr := domain.NewRevocation(facts)
		if newErr != nil {
			return pendingRevocation{}, false, contract.FromDomainError(newErr)
		}
		return pendingRevocation{change: change, revocation: created, isNew: true}, true, nil
	default:
		return pendingRevocation{}, false, storeError(err, "revocation_read_failed", "could not read the revocation ledger")
	}
}

// recordCRLDemand merges the "publish a CRL covering at least this
// generation" demand into this CA key's single job row.
func recordCRLDemand(ctx context.Context, tx port.TxStores, issuer domain.CAKeyGenerationID, generation int64) error {
	payload, err := json.Marshal(crlPublishPayload{RequiredGeneration: generation})
	if err != nil {
		return contract.WrapAppError(contract.ErrorKindValidation, "crl_demand_payload_failed",
			"could not encode the CRL job payload", err)
	}
	if err := tx.Jobs().UpsertDemand(ctx, CRLDedupKey(issuer), JobKindCRLPublish, crlPublishPayloadVersion, payload); err != nil {
		return storeError(err, "crl_demand_failed", "could not record the CRL publication demand")
	}
	return nil
}

// appendRevocationAudit records one changed row. Details carry only public
// facts: issuer, serial, reason and the batch generation.
func appendRevocationAudit(ctx context.Context, tx port.TxStores, revocation domain.Revocation, change RevocationChange, meta RevocationMeta) error {
	id := meta.IDs.NewUUID()
	event := port.AuditEvent{
		ID:         id,
		OccurredAt: meta.Now,
		ActorKind:  meta.ActorKind,
		ActorID:    meta.ActorID,
		TokenID:    meta.TokenID,
		Action:     meta.Action,
		TargetType: "revocation",
		TargetID:   string(revocation.ID()),
		ClientIP:   clientIP(meta.Request),
		Result:     contract.AuditResultSuccess,
		Details: contract.AuditDetails{
			SchemaVersion: 1,
			Fields: map[string]string{
				"issuer":            string(revocation.IssuerID()),
				"serial":            revocation.Serial().Hex(),
				"reason":            string(revocation.Reason()),
				"source":            string(revocation.Source()),
				"change_generation": fmt.Sprintf("%d", revocation.ChangeGeneration()),
			},
		},
	}
	var scopes []domain.AuthorityID
	if change.AuthorityID != "" {
		scopes = []domain.AuthorityID{change.AuthorityID}
	}
	if err := tx.Audit().Append(ctx, event, scopes); err != nil {
		return storeError(err, "revocation_audit_failed", "could not record the revocation audit event")
	}
	return nil
}

// clientIP renders the request's client address, empty when unset.
func clientIP(meta contract.RequestMeta) string {
	if !meta.ClientIP.IsValid() {
		return ""
	}
	return meta.ClientIP.String()
}

// storeError classifies a repository error through port.ClassifyStoreError,
// falling back to the domain mapping for anything it does not recognize, so
// no service branches on error strings (docs/backend-implementation.md §10).
func storeError(err error, code, detail string) error {
	if kind, ok := port.ClassifyStoreError(err); ok {
		return contract.WrapAppError(kind, code, detail, err)
	}
	return contract.WrapAppError(contract.ErrorKindUnavailable, code, detail, err)
}
