// authority.go implements AuthorityService (docs/backend-implementation.md
// §3 AuthorityService row): authority creation, policy changes, issuance
// state transitions, closure/key destruction and archival. Closure facts are
// read from the issuer's certificate and CRL rows while the authority row is
// locked; the CA generation marker and signing secret are changed in the same
// transaction as the authority transition.
package service

import (
	"context"
	"errors"
	"fmt"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// AuthorityDeps is AuthorityService's dependency set: CommonDeps plus the
// signing dependencies docs/backend-implementation.md §5 names for
// Authority/Issuance jointly ("KeyEngine, CertificateSigner, SerialGenerator,
// ProfileValidator"). ProfileValidator is required at construction, matching
// IssuanceDeps, but never called: a CA certificate carries no profile or
// SANs (domain.IssuanceRequest.ValidateFor's subordinate-CA branch requires
// both empty), and port.ProfileValidator's own doc comment says the
// operator-configurable policy it would check is not specified anywhere yet.
type AuthorityDeps struct {
	CommonDeps
	KeyEngine         port.KeyEngine
	CertificateSigner port.CertificateSigner
	SerialGenerator   port.SerialGenerator
	ProfileValidator  port.ProfileValidator
}

// Validate reports the first missing dependency, common or Authority-specific.
func (d AuthorityDeps) Validate() error {
	if err := d.CommonDeps.Validate(); err != nil {
		return err
	}
	return firstMissing(
		required{"KeyEngine", d.KeyEngine == nil},
		required{"CertificateSigner", d.CertificateSigner == nil},
		required{"SerialGenerator", d.SerialGenerator == nil},
		required{"ProfileValidator", d.ProfileValidator == nil},
	)
}

// AuthorityService implements the Create/Rename/SetIssuanceState methods
// (docs/backend-implementation.md §3 AuthorityService row).
type AuthorityService struct {
	deps AuthorityDeps
}

// NewAuthorityService constructs the service, failing fast on a missing
// dependency rather than at the first request.
func NewAuthorityService(deps AuthorityDeps) (*AuthorityService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &AuthorityService{deps: deps}, nil
}

const authorityOperationCreate = "authority.create"

// ---- idempotency input DTO (docs/backend-implementation.md §11.6) ----

// authorityCreateHashInput is authority.create's v1 input envelope. Validity
// stays nil when the client omitted it, mirroring issueHashInput's rule:
// the hash must never carry a Settings-resolved default, only what the
// client actually sent (§11.6 "선택값 생략은 명시값과 구별해 보존한다").
type authorityCreateHashInput struct {
	Kind              string        `json:"kind"`
	Name              string        `json:"name"`
	ParentAuthorityID string        `json:"parent_authority_id,omitempty"`
	Subject           hashSubject   `json:"subject"`
	KeyAlgorithm      string        `json:"key_algorithm"`
	Validity          *hashValidity `json:"validity,omitempty"`
}

// ---- stored result DTO (§14.7) ----

const authorityStoredResultSchemaVersion = 1

// storedAuthorityCreateResult stores only the identifier a replay needs to
// re-read the live row. Every other field on AuthorityView (issuance_state,
// version, key_available, affected, archived_at) can change after creation,
// so a replay must report current truth rather than a frozen snapshot --
// the same rule §14.7 states for a replayed issuance's delivery status.
type storedAuthorityCreateResult struct {
	SchemaVersion int    `json:"schema_version"`
	AuthorityID   string `json:"authority_id"`
}

func decodeStoredAuthorityResult(stored port.OperationRequestResult) (storedAuthorityCreateResult, error) {
	var v storedAuthorityCreateResult
	if err := DecodeStoredResult(stored, &v); err != nil {
		return storedAuthorityCreateResult{}, err
	}
	if v.SchemaVersion != authorityStoredResultSchemaVersion {
		return storedAuthorityCreateResult{}, contract.NewAppError(contract.ErrorKindUnavailable, "authority_stored_result_schema_unsupported",
			"a stored authority creation result carries an unsupported schema_version").
			WithField("schema_version", fmt.Sprint(v.SchemaVersion))
	}
	return v, nil
}

// toView re-reads the live authority row for replay. CreatedAt is left zero:
// there is no created_at column on the authorities table
// (docs/data-model.md's authorities row lists none) and no other stored fact
// this developer's files can derive it from, so a replay cannot recover the
// original creation instant. Flagged for the lead alongside AuthorityView's
// own already-documented CRLStatus gap.
func (v storedAuthorityCreateResult) toView(ctx context.Context, tx port.TxStores) (contract.AuthorityView, error) {
	authority, err := tx.PKI().GetIssuerForUpdate(ctx, domain.AuthorityID(v.AuthorityID))
	if err != nil {
		return contract.AuthorityView{}, storeError(err, "authority_replay_read_failed",
			"could not read the current authority for replay")
	}
	return toAuthorityView(authority, domain.Instant{}), nil
}

// toAuthorityView projects a domain.Authority into the OpenAPI response
// shape. createdAt is the instant this call created the authority; pass the
// zero value when the caller cannot know it (a replay, or an authority read
// back after Rename/SetIssuanceState).
func toAuthorityView(a domain.Authority, createdAt domain.Instant) contract.AuthorityView {
	view := contract.AuthorityView{
		ID:              a.ID(),
		Kind:            a.Kind(),
		Name:            a.Name(),
		IssuanceState:   a.IssuanceState(),
		KeyGenerationID: a.KeyGenerationID(),
		KeyAvailable:    a.KeyAvailable(),
		Affected:        a.Affected(),
		NotAfter:        a.CertificateWindow().NotAfter(),
		Version:         a.Version(),
		CreatedAt:       createdAt,
	}
	if parentID := a.ManagementParentID(); parentID != "" {
		view.ManagementParentID = &parentID
	}
	if certID := a.IssuanceCertificateID(); certID != "" {
		view.IssuanceCertificateID = &certID
	}
	if archivedAt := a.ArchivedAt(); !archivedAt.IsZero() {
		view.ArchivedAt = &archivedAt
	}
	return view
}

// ---- Create ----

// authorityCreatePrepared is everything Create builds before opening its
// Write, mirroring issuePrepared's shape and the same non-authoritative
// contract: the commit re-reads and re-checks every fact this depends on.
type authorityCreatePrepared struct {
	now  domain.Instant
	kind domain.AuthorityKind

	validity        domain.CalendarValidity
	settingsVersion *domain.Version // nil when validity was explicit: nothing to re-check

	parentAuthorityID domain.AuthorityID // empty for a Root
	issuerCertificate domain.Certificate // parent's CA certificate for an Intermediate; zero (self-signed) for a Root

	plan domain.IssuancePlan

	authorityID     domain.AuthorityID
	keyGenerationID domain.CAKeyGenerationID
	keyMaterialID   domain.KeyMaterialID
	publicKey       domain.PublicKey
	generatedSecret *domain.EncryptedSecret

	certificate domain.Certificate
}

// Create makes a new Root or Intermediate authority: generate its signing
// key and sign its own certificate (self-signed for a Root, signed by the
// named parent for an Intermediate), then store everything in one Write
// (docs/backend-implementation.md §8 "CA 생성" row: prep is "parent
// snapshot, 새 키·CA 서명"; the Write is "parent 권한·상태·기간 재확인,
// CA/키/인증서·CRL 상태·요청 결과·감사"). Bootstrap authorities are created
// through a separate internal path -- AuthorityCreateCommand.DomainKind
// already refuses that kind for this public command.
func (s *AuthorityService) Create(ctx context.Context, meta contract.MutationMeta, cmd contract.AuthorityCreateCommand) (contract.AuthorityView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.AuthorityView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindForbidden, "authority_requires_admin",
			"creating an authority requires an administrator session")
	}
	kind, err := cmd.DomainKind()
	if err != nil {
		return contract.AuthorityView{}, err
	}
	subject, err := cmd.DomainSubject()
	if err != nil {
		return contract.AuthorityView{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_subject", "subject is invalid", err)
	}
	keyAlgorithm, err := cmd.DomainKeyAlgorithm()
	if err != nil {
		return contract.AuthorityView{}, err
	}

	hashInput := authorityCreateHashInput{
		Kind:              cmd.Kind,
		Name:              cmd.Name,
		ParentAuthorityID: NormalizeUUID(string(cmd.ParentAuthorityID)),
		Subject:           subjectForHash(subject),
		KeyAlgorithm:      string(keyAlgorithm),
	}
	if cmd.Validity != nil {
		hashInput.Validity = &hashValidity{Value: cmd.Validity.Value, Unit: cmd.Validity.Unit}
	}
	inputHash, err := InputHash(authorityOperationCreate, map[string]string{}, hashInput)
	if err != nil {
		return contract.AuthorityView{}, err
	}
	reqKey, err := RequestKey(meta, authorityOperationCreate)
	if err != nil {
		return contract.AuthorityView{}, err
	}

	// The authorization scope for creating an Intermediate is its named
	// parent (§8 "parent 권한 ... 재확인": you need management authority over
	// the Root before you may spawn an Intermediate under it). A Root has no
	// parent to check against; nothing in the current MVP role model
	// (data-model.md "미래 역할 테이블을 미리 빈 상태로 구현하지 않는다") has
	// a scope narrower than the single global administrator for that case,
	// so an empty scope is used, matching settingsScope's reasoning for the
	// same situation.
	var scope []domain.AuthorityID
	if kind == domain.AuthorityKindIntermediate {
		scope = []domain.AuthorityID{cmd.ParentAuthorityID}
	}
	// §6: admission is checked before any expensive preparation.
	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionAuthorityCreate, port.NewAuthorizationScope(scope...)); err != nil {
		return contract.AuthorityView{}, err
	}

	// §10: a request already canceled before any work started produces no
	// external effect at all -- not even a key generation.
	if err := ctx.Err(); err != nil {
		return contract.AuthorityView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	var result contract.AuthorityView
	if found, err := s.replayCreateBeforePreparation(ctx, reqKey, inputHash, meta.Principal, scope, &result); err != nil {
		return contract.AuthorityView{}, err
	} else if found {
		return result, nil
	}

	var reuse *authorityCreatePrepared
	for attempt := 0; attempt < maxSerialAttempts; attempt++ {
		prep, err := s.prepareCreate(ctx, meta, cmd, kind, subject, keyAlgorithm, reuse)
		if err != nil {
			return contract.AuthorityView{}, err
		}
		reuse = &prep

		err = RunWithRetry(ctx, func() error {
			return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
				return s.commitCreate(ctx, tx, meta, cmd, reqKey, inputHash, prep, &result)
			})
		})
		if errors.Is(err, errRePrepare) {
			continue
		}
		if err != nil {
			return contract.AuthorityView{}, err
		}
		return result, nil
	}
	return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindConflict, "authority_serial_exhausted",
		"could not obtain a unique serial after repeated signing attempts")
}

// replayCreateBeforePreparation is Create's read-only duplicate probe,
// mirroring IssuanceService.replayBeforePreparation: it authenticates and
// authorizes FIRST (§8 "현재 인증/권한이 없는 요청은 기존 결과도 받지
// 못한다"), then looks for a stored result so a retried request never pays
// for a second key generation and signature. It is not authoritative --
// commitCreate runs the same checks again inside the Write.
func (s *AuthorityService) replayCreateBeforePreparation(
	ctx context.Context,
	reqKey port.OperationRequestKey,
	inputHash string,
	principal contract.Principal,
	scope []domain.AuthorityID,
	result *contract.AuthorityView,
) (bool, error) {
	var found bool
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, principal, port.ActionAuthorityCreate, port.NewAuthorizationScope(scope...)); err != nil {
			return err
		}
		stored, ok, err := ReplayStoredResult(ctx, tx, reqKey, inputHash)
		if err != nil || !ok {
			return err
		}
		view, err := decodeStoredAuthorityResult(stored)
		if err != nil {
			return err
		}
		projected, err := view.toView(ctx, tx)
		if err != nil {
			return err
		}
		*result = projected
		found = true
		return nil
	})
	return found, err
}

// resolveAuthorityCreateValidity fills in an omitted validity from the
// current installation Settings (RootValidity or IntermediateValidity,
// matching kind). Per §14.8, a missing/corrupt/unsupported-schema Settings
// row is then a create-time error, never a factory default -- the same rule
// resolveSeriesDefaults applies for Leaf issuance. The returned *domain.
// Version is nil when validity was explicit, signalling the caller that
// nothing here depends on the Settings snapshot and there is therefore
// nothing to re-check for staleness at commit time.
func resolveAuthorityCreateValidity(ctx context.Context, tx port.TxStores, kind domain.AuthorityKind, requested *contract.ValidityInput) (domain.CalendarValidity, *domain.Version, error) {
	if requested != nil {
		v, err := requested.Domain()
		if err != nil {
			return domain.CalendarValidity{}, nil, contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity",
				"validity must have a positive value and a supported unit", err)
		}
		return v, nil, nil
	}
	settings, err := tx.Installation().GetSettings(ctx)
	switch {
	case errors.Is(err, port.ErrNotFound):
		return domain.CalendarValidity{}, nil, contract.NewAppError(contract.ErrorKindConflict, "authority_settings_not_configured",
			"installation settings have not been initialized; complete Setup before creating an authority")
	case err != nil:
		return domain.CalendarValidity{}, nil, storeError(err, "authority_settings_read_failed", "could not read installation settings")
	}
	snap, err := DecodeSettingsV1(settings)
	if err != nil {
		return domain.CalendarValidity{}, nil, err
	}
	version := settings.Version
	switch kind {
	case domain.AuthorityKindRoot:
		return snap.RootValidity, &version, nil
	case domain.AuthorityKindIntermediate:
		return snap.IntermediateValidity, &version, nil
	default:
		return domain.CalendarValidity{}, nil, contract.NewAppError(contract.ErrorKindValidation, "invalid_kind", "kind is unsupported")
	}
}

// prepareCreate performs §8's out-of-transaction preparation: resolve
// validity, read the parent (Intermediate only) and its signing key, plan
// the issuance, generate a key and sign.
//
// On a serial-collision retry (reuse != nil) the authority/key-generation/
// key-material identity and the already-generated key are kept, and only a
// fresh certificate id and serial are minted and signed against -- the same
// rule prepareIssue documents, so a collision retry never mints a second
// unused key pair.
func (s *AuthorityService) prepareCreate(ctx context.Context, meta contract.MutationMeta, cmd contract.AuthorityCreateCommand, kind domain.AuthorityKind, subject domain.Subject, keyAlgorithm domain.KeyAlgorithm, reuse *authorityCreatePrepared) (authorityCreatePrepared, error) {
	prep := authorityCreatePrepared{now: s.deps.Clock.Now(), kind: kind}

	var parent domain.Authority
	var issuerSecret domain.EncryptedSecret
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		validity, settingsVersion, err := resolveAuthorityCreateValidity(ctx, tx, kind, cmd.Validity)
		if err != nil {
			return err
		}
		prep.validity = validity
		prep.settingsVersion = settingsVersion

		if kind == domain.AuthorityKindIntermediate {
			p, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.ParentAuthorityID)
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "authority_parent_not_found",
					"parent authority does not exist").WithField("parent_authority_id", string(cmd.ParentAuthorityID))
			} else if err != nil {
				return storeError(err, "authority_parent_read_failed", "could not read the parent authority")
			}
			parent = p
			secret, cert, err := caSigningSecret(ctx, tx, p)
			if err != nil {
				return err
			}
			issuerSecret = secret
			prep.issuerCertificate = cert
		}
		return nil
	}); err != nil {
		return authorityCreatePrepared{}, err
	}

	window, err := prep.validity.Window(prep.now)
	if err != nil {
		return authorityCreatePrepared{}, contract.FromDomainError(err)
	}

	if reuse != nil {
		prep.authorityID = reuse.authorityID
		prep.keyGenerationID = reuse.keyGenerationID
		prep.keyMaterialID = reuse.keyMaterialID
		prep.publicKey = reuse.publicKey
		prep.generatedSecret = reuse.generatedSecret
	} else {
		authorityID, err := domain.ParseAuthorityID(s.deps.IDs.NewUUID())
		if err != nil {
			return authorityCreatePrepared{}, contract.FromDomainError(err)
		}
		keyGenID, err := domain.ParseCAKeyGenerationID(s.deps.IDs.NewUUID())
		if err != nil {
			return authorityCreatePrepared{}, contract.FromDomainError(err)
		}
		keyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
		if err != nil {
			return authorityCreatePrepared{}, contract.FromDomainError(err)
		}
		prep.authorityID = authorityID
		prep.keyGenerationID = keyGenID
		prep.keyMaterialID = keyMaterialID
	}

	req := domain.IssuanceRequest{Subject: subject, KeyAlgorithm: keyAlgorithm, Window: window}
	switch kind {
	case domain.AuthorityKindIntermediate:
		// PlanSubordinateCAIssuance re-checks the parent's own CanIssue policy
		// (state, key availability, compromise/takeover, period) as part of
		// planning -- §8's "parent 권한·상태·기간 재확인" performed once here
		// during prep and again in commitCreate under lock.
		plan, err := domain.PlanSubordinateCAIssuance(parent, req, prep.now)
		if err != nil {
			return authorityCreatePrepared{}, contract.FromDomainError(err)
		}
		prep.plan = plan
		prep.parentAuthorityID = parent.ID()
	case domain.AuthorityKindRoot:
		// A self-signed Root has no issuer to check CanIssue against; its
		// plan names itself as its own issuer (data-model.md "self-signed
		// Root는 issuer 인증서 NULL, certificates의 issuer 키는 자기 CA
		// 키").
		if subject.CommonName() == "" {
			return authorityCreatePrepared{}, contract.NewAppError(contract.ErrorKindValidation, "invalid_subject",
				"subject common name must be set")
		}
		if err := keyAlgorithm.Validate(); err != nil {
			return authorityCreatePrepared{}, contract.FromDomainError(err)
		}
		prep.plan = domain.IssuancePlan{
			Subject:               subject,
			KeyAlgorithm:          keyAlgorithm,
			Window:                window,
			IssuerAuthorityID:     prep.authorityID,
			IssuerKeyGenerationID: prep.keyGenerationID,
		}
	}

	certificateID, err := domain.ParseCertificateID(s.deps.IDs.NewUUID())
	if err != nil {
		return authorityCreatePrepared{}, contract.FromDomainError(err)
	}

	if reuse != nil {
		issuerCert := prep.issuerCertificate
		issuerKey := issuerSecret
		if kind == domain.AuthorityKindRoot {
			issuerKey = *prep.generatedSecret
		}
		cert, err := resignWithNewSerial(ctx, s.deps.CertificateSigner, s.deps.SerialGenerator, prep.plan, certificateID,
			prep.keyMaterialID, prep.publicKey, domain.CertificateKindCA, meta.Principal.AccountID(), issuerCert, issuerKey, nil)
		if err != nil {
			return authorityCreatePrepared{}, err
		}
		prep.certificate = cert
		return prep, nil
	}

	switch kind {
	case domain.AuthorityKindIntermediate:
		ref := signingKeyRef{Fresh: &port.KeySpec{KeyMaterialID: prep.keyMaterialID, Algorithm: keyAlgorithm, Purpose: domain.SecretPurposeCASigning}}
		prepared, err := prepareCertificate(ctx, s.deps.KeyEngine, s.deps.CertificateSigner, s.deps.SerialGenerator, prep.plan, ref,
			domain.PublicKey{}, certificateID, prep.issuerCertificate, issuerSecret, domain.CertificateKindCA, meta.Principal.AccountID(), nil)
		if err != nil {
			return authorityCreatePrepared{}, err
		}
		prep.publicKey = prepared.GeneratedPublic
		prep.generatedSecret = prepared.GeneratedSecret
		prep.certificate = prepared.Certificate
	case domain.AuthorityKindRoot:
		// prepareCertificate cannot sign a self-signed Root: it takes the
		// issuer's signing key as an already-resolved parameter, but for a
		// self-signature that key IS the fresh one being generated in this
		// same call. resolveSigningKey/signCertificate are the same two
		// building blocks prepareCertificate composes; calling them directly
		// here is the reuse the certificate.go doc comment anticipates for a
		// caller that cannot use the bundled helper as-is.
		keyMaterialID, publicKey, generatedSecret, err := resolveSigningKey(ctx, s.deps.KeyEngine, signingKeyRef{
			Fresh: &port.KeySpec{KeyMaterialID: prep.keyMaterialID, Algorithm: keyAlgorithm, Purpose: domain.SecretPurposeCASigning},
		})
		if err != nil {
			return authorityCreatePrepared{}, err
		}
		_ = keyMaterialID // already prep.keyMaterialID by construction (KeySpec echoes it back)
		prep.publicKey = publicKey
		prep.generatedSecret = generatedSecret

		serial, err := newSerial(ctx, s.deps.SerialGenerator)
		if err != nil {
			return authorityCreatePrepared{}, err
		}
		cert, err := signCertificate(ctx, s.deps.CertificateSigner, port.CertificateSigningRequest{
			Plan:               prep.plan,
			CertificateID:      certificateID,
			KeyMaterialID:      prep.keyMaterialID,
			SubjectPublicKey:   publicKey,
			Serial:             serial,
			Kind:               domain.CertificateKindCA,
			CreatedByAccountID: meta.Principal.AccountID(),
			// IssuerCertificate omitted: self-signed Root (§14.10 "Root
			// 자체 서명에서만 생략 가능").
		}, *generatedSecret)
		if err != nil {
			return authorityCreatePrepared{}, err
		}
		prep.certificate = cert
	}
	return prep, nil
}

// commitCreate is Create's single Write, in §4's fixed order: authorization,
// stored-result replay, parent/current-policy re-check, then the stores, the
// request result and the audit row.
func (s *AuthorityService) commitCreate(ctx context.Context, tx port.TxStores, meta contract.MutationMeta, cmd contract.AuthorityCreateCommand, reqKey port.OperationRequestKey, inputHash string, prep authorityCreatePrepared, result *contract.AuthorityView) error {
	if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
		return err
	}
	var scope []domain.AuthorityID
	if prep.kind == domain.AuthorityKindIntermediate {
		scope = []domain.AuthorityID{prep.parentAuthorityID}
	}
	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionAuthorityCreate, port.NewAuthorizationScope(scope...)); err != nil {
		return err
	}

	if stored, found, err := ReplayStoredResult(ctx, tx, reqKey, inputHash); err != nil {
		return err
	} else if found {
		view, err := decodeStoredAuthorityResult(stored)
		if err != nil {
			return err
		}
		v, err := view.toView(ctx, tx)
		if err != nil {
			return err
		}
		*result = v
		return nil
	}

	if prep.kind == domain.AuthorityKindIntermediate {
		parent, err := tx.PKI().GetIssuerForUpdate(ctx, prep.parentAuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "authority_parent_not_found",
				"parent authority does not exist").WithField("parent_authority_id", string(prep.parentAuthorityID))
		} else if err != nil {
			return storeError(err, "authority_parent_read_failed", "could not read the parent authority")
		}
		// The certificate was signed under the parent's key generation as
		// read during preparation. If the parent has since moved to a new
		// key generation, the signed DER belongs to a parent this commit no
		// longer recognizes, so the preparation is redone (§8, mirroring
		// commitIssue's identical check on the Leaf issuer).
		if parent.KeyGenerationID() != prep.plan.IssuerKeyGenerationID {
			return errRePrepare
		}
		commitNow := s.deps.Clock.Now()
		if err := parent.CanIssue(domain.IssuerContext{RequestedWindow: prep.plan.Window, Intent: domain.IssuanceIntentSubordinateCA}, commitNow); err != nil {
			return contract.FromDomainError(err)
		}
		if _, _, err := verifyCASigningKeyLive(ctx, tx, parent); err != nil {
			return err
		}
	}

	if prep.settingsVersion != nil {
		if err := settingsUnchanged(ctx, tx, *prep.settingsVersion); err != nil {
			return err
		}
	}
	if err := ensureSerialUnused(ctx, tx, prep.plan.IssuerKeyGenerationID, prep.certificate.Serial()); err != nil {
		return err
	}
	if prep.generatedSecret == nil {
		return contract.NewAppError(contract.ErrorKindUnavailable, "authority_missing_generated_secret",
			"authority creation did not produce a key to store")
	}

	if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: prep.keyMaterialID, PublicKey: prep.publicKey, Origin: "generated"}); err != nil {
		return storeError(err, "authority_key_material_store_failed", "could not store the new key material")
	}
	// The CA signing secret has no one-shot delivery: unlike a fresh Leaf
	// key, a CA key is never handed to a client (docs/certificate-
	// lifecycle.md "Root·Intermediate 모두 다운로드 기능 및 API를 제공하지
	// 않는다") and data-model.md forbids delivery rows for CA/internal_tls
	// keys outright ("내부 TLS와 CA에 delivery 생성은 금지한다").
	if err := tx.Secrets().InsertEncrypted(ctx, *prep.generatedSecret); err != nil {
		return storeError(err, "authority_secret_store_failed", "could not store the encrypted CA key")
	}
	if err := tx.PKI().InsertKeyGeneration(ctx, port.CAKeyGeneration{
		ID:            prep.keyGenerationID,
		AuthorityID:   prep.authorityID,
		KeyMaterialID: prep.keyMaterialID,
		GenerationNo:  1,
	}); err != nil {
		return storeError(err, "authority_key_generation_store_failed", "could not store the CA key generation")
	}
	if err := tx.PKI().InsertCertificate(ctx, prep.certificate); err != nil {
		return storeError(err, "authority_certificate_store_failed", "could not store the certificate")
	}
	var issuerCACertificateID domain.CertificateID
	if prep.kind == domain.AuthorityKindIntermediate {
		issuerCACertificateID = prep.issuerCertificate.ID()
	}
	if err := tx.PKI().InsertCACertificateRecord(ctx, port.CACertificateRecord{
		CertificateID:         prep.certificate.ID(),
		CAKeyGenerationID:     prep.keyGenerationID,
		IssuerCACertificateID: issuerCACertificateID,
	}); err != nil {
		return storeError(err, "authority_ca_certificate_record_store_failed", "could not store the CA certificate record")
	}

	// IssuanceState starts at inventory: domain.IssuanceStateInventory's own
	// doc comment names exactly this shape ("a created-but-not-yet-activated
	// authority, e.g. a successor CA prepared ahead of a planned
	// transition"). An administrator activates it explicitly through
	// SetIssuanceState once ready.
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                    prep.authorityID,
		Kind:                  prep.kind,
		Name:                  cmd.Name,
		ManagementParentID:    prep.parentAuthorityID,
		IssuanceState:         domain.IssuanceStateInventory,
		IssuanceCertificateID: prep.certificate.ID(),
		KeyGenerationID:       prep.keyGenerationID,
		KeyAvailable:          true,
		CertificateWindow:     prep.certificate.Validity(),
	})
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.PKI().InsertAuthority(ctx, authority); err != nil {
		return storeError(err, "authority_store_failed", "could not store the authority")
	}

	// data-model.md "아직 crl_states가 없는 CA는 동일 생성 트랜잭션에서 먼저
	// 만든다": SaveState also serves as the insert path for a CA key's first
	// crl_states row, with expectedVersion 0 signalling "no row yet" (the
	// same convention InstallationRepository.SaveSettings documents).
	crlState, err := domain.NewCRLState(domain.CRLStateFacts{
		CAKeyGenerationID: prep.keyGenerationID,
		PublicationState:  domain.PublicationStateInactive,
	})
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.CRLs().SaveState(ctx, crlState, 0); err != nil {
		return storeError(err, "authority_crl_state_store_failed", "could not store the CRL state")
	}

	view := storedAuthorityCreateResult{
		SchemaVersion: authorityStoredResultSchemaVersion,
		AuthorityID:   string(prep.authorityID),
	}
	if err := StoreRequestResult(ctx, tx, reqKey, inputHash, view); err != nil {
		return err
	}

	commitNow := s.deps.Clock.Now()
	// A new Intermediate's creation is genuinely a two-CA fact -- both the
	// new authority's own trail and its parent's should show it -- unlike a
	// plain leaf event's single management scope (§14.6 forbids replicating
	// an ancestor there). This mirrors the existing multi-scope rule for a
	// transition ("전환으로 여러 CA가 관련된 작업은 기존 복수 scope 감사
	// 규칙을 적용한다") rather than the single-scope leaf rule; flagged for
	// the lead as this developer's reading rather than a literal doc
	// instruction for this exact event.
	auditScope := []domain.AuthorityID{prep.authorityID}
	if prep.kind == domain.AuthorityKindIntermediate {
		auditScope = []domain.AuthorityID{prep.authorityID, prep.parentAuthorityID}
	}
	event := port.AuditEvent{
		ID:         s.deps.IDs.NewUUID(),
		OccurredAt: commitNow,
		ActorKind:  contract.AuditActorAccount,
		ActorID:    string(meta.Principal.AccountID()),
		Action:     "authority.create",
		TargetType: "authority",
		TargetID:   string(prep.authorityID),
		ClientIP:   clientIP(meta.RequestMeta),
		Result:     contract.AuditResultSuccess,
		Details:    contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"kind": string(prep.kind)}},
	}
	if err := tx.Audit().Append(ctx, event, auditScope); err != nil {
		return storeError(err, "authority_audit_failed", "could not record the authority audit event")
	}

	*result = toAuthorityView(authority, commitNow)
	return nil
}

// ---- Rename ----

// Rename changes an authority's display name
// (docs/backend-implementation.md §3 "Rename: NamePatch → Authority";
// "나머지는 Authority version 필수"). There is no out-of-transaction
// preparation: nothing here does I/O beyond the store itself, so the entire
// operation is one Write.
func (s *AuthorityService) Rename(ctx context.Context, meta contract.MutationMeta, cmd contract.AuthorityRenameCommand) (contract.AuthorityView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.AuthorityView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindForbidden, "authority_requires_admin",
			"renaming an authority requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.AuthorityView{}, err
	}

	var result contract.AuthorityView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		authority, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.AuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "authority_not_found", "authority does not exist").
				WithField("authority_id", string(cmd.AuthorityID))
		} else if err != nil {
			return storeError(err, "authority_read_failed", "could not read the authority")
		}
		// §2/§14.6: audit and authorization scope come from the row just
		// read, never from the path id directly, even though the two agree
		// here by construction.
		scope, err := authorityScopeFromRow(authority)
		if err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionAuthorityRename, port.NewAuthorizationScope(scope)); err != nil {
			return err
		}
		if authority.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "authority_version_conflict",
				"authority has changed since this request was prepared")
		}

		renamed, err := authority.Rename(domain.AuthorityPolicy{Name: cmd.Name})
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.PKI().SaveAuthority(ctx, renamed, expectedVersion); err != nil {
			return storeError(err, "authority_save_failed", "could not save the authority")
		}

		now := s.deps.Clock.Now()
		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "authority.rename",
			TargetType: "authority",
			TargetID:   string(cmd.AuthorityID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, []domain.AuthorityID{scope}); err != nil {
			return storeError(err, "authority_audit_failed", "could not record the rename audit event")
		}

		result = toAuthorityView(renamed, domain.Instant{})
		return nil
	})
	if err != nil {
		return contract.AuthorityView{}, err
	}
	return result, nil
}

// ---- SetIssuanceState ----

// SetIssuanceState enables or stops issuance for an authority
// (docs/backend-implementation.md §3 "SetIssuanceState: IssuanceState →
// Authority"). AuthoritySetIssuanceStateCommand.DomainState already refuses
// "inventory" -- a client can only ever request enabled or stopped, matching
// domain.Authority.Enable/StopIssuance, the only two transitions this
// command can name.
//
// This is Authority's half of U05's "issuer stopped ... 시 발급 거부": once
// this stores stopped, IssuanceService.CanIssue (already merged, out of this
// developer's files) rejects new issuance/renewal against this authority the
// next time it reads the row, because domain.Authority.CanIssue checks
// issuance_state == enabled unconditionally.
func (s *AuthorityService) SetIssuanceState(ctx context.Context, meta contract.MutationMeta, cmd contract.AuthoritySetIssuanceStateCommand) (contract.AuthorityView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.AuthorityView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindForbidden, "authority_requires_admin",
			"changing issuance state requires an administrator session")
	}
	targetState, err := cmd.DomainState()
	if err != nil {
		return contract.AuthorityView{}, err
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.AuthorityView{}, err
	}

	var result contract.AuthorityView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		authority, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.AuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "authority_not_found", "authority does not exist").
				WithField("authority_id", string(cmd.AuthorityID))
		} else if err != nil {
			return storeError(err, "authority_read_failed", "could not read the authority")
		}
		scope, err := authorityScopeFromRow(authority)
		if err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionAuthoritySetIssuanceState, port.NewAuthorizationScope(scope)); err != nil {
			return err
		}
		if authority.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "authority_version_conflict",
				"authority has changed since this request was prepared")
		}

		var next domain.Authority
		switch targetState {
		case domain.IssuanceStateEnabled:
			next, err = authority.Enable()
		case domain.IssuanceStateStopped:
			next, err = authority.StopIssuance()
		default:
			// AuthoritySetIssuanceStateCommand.DomainState already restricts
			// the wire value to these two; unreachable in practice.
			return contract.NewAppError(contract.ErrorKindValidation, "invalid_state", "state must be enabled or stopped")
		}
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.PKI().SaveAuthority(ctx, next, expectedVersion); err != nil {
			return storeError(err, "authority_save_failed", "could not save the authority")
		}

		now := s.deps.Clock.Now()
		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "authority.set_issuance_state",
			TargetType: "authority",
			TargetID:   string(cmd.AuthorityID),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"state": string(targetState)}},
		}
		if err := tx.Audit().Append(ctx, event, []domain.AuthorityID{scope}); err != nil {
			return storeError(err, "authority_audit_failed", "could not record the issuance-state audit event")
		}

		result = toAuthorityView(next, domain.Instant{})
		return nil
	})
	if err != nil {
		return contract.AuthorityView{}, err
	}
	return result, nil
}

// authorityClosureFacts reads the stored certificates and CRL publication
// state needed by Authority.Archive/DestroyKey. The CA generation row is the
// issuer namespace; management parentage is not substituted for it.
func authorityClosureFacts(ctx context.Context, tx port.TxStores, authority domain.Authority, now domain.Instant) (domain.ClosureFacts, error) {
	certificates, err := tx.PKI().ListCertificatesByIssuer(ctx, authority.KeyGenerationID())
	if err != nil {
		return domain.ClosureFacts{}, storeError(err, "authority_closure_certificates_read_failed", "could not read certificates signed by the authority")
	}
	facts := domain.ClosureFacts{AllDependentCertificatesExpired: true}
	for _, certificate := range certificates {
		if !certificate.IsExpiredAt(now) {
			facts.AllDependentCertificatesExpired = false
			break
		}
	}
	if len(certificates) == 0 {
		// A never-used inventory authority has no certificate interval that
		// requires a final CRL. This is the explicit inventory exception in
		// backend-implementation.md §15.1.
		facts.RequiredCRLsPublished = true
		return facts, nil
	}

	state, err := tx.CRLs().GetStateForUpdate(ctx, authority.KeyGenerationID())
	if errors.Is(err, port.ErrNotFound) {
		return facts, nil
	}
	if err != nil {
		return domain.ClosureFacts{}, storeError(err, "authority_closure_crl_state_read_failed", "could not read the authority's CRL state")
	}
	facts.RequiredCRLsPublished = state.PublishedDocumentID() != "" &&
		state.PublishedGeneration() >= state.RevocationGeneration()
	return facts, nil
}

// DestroyKey permanently removes the CA signing secret while preserving the
// key material, certificates, issuance history and CRL state. Closure facts
// are collected from current rows inside the same transaction that locks the
// Authority and records the generation marker/version/audit changes.
func (s *AuthorityService) DestroyKey(ctx context.Context, meta contract.MutationMeta, cmd contract.AuthorityDestroyKeyCommand) (contract.AuthorityView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.AuthorityView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindForbidden, "authority_requires_admin",
			"destroying an authority key requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.AuthorityView{}, err
	}

	var result contract.AuthorityView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		authority, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.AuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "authority_not_found", "authority does not exist").
				WithField("authority_id", string(cmd.AuthorityID))
		}
		if err != nil {
			return storeError(err, "authority_read_failed", "could not read the authority")
		}
		scope, err := authorityScopeFromRow(authority)
		if err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionAuthorityDestroyKey, port.NewAuthorizationScope(scope)); err != nil {
			return err
		}
		if authority.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "authority_version_conflict",
				"authority has changed since this request was prepared")
		}
		if authority.KeyGenerationID() != cmd.KeyGenerationID {
			return contract.NewAppError(contract.ErrorKindConflict, "authority_key_generation_mismatch",
				"the requested key generation is not the authority's current generation")
		}

		generation, err := tx.PKI().GetCAKeyGeneration(ctx, cmd.KeyGenerationID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "authority_key_generation_not_found",
				"the requested CA key generation does not exist")
		}
		if err != nil {
			return storeError(err, "authority_key_generation_read_failed", "could not read the CA key generation")
		}
		if generation.AuthorityID != authority.ID() {
			return contract.NewAppError(contract.ErrorKindConflict, "authority_key_generation_mismatch",
				"the requested key generation belongs to another authority")
		}
		now := s.deps.Clock.Now()
		closure, err := authorityClosureFacts(ctx, tx, authority, now)
		if err != nil {
			return err
		}
		destroyed, err := authority.DestroyKey(closure, now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		generation.KeyDestroyedAt = now
		if err := tx.PKI().SaveCAKeyGeneration(ctx, generation); err != nil {
			return storeError(err, "authority_key_generation_save_failed", "could not record CA key destruction")
		}
		purpose := domain.SecretPurposeCASigning
		if authority.Kind() == domain.AuthorityKindBootstrap {
			purpose = domain.SecretPurposeBootstrapCA
		}
		if err := tx.Secrets().Delete(ctx, generation.KeyMaterialID, purpose); err != nil {
			return storeError(err, "authority_secret_delete_failed", "could not delete the CA signing secret")
		}
		if err := tx.PKI().SaveAuthority(ctx, destroyed, expectedVersion); err != nil {
			return storeError(err, "authority_save_failed", "could not record authority key availability")
		}

		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "authority.destroy_key",
			TargetType: "authority",
			TargetID:   string(authority.ID()),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{
				"key_generation_id": string(cmd.KeyGenerationID),
				"justification":     cmd.Justification,
			}},
		}
		if err := tx.Audit().Append(ctx, event, []domain.AuthorityID{scope}); err != nil {
			return storeError(err, "authority_audit_failed", "could not record the key destruction audit event")
		}
		result = toAuthorityView(destroyed, domain.Instant{})
		return nil
	})
	if err != nil {
		return contract.AuthorityView{}, err
	}
	return result, nil
}

// Archive retains an authority and its public history after issuance has been
// stopped, all dependent certificates have expired and the final CRL proof is
// present. It does not destroy the signing key; that remains a separate
// explicit DestroyKey operation.
func (s *AuthorityService) Archive(ctx context.Context, meta contract.MutationMeta, cmd contract.AuthorityArchiveCommand) (contract.AuthorityView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.AuthorityView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.AuthorityView{}, contract.NewAppError(contract.ErrorKindForbidden, "authority_requires_admin",
			"archiving an authority requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.AuthorityView{}, err
	}

	var result contract.AuthorityView
	err = s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		authority, err := tx.PKI().GetIssuerForUpdate(ctx, cmd.AuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "authority_not_found", "authority does not exist").
				WithField("authority_id", string(cmd.AuthorityID))
		}
		if err != nil {
			return storeError(err, "authority_read_failed", "could not read the authority")
		}
		scope, err := authorityScopeFromRow(authority)
		if err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionAuthorityArchive, port.NewAuthorizationScope(scope)); err != nil {
			return err
		}
		if authority.Version() != expectedVersion {
			return contract.NewAppError(contract.ErrorKindConflict, "authority_version_conflict",
				"authority has changed since this request was prepared")
		}
		now := s.deps.Clock.Now()
		closure, err := authorityClosureFacts(ctx, tx, authority, now)
		if err != nil {
			return err
		}
		archived, err := authority.Archive(closure, now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.PKI().SaveAuthority(ctx, archived, expectedVersion); err != nil {
			return storeError(err, "authority_save_failed", "could not archive the authority")
		}
		event := port.AuditEvent{
			ID:         s.deps.IDs.NewUUID(),
			OccurredAt: now,
			ActorKind:  contract.AuditActorAccount,
			ActorID:    string(meta.Principal.AccountID()),
			Action:     "authority.archive",
			TargetType: "authority",
			TargetID:   string(authority.ID()),
			ClientIP:   clientIP(meta.RequestMeta),
			Result:     contract.AuditResultSuccess,
			Details:    contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, []domain.AuthorityID{scope}); err != nil {
			return storeError(err, "authority_audit_failed", "could not record the authority archive audit event")
		}
		result = toAuthorityView(archived, domain.Instant{})
		return nil
	})
	if err != nil {
		return contract.AuthorityView{}, err
	}
	return result, nil
}
