package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// maxSerialAttempts bounds the "충돌은 같은 요청 ID로 새 serial을 만들어
// 제한 재준비할 수 있다" retry (docs/backend-implementation.md §8). The doc
// only says "limited"; a concrete ceiling is this developer's implementation
// choice (docs/backend-implementation.md §11 "함수 내부 알고리즘 ... 는
// 개발자가 결정한다"), not a product policy question.
const maxSerialAttempts = 5

const (
	issuanceOperationIssue = "issuance.issue"
	issuanceOperationRenew = "issuance.renew"
)

// IssuanceDeps is IssuanceService's dependency set: CommonDeps plus the
// signing dependencies docs/backend-implementation.md §5 names for
// Authority/Issuance ("KeyEngine, CertificateSigner, SerialGenerator,
// ProfileValidator").
type IssuanceDeps struct {
	CommonDeps
	KeyEngine         port.KeyEngine
	CertificateSigner port.CertificateSigner
	SerialGenerator   port.SerialGenerator
	ProfileValidator  port.ProfileValidator
}

// Validate reports the first missing dependency, common or Issuance-specific
// (docs/backend-implementation.md §5 "필수 의존성이 nil이면 시작 시
// 실패한다").
func (d IssuanceDeps) Validate() error {
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

// IssuanceService implements the Leaf issuance and renewal methods
// (docs/backend-implementation.md §3 IssuanceService row). Reissue,
// UpdateSeries and ArchiveSeries are out of this developer's assigned scope
// and are not implemented here.
type IssuanceService struct {
	deps IssuanceDeps
}

// NewIssuanceService constructs the service, failing fast on a missing
// dependency rather than at the first request.
func NewIssuanceService(deps IssuanceDeps) (*IssuanceService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &IssuanceService{deps: deps}, nil
}

// ---- idempotency input DTOs (docs/backend-implementation.md §11.6) ----

// hashSubject/hashSAN/hashValidity are the typed, per-operation normalized
// shapes InputHash hashes. They deliberately do not reuse contract's wire
// DTOs: those carry raw client strings, while these carry validated,
// domain-normalized values so equivalent requests always hash the same way.
type hashSubject struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
}

type hashSAN struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type hashValidity struct {
	Value int    `json:"value"`
	Unit  string `json:"unit"`
}

// issueHashInput is issuance.issue's v1 input envelope. Validity/RotateEvery
// stay nil when the client omitted them: §11.6 "선택값 생략은 명시값과
// 구별해 보존한다" and "설치 기본값 적용 전에 해시를 계산한다" together mean
// the hash must never carry a Settings-resolved value, only what the client
// actually sent.
type issueHashInput struct {
	Name         string        `json:"name"`
	AuthorityID  string        `json:"authority_id"`
	Profile      string        `json:"profile"`
	Subject      hashSubject   `json:"subject"`
	SANs         []hashSAN     `json:"sans,omitempty"`
	KeyAlgorithm string        `json:"key_algorithm"`
	Validity     *hashValidity `json:"validity,omitempty"`
	RotateEvery  *int          `json:"rotate_every,omitempty"`
}

// renewHashInput is issuance.renew's v1 input envelope.
type renewHashInput struct {
	SourceCertificateID string  `json:"source_certificate_id"`
	TargetAuthorityID   *string `json:"target_authority_id,omitempty"`
	TransitionID        *string `json:"transition_id,omitempty"`
}

// normalizedSANsForHash renders sans into the sorted, deduplicated
// type/value form §11.6 requires ("SAN은 domain 정규화 후 type/value 순
// 정렬·중복 제거"). sans is assumed already domain-validated (NewSAN already
// normalizes case/whitespace per type).
func normalizedSANsForHash(sans []domain.SAN) []hashSAN {
	if len(sans) == 0 {
		return nil
	}
	out := make([]hashSAN, 0, len(sans))
	seen := make(map[hashSAN]struct{}, len(sans))
	for _, s := range sans {
		h := hashSAN{Type: string(s.Type()), Value: s.Value()}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func subjectForHash(s domain.Subject) hashSubject {
	return hashSubject{
		CommonName:         s.CommonName(),
		Organization:       s.Organization(),
		OrganizationalUnit: s.OrganizationalUnit(),
		Country:            s.Country(),
	}
}

// ---- stored result DTOs ----
//
// storedIssuanceResult is the DTO StoreRequestResult persists and
// ReplayStoredResult later replays through DecodeStoredResult. §14.7 fixes
// two things about it: it must carry its own schema_version=1 (checked by
// decodeStoredIssuanceResult below, so an unknown version is an error rather
// than a best-effort decode), and a replay must re-read the *current*
// delivery status rather than trust whatever was true at commit time
// ("재생 시 인증서 식별자·발급 당시 정책은 유지하되 수령 상태는 현재
// 저장값으로 조회한다"). That second rule is why this DTO stores only
// DeliveryID (an identifier, stable forever) and not a frozen state/expiry
// snapshot: toView reads the live domain.Delivery row through tx at replay
// time. It carries no domain.Instant field at all, sidestepping the
// domain.Instant JSON gap (no MarshalJSON/UnmarshalJSON; see
// docs/backend-implementation.md §14.7 "domain.Instant에 이 문제를 우회하기
// 위한 범용 JSON marshaller를 추가하지 않는다") entirely rather than working
// around it.
const issuanceStoredResultSchemaVersion = 1

type storedIssuanceResult struct {
	SchemaVersion   int    `json:"schema_version"`
	SeriesID        string `json:"series_id"`
	CertificateID   string `json:"certificate_id"`
	KeyGenerationID string `json:"key_generation_id"`
	RenewalCount    int64  `json:"renewal_count"`
	KeyRotated      bool   `json:"key_rotated"`
	// DeliveryID is empty when this issuance/renewal produced no delivery (a
	// reuse renewal that neither generated nor rotated a key).
	DeliveryID string `json:"delivery_id,omitempty"`
}

// decodeStoredIssuanceResult decodes stored through DecodeStoredResult and
// additionally rejects a schema_version this code does not understand
// (§14.7). A future schema bump must not be silently reinterpreted under the
// current field layout.
func decodeStoredIssuanceResult(stored port.OperationRequestResult) (storedIssuanceResult, error) {
	var v storedIssuanceResult
	if err := DecodeStoredResult(stored, &v); err != nil {
		return storedIssuanceResult{}, err
	}
	if v.SchemaVersion != issuanceStoredResultSchemaVersion {
		return storedIssuanceResult{}, contract.NewAppError(contract.ErrorKindUnavailable, "issuance_stored_result_schema_unsupported",
			"a stored issuance result carries an unsupported schema_version").
			WithField("schema_version", fmt.Sprint(v.SchemaVersion))
	}
	return v, nil
}

// toView projects the stored, identifier-only DTO into the response shape,
// re-reading delivery status live rather than trusting a frozen snapshot
// (§14.7). tx.Delivery().GetDeliveryForUpdate is the only read this port
// exposes for a delivery by id; it is used the same way inside a Write
// (commitIssue/commitRenew's own replay branch) and inside a plain Read
// (replayBeforePreparation), matching existing precedent elsewhere in this
// package (deliver_postprocess.go, distribution.go, recovery.go).
func (v storedIssuanceResult) toView(ctx context.Context, tx port.TxStores) (contract.IssuanceView, error) {
	out := contract.IssuanceView{
		SeriesID:        domain.SeriesID(v.SeriesID),
		CertificateID:   domain.CertificateID(v.CertificateID),
		KeyGenerationID: domain.LeafKeyGenerationID(v.KeyGenerationID),
		RenewalCount:    v.RenewalCount,
		KeyRotated:      v.KeyRotated,
	}
	if v.DeliveryID != "" {
		delivery, err := tx.Delivery().GetDeliveryForUpdate(ctx, domain.DeliveryID(v.DeliveryID))
		if err != nil {
			return contract.IssuanceView{}, storeError(err, "issuance_replay_delivery_read_failed",
				"could not read the current delivery status for replay")
		}
		out.Delivery = toDeliveryView(delivery)
	}
	return out, nil
}

// toDeliveryView projects a live domain.Delivery into its response shape.
// ConsumedAt/FinishedAt are nullable in contract.DeliveryView and zero on a
// domain.Delivery that has not reached that state yet, so a zero instant
// becomes a nil pointer rather than a rendered zero time.
func toDeliveryView(d domain.Delivery) *contract.DeliveryView {
	return &contract.DeliveryView{
		ID:            d.ID(),
		CertificateID: d.CertificateID(),
		State:         d.State(),
		ExpiresAt:     d.ExpiresAt(),
		ConsumedAt:    instantPtr(d.ConsumedAt()),
		FinishedAt:    instantPtr(d.FinishedAt()),
		FailureCode:   d.FailureCode(),
		Version:       d.Version(),
	}
}

func instantPtr(at domain.Instant) *domain.Instant {
	if at.IsZero() {
		return nil
	}
	return &at
}

// ---- leaf_certificates subtype snapshot (§14.2/§14.4) ----

const leafPolicySnapshotSchemaVersion = 1

// leafPolicySnapshotV1 is policy_snapshot_json's shape: what data-model.md's
// leaf_certificates row requires preserved from the moment this particular
// certificate was issued ("당시 프로필·SAN·기간·교체 주기 보존"), independent
// of whatever the series' live Policy is by the time someone reads it back.
type leafPolicySnapshotV1 struct {
	SchemaVersion int                    `json:"schema_version"`
	Profile       string                 `json:"profile"`
	SANs          []hashSAN              `json:"sans,omitempty"`
	Validity      settingsValidityWireV1 `json:"validity"`
	RotateEvery   int                    `json:"rotate_every"`
}

// leafPolicySnapshotJSON builds the policy_snapshot_json blob for cert,
// under the policy that was in force when it was planned. cert's own SANs
// are used (the certificate that was actually signed), in their original
// order -- unlike normalizedSANsForHash, this is a historical record, not an
// idempotency key, so it is neither sorted nor deduplicated.
func leafPolicySnapshotJSON(cert domain.Certificate, policy domain.SeriesPolicy) ([]byte, error) {
	sans := cert.SANs()
	wireSANs := make([]hashSAN, len(sans))
	for i, s := range sans {
		wireSANs[i] = hashSAN{Type: string(s.Type()), Value: s.Value()}
	}
	snap := leafPolicySnapshotV1{
		SchemaVersion: leafPolicySnapshotSchemaVersion,
		Profile:       string(cert.Profile()),
		SANs:          wireSANs,
		Validity: settingsValidityWireV1{
			Value: policy.CertificateValidity.Value(),
			Unit:  string(policy.CertificateValidity.Unit()),
		},
		RotateEvery: policy.RotateEvery,
	}
	encoded, err := json.Marshal(snap)
	if err != nil {
		return nil, contract.WrapAppError(contract.ErrorKindValidation, "issuance_policy_snapshot_encode_failed",
			"could not encode the policy snapshot", err)
	}
	return encoded, nil
}

// ---- installation Settings resolution ----

// resolvedSeriesDefaults is what a fresh Issue call needs once
// validity/rotate_every are settled, whether from the request or Settings.
type resolvedSeriesDefaults struct {
	Validity               domain.CalendarValidity
	RotateEvery            int
	PrivateDeliverySeconds int
	// SettingsVersion is the version of the service_settings row these
	// defaults were resolved from, kept so the commit can detect that the
	// snapshot moved since preparation (§14.8 "설정 version이 준비 후
	// 바뀌면 commit 전에 다시 준비하되").
	SettingsVersion domain.Version
}

// resolveSeriesDefaults fills in an omitted validity/rotate_every from the
// current installation Settings. PrivateDeliverySeconds always comes from
// Settings, since IssuanceIssueCommand carries no per-request override for
// it. Per §14.8, a missing, corrupt, or unsupported-schema-version Settings
// row is an issuance-time error, never silently covered by a factory
// default: "초기 미설정은 Setup의 명시적 초기화 경로로만 처리하며 운영
// 발급은 검증된 snapshot을 요구한다". A fresh install that has not run Setup
// yet is therefore expected to fail Issue/Renew with
// issuance_settings_not_configured until Setup's explicit initialization
// path (out of this developer's assigned files) has written a validated
// snapshot.
func resolveSeriesDefaults(ctx context.Context, tx port.TxStores, validity *contract.ValidityInput, rotateEvery *int) (resolvedSeriesDefaults, error) {
	out := resolvedSeriesDefaults{}
	if validity != nil {
		v, err := validity.Domain()
		if err != nil {
			return resolvedSeriesDefaults{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity",
				"validity must have a positive value and a supported unit", err)
		}
		out.Validity = v
	}
	if rotateEvery != nil {
		out.RotateEvery = *rotateEvery
	}

	settings, err := tx.Installation().GetSettings(ctx)
	switch {
	case errors.Is(err, port.ErrNotFound):
		return resolvedSeriesDefaults{}, contract.NewAppError(contract.ErrorKindConflict, "issuance_settings_not_configured",
			"installation settings have not been initialized; complete Setup before issuing certificates")
	case err != nil:
		return resolvedSeriesDefaults{}, storeError(err, "issuance_settings_read_failed", "could not read installation settings")
	}
	snap, err := DecodeSettingsV1(settings)
	if err != nil {
		return resolvedSeriesDefaults{}, err
	}
	if out.Validity.IsZero() {
		out.Validity = snap.LeafValidity
	}
	if out.RotateEvery == 0 {
		out.RotateEvery = snap.RotateEvery
	}
	out.PrivateDeliverySeconds = snap.PrivateDeliverySeconds
	out.SettingsVersion = settings.Version
	return out, nil
}

// settingsUnchanged reports whether the service_settings row still holds the
// version a preparation resolved its defaults from. §14.8 requires a
// preparation built on a superseded snapshot to be redone before it commits;
// a replayed result is not affected, because replay returns before this is
// ever reached.
func settingsUnchanged(ctx context.Context, tx port.TxStores, prepared domain.Version) error {
	settings, err := tx.Installation().GetSettings(ctx)
	switch {
	case errors.Is(err, port.ErrNotFound):
		return contract.NewAppError(contract.ErrorKindConflict, "issuance_settings_not_configured",
			"installation settings have not been initialized; complete Setup before issuing certificates")
	case err != nil:
		return storeError(err, "issuance_settings_read_failed", "could not read installation settings")
	}
	if settings.Version != prepared {
		return errRePrepare
	}
	return nil
}

// ---- shared signing helper ----

// errRePrepare is the internal signal that a commit found the prepared
// material stale -- a serial the store already holds, or an issuer that
// moved since preparation. docs/backend-implementation.md §8 answers both
// the same way: throw the prepared result away and prepare again under the
// same request id ("충돌은 같은 요청 ID로 새 serial을 만들어 제한
// 재준비할 수 있다"; "SAN·서명 정책의 중대한 사실이 바뀐 준비 결과는 버리고
// 다시 준비한다"). It never escapes Issue/Renew.
var errRePrepare = errors.New("service: prepared issuance is stale, prepare again")

// ensureSerialUnused is the commit-side half of §8's serial rule: the serial
// was created before signing, and the commit checks it against BOTH the
// certificate table and the revocation ledger -- a revoked serial must never
// be handed out again even if its certificate row is gone. Both halves live
// behind PKIRepository.SerialExists, whose own contract is exactly that
// two-table check, so this does not take a second lock on the revocation
// row. A collision asks for a fresh preparation rather than editing the
// signed DER, which is never touched.
func ensureSerialUnused(ctx context.Context, tx port.TxStores, issuer domain.CAKeyGenerationID, serial domain.SerialNumber) error {
	exists, err := tx.PKI().SerialExists(ctx, issuer, serial)
	if err != nil {
		return storeError(err, "issuance_serial_check_failed", "could not check serial uniqueness")
	}
	if exists {
		return errRePrepare
	}
	return nil
}

// verifyCASigningKeyLive performs §14.9's consistency checks against
// issuer's current CA key generation, required in both preparation and
// commit ("준비와 commit 양쪽에서 확인"): the generation's key must not have
// been destroyed, and the authority's selected issuance certificate must
// actually correspond to that same generation and key material -- otherwise
// a stale IssuanceCertificateID pointer could sign with one key while
// embedding a different CA certificate as issuer. It returns the issuer's
// own certificate, needed as CertificateSigningRequest.IssuerCertificate
// (§14.10), without touching the secret store -- the commit-side re-check
// re-verifies these facts but has no need to re-read the actual key
// ciphertext a second time, since prepare already did the one signature this
// request needs.
func verifyCASigningKeyLive(ctx context.Context, tx port.TxStores, issuer domain.Authority) (domain.Certificate, port.CAKeyGeneration, error) {
	generation, err := tx.PKI().GetCAKeyGeneration(ctx, issuer.KeyGenerationID())
	if errors.Is(err, port.ErrNotFound) {
		return domain.Certificate{}, port.CAKeyGeneration{}, contract.NewAppError(contract.ErrorKindUnavailable,
			"issuance_ca_key_generation_not_found", "the issuing authority's CA key generation could not be found")
	} else if err != nil {
		return domain.Certificate{}, port.CAKeyGeneration{}, storeError(err, "issuance_ca_key_generation_read_failed",
			"could not read the issuing authority's CA key generation")
	}
	if !generation.KeyDestroyedAt.IsZero() {
		return domain.Certificate{}, port.CAKeyGeneration{}, contract.NewAppError(contract.ErrorKindForbidden,
			"issuance_ca_key_destroyed", "the issuing authority's signing key has been destroyed")
	}

	caCert, err := tx.PKI().GetCertificate(ctx, issuer.IssuanceCertificateID())
	if err != nil {
		return domain.Certificate{}, port.CAKeyGeneration{}, storeError(err, "issuance_issuer_certificate_read_failed",
			"could not read the issuing authority's own certificate")
	}
	if caCert.KeyMaterialID() != generation.KeyMaterialID {
		return domain.Certificate{}, port.CAKeyGeneration{}, contract.NewAppError(contract.ErrorKindForbidden,
			"issuance_ca_certificate_key_mismatch",
			"the issuing authority's certificate does not use its current CA key generation's key material")
	}
	caRecord, err := tx.PKI().GetCACertificateRecord(ctx, caCert.ID())
	if err != nil {
		return domain.Certificate{}, port.CAKeyGeneration{}, storeError(err, "issuance_ca_certificate_record_read_failed",
			"could not read the issuing authority's CA certificate record")
	}
	if caRecord.CAKeyGenerationID != issuer.KeyGenerationID() {
		return domain.Certificate{}, port.CAKeyGeneration{}, contract.NewAppError(contract.ErrorKindForbidden,
			"issuance_ca_certificate_generation_mismatch",
			"the issuing authority's certificate does not belong to its current CA key generation")
	}
	return caCert, generation, nil
}

// caSigningSecret resolves issuer's CA signing key the §14.9 way:
// Authority.KeyGenerationID -> PKIRepository.GetCAKeyGeneration ->
// KeyMaterialID -> the ca_signing (or bootstrap_ca) secret. §14.9 explicitly
// rules out the older path through the authority's own certificate
// ("issuer DN/확장/유효기간 검증용이며 세대 행 조회를 대신하지 않는다"),
// because that path cannot see the generation row's KeyDestroyedAt. It
// layers the actual secret fetch on top of verifyCASigningKeyLive's
// consistency checks; use this at preparation time (where the secret is
// actually needed to sign) and verifyCASigningKeyLive alone for the
// commit-side re-check.
func caSigningSecret(ctx context.Context, tx port.TxStores, issuer domain.Authority) (domain.EncryptedSecret, domain.Certificate, error) {
	caCert, generation, err := verifyCASigningKeyLive(ctx, tx, issuer)
	if err != nil {
		return domain.EncryptedSecret{}, domain.Certificate{}, err
	}
	purpose := domain.SecretPurposeCASigning
	if issuer.Kind() == domain.AuthorityKindBootstrap {
		// §14.9: bootstrap issuance is a separate allowed intent under the
		// bootstrap_ca purpose, never ca_signing.
		purpose = domain.SecretPurposeBootstrapCA
	}
	secret, err := tx.Secrets().GetEncrypted(ctx, generation.KeyMaterialID, purpose)
	if err != nil {
		return domain.EncryptedSecret{}, domain.Certificate{}, storeError(err, "issuance_issuer_secret_read_failed",
			"could not read the issuing authority's signing key")
	}
	return secret, caCert, nil
}

// resignWithNewSerial mints a fresh serial and re-signs against an already-
// resolved key, the §14.10 collision-retry path ("serial 충돌만의 재시도는
// 같은 요청과 키에 새 serial을 사용해 다시 서명한다"). It is the manual
// counterpart of prepareCertificate for a retry: prepareCertificate always
// resolves a key first, which would generate a second, unused key pair on
// every collision if called again.
func resignWithNewSerial(
	ctx context.Context,
	signer port.CertificateSigner,
	serials port.SerialGenerator,
	plan domain.IssuancePlan,
	certificateID domain.CertificateID,
	keyMaterialID domain.KeyMaterialID,
	subjectPublicKey domain.PublicKey,
	kind domain.CertificateKind,
	createdBy domain.AccountID,
	issuerCertificate domain.Certificate,
	issuerKey domain.EncryptedSecret,
) (domain.Certificate, error) {
	serial, err := newSerial(ctx, serials)
	if err != nil {
		return domain.Certificate{}, err
	}
	return signCertificate(ctx, signer, port.CertificateSigningRequest{
		Plan:               plan,
		CertificateID:      certificateID,
		KeyMaterialID:      keyMaterialID,
		SubjectPublicKey:   subjectPublicKey,
		Serial:             serial,
		Kind:               kind,
		CreatedByAccountID: createdBy,
		IssuerCertificate:  issuerCertificate,
		// §14: CRL distribution point URL construction is not specified by
		// any doc this developer's scope covers (flagged for the lead).
		CRLDistributionPoints: nil,
	}, issuerKey)
}

// storeFreshKeyAndDelivery persists a freshly generated key's ciphertext and
// creates its one-shot pending delivery row, the commit-side counterpart of
// a Fresh signingKeyRef (docs/backend-implementation.md §8 "계보·인증서·
// 암호문·delivery·요청 결과·감사").
func storeFreshKeyAndDelivery(
	ctx context.Context,
	tx port.TxStores,
	ids port.IDGenerator,
	now domain.Instant,
	keyMaterialID domain.KeyMaterialID,
	publicKey domain.PublicKey,
	secret domain.EncryptedSecret,
	leafKeyGenerationID domain.LeafKeyGenerationID,
	certificateID domain.CertificateID,
	deliverySeconds int,
) (domain.Delivery, error) {
	if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{
		ID:        keyMaterialID,
		PublicKey: publicKey,
		Origin:    "generated",
	}); err != nil {
		return domain.Delivery{}, storeError(err, "issuance_key_material_store_failed", "could not store the new key material")
	}
	if err := tx.Secrets().InsertEncrypted(ctx, secret); err != nil {
		return domain.Delivery{}, storeError(err, "issuance_secret_store_failed", "could not store the encrypted private key")
	}
	deliveryID, err := domain.ParseDeliveryID(ids.NewUUID())
	if err != nil {
		return domain.Delivery{}, contract.FromDomainError(err)
	}
	delivery, err := domain.NewDelivery(domain.DeliveryFacts{
		ID:                  deliveryID,
		LeafKeyGenerationID: leafKeyGenerationID,
		CertificateID:       certificateID,
		ExpiresAt:           now.Add(domain.NewDuration(time.Duration(deliverySeconds) * time.Second)),
		State:               domain.DeliveryStatePending,
	})
	if err != nil {
		return domain.Delivery{}, contract.FromDomainError(err)
	}
	if err := tx.Delivery().InsertDelivery(ctx, delivery); err != nil {
		return domain.Delivery{}, storeError(err, "issuance_delivery_store_failed", "could not store the delivery record")
	}
	return delivery, nil
}

// appendIssuanceAudit records one issuance/renewal audit event, scoped to
// the issuing authority (docs/backend-implementation.md §2: scope built from
// stored relations, never a client-supplied id).
func appendIssuanceAudit(ctx context.Context, tx port.TxStores, ids port.IDGenerator, now domain.Instant, meta contract.MutationMeta, action string, cert domain.Certificate, authorityID domain.AuthorityID) error {
	event := port.AuditEvent{
		ID:         ids.NewUUID(),
		OccurredAt: now,
		ActorKind:  contract.AuditActorAccount,
		ActorID:    string(meta.Principal.AccountID()),
		Action:     action,
		TargetType: "certificate",
		TargetID:   string(cert.ID()),
		ClientIP:   clientIP(meta.RequestMeta),
		Result:     contract.AuditResultSuccess,
		Details: contract.AuditDetails{
			SchemaVersion: 1,
			Fields: map[string]string{
				"serial": cert.Serial().Hex(),
			},
		},
	}
	if err := tx.Audit().Append(ctx, event, []domain.AuthorityID{authorityID}); err != nil {
		return storeError(err, "issuance_audit_failed", "could not record the issuance audit event")
	}
	return nil
}

// ---- Issue ----

// Issue creates a brand-new leaf series and its first certificate
// (docs/backend-implementation.md §3 IssuanceService.Issue; §8 "Leaf
// 발급/갱신" row).
func (s *IssuanceService) Issue(ctx context.Context, meta contract.MutationMeta, cmd contract.IssuanceIssueCommand) (contract.IssuanceView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.IssuanceView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.IssuanceView{}, contract.NewAppError(contract.ErrorKindForbidden, "issuance_requires_admin",
			"issuing a certificate requires an administrator session")
	}

	profile, err := cmd.DomainProfile()
	if err != nil {
		return contract.IssuanceView{}, err
	}
	subject, err := cmd.Subject.Domain()
	if err != nil {
		return contract.IssuanceView{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_subject", "subject is invalid", err)
	}
	sans, err := cmd.DomainSANs()
	if err != nil {
		return contract.IssuanceView{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_sans", "sans are invalid", err)
	}
	keyAlgorithm, err := cmd.DomainKeyAlgorithm()
	if err != nil {
		return contract.IssuanceView{}, err
	}
	rotateEvery, rotateEveryPresent := cmd.DomainRotateEvery()

	hashInput := issueHashInput{
		Name:         cmd.Name,
		AuthorityID:  NormalizeUUID(string(cmd.AuthorityID)),
		Profile:      string(profile),
		Subject:      subjectForHash(subject),
		SANs:         normalizedSANsForHash(sans),
		KeyAlgorithm: string(keyAlgorithm),
	}
	if cmd.Validity != nil {
		hashInput.Validity = &hashValidity{Value: cmd.Validity.Value, Unit: cmd.Validity.Unit}
	}
	if rotateEveryPresent {
		hashInput.RotateEvery = &rotateEvery
	}
	target := map[string]string{"authority_id": NormalizeUUID(string(cmd.AuthorityID))}
	inputHash, err := InputHash(issuanceOperationIssue, target, hashInput)
	if err != nil {
		return contract.IssuanceView{}, err
	}
	reqKey, err := RequestKey(meta, issuanceOperationIssue)
	if err != nil {
		return contract.IssuanceView{}, err
	}

	authorityID := cmd.AuthorityID
	// §6: the expensive work (key generation, signing) must sit behind an
	// admission check, so permission is settled before preparation starts.
	// It is checked again inside the commit -- preparation reads can never
	// authorize a commit.
	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionIssuanceIssue, port.NewAuthorizationScope(authorityID)); err != nil {
		return contract.IssuanceView{}, err
	}

	req := domain.IssuanceRequest{Profile: profile, Subject: subject, SANs: sans, KeyAlgorithm: keyAlgorithm}
	var result contract.IssuanceView
	var reuse *issuePrepared

	// §10: a request already canceled before any work started produces no
	// external effect at all -- not even a key generation.
	if err := ctx.Err(); err != nil {
		return contract.IssuanceView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}
	if found, err := s.replayBeforePreparation(ctx, reqKey, inputHash, &result); err != nil {
		return contract.IssuanceView{}, err
	} else if found {
		return result, nil
	}

	// §8 "Leaf 발급/갱신": snapshot -> plan -> key generation -> signing all
	// happen OUTSIDE the transaction; the single Write below only re-checks
	// and stores. A stale preparation (serial collision, issuer moved) is
	// redone in full under the same request id, at most maxSerialAttempts
	// times.
	for attempt := 0; attempt < maxSerialAttempts; attempt++ {
		prep, err := s.prepareIssue(ctx, meta, cmd, req, rotateEvery, rotateEveryPresent, authorityID, reuse)
		if err != nil {
			return contract.IssuanceView{}, err
		}
		// A collision retry re-signs against the key that was already
		// generated rather than burning a second key pair (see
		// resolveSigningKey's doc comment).
		reuse = &prep

		err = RunWithRetry(ctx, func() error {
			return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
				return s.commitIssue(ctx, tx, meta, cmd, reqKey, inputHash, prep, &result)
			})
		})
		if errors.Is(err, errRePrepare) {
			continue
		}
		if err != nil {
			return contract.IssuanceView{}, err
		}
		return result, nil
	}
	return contract.IssuanceView{}, contract.NewAppError(contract.ErrorKindConflict, "issuance_serial_exhausted",
		"could not obtain a unique serial after repeated signing attempts")
}

// replayBeforePreparation is the read-only probe that keeps a duplicate
// request from paying for a key generation and a signature at all. §8's rule
// is that a stored successful result is replayed before the expected-version
// check; running that lookup here as well -- outside the transaction, after
// authorization -- means a retried request short-circuits before the
// expensive preparation §6 guards with an admission semaphore. It is not the
// authoritative check: commitIssue/commitRenew run ReplayStoredResult again
// inside the Write, which is the one that decides.
func (s *IssuanceService) replayBeforePreparation(ctx context.Context, reqKey port.OperationRequestKey, inputHash string, result *contract.IssuanceView) (bool, error) {
	var found bool
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		stored, ok, err := ReplayStoredResult(ctx, tx, reqKey, inputHash)
		if err != nil || !ok {
			return err
		}
		view, err := decodeStoredIssuanceResult(stored)
		if err != nil {
			return err
		}
		v, err := view.toView(ctx, tx)
		if err != nil {
			return err
		}
		*result = v
		found = true
		return nil
	})
	return found, err
}

// issuePrepared is everything Issue builds before opening its Write: the
// snapshot it planned against, the freshly generated key and the signed
// certificate. Nothing in here is authoritative -- the commit re-reads and
// re-checks every fact it depends on (§4 "Write callback 내부 순서는 인증/
// 권한 확인 -> 요청 결과 재확인 -> version/현재 정책 확인 -> ...").
type issuePrepared struct {
	now               domain.Instant
	policy            domain.SeriesPolicy
	defaults          resolvedSeriesDefaults
	plan              domain.IssuancePlan
	issuerCertificate domain.Certificate
	keyMaterialID     domain.KeyMaterialID
	publicKey         domain.PublicKey
	generatedSecret   *domain.EncryptedSecret
	certificate       domain.Certificate
}

// prepareIssue performs §8's out-of-transaction preparation. Its reads go
// through ReadStore, whose contract is that a read is preparation input only
// and never authorizes a commit.
//
// On a serial-collision retry (reuse != nil) it keeps the previously
// resolved key and only mints a new serial and re-signs
// (docs/backend-implementation.md §14.10 "serial 충돌만의 재시도는 같은
// 요청과 키에 새 serial을 사용해 다시 서명한다") instead of calling
// prepareCertificate again, which would burn a second, unused key pair for a
// fresh issuance's ref.Fresh.
func (s *IssuanceService) prepareIssue(ctx context.Context, meta contract.MutationMeta, cmd contract.IssuanceIssueCommand, req domain.IssuanceRequest, rotateEvery int, rotateEveryPresent bool, authorityID domain.AuthorityID, reuse *issuePrepared) (issuePrepared, error) {
	prep := issuePrepared{now: s.deps.Clock.Now()}

	var (
		authority    domain.Authority
		issuerSecret domain.EncryptedSecret
	)
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		a, err := tx.PKI().GetIssuerForUpdate(ctx, authorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "authority_not_found", "authority does not exist").
				WithField("authority_id", string(authorityID))
		} else if err != nil {
			return storeError(err, "issuance_authority_read_failed", "could not read the issuing authority")
		}
		authority = a

		defaults, err := resolveSeriesDefaults(ctx, tx, cmd.Validity, orNil(rotateEveryPresent, rotateEvery))
		if err != nil {
			return err
		}
		prep.defaults = defaults

		secret, issuerCert, err := caSigningSecret(ctx, tx, a)
		if err != nil {
			return err
		}
		issuerSecret = secret
		prep.issuerCertificate = issuerCert
		return nil
	}); err != nil {
		return issuePrepared{}, err
	}

	prep.policy = domain.SeriesPolicy{RotateEvery: prep.defaults.RotateEvery, CertificateValidity: prep.defaults.Validity}
	if err := prep.policy.Validate(); err != nil {
		return issuePrepared{}, contract.FromDomainError(err)
	}
	window, err := domain.PlanLeafWindow(prep.policy, prep.now)
	if err != nil {
		return issuePrepared{}, contract.FromDomainError(err)
	}
	req.Window = window
	plan, err := domain.PlanIssuance(authority, req, prep.now)
	if err != nil {
		return issuePrepared{}, contract.FromDomainError(err)
	}
	prep.plan = plan

	// §14.10: the app chooses the certificate id before signing, not the
	// signer.
	certificateID, err := domain.ParseCertificateID(s.deps.IDs.NewUUID())
	if err != nil {
		return issuePrepared{}, contract.FromDomainError(err)
	}

	if reuse != nil {
		prep.keyMaterialID, prep.publicKey, prep.generatedSecret = reuse.keyMaterialID, reuse.publicKey, reuse.generatedSecret
		cert, err := resignWithNewSerial(ctx, s.deps.CertificateSigner, s.deps.SerialGenerator, plan, certificateID,
			prep.keyMaterialID, prep.publicKey, domain.CertificateKindLeaf, meta.Principal.AccountID(), prep.issuerCertificate, issuerSecret)
		if err != nil {
			return issuePrepared{}, err
		}
		prep.certificate = cert
		return prep, nil
	}

	newKeyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
	if err != nil {
		return issuePrepared{}, contract.FromDomainError(err)
	}
	ref := signingKeyRef{Fresh: &port.KeySpec{KeyMaterialID: newKeyMaterialID, Algorithm: req.KeyAlgorithm, Purpose: domain.SecretPurposeLeafDelivery}}
	prepared, err := prepareCertificate(ctx, s.deps.KeyEngine, s.deps.CertificateSigner, s.deps.SerialGenerator, plan, ref,
		domain.PublicKey{}, certificateID, prep.issuerCertificate, issuerSecret, domain.CertificateKindLeaf, meta.Principal.AccountID(), nil)
	if err != nil {
		return issuePrepared{}, err
	}
	prep.keyMaterialID = prepared.KeyMaterialID
	prep.publicKey = prepared.GeneratedPublic
	prep.generatedSecret = prepared.GeneratedSecret
	prep.certificate = prepared.Certificate
	return prep, nil
}

// commitIssue is the single Write of §8's "Leaf 발급" row, in §4's fixed
// order: authorization, stored-result replay, current-policy re-check, then
// the stores, the request result and the audit row.
func (s *IssuanceService) commitIssue(ctx context.Context, tx port.TxStores, meta contract.MutationMeta, cmd contract.IssuanceIssueCommand, reqKey port.OperationRequestKey, inputHash string, prep issuePrepared, result *contract.IssuanceView) error {
	authorityID := cmd.AuthorityID
	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionIssuanceIssue, port.NewAuthorizationScope(authorityID)); err != nil {
		return err
	}

	if stored, found, err := ReplayStoredResult(ctx, tx, reqKey, inputHash); err != nil {
		return err
	} else if found {
		view, err := decodeStoredIssuanceResult(stored)
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

	authority, err := tx.PKI().GetIssuerForUpdate(ctx, authorityID)
	if errors.Is(err, port.ErrNotFound) {
		return contract.NewAppError(contract.ErrorKindValidation, "authority_not_found", "authority does not exist").
			WithField("authority_id", string(authorityID))
	} else if err != nil {
		return storeError(err, "issuance_authority_read_failed", "could not read the issuing authority")
	}
	// The certificate was signed under the issuer's key generation as it
	// read during preparation. If the issuer has since moved to a new key
	// generation, the signed DER belongs to an issuer this commit is no
	// longer authorizing, so the preparation is thrown away (§8).
	if authority.KeyGenerationID() != prep.plan.IssuerKeyGenerationID {
		return errRePrepare
	}
	// §13-3: app assembles the IssuerContext and re-checks CanIssue inside
	// the transaction, against the same window the certificate was signed
	// for.
	if err := authority.CanIssue(domain.IssuerContext{RequestedWindow: prep.plan.Window, Intent: domain.IssuanceIntentLeaf}, prep.now); err != nil {
		return contract.FromDomainError(err)
	}
	// §14.9: the CA key generation's destroyed/mismatch state is re-checked
	// inside the commit as well as during preparation -- a key destroyed
	// between the two must still block the store, even though the signature
	// itself was already produced.
	if _, _, err := verifyCASigningKeyLive(ctx, tx, authority); err != nil {
		return err
	}
	// §14.8: the policy this certificate was planned under came from the
	// settings snapshot read during preparation. If an operator changed
	// settings in between, the prepared window/rotation no longer reflects
	// current policy, so the preparation is redone rather than committed.
	if err := settingsUnchanged(ctx, tx, prep.defaults.SettingsVersion); err != nil {
		return err
	}
	if err := ensureSerialUnused(ctx, tx, prep.plan.IssuerKeyGenerationID, prep.certificate.Serial()); err != nil {
		return err
	}

	cert := prep.certificate
	seriesID, err := domain.ParseSeriesID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.FromDomainError(err)
	}
	leafKeyGenID, err := domain.ParseLeafKeyGenerationID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.FromDomainError(err)
	}
	leafKeyGen, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
		ID:            leafKeyGenID,
		SeriesID:      seriesID,
		KeyMaterialID: prep.keyMaterialID,
		GenerationNo:  1,
		RenewalCount:  0,
		Custody:       domain.KeyCustodyPendingDelivery,
	})
	if err != nil {
		return contract.FromDomainError(err)
	}
	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID:                     seriesID,
		Name:                   cmd.Name,
		Purpose:                domain.SeriesPurposeDistributed,
		ManagementAuthorityID:  authorityID,
		CurrentCertificateID:   cert.ID(),
		CurrentKeyGenerationID: leafKeyGenID,
		Policy:                 prep.policy,
	})
	if err != nil {
		return contract.FromDomainError(err)
	}

	if err := tx.PKI().InsertLeafKeyGeneration(ctx, leafKeyGen); err != nil {
		return storeError(err, "issuance_leaf_key_generation_store_failed", "could not store the leaf key generation")
	}
	if err := tx.PKI().InsertCertificate(ctx, cert); err != nil {
		return storeError(err, "issuance_certificate_store_failed", "could not store the certificate")
	}
	policySnapshot, err := leafPolicySnapshotJSON(cert, prep.policy)
	if err != nil {
		return err
	}
	// §14.2/§14.4: the leaf_certificates subtype row is stored in the same
	// Write as the certificate itself -- without it this certificate's chain
	// could never be resolved.
	if err := tx.PKI().InsertLeafCertificateRecord(ctx, port.LeafCertificateRecord{
		CertificateID:         cert.ID(),
		SeriesID:              seriesID,
		LeafKeyGenerationID:   leafKeyGenID,
		IssuerCACertificateID: prep.issuerCertificate.ID(),
		Operation:             port.CertificateOperationInitial,
		RenewalCountAtIssue:   0,
		PolicySnapshotJSON:    policySnapshot,
	}); err != nil {
		return storeError(err, "issuance_leaf_certificate_record_store_failed", "could not store the leaf certificate record")
	}
	if err := tx.PKI().InsertSeries(ctx, series); err != nil {
		return storeError(err, "issuance_series_store_failed", "could not store the series")
	}
	if prep.generatedSecret == nil {
		return contract.NewAppError(contract.ErrorKindUnavailable, "issuance_missing_generated_secret",
			"a fresh issuance did not produce a key to store")
	}
	delivery, err := storeFreshKeyAndDelivery(ctx, tx, s.deps.IDs, prep.now, prep.keyMaterialID, prep.publicKey, *prep.generatedSecret, leafKeyGenID, cert.ID(), prep.defaults.PrivateDeliverySeconds)
	if err != nil {
		return err
	}

	view := storedIssuanceResult{
		SchemaVersion:   issuanceStoredResultSchemaVersion,
		SeriesID:        string(seriesID),
		CertificateID:   string(cert.ID()),
		KeyGenerationID: string(leafKeyGenID),
		RenewalCount:    0,
		KeyRotated:      true,
		DeliveryID:      string(delivery.ID()),
	}
	if err := StoreRequestResult(ctx, tx, reqKey, inputHash, view); err != nil {
		return err
	}
	if err := appendIssuanceAudit(ctx, tx, s.deps.IDs, prep.now, meta, "issuance.issue", cert, authorityID); err != nil {
		return err
	}
	v, err := view.toView(ctx, tx)
	if err != nil {
		return err
	}
	*result = v
	return nil
}

// orNil returns a pointer to v when present is true, else nil. It exists so
// cmd.DomainRotateEvery()'s (value, present) pair can be threaded into
// resolveSeriesDefaults' *int parameter without a local if/else at every
// call site.
func orNil(present bool, v int) *int {
	if !present {
		return nil
	}
	return &v
}

// ---- Renew ----

// Renew issues the next certificate in an existing series, reusing the
// current key unless the series' rotation policy calls for a new one
// (docs/backend-implementation.md §3 IssuanceService.Renew; §8 "Leaf
// 발급/갱신" row; docs/certificate-lifecycle.md "갱신 횟수 계산").
func (s *IssuanceService) Renew(ctx context.Context, meta contract.MutationMeta, cmd contract.IssuanceRenewCommand) (contract.IssuanceView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.IssuanceView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.IssuanceView{}, contract.NewAppError(contract.ErrorKindForbidden, "issuance_requires_admin",
			"renewing a certificate requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.IssuanceView{}, err
	}

	hashInput := renewHashInput{SourceCertificateID: NormalizeUUID(string(cmd.SourceCertificateID))}
	if cmd.TargetAuthorityID != "" {
		v := NormalizeUUID(string(cmd.TargetAuthorityID))
		hashInput.TargetAuthorityID = &v
	}
	if cmd.TransitionID != "" {
		v := NormalizeUUID(string(cmd.TransitionID))
		hashInput.TransitionID = &v
	}
	target := map[string]string{"series_id": NormalizeUUID(string(cmd.SeriesID))}
	inputHash, err := InputHash(issuanceOperationRenew, target, hashInput)
	if err != nil {
		return contract.IssuanceView{}, err
	}
	reqKey, err := RequestKey(meta, issuanceOperationRenew)
	if err != nil {
		return contract.IssuanceView{}, err
	}

	seriesID := cmd.SeriesID
	var result contract.IssuanceView
	var reuse *renewPrepared

	if err := ctx.Err(); err != nil {
		return contract.IssuanceView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}
	if found, err := s.replayBeforePreparation(ctx, reqKey, inputHash, &result); err != nil {
		return contract.IssuanceView{}, err
	} else if found {
		return result, nil
	}

	// Same §8 split as Issue: snapshot -> plan -> (rotation only) key
	// generation -> signing outside the transaction, one Write to re-check
	// and store.
	for attempt := 0; attempt < maxSerialAttempts; attempt++ {
		prep, err := s.prepareRenew(ctx, meta, cmd, seriesID, expectedVersion, reuse)
		if err != nil {
			return contract.IssuanceView{}, err
		}
		reuse = &prep

		err = RunWithRetry(ctx, func() error {
			return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
				return s.commitRenew(ctx, tx, meta, cmd, reqKey, inputHash, expectedVersion, prep, &result)
			})
		})
		if errors.Is(err, errRePrepare) {
			continue
		}
		if err != nil {
			return contract.IssuanceView{}, err
		}
		return result, nil
	}
	return contract.IssuanceView{}, contract.NewAppError(contract.ErrorKindConflict, "issuance_serial_exhausted",
		"could not obtain a unique serial after repeated signing attempts")
}

// renewPrepared is Renew's out-of-transaction preparation, the counterpart
// of issuePrepared.
type renewPrepared struct {
	now               domain.Instant
	snapshot          port.SeriesSnapshot
	targetAuthorityID domain.AuthorityID
	targetIssuerKeyID domain.CAKeyGenerationID
	issuerCertificate domain.Certificate
	renewalPlan       domain.RenewalPlan
	plan              domain.IssuancePlan
	keyRotated        bool
	keyMaterialID     domain.KeyMaterialID
	publicKey         domain.PublicKey
	generatedSecret   *domain.EncryptedSecret
	deliverySeconds   int
	settingsVersion   domain.Version
	certificate       domain.Certificate
}

// prepareRenew reads the series/certificate/issuer snapshot, plans the
// renewal and signs -- all outside any transaction (§8). The renewal
// decision it makes here (reuse the key or rotate) is re-derived and
// re-checked inside commitRenew before anything is stored.
func (s *IssuanceService) prepareRenew(ctx context.Context, meta contract.MutationMeta, cmd contract.IssuanceRenewCommand, seriesID domain.SeriesID, expectedVersion domain.Version, reuse *renewPrepared) (renewPrepared, error) {
	prep := renewPrepared{now: s.deps.Clock.Now()}

	var (
		currentCert      domain.Certificate
		targetIssuer     domain.Authority
		issuerSecret     domain.EncryptedSecret
		issuerCert       domain.Certificate
		currentPublicKey domain.PublicKey
		revoked          bool
	)
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, seriesID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "series_not_found", "series does not exist").
				WithField("series_id", string(seriesID))
		} else if err != nil {
			return storeError(err, "issuance_series_read_failed", "could not read the series")
		}
		prep.snapshot = snapshot

		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionIssuanceRenew, port.NewAuthorizationScope(snapshot.Series.ManagementAuthorityID())); err != nil {
			return err
		}
		if snapshot.Series.IsArchived() {
			return contract.NewAppError(contract.ErrorKindConflict, "series_archived", "series is archived")
		}
		if snapshot.Series.CurrentCertificateID() != cmd.SourceCertificateID {
			return contract.NewAppError(contract.ErrorKindConflict, "source_certificate_mismatch",
				"source_certificate_id does not match the series' current certificate")
		}

		cert, err := tx.PKI().GetCertificate(ctx, cmd.SourceCertificateID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "certificate_not_found", "source certificate does not exist")
		} else if err != nil {
			return storeError(err, "issuance_certificate_read_failed", "could not read the current certificate")
		}
		currentCert = cert

		// §14.10: the subject public key for a reuse renewal is the stored
		// key material's public half, read by id -- the leaf private key
		// itself is never read on this path (certificate-lifecycle.md "일반
		// 갱신에 서버 보관 Leaf 개인키는 필요하지 않다"). This is fetched
		// unconditionally here (before the rotate-vs-reuse decision, which
		// depends on facts not yet known) so it is available if the decision
		// below turns out to be a reuse; a rotation path simply does not use
		// it.
		currentKeyMaterial, err := tx.PKI().GetKeyMaterial(ctx, snapshot.CurrentKeyGeneration.KeyMaterialID())
		if err != nil {
			return storeError(err, "issuance_key_material_read_failed", "could not read the current key material")
		}
		currentPublicKey = currentKeyMaterial.PublicKey

		// A revoked or compromise-impacted key is never renewed on the
		// ordinary path (certificate-lifecycle.md "폐기되었거나 유출 영향이
		// 있는 인증서의 기존 키를 일반 갱신 경로로 재사용하지 않는다").
		_, revokedErr := tx.Revocations().FindForUpdate(ctx, cert.IssuerCAKeyGenerationID(), cert.Serial())
		revoked = revokedErr == nil
		if revokedErr != nil && !errors.Is(revokedErr, port.ErrNotFound) {
			return storeError(revokedErr, "issuance_revocation_read_failed", "could not check the current certificate's revocation state")
		}

		targetAuthorityID := cmd.TargetAuthorityID
		if targetAuthorityID == "" {
			targetAuthorityID = snapshot.Series.ManagementAuthorityID()
		}
		prep.targetAuthorityID = targetAuthorityID
		issuer, err := tx.PKI().GetIssuerForUpdate(ctx, targetAuthorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "authority_not_found", "target authority does not exist")
		} else if err != nil {
			return storeError(err, "issuance_authority_read_failed", "could not read the target authority")
		}
		targetIssuer = issuer

		secret, issuerCACert, err := caSigningSecret(ctx, tx, issuer)
		if err != nil {
			return err
		}
		issuerSecret = secret
		issuerCert = issuerCACert

		defaults, err := resolveSeriesDefaults(ctx, tx, nil, nil)
		if err != nil {
			return err
		}
		prep.deliverySeconds = defaults.PrivateDeliverySeconds
		prep.settingsVersion = defaults.SettingsVersion
		return nil
	}); err != nil {
		return renewPrepared{}, err
	}

	if prep.snapshot.Series.Version() != expectedVersion {
		return renewPrepared{}, contract.NewAppError(contract.ErrorKindConflict, "version_mismatch",
			"series has moved on since expected_version was read")
	}

	policyWindow, err := prep.snapshot.Series.Policy().PlanWindow(prep.now)
	if err != nil {
		return renewPrepared{}, contract.FromDomainError(err)
	}
	if err := targetIssuer.CanIssue(domain.IssuerContext{RequestedWindow: policyWindow, Intent: domain.IssuanceIntentLeaf}, prep.now); err != nil {
		return renewPrepared{}, contract.FromDomainError(err)
	}

	keyReady := !revoked && prep.snapshot.CurrentKeyGeneration.Custody() == domain.KeyCustodyClientHeld
	renewalPlan, err := prep.snapshot.Series.PlanRenewal(domain.RenewalFacts{
		CurrentGeneration:   prep.snapshot.CurrentKeyGeneration,
		TargetIssuerID:      prep.targetAuthorityID,
		TargetIssuerWindow:  targetIssuer.CertificateWindow(),
		RequestedWindow:     policyWindow,
		KeyReadyForRenewal:  keyReady,
		IsEmergencyReissue:  false,
		NextKeyGenerationNo: prep.snapshot.CurrentKeyGeneration.GenerationNo() + 1,
	}, prep.now)
	if err != nil {
		return renewPrepared{}, contract.FromDomainError(err)
	}
	prep.renewalPlan = renewalPlan
	prep.keyRotated = renewalPlan.Action == domain.RenewalActionRotateKey
	prep.targetIssuerKeyID = targetIssuer.KeyGenerationID()
	prep.issuerCertificate = issuerCert
	prep.plan = domain.IssuancePlan{
		Profile:               currentCert.Profile(),
		Subject:               currentCert.Subject(),
		SANs:                  currentCert.SANs(),
		KeyAlgorithm:          currentCert.KeyAlgorithm(),
		Window:                renewalPlan.Window,
		IssuerAuthorityID:     targetIssuer.ID(),
		IssuerKeyGenerationID: targetIssuer.KeyGenerationID(),
	}

	// §14.10: the app chooses the certificate id before signing.
	certificateID, err := domain.ParseCertificateID(s.deps.IDs.NewUUID())
	if err != nil {
		return renewPrepared{}, contract.FromDomainError(err)
	}

	if reuse != nil && reuse.keyRotated == prep.keyRotated {
		// Collision retry: re-sign against the key the first attempt already
		// resolved instead of generating another one (§14.10 "serial 충돌만의
		// 재시도는 같은 요청과 키에 새 serial을 사용해 다시 서명한다").
		prep.keyMaterialID, prep.publicKey, prep.generatedSecret = reuse.keyMaterialID, reuse.publicKey, reuse.generatedSecret
		cert, err := resignWithNewSerial(ctx, s.deps.CertificateSigner, s.deps.SerialGenerator, prep.plan, certificateID,
			prep.keyMaterialID, prep.publicKey, domain.CertificateKindLeaf, meta.Principal.AccountID(), prep.issuerCertificate, issuerSecret)
		if err != nil {
			return renewPrepared{}, err
		}
		prep.certificate = cert
		return prep, nil
	}

	var (
		ref               signingKeyRef
		existingPublicKey domain.PublicKey
	)
	if prep.keyRotated {
		newKeyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
		if err != nil {
			return renewPrepared{}, contract.FromDomainError(err)
		}
		ref = signingKeyRef{Fresh: &port.KeySpec{KeyMaterialID: newKeyMaterialID, Algorithm: currentCert.KeyAlgorithm(), Purpose: domain.SecretPurposeLeafDelivery}}
	} else {
		// An ordinary renewal signs against the stored public key read
		// during preparation; the leaf private key is never read
		// (certificate-lifecycle.md "일반 갱신에 서버 보관 Leaf 개인키는
		// 필요하지 않다").
		ref = signingKeyRef{Existing: prep.snapshot.CurrentKeyGeneration.KeyMaterialID()}
		existingPublicKey = currentPublicKey
	}
	prepared, err := prepareCertificate(ctx, s.deps.KeyEngine, s.deps.CertificateSigner, s.deps.SerialGenerator, prep.plan, ref,
		existingPublicKey, certificateID, prep.issuerCertificate, issuerSecret, domain.CertificateKindLeaf, meta.Principal.AccountID(), nil)
	if err != nil {
		return renewPrepared{}, err
	}
	prep.keyMaterialID = prepared.KeyMaterialID
	prep.generatedSecret = prepared.GeneratedSecret
	if prep.keyRotated {
		prep.publicKey = prepared.GeneratedPublic
	} else {
		// prepareCertificate's preparedCertificate.GeneratedPublic is zero
		// for a reused key (nothing was generated); the subject public key
		// for a resign-only retry must still be available, so it is tracked
		// independently of that struct here.
		prep.publicKey = existingPublicKey
	}
	prep.certificate = prepared.Certificate
	return prep, nil
}

// commitRenew is Renew's single Write, in §4's fixed order.
func (s *IssuanceService) commitRenew(ctx context.Context, tx port.TxStores, meta contract.MutationMeta, cmd contract.IssuanceRenewCommand, reqKey port.OperationRequestKey, inputHash string, expectedVersion domain.Version, prep renewPrepared, result *contract.IssuanceView) error {
	snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, cmd.SeriesID)
	if errors.Is(err, port.ErrNotFound) {
		return contract.NewAppError(contract.ErrorKindValidation, "series_not_found", "series does not exist").
			WithField("series_id", string(cmd.SeriesID))
	} else if err != nil {
		return storeError(err, "issuance_series_read_failed", "could not read the series")
	}

	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionIssuanceRenew, port.NewAuthorizationScope(snapshot.Series.ManagementAuthorityID())); err != nil {
		return err
	}

	if stored, found, err := ReplayStoredResult(ctx, tx, reqKey, inputHash); err != nil {
		return err
	} else if found {
		view, err := decodeStoredIssuanceResult(stored)
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

	if snapshot.Series.IsArchived() {
		return contract.NewAppError(contract.ErrorKindConflict, "series_archived", "series is archived")
	}
	if snapshot.Series.Version() != expectedVersion {
		return contract.NewAppError(contract.ErrorKindConflict, "version_mismatch", "series has moved on since expected_version was read")
	}
	if snapshot.Series.CurrentCertificateID() != cmd.SourceCertificateID {
		return contract.NewAppError(contract.ErrorKindConflict, "source_certificate_mismatch",
			"source_certificate_id does not match the series' current certificate")
	}
	if snapshot.CurrentKeyGeneration.ID() != prep.snapshot.CurrentKeyGeneration.ID() ||
		snapshot.CurrentKeyGeneration.Custody() != prep.snapshot.CurrentKeyGeneration.Custody() {
		// The key custody the rotation decision was made against moved.
		return errRePrepare
	}

	targetIssuer, err := tx.PKI().GetIssuerForUpdate(ctx, prep.targetAuthorityID)
	if errors.Is(err, port.ErrNotFound) {
		return contract.NewAppError(contract.ErrorKindValidation, "authority_not_found", "target authority does not exist")
	} else if err != nil {
		return storeError(err, "issuance_authority_read_failed", "could not read the target authority")
	}
	if targetIssuer.KeyGenerationID() != prep.targetIssuerKeyID {
		return errRePrepare
	}
	// §13-3: the IssuerContext is assembled by app and CanIssue is re-checked
	// inside the transaction.
	if err := targetIssuer.CanIssue(domain.IssuerContext{RequestedWindow: prep.plan.Window, Intent: domain.IssuanceIntentLeaf}, prep.now); err != nil {
		return contract.FromDomainError(err)
	}
	// §14.9: re-verify the CA key generation/certificate consistency inside
	// the commit as well.
	if _, _, err := verifyCASigningKeyLive(ctx, tx, targetIssuer); err != nil {
		return err
	}
	// §14.8, same rule as Issue: a renewal planned against a superseded
	// settings snapshot is redone rather than committed.
	if err := settingsUnchanged(ctx, tx, prep.settingsVersion); err != nil {
		return err
	}
	if err := ensureSerialUnused(ctx, tx, prep.plan.IssuerKeyGenerationID, prep.certificate.Serial()); err != nil {
		return err
	}

	cert := prep.certificate
	if err := tx.PKI().InsertCertificate(ctx, cert); err != nil {
		return storeError(err, "issuance_certificate_store_failed", "could not store the renewed certificate")
	}

	var leafKeyGenID domain.LeafKeyGenerationID
	var deliveryID domain.DeliveryID
	if prep.keyRotated {
		newGenID, err := domain.ParseLeafKeyGenerationID(s.deps.IDs.NewUUID())
		if err != nil {
			return contract.FromDomainError(err)
		}
		newGen, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
			ID:            newGenID,
			SeriesID:      snapshot.Series.ID(),
			KeyMaterialID: prep.keyMaterialID,
			GenerationNo:  prep.renewalPlan.NextKeyGenerationNo,
			RenewalCount:  prep.renewalPlan.NextRenewalCount,
			Custody:       domain.KeyCustodyPendingDelivery,
		})
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.PKI().InsertLeafKeyGeneration(ctx, newGen); err != nil {
			return storeError(err, "issuance_leaf_key_generation_store_failed", "could not store the rotated leaf key generation")
		}
		leafKeyGenID = newGenID
		if prep.generatedSecret == nil {
			return contract.NewAppError(contract.ErrorKindUnavailable, "issuance_missing_generated_secret",
				"a key rotation did not produce a key to store")
		}
		delivery, err := storeFreshKeyAndDelivery(ctx, tx, s.deps.IDs, prep.now, prep.keyMaterialID, prep.publicKey, *prep.generatedSecret, newGenID, cert.ID(), prep.deliverySeconds)
		if err != nil {
			return err
		}
		deliveryID = delivery.ID()
	} else {
		leafKeyGenID = prep.renewalPlan.KeyGenerationID
		updatedGen, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
			ID:                  snapshot.CurrentKeyGeneration.ID(),
			SeriesID:            snapshot.CurrentKeyGeneration.SeriesID(),
			KeyMaterialID:       snapshot.CurrentKeyGeneration.KeyMaterialID(),
			GenerationNo:        snapshot.CurrentKeyGeneration.GenerationNo(),
			RenewalCount:        prep.renewalPlan.NextRenewalCount,
			PriorHistoryUnknown: snapshot.CurrentKeyGeneration.PriorHistoryUnknown(),
			Custody:             snapshot.CurrentKeyGeneration.Custody(),
		})
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.PKI().SaveLeafKeyGeneration(ctx, updatedGen); err != nil {
			return storeError(err, "issuance_leaf_key_generation_save_failed", "could not update the leaf key generation")
		}
	}

	updatedSeries, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID:                     snapshot.Series.ID(),
		Name:                   snapshot.Series.Name(),
		Purpose:                snapshot.Series.Purpose(),
		ManagementAuthorityID:  snapshot.Series.ManagementAuthorityID(),
		CurrentCertificateID:   cert.ID(),
		CurrentKeyGenerationID: leafKeyGenID,
		Policy:                 snapshot.Series.Policy(),
		Version:                snapshot.Series.Version().Next(),
	})
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.PKI().SaveSeries(ctx, updatedSeries, expectedVersion); err != nil {
		return storeError(err, "issuance_series_save_failed", "could not update the series")
	}

	// §14.2/§14.4: the leaf_certificates subtype row, in the same Write as
	// the certificate. Operation distinguishes an ordinary reuse renewal
	// from one that rotated to a new key, per data-model.md's
	// operation=initial/renew/rekey/migrate/emergency/import enum; no doc in
	// this developer's scope names which of renew/rekey applies to which
	// case, so this maps key-reuse to "renew" and key-rotation to "rekey" as
	// the most literal reading of the enum names -- flagged for the lead to
	// confirm.
	operation := port.CertificateOperationRenew
	if prep.keyRotated {
		operation = port.CertificateOperationRekey
	}
	policySnapshot, err := leafPolicySnapshotJSON(cert, snapshot.Series.Policy())
	if err != nil {
		return err
	}
	if err := tx.PKI().InsertLeafCertificateRecord(ctx, port.LeafCertificateRecord{
		CertificateID:         cert.ID(),
		SeriesID:              snapshot.Series.ID(),
		LeafKeyGenerationID:   leafKeyGenID,
		IssuerCACertificateID: prep.issuerCertificate.ID(),
		PreviousCertificateID: cmd.SourceCertificateID,
		Operation:             operation,
		RenewalCountAtIssue:   prep.renewalPlan.NextRenewalCount,
		PolicySnapshotJSON:    policySnapshot,
	}); err != nil {
		return storeError(err, "issuance_leaf_certificate_record_store_failed", "could not store the leaf certificate record")
	}

	view := storedIssuanceResult{
		SchemaVersion:   issuanceStoredResultSchemaVersion,
		SeriesID:        string(snapshot.Series.ID()),
		CertificateID:   string(cert.ID()),
		KeyGenerationID: string(leafKeyGenID),
		RenewalCount:    int64(prep.renewalPlan.NextRenewalCount),
		KeyRotated:      prep.keyRotated,
		DeliveryID:      string(deliveryID),
	}
	if err := StoreRequestResult(ctx, tx, reqKey, inputHash, view); err != nil {
		return err
	}
	if err := appendIssuanceAudit(ctx, tx, s.deps.IDs, prep.now, meta, "issuance.renew", cert, targetIssuer.ID()); err != nil {
		return err
	}
	v, err := view.toView(ctx, tx)
	if err != nil {
		return err
	}
	*result = v
	return nil
}
