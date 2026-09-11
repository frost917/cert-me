package service

import (
	"context"
	"encoding/json"
	"errors"
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

// defaultLeafValidityYears/defaultRotateEvery/defaultPrivateDeliverySeconds
// are the certificate-lifecycle.md factory defaults ("Leaf 기본 유효기간
// 1년", "기본 교체 주기는 3회", "개인키 수령 기한은 발급 후 기본 3시간"),
// used when an issuance omits validity/rotate_every and no installation
// Settings row has resolved them yet (a fresh install before SettingsService
// has ever been touched).
const (
	defaultLeafValidityYears      = 1
	defaultRotateEvery            = 3
	defaultPrivateDeliverySeconds = 3 * 60 * 60
	issuanceOperationIssue        = "issuance.issue"
	issuanceOperationRenew        = "issuance.renew"
)

// IssuanceDeps is IssuanceService's dependency set: CommonDeps plus the
// signing dependencies docs/backend-implementation.md §5 names for
// Authority/Issuance ("KeyEngine, CertificateSigner, ProfileValidator").
type IssuanceDeps struct {
	CommonDeps
	KeyEngine         port.KeyEngine
	CertificateSigner port.CertificateSigner
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
// contract.IssuanceView and contract.DeliveryView are not stored directly:
// domain.Instant has no MarshalJSON/UnmarshalJSON of its own (its only field
// is unexported), so encoding/json would silently serialize every
// domain.Instant field in DeliveryView as "{}" and decode it back as the
// zero instant -- corrupting the stored ExpiresAt on every replay. This is a
// domain.Instant gap flagged for the lead (out of this developer's assigned
// files); this local, service-owned wire shape works around it by carrying
// every instant as its UnixMicro int64 instead.

type storedDeliveryView struct {
	ID              string `json:"id"`
	CertificateID   string `json:"certificate_id"`
	State           string `json:"state"`
	ExpiresAtMicros int64  `json:"expires_at_micros"`
	FailureCode     string `json:"failure_code,omitempty"`
	Version         int64  `json:"version"`
}

type storedIssuanceResult struct {
	SeriesID        string              `json:"series_id"`
	CertificateID   string              `json:"certificate_id"`
	KeyGenerationID string              `json:"key_generation_id"`
	RenewalCount    int64               `json:"renewal_count"`
	KeyRotated      bool                `json:"key_rotated"`
	Delivery        *storedDeliveryView `json:"delivery,omitempty"`
}

func toStoredDeliveryView(d domain.Delivery) *storedDeliveryView {
	return &storedDeliveryView{
		ID:              string(d.ID()),
		CertificateID:   string(d.CertificateID()),
		State:           string(d.State()),
		ExpiresAtMicros: d.ExpiresAt().UnixMicro(),
		FailureCode:     d.FailureCode(),
		Version:         d.Version().Int64(),
	}
}

func (v storedIssuanceResult) toView() contract.IssuanceView {
	out := contract.IssuanceView{
		SeriesID:        domain.SeriesID(v.SeriesID),
		CertificateID:   domain.CertificateID(v.CertificateID),
		KeyGenerationID: domain.LeafKeyGenerationID(v.KeyGenerationID),
		RenewalCount:    v.RenewalCount,
		KeyRotated:      v.KeyRotated,
	}
	if v.Delivery != nil {
		expires := domain.InstantFromUnixMicro(v.Delivery.ExpiresAtMicros)
		out.Delivery = &contract.DeliveryView{
			ID:            domain.DeliveryID(v.Delivery.ID),
			CertificateID: domain.CertificateID(v.Delivery.CertificateID),
			State:         domain.DeliveryState(v.Delivery.State),
			ExpiresAt:     expires,
			FailureCode:   v.Delivery.FailureCode,
			Version:       domain.Version(v.Delivery.Version),
		}
	}
	return out
}

// ---- installation Settings resolution ----

// installationSettingsSnapshot is the subset of the service_settings JSON
// blob this service needs to resolve an omitted validity/rotate_every
// (docs/backend-implementation.md §3 "생략된 기본값은 발급 시 확정해 결과에
// 포함한다"). FLAGGED FOR THE LEAD: SettingsService (B04) has not been
// implemented yet and no shared encoder/decoder for service_settings.
// settings_json is reachable from this package, so the field names below
// are this developer's placeholder guess at the wire shape, not a decided
// contract. It only matters for a brand-new request's default resolution
// (see StoreRequestResult/ReplayStoredResult below): the idempotency hash
// itself never carries a resolved value, so a mismatch here cannot corrupt
// idempotency correctness, only which default a first-time omitted field
// gets. This must be reconciled with SettingsService before B04.
type installationSettingsSnapshot struct {
	LeafValidityValue      int    `json:"leaf_validity_value"`
	LeafValidityUnit       string `json:"leaf_validity_unit"`
	RotateEvery            int    `json:"rotate_every"`
	PrivateDeliverySeconds int    `json:"private_delivery_seconds"`
}

// resolvedSeriesDefaults is what a fresh Issue call needs once
// validity/rotate_every are settled, whether from the request or Settings.
type resolvedSeriesDefaults struct {
	Validity               domain.CalendarValidity
	RotateEvery            int
	PrivateDeliverySeconds int
}

// resolveSeriesDefaults fills in an omitted validity/rotate_every from the
// current installation Settings, falling back to the certificate-
// lifecycle.md factory defaults when no Settings row has been saved yet (a
// fresh install) or the stored blob does not decode. It always resolves
// PrivateDeliverySeconds from Settings/the factory default, since
// IssuanceIssueCommand carries no per-request override for that field.
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

	if out.Validity.IsZero() || out.RotateEvery == 0 || out.PrivateDeliverySeconds == 0 {
		settings, err := tx.Installation().GetSettings(ctx)
		switch {
		case err == nil:
			var snap installationSettingsSnapshot
			if decodeErr := json.Unmarshal(settings.SettingsJSON, &snap); decodeErr == nil {
				if out.Validity.IsZero() && snap.LeafValidityValue > 0 {
					if v, e := domain.NewCalendarValidity(snap.LeafValidityValue, domain.ValidityUnit(snap.LeafValidityUnit)); e == nil {
						out.Validity = v
					}
				}
				if out.RotateEvery == 0 && snap.RotateEvery > 0 {
					out.RotateEvery = snap.RotateEvery
				}
				if snap.PrivateDeliverySeconds > 0 {
					out.PrivateDeliverySeconds = snap.PrivateDeliverySeconds
				}
			}
		case errors.Is(err, port.ErrNotFound):
			// No Settings row yet (fresh install): fall through to the
			// factory defaults below.
		default:
			return resolvedSeriesDefaults{}, storeError(err, "issuance_settings_read_failed", "could not read installation settings")
		}
	}

	if out.Validity.IsZero() {
		v, err := domain.NewCalendarValidity(defaultLeafValidityYears, domain.ValidityUnitYears)
		if err != nil {
			return resolvedSeriesDefaults{}, contract.FromDomainError(err)
		}
		out.Validity = v
	}
	if out.RotateEvery == 0 {
		out.RotateEvery = defaultRotateEvery
	}
	if out.PrivateDeliverySeconds == 0 {
		out.PrivateDeliverySeconds = defaultPrivateDeliverySeconds
	}
	return out, nil
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

// issuerSigningSecret resolves issuer's own encrypted CA key. Authority
// carries a CAKeyGenerationID, not a KeyMaterialID, and PKIRepository has no
// method to read a stored CAKeyGeneration row back by id -- so this goes
// through issuer's own certificate instead (Authority.IssuanceCertificateID
// -> PKIRepository.GetCertificate -> Certificate.KeyMaterialID), which is
// already guaranteed set for any authority CanIssue accepts. This is an
// interpretation of an incomplete PKIRepository, flagged for the lead rather
// than adding the missing method myself (internal/app/port is out of this
// developer's assigned files).
func issuerSigningSecret(ctx context.Context, tx port.TxStores, issuer domain.Authority) (domain.EncryptedSecret, error) {
	caCert, err := tx.PKI().GetCertificate(ctx, issuer.IssuanceCertificateID())
	if err != nil {
		return domain.EncryptedSecret{}, storeError(err, "issuance_issuer_certificate_read_failed",
			"could not read the issuing authority's own certificate")
	}
	purpose := domain.SecretPurposeCASigning
	if issuer.Kind() == domain.AuthorityKindBootstrap {
		purpose = domain.SecretPurposeBootstrapCA
	}
	secret, err := tx.Secrets().GetEncrypted(ctx, caCert.KeyMaterialID(), purpose)
	if err != nil {
		return domain.EncryptedSecret{}, storeError(err, "issuance_issuer_secret_read_failed",
			"could not read the issuing authority's signing key")
	}
	return secret, nil
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
		var view storedIssuanceResult
		if err := DecodeStoredResult(stored, &view); err != nil {
			return err
		}
		*result = view.toView()
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
	now             domain.Instant
	policy          domain.SeriesPolicy
	defaults        resolvedSeriesDefaults
	plan            domain.IssuancePlan
	keyMaterialID   domain.KeyMaterialID
	publicKey       domain.PublicKey
	generatedSecret *domain.EncryptedSecret
	certificate     domain.Certificate
}

// prepareIssue performs §8's out-of-transaction preparation. Its reads go
// through ReadStore, whose contract is that a read is preparation input only
// and never authorizes a commit.
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

		secret, err := issuerSigningSecret(ctx, tx, a)
		if err != nil {
			return err
		}
		issuerSecret = secret
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

	if reuse != nil {
		prep.keyMaterialID, prep.publicKey, prep.generatedSecret = reuse.keyMaterialID, reuse.publicKey, reuse.generatedSecret
	} else {
		newKeyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
		if err != nil {
			return issuePrepared{}, contract.FromDomainError(err)
		}
		ref := signingKeyRef{Fresh: &port.KeySpec{KeyMaterialID: newKeyMaterialID, Algorithm: req.KeyAlgorithm, Purpose: domain.SecretPurposeLeafDelivery}}
		keyMaterialID, publicKey, generatedSecret, err := resolveSigningKey(ctx, s.deps.KeyEngine, ref)
		if err != nil {
			return issuePrepared{}, err
		}
		prep.keyMaterialID, prep.publicKey, prep.generatedSecret = keyMaterialID, publicKey, generatedSecret
	}

	cert, err := signCertificate(ctx, s.deps.CertificateSigner, s.deps.IDs, plan, issuerSecret, prep.keyMaterialID, domain.CertificateKindLeaf, meta.Principal.AccountID())
	if err != nil {
		return issuePrepared{}, err
	}
	prep.certificate = cert
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
		var view storedIssuanceResult
		if err := DecodeStoredResult(stored, &view); err != nil {
			return err
		}
		*result = view.toView()
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
		SeriesID:        string(seriesID),
		CertificateID:   string(cert.ID()),
		KeyGenerationID: string(leafKeyGenID),
		RenewalCount:    0,
		KeyRotated:      true,
		Delivery:        toStoredDeliveryView(delivery),
	}
	if err := StoreRequestResult(ctx, tx, reqKey, inputHash, view); err != nil {
		return err
	}
	if err := appendIssuanceAudit(ctx, tx, s.deps.IDs, prep.now, meta, "issuance.issue", cert, authorityID); err != nil {
		return err
	}
	*result = view.toView()
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
	renewalPlan       domain.RenewalPlan
	plan              domain.IssuancePlan
	keyRotated        bool
	keyMaterialID     domain.KeyMaterialID
	publicKey         domain.PublicKey
	generatedSecret   *domain.EncryptedSecret
	deliverySeconds   int
	certificate       domain.Certificate
}

// prepareRenew reads the series/certificate/issuer snapshot, plans the
// renewal and signs -- all outside any transaction (§8). The renewal
// decision it makes here (reuse the key or rotate) is re-derived and
// re-checked inside commitRenew before anything is stored.
func (s *IssuanceService) prepareRenew(ctx context.Context, meta contract.MutationMeta, cmd contract.IssuanceRenewCommand, seriesID domain.SeriesID, expectedVersion domain.Version, reuse *renewPrepared) (renewPrepared, error) {
	prep := renewPrepared{now: s.deps.Clock.Now()}

	var (
		currentCert  domain.Certificate
		targetIssuer domain.Authority
		issuerSecret domain.EncryptedSecret
		revoked      bool
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

		secret, err := issuerSigningSecret(ctx, tx, issuer)
		if err != nil {
			return err
		}
		issuerSecret = secret

		defaults, err := resolveSeriesDefaults(ctx, tx, nil, nil)
		if err != nil {
			return err
		}
		prep.deliverySeconds = defaults.PrivateDeliverySeconds
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
	prep.plan = domain.IssuancePlan{
		Profile:               currentCert.Profile(),
		Subject:               currentCert.Subject(),
		SANs:                  currentCert.SANs(),
		KeyAlgorithm:          currentCert.KeyAlgorithm(),
		Window:                renewalPlan.Window,
		IssuerAuthorityID:     targetIssuer.ID(),
		IssuerKeyGenerationID: targetIssuer.KeyGenerationID(),
	}

	switch {
	case reuse != nil && reuse.keyRotated == prep.keyRotated:
		// Collision retry: re-sign against the key the first attempt already
		// resolved instead of generating another one.
		prep.keyMaterialID, prep.publicKey, prep.generatedSecret = reuse.keyMaterialID, reuse.publicKey, reuse.generatedSecret
	case !prep.keyRotated:
		// An ordinary renewal signs against the stored public key; the leaf
		// private key is never read (certificate-lifecycle.md "일반 갱신에
		// 서버 보관 Leaf 개인키는 필요하지 않다").
		prep.keyMaterialID = prep.snapshot.CurrentKeyGeneration.KeyMaterialID()
	default:
		newKeyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
		if err != nil {
			return renewPrepared{}, contract.FromDomainError(err)
		}
		ref := signingKeyRef{Fresh: &port.KeySpec{KeyMaterialID: newKeyMaterialID, Algorithm: currentCert.KeyAlgorithm(), Purpose: domain.SecretPurposeLeafDelivery}}
		keyMaterialID, publicKey, generatedSecret, err := resolveSigningKey(ctx, s.deps.KeyEngine, ref)
		if err != nil {
			return renewPrepared{}, err
		}
		prep.keyMaterialID, prep.publicKey, prep.generatedSecret = keyMaterialID, publicKey, generatedSecret
	}

	cert, err := signCertificate(ctx, s.deps.CertificateSigner, s.deps.IDs, prep.plan, issuerSecret, prep.keyMaterialID, domain.CertificateKindLeaf, meta.Principal.AccountID())
	if err != nil {
		return renewPrepared{}, err
	}
	prep.certificate = cert
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
		var view storedIssuanceResult
		if err := DecodeStoredResult(stored, &view); err != nil {
			return err
		}
		*result = view.toView()
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
	if err := ensureSerialUnused(ctx, tx, prep.plan.IssuerKeyGenerationID, prep.certificate.Serial()); err != nil {
		return err
	}

	cert := prep.certificate
	if err := tx.PKI().InsertCertificate(ctx, cert); err != nil {
		return storeError(err, "issuance_certificate_store_failed", "could not store the renewed certificate")
	}

	var leafKeyGenID domain.LeafKeyGenerationID
	var deliveryView *storedDeliveryView
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
		deliveryView = toStoredDeliveryView(delivery)
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

	view := storedIssuanceResult{
		SeriesID:        string(snapshot.Series.ID()),
		CertificateID:   string(cert.ID()),
		KeyGenerationID: string(leafKeyGenID),
		RenewalCount:    int64(prep.renewalPlan.NextRenewalCount),
		KeyRotated:      prep.keyRotated,
		Delivery:        deliveryView,
	}
	if err := StoreRequestResult(ctx, tx, reqKey, inputHash, view); err != nil {
		return err
	}
	if err := appendIssuanceAudit(ctx, tx, s.deps.IDs, prep.now, meta, "issuance.renew", cert, targetIssuer.ID()); err != nil {
		return err
	}
	*result = view.toView()
	return nil
}
