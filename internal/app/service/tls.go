// Package service contains the application orchestration for TLS candidate
// management, explicit file reload, bootstrap HTTPS and restart recovery.
// Preparation happens outside writes; every commit path re-checks the
// authoritative installation/PKI facts while holding its transaction lock
// (docs/backend-implementation.md §§8–9, 15.3).
package service

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// TLSDeps is TLSService's dependency set. The file source is intentionally a
// narrow configured-source port: Reload has an empty command and never
// accepts an arbitrary path from the request.
type TLSDeps struct {
	CommonDeps
	KeyEngine         port.KeyEngine
	CertificateSigner port.CertificateSigner
	SerialGenerator   port.SerialGenerator
	ChainValidator    port.ChainValidator
	TLSInstaller      port.TLSInstaller
	PKIParser         port.PKIParser
	FileSource        port.TLSFileSource
	RuntimeGate       port.RuntimeGate
}

// Validate reports the first missing dependency, common or TLS-specific.
func (d TLSDeps) Validate() error {
	if err := d.CommonDeps.Validate(); err != nil {
		return err
	}
	return firstMissing(
		required{"KeyEngine", d.KeyEngine == nil},
		required{"CertificateSigner", d.CertificateSigner == nil},
		required{"SerialGenerator", d.SerialGenerator == nil},
		required{"ChainValidator", d.ChainValidator == nil},
		required{"TLSInstaller", d.TLSInstaller == nil},
		required{"PKIParser", d.PKIParser == nil},
		required{"FileSource", d.FileSource == nil},
		required{"RuntimeGate", d.RuntimeGate == nil},
	)
}

// TLSService implements the complete B04 TLS service surface.
//
// mu is the "프로세스 내 TLS 변경 mutex" §9 requires under Activate: it
// serializes the whole prepare-validate-commit-apply-record sequence (and
// Reconcile's analogous one) so two concurrent callers can never both decide
// they own the in-memory listener swap at once. It is process-local by
// design -- the DB-level optimistic lock (installation.version) is the
// cross-process guard; this mutex is the additional in-process one §9 names
// separately because TLSInstaller.Apply itself has no locking of its own.
type TLSService struct {
	deps TLSDeps
	mu   sync.Mutex
}

// NewTLSService constructs the service, failing fast on a missing
// dependency (§5 "필수 의존성이 nil이면 시작 시 실패한다").
func NewTLSService(deps TLSDeps) (*TLSService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &TLSService{deps: deps}, nil
}

// tlsScope is the installation-wide scope for TLS management events. It is a
// typed installation scope, not an empty authority list that could be
// misinterpreted as unrestricted access.
func tlsScope() port.AuditScope { return port.NewInstallationAuditScope() }

// requireInternalOperation is §13 ruling 5's gate for TLS.Bootstrap/
// TLS.Reconcile: "대응 내부 operation만 허용한다
// (port.Action.RequiredInternalOperation()이 이미 그 짝을 갖고 있다)". It is
// checked directly against the principal rather than through the generic
// Authorizer, the same way crl.go's Publish checks
// Principal.Can(InternalOperationCRLPublish) directly -- there is no
// AuthorityID scope an AuthorizationScope would add for a process-internal
// caller, and unlike ActionCRLPublish, ActionTLSReconcile/ActionTLSBootstrap
// ARE paired in port.actionInternalOperations, so RequiredInternalOperation
// is used here instead of a hand-rolled pairing.
func requireInternalOperation(principal contract.Principal, action port.Action) error {
	op, ok := action.RequiredInternalOperation()
	if !ok {
		// Every action this file actually calls this for is paired; a
		// caller passing an unpaired action is this file's own bug, not a
		// caller-facing situation, but §13 ruling 5's "미정의 Action은
		// 거부한다" still applies rather than defaulting to permissive.
		return contract.NewAppError(contract.ErrorKindForbidden, "tls_internal_action_undefined",
			"this action has no configured internal operation").WithField("action", string(action))
	}
	if !principal.IsInternal() || !principal.Can(op) {
		return contract.NewAppError(contract.ErrorKindForbidden, "tls_internal_operation_required",
			"this operation requires the matching internal operation").WithField("action", string(action))
	}
	return nil
}

// ---- shared view/facts helpers ----

// toTLSVersionView projects a domain.TLSVersion into its OpenAPI shape.
func toTLSVersionView(v domain.TLSVersion) contract.TLSVersionView {
	view := contract.TLSVersionView{
		ID:                  v.ID(),
		Source:              v.Source(),
		NotAfter:            v.NotAfter(),
		ValidatedServiceURL: v.ValidatedServiceURL(),
	}
	if certID := v.ManagedCertificateID(); certID != "" {
		view.CertificateID = &certID
	}
	return view
}

// currentServiceURL reads the installation's current Settings.ServiceURL, or
// "" if Settings has never been configured (a fresh installation with no
// settings row is not this function's error to raise -- its callers treat an
// empty result as "nothing to compare against" the same way
// settings_service.go's requireServiceURLMatchesActiveTLS does).
func currentServiceURL(ctx context.Context, tx port.TxStores) (string, error) {
	settings, err := tx.Installation().GetSettings(ctx)
	if errors.Is(err, port.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", storeError(err, "tls_settings_read_failed", "could not read installation settings")
	}
	snap, err := DecodeSettingsV1(settings)
	if err != nil {
		return "", err
	}
	return snap.ServiceURL, nil
}

// serviceAddressMatchesSANs reports whether one of sans names serviceURL's
// host, the real-address check architecture.md requires for a non-bootstrap
// candidate ("운영 인증서 교체 후보에는 실제 서비스 주소 검증을 적용한다")
// without specifying an exact algorithm. This developer's reading: exact
// (case-insensitive for dns) host equality against a dns/ip SAN -- flagged
// for the lead as an inference, not a literal doc rule.
func serviceAddressMatchesSANs(serviceURL string, sans []domain.SAN) bool {
	u, err := url.Parse(serviceURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, s := range sans {
			if s.Type() == domain.SANTypeIP && s.Value() == ip.String() {
				return true
			}
		}
		return false
	}
	lowerHost := strings.ToLower(host)
	for _, s := range sans {
		if s.Type() == domain.SANTypeDNS && strings.ToLower(s.Value()) == lowerHost {
			return true
		}
	}
	return false
}

// pemEncodeChain concatenates chainDER into a PEM bundle. This is this
// developer's inferred wire representation for tls_versions.chain_bundle --
// no doc fixes the byte format, and architecture.md's directory notes assign
// "묶음" (bundling) to internal/adapter/crypto, not internal/app/service.
// PEM concatenation is the ordinary, unambiguous shape of a "chain.pem" file
// (docs/backend-implementation.md §14.3 already uses exactly this shape for
// the public download's chain.pem) and is plain text encoding, not
// cryptography, so this developer judged it safe to compute directly with
// the standard library rather than block IssueCandidate on it entirely.
// Flagged for the lead to confirm against whatever B05's real TLSInstaller
// adapter expects.
func pemEncodeChain(chainDER [][]byte) []byte {
	var buf bytes.Buffer
	for _, der := range chainDER {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return buf.Bytes()
}

// splitPEMChain reverses pemEncodeChain, used by Reconcile to recover chain
// DER pieces for ChainValidator from a stored bootstrap/external candidate's
// chain_bundle (a managed candidate's chain is instead walked fresh from the
// stored PKI relations via buildChainDER, which needs no such round trip).
// Same inferred-format caveat as pemEncodeChain.
func splitPEMChain(bundle []byte) ([][]byte, error) {
	var out [][]byte
	rest := bundle
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
	if len(out) == 0 && len(bundle) > 0 {
		return nil, contract.NewAppError(contract.ErrorKindUnavailable, "tls_chain_bundle_undecodable",
			"the stored chain bundle could not be decoded")
	}
	return out, nil
}

// buildValidationFacts computes domain.TLSValidationFacts for candidate
// against now, the input domain.TLSChange.ValidateCandidate/Reconcile need
// to decide whether a candidate may become (or stay) active. now is always
// caller-supplied and always read AFTER whatever lock the caller holds --
// this function never calls the clock itself, so it cannot reintroduce a
// stale-now bug at a second remove.
func (s *TLSService) buildValidationFacts(ctx context.Context, tx port.TxStores, candidate domain.TLSVersion, now domain.Instant) (domain.TLSValidationFacts, error) {
	facts := domain.TLSValidationFacts{CandidateSource: candidate.Source()}
	facts.WithinValidityPeriod = !candidate.IsExpiredAt(now)

	var chainDER [][]byte
	if candidate.Source() == domain.TLSSourceManaged {
		cert, err := tx.PKI().GetCertificate(ctx, candidate.ManagedCertificateID())
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return domain.TLSValidationFacts{}, contract.NewAppError(contract.ErrorKindUnavailable,
					"tls_candidate_certificate_missing", "the candidate's managed certificate could not be found")
			}
			return domain.TLSValidationFacts{}, storeError(err, "tls_candidate_certificate_read_failed",
				"could not read the candidate's managed certificate")
		}
		facts.PurposeMatchesServerAuth = cert.Profile() == domain.CertificateProfileServerTLS
		facts.KeyMatchesCertificate = cert.KeyMaterialID() == candidate.KeyMaterialID()
		chain, err := buildChainDER(ctx, tx, candidate.ManagedCertificateID())
		if err != nil {
			return domain.TLSValidationFacts{}, err
		}
		chainDER = chain
	} else {
		// Bootstrap and uploaded external candidates are immutable snapshots.
		// Bootstrap facts are fixed by prepareBootstrap; external facts were
		// parsed and checked by uploadCandidate before their snapshot was
		// stored. Reconcile still parses the stored chain bytes and always
		// reruns chain validation below, while the purpose/key facts come from
		// that earlier typed validation rather than from a request payload.
		chain, err := splitPEMChain(candidate.ChainBundle())
		if err != nil {
			return domain.TLSValidationFacts{}, err
		}
		chainDER = chain
		facts.PurposeMatchesServerAuth = true
		facts.KeyMatchesCertificate = true
	}

	facts.ChainVerified = s.deps.ChainValidator.Validate(ctx, candidate.LeafDER(), chainDER, now) == nil

	if candidate.Source() == domain.TLSSourceBootstrap {
		facts.ServiceAddressMatches = true // not required for bootstrap (domain.TLSValidationFacts.requiresServiceAddress)
	} else {
		serviceURL, err := currentServiceURL(ctx, tx)
		if err != nil {
			return domain.TLSValidationFacts{}, err
		}
		facts.ServiceAddressMatches = candidate.ValidatedServiceURL() != "" && candidate.ValidatedServiceURL() == serviceURL
	}
	return facts, nil
}

// ---- Status ----

// Status reports the installation's current TLS state
// (docs/backend-implementation.md §3 "Status: Empty → TLSStatus").
func (s *TLSService) Status(ctx context.Context, meta contract.RequestMeta, cmd contract.TLSStatusQuery) (contract.TLSStatusView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TLSStatusView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.TLSStatusView{}, contract.NewAppError(contract.ErrorKindForbidden, "tls_requires_admin",
			"reading TLS status requires an administrator session")
	}

	var view contract.TLSStatusView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTLSStatus, port.NewAuthorizationScope()); err != nil {
			return err
		}
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return storeError(err, "tls_installation_read_failed", "could not read the installation state")
		}
		view.Version = installation.Version
		if installation.ActiveTLSVersionID == "" {
			return nil // fresh installation: no HTTPS version has ever been active
		}
		change, err := tx.TLS().GetActiveForUpdate(ctx)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindUnavailable, "tls_active_change_missing",
					"the installation names an active TLS version with no change record")
			}
			return storeError(err, "tls_active_change_read_failed", "could not read the active TLS change")
		}
		version, err := tx.TLS().GetVersion(ctx, installation.ActiveTLSVersionID)
		if err != nil {
			return storeError(err, "tls_active_version_read_failed", "could not read the active TLS version")
		}
		activeView := toTLSVersionView(version)
		view.Active = &activeView
		phase := change.Phase()
		view.Phase = &phase
		candidateID := change.CandidateVersionID()
		view.CandidateID = &candidateID
		view.ErrorCode = change.ErrorCode()
		return nil
	})
	if err != nil {
		return contract.TLSStatusView{}, err
	}
	return view, nil
}

// ---- UploadCandidate ----

// UploadCandidate stores an operator-supplied certificate/chain/key as a new,
// unactivated TLSVersion candidate (docs/backend-implementation.md §3
// "UploadCandidate: TLSUpload -> TLSVersion"). Unlike IssueCandidate this
// never touches CertificateSigner/SerialGenerator or any PKI issuance row --
// the certificate already exists; this only validates it and stores it as an
// external-source candidate (domain.TLSSourceExternal), exactly parallel to
// IssueCandidate storing a managed one.
//
// Parsing (PKIParser) and key import (KeyEngine.ImportTLS) both run OUTSIDE
// the Write, mirroring prepareIssueCandidate/prepareCertificate's own split
// (§8 "준비는 트랜잭션 밖"): the Write only re-confirms auth/authorization and
// persists what was already built and validated.
//
// §13 ruling 4's secret lifecycle: ParseInternalTLSKey hands this call a
// freshly-decrypted secret.Input it owns (a NEW one, distinct from
// cmd.Passphrase); it is deferred closed immediately after a successful
// parse (§10 "secret은 즉시 defer Close"), covering KeyEngine.ImportTLS's
// success and failure paths and every return above that point alike. If
// ParseInternalTLSKey itself fails, there is nothing for this call to close --
// its own doc comment requires the parser to close whatever secret it
// created internally before returning an error ("중간 실패 시 파서가 이미
// 만든 비밀을 닫는다"). cmd.Key's own Passphrase is NEVER closed here: per
// TLSUploadCandidateCommand's doc comment it is owned by the CALLER of this
// method, which releases it after UploadCandidate returns, success or not.
//
// This never creates a leaf_delivery/DownloadGrant row, structurally, the
// same way IssueCandidate does not: §5's "계획의 custody가 처음부터
// internal이며 response에 download grant가 없다" applies equally to an
// uploaded certificate's private key, which is stored for the installer's
// own use, never queued for one-shot pickup.
//
// One inference this developer made, flagged for the lead: cmd.Certificate
// and cmd.Chain are two SEPARATE byte fields on the command (unlike a single
// combined PEM bundle), so this reads Certificate as exactly one leaf
// certificate and Chain as zero or more intermediate certificates, in
// upload order -- the natural reading of two distinct fields, but not a
// literal rule any doc states in those words.
func (s *TLSService) UploadCandidate(ctx context.Context, meta contract.MutationMeta, cmd contract.TLSUploadCandidateCommand) (contract.TLSVersionView, error) {
	return s.uploadCandidate(ctx, meta, cmd, port.ActionTLSUploadCandidate, "tls.upload_candidate", false)
}

func (s *TLSService) uploadCandidate(ctx context.Context, meta contract.MutationMeta, cmd contract.TLSUploadCandidateCommand, action port.Action, auditAction string, admitted bool) (contract.TLSVersionView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TLSVersionView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.TLSVersionView{}, contract.NewAppError(contract.ErrorKindForbidden, "tls_requires_admin",
			"uploading a TLS candidate requires an administrator session")
	}
	if !admitted {
		// §6/§8: admission is checked before any expensive parsing/import work.
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, action, port.NewAuthorizationScope()); err != nil {
			return contract.TLSVersionView{}, err
		}
		if err := ctx.Err(); err != nil {
			return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
				"the request was canceled before it completed", err)
		}
		// Authentication can become stale while the request is being prepared.
		// Re-check it before parsing/importing the supplied key so an expired or
		// superseded session cannot spend work or reach the write path. The write
		// below repeats this check under the commit transaction for the required
		// TOCTOU protection.
		if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
			return requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock)
		}); err != nil {
			return contract.TLSVersionView{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	leafBundle, err := s.deps.PKIParser.ParseCertificateBundle(ctx, port.CertificateBundleInput{Data: cmd.Certificate})
	if err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindValidation, "tls_upload_certificate_invalid",
			"the uploaded certificate could not be parsed", err)
	}
	if len(leafBundle.Certificates) != 1 {
		return contract.TLSVersionView{}, contract.NewAppError(contract.ErrorKindValidation, "tls_upload_certificate_count",
			"the certificate field must contain exactly one certificate").
			WithField("count", fmt.Sprintf("%d", len(leafBundle.Certificates)))
	}
	leaf := leafBundle.Certificates[0]
	if err := validateParsedCertificateFacts(leaf); err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindValidation, "tls_upload_certificate_facts_invalid",
			"the uploaded certificate facts are inconsistent", err)
	}
	if leaf.Kind != domain.CertificateKindLeaf {
		return contract.TLSVersionView{}, contract.NewAppError(contract.ErrorKindValidation, "tls_upload_certificate_kind",
			"the TLS certificate must be a leaf certificate")
	}
	if leaf.Profile != domain.CertificateProfileServerTLS {
		return contract.TLSVersionView{}, contract.NewAppError(contract.ErrorKindValidation, "tls_upload_certificate_purpose",
			"the TLS certificate must have the serverAuth profile")
	}
	if err := domain.ValidateSANsForProfile(leaf.Profile, leaf.SANs); err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindValidation, "tls_upload_certificate_purpose",
			"the TLS certificate SANs do not satisfy the serverAuth profile", err)
	}

	var chainDER [][]byte
	if len(cmd.Chain) > 0 {
		chainBundle, err := s.deps.PKIParser.ParseCertificateBundle(ctx, port.CertificateBundleInput{Data: cmd.Chain})
		if err != nil {
			return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindValidation, "tls_upload_chain_invalid",
				"the uploaded chain could not be parsed", err)
		}
		for _, c := range chainBundle.Certificates {
			if err := validateParsedCertificateFacts(c); err != nil {
				return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindValidation, "tls_upload_chain_facts_invalid",
					"the uploaded chain facts are inconsistent", err)
			}
			if c.Kind != domain.CertificateKindCA {
				return contract.TLSVersionView{}, contract.NewAppError(contract.ErrorKindValidation, "tls_upload_chain_not_ca",
					"every uploaded TLS chain certificate must be a CA certificate")
			}
			chainDER = append(chainDER, c.DER)
		}
	}
	if err := s.deps.ChainValidator.Validate(ctx, leaf.DER, chainDER, s.deps.Clock.Now()); err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindValidation, "tls_upload_chain_invalid",
			"the uploaded TLS certificate chain could not be verified", err)
	}

	// ParseInternalTLSKey both decrypts (if cmd.Passphrase is set) and
	// checks the derived public key against the leaf's own public key --
	// §13 ruling 4's "internal_tls 목적과 인증서 공개키 일치를 검증한다" --
	// so a mismatched or wrong-purpose key is rejected here, before any
	// store write.
	validated, err := s.deps.PKIParser.ParseInternalTLSKey(ctx, port.TLSKeyInput{
		Data: cmd.Key, Passphrase: cmd.Passphrase, ExpectedPublicKey: leaf.PublicKey,
	})
	if err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindValidation, "tls_upload_key_invalid",
			"the uploaded key could not be validated against the certificate", err)
	}
	if validated.PrivateKey == nil || !validated.PublicKey.Equal(leaf.PublicKey) {
		if validated.PrivateKey != nil {
			_ = validated.PrivateKey.Close()
		}
		return contract.TLSVersionView{}, contract.NewAppError(contract.ErrorKindValidation, "tls_upload_key_invalid",
			"the uploaded key parser returned an inconsistent key")
	}
	defer validated.PrivateKey.Close()

	keyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.TLSVersionView{}, contract.FromDomainError(err)
	}
	generated, err := s.deps.KeyEngine.ImportTLS(ctx, validated, port.KeySpec{
		KeyMaterialID: keyMaterialID, Algorithm: validated.Algorithm, Purpose: domain.SecretPurposeInternalTLS,
	})
	if err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "tls_upload_key_import_failed",
			"could not import the uploaded key", err)
	}

	var settingsServiceURL string
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		url, err := currentServiceURL(ctx, tx)
		if err != nil {
			return err
		}
		settingsServiceURL = url
		return nil
	}); err != nil {
		return contract.TLSVersionView{}, err
	}
	// architecture.md "운영 인증서 교체 후보에는 실제 서비스 주소 검증을
	// 적용한다": exactly commitIssueCandidate's own rule for a managed
	// candidate, applied identically here -- an uploaded certificate whose
	// SAN does not name the installation's current service address is
	// stored with an empty ValidatedServiceURL, which domain.NewTLSVersion
	// itself then refuses for a non-bootstrap source.
	serviceURL := ""
	if serviceAddressMatchesSANs(settingsServiceURL, leaf.SANs) {
		serviceURL = settingsServiceURL
	}

	tlsVersionID, err := domain.ParseTLSVersionID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.TLSVersionView{}, contract.FromDomainError(err)
	}
	version, err := domain.NewTLSVersion(domain.TLSVersionFacts{
		ID: tlsVersionID, Source: domain.TLSSourceExternal, KeyMaterialID: keyMaterialID,
		LeafDER: leaf.DER, ChainBundle: pemEncodeChain(chainDER),
		ValidatedServiceURL: serviceURL, NotAfter: leaf.Validity.NotAfter(),
	})
	if err != nil {
		return contract.TLSVersionView{}, contract.FromDomainError(err)
	}

	var result contract.TLSVersionView
	writeErr := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, action, port.NewAuthorizationScope()); err != nil {
			return err
		}
		if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyMaterialID, PublicKey: generated.PublicKey, Origin: "imported"}); err != nil {
			return storeError(err, "tls_key_material_store_failed", "could not store the uploaded key material")
		}
		// internal_tls purpose, permanent storage: same custody rule
		// commitIssueCandidate's own comment gives -- never a leaf_delivery
		// secret, never queued for one-shot pickup or deleted after a
		// download.
		if err := tx.Secrets().InsertEncrypted(ctx, generated.EncryptedSecret); err != nil {
			return storeError(err, "tls_secret_store_failed", "could not store the uploaded encrypted key")
		}
		if err := tx.TLS().InsertVersion(ctx, version); err != nil {
			return storeError(err, "tls_version_store_failed", "could not store the uploaded TLS candidate")
		}

		now := s.deps.Clock.Now()
		event := port.AuditEvent{
			ID: s.deps.IDs.NewUUID(), OccurredAt: now, ActorKind: contract.AuditActorAccount,
			ActorID: string(meta.Principal.AccountID()), Action: auditAction, TargetType: "tls_version",
			TargetID: string(tlsVersionID), ClientIP: clientIP(meta.RequestMeta), Result: contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, tlsScope()); err != nil {
			return storeError(err, "tls_audit_failed", "could not record the TLS upload audit event")
		}

		result = toTLSVersionView(version)
		return nil
	})
	if writeErr != nil {
		return contract.TLSVersionView{}, writeErr
	}
	return result, nil
}

// Reload explicitly re-reads the configured certificate source and stores a
// new external candidate. The empty command carries no path: runtime/config
// owns source selection, while this method owns validation, encryption and
// secret cleanup. It never calls Activate or changes the listener.
func (s *TLSService) Reload(ctx context.Context, meta contract.MutationMeta, cmd contract.TLSReloadCommand) (contract.TLSVersionView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TLSVersionView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.TLSVersionView{}, contract.NewAppError(contract.ErrorKindForbidden, "tls_requires_admin",
			"reloading a TLS candidate requires an administrator session")
	}
	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTLSReload, port.NewAuthorizationScope()); err != nil {
		return contract.TLSVersionView{}, err
	}
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		return requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock)
	}); err != nil {
		return contract.TLSVersionView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before the configured TLS source was loaded", err)
	}

	input, err := s.deps.FileSource.Load(ctx)
	if err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "tls_reload_source_failed",
			"the configured TLS source could not be loaded", err)
	}
	if input.Passphrase != nil {
		defer input.Passphrase.Close()
	}
	return s.uploadCandidate(ctx, meta, contract.TLSUploadCandidateCommand{
		Certificate: input.Certificate,
		Chain:       input.Chain,
		Key:         input.Key,
		Passphrase:  input.Passphrase,
	}, port.ActionTLSReload, "tls.reload", true)
}

// tlsBootstrapPrepared contains the complete bootstrap graph prepared before
// the activation transaction. The Root, its bootstrap key generation, the
// temporary Leaf, its series and the TLS snapshot are committed together so
// a restart can recover one coherent public history.
type tlsBootstrapPrepared struct {
	authority       domain.Authority
	hasExisting     bool
	existingVersion domain.Version
	rootKeyMaterial port.KeyMaterial
	rootGeneration  port.CAKeyGeneration
	rootCertificate domain.Certificate
	rootSecret      domain.EncryptedSecret
	leafKeyMaterial port.KeyMaterial
	leafGeneration  domain.LeafKeyGeneration
	leafCertificate domain.Certificate
	leafRecord      port.LeafCertificateRecord
	series          domain.LeafSeries
	crlState        domain.CRLState
	version         domain.TLSVersion
	leafSecret      domain.EncryptedSecret
}

func validateGeneratedKey(generated port.GeneratedKey, keyMaterialID domain.KeyMaterialID, purpose domain.SecretPurpose, algorithm domain.KeyAlgorithm) error {
	if generated.PublicKey.IsZero() || generated.PublicKey.Algorithm() != algorithm {
		return contract.NewAppError(contract.ErrorKindUnavailable, "tls_bootstrap_key_invalid",
			"the key engine returned an inconsistent bootstrap public key")
	}
	secret := generated.EncryptedSecret
	if secret.IsZero() || secret.OwnerKeyID() != keyMaterialID || secret.Purpose() != purpose {
		return contract.NewAppError(contract.ErrorKindUnavailable, "tls_bootstrap_secret_invalid",
			"the key engine returned an inconsistent bootstrap secret")
	}
	return nil
}

// findBootstrapAuthority reads the single local bootstrap management row, if
// one exists. The query repository is used only for this preparation read;
// Bootstrap re-reads the selected row with GetIssuerForUpdate before writing,
// so a concurrent change cannot be mistaken for the snapshot we prepared.
func (s *TLSService) findBootstrapAuthority(ctx context.Context) (domain.Authority, bool, error) {
	var found domain.Authority
	foundOne := false
	cursor := ""
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		for {
			page, err := tx.Queries().ListAuthorities(ctx, contract.AuthorityListQuery{
				Page: contract.PageRequest{Cursor: cursor, Limit: 200},
			}, port.QueryScope{All: true})
			if err != nil {
				return storeError(err, "tls_bootstrap_authority_lookup_failed", "could not find the bootstrap authority")
			}
			for _, authority := range page.Items {
				if authority.Kind() != domain.AuthorityKindBootstrap {
					continue
				}
				if foundOne {
					return contract.NewAppError(contract.ErrorKindUnavailable, "tls_bootstrap_authority_ambiguous",
						"more than one bootstrap authority exists")
				}
				found = authority
				foundOne = true
			}
			if page.NextCursor == nil {
				return nil
			}
			if *page.NextCursor == cursor {
				return contract.NewAppError(contract.ErrorKindUnavailable, "tls_bootstrap_authority_cursor_invalid",
					"the bootstrap authority query returned a repeating cursor")
			}
			cursor = *page.NextCursor
		}
	})
	if err != nil {
		return domain.Authority{}, false, err
	}
	return found, foundOne, nil
}

// prepareBootstrap creates the fixed local Root and temporary serverAuth Leaf
// specified by docs/architecture.md and backend-implementation.md §15.3.
// It does not inspect hostnames, mutate setup state or create a delivery.
func (s *TLSService) prepareBootstrap(ctx context.Context, existing *domain.Authority) (tlsBootstrapPrepared, error) {
	const bootstrapName = "cert-me"
	const bootstrapDays = 30

	prepared := tlsBootstrapPrepared{}
	var err error
	authorityID := domain.AuthorityID("")
	rootGenerationNo := 1
	if existing != nil {
		if existing.Kind() != domain.AuthorityKindBootstrap {
			return tlsBootstrapPrepared{}, contract.NewAppError(contract.ErrorKindUnavailable, "tls_bootstrap_authority_invalid",
				"the stored bootstrap authority has an invalid kind")
		}
		if existing.IsArchived() {
			return tlsBootstrapPrepared{}, contract.NewAppError(contract.ErrorKindConflict, "tls_bootstrap_authority_archived",
				"an archived bootstrap authority cannot be regenerated")
		}
		if existing.IssuanceState() != domain.IssuanceStateEnabled {
			return tlsBootstrapPrepared{}, contract.NewAppError(contract.ErrorKindConflict, "tls_bootstrap_authority_not_enabled",
				"the bootstrap authority is not enabled")
		}
		if existing.Affected() || existing.PendingTakeover() {
			return tlsBootstrapPrepared{}, contract.NewAppError(contract.ErrorKindConflict, "tls_bootstrap_authority_not_eligible",
				"the bootstrap authority carries an unresolved impact or takeover state")
		}
		authorityID = existing.ID()
		prepared.hasExisting = true
		prepared.existingVersion = existing.Version()
		var generation port.CAKeyGeneration
		if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
			var err error
			generation, err = tx.PKI().GetCAKeyGeneration(ctx, existing.KeyGenerationID())
			return err
		}); err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return tlsBootstrapPrepared{}, contract.NewAppError(contract.ErrorKindUnavailable, "tls_bootstrap_generation_missing",
					"the bootstrap authority's current key generation could not be found")
			}
			return tlsBootstrapPrepared{}, storeError(err, "tls_bootstrap_generation_read_failed", "could not read the bootstrap key generation")
		}
		if generation.AuthorityID != authorityID {
			return tlsBootstrapPrepared{}, contract.NewAppError(contract.ErrorKindUnavailable, "tls_bootstrap_generation_mismatch",
				"the bootstrap authority's key generation belongs to another authority")
		}
		rootGenerationNo = generation.GenerationNo + 1
	} else {
		var parseErr error
		authorityID, parseErr = domain.ParseAuthorityID(s.deps.IDs.NewUUID())
		if parseErr != nil {
			return tlsBootstrapPrepared{}, contract.FromDomainError(parseErr)
		}
	}
	rootGenerationID, err := domain.ParseCAKeyGenerationID(s.deps.IDs.NewUUID())
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	rootKeyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	rootCertificateID, err := domain.ParseCertificateID(s.deps.IDs.NewUUID())
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	leafGenerationID, err := domain.ParseLeafKeyGenerationID(s.deps.IDs.NewUUID())
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	if prepared.leafKeyMaterial.ID, err = domain.ParseKeyMaterialID(s.deps.IDs.NewUUID()); err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	leafCertificateID, err := domain.ParseCertificateID(s.deps.IDs.NewUUID())
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	prepared.rootKeyMaterial.ID = rootKeyMaterialID
	prepared.rootGeneration.ID = rootGenerationID
	prepared.rootGeneration.AuthorityID = authorityID
	prepared.rootGeneration.GenerationNo = rootGenerationNo
	seriesID, err := domain.ParseSeriesID(s.deps.IDs.NewUUID())
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	tlsVersionID, err := domain.ParseTLSVersionID(s.deps.IDs.NewUUID())
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}

	now := s.deps.Clock.Now()
	validity, err := domain.NewCalendarValidity(bootstrapDays, domain.ValidityUnitDays)
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	window, err := validity.Window(now)
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: bootstrapName})
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	leafSAN, err := domain.NewBootstrapDNSNameSAN()
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	const algorithm = domain.KeyAlgorithmECDSAP256

	rootGenerated, err := s.deps.KeyEngine.Generate(ctx, port.KeySpec{
		KeyMaterialID: prepared.rootKeyMaterial.ID,
		Algorithm:     algorithm,
		Purpose:       domain.SecretPurposeBootstrapCA,
	})
	if err != nil {
		return tlsBootstrapPrepared{}, contract.WrapAppError(contract.ErrorKindUnavailable, "tls_bootstrap_root_key_generate_failed",
			"could not generate the bootstrap root key", err)
	}
	if err := validateGeneratedKey(rootGenerated, prepared.rootKeyMaterial.ID, domain.SecretPurposeBootstrapCA, algorithm); err != nil {
		return tlsBootstrapPrepared{}, err
	}
	prepared.rootKeyMaterial.PublicKey = rootGenerated.PublicKey
	prepared.rootKeyMaterial.Origin = "generated"
	prepared.rootSecret = rootGenerated.EncryptedSecret
	prepared.rootGeneration.KeyMaterialID = prepared.rootKeyMaterial.ID
	prepared.rootGeneration.GenerationNo = rootGenerationNo

	rootPlan := domain.IssuancePlan{
		Subject: subject, KeyAlgorithm: algorithm, Window: window,
		IssuerAuthorityID: authorityID, IssuerKeyGenerationID: rootGenerationID,
	}
	rootSerial, err := newSerial(ctx, s.deps.SerialGenerator)
	if err != nil {
		return tlsBootstrapPrepared{}, err
	}
	root, err := signCertificate(ctx, s.deps.CertificateSigner, port.CertificateSigningRequest{
		Plan: rootPlan, CertificateID: rootCertificateID, KeyMaterialID: prepared.rootKeyMaterial.ID,
		SubjectPublicKey: rootGenerated.PublicKey, Kind: domain.CertificateKindCA,
		Serial:            rootSerial,
		IssuerCertificate: domain.Certificate{},
	}, prepared.rootSecret)
	if err != nil {
		return tlsBootstrapPrepared{}, err
	}
	prepared.rootCertificate = root

	authorityVersion := domain.Version(0)
	if existing != nil {
		authorityVersion = existing.Version().Next()
	}
	prepared.authority, err = domain.NewAuthority(domain.AuthorityFacts{
		ID: authorityID, Kind: domain.AuthorityKindBootstrap, Name: bootstrapName,
		IssuanceState: domain.IssuanceStateEnabled, IssuanceCertificateID: root.ID(),
		KeyGenerationID: rootGenerationID, KeyAvailable: true,
		CertificateWindow: window, Version: authorityVersion,
	})
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	leafValidity := domain.IssuanceRequest{
		Profile: domain.CertificateProfileServerTLS, Subject: subject,
		SANs: []domain.SAN{leafSAN}, KeyAlgorithm: algorithm, Window: window,
	}
	plan, err := domain.PlanBootstrapIssuance(prepared.authority, leafValidity, now)
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	leafPrepared, err := prepareCertificate(ctx, s.deps.KeyEngine, s.deps.CertificateSigner, s.deps.SerialGenerator,
		plan, signingKeyRef{Fresh: &port.KeySpec{
			KeyMaterialID: prepared.leafKeyMaterial.ID, Algorithm: algorithm, Purpose: domain.SecretPurposeInternalTLS,
		}}, domain.PublicKey{}, leafCertificateID, prepared.rootCertificate, prepared.rootSecret,
		domain.CertificateKindLeaf, domain.AccountID(""), nil)
	if err != nil {
		return tlsBootstrapPrepared{}, err
	}
	if leafPrepared.GeneratedSecret == nil || leafPrepared.KeyMaterialID != prepared.leafKeyMaterial.ID {
		return tlsBootstrapPrepared{}, contract.NewAppError(contract.ErrorKindUnavailable, "tls_bootstrap_leaf_key_invalid",
			"the bootstrap leaf key generation returned no usable secret")
	}
	if err := validateGeneratedKey(port.GeneratedKey{
		PublicKey: leafPrepared.GeneratedPublic, EncryptedSecret: *leafPrepared.GeneratedSecret,
	}, prepared.leafKeyMaterial.ID, domain.SecretPurposeInternalTLS, algorithm); err != nil {
		return tlsBootstrapPrepared{}, err
	}
	prepared.leafKeyMaterial.PublicKey = leafPrepared.GeneratedPublic
	prepared.leafKeyMaterial.Origin = "generated"
	prepared.leafSecret = *leafPrepared.GeneratedSecret
	prepared.leafCertificate = leafPrepared.Certificate

	prepared.leafGeneration, err = domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
		ID: leafGenerationID, SeriesID: seriesID, KeyMaterialID: prepared.leafKeyMaterial.ID,
		GenerationNo: 1, RenewalCount: 0, Custody: domain.KeyCustodyInternal,
	})
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	policy := domain.SeriesPolicy{RotateEvery: 1, CertificateValidity: validity}
	if err := policy.Validate(); err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	policySnapshot, err := leafPolicySnapshotJSON(prepared.leafCertificate, policy)
	if err != nil {
		return tlsBootstrapPrepared{}, err
	}
	prepared.leafRecord = port.LeafCertificateRecord{
		CertificateID: prepared.leafCertificate.ID(), SeriesID: seriesID,
		LeafKeyGenerationID: leafGenerationID, IssuerCACertificateID: prepared.rootCertificate.ID(),
		Operation: port.CertificateOperationInitial, RenewalCountAtIssue: 0, PolicySnapshotJSON: policySnapshot,
	}
	prepared.series, err = domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID: seriesID, Name: bootstrapName, Purpose: domain.SeriesPurposeBootstrapTLS,
		ManagementAuthorityID: prepared.authority.ID(), CurrentCertificateID: prepared.leafCertificate.ID(),
		CurrentKeyGenerationID: leafGenerationID, Policy: policy,
	})
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	prepared.crlState, err = domain.NewCRLState(domain.CRLStateFacts{
		CAKeyGenerationID:      prepared.rootGeneration.ID,
		PublicationState:       domain.PublicationStateInactive,
		SigningCACertificateID: prepared.rootCertificate.ID(),
	})
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	if err := s.deps.ChainValidator.Validate(ctx, prepared.leafCertificate.DER(), [][]byte{prepared.rootCertificate.DER()}, now); err != nil {
		return tlsBootstrapPrepared{}, contract.WrapAppError(contract.ErrorKindValidation, "tls_bootstrap_chain_invalid",
			"the generated bootstrap certificate chain could not be verified", err)
	}
	prepared.version, err = domain.NewTLSVersion(domain.TLSVersionFacts{
		ID: tlsVersionID, Source: domain.TLSSourceBootstrap, KeyMaterialID: prepared.leafKeyMaterial.ID,
		LeafDER: prepared.leafCertificate.DER(), ChainBundle: pemEncodeChain([][]byte{prepared.rootCertificate.DER()}),
		NotAfter: prepared.leafCertificate.Validity().NotAfter(),
	})
	if err != nil {
		return tlsBootstrapPrepared{}, contract.FromDomainError(err)
	}
	return prepared, nil
}

// Bootstrap creates or explicitly regenerates the local temporary HTTPS
// chain. It is internal-only and never resets account/setup state. An
// operational TLS version blocks the operation; expiration alone never
// triggers it.
func (s *TLSService) Bootstrap(ctx context.Context, meta contract.MutationMeta, cmd contract.TLSBootstrapCommand) (contract.TLSStatusView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TLSStatusView{}, err
	}
	if err := requireInternalOperation(meta.Principal, port.ActionTLSBootstrap); err != nil {
		return contract.TLSStatusView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before bootstrap started", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, found, err := s.findBootstrapAuthority(ctx)
	if err != nil {
		return contract.TLSStatusView{}, err
	}
	var existingPtr *domain.Authority
	if found {
		existingPtr = &existing
	}
	prepared, err := s.prepareBootstrap(ctx, existingPtr)
	if err != nil {
		return contract.TLSStatusView{}, err
	}

	var outcome tlsActivationOutcome
	writeErr := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return storeError(err, "tls_installation_read_failed", "could not read the installation state")
		}
		var previousVersionID domain.TLSVersionID
		if active, activeErr := tx.TLS().GetActiveForUpdate(ctx); activeErr == nil {
			if active.Phase() != domain.TLSChangePhaseApplied {
				return contract.NewAppError(contract.ErrorKindConflict, "tls_bootstrap_blocked_pending_reconcile",
					"the current TLS pointer is not an applied bootstrap version; run Reconcile first")
			}
			activeVersion, err := tx.TLS().GetVersion(ctx, active.CandidateVersionID())
			if err != nil {
				return storeError(err, "tls_bootstrap_active_version_read_failed", "could not read the active TLS version")
			}
			if activeVersion.Source() != domain.TLSSourceBootstrap {
				return contract.NewAppError(contract.ErrorKindConflict, "tls_bootstrap_operational_active",
					"bootstrap cannot replace an operational TLS version")
			}
			previousVersionID = active.CandidateVersionID()
		} else if errors.Is(activeErr, port.ErrNotFound) {
			if installation.ActiveTLSVersionID != "" {
				return contract.NewAppError(contract.ErrorKindUnavailable, "tls_bootstrap_active_change_missing",
					"the installation names an active TLS version with no change record")
			}
		} else {
			return storeError(activeErr, "tls_bootstrap_active_change_read_failed", "could not read the active TLS change")
		}

		if err := tx.PKI().InsertKeyMaterial(ctx, prepared.rootKeyMaterial); err != nil {
			return storeError(err, "tls_bootstrap_root_key_material_store_failed", "could not store the bootstrap root public key")
		}
		if err := tx.Secrets().InsertEncrypted(ctx, prepared.rootSecret); err != nil {
			return storeError(err, "tls_bootstrap_root_secret_store_failed", "could not store the bootstrap root secret")
		}
		if err := tx.PKI().InsertKeyGeneration(ctx, prepared.rootGeneration); err != nil {
			return storeError(err, "tls_bootstrap_root_generation_store_failed", "could not store the bootstrap root key generation")
		}
		if err := tx.PKI().InsertCertificate(ctx, prepared.rootCertificate); err != nil {
			return storeError(err, "tls_bootstrap_root_certificate_store_failed", "could not store the bootstrap root certificate")
		}
		if err := tx.PKI().InsertCACertificateRecord(ctx, port.CACertificateRecord{
			CertificateID: prepared.rootCertificate.ID(), CAKeyGenerationID: prepared.rootGeneration.ID,
		}); err != nil {
			return storeError(err, "tls_bootstrap_ca_record_store_failed", "could not store the bootstrap CA certificate record")
		}
		if prepared.hasExisting {
			current, err := tx.PKI().GetIssuerForUpdate(ctx, prepared.authority.ID())
			if err != nil {
				return storeError(err, "tls_bootstrap_authority_read_failed", "could not lock the bootstrap authority")
			}
			if current.Version() != prepared.existingVersion || current.Kind() != domain.AuthorityKindBootstrap {
				return contract.NewAppError(contract.ErrorKindConflict, "tls_bootstrap_authority_changed",
					"the bootstrap authority changed while regeneration was being prepared")
			}
			if err := tx.PKI().SaveAuthority(ctx, prepared.authority, prepared.existingVersion); err != nil {
				return storeError(err, "tls_bootstrap_authority_store_failed", "could not update the bootstrap authority")
			}
		} else if err := tx.PKI().InsertAuthority(ctx, prepared.authority); err != nil {
			return storeError(err, "tls_bootstrap_authority_store_failed", "could not store the bootstrap authority")
		}
		if err := tx.CRLs().SaveState(ctx, prepared.crlState, 0); err != nil {
			return storeError(err, "tls_bootstrap_crl_state_store_failed", "could not store the bootstrap CRL state")
		}
		if err := tx.PKI().InsertKeyMaterial(ctx, prepared.leafKeyMaterial); err != nil {
			return storeError(err, "tls_bootstrap_leaf_key_material_store_failed", "could not store the bootstrap leaf public key")
		}
		if err := tx.Secrets().InsertEncrypted(ctx, prepared.leafSecret); err != nil {
			return storeError(err, "tls_bootstrap_leaf_secret_store_failed", "could not store the bootstrap TLS secret")
		}
		if err := tx.PKI().InsertLeafKeyGeneration(ctx, prepared.leafGeneration); err != nil {
			return storeError(err, "tls_bootstrap_leaf_generation_store_failed", "could not store the bootstrap leaf key generation")
		}
		if err := tx.PKI().InsertCertificate(ctx, prepared.leafCertificate); err != nil {
			return storeError(err, "tls_bootstrap_leaf_certificate_store_failed", "could not store the bootstrap leaf certificate")
		}
		if err := tx.PKI().InsertLeafCertificateRecord(ctx, prepared.leafRecord); err != nil {
			return storeError(err, "tls_bootstrap_leaf_record_store_failed", "could not store the bootstrap leaf certificate record")
		}
		if err := tx.PKI().InsertSeries(ctx, prepared.series); err != nil {
			return storeError(err, "tls_bootstrap_series_store_failed", "could not store the bootstrap TLS series")
		}
		if err := tx.TLS().InsertVersion(ctx, prepared.version); err != nil {
			return storeError(err, "tls_bootstrap_version_store_failed", "could not store the bootstrap TLS version")
		}

		now := s.deps.Clock.Now()
		facts := domain.TLSValidationFacts{
			CandidateSource: domain.TLSSourceBootstrap, KeyMatchesCertificate: true,
			WithinValidityPeriod: !prepared.version.IsExpiredAt(now), PurposeMatchesServerAuth: true,
			ServiceAddressMatches: true, ChainVerified: true,
		}
		change, err := domain.NewCandidateTLSChange(previousVersionID, prepared.version.ID())
		if err != nil {
			return contract.FromDomainError(err)
		}
		change, err = change.ValidateCandidate(facts)
		if err != nil {
			return contract.FromDomainError(err)
		}
		committed, err := change.Commit(now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.TLS().SaveChange(ctx, committed, 0); err != nil {
			return storeError(err, "tls_bootstrap_change_store_failed", "could not store the bootstrap TLS change")
		}
		if err := tx.TLS().SetActive(ctx, installation.Version, prepared.version.ID()); err != nil {
			return storeError(err, "tls_bootstrap_set_active_failed", "could not activate the bootstrap TLS pointer")
		}
		event := port.AuditEvent{
			ID: s.deps.IDs.NewUUID(), OccurredAt: now, ActorKind: contract.AuditActorSystem,
			Action: "tls.bootstrap.committed", TargetType: "authority", TargetID: string(prepared.authority.ID()),
			Result: contract.AuditResultSuccess, Details: contract.AuditDetails{SchemaVersion: 1},
		}
		if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(prepared.authority.ID())); err != nil {
			return storeError(err, "tls_bootstrap_audit_failed", "could not record the bootstrap audit event")
		}
		outcome = tlsActivationOutcome{
			candidate: prepared.version, secret: prepared.leafSecret, change: committed,
			previousVersionID: previousVersionID, installationVersionAfterSetActive: installation.Version.Next(),
		}
		return nil
	})
	if writeErr != nil {
		if errors.Is(writeErr, port.ErrCommitUnknown) {
			s.deps.RuntimeGate.FailClosed("tls_bootstrap_commit_unknown")
		}
		return contract.TLSStatusView{}, writeErr
	}

	preparedHandle, err := s.deps.TLSInstaller.Prepare(ctx, outcome.candidate, outcome.secret)
	if err != nil {
		if rollbackErr := s.rollbackActivation(ctx, meta, outcome, "tls_bootstrap_prepare_failed"); rollbackErr != nil {
			s.deps.RuntimeGate.FailClosed("tls_bootstrap_prepare_rollback_failed")
		}
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "tls_bootstrap_prepare_failed",
			"could not prepare the bootstrap TLS configuration", err)
	}
	defer s.deps.TLSInstaller.Discard(preparedHandle)
	if err := s.deps.TLSInstaller.Apply(ctx, preparedHandle); err != nil {
		if rollbackErr := s.rollbackActivation(ctx, meta, outcome, "tls_bootstrap_apply_failed"); rollbackErr != nil {
			s.deps.RuntimeGate.FailClosed("tls_bootstrap_apply_rollback_failed")
		}
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "tls_bootstrap_apply_failed",
			"could not apply the bootstrap TLS configuration", err)
	}

	now := s.deps.Clock.Now()
	applied, err := outcome.change.Apply(now)
	if err != nil {
		s.deps.RuntimeGate.FailClosed("tls_bootstrap_applied_record_failed")
		_ = s.markRecoveryRequired(ctx, outcome.change, "tls_bootstrap_applied_record_failed")
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindCommitUnknown, "tls_bootstrap_applied_record_failed",
			"the bootstrap TLS configuration was applied but its outcome could not be recorded", err)
	}
	recordErr := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := tx.TLS().SaveChange(ctx, applied, outcome.change.Version()); err != nil {
			return storeError(err, "tls_bootstrap_change_record_failed", "could not record the applied bootstrap TLS change")
		}
		event := port.AuditEvent{
			ID: s.deps.IDs.NewUUID(), OccurredAt: now, ActorKind: contract.AuditActorSystem,
			Action: "tls.bootstrap", TargetType: "authority", TargetID: string(prepared.authority.ID()),
			Result: contract.AuditResultSuccess, Details: contract.AuditDetails{SchemaVersion: 1},
		}
		return tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(prepared.authority.ID()))
	})
	if recordErr != nil {
		s.deps.RuntimeGate.FailClosed("tls_bootstrap_record_failed")
		_ = s.markRecoveryRequired(ctx, outcome.change, "tls_bootstrap_record_failed")
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindCommitUnknown, "tls_bootstrap_record_failed",
			"the bootstrap TLS configuration was applied but its outcome could not be recorded", recordErr)
	}

	return contract.TLSStatusView{
		Active: ptrTLSVersionView(toTLSVersionView(outcome.candidate)),
		Phase:  ptrPhase(domain.TLSChangePhaseApplied), CandidateID: ptrTLSVersionID(outcome.candidate.ID()),
		Version: outcome.installationVersionAfterSetActive,
	}, nil
}

// ---- IssueCandidate ----

const tlsOperationIssueCandidate = "tls.issue_candidate"

// tlsIssueCandidateHashInput is tls.issue_candidate's v1 idempotency
// envelope (§11.6), mirroring issueHashInput's shape.
type tlsIssueCandidateHashInput struct {
	AuthorityID  string        `json:"authority_id"`
	Subject      hashSubject   `json:"subject"`
	SANs         []hashSAN     `json:"sans"`
	KeyAlgorithm string        `json:"key_algorithm"`
	Validity     *hashValidity `json:"validity,omitempty"`
}

const tlsVersionStoredResultSchemaVersion = 1

// storedTLSVersionResult stores only the id a replay needs to re-read the
// live TLSVersion snapshot -- TLSVersion is immutable once created, so
// unlike storedAuthorityCreateResult there is no "current truth may have
// moved on" field to omit here.
type storedTLSVersionResult struct {
	SchemaVersion int    `json:"schema_version"`
	TLSVersionID  string `json:"tls_version_id"`
}

func decodeStoredTLSVersionResult(stored port.OperationRequestResult) (storedTLSVersionResult, error) {
	var v storedTLSVersionResult
	if err := DecodeStoredResult(stored, &v); err != nil {
		return storedTLSVersionResult{}, err
	}
	if v.SchemaVersion != tlsVersionStoredResultSchemaVersion {
		return storedTLSVersionResult{}, contract.NewAppError(contract.ErrorKindUnavailable, "tls_stored_result_schema_unsupported",
			"a stored TLS candidate result carries an unsupported schema_version").
			WithField("schema_version", fmt.Sprintf("%d", v.SchemaVersion))
	}
	return v, nil
}

func (v storedTLSVersionResult) toView(ctx context.Context, tx port.TxStores) (contract.TLSVersionView, error) {
	id, err := domain.ParseTLSVersionID(v.TLSVersionID)
	if err != nil {
		return contract.TLSVersionView{}, contract.FromDomainError(err)
	}
	version, err := tx.TLS().GetVersion(ctx, id)
	if err != nil {
		return contract.TLSVersionView{}, storeError(err, "tls_replay_read_failed", "could not read the candidate for replay")
	}
	return toTLSVersionView(version), nil
}

// tlsIssueCandidatePrepared is everything IssueCandidate builds before
// opening its Write, mirroring issuePrepared's non-authoritative contract.
type tlsIssueCandidatePrepared struct {
	now                domain.Instant
	validity           domain.CalendarValidity
	settingsVersion    domain.Version
	settingsServiceURL string
	authority          domain.Authority
	issuerCertificate  domain.Certificate
	plan               domain.IssuancePlan
	keyMaterialID      domain.KeyMaterialID
	publicKey          domain.PublicKey
	generatedSecret    *domain.EncryptedSecret
	certificate        domain.Certificate
}

// IssueCandidate signs a fresh internal-custody Leaf under an existing
// operational Intermediate and stores it as a new, unactivated TLSVersion
// candidate (docs/backend-implementation.md §3 "IssueCandidate: TLSIssue →
// TLSVersion"; idempotency required).
//
// This calls prepareCertificate/signCertificate directly, the same building
// blocks Authority/Issuance use, rather than going through
// IssuanceService.Issue: §5 forbids the shortcut of issuing an ordinary Leaf
// and then deleting its delivery ("내부 TLS 발급이 일반 Leaf 발급 서비스를
// 호출해 delivery를 만든 뒤 삭제하는 방식은 금지한다. 계획의 custody가 처음부터
// internal이며 response에 download grant가 없다"), so this function never
// calls storeFreshKeyAndDelivery/InsertDelivery at all -- there is no leaf
// delivery, grant, or download-related row created here, structurally, not
// just as an emptied-out later step.
func (s *TLSService) IssueCandidate(ctx context.Context, meta contract.MutationMeta, cmd contract.TLSIssueCandidateCommand) (contract.TLSVersionView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TLSVersionView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.TLSVersionView{}, contract.NewAppError(contract.ErrorKindForbidden, "tls_requires_admin",
			"issuing a TLS candidate requires an administrator session")
	}

	subject, err := cmd.Subject.Domain()
	if err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_subject", "subject is invalid", err)
	}
	sans, err := contract.SANInputs(cmd.SANs)
	if err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindValidation, "invalid_sans", "sans are invalid", err)
	}
	keyAlgorithm := domain.KeyAlgorithm(cmd.KeyAlgorithm)
	if keyAlgorithm == "" {
		keyAlgorithm = domain.DefaultKeyAlgorithm
	} else if err := keyAlgorithm.Validate(); err != nil {
		return contract.TLSVersionView{}, contract.FromDomainError(err)
	}

	hashInput := tlsIssueCandidateHashInput{
		AuthorityID:  NormalizeUUID(string(cmd.AuthorityID)),
		Subject:      subjectForHash(subject),
		SANs:         normalizedSANsForHash(sans),
		KeyAlgorithm: string(keyAlgorithm),
	}
	if cmd.Validity != nil {
		hashInput.Validity = &hashValidity{Value: cmd.Validity.Value, Unit: cmd.Validity.Unit}
	}
	target := map[string]string{"authority_id": NormalizeUUID(string(cmd.AuthorityID))}
	inputHash, err := InputHash(tlsOperationIssueCandidate, target, hashInput)
	if err != nil {
		return contract.TLSVersionView{}, err
	}
	reqKey, err := RequestKey(meta, tlsOperationIssueCandidate)
	if err != nil {
		return contract.TLSVersionView{}, err
	}

	authorityID := cmd.AuthorityID
	// §6: admission is checked before any expensive preparation.
	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTLSIssueCandidate, port.NewAuthorizationScope(authorityID)); err != nil {
		return contract.TLSVersionView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.TLSVersionView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	var result contract.TLSVersionView
	if found, err := s.replayIssueCandidateBeforePreparation(ctx, reqKey, inputHash, meta.Principal, authorityID, &result); err != nil {
		return contract.TLSVersionView{}, err
	} else if found {
		return result, nil
	}

	req := domain.IssuanceRequest{Profile: domain.CertificateProfileServerTLS, Subject: subject, SANs: sans, KeyAlgorithm: keyAlgorithm}
	var reuse *tlsIssueCandidatePrepared
	for attempt := 0; attempt < maxSerialAttempts; attempt++ {
		prep, err := s.prepareIssueCandidate(ctx, meta, cmd, req, authorityID, reuse)
		if err != nil {
			return contract.TLSVersionView{}, err
		}
		reuse = &prep

		err = RunWithRetry(ctx, func() error {
			return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
				return s.commitIssueCandidate(ctx, tx, meta, cmd, reqKey, inputHash, authorityID, prep, &result)
			})
		})
		if errors.Is(err, errRePrepare) {
			continue
		}
		if err != nil {
			return contract.TLSVersionView{}, err
		}
		return result, nil
	}
	return contract.TLSVersionView{}, contract.NewAppError(contract.ErrorKindConflict, "tls_issue_candidate_serial_exhausted",
		"could not obtain a unique serial after repeated signing attempts")
}

func (s *TLSService) replayIssueCandidateBeforePreparation(ctx context.Context, reqKey port.OperationRequestKey, inputHash string, principal contract.Principal, authorityID domain.AuthorityID, result *contract.TLSVersionView) (bool, error) {
	var found bool
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, principal, port.ActionTLSIssueCandidate, port.NewAuthorizationScope(authorityID)); err != nil {
			return err
		}
		stored, ok, err := ReplayStoredResult(ctx, tx, reqKey, inputHash)
		if err != nil || !ok {
			return err
		}
		view, err := decodeStoredTLSVersionResult(stored)
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

// prepareIssueCandidate performs the out-of-transaction preparation §8's
// "Leaf 발급" row pattern uses: snapshot, plan, key generation, signing. On a
// serial-collision retry (reuse != nil) it keeps the already-generated key
// and only re-signs, matching prepareIssue's own documented reason.
func (s *TLSService) prepareIssueCandidate(ctx context.Context, meta contract.MutationMeta, cmd contract.TLSIssueCandidateCommand, req domain.IssuanceRequest, authorityID domain.AuthorityID, reuse *tlsIssueCandidatePrepared) (tlsIssueCandidatePrepared, error) {
	prep := tlsIssueCandidatePrepared{now: s.deps.Clock.Now()}

	var issuerSecret domain.EncryptedSecret
	if err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		authority, err := tx.PKI().GetIssuerForUpdate(ctx, authorityID)
		if errors.Is(err, port.ErrNotFound) {
			return contract.NewAppError(contract.ErrorKindValidation, "tls_authority_not_found", "authority does not exist").
				WithField("authority_id", string(authorityID))
		} else if err != nil {
			return storeError(err, "tls_authority_read_failed", "could not read the issuing authority")
		}
		prep.authority = authority

		if cmd.Validity != nil {
			v, err := cmd.Validity.Domain()
			if err != nil {
				return contract.WrapAppError(contract.ErrorKindValidation, "invalid_validity", "validity must have a positive value and a supported unit", err)
			}
			prep.validity = v
		} else {
			settings, err := tx.Installation().GetSettings(ctx)
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindConflict, "tls_settings_not_configured",
					"installation settings have not been initialized")
			} else if err != nil {
				return storeError(err, "tls_settings_read_failed", "could not read installation settings")
			}
			snap, err := DecodeSettingsV1(settings)
			if err != nil {
				return err
			}
			prep.validity = snap.LeafValidity
			prep.settingsVersion = settings.Version
			prep.settingsServiceURL = snap.ServiceURL
		}
		if prep.settingsServiceURL == "" {
			// Validity was explicit, so the settings row was never read above;
			// the service-address check still needs the current service_url.
			url, err := currentServiceURL(ctx, tx)
			if err != nil {
				return err
			}
			prep.settingsServiceURL = url
		}

		secret, issuerCert, err := caSigningSecret(ctx, tx, authority)
		if err != nil {
			return err
		}
		issuerSecret = secret
		prep.issuerCertificate = issuerCert
		return nil
	}); err != nil {
		return tlsIssueCandidatePrepared{}, err
	}

	window, err := prep.validity.Window(prep.now)
	if err != nil {
		return tlsIssueCandidatePrepared{}, contract.FromDomainError(err)
	}
	req.Window = window
	plan, err := domain.PlanIssuance(prep.authority, req, prep.now)
	if err != nil {
		return tlsIssueCandidatePrepared{}, contract.FromDomainError(err)
	}
	prep.plan = plan

	certificateID, err := domain.ParseCertificateID(s.deps.IDs.NewUUID())
	if err != nil {
		return tlsIssueCandidatePrepared{}, contract.FromDomainError(err)
	}

	if reuse != nil {
		prep.keyMaterialID, prep.publicKey, prep.generatedSecret = reuse.keyMaterialID, reuse.publicKey, reuse.generatedSecret
		cert, err := resignWithNewSerial(ctx, s.deps.CertificateSigner, s.deps.SerialGenerator, plan, certificateID,
			prep.keyMaterialID, prep.publicKey, domain.CertificateKindLeaf, meta.Principal.AccountID(), prep.issuerCertificate, issuerSecret, nil)
		if err != nil {
			return tlsIssueCandidatePrepared{}, err
		}
		prep.certificate = cert
		return prep, nil
	}

	newKeyMaterialID, err := domain.ParseKeyMaterialID(s.deps.IDs.NewUUID())
	if err != nil {
		return tlsIssueCandidatePrepared{}, contract.FromDomainError(err)
	}
	ref := signingKeyRef{Fresh: &port.KeySpec{KeyMaterialID: newKeyMaterialID, Algorithm: req.KeyAlgorithm, Purpose: domain.SecretPurposeInternalTLS}}
	prepared, err := prepareCertificate(ctx, s.deps.KeyEngine, s.deps.CertificateSigner, s.deps.SerialGenerator, plan, ref,
		domain.PublicKey{}, certificateID, prep.issuerCertificate, issuerSecret, domain.CertificateKindLeaf, meta.Principal.AccountID(), nil)
	if err != nil {
		return tlsIssueCandidatePrepared{}, err
	}
	prep.keyMaterialID = prepared.KeyMaterialID
	prep.publicKey = prepared.GeneratedPublic
	prep.generatedSecret = prepared.GeneratedSecret
	prep.certificate = prepared.Certificate
	return prep, nil
}

// commitIssueCandidate is IssueCandidate's single Write: authorization,
// stored-result replay, current-policy re-check, then the stores (key
// material, the internal_tls secret -- NEVER a leaf_delivery secret or a
// Delivery row -- the certificate, its leaf_certificates/leaf_key_generation
// subtype rows with custody=internal, a fresh internal_tls-purpose series,
// the new TLSVersion, the request result and the audit row.
func (s *TLSService) commitIssueCandidate(ctx context.Context, tx port.TxStores, meta contract.MutationMeta, cmd contract.TLSIssueCandidateCommand, reqKey port.OperationRequestKey, inputHash string, authorityID domain.AuthorityID, prep tlsIssueCandidatePrepared, result *contract.TLSVersionView) error {
	if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
		return err
	}
	if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTLSIssueCandidate, port.NewAuthorizationScope(authorityID)); err != nil {
		return err
	}
	if stored, found, err := ReplayStoredResult(ctx, tx, reqKey, inputHash); err != nil {
		return err
	} else if found {
		view, err := decodeStoredTLSVersionResult(stored)
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
		return contract.NewAppError(contract.ErrorKindValidation, "tls_authority_not_found", "authority does not exist").
			WithField("authority_id", string(authorityID))
	} else if err != nil {
		return storeError(err, "tls_authority_read_failed", "could not read the issuing authority")
	}
	if authority.KeyGenerationID() != prep.plan.IssuerKeyGenerationID {
		return errRePrepare
	}
	commitNow := s.deps.Clock.Now()
	if err := authority.CanIssue(domain.IssuerContext{RequestedWindow: prep.plan.Window, Intent: domain.IssuanceIntentLeaf}, commitNow); err != nil {
		return contract.FromDomainError(err)
	}
	if _, _, err := verifyCASigningKeyLive(ctx, tx, authority); err != nil {
		return err
	}
	if prep.settingsVersion != 0 {
		if err := settingsUnchanged(ctx, tx, prep.settingsVersion); err != nil {
			return err
		}
	}
	if err := ensureSerialUnused(ctx, tx, prep.plan.IssuerKeyGenerationID, prep.certificate.Serial()); err != nil {
		return err
	}
	if prep.generatedSecret == nil {
		return contract.NewAppError(contract.ErrorKindUnavailable, "tls_issue_candidate_missing_generated_secret",
			"issuing a TLS candidate did not produce a key to store")
	}

	cert := prep.certificate
	if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: prep.keyMaterialID, PublicKey: prep.publicKey, Origin: "generated"}); err != nil {
		return storeError(err, "tls_key_material_store_failed", "could not store the new key material")
	}
	// internal_tls purpose, permanent storage: unlike an ordinary Leaf's
	// leaf_delivery secret, this key is never queued for one-shot pickup and
	// is never deleted after a download (§5 "계획의 custody가 처음부터
	// internal이며 response에 download grant가 없다").
	if err := tx.Secrets().InsertEncrypted(ctx, *prep.generatedSecret); err != nil {
		return storeError(err, "tls_secret_store_failed", "could not store the encrypted TLS key")
	}
	if err := tx.PKI().InsertCertificate(ctx, cert); err != nil {
		return storeError(err, "tls_certificate_store_failed", "could not store the certificate")
	}

	seriesID, err := domain.ParseSeriesID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.FromDomainError(err)
	}
	leafKeyGenID, err := domain.ParseLeafKeyGenerationID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.FromDomainError(err)
	}
	leafKeyGen, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
		ID: leafKeyGenID, SeriesID: seriesID, KeyMaterialID: prep.keyMaterialID,
		GenerationNo: 1, RenewalCount: 0, Custody: domain.KeyCustodyInternal,
	})
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.PKI().InsertLeafKeyGeneration(ctx, leafKeyGen); err != nil {
		return storeError(err, "tls_leaf_key_generation_store_failed", "could not store the leaf key generation")
	}

	policy := domain.SeriesPolicy{RotateEvery: 3, CertificateValidity: prep.validity} // 3: data-model.md's documented rotate_every default; TLS candidates do not use rotation, only the storage shape requires a policy
	if err := policy.Validate(); err != nil {
		return contract.FromDomainError(err)
	}
	policySnapshot, err := leafPolicySnapshotJSON(cert, policy)
	if err != nil {
		return err
	}
	if err := tx.PKI().InsertLeafCertificateRecord(ctx, port.LeafCertificateRecord{
		CertificateID: cert.ID(), SeriesID: seriesID, LeafKeyGenerationID: leafKeyGenID,
		IssuerCACertificateID: prep.issuerCertificate.ID(), Operation: port.CertificateOperationInitial,
		RenewalCountAtIssue: 0, PolicySnapshotJSON: policySnapshot,
	}); err != nil {
		return storeError(err, "tls_leaf_certificate_record_store_failed", "could not store the leaf certificate record")
	}

	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID: seriesID, Name: "internal_tls_" + string(cert.ID()), Purpose: domain.SeriesPurposeInternalTLS,
		ManagementAuthorityID: authorityID, CurrentCertificateID: cert.ID(), CurrentKeyGenerationID: leafKeyGenID, Policy: policy,
	})
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.PKI().InsertSeries(ctx, series); err != nil {
		return storeError(err, "tls_series_store_failed", "could not store the series")
	}

	chainDER, err := buildChainDER(ctx, tx, cert.ID())
	if err != nil {
		return err
	}
	tlsVersionID, err := domain.ParseTLSVersionID(s.deps.IDs.NewUUID())
	if err != nil {
		return contract.FromDomainError(err)
	}
	serviceURL := ""
	if serviceAddressMatchesSANs(prep.settingsServiceURL, prep.plan.SANs) {
		serviceURL = prep.settingsServiceURL
	}
	version, err := domain.NewTLSVersion(domain.TLSVersionFacts{
		ID: tlsVersionID, Source: domain.TLSSourceManaged, KeyMaterialID: prep.keyMaterialID,
		ManagedCertificateID: cert.ID(), LeafDER: cert.DER(), ChainBundle: pemEncodeChain(chainDER),
		ValidatedServiceURL: serviceURL, NotAfter: cert.Validity().NotAfter(),
	})
	if err != nil {
		return contract.FromDomainError(err)
	}
	if err := tx.TLS().InsertVersion(ctx, version); err != nil {
		return storeError(err, "tls_version_store_failed", "could not store the TLS candidate")
	}

	view := storedTLSVersionResult{SchemaVersion: tlsVersionStoredResultSchemaVersion, TLSVersionID: string(tlsVersionID)}
	if err := StoreRequestResult(ctx, tx, reqKey, inputHash, view); err != nil {
		return err
	}

	event := port.AuditEvent{
		ID: s.deps.IDs.NewUUID(), OccurredAt: commitNow, ActorKind: contract.AuditActorAccount,
		ActorID: string(meta.Principal.AccountID()), Action: "tls.issue_candidate", TargetType: "tls_version",
		TargetID: string(tlsVersionID), ClientIP: clientIP(meta.RequestMeta), Result: contract.AuditResultSuccess,
		Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"serial": cert.Serial().Hex()}},
	}
	if err := tx.Audit().Append(ctx, event, port.NewAuthoritiesAuditScope(authorityID)); err != nil {
		return storeError(err, "tls_audit_failed", "could not record the TLS issuance audit event")
	}

	*result = toTLSVersionView(version)
	return nil
}

// ---- small pointer helpers for the OpenAPI-shaped nullable fields ----

func ptrTLSVersionView(v contract.TLSVersionView) *contract.TLSVersionView { return &v }
func ptrPhase(p domain.TLSChangePhase) *domain.TLSChangePhase              { return &p }
func ptrTLSVersionID(id domain.TLSVersionID) *domain.TLSVersionID          { return &id }

// ---- Activate ----

// tlsActivationOutcome is Activate's first Write's result, encoded as data
// rather than a Go error for the "validation_failed" case -- the same
// pattern domain.TLSChange.ValidateCandidate itself uses ("a failing
// candidate ... is not reported through the error return: keeping the
// existing certificate while recording why the candidate was rejected is
// the expected, successful outcome"). A validation failure must leave the
// active version untouched, which this achieves structurally: the Write
// callback returns nil (commits, e.g. the rejection audit row), and
// Activate inspects the outcome afterward to decide what to return to its
// own caller -- it never calls SetActive on this path at all.
type tlsActivationOutcome struct {
	validationFailed bool
	errorCode        string

	candidate                         domain.TLSVersion
	secret                            domain.EncryptedSecret
	change                            domain.TLSChange // committed phase
	previousVersionID                 domain.TLSVersionID
	installationVersionAfterSetActive domain.Version
}

// Activate is TLSService's activation half (docs/backend-implementation.md
// §3 "Activate: TLSActivation → TLSStatus"; §9). Its shape follows §9's
// literal, fixed order: under the process-wide TLS mutex, re-check the TLS
// status version and commit the phase/pointer change in one Write, THEN
// call TLSInstaller.Apply OUTSIDE that transaction, THEN record the outcome
// in a second Write. This is deliberately not one big transaction: once
// Apply has run it cannot be undone by a DB rollback, so the DB record of
// "we are about to apply this" must already be durable before Apply is
// ever called (docs/backend-implementation.md §9 "committed 기록/활성
// 포인터 변경 → Installer.Apply → DB applied 기록"). See
// TestActivate_OneBigTransactionWouldMisrecordAnAmbiguousApply in
// tls_test.go for why the simpler single-Write shape was rejected.
func (s *TLSService) Activate(ctx context.Context, meta contract.MutationMeta, cmd contract.TLSActivateCommand) (contract.TLSStatusView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TLSStatusView{}, err
	}
	if !meta.Principal.IsAdmin() {
		return contract.TLSStatusView{}, contract.NewAppError(contract.ErrorKindForbidden, "tls_requires_admin",
			"activating a TLS candidate requires an administrator session")
	}
	expectedVersion, err := meta.RequireExpectedVersion()
	if err != nil {
		return contract.TLSStatusView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var outcome tlsActivationOutcome
	writeErr := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionTLSActivate, port.NewAuthorizationScope()); err != nil {
			return err
		}

		candidate, err := tx.TLS().GetVersion(ctx, cmd.CandidateID)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "tls_candidate_not_found", "candidate does not exist").
					WithField("candidate_id", string(cmd.CandidateID))
			}
			return storeError(err, "tls_candidate_read_failed", "could not read the candidate")
		}

		var previousVersionID domain.TLSVersionID
		active, activeErr := tx.TLS().GetActiveForUpdate(ctx)
		switch {
		case activeErr == nil:
			// A non-terminal active change means a prior activation attempt
			// never reached a resolved (applied/rolled_back) outcome --
			// §9's "일반 서비스 재개를 막고 Reconcile로 판단한다": this
			// developer's reading is that "일반 서비스" here means Activate
			// itself refuses to layer a new attempt on top of an unresolved
			// one until Reconcile clears it.
			if !active.Phase().IsTerminal() {
				return contract.NewAppError(contract.ErrorKindConflict, "tls_activation_blocked_pending_reconcile",
					"the previous TLS change has not reached a terminal state; run Reconcile first")
			}
			previousVersionID = active.CandidateVersionID()
		case errors.Is(activeErr, port.ErrNotFound):
			// No HTTPS version has ever been activated -- fine, this is the
			// first one.
		default:
			return storeError(activeErr, "tls_active_change_read_failed", "could not read the active TLS change")
		}

		secret, err := tx.Secrets().GetEncrypted(ctx, candidate.KeyMaterialID(), domain.SecretPurposeInternalTLS)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindConflict, "tls_candidate_key_missing",
					"the candidate's stored key is no longer available")
			}
			return storeError(err, "tls_candidate_key_read_failed", "could not read the candidate's stored key")
		}

		// §9/the "오래된 시각 금지" rule: now is read here, with the
		// candidate/active rows already read under this Write's lock, never
		// carried in from before Activate opened this transaction.
		now := s.deps.Clock.Now()
		facts, err := s.buildValidationFacts(ctx, tx, candidate, now)
		if err != nil {
			return err
		}

		change, err := domain.NewCandidateTLSChange(previousVersionID, cmd.CandidateID)
		if err != nil {
			return contract.FromDomainError(err)
		}
		change, err = change.ValidateCandidate(facts)
		if err != nil {
			return contract.FromDomainError(err)
		}

		if !change.Validated() {
			outcome = tlsActivationOutcome{validationFailed: true, errorCode: change.ErrorCode()}
			event := port.AuditEvent{
				ID: s.deps.IDs.NewUUID(), OccurredAt: now, ActorKind: contract.AuditActorAccount,
				ActorID: string(meta.Principal.AccountID()), Action: "tls.activate.rejected", TargetType: "tls_version",
				TargetID: string(cmd.CandidateID), ClientIP: clientIP(meta.RequestMeta), Result: contract.AuditResultFailure,
				Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"error_code": change.ErrorCode()}},
			}
			if err := tx.Audit().Append(ctx, event, tlsScope()); err != nil {
				return storeError(err, "tls_audit_failed", "could not record the activation rejection audit event")
			}
			return nil
		}

		committed, err := change.Commit(now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		// This candidate's TLSChange row has never been saved before --
		// straight to its committed phase, expectedVersion 0 signals the
		// fresh insert (the row's OWN stored version is whatever Commit
		// left it at, not forced to expectedVersion+1: §5 "finalVersion=
		// expectedVersion+1을 강제하지 않는다").
		if err := tx.TLS().SaveChange(ctx, committed, 0); err != nil {
			return storeError(err, "tls_change_store_failed", "could not store the TLS change")
		}
		if err := tx.TLS().SetActive(ctx, expectedVersion, cmd.CandidateID); err != nil {
			if errors.Is(err, port.ErrVersionConflict) {
				return contract.NewAppError(contract.ErrorKindConflict, "tls_status_version_conflict",
					"TLS status has changed since this request was prepared")
			}
			return storeError(err, "tls_set_active_failed", "could not move the active TLS pointer")
		}

		outcome = tlsActivationOutcome{
			candidate: candidate, secret: secret, change: committed,
			previousVersionID: previousVersionID, installationVersionAfterSetActive: expectedVersion.Next(),
		}
		return nil
	})
	if writeErr != nil {
		if errors.Is(writeErr, port.ErrCommitUnknown) {
			s.deps.RuntimeGate.FailClosed("tls_activate_commit_unknown")
		}
		return contract.TLSStatusView{}, writeErr
	}
	if outcome.validationFailed {
		return contract.TLSStatusView{}, contract.NewAppError(contract.ErrorKindValidation, outcome.errorCode,
			"the candidate failed validation")
	}

	// §9: "준비한 후보를 TLSInstaller.Prepare에 넣어 실제 적용 가능한 메모리
	// 설정을 먼저 만든다" -- Prepare/Apply run OUTSIDE the Write that just
	// committed, using the candidate/secret that Write already re-verified.
	prepared, err := s.deps.TLSInstaller.Prepare(ctx, outcome.candidate, outcome.secret)
	if err != nil {
		if rollbackErr := s.rollbackActivation(ctx, meta, outcome, "tls_prepare_failed"); rollbackErr != nil {
			s.deps.RuntimeGate.FailClosed("tls_prepare_rollback_failed")
		}
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "tls_prepare_failed",
			"could not prepare the TLS candidate for activation", err)
	}
	// §13: deferred immediately after a successful Prepare, so a panic below
	// or any return path still releases the registry entry. A successful
	// Apply consumes the handle first, so this is a no-op on that path
	// (§13 "성공 후 defer된 Discard는 활성 설정을 지우지 않는다").
	defer s.deps.TLSInstaller.Discard(prepared)

	if err := s.deps.TLSInstaller.Apply(ctx, prepared); err != nil {
		// §9 "Apply 실패는 DB/메모리 모두 원복한다": the in-memory half is
		// TLSInstaller's own contract (a failed Apply leaves the previous
		// listener serving); the DB half is rollbackActivation below.
		if rollbackErr := s.rollbackActivation(ctx, meta, outcome, "tls_apply_failed"); rollbackErr != nil {
			s.deps.RuntimeGate.FailClosed("tls_apply_rollback_failed")
		}
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "tls_apply_failed",
			"could not apply the TLS candidate", err)
	}

	appliedNow := s.deps.Clock.Now()
	applied, err := outcome.change.Apply(appliedNow)
	if err != nil {
		// Unreachable in practice (outcome.change is always committed on
		// this path), but treated as the same ambiguous-recording case
		// rather than a panic.
		s.deps.RuntimeGate.FailClosed("tls_applied_transition_failed")
		_ = s.markRecoveryRequired(ctx, outcome.change, "tls_applied_transition_failed")
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindCommitUnknown, "tls_applied_record_failed",
			"the TLS candidate was applied but its outcome could not be recorded", err)
	}
	recordErr := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		if err := tx.TLS().SaveChange(ctx, applied, outcome.change.Version()); err != nil {
			return storeError(err, "tls_change_store_failed", "could not record the applied TLS change")
		}
		if outcome.candidate.Source() != domain.TLSSourceBootstrap {
			if err := deleteBootstrapSecrets(ctx, tx); err != nil {
				return storeError(err, "tls_bootstrap_secret_cleanup_failed", "could not delete bootstrap TLS secrets after operational activation")
			}
		}
		event := port.AuditEvent{
			ID: s.deps.IDs.NewUUID(), OccurredAt: appliedNow, ActorKind: contract.AuditActorAccount,
			ActorID: string(meta.Principal.AccountID()), Action: "tls.activate", TargetType: "tls_version",
			TargetID: string(cmd.CandidateID), ClientIP: clientIP(meta.RequestMeta), Result: contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1},
		}
		return tx.Audit().Append(ctx, event, tlsScope())
	})
	if recordErr != nil {
		// §9: "applied 기록 실패를 포함한 불명확한 변경은 ... Reconcile로
		// 판단한다." The listener has already been swapped; only the DB
		// record is uncertain. Best-effort mark recovery_required so
		// Reconcile has a defined starting point -- its own failure is not
		// this call's to surface, the same reasoning TLSInstaller.Discard's
		// doc comment gives for never returning an error of its own.
		s.deps.RuntimeGate.FailClosed("tls_applied_record_failed")
		_ = s.markRecoveryRequired(ctx, outcome.change, "tls_applied_record_failed")
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindCommitUnknown, "tls_applied_record_failed",
			"the TLS candidate was applied but recording it failed or is unknown", recordErr)
	}

	return contract.TLSStatusView{
		Active:      ptrTLSVersionView(toTLSVersionView(outcome.candidate)),
		Phase:       ptrPhase(domain.TLSChangePhaseApplied),
		CandidateID: ptrTLSVersionID(cmd.CandidateID),
		ErrorCode:   "",
		Version:     outcome.installationVersionAfterSetActive,
	}, nil
}

// deleteBootstrapSecrets removes private material that is no longer needed
// once an operational TLS snapshot is live. The public key rows, certificates,
// TLSVersion snapshots and their change history remain untouched so a later
// audit/recovery read still has the complete public history. Deletion is
// idempotent: ListEncrypted may contain no matching row after a retry.
func deleteBootstrapSecrets(ctx context.Context, tx port.TxStores) error {
	secrets, err := tx.Secrets().ListEncrypted(ctx)
	if err != nil {
		return err
	}
	for _, secret := range secrets {
		if secret.Purpose() == domain.SecretPurposeBootstrapCA {
			if err := tx.Secrets().Delete(ctx, secret.OwnerKeyID(), secret.Purpose()); err != nil {
				return err
			}
		}
	}
	versions, err := tx.TLS().ListVersions(ctx)
	if err != nil {
		return err
	}
	for _, version := range versions {
		if version.Source() == domain.TLSSourceBootstrap {
			if err := tx.Secrets().Delete(ctx, version.KeyMaterialID(), domain.SecretPurposeInternalTLS); err != nil {
				return err
			}
		}
	}
	return nil
}

// rollbackActivation is §9's "Apply 실패는 DB/메모리 모두 원복한다" DB half:
// a best-effort separate Write that moves the just-committed TLSChange to
// rolled_back and reverts the installation's active pointer back to
// previousVersionID.
//
// A first activation uses TLSRepository.ClearActive; a late rollback is
// guarded by both the installation version and candidate id so it cannot
// clear a newer activation.
func (s *TLSService) rollbackActivation(ctx context.Context, meta contract.MutationMeta, outcome tlsActivationOutcome, errorCode string) error {
	now := s.deps.Clock.Now()
	return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		rolledBack, err := outcome.change.RollbackApply(errorCode, now)
		if err != nil {
			return err
		}
		if err := tx.TLS().SaveChange(ctx, rolledBack, outcome.change.Version()); err != nil {
			return err
		}
		if outcome.previousVersionID != "" {
			if err := tx.TLS().SetActive(ctx, outcome.installationVersionAfterSetActive, outcome.previousVersionID); err != nil {
				return err
			}
		} else if err := tx.TLS().ClearActive(ctx, outcome.installationVersionAfterSetActive, outcome.candidate.ID()); err != nil {
			return err
		}
		event := port.AuditEvent{
			ID: s.deps.IDs.NewUUID(), OccurredAt: now, ActorKind: contract.AuditActorAccount,
			Action: "tls.activate.rolled_back", TargetType: "tls_version", TargetID: string(rolledBack.CandidateVersionID()),
			ClientIP: clientIP(meta.RequestMeta), Result: contract.AuditResultFailure,
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"error_code": errorCode}},
		}
		if meta.Principal.IsAdmin() {
			event.ActorKind = contract.AuditActorAccount
			event.ActorID = string(meta.Principal.AccountID())
		}
		return tx.Audit().Append(ctx, event, tlsScope())
	})
}

// markRecoveryRequired is the best-effort marker for §9's ambiguous-change
// case: the DB write that would record "applied" failed or is unknown, so
// the change is stamped recovery_required instead of left claiming
// "committed" (which would look, to a later Activate, like a resumable
// normal attempt rather than the maintenance condition it actually is).
func (s *TLSService) markRecoveryRequired(ctx context.Context, committed domain.TLSChange, errorCode string) error {
	now := s.deps.Clock.Now()
	return s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		recovery, err := committed.MarkRecoveryRequired(errorCode, now)
		if err != nil {
			return err
		}
		return tx.TLS().SaveChange(ctx, recovery, committed.Version())
	})
}

// ---- Reconcile ----

// Reconcile resolves a recovery_required TLS change (docs/backend-
// implementation.md §9, §13 ruling 5): internal-only, gated by
// requireInternalOperation rather than the generic Authorizer. It re-
// validates the recorded candidate from its OWN stored, previously-validated
// snapshot (never an existing external file's current content -- §9 "기존
// 외부 파일의 현재 내용은 복구 중 자동 불러오지 않는다. DB의 검증된 snapshot만
// 사용한다"), and only actually swaps the live listener (via TLSInstaller)
// for whichever version wins -- a process restart means the in-memory
// listener from before the crash is gone, so "resolved to applied" must
// still mean an actual Apply call happened in THIS process, not just a
// phase label change.
//
// Apply is intentionally still performed from this recovery transaction's
// callback because Reconcile runs during startup before normal admission. Any
// error after the installer is touched, including a rollback or unknown
// commit, fails the RuntimeGate; Reconcile never reports a normal success
// while the persisted decision may still be unresolved.
func (s *TLSService) Reconcile(ctx context.Context, meta contract.MutationMeta, cmd contract.TLSReconcileCommand) (contract.TLSStatusView, error) {
	if err := cmd.Validate(); err != nil {
		return contract.TLSStatusView{}, err
	}
	if err := requireInternalOperation(meta.Principal, port.ActionTLSReconcile); err != nil {
		return contract.TLSStatusView{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.TLSStatusView{}, contract.WrapAppError(contract.ErrorKindUnavailable, "request_canceled",
			"the request was canceled before it completed", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var view contract.TLSStatusView
	failureCode := ""
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return storeError(err, "tls_installation_read_failed", "could not read the installation state")
		}
		view.Version = installation.Version

		active, err := tx.TLS().GetActiveForUpdate(ctx)
		if errors.Is(err, port.ErrNotFound) {
			if installation.ActiveTLSVersionID == "" {
				return nil // nothing has ever been activated; nothing to reconcile
			}
			failureCode = "tls_active_change_missing"
			return contract.NewAppError(contract.ErrorKindUnavailable, failureCode,
				"the installation names an active TLS version with no change record")
		}
		if err != nil {
			return storeError(err, "tls_active_change_read_failed", "could not read the active TLS change")
		}
		if active.Phase() == domain.TLSChangePhaseApplied {
			if installation.ActiveTLSVersionID == "" || installation.ActiveTLSVersionID != active.CandidateVersionID() {
				failureCode = "tls_applied_pointer_inconsistent"
				return contract.NewAppError(contract.ErrorKindUnavailable, failureCode,
					"the applied TLS change does not match the installation's active pointer")
			}
			// Already resolved -- report current state, do nothing. A terminal
			// applied row is not an unresolved Apply window, so Reconcile must
			// not touch the live installer merely because the process restarted.
			version, err := tx.TLS().GetVersion(ctx, installation.ActiveTLSVersionID)
			if err != nil {
				return storeError(err, "tls_active_version_read_failed", "could not read the active TLS version")
			}
			activeView := toTLSVersionView(version)
			view.Active = &activeView
			phase := active.Phase()
			view.Phase = &phase
			candidateID := active.CandidateVersionID()
			view.CandidateID = &candidateID
			view.ErrorCode = active.ErrorCode()
			return nil
		}
		if active.Phase() == domain.TLSChangePhaseRolledBack {
			failureCode = "tls_rolled_back_pointer_inconsistent"
			return contract.NewAppError(contract.ErrorKindUnavailable, failureCode,
				"a rolled-back TLS change is still named by the installation's active pointer")
		}
		if active.Phase() == domain.TLSChangePhasePrepared {
			failureCode = "tls_reconcile_prepared_active"
			return contract.NewAppError(contract.ErrorKindUnavailable, failureCode,
				"a prepared TLS change cannot be activated during reconciliation")
		}
		if active.Phase() == domain.TLSChangePhaseCommitted {
			// The committed row and active pointer are the durable decision
			// written immediately before Installer.Apply. A restart can land
			// here before Apply or before the applied record, so move it into
			// the explicit recovery state before evaluating the stored
			// candidate/previous snapshots.
			now := s.deps.Clock.Now()
			recovery, err := active.MarkRecoveryRequired("tls_reconcile_committed", now)
			if err != nil {
				failureCode = "tls_reconcile_committed_marker_failed"
				return contract.WrapAppError(contract.ErrorKindUnavailable, failureCode,
					"the committed TLS change could not be moved into recovery", err)
			}
			if err := tx.TLS().SaveChange(ctx, recovery, active.Version()); err != nil {
				failureCode = "tls_reconcile_committed_marker_failed"
				return storeError(err, failureCode, "could not record the committed TLS change as recovery-required")
			}
			active = recovery
		}

		now := s.deps.Clock.Now()

		var candidateFacts, previousFacts domain.TLSValidationFacts
		var candidateVersion, previousVersion domain.TLSVersion
		var haveCandidate, havePrevious bool

		if cv, err := tx.TLS().GetVersion(ctx, active.CandidateVersionID()); err == nil {
			candidateVersion = cv
			if f, err := s.buildValidationFacts(ctx, tx, cv, now); err == nil {
				candidateFacts = f
				haveCandidate = true
			}
		} else if !errors.Is(err, port.ErrNotFound) {
			return storeError(err, "tls_candidate_read_failed", "could not read the recorded candidate")
		}

		if active.PreviousVersionID() != "" {
			if pv, err := tx.TLS().GetVersion(ctx, active.PreviousVersionID()); err == nil {
				previousVersion = pv
				if f, err := s.buildValidationFacts(ctx, tx, pv, now); err == nil {
					previousFacts = f
					havePrevious = true
				}
			} else if !errors.Is(err, port.ErrNotFound) {
				return storeError(err, "tls_previous_read_failed", "could not read the recorded previous version")
			}
		}

		facts := domain.TLSReconcileFacts{PreviousFacts: previousFacts}
		if haveCandidate {
			facts.CandidateVersionID = active.CandidateVersionID()
			facts.CandidateFacts = candidateFacts
		}
		if havePrevious {
			facts.PreviousVersionID = active.PreviousVersionID()
		}

		reconciled, recErr := active.Reconcile(facts, now)
		if recErr != nil {
			failureCode = "tls_recovery_unresolved"
			return contract.WrapAppError(contract.ErrorKindUnavailable, failureCode,
				"neither the candidate nor the previous TLS version could be re-validated", recErr)
		}

		var winner domain.TLSVersion
		var winnerSecret domain.EncryptedSecret
		switch reconciled.Phase() {
		case domain.TLSChangePhaseApplied:
			winner = candidateVersion
		case domain.TLSChangePhaseRolledBack:
			winner = previousVersion
		}
		if winner.ID() == "" {
			failureCode = "tls_reconcile_winner_missing"
			return contract.NewAppError(contract.ErrorKindUnavailable, failureCode,
				"the reconciled TLS change did not identify a usable winning version")
		}
		winnerSecret, err = tx.Secrets().GetEncrypted(ctx, winner.KeyMaterialID(), domain.SecretPurposeInternalTLS)
		if err != nil {
			failureCode = "tls_reconcile_winner_key_read_failed"
			return storeError(err, "tls_winner_key_read_failed", "could not read the winning TLS version's stored key")
		}

		prepared, err := s.deps.TLSInstaller.Prepare(ctx, winner, winnerSecret)
		if err != nil {
			failureCode = "tls_reconcile_prepare_failed"
			return contract.WrapAppError(contract.ErrorKindUnavailable, "tls_reconcile_prepare_failed",
				"could not prepare the reconciled TLS version", err)
		}
		defer s.deps.TLSInstaller.Discard(prepared)
		if err := s.deps.TLSInstaller.Apply(ctx, prepared); err != nil {
			failureCode = "tls_reconcile_apply_failed"
			return contract.WrapAppError(contract.ErrorKindUnavailable, "tls_reconcile_apply_failed",
				"could not apply the reconciled TLS version", err)
		}

		if err := tx.TLS().SaveChange(ctx, reconciled, active.Version()); err != nil {
			failureCode = "tls_reconcile_record_failed"
			return storeError(err, "tls_change_store_failed", "could not record the reconciled TLS change")
		}
		if winner.Source() != domain.TLSSourceBootstrap {
			if err := deleteBootstrapSecrets(ctx, tx); err != nil {
				failureCode = "tls_reconcile_bootstrap_secret_cleanup_failed"
				return storeError(err, failureCode, "could not delete bootstrap TLS secrets after operational recovery")
			}
		}
		if reconciled.Phase() == domain.TLSChangePhaseRolledBack {
			if err := tx.TLS().SetActive(ctx, installation.Version, active.PreviousVersionID()); err != nil {
				failureCode = "tls_reconcile_pointer_failed"
				return storeError(err, "tls_set_active_failed", "could not revert the active TLS pointer")
			}
			view.Version = installation.Version.Next()
		}

		event := port.AuditEvent{
			ID: s.deps.IDs.NewUUID(), OccurredAt: now, ActorKind: contract.AuditActorSystem,
			Action: "tls.reconcile", TargetType: "tls_version", TargetID: string(reconciled.CandidateVersionID()),
			Result:  contract.AuditResultSuccess,
			Details: contract.AuditDetails{SchemaVersion: 1, Fields: map[string]string{"phase": string(reconciled.Phase())}},
		}
		if err := tx.Audit().Append(ctx, event, tlsScope()); err != nil {
			failureCode = "tls_reconcile_audit_failed"
			return storeError(err, "tls_audit_failed", "could not record the reconcile audit event")
		}

		winnerView := toTLSVersionView(winner)
		view.Active = &winnerView
		phase := reconciled.Phase()
		view.Phase = &phase
		candidateID := reconciled.CandidateVersionID()
		view.CandidateID = &candidateID
		view.ErrorCode = reconciled.ErrorCode()
		return nil
	})
	if err != nil {
		if failureCode == "" {
			failureCode = "tls_reconcile_failed"
		}
		s.deps.RuntimeGate.FailClosed(failureCode)
		return contract.TLSStatusView{}, err
	}
	return view, nil
}
