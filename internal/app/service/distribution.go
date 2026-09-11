// Package service: DistributionService implements the download/delivery
// half of the app (docs/backend-implementation.md §3, §7). Deliver is the
// one method that ever hands raw certificate/key bytes to a client; every
// other method in this file exists to make that hand-off safe.
package service

import (
	"context"
	"errors"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// deliverSendTimeout is the maximum real wall-clock time Send is given once
// the consuming transaction has committed (docs/api-contract.md "개인키
// 전송 Send는 소비 커밋 후 최대 60초의 실제 쓰기 deadline을 적용한다"; this
// project applies the same fixed deadline to a public transfer too, since
// api-contract.md does not carve out a separate, shorter deadline for it).
// It is a package var, not a const, purely so a test can shrink it to
// exercise the timeout-cleanup path without a real 60-second wait; the
// production value the constructor sees is always this default.
var deliverSendTimeout = 60 * time.Second

// deliverPostProcessTimeout is the "서버 runtime 수명에서 분리한 최대 5초
// 후처리 context" docs/backend-implementation.md §7 step 5 requires. It runs
// on context.Background(), not the caller's ctx, precisely because it must
// still record an outcome after the caller's own request context could
// already be canceled (client disconnect, handler timeout). Overridable in
// tests for the same reason as deliverSendTimeout above.
var deliverPostProcessTimeout = 5 * time.Second

// errPayloadReaderClosed is what a DownloadSink sees if it tries to Read
// after Send has returned. DownloadSink's contract (port/download.go) is
// that it "must not retain r ... and Send 반환 전에 사용을 종료한다"; this
// error is what makes a violation of that observable instead of silently
// reading zeroed or reused memory.
var errPayloadReaderClosed = errors.New("service: download payload reader is closed")

// DistributionDeps is DistributionService's dependency set
// (docs/backend-implementation.md §5 table row "Distribution: TokenCodec,
// DeliveryEncoder, PublicCertificateEncoder, OperationalLogger,
// RuntimeGate" -- the §14 ruling that settled the two dependencies this row
// used to lack).
type DistributionDeps struct {
	CommonDeps
	TokenCodec               port.TokenCodec
	DeliveryEncoder          port.DeliveryEncoder
	PublicCertificateEncoder port.PublicCertificateEncoder
	OperationalLogger        port.OperationalLogger
	RuntimeGate              port.RuntimeGate
}

// Validate reports the first missing dependency, common or Distribution-
// specific, so a misconfigured assembly fails at startup (§5 "필수
// 의존성이 nil이면 시작 시 실패한다").
func (d DistributionDeps) Validate() error {
	if err := d.CommonDeps.Validate(); err != nil {
		return err
	}
	return firstMissing(
		required{"TokenCodec", d.TokenCodec == nil},
		required{"DeliveryEncoder", d.DeliveryEncoder == nil},
		required{"PublicCertificateEncoder", d.PublicCertificateEncoder == nil},
		required{"OperationalLogger", d.OperationalLogger == nil},
		required{"RuntimeGate", d.RuntimeGate == nil},
	)
}

// DistributionService implements Deliver (docs/backend-implementation.md
// §7) plus CreateLink/ReportFailure. Only Deliver is in this file's scope;
// CreateLink/ReportFailure are a different developer's assignment on this
// branch and are intentionally not implemented here.
type DistributionService struct {
	deps DistributionDeps
}

// NewDistributionService constructs the service, failing immediately if a
// required dependency is missing (§5).
func NewDistributionService(deps DistributionDeps) (*DistributionService, error) {
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return &DistributionService{deps: deps}, nil
}

// toDeliveryFormat maps the wire-facing contract.DownloadFormat onto the
// port-level port.DeliveryFormat the encoder/public-bundle builder use.
// Both enums are fixed to the same three values; this only exists so the
// two layers are not accidentally coupled by sharing one type across a
// package boundary that otherwise keeps wire and encoder concerns separate.
func toDeliveryFormat(f contract.DownloadFormat) (port.DeliveryFormat, error) {
	switch f {
	case contract.DownloadFormatPEM:
		return port.DeliveryFormatPEM, nil
	case contract.DownloadFormatZIP:
		return port.DeliveryFormatZIP, nil
	case contract.DownloadFormatPKCS12:
		return port.DeliveryFormatPKCS12, nil
	default:
		return "", contract.NewAppError(contract.ErrorKindValidation, "download_format_invalid", "unsupported download format")
	}
}

// fixedFilename builds the safe, fixed Content-Disposition filename
// (docs/api-contract.md "토큰·Subject·사용자 파일명을 파일명에 삽입하지
// 않는다"). It depends only on purpose and format, never on any value the
// client or the certificate itself supplied.
func fixedFilename(purpose domain.GrantPurpose, format port.DeliveryFormat) string {
	base := "certificate"
	if purpose == domain.GrantPurposeLeafPrivate {
		base = "private-key"
	}
	switch format {
	case port.DeliveryFormatZIP:
		return base + ".zip"
	case port.DeliveryFormatPKCS12:
		return base + ".p12"
	default:
		return base + ".pem"
	}
}

// preparedDelivery is everything Deliver's prepare step (§7 steps 1-2)
// produces before any Write is opened. It owns bundle from the moment
// prepare returns it; Deliver is responsible for Close-ing it on every exit
// path (§7 step 5's "Send가 반환하거나 panic하면 payload를 정리한다" plus
// the encoding-failure and pre-Send-failure paths that never reach Send at
// all).
type preparedDelivery struct {
	tokenHash   domain.TokenHash
	purpose     domain.GrantPurpose
	certificate domain.Certificate
	bundle      port.EncodedBundle
	contentType string
	filename    string
}

// validatePublicFormat rejects the format/PEMPart combinations §14.4/§14.3
// forbid for a public (no private key) download, before anything is
// consumed. docs/api-contract.md:119 "public 토큰은 PEM certificate/chain
// 또는 공개 ZIP만 허용한다" -- a public PKCS#12 is not a narrower version of
// the private one, it is undefined, so this refuses it rather than
// inventing a key-less container shape (§14.4: "새 공개 PKCS#12 형식을
// 설계하지 않는다"). private_key is rejected the same way a public grant can
// never yield key material regardless of format.
func validatePublicFormat(format port.DeliveryFormat, pemPart contract.DownloadPart) error {
	if format == port.DeliveryFormatPKCS12 {
		return contract.NewAppError(contract.ErrorKindValidation, "public_pkcs12_undefined",
			"pkcs12 is not defined for a public certificate download")
	}
	if pemPart == contract.DownloadPartPrivateKey {
		return contract.NewAppError(contract.ErrorKindValidation,
			"public_download_no_private_key", "a public download cannot include the private key")
	}
	return nil
}

// prepare performs §7 steps 1-2: read the grant/certificate/delivery/
// ciphertext/chain (outside any Write, as preparation input only --
// ReadStore's own contract is that a read never authorizes a commit) and
// have the payload encoder complete the in-memory bundle. An encoding or
// chain-resolution failure here never touches the store, so it cannot
// consume anything (docs/backend-implementation.md §11 B03 acceptance:
// "인코딩 실패 시 소비 0회"; §14.2 "누락·순환·issuer 키 불일치는 인코딩
// 전에 오류이며 빈 chain으로 성공하지 않는다").
//
// The chain is always resolved, for both purposes and every format/PEMPart
// choice: §14.2 requires a valid stored issuer chain to exist before any
// encoding happens, not only when the caller's chosen part/format would
// actually surface it.
func (s *DistributionService) prepare(ctx context.Context, cmd contract.DownloadCommand, format port.DeliveryFormat, now domain.Instant) (preparedDelivery, error) {
	tokenHash, err := s.deps.TokenCodec.Hash(ctx, cmd.RawToken)
	if err != nil {
		return preparedDelivery{}, contract.WrapAppError(contract.ErrorKindValidation,
			"raw_token_hash_failed", "could not process the download token", err)
	}

	var (
		grant       domain.DownloadGrant
		certificate domain.Certificate
		leafSecret  domain.EncryptedSecret
		chainDER    [][]byte
	)
	readErr := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		g, err := tx.Delivery().GetGrantForUpdate(ctx, tokenHash)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "download_token_invalid", "download link is invalid")
			}
			return storeError(err, "download_grant_read_failed", "could not read the download link")
		}
		if err := g.Validate(g.Purpose(), g.CertificateID(), g.DeliveryID(), now); err != nil {
			return contract.FromDomainError(err)
		}
		cert, err := tx.PKI().GetCertificate(ctx, g.CertificateID())
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "certificate_not_found", "the certificate for this download link is missing")
			}
			return storeError(err, "certificate_read_failed", "could not read the certificate")
		}
		grant = g
		certificate = cert

		// §14.2: the stored issuer chain must resolve before any encoding
		// happens, regardless of purpose/format/PEMPart, and a resolution
		// failure here is unavailable rather than validation -- the client
		// asked for a legitimate download and the stored relations simply do
		// not resolve. buildChainDER is the one common function every chain
		// consumer (this file, and the CA-certificate download routes B03
		// does not implement yet) must go through (§14.2 "app의 공통 조회
		// 함수가 이 typed port로 chain을 구성한다").
		chain, err := buildChainDER(ctx, tx, cert.ID())
		if err != nil {
			return err
		}
		chainDER = chain

		if g.Purpose() != domain.GrantPurposeLeafPrivate {
			return validatePublicFormat(format, cmd.PEMPart)
		}

		// docs/api-contract.md: "private 토큰으로 공개 자료만 받는 조합은
		// 422이며 소비하지 않는다." A private grant may only be redeemed for
		// private_key PEM, the full key+cert+chain ZIP, or PKCS#12; asking a
		// private link for a certificate-only or chain-only PEM must be
		// rejected here, before anything is consumed -- letting it through
		// would burn the one-shot private custody on a response that never
		// actually contained the key.
		if format == port.DeliveryFormatPEM &&
			(cmd.PEMPart == contract.DownloadPartCertificate || cmd.PEMPart == contract.DownloadPartChain) {
			return contract.NewAppError(contract.ErrorKindValidation, "download_purpose_mismatch",
				"this download link only provides the private key bundle")
		}
		d, err := tx.Delivery().GetDeliveryForUpdate(ctx, g.DeliveryID())
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "delivery_not_found", "delivery record is missing")
			}
			return storeError(err, "delivery_read_failed", "could not read the delivery record")
		}
		if err := d.CanConsume(now); err != nil {
			return contract.FromDomainError(err)
		}
		secret, err := tx.Secrets().GetEncrypted(ctx, cert.KeyMaterialID(), domain.SecretPurposeLeafDelivery)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindConflict, "delivery_secret_missing", "the delivery ciphertext is no longer available")
			}
			return storeError(err, "delivery_secret_read_failed", "could not read the delivery ciphertext")
		}
		leafSecret = secret
		return nil
	})
	if readErr != nil {
		return preparedDelivery{}, readErr
	}

	var (
		bundle port.EncodedBundle
		encErr error
	)
	if grant.Purpose() == domain.GrantPurposeLeafPrivate {
		bundle, encErr = s.deps.DeliveryEncoder.Encode(ctx, port.DeliveryEncodeInput{
			Certificate:    certificate,
			ChainDER:       chainDER,
			LeafSecret:     leafSecret,
			Format:         format,
			PEMPart:        string(cmd.PEMPart),
			PKCS12Password: cmd.PKCS12Password,
		})
	} else {
		// §14.3: the public path never touches a decryption dependency --
		// port.PublicCertificateEncoder's input carries only public material
		// (the target certificate, its issuer chain, format/PEMPart), and
		// the encoder itself decides where the target goes for each format
		// (PEM part=chain is target→Root; ZIP splits certificate.pem/
		// chain.pem). This file no longer builds PEM/ZIP bytes itself.
		bundle, encErr = s.deps.PublicCertificateEncoder.Encode(ctx, port.PublicEncodeInput{
			Certificate: certificate,
			ChainDER:    chainDER,
			Format:      format,
			PEMPart:     string(cmd.PEMPart),
		})
	}
	if encErr != nil {
		// An encoder that returns a bundle alongside its error is still
		// handing back live plaintext (port.EncodedBundle.Use works on it
		// until Close is called). This path returns before Deliver's own
		// `defer prep.bundle.Close()` is installed, so nothing else will
		// ever close it if this function does not -- close it here so a
		// buggy or malicious encoder cannot leave decrypted key/certificate
		// material reachable through a bundle nobody else holds a reference
		// to releasing.
		bundle.Close()
		return preparedDelivery{}, encErr
	}

	return preparedDelivery{
		tokenHash:   tokenHash,
		purpose:     grant.Purpose(),
		certificate: certificate,
		bundle:      bundle,
		contentType: bundle.ContentType,
		filename:    fixedFilename(grant.Purpose(), format),
	}, nil
}

// consumedTransfer is what commitConsumption's Write produces: the grant and
// (for a private transfer) the delivery, both as they now read after being
// consumed in that commit. Only a Write that actually reaches its Store
// call produces one of these -- a definite rollback or a commit_unknown
// never populates it, which is exactly why Deliver only calls sink.Send once
// it holds a consumedTransfer (§7 step 4: "commit 패자에게는 sink 호출이
// 없다").
type consumedTransfer struct {
	grant    domain.DownloadGrant
	delivery domain.Delivery // zero value for a public transfer
}

// appendDistributionAudit records one Deliver-related audit event, scoped to
// the certificate's management authority (§14.6).
func appendDistributionAudit(ctx context.Context, tx port.TxStores, ids port.IDGenerator, now domain.Instant, meta contract.RequestMeta, action string, grantID domain.GrantID, result contract.AuditResult, scope domain.AuthorityID) error {
	event := port.AuditEvent{
		ID:         ids.NewUUID(),
		OccurredAt: now,
		ActorKind:  contract.AuditActorDownloadToken,
		ActorID:    string(grantID),
		TokenID:    string(grantID),
		Action:     action,
		TargetType: "download_grant",
		TargetID:   string(grantID),
		ClientIP:   clientIP(meta),
		Result:     result,
		Details:    contract.AuditDetails{SchemaVersion: 1},
	}
	if err := tx.Audit().Append(ctx, event, []domain.AuthorityID{scope}); err != nil {
		return storeError(err, "distribution_audit_failed", "could not record the download audit event")
	}
	return nil
}

// commitConsumption is §7 step 3: the single Write that re-verifies the
// grant/delivery/deadline under lock and commits the one-shot consumption --
// private: transferring + temporary-ciphertext delete + invalidate every
// other private grant on the same delivery + start audit, all together;
// public: consume the grant + start audit. It never calls the encoder and
// never touches sink: those already ran (prepare) or run only after this
// commit succeeds (sendAndRecord), matching the "encoding failure consumes
// nothing" / "commit loser never reaches Send" rules.
func (s *DistributionService) commitConsumption(ctx context.Context, meta contract.RequestMeta, prep preparedDelivery) (consumedTransfer, domain.Instant, error) {
	var result consumedTransfer
	var consumeNow domain.Instant
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		grant, err := tx.Delivery().GetGrantForUpdate(ctx, prep.tokenHash)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "download_token_invalid", "download link is invalid")
			}
			return storeError(err, "download_grant_read_failed", "could not read the download link")
		}
		// Re-read the clock now that GetGrantForUpdate has taken the row
		// lock, instead of reusing prepare()'s now. Encoding (§7 step 2) can
		// take real wall-clock time, and prepare's now was only ever a
		// snapshot for preparation-time checks; reusing it here would let a
		// grant/delivery whose deadline passed during encoding still be
		// validated and Consumed against a now that predates that deadline.
		// The reviewer reproduced exactly this with a delayed encoder and an
		// advancing clock (PR #3 finding).
		now := s.deps.Clock.Now()
		consumeNow = now
		if err := grant.Validate(grant.Purpose(), grant.CertificateID(), grant.DeliveryID(), now); err != nil {
			return contract.FromDomainError(err)
		}
		// The payload was built against prep.purpose/prep.certificate before
		// this commit opened. If the grant's own target has somehow moved
		// since (it should not -- purpose/certificate/delivery are set once
		// at grant creation and never changed by Save), the encoded payload
		// no longer matches what this commit is about to authorize, so this
		// refuses rather than trusting the stale prepared payload. Deliver
		// does not retry (RunWithRetry is for pre-external-effect
		// preparation only, and no external effect has happened yet, but a
		// mismatch here is not the "clean version race" RunWithRetry
		// resolves either), so this is a hard failure.
		if grant.Purpose() != prep.purpose || grant.CertificateID() != prep.certificate.ID() {
			return contract.NewAppError(contract.ErrorKindConflict, "download_grant_changed", "the download link changed since it was read")
		}

		scope, err := leafManagementAuthority(ctx, tx, prep.certificate.ID())
		if err != nil {
			return err
		}

		if grant.Purpose() != domain.GrantPurposeLeafPrivate {
			consumedGrant, err := grant.Consume(now)
			if err != nil {
				return contract.FromDomainError(err)
			}
			if err := tx.Delivery().SaveGrant(ctx, consumedGrant, grant.Version()); err != nil {
				return storeError(err, "download_grant_save_failed", "could not consume the download link")
			}
			if err := appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.public.start", consumedGrant.ID(), contract.AuditResultSuccess, scope); err != nil {
				return err
			}
			result = consumedTransfer{grant: consumedGrant}
			return nil
		}

		delivery, err := tx.Delivery().GetDeliveryForUpdate(ctx, grant.DeliveryID())
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "delivery_not_found", "delivery record is missing")
			}
			return storeError(err, "delivery_read_failed", "could not read the delivery record")
		}
		if err := delivery.CanConsume(now); err != nil {
			return contract.FromDomainError(err)
		}
		consumedGrant, err := grant.Consume(now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		consumedDelivery, err := delivery.Consume(now)
		if err != nil {
			return contract.FromDomainError(err)
		}
		if err := tx.Delivery().SaveGrant(ctx, consumedGrant, grant.Version()); err != nil {
			return storeError(err, "download_grant_save_failed", "could not consume the download link")
		}
		if err := tx.Delivery().SaveDelivery(ctx, consumedDelivery, delivery.Version()); err != nil {
			return storeError(err, "delivery_save_failed", "could not update the delivery record")
		}
		if err := tx.Secrets().Delete(ctx, prep.certificate.KeyMaterialID(), domain.SecretPurposeLeafDelivery); err != nil {
			return storeError(err, "delivery_secret_delete_failed", "could not remove the delivery ciphertext")
		}
		if err := tx.Delivery().InvalidatePrivateGrants(ctx, consumedDelivery.ID(), now); err != nil {
			return storeError(err, "delivery_grant_invalidate_failed", "could not invalidate remaining private links")
		}
		if err := appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.private.start", consumedGrant.ID(), contract.AuditResultSuccess, scope); err != nil {
			return err
		}
		result = consumedTransfer{grant: consumedGrant, delivery: consumedDelivery}
		return nil
	})
	return result, consumeNow, err
}

// Deliver is the fixed signature docs/backend-implementation.md §7 assigns
// DistributionService: "Deliver는 payload를 반환하지 않고 소비 성공 후에만
// sink를 호출한다." See this file's package doc and prepare/
// commitConsumption/sendAndRecord (deliver_postprocess.go) for the five
// steps §7 lists.
func (s *DistributionService) Deliver(ctx context.Context, meta contract.RequestMeta, cmd contract.DownloadCommand, sink port.DownloadSink) (contract.TransferSummary, error) {
	if sink == nil {
		return contract.TransferSummary{}, contract.NewAppError(contract.ErrorKindValidation, "download_sink_missing", "a download sink is required")
	}
	if err := cmd.Validate(); err != nil {
		return contract.TransferSummary{}, err
	}
	format, err := toDeliveryFormat(cmd.Format)
	if err != nil {
		return contract.TransferSummary{}, err
	}
	prepareNow := s.deps.Clock.Now()

	prep, err := s.prepare(ctx, cmd, format, prepareNow)
	if err != nil {
		// Step 2's rule: an encoding/preparation failure never reaches a
		// Write, so nothing was ever consumed.
		return contract.TransferSummary{}, err
	}
	// Safety net: every return path below either hands bundle to Send (which
	// itself is followed by an explicit Close in sendAndRecord) or returns
	// before that; Close is idempotent, so a redundant call here is free.
	defer prep.bundle.Close()

	// commitConsumption re-reads the clock itself once it holds the grant's
	// row lock (see its comment) -- prepareNow above is preparation-only and
	// must not be reused past this point (PR #3 finding: reusing it let an
	// expiry that landed during encoding go unnoticed).
	consumed, now, err := s.commitConsumption(ctx, meta, prep)
	if err != nil {
		if errors.Is(err, port.ErrCommitUnknown) {
			// §12: "private 소비 commit 미확정 ... 은 FailClosed 대상이다."
			// A public commit_unknown has no such rule -- there is no key
			// custody at risk, so the request simply fails.
			if prep.purpose == domain.GrantPurposeLeafPrivate {
				s.deps.RuntimeGate.FailClosed("distribution_consume_commit_unknown")
			}
			return contract.TransferSummary{}, contract.WrapAppError(contract.ErrorKindCommitUnknown,
				"download_commit_unknown", "the download consumption outcome is unknown", err)
		}
		// §12: "확정 rollback으로 소비가 없었던 경우는 payload만 지우고
		// 반환한다." -- the deferred Close above is exactly that; nothing
		// else to do.
		return contract.TransferSummary{}, err
	}

	return s.sendAndRecord(ctx, meta, sink, prep, consumed, now)
}
