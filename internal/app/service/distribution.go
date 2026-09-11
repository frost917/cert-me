// Package service: DistributionService implements the download/delivery
// half of the app (docs/backend-implementation.md §3, §7). Deliver is the
// one method that ever hands raw certificate/key bytes to a client; every
// other method in this file exists to make that hand-off safe.
package service

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
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
// DeliveryEncoder, RuntimeGate").
type DistributionDeps struct {
	CommonDeps
	TokenCodec      port.TokenCodec
	DeliveryEncoder port.DeliveryEncoder
	RuntimeGate     port.RuntimeGate
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

// prepare performs §7 steps 1-2: read the grant/certificate/delivery/
// ciphertext (outside any Write, as preparation input only -- ReadStore's
// own contract is that a read never authorizes a commit) and have the
// payload encoder complete the in-memory bundle. An encoding failure here
// never touches the store, so it cannot consume anything
// (docs/backend-implementation.md §11 B03 acceptance: "인코딩 실패 시
// 소비 0회").
//
// KNOWN GAP (flagged for the lead, not guessed around): building a real
// certificate chain for ChainDER would require resolving the certificate's
// IssuerCAKeyGenerationID back to the Authority (or ca_certificates row)
// that signed it, so the chain can be walked up to the root. Neither
// port.PKIRepository nor any other Distribution dependency exposes that
// lookup (there is no GetAuthorityByKeyGeneration, no CA-certificate-by-
// key-generation read -- see internal/app/port/pki.go). ChainDER is
// therefore always empty below. This is not a product-behavior guess; it is
// the direct consequence of a port surface this file is not allowed to
// extend (out of this assignment's file scope).
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

		if g.Purpose() != domain.GrantPurposeLeafPrivate {
			return nil
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
			ChainDER:       nil, // see the gap noted in this function's doc comment
			LeafSecret:     leafSecret,
			Format:         format,
			PEMPart:        string(cmd.PEMPart),
			PKCS12Password: cmd.PKCS12Password,
		})
	} else {
		// ASSUMPTION (flagged for the lead): port.DeliveryEncoder's own doc
		// comment scopes it to "leaf_delivery 암호문만 허용" -- it exists to
		// turn an *encrypted private key* into a client bundle, and its
		// DeliveryEncodeInput.LeafSecret field is not optional. A public
		// download carries no private key at all, and §5 lists no second,
		// public-only encoder dependency for Distribution. So the public
		// payload is built directly here, from data that is already public
		// (the certificate DER); no decryption or DeliveryEncoder round trip
		// is involved. If this reading is wrong, the fix is a new documented
		// dependency, not a change to how this function calls the existing
		// one.
		bundle, encErr = encodePublicBundle(certificate, nil, format, string(cmd.PEMPart))
	}
	if encErr != nil {
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

// encodePublicBundle builds the public (no private key) leaf download
// payload directly, since no port encoder is scoped to this case -- see
// prepare's doc comment. chainDER is always empty today (the same gap noted
// there); pemPart selects which PEM blocks go in for the pem format.
func encodePublicBundle(cert domain.Certificate, chainDER [][]byte, format port.DeliveryFormat, pemPart string) (port.EncodedBundle, error) {
	if pemPart == string(contract.DownloadPartPrivateKey) {
		return port.EncodedBundle{}, contract.NewAppError(contract.ErrorKindValidation,
			"public_download_no_private_key", "a public download cannot include the private key")
	}
	switch format {
	case port.DeliveryFormatPEM:
		var buf bytes.Buffer
		if pemPart == "" || pemPart == string(contract.DownloadPartCertificate) {
			if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.DER()}); err != nil {
				return port.EncodedBundle{}, contract.WrapAppError(contract.ErrorKindValidation, "public_bundle_encode_failed", "could not encode the certificate", err)
			}
		}
		if pemPart == "" || pemPart == string(contract.DownloadPartChain) {
			for _, der := range chainDER {
				if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
					return port.EncodedBundle{}, contract.WrapAppError(contract.ErrorKindValidation, "public_bundle_encode_failed", "could not encode the certificate chain", err)
				}
			}
		}
		return port.NewEncodedBundle(buf.Bytes(), "application/x-pem-file"), nil
	case port.DeliveryFormatZIP:
		return encodePublicZIP(cert, chainDER)
	case port.DeliveryFormatPKCS12:
		// ASSUMPTION (flagged for the lead): a PKCS#12 container is normally
		// used to carry a private key alongside its certificate. No document
		// defines what a "public, key-less pkcs12" download should contain,
		// so this refuses it rather than inventing a shape.
		return port.EncodedBundle{}, contract.NewAppError(contract.ErrorKindValidation,
			"public_pkcs12_undefined", "pkcs12 is not defined for a public certificate download")
	default:
		return port.EncodedBundle{}, contract.NewAppError(contract.ErrorKindValidation, "download_format_invalid", "unsupported download format")
	}
}

// encodePublicZIP archives the public certificate (and any chain entries)
// as sibling PEM files, matching the safe-fixed-filename policy inside the
// archive too.
func encodePublicZIP(cert domain.Certificate, chainDER [][]byte) (port.EncodedBundle, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	writePEM := func(name string, der []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		return pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	if err := writePEM("certificate.pem", cert.DER()); err != nil {
		_ = zw.Close()
		return port.EncodedBundle{}, contract.WrapAppError(contract.ErrorKindValidation, "public_bundle_encode_failed", "could not encode the certificate", err)
	}
	for i, der := range chainDER {
		if err := writePEM(fmt.Sprintf("chain-%d.pem", i+1), der); err != nil {
			_ = zw.Close()
			return port.EncodedBundle{}, contract.WrapAppError(contract.ErrorKindValidation, "public_bundle_encode_failed", "could not encode the certificate chain", err)
		}
	}
	if err := zw.Close(); err != nil {
		return port.EncodedBundle{}, contract.WrapAppError(contract.ErrorKindValidation, "public_bundle_encode_failed", "could not finish the certificate archive", err)
	}
	return port.NewEncodedBundle(buf.Bytes(), "application/zip"), nil
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

// appendDistributionAudit records one Deliver-related audit event. Scope is
// intentionally nil: resolving the owning Authority from a leaf certificate
// requires the same certificate-to-issuer walk prepare's doc comment flags
// as missing from PKIRepository, so this event is not scoped to any
// authority today. Flagged for the lead alongside the chain-building gap.
func appendDistributionAudit(ctx context.Context, tx port.TxStores, ids port.IDGenerator, now domain.Instant, meta contract.RequestMeta, action string, grantID domain.GrantID, result contract.AuditResult) error {
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
	if err := tx.Audit().Append(ctx, event, nil); err != nil {
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
func (s *DistributionService) commitConsumption(ctx context.Context, meta contract.RequestMeta, prep preparedDelivery, now domain.Instant) (consumedTransfer, error) {
	var result consumedTransfer
	err := s.deps.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		grant, err := tx.Delivery().GetGrantForUpdate(ctx, prep.tokenHash)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return contract.NewAppError(contract.ErrorKindValidation, "download_token_invalid", "download link is invalid")
			}
			return storeError(err, "download_grant_read_failed", "could not read the download link")
		}
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

		if grant.Purpose() != domain.GrantPurposeLeafPrivate {
			consumedGrant, err := grant.Consume(now)
			if err != nil {
				return contract.FromDomainError(err)
			}
			if err := tx.Delivery().SaveGrant(ctx, consumedGrant, grant.Version()); err != nil {
				return storeError(err, "download_grant_save_failed", "could not consume the download link")
			}
			if err := appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.public.start", consumedGrant.ID(), contract.AuditResultSuccess); err != nil {
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
		if err := appendDistributionAudit(ctx, tx, s.deps.IDs, now, meta, "distribution.deliver.private.start", consumedGrant.ID(), contract.AuditResultSuccess); err != nil {
			return err
		}
		result = consumedTransfer{grant: consumedGrant, delivery: consumedDelivery}
		return nil
	})
	return result, err
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
	now := s.deps.Clock.Now()

	prep, err := s.prepare(ctx, cmd, format, now)
	if err != nil {
		// Step 2's rule: an encoding/preparation failure never reaches a
		// Write, so nothing was ever consumed.
		return contract.TransferSummary{}, err
	}
	// Safety net: every return path below either hands bundle to Send (which
	// itself is followed by an explicit Close in sendAndRecord) or returns
	// before that; Close is idempotent, so a redundant call here is free.
	defer prep.bundle.Close()

	consumed, err := s.commitConsumption(ctx, meta, prep, now)
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
