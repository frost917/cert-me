package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// maxChainDepth bounds the walk below. docs/data-model.md allows Root and
// Intermediate only, so a real chain is at most two CA certificates deep;
// this ceiling exists to turn a cyclic or corrupt issuer link into a bounded
// error instead of an infinite loop, not to express a policy about depth.
const maxChainDepth = 16

// buildChainDER resolves the issuer chain of one certificate, from its
// issuer up to the self-signed Root, as the app-wide common function
// docs/backend-implementation.md §14.2 requires ("app의 공통 조회 함수가 이
// typed port로 chain을 구성한다").
//
// The walk follows the STORED issuer link on each subtype row
// (leaf_certificates.issuer_ca_certificate_id, then
// ca_certificates.issuer_ca_certificate_id), never the issuing authority's
// current IssuanceCertificateID or its management parent. §14.2 is explicit:
// "현재 Authority.IssuanceCertificateID나 management_parent로 과거 체인을
// 대체하지 않는다" -- a certificate signed before its CA rotated must still
// resolve to the chain it was actually issued under.
//
// The result is issuer→Root and EXCLUDES the target certificate itself
// (§14.2 "내부 ChainDER는 대상 인증서를 제외한 issuer→Root 순서다"); the
// encoders decide where the target goes for each output format.
//
// A missing link, a cycle or an issuer whose CA key generation does not
// match the certificate's recorded issuer is an error before any encoding
// happens -- an empty chain is never a successful result ("누락·순환·issuer
// 키 불일치는 인코딩 전에 오류이며 빈 chain으로 성공하지 않는다").
func buildChainDER(ctx context.Context, tx port.TxStores, certificateID domain.CertificateID) ([][]byte, error) {
	leaf, err := tx.PKI().GetLeafCertificateRecord(ctx, certificateID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, chainError("chain_leaf_record_missing",
				"this certificate has no stored issuance record to resolve a chain from", certificateID)
		}
		return nil, storeError(err, "chain_leaf_record_read_failed", "could not read the certificate's issuance record")
	}
	if leaf.IssuerCACertificateID == "" {
		return nil, chainError("chain_issuer_missing",
			"this certificate records no issuing CA certificate", certificateID)
	}

	// The leaf's own certificate names the CA key generation that signed it;
	// the CA certificate the record points at must certify that same
	// generation, or the stored link and the signature disagree.
	certificate, err := tx.PKI().GetCertificate(ctx, certificateID)
	if err != nil {
		return nil, storeError(err, "chain_certificate_read_failed", "could not read the certificate")
	}

	chain := make([][]byte, 0, 2)
	seen := map[domain.CertificateID]struct{}{certificateID: {}}
	expectedKeyGeneration := certificate.IssuerCAKeyGenerationID()
	next := leaf.IssuerCACertificateID

	for depth := 0; depth < maxChainDepth; depth++ {
		if _, cycle := seen[next]; cycle {
			return nil, chainError("chain_cycle", "the stored issuer chain is cyclic", next)
		}
		seen[next] = struct{}{}

		record, err := tx.PKI().GetCACertificateRecord(ctx, next)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return nil, chainError("chain_ca_record_missing",
					"a certificate in the stored issuer chain has no CA record", next)
			}
			return nil, storeError(err, "chain_ca_record_read_failed", "could not read a CA certificate record")
		}
		if record.CAKeyGenerationID != expectedKeyGeneration {
			return nil, chainError("chain_issuer_key_mismatch",
				"the stored issuer certificate does not certify the signing key generation", next)
		}

		caCertificate, err := tx.PKI().GetCertificate(ctx, next)
		if err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return nil, chainError("chain_certificate_missing",
					"a certificate in the stored issuer chain is missing", next)
			}
			return nil, storeError(err, "chain_certificate_read_failed", "could not read a chain certificate")
		}
		chain = append(chain, caCertificate.DER())

		if record.IssuerCACertificateID == "" {
			// A self-signed Root terminates the walk (docs/data-model.md
			// "self-signed Root는 issuer 인증서 NULL").
			return chain, nil
		}
		expectedKeyGeneration = caCertificate.IssuerCAKeyGenerationID()
		next = record.IssuerCACertificateID
	}
	return nil, chainError("chain_too_deep", "the stored issuer chain is longer than supported", certificateID)
}

// chainError is the single shape every chain-resolution failure takes. They
// are unavailable rather than validation: the client asked for a legitimate
// download, and the stored relations turned out not to resolve.
func chainError(code, detail string, certificateID domain.CertificateID) error {
	return contract.NewAppError(contract.ErrorKindUnavailable, code, detail).
		WithField("certificate_id", string(certificateID))
}
