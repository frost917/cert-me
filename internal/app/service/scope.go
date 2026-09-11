// scope.go owns audit- and authorization-scope construction from STORED
// relations, for every service (docs/backend-implementation.md §2 "권한 검사
// 입력의 Scope는 DB 관계에서 구성하며 사용자 제공 Root ID를 신뢰하지
// 않는다", §14.6).
//
// One file, because §14.6's rules are cross-service and only hold if every
// service builds scope the same way:
//   - scope comes from rows read or written in this same transaction, never
//     from an AuthorityID the caller supplied;
//   - a plain leaf event carries exactly ONE managing authority and does not
//     replicate its ancestors ("상위 관리 Authority를 동일 이벤트의 추가
//     scope로 복제하지 않는다") -- multiple scopes demand permission on ALL
//     of them, so adding an ancestor would lock an intermediate administrator
//     out of their own range;
//   - a resolution failure is an error, never a silently empty scope
//     ("현재 MVP도 scope를 비워 저장하지 않는다");
//   - the management relation is never mixed with a certificate's historical
//     issuance chain, which buildChainDER derives separately (§14.2/§14.6
//     "관리 관계와 혼용하지 않는다").
//
// Operations that genuinely involve several CAs -- a transition -- keep the
// existing multi-scope audit rule and build their list from the stored
// relations they touched, not from request input.
package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// leafManagementAuthority resolves the management authority a
// download/delivery/recovery/expiry event is scoped to (§14.6): leaf_certificates
// -> SeriesID -> LeafSeries.ManagementAuthorityID, both read from stored
// relations under this same transaction. This is deliberately NOT the
// certificate's cryptographic issuance chain buildChainDER walks (§14.2) --
// "인증서의 역사적 발급 체인은 2번 경로로 별도로 구하고 관리 관계와 혼용하지
// 않는다" -- and it never trusts a caller-supplied AuthorityID. Every audit
// call in this file and in recovery.go goes through this one function so a
// download's audit scope and the RevocationChange.AuthorityID a failed
// transfer or recovery hands to applyRevocations cannot drift apart.
//
// A missing leaf record or series row is an error, never a silently empty
// scope (§14.6 "현재 MVP도 scope를 비워 저장하지 않는다").
func leafManagementAuthority(ctx context.Context, tx port.TxStores, certificateID domain.CertificateID) (domain.AuthorityID, error) {
	leaf, err := tx.PKI().GetLeafCertificateRecord(ctx, certificateID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return "", contract.NewAppError(contract.ErrorKindUnavailable, "distribution_scope_leaf_record_missing",
				"this certificate has no stored issuance record to scope the audit to").WithField("certificate_id", string(certificateID))
		}
		return "", storeError(err, "distribution_scope_leaf_record_read_failed", "could not read the certificate's issuance record")
	}
	snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, leaf.SeriesID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return "", contract.NewAppError(contract.ErrorKindUnavailable, "distribution_scope_series_missing",
				"this certificate's series record is missing").WithField("certificate_id", string(certificateID))
		}
		return "", storeError(err, "distribution_scope_series_read_failed", "could not read the certificate's series")
	}
	authorityID := snapshot.Series.ManagementAuthorityID()
	if authorityID == "" {
		return "", contract.NewAppError(contract.ErrorKindUnavailable, "distribution_scope_empty",
			"could not resolve a management authority for this certificate").WithField("certificate_id", string(certificateID))
	}
	return authorityID, nil
}

// authorityScopeFromRow is the CA-level counterpart: the scope of an event
// about an authority is that authority itself, taken from the row the
// service read under its own transaction. It exists so a service has an
// obvious thing to call instead of reaching for the AuthorityID that arrived
// on the command -- the two are equal only after the row has been read, and
// §2 requires the read.
func authorityScopeFromRow(authority domain.Authority) (domain.AuthorityID, error) {
	id := authority.ID()
	if id == "" {
		return "", contract.NewAppError(contract.ErrorKindUnavailable, "authority_scope_empty",
			"could not resolve an authority scope for this event")
	}
	return id, nil
}
