package contract

import "cert-me/internal/domain"

// PublicCACertificateQuery addresses a CA certificate by its immutable
// certificate id, so a fixed public URL continues to identify the same DER
// after its authority rotates or is archived.
type PublicCACertificateQuery struct {
	CertificateID domain.CertificateID
}

func (q PublicCACertificateQuery) Validate() error {
	_, err := domain.ParseCertificateID(string(q.CertificateID))
	return requireNoDomainError(err)
}

// PublicCACertificateView carries the immutable target certificate and its
// stored issuer path, ordered from the target through the Root. DER slices
// contain public certificate material only; no private key or download
// credential is part of this result.
type PublicCACertificateView struct {
	Certificate domain.Certificate
	ChainDER    [][]byte
}
