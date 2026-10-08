package service

import (
	"context"
	"errors"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type publicCAState struct {
	certificate domain.Certificate
	record      port.CACertificateRecord
	authority   domain.Authority
}

// ReadPublicCACertificate returns one immutable Root or Intermediate
// certificate and its stored certificate-to-Root path. The path is addressed
// by certificate id rather than Authority.IssuanceCertificateID, so rotation,
// archival and key destruction do not change a published URL.
func (s *QueryService) ReadPublicCACertificate(ctx context.Context, meta contract.RequestMeta, query contract.PublicCACertificateQuery) (contract.PublicCACertificateView, error) {
	if err := query.Validate(); err != nil {
		return contract.PublicCACertificateView{}, err
	}

	var view contract.PublicCACertificateView
	err := s.deps.ReadStore.Read(ctx, func(tx port.TxStores) error {
		if err := requireCurrentAuth(ctx, tx, meta.Principal, s.deps.Clock); err != nil {
			return err
		}
		if err := s.deps.Authorizer.Authorize(ctx, meta.Principal, port.ActionQueryReadPublicCA, port.NewAuthorizationScope()); err != nil {
			return err
		}

		certificate, err := tx.PKI().GetCertificate(ctx, query.CertificateID)
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("certificate", "the public CA certificate was not found")
		}
		if err != nil {
			return storeError(err, "query_public_ca_certificate_read_failed", "could not read the public CA certificate")
		}
		if certificate.ID() != query.CertificateID || certificate.Kind() != domain.CertificateKindCA {
			return queryNotFound("certificate", "the public CA certificate was not found")
		}

		record, err := tx.PKI().GetCACertificateRecord(ctx, query.CertificateID)
		if errors.Is(err, port.ErrNotFound) {
			return queryNotFound("certificate", "the public CA certificate was not found")
		}
		if err != nil {
			return storeError(err, "query_public_ca_record_read_failed", "could not read the public CA certificate record")
		}
		if record.CertificateID != query.CertificateID {
			return chainError("public_ca_record_mismatch", "the stored CA certificate record does not match its certificate", query.CertificateID)
		}

		// The public-read action is authorized above. This internal owner
		// lookup is derived solely from the stored CA record and serves only
		// to classify Root/Intermediate versus private bootstrap material.
		// Its management projection is never returned to the public caller.
		hop, err := loadPublicCAState(ctx, tx, certificate, record, adminScope(), true)
		if err != nil {
			return err
		}
		if hop.authority.Kind() != domain.AuthorityKindRoot && hop.authority.Kind() != domain.AuthorityKindIntermediate {
			return queryNotFound("certificate", "the public CA certificate was not found")
		}

		chainDER, err := publicCAChainDER(ctx, tx, hop, adminScope())
		if err != nil {
			return err
		}
		view = contract.PublicCACertificateView{
			Certificate: certificate,
			ChainDER:    cloneDERChain(chainDER),
		}
		return nil
	})
	if err != nil {
		return contract.PublicCACertificateView{}, err
	}
	return view, nil
}

func loadPublicCAState(ctx context.Context, tx port.TxStores, certificate domain.Certificate, record port.CACertificateRecord, scope port.QueryScope, target bool) (publicCAState, error) {
	if certificate.Kind() != domain.CertificateKindCA || certificate.ID() != record.CertificateID {
		return publicCAState{}, chainError("public_ca_record_mismatch", "the stored CA certificate record does not match its certificate", certificate.ID())
	}

	generation, err := tx.PKI().GetCAKeyGeneration(ctx, record.CAKeyGenerationID)
	if errors.Is(err, port.ErrNotFound) {
		return publicCAState{}, chainError("public_ca_generation_missing", "a CA certificate has no stored key generation", certificate.ID())
	}
	if err != nil {
		return publicCAState{}, storeError(err, "query_public_ca_generation_read_failed", "could not read a CA key generation")
	}
	if generation.ID != record.CAKeyGenerationID || generation.AuthorityID == "" {
		return publicCAState{}, chainError("public_ca_generation_mismatch", "the stored CA key generation does not match its certificate record", certificate.ID())
	}

	queriedAuthority, err := tx.Queries().GetAuthority(ctx, generation.AuthorityID, scope)
	if errors.Is(err, port.ErrNotFound) {
		if target {
			return publicCAState{}, queryNotFound("certificate", "the public CA certificate was not found")
		}
		return publicCAState{}, chainError("public_ca_authority_missing", "a CA certificate has no visible authority record", certificate.ID())
	}
	if err != nil {
		return publicCAState{}, storeError(err, "query_public_ca_authority_read_failed", "could not read the CA authority")
	}
	if queriedAuthority.Authority.ID() != generation.AuthorityID {
		return publicCAState{}, chainError("public_ca_authority_mismatch", "the stored CA key generation does not match its authority", certificate.ID())
	}
	return publicCAState{certificate: certificate, record: record, authority: queriedAuthority.Authority}, nil
}

// publicCAChainDER walks only stored CA certificate relations. It returns
// the requested certificate first and the actual self-signed Root last.
// Authority pointers are intentionally not used to reconstruct old chains.
func publicCAChainDER(ctx context.Context, tx port.TxStores, target publicCAState, scope port.QueryScope) ([][]byte, error) {
	chain := make([][]byte, 0, 2)
	seen := map[domain.CertificateID]struct{}{target.certificate.ID(): {}}
	current := target

	for depth := 0; depth < maxChainDepth; depth++ {
		switch current.authority.Kind() {
		case domain.AuthorityKindRoot:
			if current.record.IssuerCACertificateID != "" {
				if _, exists := seen[current.record.IssuerCACertificateID]; exists {
					return nil, chainError("public_ca_chain_cycle", "the stored CA certificate chain is cyclic", current.record.IssuerCACertificateID)
				}
				return nil, chainError("public_ca_root_has_issuer", "the stored Root certificate unexpectedly has an issuer", current.certificate.ID())
			}
			if current.certificate.IssuerCAKeyGenerationID() != current.record.CAKeyGenerationID {
				return nil, chainError("public_ca_root_signer_mismatch", "the stored Root certificate is not self-signed by its recorded key generation", current.certificate.ID())
			}
			chain = append(chain, current.certificate.DER())
			return chain, nil

		case domain.AuthorityKindIntermediate:
			if current.record.IssuerCACertificateID == "" {
				return nil, chainError("public_ca_issuer_missing", "the stored Intermediate certificate has no Root issuer", current.certificate.ID())
			}
			issuerID := current.record.IssuerCACertificateID
			if _, exists := seen[issuerID]; exists {
				return nil, chainError("public_ca_chain_cycle", "the stored CA certificate chain is cyclic", issuerID)
			}
			seen[issuerID] = struct{}{}

			issuerCertificate, err := tx.PKI().GetCertificate(ctx, issuerID)
			if errors.Is(err, port.ErrNotFound) {
				return nil, chainError("public_ca_issuer_missing", "the stored CA issuer certificate is missing", issuerID)
			}
			if err != nil {
				return nil, storeError(err, "query_public_ca_issuer_read_failed", "could not read the stored CA issuer certificate")
			}
			issuerRecord, err := tx.PKI().GetCACertificateRecord(ctx, issuerID)
			if errors.Is(err, port.ErrNotFound) {
				return nil, chainError("public_ca_issuer_record_missing", "the stored CA issuer has no CA certificate record", issuerID)
			}
			if err != nil {
				return nil, storeError(err, "query_public_ca_issuer_record_read_failed", "could not read the stored CA issuer record")
			}
			if issuerRecord.CertificateID != issuerID || issuerRecord.CAKeyGenerationID != current.certificate.IssuerCAKeyGenerationID() {
				return nil, chainError("public_ca_issuer_generation_mismatch", "the stored issuer certificate does not match the signing key generation", issuerID)
			}
			issuer, err := loadPublicCAState(ctx, tx, issuerCertificate, issuerRecord, scope, false)
			if err != nil {
				return nil, err
			}
			if issuer.authority.Kind() != domain.AuthorityKindRoot {
				return nil, chainError("public_ca_parent_not_root", "an Intermediate certificate must chain directly to a Root certificate", issuerID)
			}
			chain = append(chain, current.certificate.DER())
			current = issuer

		default:
			return nil, chainError("public_ca_authority_kind_invalid", "the stored CA chain contains a non-public authority", current.certificate.ID())
		}
	}
	return nil, chainError("public_ca_chain_too_deep", "the stored CA certificate chain is longer than supported", target.certificate.ID())
}

func cloneDERChain(chain [][]byte) [][]byte {
	if len(chain) == 0 {
		return nil
	}
	cloned := make([][]byte, len(chain))
	for i := range chain {
		cloned[i] = append([]byte(nil), chain[i]...)
	}
	return cloned
}
