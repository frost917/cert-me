package pki

import "cert-me/internal/domain"

func validateAuthority(value domain.Authority) error {
	if value.Version() < 0 {
		return domain.ErrInvalidValue
	}
	if _, err := domain.ParseAuthorityID(string(value.ID())); err != nil {
		return err
	}
	if _, err := domain.ParseCAKeyGenerationID(string(value.KeyGenerationID())); err != nil {
		return err
	}
	if value.ManagementParentID() != "" {
		if _, err := domain.ParseAuthorityID(string(value.ManagementParentID())); err != nil {
			return err
		}
	}
	if value.IssuanceCertificateID() != "" {
		if _, err := domain.ParseCertificateID(string(value.IssuanceCertificateID())); err != nil {
			return err
		}
	}
	_, err := domain.NewAuthority(domain.AuthorityFacts{
		ID: value.ID(), Kind: value.Kind(), Name: value.Name(),
		ManagementParentID: value.ManagementParentID(), IssuanceState: value.IssuanceState(),
		IssuanceCertificateID: value.IssuanceCertificateID(), KeyGenerationID: value.KeyGenerationID(),
		KeyAvailable: value.KeyAvailable(), Affected: value.Affected(), PendingTakeover: value.PendingTakeover(),
		CertificateWindow: value.CertificateWindow(), ArchivedAt: value.ArchivedAt(), Version: value.Version(),
	})
	return err
}

func validateSeries(value domain.LeafSeries) error {
	if value.Version() < 0 {
		return domain.ErrInvalidValue
	}
	if _, err := domain.ParseSeriesID(string(value.ID())); err != nil {
		return err
	}
	if value.CurrentCertificateID() != "" {
		if _, err := domain.ParseCertificateID(string(value.CurrentCertificateID())); err != nil {
			return err
		}
	}
	if value.CurrentKeyGenerationID() != "" {
		if _, err := domain.ParseLeafKeyGenerationID(string(value.CurrentKeyGenerationID())); err != nil {
			return err
		}
	}
	_, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID: value.ID(), Name: value.Name(), Purpose: value.Purpose(),
		ManagementAuthorityID:  value.ManagementAuthorityID(),
		CurrentCertificateID:   value.CurrentCertificateID(),
		CurrentKeyGenerationID: value.CurrentKeyGenerationID(), Policy: value.Policy(),
		Version: value.Version(), ArchivedAt: value.ArchivedAt(),
	})
	return err
}

func validateLeafKeyGeneration(value domain.LeafKeyGeneration) error {
	_, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
		ID: value.ID(), SeriesID: value.SeriesID(), KeyMaterialID: value.KeyMaterialID(),
		GenerationNo: value.GenerationNo(), RenewalCount: value.RenewalCount(),
		PriorHistoryUnknown: value.PriorHistoryUnknown(), Custody: value.Custody(),
	})
	return err
}

func validateCertificate(value domain.Certificate) error {
	if value.CreatedByAccountID() != "" {
		if _, err := domain.ParseAccountID(string(value.CreatedByAccountID())); err != nil {
			return err
		}
	}
	_, err := domain.NewCertificate(domain.CertificateFacts{
		ID: value.ID(), DER: value.DER(), KeyMaterialID: value.KeyMaterialID(),
		IssuerCAKeyGenerationID: value.IssuerCAKeyGenerationID(), Serial: value.Serial(),
		Validity: value.Validity(), Subject: value.Subject(), SANs: value.SANs(),
		Kind: value.Kind(), Profile: value.Profile(), KeyAlgorithm: value.KeyAlgorithm(),
		Origin: value.Origin(), CreatedByAccountID: value.CreatedByAccountID(), Version: value.Version(),
	})
	return err
}
