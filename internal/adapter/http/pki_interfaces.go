package httpadapter

import (
	"context"

	"cert-me/internal/app/contract"
)

type AuthorityApplication interface {
	Create(context.Context, contract.MutationMeta, contract.AuthorityCreateCommand) (contract.AuthorityView, error)
	Rename(context.Context, contract.MutationMeta, contract.AuthorityRenameCommand) (contract.AuthorityView, error)
	SetIssuanceState(context.Context, contract.MutationMeta, contract.AuthoritySetIssuanceStateCommand) (contract.AuthorityView, error)
	DestroyKey(context.Context, contract.MutationMeta, contract.AuthorityDestroyKeyCommand) (contract.AuthorityView, error)
	Archive(context.Context, contract.MutationMeta, contract.AuthorityArchiveCommand) (contract.AuthorityView, error)
}

type PKIQueryApplication interface {
	ListAuthorities(context.Context, contract.RequestMeta, contract.AuthorityListQuery) (contract.Page[contract.AuthorityView], error)
	GetAuthority(context.Context, contract.RequestMeta, contract.AuthorityGetQuery) (contract.AuthorityView, error)
	GetCRLStatus(context.Context, contract.RequestMeta, contract.GetCRLStatusQuery) (contract.CRLStatusView, error)
}

type IssuanceApplication interface {
	Issue(context.Context, contract.MutationMeta, contract.IssuanceIssueCommand) (contract.IssuanceView, error)
	Renew(context.Context, contract.MutationMeta, contract.IssuanceRenewCommand) (contract.IssuanceView, error)
	Reissue(context.Context, contract.MutationMeta, contract.IssuanceReissueCommand) (contract.IssuanceView, error)
	UpdateSeries(context.Context, contract.MutationMeta, contract.IssuanceUpdateSeriesCommand) (contract.LeafSeriesView, error)
	ArchiveSeries(context.Context, contract.MutationMeta, contract.IssuanceArchiveSeriesCommand) (contract.LeafSeriesView, error)
}

type LeafQueryApplication interface {
	ListSeries(context.Context, contract.RequestMeta, contract.SeriesListQuery) (contract.Page[contract.LeafSeriesView], error)
	GetSeries(context.Context, contract.RequestMeta, contract.SeriesGetQuery) (contract.LeafSeriesView, error)
	ListCertificates(context.Context, contract.RequestMeta, contract.CertificateListQuery) (contract.Page[contract.CertificateView], error)
	GetCertificate(context.Context, contract.RequestMeta, contract.CertificateGetQuery) (contract.CertificateView, error)
}
