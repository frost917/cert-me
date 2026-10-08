package service

import (
	"context"
	"errors"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func TestPublicCAReadFailsClosedOnRepositoryErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wantCode string
		inject   func(*publicCAFailurePlan, transitionCA, transitionCA, error)
	}{
		{
			name:     "certificate read",
			wantCode: "query_public_ca_certificate_read_failed",
			inject: func(plan *publicCAFailurePlan, _, intermediate transitionCA, err error) {
				plan.certificateErrID, plan.certificateErr = intermediate.certID, err
			},
		},
		{
			name:     "CA certificate record read",
			wantCode: "query_public_ca_record_read_failed",
			inject: func(plan *publicCAFailurePlan, _, intermediate transitionCA, err error) {
				plan.recordErrID, plan.recordErr = intermediate.certID, err
			},
		},
		{
			name:     "key generation read",
			wantCode: "query_public_ca_generation_read_failed",
			inject: func(plan *publicCAFailurePlan, _, intermediate transitionCA, err error) {
				plan.generationErrID, plan.generationErr = intermediate.keyGenID, err
			},
		},
		{
			name:     "authority read",
			wantCode: "query_public_ca_authority_read_failed",
			inject: func(plan *publicCAFailurePlan, _, intermediate transitionCA, err error) {
				plan.authorityErrID, plan.authorityErr = intermediate.authorityID, err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, root, intermediate := publicCAFailureFixture(t)
			plan := publicCAFailurePlan{}
			tc.inject(&plan, root, intermediate, errors.New("injected repository read failure"))
			svc := publicCAQueryService(t, f, &publicCAFailureReadStore{ReadStore: f.store, plan: plan}, f.store)
			view, err := svc.ReadPublicCACertificate(context.Background(), anonymousPublicCARequest(),
				contract.PublicCACertificateQuery{CertificateID: intermediate.certID})
			assertPublicCAFailure(t, err, contract.ErrorKindUnavailable, tc.wantCode)
			if view.Certificate.ID() != "" || len(view.ChainDER) != 0 {
				t.Fatalf("repository failure returned partial certificate material: %+v", view)
			}
		})
	}
}

func TestPublicCAReadRejectsInvalidPersistedLineage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wantCode string
		prepare  func(*testing.T, *queryFixture, transitionCA, transitionCA, *publicCAFailurePlan)
	}{
		{
			name:     "target certificate record points at another certificate",
			wantCode: "public_ca_record_mismatch",
			prepare: func(_ *testing.T, _ *queryFixture, root, intermediate transitionCA, plan *publicCAFailurePlan) {
				plan.mutateRecordID = intermediate.certID
				plan.mutateRecord = func(record port.CACertificateRecord) (port.CACertificateRecord, error) {
					record.CertificateID = root.certID
					return record, nil
				}
			},
		},
		{
			name:     "target generation belongs to a non-visible authority",
			wantCode: "not_found",
			prepare: func(t *testing.T, f *queryFixture, _, intermediate transitionCA, plan *publicCAFailurePlan) {
				otherAuthority := mustID(t, f.ids, domain.ParseAuthorityID)
				plan.mutateGenerationID = intermediate.keyGenID
				plan.mutateGeneration = func(generation port.CAKeyGeneration) port.CAKeyGeneration {
					generation.AuthorityID = otherAuthority
					return generation
				}
			},
		},
		{
			name:     "target authority projection disagrees with generation owner",
			wantCode: "public_ca_authority_mismatch",
			prepare: func(_ *testing.T, _ *queryFixture, _, intermediate transitionCA, plan *publicCAFailurePlan) {
				plan.authorityMismatchID = intermediate.authorityID
			},
		},
		{
			name:     "intermediate record has no issuer",
			wantCode: "public_ca_issuer_missing",
			prepare: func(_ *testing.T, _ *queryFixture, _, intermediate transitionCA, plan *publicCAFailurePlan) {
				plan.mutateRecordID = intermediate.certID
				plan.mutateRecord = func(record port.CACertificateRecord) (port.CACertificateRecord, error) {
					record.IssuerCACertificateID = ""
					return record, nil
				}
			},
		},
		{
			name:     "issuer certificate is missing",
			wantCode: "public_ca_issuer_missing",
			prepare: func(_ *testing.T, _ *queryFixture, root, _ transitionCA, plan *publicCAFailurePlan) {
				plan.certificateErrID, plan.certificateErr = root.certID, port.ErrNotFound
			},
		},
		{
			name:     "issuer record is missing",
			wantCode: "public_ca_issuer_record_missing",
			prepare: func(_ *testing.T, _ *queryFixture, root, _ transitionCA, plan *publicCAFailurePlan) {
				plan.recordErrID, plan.recordErr = root.certID, port.ErrNotFound
			},
		},
		{
			name:     "issuer certificate record disagrees with its signing generation",
			wantCode: "public_ca_issuer_generation_mismatch",
			prepare: func(t *testing.T, f *queryFixture, root, _ transitionCA, plan *publicCAFailurePlan) {
				otherRootGeneration, _ := seedRootKeyGeneration(t, f.store, f.ids, root.authorityID, 2, "bd21", f.now, domain.Instant{})
				plan.mutateRecordID = root.certID
				plan.mutateRecord = func(record port.CACertificateRecord) (port.CACertificateRecord, error) {
					record.CAKeyGenerationID = otherRootGeneration
					return record, nil
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, root, intermediate := publicCAFailureFixture(t)
			plan := publicCAFailurePlan{}
			tc.prepare(t, f, root, intermediate, &plan)
			svc := publicCAQueryService(t, f, &publicCAFailureReadStore{ReadStore: f.store, plan: plan}, f.store)
			view, err := svc.ReadPublicCACertificate(context.Background(), anonymousPublicCARequest(),
				contract.PublicCACertificateQuery{CertificateID: intermediate.certID})
			wantKind := contract.ErrorKindUnavailable
			if tc.wantCode == "not_found" {
				wantKind = contract.ErrorKindValidation
			}
			assertPublicCAFailure(t, err, wantKind, tc.wantCode)
			if view.Certificate.ID() != "" || len(view.ChainDER) != 0 {
				t.Fatalf("corrupt lineage returned partial certificate material: %+v", view)
			}
		})
	}
}

func TestPublicCAReadRequiresAuthorizationAndKeepsUnknownIssuerPrivate(t *testing.T) {
	t.Run("authorization denial", func(t *testing.T) {
		f, _, intermediate := publicCAFailureFixture(t)
		f.authorizer.deny = map[port.Action]bool{port.ActionQueryReadPublicCA: true}
		svc := publicCAQueryService(t, f, f.store, f.store)
		_, err := svc.ReadPublicCACertificate(context.Background(), anonymousPublicCARequest(),
			contract.PublicCACertificateQuery{CertificateID: intermediate.certID})
		assertPublicCAFailure(t, err, contract.ErrorKindForbidden, "denied_for_test")
	})

	t.Run("missing target generation", func(t *testing.T) {
		f, _, intermediate := publicCAFailureFixture(t)
		plan := publicCAFailurePlan{generationErrID: intermediate.keyGenID, generationErr: port.ErrNotFound}
		svc := publicCAQueryService(t, f, &publicCAFailureReadStore{ReadStore: f.store, plan: plan}, f.store)
		view, err := svc.ReadPublicCACertificate(context.Background(), anonymousPublicCARequest(),
			contract.PublicCACertificateQuery{CertificateID: intermediate.certID})
		assertPublicCAFailure(t, err, contract.ErrorKindUnavailable, "public_ca_generation_missing")
		if view.Certificate.ID() != "" || len(view.ChainDER) != 0 {
			t.Fatalf("missing generation returned partial certificate material: %+v", view)
		}
	})
}

func publicCAFailureFixture(t *testing.T) (*queryFixture, transitionCA, transitionCA) {
	t.Helper()
	f := newQueryFixture(t)
	root := transitionCA{authorityID: f.authorityID, certID: f.caCertID, keyGenID: f.caKeyGenID}
	intermediate := seedTransitionIntermediate(t, f.store, f.ids, root, f.now, "bd11", true)
	return f, root, intermediate
}

func anonymousPublicCARequest() contract.RequestMeta {
	return contract.RequestMeta{Principal: contract.AnonymousPrincipal()}
}

func assertPublicCAFailure(t *testing.T, err error, kind contract.ErrorKind, code string) {
	t.Helper()
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != kind || appErr.Code() != code {
		t.Fatalf("error = %v, want %s/%s", err, kind, code)
	}
}

type publicCAFailurePlan struct {
	certificateErrID    domain.CertificateID
	certificateErr      error
	recordErrID         domain.CertificateID
	recordErr           error
	generationErrID     domain.CAKeyGenerationID
	generationErr       error
	mutateGenerationID  domain.CAKeyGenerationID
	mutateGeneration    func(port.CAKeyGeneration) port.CAKeyGeneration
	authorityErrID      domain.AuthorityID
	authorityErr        error
	authorityMismatchID domain.AuthorityID
	mutateRecordID      domain.CertificateID
	mutateRecord        func(port.CACertificateRecord) (port.CACertificateRecord, error)
}

type publicCAFailureReadStore struct {
	port.ReadStore
	plan publicCAFailurePlan
}

func (s *publicCAFailureReadStore) Read(ctx context.Context, callback func(port.TxStores) error) error {
	return s.ReadStore.Read(ctx, func(tx port.TxStores) error {
		return callback(publicCAFailureTxStores{
			TxStores: tx,
			pki:      publicCAFailurePKIRepository{PKIRepository: tx.PKI(), plan: s.plan},
			queries:  publicCAFailureQueryRepository{QueryRepository: tx.Queries(), plan: s.plan},
		})
	})
}

type publicCAFailureTxStores struct {
	port.TxStores
	pki     port.PKIRepository
	queries port.QueryRepository
}

func (tx publicCAFailureTxStores) PKI() port.PKIRepository       { return tx.pki }
func (tx publicCAFailureTxStores) Queries() port.QueryRepository { return tx.queries }

type publicCAFailurePKIRepository struct {
	port.PKIRepository
	plan publicCAFailurePlan
}

func (r publicCAFailurePKIRepository) GetCertificate(ctx context.Context, id domain.CertificateID) (domain.Certificate, error) {
	if id == r.plan.certificateErrID && r.plan.certificateErr != nil {
		return domain.Certificate{}, r.plan.certificateErr
	}
	return r.PKIRepository.GetCertificate(ctx, id)
}

func (r publicCAFailurePKIRepository) GetCACertificateRecord(ctx context.Context, id domain.CertificateID) (port.CACertificateRecord, error) {
	if id == r.plan.recordErrID && r.plan.recordErr != nil {
		return port.CACertificateRecord{}, r.plan.recordErr
	}
	record, err := r.PKIRepository.GetCACertificateRecord(ctx, id)
	if err != nil || id != r.plan.mutateRecordID || r.plan.mutateRecord == nil {
		return record, err
	}
	return r.plan.mutateRecord(record)
}

func (r publicCAFailurePKIRepository) GetCAKeyGeneration(ctx context.Context, id domain.CAKeyGenerationID) (port.CAKeyGeneration, error) {
	if id == r.plan.generationErrID && r.plan.generationErr != nil {
		return port.CAKeyGeneration{}, r.plan.generationErr
	}
	generation, err := r.PKIRepository.GetCAKeyGeneration(ctx, id)
	if err == nil && id == r.plan.mutateGenerationID && r.plan.mutateGeneration != nil {
		generation = r.plan.mutateGeneration(generation)
	}
	return generation, err
}

type publicCAFailureQueryRepository struct {
	port.QueryRepository
	plan publicCAFailurePlan
}

func (r publicCAFailureQueryRepository) GetAuthority(ctx context.Context, id domain.AuthorityID, scope port.QueryScope) (port.QueriedAuthority, error) {
	if id == r.plan.authorityErrID && r.plan.authorityErr != nil {
		return port.QueriedAuthority{}, r.plan.authorityErr
	}
	if id == r.plan.authorityMismatchID {
		return port.QueriedAuthority{}, nil
	}
	return r.QueryRepository.GetAuthority(ctx, id, scope)
}
