package service

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

func TestQueryServiceReadPublicCACertificateUsesImmutableCertificateIDAndStoredChain(t *testing.T) {
	f := newQueryFixture(t)
	root := transitionCA{authorityID: f.authorityID, certID: f.caCertID, keyGenID: f.caKeyGenID}
	intermediate := seedTransitionIntermediate(t, f.store, f.ids, root, f.now, "bb01", true)
	oldRoot := publicCAReadCertificate(t, f.store, root.certID)
	intermediateCertificate := publicCAReadCertificate(t, f.store, intermediate.certID)

	newRootKeyGeneration, newRootCertificate := seedRootKeyGeneration(t, f.store, f.ids,
		root.authorityID, 2, "bb02", f.now, domain.Instant{})
	publicCARotateAuthorityPointer(t, f.store, root.authorityID, newRootKeyGeneration, newRootCertificate)

	reads := &publicCAReadCounter{ReadStore: f.store}
	unit := &publicCANoWriteUnitOfWork{UnitOfWork: f.store}
	svc := publicCAQueryService(t, f, reads, unit)
	meta := contract.RequestMeta{Principal: contract.AnonymousPrincipal()}
	ctx := context.Background()

	view, err := svc.ReadPublicCACertificate(ctx, meta, contract.PublicCACertificateQuery{CertificateID: intermediate.certID})
	if err != nil {
		t.Fatalf("ReadPublicCACertificate(intermediate): %v", err)
	}
	if view.Certificate.ID() != intermediate.certID || !bytes.Equal(view.Certificate.DER(), intermediateCertificate.DER()) {
		t.Fatalf("target certificate = %q, want immutable intermediate %q", view.Certificate.ID(), intermediate.certID)
	}
	if len(view.ChainDER) != 2 || !bytes.Equal(view.ChainDER[0], intermediateCertificate.DER()) || !bytes.Equal(view.ChainDER[1], oldRoot.DER()) {
		t.Fatalf("chain DER = %q, want target then stored old Root", view.ChainDER)
	}
	if reads.reads != 1 {
		t.Fatalf("ReadStore calls = %d, want one read snapshot", reads.reads)
	}
	if unit.writes != 0 {
		t.Fatalf("UnitOfWork writes = %d, public certificate query must be read-only", unit.writes)
	}
	if got := f.authorizer.lastAction(); got != port.ActionQueryReadPublicCA {
		t.Fatalf("last authorization action = %q, want %q", got, port.ActionQueryReadPublicCA)
	}

	oldRootView, err := svc.ReadPublicCACertificate(ctx, meta, contract.PublicCACertificateQuery{CertificateID: root.certID})
	if err != nil {
		t.Fatalf("ReadPublicCACertificate(old Root): %v", err)
	}
	if oldRootView.Certificate.ID() != root.certID || !bytes.Equal(oldRootView.Certificate.DER(), oldRoot.DER()) {
		t.Fatalf("old certificate URL resolved to %q, want retained certificate %q", oldRootView.Certificate.ID(), root.certID)
	}
	if len(oldRootView.ChainDER) != 1 || !bytes.Equal(oldRootView.ChainDER[0], oldRoot.DER()) {
		t.Fatalf("old Root chain = %q, want its own immutable DER", oldRootView.ChainDER)
	}
}

func TestQueryServiceReadPublicCACertificateHidesUnknownLeafAndBootstrapCertificates(t *testing.T) {
	f := newQueryFixture(t)
	bootstrapID := seedPublicCABootstrap(t, f)
	unknownID := mustID(t, f.ids, domain.ParseCertificateID)
	meta := contract.RequestMeta{Principal: contract.AnonymousPrincipal()}

	for _, tt := range []struct {
		name string
		id   domain.CertificateID
	}{
		{name: "unknown certificate", id: unknownID},
		{name: "Leaf certificate", id: f.leafCertID},
		{name: "bootstrap CA certificate", id: bootstrapID},
	} {
		t.Run(tt.name, func(t *testing.T) {
			view, err := f.svc.ReadPublicCACertificate(context.Background(), meta,
				contract.PublicCACertificateQuery{CertificateID: tt.id})
			assertPublicCANotFound(t, err)
			if view.Certificate.ID() != "" || len(view.ChainDER) != 0 {
				t.Fatalf("not-found result contains public material: certificate=%q chain length=%d", view.Certificate.ID(), len(view.ChainDER))
			}
		})
	}
}

func TestQueryServiceReadPublicCACertificateRejectsCorruptStoredIssuerChains(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(transitionCA, transitionCA, port.CACertificateRecord) (port.CACertificateRecord, error)
	}{
		{
			name: "cycle",
			mutate: func(_, _ transitionCA, record port.CACertificateRecord) (port.CACertificateRecord, error) {
				record.IssuerCACertificateID = record.CertificateID
				return record, nil
			},
		},
		{
			name: "missing issuer record",
			mutate: func(_, _ transitionCA, _ port.CACertificateRecord) (port.CACertificateRecord, error) {
				return port.CACertificateRecord{}, port.ErrNotFound
			},
		},
		{
			name: "issuer signer generation mismatch",
			mutate: func(_, intermediate transitionCA, record port.CACertificateRecord) (port.CACertificateRecord, error) {
				record.CAKeyGenerationID = intermediate.keyGenID
				return record, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newQueryFixture(t)
			root := transitionCA{authorityID: f.authorityID, certID: f.caCertID, keyGenID: f.caKeyGenID}
			intermediate := seedTransitionIntermediate(t, f.store, f.ids, root, f.now, "bc01", true)
			readStore := &publicCACorruptRecordReadStore{
				ReadStore: f.store,
				target:    root.certID,
				mutate: func(record port.CACertificateRecord) (port.CACertificateRecord, error) {
					return tt.mutate(root, intermediate, record)
				},
			}
			svc := publicCAQueryService(t, f, readStore, &publicCANoWriteUnitOfWork{UnitOfWork: f.store})
			view, err := svc.ReadPublicCACertificate(context.Background(),
				contract.RequestMeta{Principal: contract.AnonymousPrincipal()},
				contract.PublicCACertificateQuery{CertificateID: intermediate.certID})
			if err == nil {
				t.Fatalf("corrupt stored chain unexpectedly succeeded with %d certificates", len(view.ChainDER))
			}
			if view.Certificate.ID() != "" || len(view.ChainDER) != 0 {
				t.Fatalf("corrupt chain returned partial material: certificate=%q chain length=%d", view.Certificate.ID(), len(view.ChainDER))
			}
		})
	}
}

func publicCAQueryService(t *testing.T, f *queryFixture, readStore port.ReadStore, unit port.UnitOfWork) *QueryService {
	t.Helper()
	if readStore == nil {
		readStore = f.store
	}
	if unit == nil {
		unit = f.store
	}
	svc, err := NewQueryService(CommonDeps{
		UnitOfWork: unit,
		ReadStore:  readStore,
		Authorizer: f.authorizer,
		Clock:      f.clock,
		IDs:        f.ids,
	})
	if err != nil {
		t.Fatalf("NewQueryService: %v", err)
	}
	return svc
}

func publicCAReadCertificate(t *testing.T, store *porttest.Store, id domain.CertificateID) domain.Certificate {
	t.Helper()
	var certificate domain.Certificate
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		certificate, err = tx.PKI().GetCertificate(context.Background(), id)
		return err
	})
	if err != nil {
		t.Fatalf("read certificate %q: %v", id, err)
	}
	return certificate
}

func publicCARotateAuthorityPointer(t *testing.T, store *porttest.Store, authorityID domain.AuthorityID, keyGenerationID domain.CAKeyGenerationID, certificateID domain.CertificateID) {
	t.Helper()
	ctx := context.Background()
	var current domain.Authority
	if err := store.Read(ctx, func(tx port.TxStores) error {
		queried, err := tx.Queries().GetAuthority(ctx, authorityID, port.QueryScope{All: true})
		current = queried.Authority
		return err
	}); err != nil {
		t.Fatalf("read authority before rotation: %v", err)
	}
	next, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                    current.ID(),
		Kind:                  current.Kind(),
		Name:                  current.Name(),
		ManagementParentID:    current.ManagementParentID(),
		IssuanceState:         current.IssuanceState(),
		IssuanceCertificateID: certificateID,
		KeyGenerationID:       keyGenerationID,
		KeyAvailable:          current.KeyAvailable(),
		Affected:              current.Affected(),
		PendingTakeover:       current.PendingTakeover(),
		CertificateWindow:     current.CertificateWindow(),
		ArchivedAt:            current.ArchivedAt(),
		Version:               current.Version().Next(),
	})
	if err != nil {
		t.Fatalf("build rotated authority: %v", err)
	}
	if err := store.Write(ctx, func(tx port.TxStores) error {
		return tx.PKI().SaveAuthority(ctx, next, current.Version())
	}); err != nil {
		t.Fatalf("rotate authority issuance certificate pointer: %v", err)
	}
}

func seedPublicCABootstrap(t *testing.T, f *queryFixture) domain.CertificateID {
	t.Helper()
	ctx := context.Background()
	authorityID := mustID(t, f.ids, domain.ParseAuthorityID)
	keyGenerationID := mustID(t, f.ids, domain.ParseCAKeyGenerationID)
	keyMaterialID := mustID(t, f.ids, domain.ParseKeyMaterialID)
	certificateID := mustID(t, f.ids, domain.ParseCertificateID)
	publicKey, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte("bootstrap-public-key-"+string(keyGenerationID)))
	if err != nil {
		t.Fatalf("bootstrap public key: %v", err)
	}
	window, err := domain.NewValidityWindow(f.now.Add(domain.NewDuration(-time.Hour)), f.now.Add(domain.NewDuration(24*365*5*time.Hour)))
	if err != nil {
		t.Fatalf("bootstrap certificate window: %v", err)
	}
	subject, err := domain.NewSubject(domain.SubjectFacts{CommonName: "Internal Bootstrap CA"})
	if err != nil {
		t.Fatalf("bootstrap subject: %v", err)
	}
	certificate, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certificateID,
		DER:                     []byte("bootstrap-certificate-der"),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: keyGenerationID,
		Serial:                  serial(t, "bd01"),
		Validity:                window,
		Subject:                 subject,
		Kind:                    domain.CertificateKindCA,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
	})
	if err != nil {
		t.Fatalf("bootstrap certificate: %v", err)
	}
	authority, err := domain.NewAuthority(domain.AuthorityFacts{
		ID:                    authorityID,
		Kind:                  domain.AuthorityKindBootstrap,
		Name:                  "Internal Bootstrap CA",
		IssuanceState:         domain.IssuanceStateStopped,
		IssuanceCertificateID: certificateID,
		KeyGenerationID:       keyGenerationID,
		KeyAvailable:          false,
		CertificateWindow:     window,
	})
	if err != nil {
		t.Fatalf("bootstrap authority: %v", err)
	}
	if err := f.store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{ID: keyMaterialID, PublicKey: publicKey, Origin: "generated"}); err != nil {
			return err
		}
		if err := tx.PKI().InsertKeyGeneration(ctx, port.CAKeyGeneration{
			ID: keyGenerationID, AuthorityID: authorityID, KeyMaterialID: keyMaterialID, GenerationNo: 1,
		}); err != nil {
			return err
		}
		if err := tx.PKI().InsertCertificate(ctx, certificate); err != nil {
			return err
		}
		if err := tx.PKI().InsertCACertificateRecord(ctx, port.CACertificateRecord{
			CertificateID: certificateID, CAKeyGenerationID: keyGenerationID,
		}); err != nil {
			return err
		}
		return tx.PKI().InsertAuthority(ctx, authority)
	}); err != nil {
		t.Fatalf("seed bootstrap CA: %v", err)
	}
	return certificateID
}

func assertPublicCANotFound(t *testing.T, err error) {
	t.Helper()
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Code() != "not_found" {
		t.Fatalf("error = %v, want not_found AppError", err)
	}
}

type publicCAReadCounter struct {
	port.ReadStore
	reads int
}

func (s *publicCAReadCounter) Read(ctx context.Context, callback func(port.TxStores) error) error {
	s.reads++
	return s.ReadStore.Read(ctx, callback)
}

type publicCANoWriteUnitOfWork struct {
	port.UnitOfWork
	writes int
}

func (u *publicCANoWriteUnitOfWork) Write(context.Context, func(port.TxStores) error) error {
	u.writes++
	return errors.New("unexpected public CA query write")
}

type publicCACorruptRecordReadStore struct {
	port.ReadStore
	target domain.CertificateID
	mutate func(port.CACertificateRecord) (port.CACertificateRecord, error)
}

func (s *publicCACorruptRecordReadStore) Read(ctx context.Context, callback func(port.TxStores) error) error {
	return s.ReadStore.Read(ctx, func(tx port.TxStores) error {
		pki := &publicCACorruptRecordRepository{PKIRepository: tx.PKI(), target: s.target, mutate: s.mutate}
		return callback(publicCACorruptRecordTx{TxStores: tx, pki: pki})
	})
}

type publicCACorruptRecordTx struct {
	port.TxStores
	pki port.PKIRepository
}

func (tx publicCACorruptRecordTx) PKI() port.PKIRepository { return tx.pki }

type publicCACorruptRecordRepository struct {
	port.PKIRepository
	target domain.CertificateID
	mutate func(port.CACertificateRecord) (port.CACertificateRecord, error)
}

func (r *publicCACorruptRecordRepository) GetCACertificateRecord(ctx context.Context, id domain.CertificateID) (port.CACertificateRecord, error) {
	record, err := r.PKIRepository.GetCACertificateRecord(ctx, id)
	if err != nil || id != r.target {
		return record, err
	}
	return r.mutate(record)
}
