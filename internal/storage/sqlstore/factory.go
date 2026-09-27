// Package sqlstore assembles the transaction-bound SQL repositories used by
// the application.
package sqlstore

import (
	"errors"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/config"
	"cert-me/internal/storage/connection"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/delivery"
	"cert-me/internal/storage/sqlstore/dialect"
	"cert-me/internal/storage/sqlstore/identity"
	"cert-me/internal/storage/sqlstore/operations"
	"cert-me/internal/storage/sqlstore/pki"
	"cert-me/internal/storage/sqlstore/revocation"
	"cert-me/internal/storage/sqlstore/workflow"
)

// NewFactory returns a transaction repository factory for kind. Every call
// binds all repositories to the same executor supplied by core.Store.
func NewFactory(kind config.DatabaseKind) (core.Factory, error) {
	d, err := dialect.New(kind)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: %w", err)
	}
	return func(executor core.SQLExecutor) (port.TxStores, error) {
		return NewTxStores(executor, d)
	}, nil
}

// NewStore builds the transaction boundary and its complete repository
// factory for one already-open database connection set.
func NewStore(db *connection.DB, kind config.DatabaseKind) (*core.Store, error) {
	factory, err := NewFactory(kind)
	if err != nil {
		return nil, err
	}
	return core.New(db, kind, factory)
}

// NewTxStores assembles the complete application-facing repository set over
// executor. The returned value is valid only for the lifetime of the
// transaction represented by executor.
func NewTxStores(executor core.SQLExecutor, d dialect.Dialect) (port.TxStores, error) {
	if executor == nil {
		return nil, errors.New("sqlstore: SQL executor is required")
	}
	validated, err := dialect.New(d.Kind())
	if err != nil {
		return nil, fmt.Errorf("sqlstore: %w", err)
	}

	identityRepositories, err := identity.New(executor, validated)
	if err != nil {
		return nil, err
	}
	workflowRepositories, err := workflow.New(executor, validated)
	if err != nil {
		return nil, err
	}
	operationRepositories, err := operations.New(executor, validated)
	if err != nil {
		return nil, err
	}
	requestRepository, err := delivery.NewRequestRepository(executor, validated)
	if err != nil {
		return nil, err
	}
	secretRepository, err := delivery.NewSecretRepository(executor, validated)
	if err != nil {
		return nil, err
	}
	deliveryRepository, err := delivery.NewDeliveryRepository(executor, validated)
	if err != nil {
		return nil, err
	}
	revocationRepository, err := revocation.NewRevocationRepository(executor, validated)
	if err != nil {
		return nil, err
	}
	crlRepository, err := revocation.NewCRLRepository(executor, validated)
	if err != nil {
		return nil, err
	}

	return txStores{
		accounts:     identityRepositories.Accounts,
		installation: identityRepositories.Installation,
		pki:          pki.New(executor, validated),
		delivery:     deliveryRepository,
		revocations:  revocationRepository,
		crls:         crlRepository,
		transitions:  workflowRepositories.Transitions,
		tls:          operationRepositories.TLS,
		requests:     requestRepository,
		secrets:      secretRepository,
		jobs:         operationRepositories.Jobs,
		maintenance:  operationRepositories.Maintenance,
		audit:        operationRepositories.Audit,
		imports:      workflowRepositories.Imports,
		queries:      operationRepositories.Queries,
	}, nil
}

type txStores struct {
	accounts     port.AccountRepository
	installation port.InstallationRepository
	pki          port.PKIRepository
	delivery     port.DeliveryRepository
	revocations  port.RevocationRepository
	crls         port.CRLRepository
	transitions  port.TransitionRepository
	tls          port.TLSRepository
	requests     port.RequestRepository
	secrets      port.SecretRepository
	jobs         port.JobRepository
	maintenance  port.MaintenanceRepository
	audit        port.AuditRepository
	imports      port.ImportRepository
	queries      port.QueryRepository
}

func (s txStores) Accounts() port.AccountRepository          { return s.accounts }
func (s txStores) Installation() port.InstallationRepository { return s.installation }
func (s txStores) PKI() port.PKIRepository                   { return s.pki }
func (s txStores) Delivery() port.DeliveryRepository         { return s.delivery }
func (s txStores) Revocations() port.RevocationRepository    { return s.revocations }
func (s txStores) CRLs() port.CRLRepository                  { return s.crls }
func (s txStores) Transitions() port.TransitionRepository    { return s.transitions }
func (s txStores) TLS() port.TLSRepository                   { return s.tls }
func (s txStores) Requests() port.RequestRepository          { return s.requests }
func (s txStores) Secrets() port.SecretRepository            { return s.secrets }
func (s txStores) Jobs() port.JobRepository                  { return s.jobs }
func (s txStores) Maintenance() port.MaintenanceRepository   { return s.maintenance }
func (s txStores) Audit() port.AuditRepository               { return s.audit }
func (s txStores) Imports() port.ImportRepository            { return s.imports }
func (s txStores) Queries() port.QueryRepository             { return s.queries }

var _ port.TxStores = txStores{}
