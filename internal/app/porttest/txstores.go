package porttest

import "cert-me/internal/app/port"

// txStores binds all twelve repositories to one working *state clone. A
// txStores value is only ever handed out by Store.Write/Store.Read, which
// already guarantee the *state it wraps is a private copy no one else can
// see (see state.go's package doc).
type txStores struct {
	s *state
}

var _ port.TxStores = (*txStores)(nil)

func (t *txStores) Accounts() port.AccountRepository          { return accountRepo{t.s} }
func (t *txStores) Installation() port.InstallationRepository { return installationRepo{t.s} }
func (t *txStores) PKI() port.PKIRepository                   { return pkiRepo{t.s} }
func (t *txStores) Delivery() port.DeliveryRepository         { return deliveryRepo{t.s} }
func (t *txStores) Revocations() port.RevocationRepository    { return revocationRepo{t.s} }
func (t *txStores) CRLs() port.CRLRepository                  { return crlRepo{t.s} }
func (t *txStores) Transitions() port.TransitionRepository    { return transitionRepo{t.s} }
func (t *txStores) TLS() port.TLSRepository                   { return tlsRepo{t.s} }
func (t *txStores) Requests() port.RequestRepository          { return requestRepo{t.s} }
func (t *txStores) Secrets() port.SecretRepository            { return secretRepo{t.s} }
func (t *txStores) Jobs() port.JobRepository                  { return jobRepo{t.s} }
func (t *txStores) Maintenance() port.MaintenanceRepository   { return maintenanceRepo{t.s} }
func (t *txStores) Audit() port.AuditRepository               { return auditRepo{t.s} }
func (t *txStores) Imports() port.ImportRepository            { return importRepo{t.s} }
func (t *txStores) Queries() port.QueryRepository             { return queryRepo{t.s} }
