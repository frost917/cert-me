// Package port declares the consumer-side interfaces internal/app depends on.
// Storage, crypto, TLS and runtime adapters implement these; nothing in this
// package imports internal/app.
package port

import (
	"context"
)

// UnitOfWork opens the single write transaction a service method is allowed to
// use. Repository methods never open or commit a transaction of their own.
//
// Contract for implementations:
//   - The callback receives TxStores bound to one transaction; writes made
//     through any other handle are not part of it.
//   - A non-nil callback error rolls back every change.
//   - A callback panic rolls back and then repanics, so runtime error handling
//     still sees it.
//   - The callback is never re-run automatically. A service that wants a retry
//     redoes its whole preparation, at most three times, and only for a clean
//     rollback before any external effect.
//   - When the commit outcome cannot be determined, Write returns an error of
//     kind commit_unknown and the caller must not release a result.
type UnitOfWork interface {
	Write(context.Context, func(TxStores) error) error
}

// ReadStore is the read-snapshot side. Results read through it are preparation
// input only and never authorize a commit; a service re-reads the facts it
// depends on inside Write.
type ReadStore interface {
	Read(context.Context, func(TxStores) error) error
}

// RuntimeGate closes the process to new work when a private-key transfer
// cannot be resolved safely.
type RuntimeGate interface {
	// FailClosed is idempotent and must not wait for the caller. It atomically
	// shuts new requests and worker admission first and then asks the runtime
	// to terminate; it never blocks on the caller's own completion.
	FailClosed(code string)
}

// TxStores is the set of repositories bound to one open transaction.
type TxStores interface {
	Accounts() AccountRepository
	Installation() InstallationRepository
	PKI() PKIRepository
	Delivery() DeliveryRepository
	Revocations() RevocationRepository
	CRLs() CRLRepository
	Transitions() TransitionRepository
	TLS() TLSRepository
	Requests() RequestRepository
	Secrets() SecretRepository
	Jobs() JobRepository
	Maintenance() MaintenanceRepository
	Audit() AuditRepository
	// Imports is not in §4's original table -- it was added by §13's closing
	// paragraph, which named import batch/takeover storage as a contract
	// gap: "계약 완결성 검토에는 ... import batch/takeover 저장·조회 ...
	// 포함한다." §13's governing rule is explicit that §4's table is not a
	// ceiling on TxStores' methods.
	Imports() ImportRepository
	// Queries is the non-locking read side QueryService needs, added for the
	// same reason and under the same §13 ruling as Imports: "범용 raw SQL
	// 우회 대신 소비 서비스가 필요한 typed port를 추가한다". See queries.go
	// for why the paged/filtered/scoped reads are a separate interface from
	// the write path's GetXForUpdate.
	Queries() QueryRepository
}
