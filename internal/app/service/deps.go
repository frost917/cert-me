// Package service holds the application services
// (docs/backend-implementation.md §5 "서비스 조립과 의존성"). A service owns
// one operation's orchestration: it prepares outside the transaction, opens
// exactly one port.UnitOfWork.Write, and re-checks inside that write every
// fact the commit depends on.
//
// Nothing here opens a transaction of its own below the service method, and
// no service hands a repository handle, port.UnitOfWork or SecretRepository
// out to an adapter (§5 "핸들러에 Db/SecretRepository를 직접 전달하지
// 않는다").
package service

import (
	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
)

// CommonDeps is the dependency set every service shares
// (docs/backend-implementation.md §5 "공통 의존성은 UoW, ReadStore,
// Authorizer, Clock, IDGenerator이며 서비스별로 필요한 것만 XDeps에 둔다").
// Each concrete XDeps embeds this and adds only what its own table row
// names.
type CommonDeps struct {
	UnitOfWork port.UnitOfWork
	ReadStore  port.ReadStore
	Authorizer port.Authorizer
	Clock      port.Clock
	IDs        port.IDGenerator
}

// Validate reports the first missing common dependency. Construction fails
// at startup rather than at the first request (§5 "필수 의존성이 nil이면
// 시작 시 실패한다").
func (d CommonDeps) Validate() error {
	return firstMissing(
		required{"UnitOfWork", d.UnitOfWork == nil},
		required{"ReadStore", d.ReadStore == nil},
		required{"Authorizer", d.Authorizer == nil},
		required{"Clock", d.Clock == nil},
		required{"IDs", d.IDs == nil},
	)
}

// required names one dependency slot and whether it was left unset. The
// caller evaluates `x == nil` itself because a nil interface value stored
// in an `any` field would compare non-nil here.
type required struct {
	Name    string
	Missing bool
}

// firstMissing returns a startup error for the first unset dependency, in
// declaration order, so a misconfigured assembly reports a stable name
// instead of whichever map iteration happened to come first.
func firstMissing(deps ...required) error {
	for _, dep := range deps {
		if dep.Missing {
			return contract.NewAppError(
				contract.ErrorKindValidation,
				"service_dependency_missing",
				"a required service dependency is not configured",
			).WithField("dependency", dep.Name)
		}
	}
	return nil
}
