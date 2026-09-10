package port_test

// Tests for docs/backend-implementation.md §13 ruling 5: every named Query
// List/Get action plus GetCRLStatus/ReadPublicCA exists and validates, no
// single-audit-get action exists, TLS.Bootstrap/TLS.Reconcile exist as
// separate internal-only actions paired one-to-one with their matching
// contract.InternalOperation, and Action.Validate rejects anything outside
// the defined set.

import (
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
)

// ruledActions is every action ruling 5 names explicitly.
var ruledActions = []port.Action{
	port.ActionQueryListAuthority, port.ActionQueryGetAuthority,
	port.ActionQueryListSeries, port.ActionQueryGetSeries,
	port.ActionQueryListCertificate, port.ActionQueryGetCertificate,
	port.ActionQueryListRevocation, port.ActionQueryGetRevocation,
	port.ActionQueryListTransition, port.ActionQueryGetTransition,
	port.ActionQueryListImport, port.ActionQueryGetImport,
	port.ActionQueryListJob, port.ActionQueryGetJob,
	port.ActionQueryListAudit, port.ActionQueryExportAudit,
	port.ActionQueryGetCRLStatus, port.ActionQueryReadPublicCA,
	port.ActionTLSBootstrap, port.ActionTLSReconcile,
}

func TestRuledActions_AllExistAndValidate(t *testing.T) {
	for _, a := range ruledActions {
		t.Run(string(a), func(t *testing.T) {
			if a == "" {
				t.Fatalf("action constant is empty")
			}
			if err := a.Validate(); err != nil {
				t.Fatalf("Validate(%q): %v", a, err)
			}
		})
	}
}

// TestRuledActions_NoSingleAuditGetAction pins ruling 5's explicit negative:
// "실제 API에 없는 단일 Audit 조회는 신설하지 않는다". Audit gets
// ListAudit/ExportAudit, not a Get-style single-item read; a hypothetical
// "Query.GetAudit" must not be a defined action.
func TestRuledActions_NoSingleAuditGetAction(t *testing.T) {
	if err := port.Action("Query.GetAudit").Validate(); err == nil {
		t.Fatalf("Query.GetAudit must not be a defined action -- ruling 5 explicitly does not add one")
	}
}

// TestAction_UndefinedActionIsRejected confirms Validate's existing
// default-deny behavior, which is what ruling 5's closing sentence
// ("미정의 Action은 거부한다") relies on rather than needing new code.
func TestAction_UndefinedActionIsRejected(t *testing.T) {
	for _, a := range []port.Action{"", "Nonsense.Action", "Query.Get Authority"} {
		if err := a.Validate(); err == nil {
			t.Fatalf("Validate(%q) must reject an undefined action", a)
		}
	}
}

// TestTLSActions_PairWithTheirOwnInternalOperationOnly proves the pairing
// ruling 5 requires ("대응 내부 operation만 허용한다"): an internal
// principal minted for InternalOperationTLSBootstrap can exercise
// ActionTLSBootstrap but not ActionTLSReconcile, and vice versa. It goes
// through the real contract.InternalPrincipalFactory/Principal.Can, not a
// hand-rolled stand-in, so it exercises the actual objects an Authorizer
// implementation would check.
func TestTLSActions_PairWithTheirOwnInternalOperationOnly(t *testing.T) {
	bootstrapOp, ok := port.ActionTLSBootstrap.RequiredInternalOperation()
	if !ok {
		t.Fatalf("ActionTLSBootstrap has no paired InternalOperation")
	}
	reconcileOp, ok := port.ActionTLSReconcile.RequiredInternalOperation()
	if !ok {
		t.Fatalf("ActionTLSReconcile has no paired InternalOperation")
	}
	if bootstrapOp != contract.InternalOperationTLSBootstrap {
		t.Fatalf("ActionTLSBootstrap paired to %q, want %q", bootstrapOp, contract.InternalOperationTLSBootstrap)
	}
	if reconcileOp != contract.InternalOperationTLSReconcile {
		t.Fatalf("ActionTLSReconcile paired to %q, want %q", reconcileOp, contract.InternalOperationTLSReconcile)
	}
	if bootstrapOp == reconcileOp {
		t.Fatalf("ActionTLSBootstrap and ActionTLSReconcile must not share one InternalOperation")
	}

	bootstrapFactory, err := contract.NewInternalPrincipalFactory(contract.InternalOperationTLSBootstrap)
	if err != nil {
		t.Fatalf("NewInternalPrincipalFactory(bootstrap): %v", err)
	}
	bootstrapPrincipal, err := bootstrapFactory.Principal(contract.InternalOperationTLSBootstrap)
	if err != nil {
		t.Fatalf("Principal(bootstrap): %v", err)
	}
	if !bootstrapPrincipal.Can(bootstrapOp) {
		t.Fatalf("a principal minted for InternalOperationTLSBootstrap cannot exercise ActionTLSBootstrap's own paired operation")
	}
	if bootstrapPrincipal.Can(reconcileOp) {
		t.Fatalf("a principal minted only for InternalOperationTLSBootstrap must not be able to exercise ActionTLSReconcile's paired operation")
	}

	reconcileFactory, err := contract.NewInternalPrincipalFactory(contract.InternalOperationTLSReconcile)
	if err != nil {
		t.Fatalf("NewInternalPrincipalFactory(reconcile): %v", err)
	}
	reconcilePrincipal, err := reconcileFactory.Principal(contract.InternalOperationTLSReconcile)
	if err != nil {
		t.Fatalf("Principal(reconcile): %v", err)
	}
	if !reconcilePrincipal.Can(reconcileOp) {
		t.Fatalf("a principal minted for InternalOperationTLSReconcile cannot exercise ActionTLSReconcile's own paired operation")
	}
	if reconcilePrincipal.Can(bootstrapOp) {
		t.Fatalf("a principal minted only for InternalOperationTLSReconcile must not be able to exercise ActionTLSBootstrap's paired operation")
	}
}

// TestAction_NonInternalActionHasNoPairedOperation spot-checks that an
// ordinary (non-TLS-internal) action is simply unpaired, not accidentally
// paired to something.
func TestAction_NonInternalActionHasNoPairedOperation(t *testing.T) {
	if _, ok := port.ActionQueryGetAuthority.RequiredInternalOperation(); ok {
		t.Fatalf("Query.GetAuthority must not be paired to an InternalOperation")
	}
}
