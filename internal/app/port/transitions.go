package port

import (
	"context"

	"cert-me/internal/domain"
)

// TransitionRepository is the storage boundary for CA transitions, their
// per-certificate impacts and manual deployment confirmations
// (docs/backend-implementation.md §4 table row "TransitionRepository";
// docs/data-model.md "전환·외부 배포 확인").
type TransitionRepository interface {
	// GetForUpdate locks and returns the transition row.
	GetForUpdate(ctx context.Context, transitionID domain.TransitionID) (domain.Transition, error)

	// Insert creates a new transition row (Create: a normal or emergency CA
	// replacement report).
	Insert(ctx context.Context, transition domain.Transition) error

	// Save persists transition under the standard optimistic-lock contract
	// (see AccountRepository.SaveAccount).
	Save(ctx context.Context, transition domain.Transition, expectedVersion domain.Version) error

	// AddImpact records that a certificate is affected by transitionID.
	// TransitionImpact carries no version of its own (data-model.md's
	// (transition_id,certificate_id) PK/FK row has none), so recording it is
	// a plain insert rather than an optimistic-lock save.
	AddImpact(ctx context.Context, impact domain.TransitionImpact) error

	// LinkReplacement updates the existing impact row -- identified by
	// (impact.TransitionID(), impact.CertificateID()) -- to point at the
	// replacement certificate TransitionImpact.RecordReplacement produced.
	// It is a distinct method from AddImpact because it must target a row
	// that already exists rather than insert a new one, and because only a
	// resolved impact (IsResolved()) is ever passed to it: a failed reissue
	// attempt must not call this, leaving the impact pending
	// (docs/data-model.md "실패한 대체 발급은 인증서 계보에 남고 성공 대상
	// 포인터 갱신").
	LinkReplacement(ctx context.Context, impact domain.TransitionImpact) error

	// AddDeploymentConfirmation appends one manual confirmation row. Like
	// TransitionImpact, DeploymentConfirmation is an append-only fact with
	// no version -- confirmations are never edited or removed
	// (docs/backend-implementation.md §2 "수동 확인 보존").
	AddDeploymentConfirmation(ctx context.Context, confirmation domain.DeploymentConfirmation) error

	// ListImpacts returns every impact recorded under transitionID, used to
	// build TransitionClosureFacts.AllImpactsAddressed for Complete.
	ListImpacts(ctx context.Context, transitionID domain.TransitionID) ([]domain.TransitionImpact, error)

	// ListDeploymentConfirmations returns every confirmation recorded under
	// transitionID. Complete needs it for the other half of
	// TransitionClosureFacts: AllImpactsAddressed comes from ListImpacts,
	// and ManualDeploymentConfirmed comes from these rows
	// (domain.TransitionClosureFacts documents it as read "from the
	// confirmation rows").
	//
	// Added in B04 alongside the service that consumes it. Without it the
	// §13 ruling 1 wiring -- "Complete는 기존 영향 처리·수동 외부 배포 확인
	// 조건을 검사해 externally_completed로 옮긴다" -- has no way to read the
	// confirmations it is required to check, and the only alternative would
	// be for the service to assume a value it cannot observe. §13's closing
	// paragraph governs: "범용 raw SQL 우회 대신 소비 서비스가 필요한 typed
	// port를 추가한다."
	ListDeploymentConfirmations(ctx context.Context, transitionID domain.TransitionID) ([]domain.DeploymentConfirmation, error)
}
