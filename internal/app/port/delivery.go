package port

import (
	"context"

	"cert-me/internal/domain"
)

// DeliveryRepository is the storage boundary for one-shot private key
// custody (key_deliveries) and download links (download_tokens)
// (docs/backend-implementation.md §4 table row "DeliveryRepository";
// docs/data-model.md "일회성 수령·공개 다운로드").
type DeliveryRepository interface {
	// GetDeliveryForUpdate locks and returns the delivery row. Every
	// consume/fail/expire transition (Delivery.Consume/Fail/Expire) must run
	// against a row read this way inside the same commit that saves it.
	GetDeliveryForUpdate(ctx context.Context, deliveryID domain.DeliveryID) (domain.Delivery, error)

	// GetGrantForUpdate locks and returns the grant row by its token hash --
	// the plaintext token never reaches this layer
	// (docs/backend-implementation.md §6 TokenCodec).
	GetGrantForUpdate(ctx context.Context, tokenHash domain.TokenHash) (domain.DownloadGrant, error)

	// InsertDelivery creates the single delivery row a leaf key generation
	// ever gets (key_deliveries.leaf_key_generation_id UQ).
	InsertDelivery(ctx context.Context, delivery domain.Delivery) error

	// InsertGrant creates a new download link.
	InsertGrant(ctx context.Context, grant domain.DownloadGrant) error

	// SaveDelivery persists delivery under the standard optimistic-lock
	// contract (see AccountRepository.SaveAccount).
	SaveDelivery(ctx context.Context, delivery domain.Delivery, expectedVersion domain.Version) error

	// SaveGrant persists grant under the standard optimistic-lock contract.
	// The docs table lists this method without a parenthetical
	// "(expectedVersion)" the way SaveDelivery's entry has one, but
	// domain.DownloadGrant carries its own Version() and rule 3 requires
	// every Save to take expectedVersion, so this signature includes it too;
	// flagged as an interpretation of the terse table for the lead.
	SaveGrant(ctx context.Context, grant domain.DownloadGrant, expectedVersion domain.Version) error

	// InvalidatePrivateGrants invalidates every not-yet-consumed private
	// grant tied to deliveryID, used on link replacement and on delivery
	// failure/expiry cleanup (docs/data-model.md "다른 남은 private 토큰은
	// 모두 무효화"). Like InvalidateResetTokens, this is a bulk call whose
	// implementation still applies DownloadGrant.Invalidate's idempotent,
	// never-touch-a-consumed-grant rule per row.
	InvalidatePrivateGrants(ctx context.Context, deliveryID domain.DeliveryID, now domain.Instant) error

	// InvalidatePublicGrants invalidates every not-yet-consumed public grant
	// for certificateID, used when a public download link is replaced
	// (docs/certificate-lifecycle.md "같은 인증서의 새 공개 다운로드 링크를
	// 발급하면 기존 미사용 공개 다운로드 링크를 무효화").
	InvalidatePublicGrants(ctx context.Context, certificateID domain.CertificateID, now domain.Instant) error

	// ListExpired returns pending deliveries whose expires_at has passed as
	// of now, up to limit rows, for the once-a-minute expiry scan
	// (docs/backend-implementation.md §9 "수령 만료 스캔은 매분... 처리
	// batch는 100개").
	ListExpired(ctx context.Context, now domain.Instant, limit int) ([]domain.Delivery, error)

	// ListPending returns every delivery still waiting for receipt, regardless
	// of its deadline, up to limit rows. Restore finalization must use this
	// recovery-specific listing so an unexpired pending delivery cannot survive
	// merely because it is not yet eligible for the ordinary expiry sweep.
	ListPending(ctx context.Context, limit int) ([]domain.Delivery, error)

	// ListTransferring returns every delivery still in the transferring
	// state, the restart-recovery set that must be resolved to failed before
	// new download/issuance requests are allowed
	// (docs/backend-implementation.md §9 "초기 재시작 복구에서 transferring을
	// failed로 바꾸는 동안 다운로드/갱신 요청을 열지 않는다").
	ListTransferring(ctx context.Context, limit int) ([]domain.Delivery, error)

	// InvalidateAllPublicGrants invalidates every outstanding public download
	// grant in the restored snapshot. A restore can contain public links for
	// certificates whose delivery rows are not present in the local listing, so
	// this is intentionally global rather than certificate-scoped.
	InvalidateAllPublicGrants(ctx context.Context, now domain.Instant) error
}
