package porttest

import (
	"context"
	"sort"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type deliveryRepo struct{ s *state }

var _ port.DeliveryRepository = deliveryRepo{}

func (r deliveryRepo) GetDeliveryForUpdate(_ context.Context, deliveryID domain.DeliveryID) (domain.Delivery, error) {
	d, ok := r.s.deliveries[deliveryID]
	if !ok {
		return domain.Delivery{}, port.ErrNotFound
	}
	return d, nil
}

// GetGrantForUpdate looks a grant up by token hash only. The double never
// stores a raw token, matching the rule that only the SHA-256 hash is
// persisted (docs/backend-implementation.md §6).
func (r deliveryRepo) GetGrantForUpdate(_ context.Context, tokenHash domain.TokenHash) (domain.DownloadGrant, error) {
	id, ok := r.s.grantsByHash[tokenHash.Hex()]
	if !ok {
		return domain.DownloadGrant{}, port.ErrNotFound
	}
	return r.s.grants[id], nil
}

func (r deliveryRepo) InsertDelivery(_ context.Context, delivery domain.Delivery) error {
	if _, ok := r.s.deliveries[delivery.ID()]; ok {
		return ErrDuplicate
	}
	r.s.deliveries[delivery.ID()] = delivery
	return nil
}

func (r deliveryRepo) InsertGrant(_ context.Context, grant domain.DownloadGrant) error {
	if _, ok := r.s.grants[grant.ID()]; ok {
		return ErrDuplicate
	}
	if _, ok := r.s.grantsByHash[grant.TokenHash().Hex()]; ok {
		return ErrDuplicate
	}
	r.s.grants[grant.ID()] = grant
	r.s.grantsByHash[grant.TokenHash().Hex()] = grant.ID()
	return nil
}

func (r deliveryRepo) SaveDelivery(_ context.Context, delivery domain.Delivery, expectedVersion domain.Version) error {
	existing, ok := r.s.deliveries[delivery.ID()]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.deliveries[delivery.ID()] = delivery
	return nil
}

func (r deliveryRepo) SaveGrant(_ context.Context, grant domain.DownloadGrant, expectedVersion domain.Version) error {
	existing, ok := r.s.grants[grant.ID()]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.grants[grant.ID()] = grant
	return nil
}

// InvalidatePrivateGrants kills every outstanding private link for one
// delivery at consumption time, so a second link issued earlier cannot still
// be redeemed (docs/backend-implementation.md §7 step 3: "전체 private grant
// 무효화"). A grant the domain refuses to invalidate -- one already consumed
// -- is left as it is rather than forced.
func (r deliveryRepo) InvalidatePrivateGrants(_ context.Context, deliveryID domain.DeliveryID, now domain.Instant) error {
	for id, g := range r.s.grants {
		if g.DeliveryID() != deliveryID || g.Purpose() != domain.GrantPurposeLeafPrivate {
			continue
		}
		next, err := g.Invalidate(now)
		if err != nil {
			continue
		}
		r.s.grants[id] = next
	}
	return nil
}

func (r deliveryRepo) InvalidatePublicGrants(_ context.Context, certificateID domain.CertificateID, now domain.Instant) error {
	for id, g := range r.s.grants {
		if g.CertificateID() != certificateID || g.Purpose() != domain.GrantPurposeLeafPublic {
			continue
		}
		next, err := g.Invalidate(now)
		if err != nil {
			continue
		}
		r.s.grants[id] = next
	}
	return nil
}

func (r deliveryRepo) InvalidateAllPublicGrants(_ context.Context, now domain.Instant) error {
	for id, g := range r.s.grants {
		if g.Purpose() != domain.GrantPurposeLeafPublic {
			continue
		}
		next, err := g.Invalidate(now)
		if err != nil {
			continue
		}
		r.s.grants[id] = next
	}
	return nil
}

// ListExpired backs the once-a-minute expiry sweep. Expiry is `now >=
// expires_at` project-wide, which is what Instant.IsExpiredAt encodes.
func (r deliveryRepo) ListExpired(_ context.Context, now domain.Instant, limit int) ([]domain.Delivery, error) {
	out := make([]domain.Delivery, 0)
	for _, d := range r.s.deliveries {
		if d.State() != domain.DeliveryStatePending {
			continue
		}
		if d.ExpiresAt().IsExpiredAt(now) {
			out = append(out, d)
		}
	}
	return limitDeliveries(out, limit), nil
}

// ListPending backs restore finalization. It deliberately does not inspect
// expires_at: restore cleanup is a safety boundary, not the ordinary expiry
// sweep, and must fail even an otherwise unexpired pending delivery.
func (r deliveryRepo) ListPending(_ context.Context, limit int) ([]domain.Delivery, error) {
	out := make([]domain.Delivery, 0)
	for _, d := range r.s.deliveries {
		if d.State() == domain.DeliveryStatePending {
			out = append(out, d)
		}
	}
	return limitDeliveries(out, limit), nil
}

// ListTransferring backs restart recovery: a delivery left mid-transfer by a
// killed process is the set this returns (docs/backend-implementation.md §9).
func (r deliveryRepo) ListTransferring(_ context.Context, limit int) ([]domain.Delivery, error) {
	out := make([]domain.Delivery, 0)
	for _, d := range r.s.deliveries {
		if d.State() == domain.DeliveryStateTransferring {
			out = append(out, d)
		}
	}
	return limitDeliveries(out, limit), nil
}

func limitDeliveries(list []domain.Delivery, limit int) []domain.Delivery {
	sort.Slice(list, func(i, j int) bool { return list[i].ID() < list[j].ID() })
	if limit > 0 && len(list) > limit {
		return list[:limit]
	}
	return list
}
