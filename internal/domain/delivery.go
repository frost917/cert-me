// Delivery and DownloadGrant model the one-shot private key handoff and the
// short-lived download links (public leaf bundle, private key receipt).
// Policy source: docs/certificate-lifecycle.md "일회성 수령과 실패", "CA 공개
// 인증서 접근"; docs/data-model.md "일회성 수령·공개 다운로드";
// docs/backend-implementation.md §2, §7.
package domain

import "fmt"

// DeliveryState mirrors key_deliveries.state (docs/data-model.md).
type DeliveryState string

const (
	DeliveryStatePending         DeliveryState = "pending"
	DeliveryStateTransferring    DeliveryState = "transferring"
	DeliveryStateServerCompleted DeliveryState = "server_completed"
	DeliveryStateFailed          DeliveryState = "failed"
	DeliveryStateExpired         DeliveryState = "expired"
)

func (s DeliveryState) Validate() error {
	switch s {
	case DeliveryStatePending, DeliveryStateTransferring, DeliveryStateServerCompleted,
		DeliveryStateFailed, DeliveryStateExpired:
		return nil
	default:
		return fmt.Errorf("%w: unsupported delivery state %q", ErrInvalidValue, string(s))
	}
}

// IsTerminal reports whether the state accepts no further transitions.
// certificate-lifecycle.md: "pending 상태로 되돌리는 전이는 없다."
func (s DeliveryState) IsTerminal() bool {
	switch s {
	case DeliveryStateServerCompleted, DeliveryStateFailed, DeliveryStateExpired:
		return true
	default:
		return false
	}
}

// Delivery is the private-key one-shot custody record for one leaf key
// generation. It is created at most once per leaf_key_generation
// (data-model.md: key_deliveries.leaf_key_generation_id UQ).
type Delivery struct {
	id                  DeliveryID
	leafKeyGenerationID LeafKeyGenerationID
	certificateID       CertificateID
	expiresAt           Instant
	state               DeliveryState
	consumedAt          Instant
	finishedAt          Instant
	failureCode         string
	version             Version
}

// DeliveryFacts is the constructor input, matching key_deliveries columns.
type DeliveryFacts struct {
	ID                  DeliveryID
	LeafKeyGenerationID LeafKeyGenerationID
	CertificateID       CertificateID
	ExpiresAt           Instant
	State               DeliveryState
	ConsumedAt          Instant
	FinishedAt          Instant
	FailureCode         string
	Version             Version
}

// NewDelivery builds a Delivery from stored facts. Fresh deliveries are
// created with State=DeliveryStatePending by the caller.
func NewDelivery(facts DeliveryFacts) (Delivery, error) {
	if _, err := ParseDeliveryID(string(facts.ID)); err != nil {
		return Delivery{}, err
	}
	if _, err := ParseLeafKeyGenerationID(string(facts.LeafKeyGenerationID)); err != nil {
		return Delivery{}, err
	}
	if _, err := ParseCertificateID(string(facts.CertificateID)); err != nil {
		return Delivery{}, err
	}
	if facts.ExpiresAt.IsZero() {
		return Delivery{}, fmt.Errorf("%w: delivery expires_at must be set", ErrInvalidValue)
	}
	if err := facts.State.Validate(); err != nil {
		return Delivery{}, err
	}
	return Delivery{
		id:                  facts.ID,
		leafKeyGenerationID: facts.LeafKeyGenerationID,
		certificateID:       facts.CertificateID,
		expiresAt:           facts.ExpiresAt,
		state:               facts.State,
		consumedAt:          facts.ConsumedAt,
		finishedAt:          facts.FinishedAt,
		failureCode:         facts.FailureCode,
		version:             facts.Version,
	}, nil
}

func (d Delivery) ID() DeliveryID                           { return d.id }
func (d Delivery) LeafKeyGenerationID() LeafKeyGenerationID { return d.leafKeyGenerationID }
func (d Delivery) CertificateID() CertificateID             { return d.certificateID }
func (d Delivery) ExpiresAt() Instant                       { return d.expiresAt }
func (d Delivery) State() DeliveryState                     { return d.state }
func (d Delivery) ConsumedAt() Instant                      { return d.consumedAt }
func (d Delivery) FinishedAt() Instant                      { return d.finishedAt }
func (d Delivery) FailureCode() string                      { return d.failureCode }
func (d Delivery) Version() Version                         { return d.version }

// CanConsume reports whether a private-key download may proceed right now.
// Expiry is checked live: planning.md "만료된 수령은 정리 작업 실행과 무관하게
// 거부된다."
func (d Delivery) CanConsume(now Instant) error {
	if d.state != DeliveryStatePending {
		return NewPolicyError(ErrInvalidTransition, "delivery_not_pending",
			fmt.Sprintf("delivery is %s, not pending", d.state))
	}
	if d.expiresAt.IsExpiredAt(now) {
		return NewPolicyError(ErrExpired, "delivery_expired", "delivery receipt window has passed")
	}
	return nil
}

// Consume moves a pending delivery to transferring. It is the first step of
// the one-shot commit (data-model.md "개인키 소비").
func (d Delivery) Consume(now Instant) (Delivery, error) {
	if err := d.CanConsume(now); err != nil {
		return Delivery{}, err
	}
	next := d
	next.state = DeliveryStateTransferring
	next.consumedAt = now
	next.version = d.version.Next()
	return next, nil
}

// Complete records the server-observed transfer completion. It only means
// the response body finished writing (backend-implementation.md §2, §7),
// never client-side storage confirmation.
func (d Delivery) Complete(now Instant) (Delivery, error) {
	if d.state != DeliveryStateTransferring {
		return Delivery{}, NewPolicyError(ErrInvalidTransition, "delivery_not_transferring",
			fmt.Sprintf("delivery is %s, not transferring", d.state))
	}
	next := d
	next.state = DeliveryStateServerCompleted
	next.finishedAt = now
	next.version = d.version.Next()
	return next, nil
}

// Fail moves the delivery to failed, from any non-terminal state or from an
// already server_completed state (an admin-reported storage failure after a
// successful transfer, certificate-lifecycle.md "일회성 수령과 실패" table).
// A delivery already failed or expired cannot be failed again: terminal
// states do not restore to pending and do not re-transition among
// themselves.
func (d Delivery) Fail(code string, now Instant) (Delivery, error) {
	if d.state == DeliveryStateFailed || d.state == DeliveryStateExpired {
		return Delivery{}, NewPolicyError(ErrInvalidTransition, "delivery_terminal",
			fmt.Sprintf("delivery is already terminal (%s)", d.state))
	}
	if code == "" {
		return Delivery{}, fmt.Errorf("%w: failure code must not be empty", ErrInvalidValue)
	}
	next := d
	next.state = DeliveryStateFailed
	next.failureCode = code
	next.finishedAt = now
	next.version = d.version.Next()
	return next, nil
}

// Expire moves a pending delivery whose deadline has passed to expired. It
// requires now to actually be past the deadline; it does not fabricate
// expiry as a way to force a transition.
func (d Delivery) Expire(now Instant) (Delivery, error) {
	if d.state != DeliveryStatePending {
		return Delivery{}, NewPolicyError(ErrInvalidTransition, "delivery_not_pending",
			fmt.Sprintf("delivery is %s, not pending", d.state))
	}
	if !d.expiresAt.IsExpiredAt(now) {
		return Delivery{}, NewPolicyError(ErrInvalidTransition, "delivery_not_expired",
			"delivery deadline has not passed yet")
	}
	next := d
	next.state = DeliveryStateExpired
	next.finishedAt = now
	next.version = d.version.Next()
	return next, nil
}

// GrantPurpose mirrors download_tokens.purpose.
type GrantPurpose string

const (
	GrantPurposeLeafPublic  GrantPurpose = "leaf_public"
	GrantPurposeLeafPrivate GrantPurpose = "leaf_private"
)

func (p GrantPurpose) Validate() error {
	switch p {
	case GrantPurposeLeafPublic, GrantPurposeLeafPrivate:
		return nil
	default:
		return fmt.Errorf("%w: unsupported grant purpose %q", ErrInvalidValue, string(p))
	}
}

// DownloadGrant is a one-shot bearer-token grant for either the public leaf
// bundle or the private key receipt. Only the token hash is retained; the
// domain never sees or stores the raw token
// (backend-implementation.md §6 TokenCodec).
type DownloadGrant struct {
	id            GrantID
	tokenHash     TokenHash
	purpose       GrantPurpose
	certificateID CertificateID
	deliveryID    DeliveryID // zero for GrantPurposeLeafPublic
	expiresAt     Instant
	consumedAt    Instant
	invalidatedAt Instant
	version       Version
}

// DownloadGrantFacts is the constructor input, matching download_tokens
// columns.
type DownloadGrantFacts struct {
	ID            GrantID
	TokenHash     TokenHash
	Purpose       GrantPurpose
	CertificateID CertificateID
	DeliveryID    DeliveryID
	ExpiresAt     Instant
	ConsumedAt    Instant
	InvalidatedAt Instant
	Version       Version
}

// NewDownloadGrant validates that private grants carry a delivery and public
// grants do not (data-model.md: "private는 delivery 필수, public은 NULL").
func NewDownloadGrant(facts DownloadGrantFacts) (DownloadGrant, error) {
	if _, err := ParseGrantID(string(facts.ID)); err != nil {
		return DownloadGrant{}, err
	}
	if facts.TokenHash.IsZero() {
		return DownloadGrant{}, fmt.Errorf("%w: grant token hash must not be empty", ErrInvalidValue)
	}
	if err := facts.Purpose.Validate(); err != nil {
		return DownloadGrant{}, err
	}
	if _, err := ParseCertificateID(string(facts.CertificateID)); err != nil {
		return DownloadGrant{}, err
	}
	switch facts.Purpose {
	case GrantPurposeLeafPrivate:
		if facts.DeliveryID == "" {
			return DownloadGrant{}, fmt.Errorf("%w: private download grant requires a delivery id", ErrInvalidValue)
		}
		if _, err := ParseDeliveryID(string(facts.DeliveryID)); err != nil {
			return DownloadGrant{}, err
		}
	case GrantPurposeLeafPublic:
		if facts.DeliveryID != "" {
			return DownloadGrant{}, fmt.Errorf("%w: public download grant must not carry a delivery id", ErrInvalidValue)
		}
	}
	if facts.ExpiresAt.IsZero() {
		return DownloadGrant{}, fmt.Errorf("%w: grant expires_at must be set", ErrInvalidValue)
	}
	return DownloadGrant{
		id:            facts.ID,
		tokenHash:     facts.TokenHash,
		purpose:       facts.Purpose,
		certificateID: facts.CertificateID,
		deliveryID:    facts.DeliveryID,
		expiresAt:     facts.ExpiresAt,
		consumedAt:    facts.ConsumedAt,
		invalidatedAt: facts.InvalidatedAt,
		version:       facts.Version,
	}, nil
}

func (g DownloadGrant) ID() GrantID                  { return g.id }
func (g DownloadGrant) TokenHash() TokenHash         { return g.tokenHash }
func (g DownloadGrant) Purpose() GrantPurpose        { return g.purpose }
func (g DownloadGrant) CertificateID() CertificateID { return g.certificateID }
func (g DownloadGrant) DeliveryID() DeliveryID       { return g.deliveryID }
func (g DownloadGrant) ExpiresAt() Instant           { return g.expiresAt }
func (g DownloadGrant) ConsumedAt() Instant          { return g.consumedAt }
func (g DownloadGrant) InvalidatedAt() Instant       { return g.invalidatedAt }
func (g DownloadGrant) Version() Version             { return g.version }

func (g DownloadGrant) isConsumed() bool    { return !g.consumedAt.IsZero() }
func (g DownloadGrant) isInvalidated() bool { return !g.invalidatedAt.IsZero() }

// Validate binds token, purpose and target together so a hashed token cannot
// be replayed against a different purpose, certificate or delivery
// (certificate-lifecycle.md "다운로드 토큰은 ... 인증서·수령 권한·용도·만료
// 시각에 결합한다").
func (g DownloadGrant) Validate(purpose GrantPurpose, certificateID CertificateID, deliveryID DeliveryID, now Instant) error {
	if g.isInvalidated() {
		return NewPolicyError(ErrAlreadyConsumed, "grant_invalidated", "download link was replaced or superseded")
	}
	if g.isConsumed() {
		return NewPolicyError(ErrAlreadyConsumed, "grant_consumed", "download link was already used")
	}
	if g.expiresAt.IsExpiredAt(now) {
		return NewPolicyError(ErrExpired, "grant_expired", "download link has expired")
	}
	if g.purpose != purpose {
		return NewPolicyError(ErrPolicyViolation, "grant_purpose_mismatch", "download link purpose does not match request")
	}
	if g.certificateID != certificateID {
		return NewPolicyError(ErrPolicyViolation, "grant_certificate_mismatch", "download link does not match certificate")
	}
	if g.purpose == GrantPurposeLeafPrivate && g.deliveryID != deliveryID {
		return NewPolicyError(ErrPolicyViolation, "grant_delivery_mismatch", "download link does not match delivery")
	}
	return nil
}

// Consume marks the grant used. Callers must call Validate first inside the
// same commit to re-check state under lock; Consume itself re-applies the
// consumed/invalidated/expiry checks so it cannot be called out of order.
func (g DownloadGrant) Consume(now Instant) (DownloadGrant, error) {
	if err := g.Validate(g.purpose, g.certificateID, g.deliveryID, now); err != nil {
		return DownloadGrant{}, err
	}
	next := g
	next.consumedAt = now
	next.version = g.version.Next()
	return next, nil
}

// Invalidate revokes an unused grant, used both for link replacement
// (certificate-lifecycle.md "같은 인증서의 새 공개 다운로드 링크를 발급하면
// 기존 미사용 공개 다운로드 링크를 무효화") and for private-grant cleanup on
// delivery failure/expiry. It is idempotent for an already invalidated
// grant and refuses to touch a consumed one: a spent one-shot permission is
// never restored or further modified.
func (g DownloadGrant) Invalidate(now Instant) (DownloadGrant, error) {
	if g.isConsumed() {
		return DownloadGrant{}, NewPolicyError(ErrAlreadyConsumed, "grant_consumed",
			"a consumed download link cannot be invalidated")
	}
	if g.isInvalidated() {
		return g, nil
	}
	next := g
	next.invalidatedAt = now
	next.version = g.version.Next()
	return next, nil
}
