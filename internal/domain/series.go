package domain

import "fmt"

// SeriesPurpose classifies what a leaf series is used for.
// [data-model.md: "purpose=distributed/internal_tls/bootstrap_tls"]
type SeriesPurpose string

const (
	SeriesPurposeDistributed  SeriesPurpose = "distributed"
	SeriesPurposeInternalTLS  SeriesPurpose = "internal_tls"
	SeriesPurposeBootstrapTLS SeriesPurpose = "bootstrap_tls"
)

func (p SeriesPurpose) Validate() error {
	switch p {
	case SeriesPurposeDistributed, SeriesPurposeInternalTLS, SeriesPurposeBootstrapTLS:
		return nil
	default:
		return fmt.Errorf("%w: unsupported series purpose %q", ErrInvalidValue, string(p))
	}
}

const (
	minRotateEvery = 1
	maxRotateEvery = 100
)

// SeriesPolicy is the operator-configurable subset of a leaf series: the key
// rotation cadence (in renewal counts, not calendar time) and the validity
// duration new certificates in the series get. [certificate-lifecycle.md
// §유효기간과 계보: "Leaf 유효기간과 키 교체 주기는 인증서 관리 단위에 저장하며
// 갱신에 계승한다"]
type SeriesPolicy struct {
	RotateEvery         int
	CertificateValidity Duration
}

func (p SeriesPolicy) Validate() error {
	if p.RotateEvery < minRotateEvery || p.RotateEvery > maxRotateEvery {
		return fmt.Errorf("%w: rotate_every must be %d..%d", ErrInvalidValue, minRotateEvery, maxRotateEvery)
	}
	if !p.CertificateValidity.IsPositive() {
		return fmt.Errorf("%w: series certificate validity must be positive", ErrInvalidValue)
	}
	return nil
}

// LeafSeries is the logical, long-lived certificate management unit a user
// keeps renewing. Its ID survives renewals and CA transitions; individual
// Certificate rows do not. [data-model.md §핵심 관계: "leaf_series는 사용자가
// 계속 관리하는 논리적 인증서 항목이다. 갱신과 CA 전환에도 ID를 유지한다"]
type LeafSeries struct {
	id                     SeriesID
	name                   string
	purpose                SeriesPurpose
	managementAuthorityID  AuthorityID
	currentCertificateID   CertificateID // empty before the first issuance
	currentKeyGenerationID LeafKeyGenerationID
	policy                 SeriesPolicy
	version                Version
	archivedAt             Instant
}

// LeafSeriesFacts is the constructor input for LeafSeries.
type LeafSeriesFacts struct {
	ID                     SeriesID
	Name                   string
	Purpose                SeriesPurpose
	ManagementAuthorityID  AuthorityID
	CurrentCertificateID   CertificateID
	CurrentKeyGenerationID LeafKeyGenerationID
	Policy                 SeriesPolicy
	Version                Version
	ArchivedAt             Instant
}

const maxSeriesNameLength = 255

// NewLeafSeries validates facts loaded from storage or a prior command.
func NewLeafSeries(facts LeafSeriesFacts) (LeafSeries, error) {
	if _, err := ParseSeriesID(string(facts.ID)); err != nil {
		return LeafSeries{}, err
	}
	if facts.Name == "" || len(facts.Name) > maxSeriesNameLength {
		return LeafSeries{}, fmt.Errorf("%w: series name must be 1..%d characters", ErrInvalidValue, maxSeriesNameLength)
	}
	if err := facts.Purpose.Validate(); err != nil {
		return LeafSeries{}, err
	}
	if _, err := ParseAuthorityID(string(facts.ManagementAuthorityID)); err != nil {
		return LeafSeries{}, err
	}
	if err := facts.Policy.Validate(); err != nil {
		return LeafSeries{}, err
	}
	return LeafSeries{
		id:                     facts.ID,
		name:                   facts.Name,
		purpose:                facts.Purpose,
		managementAuthorityID:  facts.ManagementAuthorityID,
		currentCertificateID:   facts.CurrentCertificateID,
		currentKeyGenerationID: facts.CurrentKeyGenerationID,
		policy:                 facts.Policy,
		version:                facts.Version,
		archivedAt:             facts.ArchivedAt,
	}, nil
}

func (s LeafSeries) ID() SeriesID                                { return s.id }
func (s LeafSeries) Name() string                                { return s.name }
func (s LeafSeries) Purpose() SeriesPurpose                      { return s.purpose }
func (s LeafSeries) ManagementAuthorityID() AuthorityID          { return s.managementAuthorityID }
func (s LeafSeries) CurrentCertificateID() CertificateID         { return s.currentCertificateID }
func (s LeafSeries) CurrentKeyGenerationID() LeafKeyGenerationID { return s.currentKeyGenerationID }
func (s LeafSeries) Policy() SeriesPolicy                        { return s.policy }
func (s LeafSeries) Version() Version                            { return s.version }
func (s LeafSeries) IsArchived() bool                            { return !s.archivedAt.IsZero() }

// ChangePolicy returns a copy of the series with an updated rotation cadence
// and/or default validity. It never touches renewal_count itself: the
// accumulated count on the current key generation is preserved and only
// interpreted differently on the next PlanRenewal call.
// [certificate-lifecycle.md §갱신 횟수 계산: "교체 주기 변경 | 다음 갱신부터
//
//	적용하며 누적 횟수 유지"]
func (s LeafSeries) ChangePolicy(policy SeriesPolicy) (LeafSeries, error) {
	if s.IsArchived() {
		return LeafSeries{}, fmt.Errorf("%w: series is archived", ErrInvalidTransition)
	}
	if err := policy.Validate(); err != nil {
		return LeafSeries{}, err
	}
	next := s
	next.policy = policy
	next.version = s.version.Next()
	return next, nil
}

// KeyCustody tracks where the private key for a leaf key generation
// currently lives. [data-model.md: "custody=pending_delivery/client_held/
// internal"]
type KeyCustody string

const (
	// KeyCustodyPendingDelivery means the server still holds an encrypted
	// copy awaiting the one-time private key pickup.
	KeyCustodyPendingDelivery KeyCustody = "pending_delivery"
	// KeyCustodyClientHeld means pickup completed (or the key was imported)
	// and the server holds no private key copy.
	KeyCustodyClientHeld KeyCustody = "client_held"
	// KeyCustodyInternal is the cert-me bootstrap HTTPS key, kept encrypted
	// on the server across restarts instead of following pickup-then-delete.
	KeyCustodyInternal KeyCustody = "internal"
)

func (c KeyCustody) Validate() error {
	switch c {
	case KeyCustodyPendingDelivery, KeyCustodyClientHeld, KeyCustodyInternal:
		return nil
	default:
		return fmt.Errorf("%w: unsupported key custody %q", ErrInvalidValue, string(c))
	}
}

// LeafKeyGeneration is one public/private key pair a series has used, and
// how many times it has been reused across renewals.
// [data-model.md: leaf_key_generations row]
type LeafKeyGeneration struct {
	id                  LeafKeyGenerationID
	seriesID            SeriesID
	keyMaterialID       KeyMaterialID
	generationNo        int
	renewalCount        int
	priorHistoryUnknown bool
	custody             KeyCustody
}

// LeafKeyGenerationFacts is the constructor input for LeafKeyGeneration.
type LeafKeyGenerationFacts struct {
	ID                  LeafKeyGenerationID
	SeriesID            SeriesID
	KeyMaterialID       KeyMaterialID
	GenerationNo        int
	RenewalCount        int
	PriorHistoryUnknown bool
	Custody             KeyCustody
}

// NewLeafKeyGeneration validates facts loaded from storage or a prior
// command. Import registers a generation with RenewalCount 0 and
// PriorHistoryUnknown true. [certificate-lifecycle.md §갱신 횟수 계산: "가져온
// Leaf는 등록 시 cert-me가 추적하는 갱신 횟수를 0으로 시작한다. 이는 기존
// 키가 새 키라는 의미가 아니며 화면에 '가져오기 이전 키 사용 이력은 포함하지
// 않음'을 표시한다"]
func NewLeafKeyGeneration(facts LeafKeyGenerationFacts) (LeafKeyGeneration, error) {
	if _, err := ParseLeafKeyGenerationID(string(facts.ID)); err != nil {
		return LeafKeyGeneration{}, err
	}
	if _, err := ParseSeriesID(string(facts.SeriesID)); err != nil {
		return LeafKeyGeneration{}, err
	}
	if _, err := ParseKeyMaterialID(string(facts.KeyMaterialID)); err != nil {
		return LeafKeyGeneration{}, err
	}
	if facts.GenerationNo < 1 {
		return LeafKeyGeneration{}, fmt.Errorf("%w: leaf key generation_no must be positive", ErrInvalidValue)
	}
	if facts.RenewalCount < 0 {
		return LeafKeyGeneration{}, fmt.Errorf("%w: leaf key renewal_count must not be negative", ErrInvalidValue)
	}
	if err := facts.Custody.Validate(); err != nil {
		return LeafKeyGeneration{}, err
	}
	return LeafKeyGeneration{
		id:                  facts.ID,
		seriesID:            facts.SeriesID,
		keyMaterialID:       facts.KeyMaterialID,
		generationNo:        facts.GenerationNo,
		renewalCount:        facts.RenewalCount,
		priorHistoryUnknown: facts.PriorHistoryUnknown,
		custody:             facts.Custody,
	}, nil
}

func (g LeafKeyGeneration) ID() LeafKeyGenerationID      { return g.id }
func (g LeafKeyGeneration) SeriesID() SeriesID           { return g.seriesID }
func (g LeafKeyGeneration) KeyMaterialID() KeyMaterialID { return g.keyMaterialID }
func (g LeafKeyGeneration) GenerationNo() int            { return g.generationNo }
func (g LeafKeyGeneration) RenewalCount() int            { return g.renewalCount }
func (g LeafKeyGeneration) PriorHistoryUnknown() bool    { return g.priorHistoryUnknown }
func (g LeafKeyGeneration) Custody() KeyCustody          { return g.custody }

// RenewalAction says whether a planned renewal reuses the current key pair
// or rotates to a brand new one.
type RenewalAction string

const (
	RenewalActionReuseKey  RenewalAction = "reuse_key"
	RenewalActionRotateKey RenewalAction = "rotate_key"
)

// RenewalFacts are the externally-known facts PlanRenewal needs beyond the
// series' own fields: the current key generation being renewed, the target
// issuing authority (already checked with Authority.CanIssue elsewhere, but
// PlanRenewal re-checks the period-covers rule against its window), whether
// the key is presently eligible for a normal renewal (fully delivered and
// not revoked/compromise-impacted -- computed by the app layer from
// Delivery/Revocation facts it owns), and whether this is an emergency
// (CA-compromise) reissue rather than a routine one.
// [certificate-lifecycle.md §CA 키 유출 시 긴급 처리: "긴급 전환에서는 영향을
//
//	받은 Leaf를 새 CA에서 재발급할 때 갱신 횟수와 관계없이 새 개인키를
//	생성한다... 새 키 세대로 전환하고 갱신 횟수를 초기화한다"]
type RenewalFacts struct {
	CurrentGeneration   LeafKeyGeneration
	TargetIssuerID      AuthorityID
	TargetIssuerWindow  ValidityWindow // the target issuer's own certificate window, for the period-covers check
	RequestedWindow     ValidityWindow // desired window for the renewed certificate
	KeyReadyForRenewal  bool           // false while the current key is pending_delivery/transferring or revoked/compromise-impacted
	IsEmergencyReissue  bool
	NextKeyGenerationNo int // generation_no to use if this renewal rotates the key
}

// RenewalPlan is the pure result of PlanRenewal: what the app layer should
// do to carry out the renewal, without having mutated the series or the key
// generation. [backend-implementation.md §2: LeafSeries "입력 객체를 미리
// 변경하지 않음"]
type RenewalPlan struct {
	Action              RenewalAction
	NextRenewalCount    int
	KeyGenerationID     LeafKeyGenerationID // the generation the renewed certificate will use (current one when reusing)
	NextKeyGenerationNo int                 // meaningful only when Action == RenewalActionRotateKey
	TargetIssuerID      AuthorityID
	Window              ValidityWindow
}

// PlanRenewal computes whether the next renewal of series reuses the current
// key or rotates to a new one, and the renewal count the stored key
// generation should carry afterwards. It is pure: series and facts are read
// only, and the caller applies the plan (issue the certificate, update
// counts, possibly create a new leaf_key_generations row) atomically.
//
// Rotation rule: the next renewal's ordinal (current renewal_count + 1) is
// compared against the *current* policy's RotateEvery. If it is greater than
// or equal, the renewal rotates to a new key and the new generation starts
// at renewal_count 0; otherwise it reuses the key and renewal_count becomes
// the ordinal. Changing RotateEvery mid-series keeps the accumulated count
// and only changes which future ordinal triggers rotation --  a normal CA
// move (TargetIssuerID differing from the series' current issuing chain)
// does not by itself reset or advance the count.
// [certificate-lifecycle.md §갱신 횟수 계산 table and: "다음 갱신의 순번(현재
//
//	횟수 + 1)이 설정한 교체 주기 이상이면 새 키로 발급"; planning.md: "정상 CA
//	교체로 기존 인증서가 자동 폐기되거나 Leaf 키 교체 횟수가 초기화되지 않는다"]
//
// An emergency reissue always rotates the key and always resets the count to
// 0, regardless of RotateEvery or the current ordinal.
func (s LeafSeries) PlanRenewal(facts RenewalFacts, now Instant) (RenewalPlan, error) {
	if s.IsArchived() {
		return RenewalPlan{}, fmt.Errorf("%w: series is archived", ErrInvalidTransition)
	}
	if facts.CurrentGeneration.SeriesID() != s.id {
		return RenewalPlan{}, fmt.Errorf("%w: key generation does not belong to this series", ErrInvalidValue)
	}
	if _, err := ParseAuthorityID(string(facts.TargetIssuerID)); err != nil {
		return RenewalPlan{}, err
	}
	if facts.RequestedWindow.IsZero() {
		return RenewalPlan{}, fmt.Errorf("%w: renewal requested window must be set", ErrInvalidValue)
	}
	if !facts.TargetIssuerWindow.IsZero() && !facts.TargetIssuerWindow.Covers(facts.RequestedWindow) {
		return RenewalPlan{}, fmt.Errorf("%w: requested validity exceeds issuer certificate period", ErrPolicyViolation)
	}

	if facts.IsEmergencyReissue {
		if facts.NextKeyGenerationNo <= facts.CurrentGeneration.GenerationNo() {
			return RenewalPlan{}, fmt.Errorf("%w: emergency reissue requires a new key generation number", ErrInvalidValue)
		}
		return RenewalPlan{
			Action:              RenewalActionRotateKey,
			NextRenewalCount:    0,
			NextKeyGenerationNo: facts.NextKeyGenerationNo,
			TargetIssuerID:      facts.TargetIssuerID,
			Window:              facts.RequestedWindow,
		}, nil
	}

	if !facts.KeyReadyForRenewal {
		return RenewalPlan{}, fmt.Errorf("%w: current key is not eligible for a normal renewal", ErrNotPermitted)
	}

	nextOrdinal := facts.CurrentGeneration.RenewalCount() + 1
	if nextOrdinal >= s.policy.RotateEvery {
		if facts.NextKeyGenerationNo <= facts.CurrentGeneration.GenerationNo() {
			return RenewalPlan{}, fmt.Errorf("%w: rotation requires a new key generation number", ErrInvalidValue)
		}
		return RenewalPlan{
			Action:              RenewalActionRotateKey,
			NextRenewalCount:    0,
			NextKeyGenerationNo: facts.NextKeyGenerationNo,
			TargetIssuerID:      facts.TargetIssuerID,
			Window:              facts.RequestedWindow,
		}, nil
	}

	return RenewalPlan{
		Action:           RenewalActionReuseKey,
		NextRenewalCount: nextOrdinal,
		KeyGenerationID:  facts.CurrentGeneration.ID(),
		TargetIssuerID:   facts.TargetIssuerID,
		Window:           facts.RequestedWindow,
	}, nil
}
