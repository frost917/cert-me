// TLSVersion and TLSChange model the dashboard's own HTTPS certificate
// lifecycle: candidate preparation, validation, activation and recovery.
// Policy source: docs/backend-implementation.md §9; docs/data-model.md
// "내부 HTTPS·유지보수·작업·감사"; docs/planning.md HTTPS replacement rules.
package domain

import "fmt"

// TLSSource mirrors tls_versions.source.
type TLSSource string

const (
	TLSSourceBootstrap TLSSource = "bootstrap"
	TLSSourceManaged   TLSSource = "managed"
	TLSSourceExternal  TLSSource = "external"
)

func (s TLSSource) Validate() error {
	switch s {
	case TLSSourceBootstrap, TLSSourceManaged, TLSSourceExternal:
		return nil
	default:
		return fmt.Errorf("%w: unsupported tls source %q", ErrInvalidValue, string(s))
	}
}

// TLSVersion is one validated, ready-to-serve HTTPS snapshot: a leaf
// certificate, its chain bundle and the key material it pairs with. It does
// not itself know whether it is active; TLSChange/the active pointer track
// that.
type TLSVersion struct {
	id                   TLSVersionID
	source               TLSSource
	keyMaterialID        KeyMaterialID
	managedCertificateID CertificateID // zero unless source == managed
	leafDER              []byte
	chainBundle          []byte
	validatedServiceURL  string
	notAfter             Instant
}

// TLSVersionFacts is the constructor input, matching tls_versions columns.
type TLSVersionFacts struct {
	ID                   TLSVersionID
	Source               TLSSource
	KeyMaterialID        KeyMaterialID
	ManagedCertificateID CertificateID
	LeafDER              []byte
	ChainBundle          []byte
	ValidatedServiceURL  string
	NotAfter             Instant
}

// NewTLSVersion copies the DER/bundle byte slices it is given.
func NewTLSVersion(facts TLSVersionFacts) (TLSVersion, error) {
	if _, err := ParseTLSVersionID(string(facts.ID)); err != nil {
		return TLSVersion{}, err
	}
	if err := facts.Source.Validate(); err != nil {
		return TLSVersion{}, err
	}
	if _, err := ParseKeyMaterialID(string(facts.KeyMaterialID)); err != nil {
		return TLSVersion{}, err
	}
	if facts.Source == TLSSourceManaged && facts.ManagedCertificateID == "" {
		return TLSVersion{}, fmt.Errorf("%w: a managed tls version must reference its certificate", ErrInvalidValue)
	}
	if facts.ManagedCertificateID != "" {
		if _, err := ParseCertificateID(string(facts.ManagedCertificateID)); err != nil {
			return TLSVersion{}, err
		}
	}
	if len(facts.LeafDER) == 0 {
		return TLSVersion{}, fmt.Errorf("%w: tls version leaf der must not be empty", ErrInvalidValue)
	}
	if facts.ValidatedServiceURL == "" {
		return TLSVersion{}, fmt.Errorf("%w: tls version needs a validated service url", ErrInvalidValue)
	}
	if facts.NotAfter.IsZero() {
		return TLSVersion{}, fmt.Errorf("%w: tls version not_after must be set", ErrInvalidValue)
	}
	return TLSVersion{
		id:                   facts.ID,
		source:               facts.Source,
		keyMaterialID:        facts.KeyMaterialID,
		managedCertificateID: facts.ManagedCertificateID,
		leafDER:              cloneBytes(facts.LeafDER),
		chainBundle:          cloneBytes(facts.ChainBundle),
		validatedServiceURL:  facts.ValidatedServiceURL,
		notAfter:             facts.NotAfter,
	}, nil
}

func (v TLSVersion) ID() TLSVersionID                    { return v.id }
func (v TLSVersion) Source() TLSSource                   { return v.source }
func (v TLSVersion) KeyMaterialID() KeyMaterialID        { return v.keyMaterialID }
func (v TLSVersion) ManagedCertificateID() CertificateID { return v.managedCertificateID }
func (v TLSVersion) LeafDER() []byte                     { return cloneBytes(v.leafDER) }
func (v TLSVersion) ChainBundle() []byte                 { return cloneBytes(v.chainBundle) }
func (v TLSVersion) ValidatedServiceURL() string         { return v.validatedServiceURL }
func (v TLSVersion) NotAfter() Instant                   { return v.notAfter }

// IsExpiredAt reports whether the leaf has passed its own not_after. Being
// expired never by itself deactivates a running server
// (certificate-lifecycle.md style "재시작 후에도 마지막 적용 인증서를
// 사용한다"); it is only meaningful input for reconcile/rollback decisions.
func (v TLSVersion) IsExpiredAt(now Instant) bool { return v.notAfter.IsExpiredAt(now) }

// TLSChangePhase mirrors tls_changes.phase.
type TLSChangePhase string

const (
	TLSChangePhasePrepared         TLSChangePhase = "prepared"
	TLSChangePhaseCommitted        TLSChangePhase = "committed"
	TLSChangePhaseApplied          TLSChangePhase = "applied"
	TLSChangePhaseRolledBack       TLSChangePhase = "rolled_back"
	TLSChangePhaseRecoveryRequired TLSChangePhase = "recovery_required"
)

func (p TLSChangePhase) Validate() error {
	switch p {
	case TLSChangePhasePrepared, TLSChangePhaseCommitted, TLSChangePhaseApplied,
		TLSChangePhaseRolledBack, TLSChangePhaseRecoveryRequired:
		return nil
	default:
		return fmt.Errorf("%w: unsupported tls change phase %q", ErrInvalidValue, string(p))
	}
}

func (p TLSChangePhase) IsTerminal() bool {
	switch p {
	case TLSChangePhaseApplied, TLSChangePhaseRolledBack:
		return true
	default:
		return false
	}
}

// TLSChange tracks one HTTPS candidate's journey from preparation to
// activation, separating "prepared" (a candidate exists and may be
// validated) from "committed"/"applied" (it is becoming, or has become, the
// live version): backend-implementation.md §9 "후보 준비와 활성화를
// 분리한다."
type TLSChange struct {
	previousVersionID  TLSVersionID // zero if there was no prior active version
	candidateVersionID TLSVersionID
	phase              TLSChangePhase
	validated          bool
	errorCode          string
	version            Version
}

// TLSChangeFacts is the constructor input, matching tls_changes columns.
type TLSChangeFacts struct {
	PreviousVersionID  TLSVersionID
	CandidateVersionID TLSVersionID
	Phase              TLSChangePhase
	Validated          bool
	ErrorCode          string
	Version            Version
}

// NewTLSChange builds a TLSChange from stored facts.
func NewTLSChange(facts TLSChangeFacts) (TLSChange, error) {
	if _, err := ParseTLSVersionID(string(facts.CandidateVersionID)); err != nil {
		return TLSChange{}, err
	}
	if facts.PreviousVersionID != "" {
		if _, err := ParseTLSVersionID(string(facts.PreviousVersionID)); err != nil {
			return TLSChange{}, err
		}
	}
	if err := facts.Phase.Validate(); err != nil {
		return TLSChange{}, err
	}
	return TLSChange{
		previousVersionID:  facts.PreviousVersionID,
		candidateVersionID: facts.CandidateVersionID,
		phase:              facts.Phase,
		validated:          facts.Validated,
		errorCode:          facts.ErrorCode,
		version:            facts.Version,
	}, nil
}

// NewCandidateTLSChange starts a fresh prepared candidate for the given
// previously-active version (zero if there was none, e.g. first bootstrap).
func NewCandidateTLSChange(previousVersionID, candidateVersionID TLSVersionID) (TLSChange, error) {
	return NewTLSChange(TLSChangeFacts{
		PreviousVersionID:  previousVersionID,
		CandidateVersionID: candidateVersionID,
		Phase:              TLSChangePhasePrepared,
	})
}

func (c TLSChange) PreviousVersionID() TLSVersionID  { return c.previousVersionID }
func (c TLSChange) CandidateVersionID() TLSVersionID { return c.candidateVersionID }
func (c TLSChange) Phase() TLSChangePhase            { return c.phase }
func (c TLSChange) Validated() bool                  { return c.validated }
func (c TLSChange) ErrorCode() string                { return c.errorCode }
func (c TLSChange) Version() Version                 { return c.version }

// TLSValidationFacts are the cryptographic/network facts the adapter (not
// the domain) already checked for the candidate. The domain only decides
// what those facts permit.
type TLSValidationFacts struct {
	KeyMatchesCertificate    bool
	WithinValidityPeriod     bool
	PurposeMatchesServerAuth bool
	ServiceAddressMatches    bool
	ChainVerified            bool
}

func (f TLSValidationFacts) allPass() bool {
	return f.KeyMatchesCertificate && f.WithinValidityPeriod && f.PurposeMatchesServerAuth &&
		f.ServiceAddressMatches && f.ChainVerified
}

// firstFailure names which check failed, for a stable error code.
func (f TLSValidationFacts) firstFailure() string {
	switch {
	case !f.KeyMatchesCertificate:
		return "tls_candidate_key_mismatch"
	case !f.WithinValidityPeriod:
		return "tls_candidate_out_of_validity"
	case !f.PurposeMatchesServerAuth:
		return "tls_candidate_wrong_purpose"
	case !f.ServiceAddressMatches:
		return "tls_candidate_address_mismatch"
	default:
		return "tls_candidate_chain_invalid"
	}
}

// ValidateCandidate checks a prepared candidate against gathered facts. A
// failing candidate stays prepared and unvalidated: it never changes the
// active version, since Commit refuses an unvalidated candidate
// (planning.md "HTTPS 교체 후보의 ... 검증 실패 시 기존 인증서를 유지한다").
func (c TLSChange) ValidateCandidate(facts TLSValidationFacts) (TLSChange, error) {
	if c.phase != TLSChangePhasePrepared {
		return TLSChange{}, NewPolicyError(ErrInvalidTransition, "tls_change_not_prepared",
			fmt.Sprintf("tls change is %s, not prepared", c.phase))
	}
	if !facts.allPass() {
		next := c
		next.validated = false
		next.errorCode = facts.firstFailure()
		return next, NewPolicyError(ErrPolicyViolation, facts.firstFailure(), "tls candidate failed validation")
	}
	next := c
	next.validated = true
	next.errorCode = ""
	return next, nil
}

// Commit moves a validated prepared candidate to committed: the DB record
// of intent to activate, written before the in-memory installer swap
// (backend-implementation.md §9 "committed 기록/활성 포인터 변경 →
// Installer.Apply").
func (c TLSChange) Commit(now Instant) (TLSChange, error) {
	if c.phase != TLSChangePhasePrepared {
		return TLSChange{}, NewPolicyError(ErrInvalidTransition, "tls_change_not_prepared",
			fmt.Sprintf("tls change is %s, not prepared", c.phase))
	}
	if !c.validated {
		return TLSChange{}, NewPolicyError(ErrNotPermitted, "tls_candidate_not_validated",
			"candidate has not passed validation")
	}
	next := c
	next.phase = TLSChangePhaseCommitted
	next.version = c.version.Next()
	_ = now
	return next, nil
}

// Apply records that the installer successfully swapped the live TLS
// configuration to the candidate.
func (c TLSChange) Apply(now Instant) (TLSChange, error) {
	if c.phase != TLSChangePhaseCommitted {
		return TLSChange{}, NewPolicyError(ErrInvalidTransition, "tls_change_not_committed",
			fmt.Sprintf("tls change is %s, not committed", c.phase))
	}
	next := c
	next.phase = TLSChangePhaseApplied
	next.version = c.version.Next()
	_ = now
	return next, nil
}

// RollbackApply records that the installer's Apply failed cleanly: both the
// in-memory config and the DB active pointer must revert to the previous
// version (backend-implementation.md §9 "Apply 실패는 DB/메모리 모두
// 원복한다"), so this candidate never becomes active.
func (c TLSChange) RollbackApply(errorCode string, now Instant) (TLSChange, error) {
	if c.phase != TLSChangePhaseCommitted {
		return TLSChange{}, NewPolicyError(ErrInvalidTransition, "tls_change_not_committed",
			fmt.Sprintf("tls change is %s, not committed", c.phase))
	}
	if errorCode == "" {
		return TLSChange{}, fmt.Errorf("%w: rollback requires an error code", ErrInvalidValue)
	}
	next := c
	next.phase = TLSChangePhaseRolledBack
	next.errorCode = errorCode
	next.version = c.version.Next()
	_ = now
	return next, nil
}

// MarkRecoveryRequired records that whether Apply (or the applied-state
// write that follows it) actually succeeded is unknown, so normal service
// must stop until Reconcile inspects stored state
// (backend-implementation.md §9 "불명확한 변경은 일반 서비스 재개를 막고
// Reconcile로 판단한다").
func (c TLSChange) MarkRecoveryRequired(errorCode string, now Instant) (TLSChange, error) {
	if c.phase.IsTerminal() {
		return TLSChange{}, NewPolicyError(ErrInvalidTransition, "tls_change_terminal",
			fmt.Sprintf("tls change is already terminal (%s)", c.phase))
	}
	if errorCode == "" {
		return TLSChange{}, fmt.Errorf("%w: recovery marker requires an error code", ErrInvalidValue)
	}
	next := c
	next.phase = TLSChangePhaseRecoveryRequired
	next.errorCode = errorCode
	next.version = c.version.Next()
	_ = now
	return next, nil
}

// CanActivate reports whether this change is ready for the installer swap
// step (i.e. Activate's "committed" precondition).
func (c TLSChange) CanActivate() bool { return c.phase == TLSChangePhaseCommitted }

// IsActive reports whether this change's candidate is the currently applied
// (live) version.
func (c TLSChange) IsActive() bool { return c.phase == TLSChangePhaseApplied }
