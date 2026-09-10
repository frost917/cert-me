package contract

import (
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// This file is TLSService's command/result contract
// (docs/backend-implementation.md §3, §9): Status, UploadCandidate,
// IssueCandidate, Reload, Activate, Bootstrap/Reconcile.

// TLSStatusQuery is the empty command for Status.
type TLSStatusQuery struct{}

func (TLSStatusQuery) Validate() error { return nil }

// TLSUploadCandidateCommand is the OpenAPI TLSUpload schema. Certificate and
// Chain are ordinary file bytes; Key's passphrase (if any) is the only
// secret, owned by this command and released by the caller after
// UploadCandidate returns, per the upload-command convention
// (docs/backend-implementation.md §3 "업로드 command는 파일 바이트와
// 키별 secret.Input을 소유하고 작업 후 해제한다").
type TLSUploadCandidateCommand struct {
	Certificate []byte
	Chain       []byte
	Key         []byte
	Passphrase  *secret.Input
}

func (c TLSUploadCandidateCommand) Validate() error {
	if len(c.Certificate) == 0 {
		return NewAppError(ErrorKindValidation, "tls_certificate_required", "certificate must not be empty")
	}
	if len(c.Key) == 0 {
		return NewAppError(ErrorKindValidation, "tls_key_required", "key must not be empty")
	}
	return nil
}

// TLSIssueCandidateCommand is the OpenAPI TLSIssue schema.
type TLSIssueCandidateCommand struct {
	AuthorityID  domain.AuthorityID `json:"authority_id"`
	Subject      SubjectInput       `json:"subject"`
	SANs         []SANInput         `json:"sans"`
	KeyAlgorithm string             `json:"key_algorithm,omitempty"`
	Validity     *ValidityInput     `json:"validity,omitempty"`
}

const maxTLSIssueSANs = 100

func (c TLSIssueCandidateCommand) Validate() error {
	if _, err := domain.ParseAuthorityID(string(c.AuthorityID)); err != nil {
		return FromDomainError(err)
	}
	if _, err := c.Subject.Domain(); err != nil {
		return FromDomainError(err)
	}
	if len(c.SANs) == 0 {
		return NewAppError(ErrorKindValidation, "sans_required", "sans must not be empty")
	}
	if len(c.SANs) > maxTLSIssueSANs {
		return NewAppError(ErrorKindValidation, "sans_too_many", "sans must have at most 100 entries")
	}
	if _, err := SANInputs(c.SANs); err != nil {
		return FromDomainError(err)
	}
	if c.KeyAlgorithm != "" {
		if err := domain.KeyAlgorithm(c.KeyAlgorithm).Validate(); err != nil {
			return FromDomainError(err)
		}
	}
	if c.Validity != nil {
		if _, err := c.Validity.Domain(); err != nil {
			return FromDomainError(err)
		}
	}
	return nil
}

// TLSReloadCommand is the empty command for Reload.
type TLSReloadCommand struct{}

func (TLSReloadCommand) Validate() error { return nil }

// TLSActivateCommand is the OpenAPI TLSActivation schema. §3 requires the
// TLS status version via MutationMeta for this method.
type TLSActivateCommand struct {
	CandidateID domain.TLSVersionID `json:"candidate_id"`
}

func (c TLSActivateCommand) Validate() error {
	if _, err := domain.ParseTLSVersionID(string(c.CandidateID)); err != nil {
		return FromDomainError(err)
	}
	return nil
}

// TLSBootstrapCommand is an internal command: runtime/local only (§3
// "나머지 내부 명령은 runtime/local 전용"), so it carries no JSON tags. It is
// an explicit empty command per §3's "인자 없는 명령도 명시적 빈 command를
// 사용한다."
type TLSBootstrapCommand struct{}

func (TLSBootstrapCommand) Validate() error { return nil }

// TLSReconcileCommand is an internal command; also runtime/local only.
type TLSReconcileCommand struct{}

func (TLSReconcileCommand) Validate() error { return nil }

// TLSVersionView is the OpenAPI TLSVersion data object.
type TLSVersionView struct {
	ID                  domain.TLSVersionID
	Source              domain.TLSSource
	CertificateID       *domain.CertificateID
	NotAfter            domain.Instant
	ValidatedServiceURL string
}

// TLSStatusView is the OpenAPI TLSStatus data object.
type TLSStatusView struct {
	Active      *TLSVersionView
	Phase       *domain.TLSChangePhase
	CandidateID *domain.TLSVersionID
	ErrorCode   string
	Version     domain.Version
}
