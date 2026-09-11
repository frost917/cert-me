package port

import (
	"context"

	"cert-me/internal/domain"
)

// CertificateSigningRequest is the complete signing input
// docs/backend-implementation.md §14.10 fixes. Before it existed, Sign took
// only a domain.IssuancePlan, which carries neither the subject public key
// to embed nor the identifiers the caller has already chosen -- so an app
// had no way to state what it wanted signed and could only re-assemble
// metadata around whatever DER came back. Everything the signer needs is
// therefore named here, and the app checks the returned certificate against
// these same fields (§14.10 "app은 반환 ID/serial/issuer/window/subject/SAN/
// kind/profile/algorithm이 요청과 일치하는지 검사하고 불일치는 오류로
// 처리한다").
type CertificateSigningRequest struct {
	// Plan is the validated issuance plan: profile, subject, SANs,
	// algorithm, window and the issuing authority/key generation.
	Plan domain.IssuancePlan
	// CertificateID and KeyMaterialID are chosen by the app before signing;
	// the signer must return a certificate carrying exactly these.
	CertificateID domain.CertificateID
	KeyMaterialID domain.KeyMaterialID
	// SubjectPublicKey is the public half being certified -- freshly
	// generated, or read back through GetKeyMaterial for a renewal that
	// reuses the key. §14.10: "재사용 갱신에 leaf 개인키를 요구하지 않는다."
	SubjectPublicKey domain.PublicKey
	// Serial comes from SerialGenerator before signing (§8 "serial은 서명 전
	// 생성하고"). A collision retry signs again with a new serial and the
	// same key; the signed DER's serial field is never edited.
	Serial domain.SerialNumber
	Kind   domain.CertificateKind
	// CreatedByAccountID is the administrator the certificate is recorded
	// against; empty for a system-originated issuance.
	CreatedByAccountID domain.AccountID
	// IssuerCertificate is the CA certificate selected for this issuance.
	// §14.10 allows it to be omitted only for a self-signed Root.
	IssuerCertificate domain.Certificate
	// CRLDistributionPoints are the URLs embedded in the certificate.
	CRLDistributionPoints []string
}

// SelfSigned reports whether this request is the Root self-signature, the
// one case §14.10 allows to carry no issuer certificate.
func (r CertificateSigningRequest) SelfSigned() bool {
	return r.IssuerCertificate.ID() == ""
}

// SerialGenerator produces the cryptographically random serial a
// certificate is signed with (docs/certificate-lifecycle.md "일련번호는
// 암호학적 난수로 생성"). It is a dependency rather than something the
// signer decides so the app can state the serial it checked for collisions,
// and so a test can make the value deterministic
// (docs/backend-implementation.md §5's Authority/Issuance row, §14.10).
type SerialGenerator interface {
	NewSerial(ctx context.Context) (domain.SerialNumber, error)
}

// PublicEncodeInput is PublicCertificateEncoder's input: public material
// only. It has no secret and no ciphertext field at all, which is the
// structural half of §14.3's rule that the public path never touches a
// decryption dependency.
type PublicEncodeInput struct {
	Certificate domain.Certificate
	// ChainDER is issuer→Root, excluding the target certificate itself
	// (§14.2). The encoder decides where the target goes per format.
	ChainDER [][]byte
	Format   DeliveryFormat
	PEMPart  string
}

// PublicCertificateEncoder builds the public (no private key) download
// bundle (docs/backend-implementation.md §14.3). It is separate from
// DeliveryEncoder, which stays restricted to leaf_delivery ciphertext:
// the public path has no key to decrypt, and giving it its own dependency
// is what keeps that restriction meaningful.
//
// §14.3 also fixes the output: PEM is real CERTIFICATE PEM and ZIP holds
// certificate.pem plus chain.pem. Handing back raw DER labelled as PEM or
// ZIP is explicitly not allowed.
type PublicCertificateEncoder interface {
	Encode(ctx context.Context, input PublicEncodeInput) (EncodedBundle, error)
}

// OperationalStage names where in a request an operational event happened.
type OperationalStage string

const (
	// OperationalStagePublicPostProcess is the public transfer's outcome
	// recording -- the one §14.5 requires a home for, since a public
	// post-processing failure must neither revoke a key nor surface as a
	// second response body.
	OperationalStagePublicPostProcess OperationalStage = "public_post_process"
)

// OperationalEvent is the typed, secret-free shape OperationalLogger
// accepts. §14.5 fixes its contents precisely: a fixed code, the request
// id, the grant/delivery/certificate ids and the stage -- and explicitly
// NOT the raw error, a URL, a token, a private key or the input command.
// There is no free-form message field, so there is nowhere for one to be
// smuggled in.
type OperationalEvent struct {
	Code          string
	RequestID     string
	Stage         OperationalStage
	GrantID       domain.GrantID
	DeliveryID    domain.DeliveryID
	CertificateID domain.CertificateID
}

// OperationalLogger records operator-facing events that are not business
// audit rows (docs/backend-implementation.md §14.5). Its contract is
// deliberately weak: Record is best-effort, must not block, must not panic,
// and returns nothing -- an operational log must never be able to turn a
// successful business outcome into a failure, and it must still work when
// the caller's context is already canceled. It is not a substitute for the
// audit database ("운영 로그는 감사 DB의 대체 성공 기록이 아니다").
type OperationalLogger interface {
	Record(event OperationalEvent)
}
