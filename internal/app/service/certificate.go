package service

import (
	"context"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// signingKeyRef selects which key pair a signing attempt uses: either a
// fresh key prepareCertificate must generate first, or an already-stored one
// (an ordinary Leaf renewal reusing the current key, certificate-
// lifecycle.md "기존 공개키로 발급 CA가 새 인증서를 서명할 수 있으므로 일반
// 갱신에 서버 보관 Leaf 개인키는 필요하지 않다" -- exactly one of the two
// fields is set, never both).
type signingKeyRef struct {
	// Fresh, when set, is the spec for a brand-new key pair to generate.
	Fresh *port.KeySpec
	// Existing, when Fresh is nil, is the KeyMaterialID an already-stored key
	// (its private half not read here) is signed against.
	Existing domain.KeyMaterialID
}

// preparedCertificate is prepareCertificate's result: the signed certificate
// plus which key material it is now tied to, and -- only when a fresh key
// was generated -- the encrypted secret the caller must store. Whether that
// secret becomes a pending Leaf delivery or internal TLS custody is not
// prepareCertificate's decision (docs/backend-implementation.md §5 "계획의
// custody가 처음부터 internal이며 response에 download grant가 없다" -- the
// same helper backs both paths, and only the caller tells them apart).
type preparedCertificate struct {
	Certificate     domain.Certificate
	KeyMaterialID   domain.KeyMaterialID
	GeneratedPublic domain.PublicKey        // zero when ref.Existing was used
	GeneratedSecret *domain.EncryptedSecret // nil when ref.Existing was used
}

// resolveSigningKey turns ref into a concrete key identity, generating a
// fresh key through keyEngine when asked. It is split out from
// prepareCertificate/signCertificate below so a caller that must retry only
// the signing half (a serial collision, see IssuanceService.Issue) does not
// generate a second, unused key pair on every retry -- key resolution runs
// once per attempt, signing can run several times against the same key.
func resolveSigningKey(ctx context.Context, keyEngine port.KeyEngine, ref signingKeyRef) (domain.KeyMaterialID, domain.PublicKey, *domain.EncryptedSecret, error) {
	switch {
	case ref.Fresh != nil:
		generated, err := keyEngine.Generate(ctx, *ref.Fresh)
		if err != nil {
			return "", domain.PublicKey{}, nil, contract.WrapAppError(contract.ErrorKindUnavailable, "issuance_key_generate_failed",
				"could not generate a new key", err)
		}
		secret := generated.EncryptedSecret
		return ref.Fresh.KeyMaterialID, generated.PublicKey, &secret, nil
	case ref.Existing != "":
		return ref.Existing, domain.PublicKey{}, nil, nil
	default:
		return "", domain.PublicKey{}, nil, contract.NewAppError(contract.ErrorKindValidation, "issuance_key_ref_missing",
			"prepareCertificate requires a fresh or existing key reference")
	}
}

// signCertificate signs request and verifies that what came back is what
// was asked for.
//
// docs/backend-implementation.md §14.10 settles what used to be a gap here.
// The request now carries the subject public key, the chosen identifiers and
// the serial, and the signer returns a certificate that must agree with
// them: "app은 반환 ID/serial/issuer/window/subject/SAN/kind/profile/
// algorithm이 요청과 일치하는지 검사하고 불일치는 오류로 처리한다. 반환
// DER에 관계없는 metadata를 다시 조립해 성공으로 만들지 않는다." So nothing
// is rebuilt here -- a mismatch is an error, not something to paper over.
func signCertificate(
	ctx context.Context,
	signer port.CertificateSigner,
	request port.CertificateSigningRequest,
	issuerKey domain.EncryptedSecret,
) (domain.Certificate, error) {
	signed, err := signer.Sign(ctx, request, issuerKey)
	if err != nil {
		return domain.Certificate{}, contract.WrapAppError(contract.ErrorKindUnavailable, "issuance_sign_failed",
			"could not sign the certificate", err)
	}
	if err := verifySignedCertificate(request, signed); err != nil {
		return domain.Certificate{}, err
	}
	return signed, nil
}

// verifySignedCertificate compares every field §14.10 names. A failure is
// unavailable rather than validation: the request itself was well-formed,
// the signing adapter misbehaved.
func verifySignedCertificate(request port.CertificateSigningRequest, signed domain.Certificate) error {
	mismatch := func(field string) error {
		return contract.NewAppError(contract.ErrorKindUnavailable, "issuance_signed_certificate_mismatch",
			"the signer returned a certificate that does not match the request").WithField("field", field)
	}
	switch {
	case signed.ID() != request.CertificateID:
		return mismatch("certificate_id")
	case signed.KeyMaterialID() != request.KeyMaterialID:
		return mismatch("key_material_id")
	case !signed.Serial().Equal(request.Serial):
		return mismatch("serial")
	case signed.IssuerCAKeyGenerationID() != request.Plan.IssuerKeyGenerationID:
		return mismatch("issuer_ca_key_generation_id")
	case signed.Kind() != request.Kind:
		return mismatch("kind")
	case signed.Profile() != request.Plan.Profile:
		return mismatch("profile")
	case signed.KeyAlgorithm() != request.Plan.KeyAlgorithm:
		return mismatch("key_algorithm")
	case !sameWindow(signed.Validity(), request.Plan.Window):
		return mismatch("validity")
	case !sameSubject(signed.Subject(), request.Plan.Subject):
		return mismatch("subject")
	case !sameSANs(signed.SANs(), request.Plan.SANs):
		return mismatch("sans")
	case len(signed.DER()) == 0:
		return mismatch("der")
	}
	return nil
}

func sameWindow(a, b domain.ValidityWindow) bool {
	return a.NotBefore().Equal(b.NotBefore()) && a.NotAfter().Equal(b.NotAfter())
}

func sameSubject(a, b domain.Subject) bool {
	return a.CommonName() == b.CommonName() &&
		a.Organization() == b.Organization() &&
		a.OrganizationalUnit() == b.OrganizationalUnit() &&
		a.Country() == b.Country()
}

// sameSANs compares order-sensitively: the plan's SAN order is the order the
// signer was asked to embed, so a reordered result is a different
// certificate from the one requested, not an equivalent one.
func sameSANs(a, b []domain.SAN) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type() != b[i].Type() || a[i].Value() != b[i].Value() {
			return false
		}
	}
	return true
}

// prepareCertificate is the common transaction-free signing step
// docs/backend-implementation.md §5 assigns Authority, Issuance and TLS to
// share ("인증서 서명 공통 함수는 prepareCertificate(plan, keyRef)로 두고
// Authority/Issuance/TLS가 사용한다"): resolve a key (generate or reuse),
// mint a serial, then sign and verify. Internal TLS issuance must call this
// directly rather than going through IssuanceService (§5 "내부 TLS 발급이
// 일반 Leaf 발급 서비스를 호출해 delivery를 만든 뒤 삭제하는 방식은
// 금지한다"), and §14.10 requires it to use the same SerialGenerator.
//
// A caller that needs a limited number of re-signs after a serial collision
// (§8 "충돌은 같은 요청 ID로 새 serial을 만들어 제한 재준비할 수 있다")
// should keep the resolved key and call signCertificate again with a new
// serial, so a collision retry never re-generates an unused second key pair.
func prepareCertificate(
	ctx context.Context,
	keyEngine port.KeyEngine,
	signer port.CertificateSigner,
	serials port.SerialGenerator,
	plan domain.IssuancePlan,
	ref signingKeyRef,
	existingPublicKey domain.PublicKey,
	certificateID domain.CertificateID,
	issuerCertificate domain.Certificate,
	issuerKey domain.EncryptedSecret,
	kind domain.CertificateKind,
	createdBy domain.AccountID,
	crlDistributionPoints []string,
) (preparedCertificate, error) {
	keyMaterialID, publicKey, generatedSecret, err := resolveSigningKey(ctx, keyEngine, ref)
	if err != nil {
		return preparedCertificate{}, err
	}
	subjectPublicKey := publicKey
	if ref.Fresh == nil {
		// A reuse renewal certifies the key material's stored public half;
		// §14.10 is explicit that this never requires the leaf private key.
		subjectPublicKey = existingPublicKey
	}
	serial, err := newSerial(ctx, serials)
	if err != nil {
		return preparedCertificate{}, err
	}
	cert, err := signCertificate(ctx, signer, port.CertificateSigningRequest{
		Plan:                  plan,
		CertificateID:         certificateID,
		KeyMaterialID:         keyMaterialID,
		SubjectPublicKey:      subjectPublicKey,
		Serial:                serial,
		Kind:                  kind,
		CreatedByAccountID:    createdBy,
		IssuerCertificate:     issuerCertificate,
		CRLDistributionPoints: crlDistributionPoints,
	}, issuerKey)
	if err != nil {
		return preparedCertificate{}, err
	}
	return preparedCertificate{
		Certificate:     cert,
		KeyMaterialID:   keyMaterialID,
		GeneratedPublic: publicKey,
		GeneratedSecret: generatedSecret,
	}, nil
}

// newSerial mints one cryptographically random serial before signing
// (§14.10; docs/certificate-lifecycle.md "일련번호는 암호학적 난수로 생성").
func newSerial(ctx context.Context, serials port.SerialGenerator) (domain.SerialNumber, error) {
	serial, err := serials.NewSerial(ctx)
	if err != nil {
		return domain.SerialNumber{}, contract.WrapAppError(contract.ErrorKindUnavailable, "issuance_serial_generate_failed",
			"could not generate a certificate serial", err)
	}
	if serial.IsZero() {
		return domain.SerialNumber{}, contract.NewAppError(contract.ErrorKindUnavailable, "issuance_serial_generate_failed",
			"the serial generator produced an empty serial")
	}
	return serial, nil
}
