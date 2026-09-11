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

// signCertificate signs plan against issuerKey and assembles the final
// domain.Certificate tied to keyMaterialID.
//
// Known contract gap (reported to the lead, not guessed around): neither
// domain.IssuancePlan nor port.CertificateSigner.Sign carries the
// certificate's own subject public key or storage id, so nothing on this
// side of the interface can literally tell a signer which SPKI to embed, and
// the signer has no channel to hand back a caller-chosen CertificateID or
// KeyMaterialID either. This function therefore trusts the signer's
// returned domain.Certificate only for the facts that are genuinely its
// call -- DER and Serial, the cryptographic material and the
// randomly-chosen serial docs/certificate-lifecycle.md requires ("일련번호는
// 암호학적 난수로 생성") -- and rebuilds the rest (ID, KeyMaterialID,
// IssuerCAKeyGenerationID, Validity, Subject, SANs, Profile, KeyAlgorithm)
// from facts this function already knows to be correct, via
// domain.NewCertificate. See the B03 report for the exact citation; this is
// flagged for a domain.IssuancePlan/port.CertificateSigner ruling before B05
// builds a real adapter against it.
func signCertificate(
	ctx context.Context,
	signer port.CertificateSigner,
	ids port.IDGenerator,
	plan domain.IssuancePlan,
	issuerKey domain.EncryptedSecret,
	keyMaterialID domain.KeyMaterialID,
	kind domain.CertificateKind,
	createdBy domain.AccountID,
) (domain.Certificate, error) {
	signed, err := signer.Sign(ctx, plan, issuerKey)
	if err != nil {
		return domain.Certificate{}, contract.WrapAppError(contract.ErrorKindUnavailable, "issuance_sign_failed",
			"could not sign the certificate", err)
	}
	certID, err := domain.ParseCertificateID(ids.NewUUID())
	if err != nil {
		return domain.Certificate{}, contract.FromDomainError(err)
	}
	cert, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      certID,
		DER:                     signed.DER(),
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: plan.IssuerKeyGenerationID,
		Serial:                  signed.Serial(),
		Validity:                plan.Window,
		Subject:                 plan.Subject,
		SANs:                    plan.SANs,
		Kind:                    kind,
		Profile:                 plan.Profile,
		KeyAlgorithm:            plan.KeyAlgorithm,
		Origin:                  domain.CertificateOriginGenerated,
		CreatedByAccountID:      createdBy,
	})
	if err != nil {
		return domain.Certificate{}, contract.FromDomainError(err)
	}
	return cert, nil
}

// prepareCertificate is the common transaction-free signing step
// docs/backend-implementation.md §5 assigns Authority, Issuance and TLS to
// share ("인증서 서명 공통 함수는 prepareCertificate(plan, keyRef)로 두고
// Authority/Issuance/TLS가 사용한다"): resolve a key (generate or reuse),
// then sign. Internal TLS issuance must call this directly rather than
// going through IssuanceService (§5 "내부 TLS 발급이 일반 Leaf 발급
// 서비스를 호출해 delivery를 만든 뒤 삭제하는 방식은 금지한다").
//
// A caller that needs a limited number of re-signs after a serial collision
// (docs/backend-implementation.md §8 "충돌은 같은 요청 ID로 새 serial을
// 만들어 제한 재준비할 수 있다") should call resolveSigningKey once and
// signCertificate repeatedly instead of calling this composed helper again,
// so a collision retry never re-generates an unused second key pair.
func prepareCertificate(
	ctx context.Context,
	keyEngine port.KeyEngine,
	signer port.CertificateSigner,
	ids port.IDGenerator,
	plan domain.IssuancePlan,
	ref signingKeyRef,
	issuerKey domain.EncryptedSecret,
	kind domain.CertificateKind,
	createdBy domain.AccountID,
) (preparedCertificate, error) {
	keyMaterialID, publicKey, generatedSecret, err := resolveSigningKey(ctx, keyEngine, ref)
	if err != nil {
		return preparedCertificate{}, err
	}
	cert, err := signCertificate(ctx, signer, ids, plan, issuerKey, keyMaterialID, kind, createdBy)
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
