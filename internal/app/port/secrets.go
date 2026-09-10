package port

import (
	"context"

	"cert-me/internal/domain"
)

// SecretRepository is the storage boundary for encrypted private-key
// ciphertext and the store-wide decryption verifier
// (docs/backend-implementation.md §4 table row "SecretRepository";
// docs/data-model.md "공개키와 암호화된 개인키"). It only ever stores and
// returns domain.EncryptedSecret, the AAD-bound value type -- there is no
// method that accepts or returns plaintext, matching backend-
// implementation.md §6's "평문 키가 app에 반환되지 않는다".
type SecretRepository interface {
	// GetEncrypted returns the encrypted secret for (keyID, purpose). It
	// returns ErrNotFound when no such secret exists -- e.g. after the key
	// has been destroyed or delivered (docs/data-model.md "CA 키 파기나
	// 수령 완료는 secret 행을 삭제하되 key_material·인증서·계보는 보존").
	GetEncrypted(ctx context.Context, keyID domain.KeyMaterialID, purpose domain.SecretPurpose) (domain.EncryptedSecret, error)

	// InsertEncrypted stores a brand-new secret row (private_key_secrets is
	// keyed by key_material_id, so a key material has at most one secret
	// row at a time).
	InsertEncrypted(ctx context.Context, secret domain.EncryptedSecret) error

	// Delete removes the secret row for (keyID, purpose), the CA-destroy and
	// delivery-consume cleanup step. It is idempotent: deleting an
	// already-gone secret is not an error.
	Delete(ctx context.Context, keyID domain.KeyMaterialID, purpose domain.SecretPurpose) error

	// ListEncrypted returns every stored secret, the full set
	// MaintenanceService.Rotate re-encrypts under a new encryption
	// generation in one UnitOfWork (docs/backend-implementation.md §9
	// "외부 Secret 파일을 변경하지 않고 UoW 하나로 암호문·verifier·키 세대를
	// 바꾼다").
	ListEncrypted(ctx context.Context) ([]domain.EncryptedSecret, error)

	// ReplaceEncrypted overwrites the existing secret row for the same
	// owner key material with a re-encrypted value (KeyEngine.Reencrypt's
	// output during rotate). Unlike InsertEncrypted it targets a row that is
	// already known to exist.
	ReplaceEncrypted(ctx context.Context, secret domain.EncryptedSecret) error

	// GetVerifier returns the fixed-PK=1 encryption_verifier row, used to
	// confirm an injected decryption key is the right one even on a database
	// with no private keys stored yet (docs/data-model.md "개인키가 없는 DB도
	// 주입 키 인증 복호화를 검사"). It returns ErrNotFound before the first
	// verifier has ever been written.
	GetVerifier(ctx context.Context) (domain.EncryptedSecret, error)

	// SaveVerifier writes the verifier row (insert on first use, replace on
	// rotate). There is exactly one verifier row, so this method covers both
	// cases rather than splitting into Insert/Replace the way the leaf
	// secret store does.
	SaveVerifier(ctx context.Context, verifier domain.EncryptedSecret) error
}
