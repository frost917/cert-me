package porttest

import (
	"context"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type secretRepo struct{ s *state }

var _ port.SecretRepository = secretRepo{}

func (r secretRepo) GetEncrypted(_ context.Context, keyID domain.KeyMaterialID, purpose domain.SecretPurpose) (domain.EncryptedSecret, error) {
	enc, ok := r.s.secrets[secretKey{keyID: keyID, purpose: purpose}]
	if !ok {
		return domain.EncryptedSecret{}, port.ErrNotFound
	}
	return enc, nil
}

// InsertEncrypted refuses to replace an existing row: rotating a ciphertext
// goes through ReplaceEncrypted, so a mis-sequenced insert cannot silently
// drop the only copy of a key.
func (r secretRepo) InsertEncrypted(_ context.Context, enc domain.EncryptedSecret) error {
	key := secretKey{keyID: enc.OwnerKeyID(), purpose: enc.Purpose()}
	if _, ok := r.s.secrets[key]; ok {
		return ErrDuplicate
	}
	r.s.secrets[key] = enc
	return nil
}

func (r secretRepo) Delete(_ context.Context, keyID domain.KeyMaterialID, purpose domain.SecretPurpose) error {
	delete(r.s.secrets, secretKey{keyID: keyID, purpose: purpose})
	return nil
}

// ListEncrypted returns every stored ciphertext in a stable order, since
// MaintenanceService.Rotate walks the whole set in one transaction and a
// test asserting "every ciphertext moved generation" needs a deterministic
// sequence.
func (r secretRepo) ListEncrypted(_ context.Context) ([]domain.EncryptedSecret, error) {
	keys := make([]secretKey, 0, len(r.s.secrets))
	for k := range r.s.secrets {
		keys = append(keys, k)
	}
	sortSecretKeys(keys)
	out := make([]domain.EncryptedSecret, 0, len(keys))
	for _, k := range keys {
		out = append(out, r.s.secrets[k])
	}
	return out, nil
}

func (r secretRepo) ReplaceEncrypted(_ context.Context, enc domain.EncryptedSecret) error {
	key := secretKey{keyID: enc.OwnerKeyID(), purpose: enc.Purpose()}
	if _, ok := r.s.secrets[key]; !ok {
		return port.ErrNotFound
	}
	r.s.secrets[key] = enc
	return nil
}

func (r secretRepo) GetVerifier(_ context.Context) (domain.EncryptedSecret, error) {
	if !r.s.verifierSet {
		return domain.EncryptedSecret{}, port.ErrNotFound
	}
	return r.s.verifier, nil
}

func (r secretRepo) SaveVerifier(_ context.Context, verifier domain.EncryptedSecret) error {
	r.s.verifier = verifier
	r.s.verifierSet = true
	return nil
}
