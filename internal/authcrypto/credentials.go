// Package authcrypto contains concrete credential primitives for services.
package authcrypto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"cert-me/internal/app/port"
	"cert-me/internal/cryptowork"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
	"golang.org/x/crypto/argon2"
)

const (
	passwordMemoryKiB = 64 * 1024
	passwordRounds    = 3
	passwordThreads   = 1
	passwordSaltBytes = 16
	passwordHashBytes = 32
	maxPasswordBytes  = 1024
	tokenBytes        = 32
)

type PasswordHasher struct{}

var _ port.PasswordHasher = PasswordHasher{}

// Hash stores the fixed Argon2id v19 profile and a fresh 16-byte salt.
func (PasswordHasher) Hash(ctx context.Context, password *secret.Input) (domain.PasswordHash, error) {
	if err := checkContext(ctx); err != nil {
		return domain.PasswordHash{}, err
	}
	if password == nil {
		return domain.PasswordHash{}, errors.New("authcrypto: password is required")
	}
	release, err := cryptowork.TryAcquire(ctx)
	if err != nil {
		return domain.PasswordHash{}, err
	}
	defer release()

	var encoded string
	err = password.Use(func(cleartext []byte) error {
		if len(cleartext) == 0 || len(cleartext) > maxPasswordBytes {
			return errors.New("authcrypto: password length is invalid")
		}
		salt := make([]byte, passwordSaltBytes)
		defer zero(salt)
		if _, err := rand.Read(salt); err != nil {
			return errors.New("authcrypto: password salt generation failed")
		}
		derived := argon2.IDKey(cleartext, salt, passwordRounds, passwordMemoryKiB, passwordThreads, passwordHashBytes)
		defer zero(derived)
		encoded = formatPasswordHash(salt, derived)
		return nil
	})
	if err != nil {
		return domain.PasswordHash{}, err
	}
	if err := checkContext(ctx); err != nil {
		return domain.PasswordHash{}, err
	}
	hash, err := domain.NewPasswordHash(encoded)
	if err != nil {
		return domain.PasswordHash{}, errors.New("authcrypto: encoded password hash is invalid")
	}
	return hash, nil
}

// Verify accepts only the exact supported Argon2id profile, so stored
// parameters cannot amplify work beyond the fixed 64 MiB, three-round cost.
func (PasswordHasher) Verify(ctx context.Context, password *secret.Input, hash domain.PasswordHash) (bool, error) {
	if err := checkContext(ctx); err != nil {
		return false, err
	}
	if password == nil || hash.IsZero() {
		return false, errors.New("authcrypto: password and hash are required")
	}
	salt, expected, err := parsePasswordHash(hash.Encoded())
	if err != nil {
		return false, errors.New("authcrypto: stored password hash is unsupported")
	}
	defer zero(salt)
	defer zero(expected)
	release, err := cryptowork.TryAcquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()

	var matches bool
	err = password.Use(func(cleartext []byte) error {
		if len(cleartext) == 0 || len(cleartext) > maxPasswordBytes {
			return errors.New("authcrypto: password length is invalid")
		}
		derived := argon2.IDKey(cleartext, salt, passwordRounds, passwordMemoryKiB, passwordThreads, passwordHashBytes)
		defer zero(derived)
		matches = subtle.ConstantTimeCompare(derived, expected) == 1
		return nil
	})
	if err != nil {
		return false, err
	}
	if err := checkContext(ctx); err != nil {
		return false, err
	}
	return matches, nil
}

func formatPasswordHash(salt, derived []byte) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		passwordMemoryKiB, passwordRounds, passwordThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived))
}

func parsePasswordHash(encoded string) ([]byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, nil, errors.New("invalid Argon2id hash header")
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 || parameters[0] != "m=65536" || parameters[1] != "t=3" || parameters[2] != "p=1" {
		return nil, nil, errors.New("unsupported Argon2id parameters")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != passwordSaltBytes {
		zero(salt)
		return nil, nil, errors.New("invalid Argon2id salt")
	}
	derived, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(derived) != passwordHashBytes {
		zero(salt)
		zero(derived)
		return nil, nil, errors.New("invalid Argon2id output")
	}
	return salt, derived, nil
}

type TokenCodec struct{}

var _ port.TokenCodec = TokenCodec{}

// NewToken returns a 32-byte random bearer token encoded as unpadded base64url
// and the SHA-256 hash of the underlying random bytes.
func (TokenCodec) NewToken(ctx context.Context) (*secret.Input, domain.TokenHash, error) {
	if err := checkContext(ctx); err != nil {
		return nil, domain.TokenHash{}, err
	}
	material := make([]byte, tokenBytes)
	if _, err := rand.Read(material); err != nil {
		zero(material)
		return nil, domain.TokenHash{}, errors.New("authcrypto: token generation failed")
	}
	digest := sha256.Sum256(material)
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(material)))
	base64.RawURLEncoding.Encode(encoded, material)
	zero(material)
	if err := checkContext(ctx); err != nil {
		zero(encoded)
		return nil, domain.TokenHash{}, err
	}
	hash, err := domain.ParseTokenHash(hex.EncodeToString(digest[:]))
	zero(digest[:])
	if err != nil {
		zero(encoded)
		return nil, domain.TokenHash{}, errors.New("authcrypto: token hash construction failed")
	}
	return secret.New(encoded), hash, nil
}

// Hash validates the canonical unpadded base64url token shape and hashes the
// decoded 32-byte value without retaining the supplied input.
func (TokenCodec) Hash(ctx context.Context, token *secret.Input) (domain.TokenHash, error) {
	if err := checkContext(ctx); err != nil {
		return domain.TokenHash{}, err
	}
	if token == nil {
		return domain.TokenHash{}, errors.New("authcrypto: token is required")
	}
	var result domain.TokenHash
	err := token.Use(func(encoded []byte) error {
		var raw [tokenBytes]byte
		defer zero(raw[:])
		if len(encoded) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
			return errors.New("authcrypto: token encoding is invalid")
		}
		decodedLength, err := base64.RawURLEncoding.Strict().Decode(raw[:], encoded)
		if err != nil || decodedLength != tokenBytes {
			return errors.New("authcrypto: token encoding is invalid")
		}
		digest := sha256.Sum256(raw[:])
		defer zero(digest[:])
		result, err = domain.ParseTokenHash(hex.EncodeToString(digest[:]))
		return err
	})
	if err != nil {
		return domain.TokenHash{}, err
	}
	if err := checkContext(ctx); err != nil {
		return domain.TokenHash{}, err
	}
	return result, nil
}

type SerialGenerator struct{}

var _ port.SerialGenerator = SerialGenerator{}

// NewSerial generates a positive 159-bit serial, leaving the high bit clear
// so the positive DER INTEGER stays within the 20-octet X.509 limit.
func (SerialGenerator) NewSerial(ctx context.Context) (domain.SerialNumber, error) {
	if err := checkContext(ctx); err != nil {
		return domain.SerialNumber{}, err
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return domain.SerialNumber{}, errors.New("authcrypto: serial generation failed")
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	if err := checkContext(ctx); err != nil {
		return domain.SerialNumber{}, err
	}
	value, err := domain.NewSerialNumberFromBig(serial)
	if err != nil {
		return domain.SerialNumber{}, errors.New("authcrypto: generated serial is invalid")
	}
	return value, nil
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("authcrypto: context is required")
	}
	return ctx.Err()
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
