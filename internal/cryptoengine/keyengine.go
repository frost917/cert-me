package cryptoengine

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"cert-me/internal/app/port"
	"cert-me/internal/cryptowork"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

const (
	secretFormatVersion = 1
	secretNonceSize     = 12
)

// KeyEngine implements port.KeyEngine without returning or retaining private
// key plaintext. Its key-encryption keys are owned by ring.
type KeyEngine struct {
	ring *KeyRing
}

var _ port.KeyEngine = (*KeyEngine)(nil)

// NewKeyEngine binds a key engine to an open key ring.
func NewKeyEngine(ring *KeyRing) (*KeyEngine, error) {
	if ring == nil {
		return nil, errors.New("cryptoengine: key ring is required")
	}
	if err := ring.withActiveKey(func(string, []byte) error { return nil }); err != nil {
		return nil, err
	}
	return &KeyEngine{ring: ring}, nil
}

// Generate creates a key pair for spec and encrypts its PKCS#8 representation
// under the active generation key.
func (e *KeyEngine) Generate(ctx context.Context, spec port.KeySpec) (port.GeneratedKey, error) {
	if err := checkContext(ctx); err != nil {
		return port.GeneratedKey{}, err
	}
	if err := validateSpec(spec, false); err != nil {
		return port.GeneratedKey{}, err
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return port.GeneratedKey{}, err
	}
	defer release()
	privateKey, err := generatePrivateKey(spec.Algorithm)
	if err != nil {
		return port.GeneratedKey{}, err
	}
	defer clearPrivateKey(privateKey)

	publicKey, err := publicKeyFor(privateKey, spec.Algorithm)
	if err != nil {
		return port.GeneratedKey{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return port.GeneratedKey{}, errors.New("cryptoengine: private key encoding failed")
	}
	defer zero(privateDER)
	if err := checkContext(ctx); err != nil {
		return port.GeneratedKey{}, err
	}
	encrypted, err := e.encryptActive(ctx, spec.KeyMaterialID, spec.Purpose, privateDER)
	if err != nil {
		return port.GeneratedKey{}, err
	}
	return port.GeneratedKey{PublicKey: publicKey, EncryptedSecret: encrypted}, nil
}

// ImportCA synchronously parses, verifies and encrypts a caller-owned CA key.
// The private Input is neither retained nor copied beyond this call.
func (e *KeyEngine) ImportCA(ctx context.Context, input port.ValidatedCAKeyInput, spec port.KeySpec) (port.GeneratedKey, error) {
	if err := checkContext(ctx); err != nil {
		return port.GeneratedKey{}, err
	}
	if err := validateSpec(spec, false); err != nil {
		return port.GeneratedKey{}, err
	}
	if spec.Purpose != domain.SecretPurposeCASigning && spec.Purpose != domain.SecretPurposeBootstrapCA {
		return port.GeneratedKey{}, errors.New("cryptoengine: CA import purpose is not allowed")
	}
	if input.Algorithm != spec.Algorithm {
		return port.GeneratedKey{}, errors.New("cryptoengine: imported key algorithm does not match specification")
	}
	return e.importKey(ctx, input.PrivateKey, input.Algorithm, input.PublicKey, spec)
}

// ImportTLS synchronously parses, verifies and encrypts an internal TLS key.
// The private Input is neither retained nor copied beyond this call.
func (e *KeyEngine) ImportTLS(ctx context.Context, input port.ValidatedTLSKeyInput, spec port.KeySpec) (port.GeneratedKey, error) {
	if err := checkContext(ctx); err != nil {
		return port.GeneratedKey{}, err
	}
	if err := validateSpec(spec, false); err != nil {
		return port.GeneratedKey{}, err
	}
	if spec.Purpose != domain.SecretPurposeInternalTLS {
		return port.GeneratedKey{}, errors.New("cryptoengine: TLS import purpose is not allowed")
	}
	if input.Algorithm != spec.Algorithm {
		return port.GeneratedKey{}, errors.New("cryptoengine: imported key algorithm does not match specification")
	}
	return e.importKey(ctx, input.PrivateKey, input.Algorithm, input.PublicKey, spec)
}

func (e *KeyEngine) importKey(ctx context.Context, input *secret.Input, algorithm domain.KeyAlgorithm, expectedPublic domain.PublicKey, spec port.KeySpec) (port.GeneratedKey, error) {
	if input == nil {
		return port.GeneratedKey{}, errors.New("cryptoengine: imported private key is required")
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return port.GeneratedKey{}, err
	}
	defer release()
	if algorithm.Validate() != nil || expectedPublic.IsZero() || expectedPublic.Algorithm() != algorithm {
		return port.GeneratedKey{}, errors.New("cryptoengine: imported key facts are invalid")
	}
	var result port.GeneratedKey
	err = input.Use(func(encoded []byte) error {
		if err := checkContext(ctx); err != nil {
			return err
		}
		privateKey, err := parsePrivateKey(encoded)
		if err != nil {
			return errors.New("cryptoengine: imported private key is invalid")
		}
		defer clearPrivateKey(privateKey)

		publicKey, err := publicKeyFor(privateKey, algorithm)
		if err != nil {
			return err
		}
		if !publicKey.Equal(expectedPublic) {
			return errors.New("cryptoengine: imported private key does not match supplied public key")
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return errors.New("cryptoengine: imported private key encoding failed")
		}
		defer zero(privateDER)
		if err := checkContext(ctx); err != nil {
			return err
		}
		encrypted, err := e.encryptActive(ctx, spec.KeyMaterialID, spec.Purpose, privateDER)
		if err != nil {
			return err
		}
		result = port.GeneratedKey{PublicKey: publicKey, EncryptedSecret: encrypted}
		return nil
	})
	if err != nil {
		return port.GeneratedKey{}, err
	}
	return result, nil
}

// Reencrypt authenticates the source ciphertext and moves it to the requested
// generation with a fresh nonce.
func (e *KeyEngine) Reencrypt(ctx context.Context, encrypted domain.EncryptedSecret, keys port.RotationKeys) (domain.EncryptedSecret, error) {
	if err := checkContext(ctx); err != nil {
		return domain.EncryptedSecret{}, err
	}
	if encrypted.IsZero() || !validGenerationID(keys.SourceGenerationID) || !validGenerationID(keys.TargetGenerationID) {
		return domain.EncryptedSecret{}, errors.New("cryptoengine: encrypted secret or generation is invalid")
	}
	if encrypted.EncryptionGenerationID() != keys.SourceGenerationID {
		return domain.EncryptedSecret{}, errors.New("cryptoengine: source generation does not match encrypted secret")
	}
	if err := validateOwnerPurpose(encrypted.OwnerKeyID(), encrypted.Purpose()); err != nil {
		return domain.EncryptedSecret{}, err
	}
	if encrypted.FormatVersion() != secretFormatVersion {
		return domain.EncryptedSecret{}, errors.New("cryptoengine: encrypted secret format is unsupported")
	}
	nonce := encrypted.Nonce()
	ciphertext := encrypted.Ciphertext()
	defer zero(nonce)
	defer zero(ciphertext)
	if len(nonce) != secretNonceSize {
		return domain.EncryptedSecret{}, errors.New("cryptoengine: encrypted secret nonce is invalid")
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return domain.EncryptedSecret{}, err
	}
	defer release()

	var result domain.EncryptedSecret
	err = e.ring.withGenerationKeys(keys.SourceGenerationID, keys.TargetGenerationID, func(sourceKey, targetKey []byte) error {
		plaintext, err := openSecret(sourceKey, encrypted.OwnerKeyID(), encrypted.Purpose(), encrypted.FormatVersion(), keys.SourceGenerationID, nonce, ciphertext)
		if err != nil {
			return err
		}
		defer zero(plaintext)
		if err := checkContext(ctx); err != nil {
			return err
		}
		result, err = sealSecret(targetKey, encrypted.OwnerKeyID(), encrypted.Purpose(), secretFormatVersion, keys.TargetGenerationID, plaintext)
		return err
	})
	if err != nil {
		return domain.EncryptedSecret{}, err
	}
	return result, nil
}

func (e *KeyEngine) encryptActive(ctx context.Context, owner domain.KeyMaterialID, purpose domain.SecretPurpose, plaintext []byte) (domain.EncryptedSecret, error) {
	if err := validateOwnerPurpose(owner, purpose); err != nil {
		return domain.EncryptedSecret{}, err
	}
	if err := checkContext(ctx); err != nil {
		return domain.EncryptedSecret{}, err
	}
	var result domain.EncryptedSecret
	err := e.ring.withActiveKey(func(generationID string, key []byte) error {
		var err error
		result, err = sealSecret(key, owner, purpose, secretFormatVersion, generationID, plaintext)
		return err
	})
	if err != nil {
		return domain.EncryptedSecret{}, err
	}
	return result, nil
}

func validateSpec(spec port.KeySpec, allowStoreVerifier bool) error {
	if _, err := domain.ParseKeyMaterialID(string(spec.KeyMaterialID)); err != nil {
		return errors.New("cryptoengine: key material id is invalid")
	}
	if err := spec.Algorithm.Validate(); err != nil {
		return errors.New("cryptoengine: key algorithm is unsupported")
	}
	if err := spec.Purpose.Validate(); err != nil {
		return errors.New("cryptoengine: secret purpose is unsupported")
	}
	if spec.Purpose == domain.SecretPurposeStoreVerifier {
		if !allowStoreVerifier || spec.KeyMaterialID != domain.StoreVerifierOwnerKeyID {
			return errors.New("cryptoengine: store verifier purpose is not valid for a private key")
		}
		return nil
	}
	if spec.KeyMaterialID == domain.StoreVerifierOwnerKeyID {
		return errors.New("cryptoengine: reserved owner id is only valid for the store verifier")
	}
	return nil
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("cryptoengine: context is required")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cryptoengine: operation canceled: %w", err)
	}
	return nil
}

func generatePrivateKey(algorithm domain.KeyAlgorithm) (any, error) {
	switch algorithm {
	case domain.KeyAlgorithmECDSAP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, errors.New("cryptoengine: ECDSA key generation failed")
		}
		return key, nil
	case domain.KeyAlgorithmECDSAP384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, errors.New("cryptoengine: ECDSA key generation failed")
		}
		return key, nil
	case domain.KeyAlgorithmRSA2048, domain.KeyAlgorithmRSA3072, domain.KeyAlgorithmRSA4096:
		bits := 0
		switch algorithm {
		case domain.KeyAlgorithmRSA2048:
			bits = 2048
		case domain.KeyAlgorithmRSA3072:
			bits = 3072
		case domain.KeyAlgorithmRSA4096:
			bits = 4096
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, errors.New("cryptoengine: RSA key generation failed")
		}
		return key, nil
	default:
		return nil, errors.New("cryptoengine: unsupported key algorithm")
	}
}

func parsePrivateKey(encoded []byte) (any, error) {
	key, err := x509.ParsePKCS8PrivateKey(encoded)
	if err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(encoded); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(encoded); err == nil {
		return key, nil
	}
	return nil, errors.New("cryptoengine: unsupported private key encoding")
}

func publicKeyFor(private any, expected domain.KeyAlgorithm) (domain.PublicKey, error) {
	actual, public := algorithmAndPublic(private)
	if actual == "" || actual != expected {
		return domain.PublicKey{}, errors.New("cryptoengine: private key algorithm does not match specification")
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return domain.PublicKey{}, errors.New("cryptoengine: public key encoding failed")
	}
	key, err := domain.NewPublicKey(actual, der)
	zero(der)
	if err != nil {
		return domain.PublicKey{}, errors.New("cryptoengine: public key facts are invalid")
	}
	return key, nil
}

func algorithmAndPublic(private any) (domain.KeyAlgorithm, any) {
	switch key := private.(type) {
	case *ecdsa.PrivateKey:
		if key == nil || key.Curve == nil || key.D == nil || key.X == nil || key.Y == nil {
			return "", nil
		}
		params := key.Curve.Params()
		if params == nil || params.N == nil || key.D.Sign() <= 0 || key.D.Cmp(params.N) >= 0 || !key.Curve.IsOnCurve(key.X, key.Y) {
			return "", nil
		}
		x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
		if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
			return "", nil
		}
		switch params.Name {
		case "P-256":
			if key.Curve != elliptic.P256() {
				return "", nil
			}
			return domain.KeyAlgorithmECDSAP256, &key.PublicKey
		case "P-384":
			if key.Curve != elliptic.P384() {
				return "", nil
			}
			return domain.KeyAlgorithmECDSAP384, &key.PublicKey
		default:
			return "", nil
		}
	case *rsa.PrivateKey:
		if key == nil || key.N == nil || key.D == nil || key.E < 3 || key.E%2 == 0 || key.Validate() != nil {
			return "", nil
		}
		switch key.N.BitLen() {
		case 2048:
			return domain.KeyAlgorithmRSA2048, &key.PublicKey
		case 3072:
			return domain.KeyAlgorithmRSA3072, &key.PublicKey
		case 4096:
			return domain.KeyAlgorithmRSA4096, &key.PublicKey
		default:
			return "", nil
		}
	default:
		return "", nil
	}
}

func clearPrivateKey(private any) {
	switch key := private.(type) {
	case *ecdsa.PrivateKey:
		if key != nil && key.D != nil {
			key.D.SetInt64(0)
		}
	case *rsa.PrivateKey:
		if key == nil {
			return
		}
		if key.D != nil {
			key.D.SetInt64(0)
		}
		for _, prime := range key.Primes {
			if prime != nil {
				prime.SetInt64(0)
			}
		}
		key.Primes = nil
		for _, value := range []*big.Int{key.Precomputed.Dp, key.Precomputed.Dq, key.Precomputed.Qinv} {
			if value != nil {
				value.SetInt64(0)
			}
		}
		for i := range key.Precomputed.CRTValues {
			crt := &key.Precomputed.CRTValues[i]
			if crt.Exp != nil {
				crt.Exp.SetInt64(0)
			}
			if crt.Coeff != nil {
				crt.Coeff.SetInt64(0)
			}
			if crt.R != nil {
				crt.R.SetInt64(0)
			}
		}
		key.Precomputed = rsa.PrecomputedValues{}
	}
}

func sealSecret(key []byte, owner domain.KeyMaterialID, purpose domain.SecretPurpose, format int, generation string, plaintext []byte) (domain.EncryptedSecret, error) {
	aad, err := associatedData(owner, purpose, format, generation)
	if err != nil {
		return domain.EncryptedSecret{}, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return domain.EncryptedSecret{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		zero(nonce)
		return domain.EncryptedSecret{}, errors.New("cryptoengine: nonce generation failed")
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	result, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID: owner, Purpose: purpose, FormatVersion: format,
		EncryptionGenerationID: generation, Nonce: nonce, Ciphertext: ciphertext,
	})
	zero(nonce)
	zero(ciphertext)
	if err != nil {
		return domain.EncryptedSecret{}, errors.New("cryptoengine: encrypted secret construction failed")
	}
	return result, nil
}

func openSecret(key []byte, owner domain.KeyMaterialID, purpose domain.SecretPurpose, format int, generation string, nonce, ciphertext []byte) ([]byte, error) {
	aad, err := associatedData(owner, purpose, format, generation)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() || len(ciphertext) < aead.Overhead() {
		return nil, errors.New("cryptoengine: encrypted secret encoding is invalid")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("cryptoengine: encrypted secret authentication failed")
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("cryptoengine: encryption key is unavailable")
	}
	aead, err := cipher.NewGCMWithNonceSize(block, secretNonceSize)
	if err != nil {
		return nil, errors.New("cryptoengine: authenticated encryption is unavailable")
	}
	return aead, nil
}

func associatedData(owner domain.KeyMaterialID, purpose domain.SecretPurpose, format int, generation string) ([]byte, error) {
	if err := validateOwnerPurpose(owner, purpose); err != nil {
		return nil, err
	}
	if format != secretFormatVersion || !validGenerationID(generation) {
		return nil, errors.New("cryptoengine: encrypted secret metadata is invalid")
	}
	namespace := "private_key_secrets"
	if purpose == domain.SecretPurposeStoreVerifier {
		namespace = "encryption_verifier"
	}
	data := []byte("cert-me/encrypted-secret/aad\x00")
	data = appendField(data, []byte(namespace))
	data = appendField(data, []byte(owner))
	data = appendField(data, []byte(purpose))
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], uint32(format))
	data = appendField(data, version[:])
	data = appendField(data, []byte(generation))
	return data, nil
}

func appendField(data, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	data = append(data, length[:]...)
	return append(data, value...)
}

func validateOwnerPurpose(owner domain.KeyMaterialID, purpose domain.SecretPurpose) error {
	if _, err := domain.ParseKeyMaterialID(string(owner)); err != nil {
		return errors.New("cryptoengine: secret owner id is invalid")
	}
	if err := purpose.Validate(); err != nil {
		return errors.New("cryptoengine: secret purpose is unsupported")
	}
	if purpose == domain.SecretPurposeStoreVerifier {
		if owner != domain.StoreVerifierOwnerKeyID {
			return errors.New("cryptoengine: store verifier owner id is invalid")
		}
	} else if owner == domain.StoreVerifierOwnerKeyID {
		return errors.New("cryptoengine: reserved owner id is only valid for the store verifier")
	}
	return nil
}
