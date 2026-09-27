package cryptoengine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

const (
	testOwnerID = domain.KeyMaterialID("11111111-1111-4111-8111-111111111111")
	testOtherID = domain.KeyMaterialID("22222222-2222-4222-8222-222222222222")
	testGenA    = "generation-a"
	testGenB    = "generation-b"
)

func testRing(t *testing.T, active string, generations map[string][]byte) *KeyRing {
	t.Helper()
	inputs := make(map[string]*secret.Input, len(generations))
	for id, key := range generations {
		inputs[id] = secret.New(append([]byte(nil), key...))
	}
	ring, err := NewKeyRing(active, inputs)
	for _, input := range inputs {
		_ = input.Close()
	}
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

func TestGenerateAndReencryptRoundTrip(t *testing.T) {
	keyA := make([]byte, encryptionKeySize)
	keyB := make([]byte, encryptionKeySize)
	for i := range keyA {
		keyA[i] = byte(i + 1)
		keyB[i] = byte(255 - i)
	}
	ring := testRing(t, testGenA, map[string][]byte{testGenA: keyA, testGenB: keyB})
	engine, err := NewKeyEngine(ring)
	if err != nil {
		t.Fatalf("NewKeyEngine: %v", err)
	}
	spec := port.KeySpec{KeyMaterialID: testOwnerID, Algorithm: domain.KeyAlgorithmECDSAP256, Purpose: domain.SecretPurposeLeafDelivery}
	generated, err := engine.Generate(context.Background(), spec)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if generated.PublicKey.IsZero() || generated.EncryptedSecret.IsZero() {
		t.Fatal("Generate returned an incomplete key")
	}
	if generated.EncryptedSecret.EncryptionGenerationID() != testGenA {
		t.Fatalf("generated secret generation = %q, want %q", generated.EncryptedSecret.EncryptionGenerationID(), testGenA)
	}
	if got := generated.EncryptedSecret.FormatVersion(); got != secretFormatVersion {
		t.Fatalf("format version = %d, want %d", got, secretFormatVersion)
	}

	moved, err := engine.Reencrypt(context.Background(), generated.EncryptedSecret, port.RotationKeys{SourceGenerationID: testGenA, TargetGenerationID: testGenB})
	if err != nil {
		t.Fatalf("Reencrypt to target: %v", err)
	}
	if moved.EncryptionGenerationID() != testGenB || moved.OwnerKeyID() != testOwnerID || moved.Purpose() != spec.Purpose {
		t.Fatalf("target metadata was not preserved: owner=%q purpose=%q generation=%q", moved.OwnerKeyID(), moved.Purpose(), moved.EncryptionGenerationID())
	}
	back, err := engine.Reencrypt(context.Background(), moved, port.RotationKeys{SourceGenerationID: testGenB, TargetGenerationID: testGenA})
	if err != nil {
		t.Fatalf("Reencrypt back: %v", err)
	}
	plain := openWithRing(t, ring, back)
	defer zero(plain)
	private, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		t.Fatalf("recovered PKCS#8: %v", err)
	}
	public, err := publicKeyFor(private, spec.Algorithm)
	clearPrivateKey(private)
	if err != nil {
		t.Fatalf("derive recovered public key: %v", err)
	}
	if !public.Equal(generated.PublicKey) {
		t.Fatal("re-encryption round trip changed the private key")
	}
}

func TestReencryptRejectsAADMetadataTampering(t *testing.T) {
	key := make([]byte, encryptionKeySize)
	for i := range key {
		key[i] = byte(73 + i)
	}
	// Both generation IDs intentionally use equal key bytes, so a changed
	// generation exercises the generation AAD field itself.
	ring := testRing(t, testGenA, map[string][]byte{testGenA: key, testGenB: key})
	engine, err := NewKeyEngine(ring)
	if err != nil {
		t.Fatal(err)
	}
	original, err := engine.Generate(context.Background(), port.KeySpec{
		KeyMaterialID: testOwnerID,
		Algorithm:     domain.KeyAlgorithmECDSAP256,
		Purpose:       domain.SecretPurposeLeafDelivery,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(domain.EncryptedSecret) domain.EncryptedSecret
	}{
		{
			name: "owner",
			mutate: func(value domain.EncryptedSecret) domain.EncryptedSecret {
				return replaceMetadata(t, value, testOtherID, value.Purpose(), value.EncryptionGenerationID())
			},
		},
		{
			name: "purpose",
			mutate: func(value domain.EncryptedSecret) domain.EncryptedSecret {
				return replaceMetadata(t, value, value.OwnerKeyID(), domain.SecretPurposeInternalTLS, value.EncryptionGenerationID())
			},
		},
		{
			name: "generation",
			mutate: func(value domain.EncryptedSecret) domain.EncryptedSecret {
				return replaceMetadata(t, value, value.OwnerKeyID(), value.Purpose(), testGenB)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			altered := test.mutate(original.EncryptedSecret)
			_, err := engine.Reencrypt(context.Background(), altered, port.RotationKeys{
				SourceGenerationID: altered.EncryptionGenerationID(),
				TargetGenerationID: testGenA,
			})
			if err == nil {
				t.Fatal("tampered metadata authenticated")
			}
		})
	}
}

func TestKeyPurposeConstraints(t *testing.T) {
	ring := testRing(t, testGenA, map[string][]byte{testGenA: make([]byte, encryptionKeySize)})
	engine, err := NewKeyEngine(ring)
	if err != nil {
		t.Fatal(err)
	}
	base := port.KeySpec{KeyMaterialID: testOwnerID, Algorithm: domain.KeyAlgorithmECDSAP256}

	base.Purpose = domain.SecretPurposeStoreVerifier
	if _, err := engine.Generate(context.Background(), base); err == nil {
		t.Fatal("Generate accepted store_verifier as a private-key purpose")
	}

	base.Purpose = domain.SecretPurposeInternalTLS
	if _, err := engine.ImportCA(context.Background(), port.ValidatedCAKeyInput{}, base); err == nil {
		t.Fatal("ImportCA accepted internal_tls purpose")
	}

	base.Purpose = domain.SecretPurposeBootstrapCA
	if _, err := engine.ImportTLS(context.Background(), port.ValidatedTLSKeyInput{}, base); err == nil {
		t.Fatal("ImportTLS accepted bootstrap_ca purpose")
	}
}

func TestImportRejectsSuppliedPublicKeyMismatch(t *testing.T) {
	ring := testRing(t, testGenA, map[string][]byte{testGenA: make([]byte, encryptionKeySize)})
	engine, err := NewKeyEngine(ring)
	if err != nil {
		t.Fatal(err)
	}
	privateA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearPrivateKey(privateA)
	defer clearPrivateKey(privateB)
	encoded, err := x509.MarshalPKCS8PrivateKey(privateA)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(encoded)
	wrongPublic, err := publicKeyFor(privateB, domain.KeyAlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	input := secret.New(append([]byte(nil), encoded...))
	defer input.Close()
	_, err = engine.ImportCA(context.Background(), port.ValidatedCAKeyInput{
		PrivateKey: input,
		Algorithm:  domain.KeyAlgorithmECDSAP256,
		PublicKey:  wrongPublic,
	}, port.KeySpec{
		KeyMaterialID: testOwnerID,
		Algorithm:     domain.KeyAlgorithmECDSAP256,
		Purpose:       domain.SecretPurposeCASigning,
	})
	if err == nil {
		t.Fatal("ImportCA accepted a private key whose public facts do not match")
	}
}

func TestKeyRingCopiesAndZerosKeysOnClose(t *testing.T) {
	inputBytes := make([]byte, encryptionKeySize)
	for i := range inputBytes {
		inputBytes[i] = byte(i + 10)
	}
	input := secret.New(inputBytes)
	ring, err := NewKeyRing(testGenA, map[string]*secret.Input{testGenA: input})
	if err != nil {
		t.Fatal(err)
	}
	owned := ring.keys[testGenA]
	if &owned[0] == &inputBytes[0] {
		t.Fatal("ring retained caller-owned key bytes")
	}
	if err := input.Close(); err != nil {
		t.Fatalf("close caller input: %v", err)
	}
	engine, err := NewKeyEngine(ring)
	if err != nil {
		t.Fatalf("caller input close invalidated copied key: %v", err)
	}
	if _, err := engine.Generate(context.Background(), port.KeySpec{
		KeyMaterialID: testOwnerID,
		Algorithm:     domain.KeyAlgorithmECDSAP256,
		Purpose:       domain.SecretPurposeLeafDelivery,
	}); err != nil {
		t.Fatalf("Generate after caller input close: %v", err)
	}
	if err := ring.Close(); err != nil {
		t.Fatalf("Close key ring: %v", err)
	}
	for i, value := range owned {
		if value != 0 {
			t.Fatalf("owned key byte %d was not zeroed", i)
		}
	}
	if _, err := NewKeyEngine(ring); err == nil {
		t.Fatal("NewKeyEngine accepted a closed key ring")
	}
}

func replaceMetadata(t *testing.T, value domain.EncryptedSecret, owner domain.KeyMaterialID, purpose domain.SecretPurpose, generation string) domain.EncryptedSecret {
	t.Helper()
	replaced, err := domain.NewEncryptedSecret(domain.EncryptedSecretFacts{
		OwnerKeyID:             owner,
		Purpose:                purpose,
		FormatVersion:          value.FormatVersion(),
		EncryptionGenerationID: generation,
		Nonce:                  value.Nonce(),
		Ciphertext:             value.Ciphertext(),
	})
	if err != nil {
		t.Fatalf("construct tampered ciphertext: %v", err)
	}
	return replaced
}

func openWithRing(t *testing.T, ring *KeyRing, value domain.EncryptedSecret) []byte {
	t.Helper()
	var plaintext []byte
	err := ring.withGenerationKeys(value.EncryptionGenerationID(), value.EncryptionGenerationID(), func(key, _ []byte) error {
		var err error
		plaintext, err = openSecret(key, value.OwnerKeyID(), value.Purpose(), value.FormatVersion(), value.EncryptionGenerationID(), value.Nonce(), value.Ciphertext())
		return err
	})
	if err != nil {
		t.Fatalf("open encrypted secret: %v", err)
	}
	return plaintext
}
