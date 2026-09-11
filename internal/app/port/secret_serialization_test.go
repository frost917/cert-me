package port

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"cert-me/internal/secret"
)

// S1 (docs/backend-implementation.md B02 acceptance: "비밀 JSON/로그 차단"):
// EncodedBundle.Data was once a plaintext private-key bundle sitting behind
// a public []byte field, so json.Marshal, fmt and slog could all leak the
// raw key. CAKeyInput.Passphrase carries the same discipline: the
// passphrase, unlike the key ciphertext bytes it decrypts, is a secret the
// struct must never leak through Marshal/fmt/slog even while the
// surrounding CAKeyInput value is otherwise ordinary and printable.

const plaintextMarker = "TOTALLY-SECRET-PRIVATE-KEY-BYTES"

func TestEncodedBundle_NoPlaintextLeaksThroughFormattingOrJSON(t *testing.T) {
	bundle := NewEncodedBundle([]byte(plaintextMarker), "application/x-pem-file")
	defer bundle.Close()

	if _, err := json.Marshal(bundle); err == nil {
		t.Fatalf("json.Marshal(EncodedBundle) must fail, not silently base64-encode the key")
	}

	forms := []string{
		fmt.Sprintf("%v", bundle),
		fmt.Sprintf("%s", bundle),
		fmt.Sprintf("%#v", bundle),
		fmt.Sprintf("%q", bundle),
	}
	for _, s := range forms {
		if strings.Contains(s, plaintextMarker) {
			t.Fatalf("formatted output leaked plaintext: %q", s)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("bundle", "bundle", bundle)
	if strings.Contains(buf.String(), plaintextMarker) {
		t.Fatalf("slog output leaked plaintext: %q", buf.String())
	}
}

func TestEncodedBundle_UseGrantsAccessThenCloseZeroes(t *testing.T) {
	original := []byte(plaintextMarker)
	data := append([]byte(nil), original...)
	bundle := NewEncodedBundle(data, "application/x-pem-file")

	var seen []byte
	if err := bundle.Use(func(b []byte) error {
		seen = append(seen, b...)
		return nil
	}); err != nil {
		t.Fatalf("Use on an open bundle: %v", err)
	}
	if string(seen) != plaintextMarker {
		t.Fatalf("Use did not hand back the plaintext: got %q", seen)
	}

	bundle.Close()
	if err := bundle.Use(func([]byte) error { return nil }); err == nil {
		t.Fatalf("Use after Close must fail")
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed after Close: got %#x", i, b)
		}
	}
}

func TestCAKeyInput_PassphraseIsASecretInput(t *testing.T) {
	passphrase := secret.New([]byte(plaintextMarker))
	defer passphrase.Close()

	input := CAKeyInput{Data: []byte("not-the-secret"), Passphrase: passphrase}

	if _, err := json.Marshal(input); err == nil {
		t.Fatalf("json.Marshal(CAKeyInput) must fail while Passphrase is set")
	}
	s := fmt.Sprintf("%v %#v", input, input)
	if strings.Contains(s, plaintextMarker) {
		t.Fatalf("formatted CAKeyInput leaked plaintext: %q", s)
	}
}
