package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestUseGivesPlaintextThenCloseZeroes(t *testing.T) {
	buf := []byte("hunter2")
	in := New(buf)

	var seen string
	if err := in.Use(func(b []byte) error {
		seen = string(b)
		return nil
	}); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if seen != "hunter2" {
		t.Fatalf("Use saw %q, want %q", seen, "hunter2")
	}
	if in.Len() != 7 {
		t.Fatalf("Len = %d, want 7", in.Len())
	}

	if err := in.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatalf("owned buffer was not zeroed: %q", buf)
	}
}

func TestCloseIsIdempotentAndBlocksUse(t *testing.T) {
	in := FromString("secret")
	for i := 0; i < 3; i++ {
		if err := in.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i, err)
		}
	}
	if err := in.Use(func([]byte) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Use after Close = %v, want ErrClosed", err)
	}
	if in.Len() != 0 || !in.IsEmpty() {
		t.Fatalf("closed input reports Len=%d IsEmpty=%v", in.Len(), in.IsEmpty())
	}
}

func TestNilInputIsSafe(t *testing.T) {
	var in *Input
	if err := in.Close(); err != nil {
		t.Fatalf("Close on nil: %v", err)
	}
	if err := in.Use(func([]byte) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Use on nil = %v, want ErrClosed", err)
	}
	if !in.IsEmpty() {
		t.Fatal("nil input should be empty")
	}
}

func TestUsePropagatesCallbackError(t *testing.T) {
	in := FromString("x")
	defer in.Close()

	want := errors.New("adapter failed")
	if err := in.Use(func([]byte) error { return want }); !errors.Is(err, want) {
		t.Fatalf("Use = %v, want %v", err, want)
	}
}

// Every textual and structured output path must be redacted.
func TestAllOutputPathsAreRedacted(t *testing.T) {
	const plaintext = "top-secret-token"
	in := FromString(plaintext)
	defer in.Close()

	renders := map[string]string{
		"String":   in.String(),
		"GoString": fmt.Sprintf("%#v", in),
		"verb-s":   fmt.Sprintf("%s", in),
		"verb-q":   fmt.Sprintf("%q", in),
		"verb-v":   fmt.Sprintf("%v", in),
		"verb-x":   fmt.Sprintf("%x", in),
		"struct":   fmt.Sprintf("%v", struct{ Password *Input }{in}),
	}
	for name, got := range renders {
		if strings.Contains(got, plaintext) {
			t.Errorf("%s leaked the plaintext: %s", name, got)
		}
		if !strings.Contains(got, "redacted") {
			t.Errorf("%s = %s, want a redacted marker", name, got)
		}
	}
}

func TestSlogOutputIsRedacted(t *testing.T) {
	const plaintext = "log-me-not"
	in := FromString(plaintext)
	defer in.Close()

	var sink bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&sink, nil))
	logger.Info("login", "password", in)

	if strings.Contains(sink.String(), plaintext) {
		t.Fatalf("slog leaked the plaintext: %s", sink.String())
	}
}

func TestJSONMarshalIsRefused(t *testing.T) {
	in := FromString("nope")
	defer in.Close()

	if _, err := json.Marshal(in); err == nil {
		t.Fatal("json.Marshal succeeded, want an error")
	}
	// A command holding a secret must fail as a whole, not silently omit it.
	type command struct {
		Name     string `json:"name"`
		Password *Input `json:"password"`
	}
	if _, err := json.Marshal(command{Name: "admin", Password: in}); err == nil {
		t.Fatal("marshalling a command with a secret succeeded, want an error")
	}
	if _, err := in.MarshalText(); !errors.Is(err, ErrNotSerializable) {
		t.Fatalf("MarshalText = %v, want ErrNotSerializable", err)
	}
}

func TestJSONUnmarshalIsRefused(t *testing.T) {
	var target struct {
		Password *Input `json:"password"`
	}
	if err := json.Unmarshal([]byte(`{"password":"from-body"}`), &target); err == nil {
		t.Fatal("decoding a secret from a JSON body succeeded, want an error")
	}
}

func TestReadAllEnforcesLimit(t *testing.T) {
	in, err := ReadAll(strings.NewReader("1234567890"), 10)
	if err != nil {
		t.Fatalf("ReadAll at the limit: %v", err)
	}
	if in.Len() != 10 {
		t.Fatalf("Len = %d, want 10", in.Len())
	}
	_ = in.Close()

	if _, err := ReadAll(strings.NewReader("12345678901"), 10); err == nil {
		t.Fatal("ReadAll over the limit succeeded, want an error")
	}
	if _, err := ReadAll(strings.NewReader("x"), 0); err == nil {
		t.Fatal("ReadAll with a non-positive limit succeeded, want an error")
	}
}

func TestCloseAllSkipsNils(t *testing.T) {
	a, b := FromString("a"), FromString("b")
	CloseAll(a, nil, b)
	for i, in := range []*Input{a, b} {
		if err := in.Use(func([]byte) error { return nil }); !errors.Is(err, ErrClosed) {
			t.Fatalf("input %d not closed: %v", i, err)
		}
	}
}
