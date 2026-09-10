package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
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

// TestUseAllowsCallbackToTouchTheInput covers the deadlock the mutex used to
// cause: sync.Mutex is not reentrant, so holding it across the callback made
// the most natural spelling -- a deferred Close inside the callback -- block
// forever. The test would hang rather than fail if that came back, so it runs
// on its own goroutine with a deadline.
func TestUseAllowsCallbackToTouchTheInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		body func(in *Input, b []byte) error
	}{
		{"close inside callback", func(in *Input, _ []byte) error {
			defer in.Close()
			return nil
		}},
		{"len inside callback", func(in *Input, _ []byte) error {
			if in.Len() == 0 {
				return errors.New("unexpected empty input")
			}
			return nil
		}},
		{"nested use", func(in *Input, _ []byte) error {
			return in.Use(func([]byte) error { return nil })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := FromString("hunter2")
			defer in.Close()

			done := make(chan error, 1)
			go func() {
				done <- in.Use(func(b []byte) error { return tc.body(in, b) })
			}()

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Use: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Use deadlocked: the callback could not touch the Input")
			}
		})
	}
}

// TestReadAllDoesNotLeaveAnUnzeroedCopy checks that a secret larger than the
// old 4096-byte starting capacity is not copied into a discarded array that
// Close can never reach.
func TestReadAllDoesNotLeaveAnUnzeroedCopy(t *testing.T) {
	const size = 9000
	plaintext := bytes.Repeat([]byte("s"), size)

	in, err := ReadAll(bytes.NewReader(plaintext), size)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if in.Len() != size {
		t.Fatalf("Len = %d, want %d", in.Len(), size)
	}

	// One allocation at full capacity means no reallocation happened, so the
	// only array holding the plaintext is the one Close zeroes.
	var capacity int
	if err := in.Use(func(b []byte) error {
		capacity = cap(b)
		return nil
	}); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if capacity != size {
		t.Errorf("buffer capacity = %d, want exactly the limit %d; a different capacity means append reallocated and left a copy behind", capacity, size)
	}

	if err := in.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := in.Use(func([]byte) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Use after Close = %v, want ErrClosed", err)
	}
}

// TestConcurrentUseAndClose is the race the counted-callback design exists to
// prevent: Close zeroing the array while a callback reads it. Run under -race.
func TestConcurrentUseAndClose(t *testing.T) {
	const size = 1 << 20
	in, err := ReadAll(bytes.NewReader(bytes.Repeat([]byte("p"), size)), size)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = in.Use(func(b []byte) error {
			for round := 0; round < 200; round++ {
				var sum int
				for _, c := range b {
					sum += int(c)
				}
				_ = sum
			}
			return nil
		})
	}()
	go func() {
		defer wg.Done()
		if err := in.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	wg.Wait()

	// Whichever order they ran in, the Input ends up closed and cleared.
	if err := in.Use(func([]byte) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Use after the race = %v, want ErrClosed", err)
	}
	if in.Len() != 0 {
		t.Errorf("Len after close = %d, want 0", in.Len())
	}
}

// TestCloseDuringUseZeroesWhenTheLastCallbackLeaves pins the deferred zeroing:
// Close does not wait, the callback keeps reading intact bytes, and the buffer
// is cleared once the last callback returns.
func TestCloseDuringUseZeroesWhenTheLastCallbackLeaves(t *testing.T) {
	owned := []byte("hunter2-hunter2")
	in := New(owned)

	entered := make(chan struct{})
	closed := make(chan struct{})

	go func() {
		<-entered
		_ = in.Close() // must return without waiting for the callback
		close(closed)
	}()

	err := in.Use(func(b []byte) error {
		close(entered)
		<-closed // Close has already run and marked the Input closed

		// The bytes this callback was handed are still intact.
		if string(b) != "hunter2-hunter2" {
			return errors.New("plaintext was zeroed while the callback was running")
		}
		// A new Use is already refused.
		if err := in.Use(func([]byte) error { return nil }); !errors.Is(err, ErrClosed) {
			return errors.New("a new Use was admitted after Close")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Use: %v", err)
	}

	// Now that the last callback has left, the buffer is zeroed.
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Errorf("buffer was not zeroed after the last callback left: %q", owned)
	}
}

// TestCloseInsideCallbackStillZeroes covers the in-callback Close, which must
// neither deadlock nor zero the bytes the callback is still reading.
func TestCloseInsideCallbackStillZeroes(t *testing.T) {
	owned := []byte("secret-value")
	in := New(owned)

	done := make(chan error, 1)
	go func() {
		done <- in.Use(func(b []byte) error {
			defer in.Close()
			if string(b) != "secret-value" {
				return errors.New("plaintext already zeroed inside the callback")
			}
			return nil
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Use: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Use deadlocked on a Close inside the callback")
	}

	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Errorf("buffer was not zeroed after the callback closed it: %q", owned)
	}
}

// TestPanickingCallbackStillReleases checks the deferred release: a callback
// that panics must not leave the Input permanently marked in use, or a later
// Close would never zero the buffer.
func TestPanickingCallbackStillReleases(t *testing.T) {
	owned := []byte("panic-path")
	in := New(owned)

	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected the callback panic to propagate")
			}
		}()
		_ = in.Use(func([]byte) error { panic("boom") })
	}()

	// The Input is usable again, so the release ran.
	if err := in.Use(func([]byte) error { return nil }); err != nil {
		t.Fatalf("Use after a panicking callback = %v, want nil", err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Errorf("buffer was not zeroed after a panicking callback: %q", owned)
	}
}

// TestNestedUseHoldsTheBufferUntilTheOuterCallbackLeaves checks the counter
// with more than one active callback.
func TestNestedUseHoldsTheBufferUntilTheOuterCallbackLeaves(t *testing.T) {
	owned := []byte("nested-secret")
	in := New(owned)

	err := in.Use(func(outer []byte) error {
		return in.Use(func(inner []byte) error {
			_ = in.Close() // deferred: two callbacks are still active
			if string(inner) != "nested-secret" || string(outer) != "nested-secret" {
				return errors.New("plaintext zeroed with callbacks still active")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("nested Use: %v", err)
	}
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Errorf("buffer was not zeroed after the outer callback left: %q", owned)
	}
}
