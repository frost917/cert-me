// Package secret carries short-lived plaintext secrets whose log and JSON
// output is blocked. It references the standard library only.
package secret

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// ErrClosed is returned when a closed Input is used.
var ErrClosed = errors.New("secret: input is closed")

// ErrNotSerializable is returned by MarshalJSON. A secret must be written
// through Use inside the adapter that needs it, never marshalled with the
// surrounding command or result.
var ErrNotSerializable = errors.New("secret: refusing to serialize secret input")

// redacted is the only textual form an Input ever produces.
const redacted = "<redacted>"

// Input owns a short-lived []byte. Close zeroes the owned buffer and drops the
// reference; it is safe to call more than once. String and LogValue are always
// redacted and MarshalJSON returns an error.
//
// Zeroing removes the value from this buffer. It is not an absolute guarantee
// of memory-safe erasure: the runtime may have copied the bytes before the
// Input took ownership.
type Input struct {
	mu     sync.Mutex
	buf    []byte
	closed bool
	// inUse counts callbacks currently running in Use. Close never waits on
	// them; it stops new callers immediately and leaves the zeroing to the
	// last callback to finish, so no callback ever reads a buffer while Close
	// writes over it.
	inUse int
}

// New takes ownership of buf. The caller must not retain or reuse buf; New
// does not copy, so the buffer Close zeroes is the caller's original.
func New(buf []byte) *Input {
	return &Input{buf: buf}
}

// FromString copies s into a new owned buffer. The original string cannot be
// zeroed, so prefer reading secrets into a []byte and calling New.
func FromString(s string) *Input {
	return &Input{buf: []byte(s)}
}

// ReadAll reads at most limit bytes from r into a new Input. It returns an
// error when r holds more than limit bytes so that oversized input is
// rejected before any expensive work.
func ReadAll(r io.Reader, limit int) (*Input, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("secret: read limit must be positive")
	}
	// Allocate the full limit up front. Growing with append would reallocate
	// and leave the discarded array holding plaintext that Close can no longer
	// reach, since Close only zeroes the array buf currently points at.
	buf := make([]byte, 0, limit)
	chunk := make([]byte, 512)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			if len(buf)+n > limit {
				zero(buf)
				zero(chunk)
				return nil, fmt.Errorf("secret: input exceeds %d bytes", limit)
			}
			buf = append(buf, chunk[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			zero(buf)
			zero(chunk)
			return nil, err
		}
	}
	zero(chunk)
	return &Input{buf: buf}, nil
}

// Use grants synchronous access to the plaintext. The callback must not retain
// the slice or hand it to another goroutine; that is the adapter contract.
// A nil Input is treated as closed so callers do not need a nil check.
//
// The bytes are read-only for the duration of the callback.
//
// The lock is released before the callback runs, so the callback may call any
// method on the same Input -- including a deferred Close, which is the natural
// thing to write. Holding a non-reentrant mutex across the callback would
// deadlock on exactly that. Releasing it alone would race instead: a Close on
// another goroutine would zero the array while the callback reads it. So the
// callback is counted while it runs, and a Close that arrives meanwhile only
// marks the Input closed; the zeroing happens when the last callback leaves.
// The release is deferred, so a panicking callback still cleans up.
func (i *Input) Use(fn func([]byte) error) error {
	if i == nil {
		return ErrClosed
	}
	i.mu.Lock()
	if i.closed || i.buf == nil {
		i.mu.Unlock()
		return ErrClosed
	}
	buf := i.buf
	i.inUse++
	i.mu.Unlock()

	defer i.release()
	return fn(buf)
}

// release ends one callback and performs a Close that was deferred while the
// callback was running.
func (i *Input) release() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.inUse--
	if i.inUse == 0 && i.closed && i.buf != nil {
		zero(i.buf)
		i.buf = nil
	}
}

// Len reports the plaintext length, which is not itself secret. A closed or
// nil Input reports 0.
func (i *Input) Len() int {
	if i == nil {
		return 0
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	// A closed Input reports 0 even while a last callback still holds the
	// buffer, so Len never contradicts Use returning ErrClosed.
	if i.closed {
		return 0
	}
	return len(i.buf)
}

// IsEmpty reports whether there is nothing to use.
func (i *Input) IsEmpty() bool { return i.Len() == 0 }

// Close zeroes the owned buffer and drops the reference. Repeated calls are
// safe, and Close on a nil Input is a no-op so defer needs no guard.
//
// Close never blocks. It marks the Input closed at once, so every later Use
// fails, but if callbacks are still running -- including a Close called from
// inside one -- the buffer is zeroed by the last of them rather than out from
// under a reader.
func (i *Input) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	i.closed = true
	if i.inUse > 0 {
		return nil
	}
	zero(i.buf)
	i.buf = nil
	return nil
}

// String is always redacted.
func (i *Input) String() string { return redacted }

// GoString keeps %#v from printing the buffer.
func (i *Input) GoString() string { return redacted }

// Format handles every verb, including %s, %q, %v and %x, so that no format
// directive can reach the underlying bytes.
func (i *Input) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		fmt.Fprintf(f, "%q", redacted)
	default:
		_, _ = io.WriteString(f, redacted)
	}
}

// LogValue is always redacted, so slog cannot print the plaintext.
func (i *Input) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON always fails: secrets are written by the adapter that needs
// them, not by marshalling a command or result that holds one.
func (i *Input) MarshalJSON() ([]byte, error) { return nil, ErrNotSerializable }

// MarshalText fails for the same reason, covering encoders that prefer it.
func (i *Input) MarshalText() ([]byte, error) { return nil, ErrNotSerializable }

// UnmarshalJSON always fails: a secret is never decoded from a JSON body
// field. Handlers convert a validated header or form value with New.
func (i *Input) UnmarshalJSON([]byte) error { return ErrNotSerializable }

// CloseAll closes every non-nil Input, ignoring nils. Use it in a single defer
// when a command owns several secrets.
func CloseAll(inputs ...*Input) {
	for _, in := range inputs {
		_ = in.Close()
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var (
	_ fmt.Formatter  = (*Input)(nil)
	_ fmt.Stringer   = (*Input)(nil)
	_ slog.LogValuer = (*Input)(nil)
	_ io.Closer      = (*Input)(nil)
)
