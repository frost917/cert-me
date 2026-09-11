package port_test

// S2 (docs/backend-implementation.md §9: "준비한 후보를 TLSInstaller.Prepare에
// 넣어 실제 적용 가능한 메모리 설정을 먼저 만든다"): the sealed
// PreparedTLSConfig marker interface used a package-private method, which
// means no adapter outside package port -- including the real B05 TLS
// installer -- can ever produce a value satisfying the interface. This file
// is an external package_test double proving the fixed design compiles from
// outside port and enforces the guarantees that matter: Apply rejects a
// handle it did not itself mint, and no caller outside the installer that
// produced a handle can change which configuration Apply will install for
// it.
//
// fakeInstaller models the registry pattern the real B05 adapter must use
// (see PreparedTLSConfig's doc comment in services.go): PreparedTLSConfig
// carries no payload, so the installer keeps its own private map from
// handle ID to the config it built in Prepare, and looks the config back up
// in Apply after Verify succeeds.

import (
	"context"
	"errors"
	"testing"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// fakeInstaller is a minimal TLSInstaller double, standing in for the real
// B05 adapter. It mints its own token once and uses it to recognize handles
// it produced, and keeps a private registry from handle ID to the config it
// built for that handle -- exactly the shape TLSInstaller's doc comments
// require of a real implementation now that PreparedTLSConfig carries no
// payload of its own.
type fakeInstaller struct {
	token     port.TLSPrepareToken
	configs   map[any]string // handle ID -> the config Prepare built for it
	applied   int
	rejected  int
	discarded int
	// lastApplied is the config fakeInstaller's own Apply most recently
	// installed, read back out of its private registry -- never anything a
	// caller could have supplied directly.
	lastApplied string
}

// The assertion is the point of this double: it makes the whole TLSInstaller
// contract a compile-time check from OUTSIDE the port package, so a method
// added to the interface cannot silently drift away from what an adapter in
// another package can actually implement. Without it, this file compiled
// happily while missing Discard entirely.
var _ port.TLSInstaller = (*fakeInstaller)(nil)

func newFakeInstaller() *fakeInstaller {
	return &fakeInstaller{token: port.NewTLSPrepareToken(), configs: map[any]string{}}
}

// discarded counts released-but-never-applied entries, so a test can tell a
// cleanup that ran from one that silently did nothing.
func (f *fakeInstaller) prepared() int { return len(f.configs) }

func (f *fakeInstaller) Prepare(ctx context.Context, candidate domain.TLSVersion, key domain.EncryptedSecret) (port.PreparedTLSConfig, error) {
	// A real installer would validate the candidate/key here and build an
	// actual in-memory listener config. The double just builds a marker
	// string, but the shape matters: the config is recorded in this
	// installer's own private registry, keyed by the handle's ID, before
	// the handle is returned. Nothing about the handle itself carries the
	// config, so nothing about the handle can be used to change it later.
	prepared := port.NewPreparedTLSConfig(f.token)
	f.configs[prepared.ID()] = "real-config"
	return prepared, nil
}

func (f *fakeInstaller) Apply(ctx context.Context, prepared port.PreparedTLSConfig) error {
	if !f.token.Verify(prepared) {
		f.rejected++
		return errors.New("tls: prepared config was not produced by this installer")
	}
	cfg, ok := f.configs[prepared.ID()]
	if !ok {
		// Verify passed (same installer's token) but this exact handle was
		// never registered -- can't happen for a handle this installer's
		// own Prepare returned, but a real installer should still treat an
		// unregistered handle as unusable rather than apply a zero value.
		f.rejected++
		return errors.New("tls: prepared config has no registered configuration")
	}
	// Apply consumes the handle exactly once: the entry leaves the registry
	// on both outcomes, so a replay of the same handle finds nothing and is
	// rejected, and a deferred Discard on the success path has nothing left
	// to release (docs/backend-implementation.md §13).
	delete(f.configs, prepared.ID())
	f.applied++
	f.lastApplied = cfg
	return nil
}

// Discard releases a prepared entry that will never be applied. It is
// idempotent, takes no context because it runs precisely where the request
// context is already cancelled, and never touches the live listener -- here,
// lastApplied.
func (f *fakeInstaller) Discard(prepared port.PreparedTLSConfig) {
	if !f.token.Verify(prepared) {
		// Releasing only our own entries is the same ownership check Apply
		// makes; another installer's handle is not ours to clean up.
		return
	}
	if _, ok := f.configs[prepared.ID()]; ok {
		f.configs[prepared.ID()] = ""
		delete(f.configs, prepared.ID())
		f.discarded++
	}
}

func TestPreparedTLSConfig_PrepareThenApplyRoundTrips(t *testing.T) {
	inst := newFakeInstaller()
	prepared, err := inst.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := inst.Apply(context.Background(), prepared); err != nil {
		t.Fatalf("Apply on a genuinely prepared config must succeed: %v", err)
	}
	if inst.applied != 1 || inst.rejected != 0 {
		t.Fatalf("want 1 applied/0 rejected, got applied=%d rejected=%d", inst.applied, inst.rejected)
	}
}

func TestPreparedTLSConfig_ApplyRejectsAForeignHandle(t *testing.T) {
	genuine := newFakeInstaller()
	impostor := newFakeInstaller() // a different installer, minting a different token

	forged, err := impostor.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if err := genuine.Apply(context.Background(), forged); err == nil {
		t.Fatalf("Apply must reject a handle minted by a different installer")
	}
	if genuine.applied != 0 || genuine.rejected != 1 {
		t.Fatalf("want 0 applied/1 rejected, got applied=%d rejected=%d", genuine.applied, genuine.rejected)
	}
}

func TestPreparedTLSConfig_ApplyRejectsAZeroValueHandle(t *testing.T) {
	// App code cannot call Prepare and must not be able to hand Apply a
	// bare, never-prepared port.PreparedTLSConfig{} and have it accepted.
	inst := newFakeInstaller()
	var neverPrepared port.PreparedTLSConfig
	if err := inst.Apply(context.Background(), neverPrepared); err == nil {
		t.Fatalf("Apply must reject a zero-value (never-Prepared) config")
	}
}

// TestPreparedTLSConfig_PayloadCannotBeSubstitutedExternally is the
// reviewer's P2 finding on this PR: the previous round's fix (a concrete
// PreparedTLSConfig carrying an installer-minted token plus a public
// `Payload any` field) closed constructibility but left the token unbound
// to the actual configuration that gets applied. A caller holding a
// legitimately Prepared handle could overwrite prepared.Payload with an
// unvalidated value, and token.Verify(prepared) still reported true --
// reproduced by this repo's history as
// TestPreparedTLSConfig_ExploitCurrentPayloadIsPublic, which failed
// (t.Fatalf'd on "BUG REPRODUCED") against the pre-fix services.go:
//
//	=== RUN   TestPreparedTLSConfig_ExploitCurrentPayloadIsPublic
//	    tls_prepare_seal_test.go:118: BUG REPRODUCED: Apply accepted a
//	    handle whose Payload was swapped to "evil-unvalidated-config" after
//	    Prepare returned it; token.Verify does not bind to the payload
//	--- FAIL: TestPreparedTLSConfig_ExploitCurrentPayloadIsPublic (0.00s)
//
// The fix removes Payload from PreparedTLSConfig entirely (see its doc
// comment in services.go): the handle now carries only the installer's
// token and an opaque per-Prepare identity (ID()), and the real
// configuration lives only in the private registry inside the installer
// that built it (fakeInstaller.configs above, mirroring what the real B05
// adapter must do). There is now no field or method through which this
// test -- or any other code outside package port -- could even attempt the
// substitution: `prepared.Payload = "evil"` is a compile error,
// "prepared.Payload undefined (type port.PreparedTLSConfig has no field or
// method Payload)", not a runtime rejection. That makes this guarantee
// structural rather than something Apply has to detect: what this test
// checks at runtime is the remaining, weaker half -- that Apply, given an
// untouched genuine handle, installs exactly the configuration its own
// Prepare registered for it, never something injected through the handle.
func TestPreparedTLSConfig_PayloadCannotBeSubstitutedExternally(t *testing.T) {
	inst := newFakeInstaller()
	prepared, err := inst.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if err := inst.Apply(context.Background(), prepared); err != nil {
		t.Fatalf("Apply on a genuinely prepared, unmodified handle must succeed: %v", err)
	}
	if got := inst.lastApplied; got != "real-config" {
		t.Fatalf("Apply installed %q, want the installer's own registered config %q", got, "real-config")
	}
}

// A Prepare that never reaches Apply must not leak its registry entry. This is
// the path the handle-ID design created: the DB write around Prepare can roll
// back, come back commit_unknown, or the request can be cancelled or panic.
func TestTLSInstaller_DiscardReleasesAnUnappliedEntry(t *testing.T) {
	inst := newFakeInstaller()
	prepared, err := inst.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if inst.prepared() != 1 {
		t.Fatalf("Prepare left %d registry entries, want 1", inst.prepared())
	}

	inst.Discard(prepared)

	if inst.prepared() != 0 {
		t.Fatalf("Discard left %d registry entries, want 0", inst.prepared())
	}
	if inst.discarded != 1 {
		t.Fatalf("discarded=%d, want 1", inst.discarded)
	}
	if inst.lastApplied != "" {
		t.Fatalf("Discard changed the live configuration to %q", inst.lastApplied)
	}
	// A released handle must not be applicable afterwards.
	if err := inst.Apply(context.Background(), prepared); err == nil {
		t.Fatal("Apply accepted a handle that had already been discarded")
	}
}

// The service defers Discard right after Prepare, so it runs on the success
// path too. It must not tear down the configuration Apply just installed:
// Apply transferred ownership to the live listener.
func TestTLSInstaller_DeferredDiscardAfterSuccessfulApplyKeepsTheActiveConfig(t *testing.T) {
	inst := newFakeInstaller()

	applyErr := func() error {
		prepared, err := inst.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
		if err != nil {
			return err
		}
		defer inst.Discard(prepared) // exactly what a service does
		return inst.Apply(context.Background(), prepared)
	}()
	if applyErr != nil {
		t.Fatalf("Apply: %v", applyErr)
	}

	if inst.lastApplied != "real-config" {
		t.Fatalf("the deferred Discard tore down the active configuration: lastApplied=%q", inst.lastApplied)
	}
	if inst.applied != 1 {
		t.Fatalf("applied=%d, want 1", inst.applied)
	}
	if inst.prepared() != 0 {
		t.Fatalf("%d registry entries survived a successful Apply, want 0", inst.prepared())
	}
}

// Discard is idempotent: that is what makes the deferred call safe regardless
// of which path the service took.
func TestTLSInstaller_DiscardIsIdempotent(t *testing.T) {
	inst := newFakeInstaller()
	prepared, err := inst.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for i := 0; i < 3; i++ {
		inst.Discard(prepared)
	}
	if inst.discarded != 1 {
		t.Fatalf("discarded=%d after three calls, want 1 release and no error", inst.discarded)
	}
	// Also safe on a handle that was already consumed by Apply, and on a
	// zero handle.
	other, err := inst.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := inst.Apply(context.Background(), other); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	inst.Discard(other)
	inst.Discard(port.PreparedTLSConfig{})
	if inst.lastApplied != "real-config" {
		t.Fatalf("a post-Apply Discard disturbed the active configuration: %q", inst.lastApplied)
	}
}

// A failed Apply must release the entry but leave the previous listener
// serving, and the handle must not be replayable afterwards.
func TestTLSInstaller_FailedApplyReleasesTheEntryAndKeepsTheOldListener(t *testing.T) {
	inst := newFakeInstaller()
	first, err := inst.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := inst.Apply(context.Background(), first); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// A second candidate whose Apply fails: drop its registry entry behind
	// its back to simulate the installer's own apply-time failure path.
	second, err := inst.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	delete(inst.configs, second.ID())
	if err := inst.Apply(context.Background(), second); err == nil {
		t.Fatal("Apply succeeded with no registered configuration")
	}
	if inst.lastApplied != "real-config" {
		t.Fatalf("a failed Apply disturbed the active configuration: %q", inst.lastApplied)
	}
	inst.Discard(second) // the service's deferred cleanup still runs
	if inst.prepared() != 0 {
		t.Fatalf("%d entries survived, want 0", inst.prepared())
	}
}

// A consumed handle must not be applicable a second time: replaying one would
// re-install a configuration whose ownership already moved to the listener.
func TestTLSInstaller_ApplyRejectsAConsumedHandle(t *testing.T) {
	inst := newFakeInstaller()
	prepared, err := inst.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := inst.Apply(context.Background(), prepared); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if err := inst.Apply(context.Background(), prepared); err == nil {
		t.Fatal("Apply accepted the same handle twice")
	}
	if inst.applied != 1 {
		t.Fatalf("applied=%d, want 1", inst.applied)
	}
}

// Discard must only release entries the installer itself prepared, the same
// ownership check Apply makes through Verify.
func TestTLSInstaller_DiscardIgnoresAForeignHandle(t *testing.T) {
	genuine := newFakeInstaller()
	impostor := newFakeInstaller()

	mine, err := genuine.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	theirs, err := impostor.Prepare(context.Background(), domain.TLSVersion{}, domain.EncryptedSecret{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	genuine.Discard(theirs)
	if impostor.prepared() != 1 {
		t.Fatalf("another installer released our entry: impostor has %d", impostor.prepared())
	}
	if genuine.prepared() != 1 {
		t.Fatalf("discarding a foreign handle disturbed our own registry: %d entries", genuine.prepared())
	}
	// Our own handle still works.
	if err := genuine.Apply(context.Background(), mine); err != nil {
		t.Fatalf("Apply on our own handle: %v", err)
	}
}
