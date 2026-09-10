package port_test

// S2 (docs/backend-implementation.md §9: "준비한 후보를 TLSInstaller.Prepare에
// 넣어 실제 적용 가능한 메모리 설정을 먼저 만든다"): the sealed
// PreparedTLSConfig marker interface used a package-private method, which
// means no adapter outside package port -- including the real B05 TLS
// installer -- can ever produce a value satisfying the interface. This file
// is an external package_test double proving the fixed design compiles from
// outside port and enforces the one guarantee that matters: Apply rejects a
// handle it did not itself mint, while accepting one it did.

import (
	"context"
	"errors"
	"testing"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// fakeInstaller is a minimal TLSInstaller double, standing in for the real
// B05 adapter. It mints its own token once and uses it to recognize handles
// it produced.
type fakeInstaller struct {
	token    port.TLSPrepareToken
	applied  int
	rejected int
}

func newFakeInstaller() *fakeInstaller {
	return &fakeInstaller{token: port.NewTLSPrepareToken()}
}

func (f *fakeInstaller) Prepare(ctx context.Context, candidate domain.TLSVersion, key domain.EncryptedSecret) (port.PreparedTLSConfig, error) {
	// A real installer would validate the candidate/key here and build an
	// actual in-memory listener config as the payload. The double just
	// carries a marker string.
	return port.NewPreparedTLSConfig(f.token, "real-config"), nil
}

func (f *fakeInstaller) Apply(ctx context.Context, prepared port.PreparedTLSConfig) error {
	if !f.token.Verify(prepared) {
		f.rejected++
		return errors.New("tls: prepared config was not produced by this installer")
	}
	f.applied++
	return nil
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
