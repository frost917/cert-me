package port_test

import (
	"reflect"
	"testing"

	"cert-me/internal/app/port"
)

// A prepared handle must carry nothing an outside caller can substitute, and
// must not leak the installer's token: either would let a caller apply a
// configuration the installer never validated.
func TestPreparedTLSConfig_PreparedHandleExposesNothingSubstitutable(t *testing.T) {
	typ := reflect.TypeOf(port.PreparedTLSConfig{})
	for i := 0; i < typ.NumField(); i++ {
		if f := typ.Field(i); f.IsExported() {
			t.Errorf("PreparedTLSConfig.%s is exported and can be overwritten by a caller", f.Name)
		}
	}
	// No method may hand back the owning token: with it, a caller could mint
	// a fresh handle that the installer's own Verify would accept.
	tokenType := reflect.TypeOf(port.TLSPrepareToken{})
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			if m.Type.Out(j) == tokenType {
				t.Errorf("PreparedTLSConfig.%s returns the installer's token", m.Name)
			}
		}
	}
	for i := 0; i < tokenType.NumField(); i++ {
		if f := tokenType.Field(i); f.IsExported() {
			t.Errorf("TLSPrepareToken.%s is exported; a caller could forge a token", f.Name)
		}
	}
}

// Each Prepare call must get its own identity, so one handle's registry entry
// can never be reached through another handle.
func TestPreparedTLSConfig_HandleIdentitiesAreDistinct(t *testing.T) {
	token := port.NewTLSPrepareToken()
	a := port.NewPreparedTLSConfig(token)
	b := port.NewPreparedTLSConfig(token)

	if a.ID() == b.ID() {
		t.Fatal("two Prepare calls produced the same handle identity")
	}
	if !token.Verify(a) || !token.Verify(b) {
		t.Fatal("the minting token does not verify its own handles")
	}
	// A different installer's token must reject both, and the zero handle
	// must be rejected by everyone.
	other := port.NewTLSPrepareToken()
	if other.Verify(a) || other.Verify(b) {
		t.Fatal("a foreign installer's token verified a handle it did not mint")
	}
	if token.Verify(port.PreparedTLSConfig{}) {
		t.Fatal("the zero handle was verified")
	}
	var zeroToken port.TLSPrepareToken
	if zeroToken.Verify(a) || zeroToken.Verify(port.PreparedTLSConfig{}) {
		t.Fatal("a zero token verified a handle")
	}
}
