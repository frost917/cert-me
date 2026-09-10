package domain

import (
	"testing"
	"time"
)

// The permitted algorithm list must match the OpenAPI key_algorithm enum and
// docs/certificate-lifecycle.md, which places Ed25519 outside MVP issuance.
func TestKeyAlgorithmValidateMatchesContract(t *testing.T) {
	allowed := []KeyAlgorithm{
		KeyAlgorithmECDSAP256,
		KeyAlgorithmECDSAP384,
		KeyAlgorithmRSA2048,
		KeyAlgorithmRSA3072,
		KeyAlgorithmRSA4096,
	}
	for _, algorithm := range allowed {
		if err := algorithm.Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", algorithm, err)
		}
	}

	rejected := []KeyAlgorithm{
		"ed25519",
		"ed448",
		"rsa_1024",
		"rsa_2047",
		"ECDSA_P256",
		"",
	}
	for _, algorithm := range rejected {
		if err := algorithm.Validate(); err == nil {
			t.Errorf("Validate(%q) = nil, want an error", algorithm)
		}
	}
}

func TestDefaultKeyAlgorithms(t *testing.T) {
	// docs/certificate-lifecycle.md: ECDSA P-256 by default, and when RSA is
	// chosen a CA defaults to 3072 while a leaf defaults to 2048.
	if DefaultKeyAlgorithm != KeyAlgorithmECDSAP256 {
		t.Errorf("DefaultKeyAlgorithm = %q, want ecdsa_p256", DefaultKeyAlgorithm)
	}
	if DefaultCARSAAlgorithm != KeyAlgorithmRSA3072 {
		t.Errorf("DefaultCARSAAlgorithm = %q, want rsa_3072", DefaultCARSAAlgorithm)
	}
	if DefaultLeafRSAAlgorithm != KeyAlgorithmRSA2048 {
		t.Errorf("DefaultLeafRSAAlgorithm = %q, want rsa_2048", DefaultLeafRSAAlgorithm)
	}
	for _, algorithm := range []KeyAlgorithm{DefaultKeyAlgorithm, DefaultCARSAAlgorithm, DefaultLeafRSAAlgorithm} {
		if err := algorithm.Validate(); err != nil {
			t.Errorf("default %q is not permitted: %v", algorithm, err)
		}
	}
}

// TestNewInstantZeroTimeIsZeroInstant covers the unset-timestamp path. Every
// "must be set" check in this package is IsZero, so a zero time.Time reaching
// NewInstant must not produce a value that passes those checks.
func TestNewInstantZeroTimeIsZeroInstant(t *testing.T) {
	zero := NewInstant(time.Time{})
	if !zero.IsZero() {
		t.Fatalf("NewInstant(time.Time{}) has micros=%d, want the zero Instant", zero.UnixMicro())
	}

	// A window built from it must be rejected, which is what protects
	// NewCertificate and the other constructors downstream.
	if _, err := NewValidityWindow(zero, NewInstant(time.Date(2, 1, 1, 0, 0, 0, 0, time.UTC))); err == nil {
		t.Error("NewValidityWindow accepted a zero notBefore, want an error")
	}

	// A real instant is unaffected and still round-trips.
	real := time.Date(2026, 9, 10, 4, 5, 6, 123456000, time.UTC)
	got := NewInstant(real)
	if got.IsZero() {
		t.Fatal("NewInstant on a real time reported IsZero")
	}
	if !got.Time().Equal(real) {
		t.Errorf("round trip = %s, want %s", got.Time().Format(time.RFC3339Nano), real.Format(time.RFC3339Nano))
	}

	// A non-UTC zero value is still zero.
	if !NewInstant(time.Time{}.In(time.FixedZone("x", 3600))).IsZero() {
		t.Error("a zero time in another zone did not map to the zero Instant")
	}

	// InstantFromUnixMicro stays the explicit escape hatch for the epoch.
	if epoch := InstantFromUnixMicro(0); !epoch.IsZero() {
		t.Error("micros 0 should be the zero Instant")
	}
}
