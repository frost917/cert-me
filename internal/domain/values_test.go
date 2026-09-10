package domain

import "testing"

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
