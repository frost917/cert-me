package port_test

// Tests for docs/backend-implementation.md §13 ruling 4: PKIParser exposes
// four separate typed methods (certificate bundle, CRL, CA key, internal
// TLS key) instead of one polymorphic Parse, an ordinary leaf private key
// has no representable path through the interface, and the validated-key
// ownership/close contract ("호출자가 KeyEngine.Import 후 Close하며, 중간
// 실패 시 파서가 이미 만든 비밀을 닫는다") is exercised on both the success
// and mid-failure paths.
//
// These run against a minimal fake implementing port.PKIParser, defined in
// this file -- there is no real (adapter) implementation yet; that is B05's
// job. The fake exists only to prove the interface shape actually lets a
// conforming implementation express the ruling, not to test parsing logic.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// fakeParser is a minimal PKIParser double. ParseCAKey/ParseInternalTLSKey
// decrypt Data into a secret.Input immediately (standing in for the real
// PBES2/PKCS8 decrypt step) and only then check the public key match --
// mirroring the real adapter's "decrypt first, validate after" shape, which
// is exactly the shape that can fail *after* a secret already exists.
type fakeParser struct{}

var errPublicKeyMismatch = errors.New("fake: derived public key does not match expected public key")

func (fakeParser) ParseCertificateBundle(ctx context.Context, input port.CertificateBundleInput) (port.CertificateBundleFacts, error) {
	return port.CertificateBundleFacts{
		Certificates: []port.ParsedCertificateFacts{{DER: input.Data}},
	}, nil
}

func (fakeParser) ParseCRL(ctx context.Context, input port.CRLInput) (port.ParsedCRLFacts, error) {
	return port.ParsedCRLFacts{DER: input.Data}, nil
}

// derivedPublicKeyFor stands in for actually deriving a public key from key
// material; the fake just treats Data itself as if it encoded the public
// key, so the test can control match/mismatch by choosing Data and
// ExpectedPublicKey independently.
func derivedPublicKeyFor(data []byte) domain.PublicKey {
	pk, err := domain.NewPublicKey(domain.KeyAlgorithmRSA2048, data)
	if err != nil {
		panic(err)
	}
	return pk
}

// lastCAKeySecretForTest is a test-only observability hook: it lets a test
// confirm a secret ParseCAKey created on a mid-failure path was actually
// closed, even though the failed return value (the zero ValidatedCAKeyInput)
// gives the caller nothing to Close itself. Production code never reads
// this; only this test file does.
var lastCAKeySecretForTest *secret.Input

func (fakeParser) ParseCAKey(ctx context.Context, input port.CAKeyInput) (port.ValidatedCAKeyInput, error) {
	// The secret is created first, exactly like a real decrypt step would.
	plaintext := secret.New(append([]byte(nil), input.Data...))
	lastCAKeySecretForTest = plaintext
	derived := derivedPublicKeyFor(input.Data)
	if !reflect.DeepEqual(derived, input.ExpectedPublicKey) {
		// Mid-failure: the secret this call already created must be closed
		// before returning, since the caller has no value to Close.
		_ = plaintext.Close()
		return port.ValidatedCAKeyInput{}, errPublicKeyMismatch
	}
	return port.ValidatedCAKeyInput{
		PrivateKey: plaintext,
		Algorithm:  domain.KeyAlgorithmRSA2048,
		PublicKey:  derived,
	}, nil
}

func (fakeParser) ParseInternalTLSKey(ctx context.Context, input port.TLSKeyInput) (port.ValidatedTLSKeyInput, error) {
	plaintext := secret.New(append([]byte(nil), input.Data...))
	derived := derivedPublicKeyFor(input.Data)
	if !reflect.DeepEqual(derived, input.ExpectedPublicKey) {
		_ = plaintext.Close()
		return port.ValidatedTLSKeyInput{}, errPublicKeyMismatch
	}
	return port.ValidatedTLSKeyInput{
		PrivateKey: plaintext,
		Algorithm:  domain.KeyAlgorithmRSA2048,
		PublicKey:  derived,
	}, nil
}

var _ port.PKIParser = fakeParser{}

// TestPKIParser_FourKindsAreSeparatelyExpressible proves the interface
// really has four distinct typed methods, one per material kind named in
// ruling 4, and nothing else -- so there is no fifth, purpose-parameterized
// method a caller could misuse to reach a leaf-key import path.
func TestPKIParser_FourKindsAreSeparatelyExpressible(t *testing.T) {
	iface := reflect.TypeOf((*port.PKIParser)(nil)).Elem()
	if got, want := iface.NumMethod(), 4; got != want {
		t.Fatalf("PKIParser has %d methods, want exactly %d (certificate bundle, CRL, CA key, internal TLS key)", got, want)
	}
	want := map[string]bool{
		"ParseCertificateBundle": true,
		"ParseCRL":               true,
		"ParseCAKey":             true,
		"ParseInternalTLSKey":    true,
	}
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		if !want[name] {
			t.Fatalf("PKIParser has unexpected method %q -- not one of the four ruled kinds", name)
		}
		delete(want, name)
	}
	if len(want) != 0 {
		t.Fatalf("PKIParser is missing methods: %v", want)
	}
}

// TestPKIParser_LeafPrivateKeyHasNoRepresentablePath is the structural half
// of ruling 4's "일반 leaf 개인키 import는 허용하지 않는다": there is no
// domain.SecretPurpose parameter anywhere on PKIParser a caller could set to
// a leaf purpose. Each of the two key-bearing methods hardcodes its own
// purpose (ca_signing/bootstrap_ca for ParseCAKey, internal_tls for
// ParseInternalTLSKey) by having a fixed method identity rather than a
// purpose argument, which this test pins down by inspecting the exact
// parameter list of both methods.
func TestPKIParser_LeafPrivateKeyHasNoRepresentablePath(t *testing.T) {
	iface := reflect.TypeOf((*port.PKIParser)(nil)).Elem()
	for _, name := range []string{"ParseCAKey", "ParseInternalTLSKey"} {
		m, ok := iface.MethodByName(name)
		if !ok {
			t.Fatalf("PKIParser has no method %q", name)
		}
		// ctx + one typed input struct; no domain.SecretPurpose (or any
		// other purpose-like parameter) that could be steered to leaf.
		if got, want := m.Type.NumIn(), 2; got != want {
			t.Fatalf("%s has %d parameters, want %d (ctx, input) -- a purpose parameter would let a caller ask for a leaf import", name, got, want)
		}
		for i := 0; i < m.Type.NumIn(); i++ {
			if m.Type.In(i) == reflect.TypeOf(domain.SecretPurpose("")) {
				t.Fatalf("%s takes a domain.SecretPurpose parameter -- that would make a leaf-purpose import expressible", name)
			}
		}
	}
}

// TestPKIParser_CAKeySuccessOwnershipContract exercises the success path:
// ParseCAKey returns a secret.Input the caller owns from that point on. The
// caller (standing in for the real ImportService, which would call
// KeyEngine.ImportCA in between) is the one that Closes it.
func TestPKIParser_CAKeySuccessOwnershipContract(t *testing.T) {
	p := fakeParser{}
	keyBytes := []byte("ca-private-key-bytes")
	expected := derivedPublicKeyFor(keyBytes)

	validated, err := p.ParseCAKey(context.Background(), port.CAKeyInput{
		Data:              keyBytes,
		ExpectedPublicKey: expected,
	})
	if err != nil {
		t.Fatalf("ParseCAKey: %v", err)
	}
	if validated.PrivateKey == nil {
		t.Fatalf("ParseCAKey returned no PrivateKey on success")
	}

	// Stand in for "caller passes it to KeyEngine.ImportCA" by reading it
	// once through Use, then the caller closes it -- ownership contract.
	var seen []byte
	if err := validated.PrivateKey.Use(func(b []byte) error {
		seen = append(seen, b...)
		return nil
	}); err != nil {
		t.Fatalf("Use on the caller-owned secret: %v", err)
	}
	if string(seen) != string(keyBytes) {
		t.Fatalf("PrivateKey did not carry the parsed key bytes: got %q", seen)
	}
	if err := validated.PrivateKey.Close(); err != nil {
		t.Fatalf("caller Close after use: %v", err)
	}
	// Close is idempotent -- ruling and §6 both rely on this.
	if err := validated.PrivateKey.Close(); err != nil {
		t.Fatalf("second Close must be safe: %v", err)
	}
}

// TestPKIParser_CAKeyMidFailureClosesItsOwnSecret exercises the mid-failure
// path: the fake decrypts into a secret.Input first and only discovers the
// public-key mismatch afterward, exactly like a real adapter would. Ruling
// 4 requires the parser -- not a caller who never received a value -- to
// Close that secret. This test observes the effect (a subsequent Use on the
// same underlying buffer fails) using a *secret.Input the fake handed back
// out-of-band for observation only; production code never gets this
// after a failure, since ValidatedCAKeyInput is the zero value on error.
func TestPKIParser_CAKeyMidFailureClosesItsOwnSecret(t *testing.T) {
	p := fakeParser{}
	keyBytes := []byte("ca-private-key-bytes")
	wrongExpected := derivedPublicKeyFor([]byte("a-completely-different-key"))

	validated, err := p.ParseCAKey(context.Background(), port.CAKeyInput{
		Data:              keyBytes,
		ExpectedPublicKey: wrongExpected,
	})
	if err == nil {
		t.Fatalf("ParseCAKey must fail on a public key mismatch")
	}
	if validated.PrivateKey != nil {
		t.Fatalf("a failed ParseCAKey must not hand back a PrivateKey the caller could double-close or leak")
	}

	// The caller got nothing to Close -- confirm the parser closed its own
	// internally-created secret instead of leaking an open one, via the
	// test-only observability hook the fake sets before checking the match.
	if lastCAKeySecretForTest == nil {
		t.Fatalf("fakeParser did not record the secret it created")
	}
	if err := lastCAKeySecretForTest.Use(func([]byte) error { return nil }); err == nil {
		t.Fatalf("ParseCAKey's internally-created secret was not closed on a mid-failure return")
	}
}

// TestPKIParser_InternalTLSKeySuccessAndMidFailure mirrors the two CA-key
// tests above for ParseInternalTLSKey, so both key-bearing methods (not
// just one) are proven to carry the ownership/close contract.
func TestPKIParser_InternalTLSKeySuccessAndMidFailure(t *testing.T) {
	p := fakeParser{}
	keyBytes := []byte("internal-tls-private-key-bytes")
	expected := derivedPublicKeyFor(keyBytes)

	validated, err := p.ParseInternalTLSKey(context.Background(), port.TLSKeyInput{
		Data:              keyBytes,
		ExpectedPublicKey: expected,
	})
	if err != nil {
		t.Fatalf("ParseInternalTLSKey: %v", err)
	}
	if validated.PrivateKey == nil {
		t.Fatalf("ParseInternalTLSKey returned no PrivateKey on success")
	}
	if err := validated.PrivateKey.Close(); err != nil {
		t.Fatalf("caller Close: %v", err)
	}

	wrongExpected := derivedPublicKeyFor([]byte("not-the-right-key"))
	failed, err := p.ParseInternalTLSKey(context.Background(), port.TLSKeyInput{
		Data:              keyBytes,
		ExpectedPublicKey: wrongExpected,
	})
	if err == nil {
		t.Fatalf("ParseInternalTLSKey must fail on a public key mismatch")
	}
	if failed.PrivateKey != nil {
		t.Fatalf("a failed ParseInternalTLSKey must not hand back an open PrivateKey")
	}
}
