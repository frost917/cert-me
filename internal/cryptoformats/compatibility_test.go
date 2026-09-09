// This package verifies selected dependencies; it is not a production key parser.
package cryptoformats

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/argon2"
	"math/big"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"testing"
	"time"
)

func TestSelectedFormats(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("test-only-format-password")
	encrypted, err := pkcs8.MarshalPrivateKey(key, password, &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 10000, HMACHash: crypto.SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := pkcs8.ParsePKCS8PrivateKey(encrypted, password)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.(*ecdsa.PrivateKey).Equal(key) {
		t.Fatal("PKCS8 key mismatch")
	}
	if _, err = pkcs8.ParsePKCS8PrivateKey(encrypted, []byte("wrong")); err == nil {
		t.Fatal("wrong password accepted")
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"fixture.internal"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := pkcs12.Modern2023.Encode(key, cert, nil, string(password))
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodedCert, err := pkcs12.Decode(bundle, string(password))
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.(*ecdsa.PrivateKey).Equal(key) || !bytes.Equal(decodedCert.Raw, der) {
		t.Fatal("PKCS12 mismatch")
	}
	if _, _, err = pkcs12.Decode(bundle, "wrong"); err == nil {
		t.Fatal("wrong PKCS12 password accepted")
	}
	if len(argon2.IDKey(password, []byte("test-only-salt-16"), 1, 1024, 1, 32)) != 32 {
		t.Fatal("Argon2id output")
	}
}
