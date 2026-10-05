package cryptoformats

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type ChainValidator struct{}

var _ port.ChainValidator = ChainValidator{}

// Validate checks the supplied issuer-first chain against its final CA root.
// It also verifies every adjacent signature explicitly so path building cannot
// silently substitute a different ordering from the caller's resolved links.
func (ChainValidator) Validate(ctx context.Context, leafDER []byte, chainDER [][]byte, now domain.Instant) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if len(leafDER) == 0 || len(chainDER) == 0 || len(chainDER) > 2 || now.IsZero() {
		return errors.New("cryptoformats: certificate chain facts are incomplete or exceed the supported depth")
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return errors.New("cryptoformats: leaf certificate is invalid")
	}
	chain := make([]*x509.Certificate, 0, len(chainDER))
	for _, der := range chainDER {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return errors.New("cryptoformats: issuer certificate is invalid")
		}
		chain = append(chain, certificate)
	}

	selfSignedRoot := len(chainDER) == 1 && bytes.Equal(chainDER[0], leafDER)
	var root *x509.Certificate
	var intermediates []*x509.Certificate
	if selfSignedRoot {
		root = leaf
		if err := requireRoot(root); err != nil {
			return err
		}
		if err := root.CheckSignatureFrom(root); err != nil {
			return errors.New("cryptoformats: root certificate is not self-signed")
		}
	} else {
		root = chain[len(chain)-1]
		if err := requireRoot(root); err != nil {
			return err
		}
		if err := root.CheckSignatureFrom(root); err != nil {
			return errors.New("cryptoformats: trust anchor is not self-signed")
		}
		intermediates = chain[:len(chain)-1]
		ordered := append([]*x509.Certificate{leaf}, chain...)
		for i := 0; i+1 < len(ordered); i++ {
			if !bytes.Equal(ordered[i].RawIssuer, ordered[i+1].RawSubject) {
				return errors.New("cryptoformats: certificate chain issuer order is inconsistent")
			}
			if err := ordered[i].CheckSignatureFrom(ordered[i+1]); err != nil {
				return errors.New("cryptoformats: certificate chain signature is invalid")
			}
		}
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediatePool := x509.NewCertPool()
	for _, certificate := range intermediates {
		if err := requireIntermediate(certificate); err != nil {
			return err
		}
		intermediatePool.AddCert(certificate)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediatePool, CurrentTime: now.Time(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("cryptoformats: certificate chain verification failed")
	}
	return checkContext(ctx)
}

func requireRoot(certificate *x509.Certificate) error {
	if certificate == nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!bytes.Equal(certificate.RawSubject, certificate.RawIssuer) {
		return errors.New("cryptoformats: trust anchor is not a self-issued CA")
	}
	return nil
}

func requireIntermediate(certificate *x509.Certificate) error {
	if certificate == nil || !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("cryptoformats: chain contains a non-CA issuer")
	}
	return nil
}

type CRLVerifier struct{}

var _ port.CRLVerifier = CRLVerifier{}

// Verify checks that a parsed CRL signature is valid under the exact issuer
// certificate selected by the application.
func (CRLVerifier) Verify(ctx context.Context, crlDER []byte, issuerCertificateDER []byte) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if len(crlDER) == 0 || len(issuerCertificateDER) == 0 {
		return errors.New("cryptoformats: CRL and issuer certificate are required")
	}
	crl, err := parseCRLDER(crlDER)
	if err != nil {
		return errors.New("cryptoformats: CRL is invalid")
	}
	issuer, err := x509.ParseCertificate(issuerCertificateDER)
	if err != nil {
		return errors.New("cryptoformats: CRL issuer certificate is invalid")
	}
	if !issuer.BasicConstraintsValid || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return errors.New("cryptoformats: CRL issuer is not authorized to sign CRLs")
	}
	if err := crl.checkSignatureFrom(issuer); err != nil {
		return errors.New("cryptoformats: CRL signature does not match its issuer")
	}
	if !bytes.Equal(crl.issuerDER, issuer.RawSubject) {
		return errors.New("cryptoformats: CRL issuer name does not match the selected certificate")
	}
	return checkContext(ctx)
}

type ProfileValidator struct{}

var _ port.ProfileValidator = ProfileValidator{}

// Validate applies the fixed certificate profile and key-algorithm rules
// already represented by the domain contract. No operator-configurable
// allowlist exists in the current Settings schema.
func (ProfileValidator) Validate(ctx context.Context, profile domain.CertificateProfile, sans []domain.SAN, algorithm domain.KeyAlgorithm) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := algorithm.Validate(); err != nil {
		return err
	}
	return domain.ValidateSANsForProfile(profile, sans)
}

type URLValidator struct{}

var _ port.URLValidator = URLValidator{}

// Validate checks that service_url is an absolute HTTPS URL with a usable
// host and port. It does not fetch or DNS-resolve the destination; that would
// make a configuration check depend on live network state and user-controlled
// server-side requests.
func (URLValidator) Validate(ctx context.Context, raw string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if raw == "" || raw != strings.TrimSpace(raw) {
		return errors.New("cryptoformats: service URL is empty or contains surrounding whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Scheme != "https" || u.Opaque != "" || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.HasSuffix(u.Host, ":") {
		return errors.New("cryptoformats: service URL must be an absolute HTTPS URL without userinfo, query, or fragment")
	}
	host := u.Hostname()
	if host == "" || strings.ContainsAny(host, " \t\r\n\\") || !validServiceURLHost(u.Host, host) {
		return errors.New("cryptoformats: service URL host is invalid")
	}
	if portText := u.Port(); portText != "" {
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return errors.New("cryptoformats: service URL port is invalid")
		}
	}
	return checkContext(ctx)
}

func validServiceURLHost(authority, host string) bool {
	if strings.HasPrefix(authority, "[") {
		closingBracket := strings.IndexByte(authority, ']')
		if closingBracket < 0 {
			return false
		}
		tail := authority[closingBracket+1:]
		if tail != "" && !strings.HasPrefix(tail, ":") {
			return false
		}
		addr, err := netip.ParseAddr(host)
		return err == nil && addr.Is6() && addr.Zone() == ""
	}
	if strings.ContainsAny(authority, "[]") {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Is4() && addr.Zone() == ""
	}
	return validServiceURLDNSHost(host)
}

func validServiceURLDNSHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}

	numeric := true
	for i := 0; i < len(host); i++ {
		if (host[i] < '0' || host[i] > '9') && host[i] != '.' {
			numeric = false
		}
	}
	if numeric {
		return false
	}

	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
				(c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("cryptoformats: context is required")
	}
	return ctx.Err()
}
