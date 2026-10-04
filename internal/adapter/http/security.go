// Package httpadapter contains the HTTP ingress boundary for the application.
package httpadapter

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxForwardedForBytes = 2 * 1024
	maxForwardedForHops  = 16
	securityCSP          = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
)

var ErrInvalidRequestMetadata = errors.New("httpadapter: invalid request metadata")

// ResolveClientIP returns the remote peer unless that peer belongs to an
// explicitly trusted CIDR. Only trusted peers may supply X-Forwarded-For.
// The returned address is unmapped and has no IPv6 zone.
func ResolveClientIP(r *http.Request, trusted []netip.Prefix) (netip.Addr, error) {
	if r == nil {
		return netip.Addr{}, fmt.Errorf("%w: request is nil", ErrInvalidRequestMetadata)
	}
	peer, err := remoteAddress(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: remote address is invalid", ErrInvalidRequestMetadata)
	}
	if !isTrusted(peer, trusted) {
		return peer, nil
	}

	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer, nil
	}
	if len(values) != 1 || len(values[0]) > maxForwardedForBytes {
		return netip.Addr{}, fmt.Errorf("%w: forwarded address header is duplicated or too large", ErrInvalidRequestMetadata)
	}

	parts := strings.Split(values[0], ",")
	if len(parts) == 0 || len(parts) > maxForwardedForHops {
		return netip.Addr{}, fmt.Errorf("%w: forwarded address chain has an invalid length", ErrInvalidRequestMetadata)
	}
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return netip.Addr{}, fmt.Errorf("%w: forwarded address chain contains an empty address", ErrInvalidRequestMetadata)
		}
		addr, err := netip.ParseAddr(part)
		if err != nil || !addr.IsValid() {
			return netip.Addr{}, fmt.Errorf("%w: forwarded address chain contains an invalid address", ErrInvalidRequestMetadata)
		}
		chain = append(chain, canonicalAddress(addr))
	}

	for i := len(chain) - 1; i >= 0; i-- {
		if !isTrusted(chain[i], trusted) {
			return chain[i], nil
		}
	}
	return chain[0], nil
}

func remoteAddress(value string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsValid() {
		return netip.Addr{}, ErrInvalidRequestMetadata
	}
	return canonicalAddress(addr), nil
}

func canonicalAddress(addr netip.Addr) netip.Addr {
	return addr.WithZone("").Unmap()
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	addr = canonicalAddress(addr)
	for _, prefix := range trusted {
		if prefix.IsValid() && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ValidateMutationOrigin requires one valid HTTPS Origin matching the
// configured service origin. Before service_url is configured, it requires
// direct HTTPS and derives the expected origin from the request authority.
// Forwarded-Host and Forwarded-Proto never affect the comparison.
func ValidateMutationOrigin(r *http.Request, serviceURL string) error {
	if r == nil {
		return fmt.Errorf("%w: request is nil", ErrInvalidRequestMetadata)
	}
	values := r.Header.Values("Origin")
	if len(values) != 1 {
		return fmt.Errorf("%w: exactly one Origin header is required", ErrInvalidRequestMetadata)
	}
	actual, err := parseOrigin(values[0])
	if err != nil {
		return fmt.Errorf("%w: Origin is invalid", ErrInvalidRequestMetadata)
	}
	expected, err := expectedOrigin(r, serviceURL)
	if err != nil || actual != expected {
		return fmt.Errorf("%w: Origin does not match the service origin", ErrInvalidRequestMetadata)
	}
	return nil
}

// ValidateCSRFReadOrigin protects the same-origin CSRF token GET. Every
// supplied source must match; when Sec-Fetch-Site is absent at least one
// valid Origin or Referer is required.
func ValidateCSRFReadOrigin(r *http.Request, serviceURL string) error {
	if r == nil {
		return fmt.Errorf("%w: request is nil", ErrInvalidRequestMetadata)
	}
	expected, err := expectedOrigin(r, serviceURL)
	if err != nil {
		return fmt.Errorf("%w: expected service origin is unavailable", ErrInvalidRequestMetadata)
	}

	fetchValues := r.Header.Values("Sec-Fetch-Site")
	if len(fetchValues) > 1 || (len(fetchValues) == 1 && fetchValues[0] != "same-origin") {
		return fmt.Errorf("%w: request is not same-origin", ErrInvalidRequestMetadata)
	}

	seenOrigin := false
	originValues := r.Header.Values("Origin")
	if len(originValues) > 1 {
		return fmt.Errorf("%w: Origin header is duplicated", ErrInvalidRequestMetadata)
	}
	if len(originValues) == 1 {
		origin, parseErr := parseOrigin(originValues[0])
		if parseErr != nil || origin != expected {
			return fmt.Errorf("%w: Origin does not match the service origin", ErrInvalidRequestMetadata)
		}
		seenOrigin = true
	}

	refererValues := r.Header.Values("Referer")
	if len(refererValues) > 1 {
		return fmt.Errorf("%w: Referer header is duplicated", ErrInvalidRequestMetadata)
	}
	if len(refererValues) == 1 {
		referer, parseErr := parseRefererOrigin(refererValues[0])
		if parseErr != nil || referer != expected {
			return fmt.Errorf("%w: Referer does not match the service origin", ErrInvalidRequestMetadata)
		}
		seenOrigin = true
	}
	if len(fetchValues) == 0 && !seenOrigin {
		return fmt.Errorf("%w: same-origin evidence is required", ErrInvalidRequestMetadata)
	}
	return nil
}

func expectedOrigin(r *http.Request, serviceURL string) (string, error) {
	if serviceURL != "" {
		return parseServiceURLOrigin(serviceURL)
	}
	if r.TLS == nil || r.Host == "" {
		return "", ErrInvalidRequestMetadata
	}
	return parseOrigin("https://" + r.Host)
}

func parseOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" ||
		u.ForceQuery || strings.Contains(raw, "#") {
		return "", ErrInvalidRequestMetadata
	}
	return normalizeHTTPSAuthority(u.Host)
}

func parseServiceURLOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.Host == "" ||
		u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", ErrInvalidRequestMetadata
	}
	return normalizeHTTPSAuthority(u.Host)
}

func parseRefererOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.Host == "" ||
		u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", ErrInvalidRequestMetadata
	}
	return normalizeHTTPSAuthority(u.Host)
}

func normalizeHTTPSAuthority(authority string) (string, error) {
	u, err := url.Parse("https://" + authority)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrInvalidRequestMetadata
	}
	var host string
	if strings.HasPrefix(u.Host, "[") {
		closingBracket := strings.IndexByte(u.Host, ']')
		if closingBracket < 0 {
			return "", ErrInvalidRequestMetadata
		}
		addr, parseErr := netip.ParseAddr(u.Host[1:closingBracket])
		if parseErr != nil || !addr.Is6() || addr.Zone() != "" {
			return "", ErrInvalidRequestMetadata
		}
		tail := u.Host[closingBracket+1:]
		if tail != "" && !strings.HasPrefix(tail, ":") {
			return "", ErrInvalidRequestMetadata
		}
		host = addr.String()
	} else {
		if strings.ContainsAny(u.Host, "[]") {
			return "", ErrInvalidRequestMetadata
		}
		host = u.Hostname()
		if host == "" {
			return "", ErrInvalidRequestMetadata
		}
		if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
			if addr.Zone() != "" || addr.Is6() {
				return "", ErrInvalidRequestMetadata
			}
			host = addr.String()
		} else if !validDNSHost(host) {
			return "", ErrInvalidRequestMetadata
		} else {
			host = strings.ToLower(host)
		}
	}

	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", ErrInvalidRequestMetadata
	}
	if port == "" || port == "443" {
		port = "443"
	} else {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || value == 0 {
			return "", ErrInvalidRequestMetadata
		}
		port = strconv.FormatUint(value, 10)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + port, nil
}

func validDNSHost(host string) bool {
	labelsHost := strings.TrimSuffix(host, ".")
	if len(labelsHost) == 0 || len(labelsHost) > 253 {
		return false
	}
	// A numeric dotted host that is not canonical IPv4 is ambiguous across
	// URL parsers. Reject it rather than compare two different spellings.
	numeric := true
	for i := 0; i < len(labelsHost); i++ {
		if (labelsHost[i] < '0' || labelsHost[i] > '9') && labelsHost[i] != '.' {
			numeric = false
		}
	}
	if numeric {
		return false
	}
	for _, label := range strings.Split(labelsHost, ".") {
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

// ApplySecurityHeaders sets the browser policy fixed by api-contract.md.
// HSTS is intentionally not enabled here; the MVP keeps it disabled until
// deployment-specific domain and recovery ownership are understood.
func ApplySecurityHeaders(header http.Header) {
	if header == nil {
		return
	}
	header.Set("Content-Security-Policy", securityCSP)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Frame-Options", "DENY")
}

// WithSecurityHeaders applies the browser policy before handing a request to
// the next handler. Route handlers may add narrower caching headers later.
func WithSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ApplySecurityHeaders(w.Header())
		next.ServeHTTP(w, r)
	})
}

// SafeRouteLabel returns the ServeMux route pattern, never the raw URL path
// or query. Unmatched requests use a fixed label so token paths and queries
// cannot leak into application logs.
func SafeRouteLabel(r *http.Request) string {
	if r == nil || r.Pattern == "" {
		return "unknown"
	}
	return r.Pattern
}
