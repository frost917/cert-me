package httpadapter

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestNormalizeHTTPSAuthorityCanonicalizesAndRejectsAmbiguousHosts(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		want      string
		wantErr   bool
	}{
		{name: "lowercases DNS and normalizes default port", authority: "CERT.EXAMPLE:443", want: "cert.example:443"},
		{name: "adds default port", authority: "cert.example", want: "cert.example:443"},
		{name: "canonical IPv4", authority: "192.0.2.10", want: "192.0.2.10:443"},
		{name: "compresses IPv6 and preserves nondefault port", authority: "[2001:0db8:0:0::1]:8443", want: "[2001:db8::1]:8443"},
		{name: "rejects noncanonical numeric host", authority: "192.0.2.999", wantErr: true},
		{name: "rejects empty port", authority: "cert.example:", wantErr: true},
		{name: "rejects zero port", authority: "cert.example:0", wantErr: true},
		{name: "rejects port overflow", authority: "cert.example:65536", wantErr: true},
		{name: "rejects nonnumeric port", authority: "cert.example:https", wantErr: true},
		{name: "rejects unbracketed IPv6", authority: "2001:db8::1", wantErr: true},
		{name: "rejects IPv6 zone", authority: "[fe80::1%25eth0]", wantErr: true},
		{name: "rejects user information", authority: "admin@cert.example", wantErr: true},
		{name: "rejects empty DNS label", authority: "cert..example", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeHTTPSAuthority(tt.authority)
			if tt.wantErr {
				if err == nil {
					t.Fatal("normalizeHTTPSAuthority accepted an invalid authority")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeHTTPSAuthority rejected a valid authority: %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalized authority = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestMutationOriginUsesCanonicalHTTPSOriginAndRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name       string
		serviceURL string
		origin     string
		wantErr    bool
	}{
		{name: "case and default port normalize", serviceURL: "https://cert.example", origin: "https://CERT.EXAMPLE:443"},
		{name: "IPv4 origin normalizes", serviceURL: "https://192.0.2.10", origin: "https://192.0.2.10:443"},
		{name: "IPv6 origin normalizes", serviceURL: "https://[2001:db8::1]", origin: "https://[2001:0db8:0:0::1]:443"},
		{name: "foreign port rejected", serviceURL: "https://cert.example", origin: "https://cert.example:8443", wantErr: true},
		{name: "non-HTTPS scheme rejected", serviceURL: "https://cert.example", origin: "http://cert.example", wantErr: true},
		{name: "path in Origin rejected", serviceURL: "https://cert.example", origin: "https://cert.example/path", wantErr: true},
		{name: "userinfo in Origin rejected", serviceURL: "https://cert.example", origin: "https://operator@cert.example", wantErr: true},
		{name: "malformed numeric service host rejected", serviceURL: "https://192.0.2.999", origin: "https://192.0.2.999", wantErr: true},
		{name: "userinfo in service URL rejected", serviceURL: "https://operator@cert.example", origin: "https://cert.example", wantErr: true},
		{name: "fragment in service URL rejected", serviceURL: "https://cert.example/#part", origin: "https://cert.example", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://cert.example/api/v1/settings", nil)
			request.Header.Set("Origin", tt.origin)
			err := ValidateMutationOrigin(request, tt.serviceURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateMutationOrigin error presence = %t; want error %t", err != nil, tt.wantErr)
			}
		})
	}

	t.Run("duplicate Origin is rejected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "https://cert.example/api/v1/settings", nil)
		request.Header.Add("Origin", "https://cert.example")
		request.Header.Add("Origin", "https://cert.example")
		if err := ValidateMutationOrigin(request, "https://cert.example"); !errors.Is(err, ErrInvalidRequestMetadata) {
			t.Fatal("ValidateMutationOrigin accepted duplicated Origin values")
		}
	})

	t.Run("unconfigured service URL requires direct HTTPS and ignores forwarded authority", func(t *testing.T) {
		tests := []struct {
			name      string
			target    string
			origin    string
			tls       bool
			forwarded bool
			wantErr   bool
		}{
			{name: "direct HTTPS authority accepted", target: "https://cert.example/settings", origin: "https://cert.example", tls: true},
			{name: "plain HTTP rejected", target: "http://cert.example/settings", origin: "https://cert.example", wantErr: true},
			{name: "forwarded host cannot authorize a foreign origin", target: "http://attacker.example/settings", origin: "https://cert.example", forwarded: true, wantErr: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodPost, tt.target, nil)
				if tt.tls {
					request.TLS = &tls.ConnectionState{}
				}
				request.Header.Set("Origin", tt.origin)
				if tt.forwarded {
					request.Header.Set("X-Forwarded-Host", "cert.example")
					request.Header.Set("X-Forwarded-Proto", "https")
				}
				err := ValidateMutationOrigin(request, "")
				if (err != nil) != tt.wantErr {
					t.Fatalf("ValidateMutationOrigin error presence = %t; want error %t", err != nil, tt.wantErr)
				}
			})
		}
	})
}

func TestResolveClientIPHonorsTrustedProxyChainAndRejectsMalformedForwarding(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:1::/48")}
	tests := []struct {
		name      string
		remote    string
		forwarded []string
		want      string
		wantErr   bool
	}{
		{name: "untrusted peer ignores malformed forwarding", remote: "192.0.2.5:1234", forwarded: []string{"not-an-address"}, want: "192.0.2.5"},
		{name: "trusted peer with no forwarding uses peer", remote: "10.0.0.5:1234", want: "10.0.0.5"},
		{name: "trusted proxy chain selects first untrusted hop", remote: "10.0.0.5:1234", forwarded: []string{"198.51.100.7, 10.0.0.4"}, want: "198.51.100.7"},
		{name: "all trusted hops fall back to earliest hop", remote: "10.0.0.5:1234", forwarded: []string{"10.0.0.1, 10.0.0.4"}, want: "10.0.0.1"},
		{name: "mapped IPv4 peer is unmapped", remote: "[::ffff:192.0.2.8]:1234", want: "192.0.2.8"},
		{name: "IPv6 zone is removed", remote: "[fe80::1%eth0]:1234", want: "fe80::1"},
		{name: "invalid remote address rejected", remote: "unknown", wantErr: true},
		{name: "duplicate forwarding header rejected", remote: "10.0.0.5:1234", forwarded: []string{"198.51.100.7", "198.51.100.8"}, wantErr: true},
		{name: "empty forwarding hop rejected", remote: "10.0.0.5:1234", forwarded: []string{"198.51.100.7,,10.0.0.4"}, wantErr: true},
		{name: "invalid forwarding address rejected", remote: "10.0.0.5:1234", forwarded: []string{"not-an-address"}, wantErr: true},
		{name: "too many forwarding hops rejected", remote: "10.0.0.5:1234", forwarded: []string{strings.TrimSuffix(strings.Repeat("198.51.100.1,", maxForwardedForHops+1), ",")}, wantErr: true},
		{name: "oversized forwarding header rejected", remote: "10.0.0.5:1234", forwarded: []string{strings.Repeat("1", maxForwardedForBytes+1)}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://cert.example/api/v1/setup", nil)
			request.RemoteAddr = tt.remote
			for _, value := range tt.forwarded {
				request.Header.Add("X-Forwarded-For", value)
			}
			got, err := ResolveClientIP(request, trusted)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidRequestMetadata) {
					t.Fatal("ResolveClientIP did not reject malformed client metadata")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveClientIP rejected valid client metadata: %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("client IP = %q; want %q", got, tt.want)
			}
		})
	}
	if _, err := ResolveClientIP(nil, trusted); !errors.Is(err, ErrInvalidRequestMetadata) {
		t.Fatal("ResolveClientIP accepted a nil request")
	}
}

func TestSecurityHeadersAndSafeRouteLabels(t *testing.T) {
	ApplySecurityHeaders(nil)
	response := httptest.NewRecorder()
	response.Header().Set("Content-Security-Policy", "unsafe-old-policy")
	ApplySecurityHeaders(response.Header())
	wantHeaders := map[string]string{
		"Content-Security-Policy": securityCSP,
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
	}
	for name, want := range wantHeaders {
		if got := response.Header().Get(name); got != want {
			t.Fatalf("security header %q = %q; want policy value", name, got)
		}
	}
	if got := SafeRouteLabel(nil); got != "unknown" {
		t.Fatalf("nil route label = %q; want unknown", got)
	}
	if got := SafeRouteLabel(httptest.NewRequest(http.MethodGet, "/unmatched?token=secret", nil)); got != "unknown" {
		t.Fatalf("unmatched route label = %q; want unknown", got)
	}

	const pathToken = "sensitive-path-token"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /reset-password/{token}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(SafeRouteLabel(r)))
	})
	routed := httptest.NewRecorder()
	mux.ServeHTTP(routed, httptest.NewRequest(http.MethodGet, "/reset-password/"+pathToken+"?token=query-secret", nil))
	if got := routed.Body.String(); got != "GET /reset-password/{token}" {
		t.Fatal("safe route label did not return the ServeMux route pattern")
	}
	if strings.Contains(routed.Body.String(), pathToken) || strings.Contains(routed.Body.String(), "query-secret") {
		t.Fatal("safe route label exposed a token path or query value")
	}

	nextSawPolicy := false
	wrapper := WithSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextSawPolicy = w.Header().Get("Content-Security-Policy") == securityCSP
		w.WriteHeader(http.StatusNoContent)
	}))
	wrapped := httptest.NewRecorder()
	wrapper.ServeHTTP(wrapped, httptest.NewRequest(http.MethodGet, "/", nil))
	if !nextSawPolicy || wrapped.Code != http.StatusNoContent {
		t.Fatal("WithSecurityHeaders did not apply CSP before calling the route")
	}
	for name, want := range wantHeaders {
		if got := wrapped.Header().Get(name); got != want {
			t.Fatalf("wrapped response omitted security header %q", name)
		}
	}
}

func TestHomePageAndAssetsUseLocalCSPCompatibleConfiguration(t *testing.T) {
	h := newHTTPTestHarness(t, httpTestServiceURL)
	page := h.request(http.MethodGet, "/", "", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("home page status = %d; want %d", page.Code, http.StatusOK)
	}
	for _, fragment := range []string{
		`"allowEval":false`,
		`"allowScriptTags":false`,
		`"includeIndicatorStyles":false`,
		`src="/assets/htmx.min.js"`,
		`src="/assets/app.js"`,
	} {
		if !strings.Contains(page.Body.String(), fragment) {
			t.Fatalf("home page omitted a local CSP setting or asset reference")
		}
	}
	if strings.Contains(page.Body.String(), "https://") {
		t.Fatal("home page included a remote asset or external origin")
	}

	asset := h.request(http.MethodGet, "/assets/app.js", "", nil)
	if asset.Code != http.StatusOK {
		t.Fatalf("local app asset status = %d; want %d", asset.Code, http.StatusOK)
	}
	if !strings.Contains(asset.Header().Get("Content-Type"), "javascript") {
		t.Fatal("local app asset was not served as JavaScript")
	}
}
