package httpadapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"cert-me/internal/cryptoformats"
)

func TestPersistedSettingsURLHasUsableMutationOrigin(t *testing.T) {
	for _, candidate := range []string{
		"https://localhost", "https://cert-me", "https://cert.example.invalid/pki",
		"https://CERT.EXAMPLE.:0443/pki", "https://127.0.0.1:8443", "https://[::1]:8443",
		"https://xn--caf-dma.example", "https://[::ffff:127.0.0.1]",
	} {
		t.Run(candidate, func(t *testing.T) {
			if err := (cryptoformats.URLValidator{}).Validate(context.Background(), candidate); err != nil {
				t.Fatalf("settings validator rejected a supported URL: %v", err)
			}
			parsed, err := url.Parse(candidate)
			if err != nil {
				t.Fatal(err)
			}
			origin := parsed.Scheme + "://" + parsed.Host
			request := httptest.NewRequest(http.MethodPost, origin+"/api/v1/setup/complete", nil)
			request.Header.Set("Origin", origin)
			if err := ValidateMutationOrigin(request, candidate); err != nil {
				t.Fatal("a persisted supported URL must allow its own browser mutation origin")
			}
		})
	}
}
