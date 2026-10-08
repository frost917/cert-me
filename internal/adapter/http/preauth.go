package httpadapter

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	preAuthCookieName = "__Host-certme_preauth"
	preAuthLifetime   = 10 * time.Minute
)

func (h *setupHandler) getPreAuthCSRF(w http.ResponseWriter, r *http.Request) {
	requestID, ok := ensureRequestID(w)
	if !ok {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", "unavailable", nil)
		return
	}
	serviceURL := h.currentServiceURL()
	if err := ValidateCSRFReadOrigin(r, serviceURL); err != nil {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", requestID, nil)
		return
	}
	origin, err := expectedOrigin(r, serviceURL)
	if err != nil {
		writeSetupError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified.", requestID, nil)
		return
	}

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", requestID, nil)
		return
	}
	expiresAt := time.Now().Add(preAuthLifetime).Unix()
	token, err := h.signPreAuthToken(expiresAt, "https://"+origin, nonce[:])
	if err != nil {
		writeSetupError(w, http.StatusServiceUnavailable, "service_unavailable", "The request could not be processed.", requestID, nil)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     preAuthCookieName,
		Value:    base64.RawURLEncoding.EncodeToString(nonce[:]),
		Path:     "/",
		MaxAge:   int(preAuthLifetime.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeSetupJSON(w, http.StatusOK, struct {
		Data struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"data"`
	}{Data: struct {
		CSRFToken string `json:"csrf_token"`
	}{CSRFToken: token}})
}

func (h *setupHandler) signPreAuthToken(expiresAt int64, origin string, nonce []byte) (string, error) {
	payload := "v1." + strconv.FormatInt(expiresAt, 10)
	mac := hmac.New(sha256.New, h.preAuthKey[:])
	fields := [][]byte{
		[]byte("cert-me/pre-auth/v1\x00"),
		[]byte(payload),
		{0},
		[]byte("pre-auth"),
		{0},
		[]byte(origin),
		{0},
		nonce,
	}
	for _, field := range fields {
		if _, err := mac.Write(field); err != nil {
			return "", fmt.Errorf("httpadapter: sign pre-auth token: %w", err)
		}
	}
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (h *setupHandler) validatePreAuth(r *http.Request, origin string) error {
	values := r.Header.Values("X-CSRF-Token")
	if len(values) != 1 || len(values[0]) < 32 || len(values[0]) > 256 {
		return errInvalidPreAuth
	}
	cookie, err := uniquePreAuthCookie(r)
	if err != nil {
		return errInvalidPreAuth
	}
	nonce, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != cookie {
		return errInvalidPreAuth
	}

	parts := strings.Split(values[0], ".")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] == "" {
		return errInvalidPreAuth
	}
	expiresAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return errInvalidPreAuth
	}
	now := time.Now().Unix()
	if expiresAt <= now || expiresAt-now > int64(preAuthLifetime.Seconds()) {
		return errInvalidPreAuth
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != sha256.Size || base64.RawURLEncoding.EncodeToString(signature) != parts[2] {
		return errInvalidPreAuth
	}
	expected, err := h.signPreAuthToken(expiresAt, origin, nonce)
	if err != nil {
		return errInvalidPreAuth
	}
	expectedSignature := strings.LastIndexByte(expected, '.')
	if expectedSignature < 0 {
		return errInvalidPreAuth
	}
	expectedMAC, err := base64.RawURLEncoding.DecodeString(expected[expectedSignature+1:])
	if err != nil || !hmac.Equal(signature, expectedMAC) {
		return errInvalidPreAuth
	}
	return nil
}

func uniquePreAuthCookie(r *http.Request) (string, error) {
	var value string
	found := false
	for _, cookie := range r.Cookies() {
		if cookie.Name != preAuthCookieName {
			continue
		}
		if found {
			return "", errInvalidPreAuth
		}
		found = true
		value = cookie.Value
	}
	if !found {
		return "", errInvalidPreAuth
	}
	return value, nil
}

var errInvalidPreAuth error = errors.New("httpadapter: invalid pre-auth credential")
