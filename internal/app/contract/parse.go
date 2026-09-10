package contract

import (
	"fmt"

	"cert-me/internal/domain"
)

const idempotencyKeyLength = 36

// parseIdempotencyKey enforces the UUID shape the doc requires for retryable
// methods. It mirrors the domain ID check rather than accepting any string, so
// two unrelated clients cannot collide on a short key and replay each other's
// result.
func parseIdempotencyKey(raw string) (string, error) {
	if len(raw) != idempotencyKeyLength {
		return "", fmt.Errorf("%w: idempotency key must be a uuid", domain.ErrInvalidValue)
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", fmt.Errorf("%w: idempotency key must be a uuid", domain.ErrInvalidValue)
			}
			continue
		}
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		if !isDigit && !isLowerHex {
			return "", fmt.Errorf("%w: idempotency key must be a lowercase uuid", domain.ErrInvalidValue)
		}
	}
	return raw, nil
}
