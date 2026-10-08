package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type systemClock struct{}

func (systemClock) Now() domain.Instant { return domain.NewInstant(time.Now().UTC()) }

type randomIDs struct{}

func (randomIDs) NewUUID() string {
	id, err := newUUID()
	if err != nil {
		return ""
	}
	return id
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("runtime: generate UUID: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	var formatted [36]byte
	compact := hex.EncodeToString(raw[:])
	position := 0
	for i := range formatted {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			formatted[i] = '-'
			continue
		}
		formatted[i] = compact[position]
		position++
	}
	return string(formatted[:]), nil
}

type adminAuthorizer struct{}

var _ port.Authorizer = adminAuthorizer{}

func (adminAuthorizer) Authorize(ctx context.Context, principal contract.Principal, action port.Action, scope port.AuthorizationScope) error {
	if ctx == nil {
		return errors.New("runtime: authorization context is required")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("runtime: authorization canceled: %w", err)
	}
	if err := action.Validate(); err != nil {
		return contract.NewAppError(contract.ErrorKindForbidden, "action_not_permitted", "the requested action is not permitted")
	}
	if err := scope.Validate(); err != nil {
		return contract.NewAppError(contract.ErrorKindForbidden, "authorization_scope_invalid", "the requested authorization scope is invalid")
	}
	if action == port.ActionQueryReadPublicCA && principal.IsAnonymous() {
		return nil
	}
	if !principal.IsAdmin() {
		return contract.NewAppError(contract.ErrorKindForbidden, "administrator_required", "this action requires an administrator session")
	}
	return nil
}

type operationalLogger struct{ logger *slog.Logger }

var _ port.OperationalLogger = operationalLogger{}

func (l operationalLogger) Record(event port.OperationalEvent) {
	if l.logger == nil {
		return
	}
	l.logger.Warn("operational event",
		"code", event.Code,
		"request_id", event.RequestID,
		"stage", event.Stage,
		"grant_id", event.GrantID,
		"delivery_id", event.DeliveryID,
		"certificate_id", event.CertificateID,
	)
}
