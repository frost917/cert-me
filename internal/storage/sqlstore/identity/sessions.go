package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// Session methods are kept here because the session bearer and CSRF hashes
// share the same row and lifetime.

func sessionFromRow(row rowScanner) (domain.SessionState, error) {
	var id, accountID, tokenHash, csrfSecretHash string
	var epoch, lastSeenAt, absoluteExpiresAt int64
	if err := row.Scan(&id, &accountID, &tokenHash, &epoch, &lastSeenAt, &absoluteExpiresAt, &csrfSecretHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.SessionState{}, port.ErrNotFound
		}
		return domain.SessionState{}, failed("read session row", err)
	}
	parsedID, err := domain.ParseSessionID(id)
	if err != nil {
		return domain.SessionState{}, failed("decode session row", err)
	}
	parsedAccountID, err := domain.ParseAccountID(accountID)
	if err != nil {
		return domain.SessionState{}, failed("decode session row", err)
	}
	parsedHash, err := domain.ParseTokenHash(tokenHash)
	if err != nil {
		return domain.SessionState{}, failed("decode session row", err)
	}
	parsedCSRFHash, err := domain.ParseTokenHash(csrfSecretHash)
	if err != nil {
		return domain.SessionState{}, failed("decode session row", err)
	}
	parsedEpoch, err := domain.ParseAuthEpoch(epoch)
	if err != nil {
		return domain.SessionState{}, failed("decode session row", err)
	}
	session, err := domain.NewSessionState(domain.SessionStateFacts{
		ID:                parsedID,
		AccountID:         parsedAccountID,
		TokenHash:         parsedHash,
		CSRFSecretHash:    parsedCSRFHash,
		AuthEpoch:         parsedEpoch,
		LastSeenAt:        domain.InstantFromUnixMicro(lastSeenAt),
		AbsoluteExpiresAt: domain.InstantFromUnixMicro(absoluteExpiresAt),
	})
	if err != nil {
		return domain.SessionState{}, failed("decode session row", err)
	}
	return session, nil
}

// FindSessionByHash resolves a session without taking a row lock.
func (r *AccountRepository) FindSessionByHash(ctx context.Context, hash domain.TokenHash) (domain.SessionState, error) {
	if err := validContext(ctx); err != nil {
		return domain.SessionState{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT id, account_id, token_hash, auth_epoch, last_seen_at, absolute_expires_at, csrf_secret_hash FROM sessions WHERE token_hash = " + b.Add(hash.Hex())
	return sessionFromRow(r.executor.QueryRowContext(ctx, query, b.Args()...))
}

// GetSessionForUpdate reads and locks one session in the current write.
func (r *AccountRepository) GetSessionForUpdate(ctx context.Context, sessionID domain.SessionID) (domain.SessionState, error) {
	if err := validContext(ctx); err != nil {
		return domain.SessionState{}, err
	}
	b := r.dialect.NewBuilder()
	query := "SELECT id, account_id, token_hash, auth_epoch, last_seen_at, absolute_expires_at, csrf_secret_hash FROM sessions WHERE id = " + b.Add(string(sessionID)) + lockSuffix(r.dialect)
	return sessionFromRow(r.executor.QueryRowContext(ctx, query, b.Args()...))
}

func (r *AccountRepository) InsertSession(ctx context.Context, session domain.SessionState) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	if session.CSRFSecretHash().IsZero() {
		return failed("insert session", errors.New("session CSRF secret hash is required"))
	}
	now := nowUnixMicro()
	b := r.dialect.NewBuilder()
	query := "INSERT INTO sessions (id, created_at, token_hash, account_id, auth_epoch, last_seen_at, absolute_expires_at, csrf_secret_hash) VALUES (" + strings.Join([]string{
		b.Add(string(session.ID())), b.Add(now), b.Add(session.TokenHash().Hex()), b.Add(string(session.AccountID())),
		b.Add(session.AuthEpoch().Int64()), b.Add(session.LastSeenAt().UnixMicro()), b.Add(session.AbsoluteExpiresAt().UnixMicro()),
		b.Add(session.CSRFSecretHash().Hex()),
	}, ", ") + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return duplicateOrFailed("insert session", err)
	}
	return nil
}

func (r *AccountRepository) DeleteSession(ctx context.Context, sessionID domain.SessionID) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "DELETE FROM sessions WHERE id = " + b.Add(string(sessionID))
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return failed("delete session", err)
	}
	return nil
}

func (r *AccountRepository) DeleteAllSessions(ctx context.Context, accountID domain.AccountID) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "DELETE FROM sessions WHERE account_id = " + b.Add(string(accountID))
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return failed("delete account sessions", err)
	}
	return nil
}

func (r *AccountRepository) SaveSession(ctx context.Context, session domain.SessionState) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE sessions SET account_id = " + b.Add(string(session.AccountID())) +
		", token_hash = " + b.Add(session.TokenHash().Hex()) +
		", csrf_secret_hash = " + b.Add(session.CSRFSecretHash().Hex()) +
		", auth_epoch = " + b.Add(session.AuthEpoch().Int64()) +
		", last_seen_at = " + b.Add(session.LastSeenAt().UnixMicro()) +
		", absolute_expires_at = " + b.Add(session.AbsoluteExpiresAt().UnixMicro()) +
		" WHERE id = " + b.Add(string(session.ID()))
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return duplicateOrFailed("save session", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return failed("save session", err)
	}
	if rows == 0 {
		// A no-op refresh may leave every stored value unchanged. Check
		// existence so it remains idempotent but still satisfies the missing-
		// row contract.
		check := r.dialect.NewBuilder()
		var one int
		query := "SELECT 1 FROM sessions WHERE id = " + check.Add(string(session.ID()))
		if err := r.executor.QueryRowContext(ctx, query, check.Args()...).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return port.ErrNotFound
			}
			return failed("check session after save", err)
		}
	}
	return nil
}
