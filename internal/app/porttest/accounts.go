package porttest

import (
	"context"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type accountRepo struct{ s *state }

var _ port.AccountRepository = accountRepo{}

func (r accountRepo) GetAccountForUpdate(_ context.Context, id domain.AccountID) (domain.Account, error) {
	a, ok := r.s.accounts[id]
	if !ok {
		return domain.Account{}, port.ErrNotFound
	}
	return a, nil
}

func (r accountRepo) FindSessionByHash(_ context.Context, hash domain.TokenHash) (domain.SessionState, error) {
	id, ok := r.s.sessionsByHash[hash.Hex()]
	if !ok {
		return domain.SessionState{}, port.ErrNotFound
	}
	return r.s.sessions[id], nil
}

func (r accountRepo) GetSessionForUpdate(_ context.Context, sessionID domain.SessionID) (domain.SessionState, error) {
	sess, ok := r.s.sessions[sessionID]
	if !ok {
		return domain.SessionState{}, port.ErrNotFound
	}
	return sess, nil
}

func (r accountRepo) InsertAccount(_ context.Context, account domain.Account) error {
	if _, ok := r.s.accounts[account.ID()]; ok {
		return ErrDuplicate
	}
	for _, existing := range r.s.accounts {
		if existing.NormalizedLoginName() == account.NormalizedLoginName() {
			return ErrDuplicate
		}
	}
	r.s.accounts[account.ID()] = account
	return nil
}

// SaveAccount enforces the standard optimistic-lock contract
// (docs/backend-implementation.md §4/§5): the row is checked against
// expectedVersion, and the object's own final Version() is written --
// never expectedVersion+1 -- so a caller that chained more than one domain
// transition before saving is honored exactly.
func (r accountRepo) SaveAccount(_ context.Context, account domain.Account, expectedVersion domain.Version) error {
	existing, ok := r.s.accounts[account.ID()]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.accounts[account.ID()] = account
	return nil
}

func (r accountRepo) InsertSession(_ context.Context, session domain.SessionState) error {
	r.s.sessions[session.ID()] = session
	r.s.sessionsByHash[session.TokenHash().Hex()] = session.ID()
	return nil
}

func (r accountRepo) DeleteSession(_ context.Context, sessionID domain.SessionID) error {
	sess, ok := r.s.sessions[sessionID]
	if !ok {
		return nil // idempotent: already gone
	}
	delete(r.s.sessions, sessionID)
	delete(r.s.sessionsByHash, sess.TokenHash().Hex())
	return nil
}

func (r accountRepo) DeleteAllSessions(_ context.Context, accountID domain.AccountID) error {
	for id, sess := range r.s.sessions {
		if sess.AccountID() == accountID {
			delete(r.s.sessions, id)
			delete(r.s.sessionsByHash, sess.TokenHash().Hex())
		}
	}
	return nil
}

func (r accountRepo) GetResetToken(_ context.Context, tokenHash domain.TokenHash) (domain.AdminResetToken, error) {
	id, ok := r.s.resetTokensByHash[tokenHash.Hex()]
	if !ok {
		return domain.AdminResetToken{}, port.ErrNotFound
	}
	return r.s.resetTokens[id], nil
}

func (r accountRepo) InsertResetToken(_ context.Context, token domain.AdminResetToken) error {
	r.s.resetTokens[token.ID()] = token
	r.s.resetTokensByHash[token.TokenHash().Hex()] = token.ID()
	return nil
}

func (r accountRepo) InvalidateResetTokens(_ context.Context, accountID domain.AccountID, now domain.Instant) error {
	for id, tok := range r.s.resetTokens {
		if tok.AccountID() != accountID {
			continue
		}
		next, err := tok.Invalidate(now)
		if err != nil {
			// Invalidate is defined idempotent/never-touch-a-consumed-token;
			// a rejection here means this row must simply be left as is.
			continue
		}
		r.s.resetTokens[id] = next
	}
	return nil
}

func (r accountRepo) SaveRateLimit(_ context.Context, record port.RateLimitRecord) error {
	key := rateLimitKey{
		kind:        record.Kind,
		subjectHash: record.SubjectHash.Hex(),
		windowStart: record.WindowStart.UnixMicro(),
	}
	r.s.rateLimits[key] = record
	return nil
}
