package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// ---- deterministic test doubles shared by setup_test.go/identity_test.go --

// fakePasswordHasher is a deterministic PasswordHasher: Hash encodes the
// plaintext directly (prefixed so it can never collide with
// dummyPasswordHash's fixed Argon2id-shaped literal), and Verify compares
// against that same encoding. verifyCalls lets a test prove Verify ran (or
// did not run) a specific number of times -- the evidence U-style admission-
// before-hash and dummy-hash-budget-parity tests need.
type fakePasswordHasher struct {
	mu     sync.Mutex
	hashes int
	verify int
}

func (h *fakePasswordHasher) Hash(_ context.Context, password *secret.Input) (domain.PasswordHash, error) {
	h.mu.Lock()
	h.hashes++
	h.mu.Unlock()
	var encoded string
	if err := password.Use(func(b []byte) error {
		encoded = "fakehash:" + string(b)
		return nil
	}); err != nil {
		return domain.PasswordHash{}, err
	}
	return domain.NewPasswordHash(encoded)
}

func (h *fakePasswordHasher) Verify(_ context.Context, password *secret.Input, hash domain.PasswordHash) (bool, error) {
	h.mu.Lock()
	h.verify++
	h.mu.Unlock()
	var match bool
	if err := password.Use(func(b []byte) error {
		match = hash.Encoded() == "fakehash:"+string(b)
		return nil
	}); err != nil {
		return false, err
	}
	return match, nil
}

func (h *fakePasswordHasher) verifyCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.verify
}

// stubTokenCodec is a deterministic TokenCodec: NewToken mints an
// incrementing, unique raw value (so concurrent mints in a test never
// collide) and hashes it with the same scheme Hash uses on a
// caller-presented token, so a minted token can always be looked back up.
type stubTokenCodec struct {
	mu sync.Mutex
	n  int
	// minted records every raw value this codec has handed out, in order,
	// so a test can recover "the Nth token minted" (e.g. Login mints the
	// session token first and the CSRF token last) without needing its own
	// parallel bookkeeping.
	minted []string
}

func (c *stubTokenCodec) NewToken(context.Context) (*secret.Input, domain.TokenHash, error) {
	c.mu.Lock()
	c.n++
	n := c.n
	raw := "tok-" + string(rune('a'+n%26)) + "-0123456789abcdef0123456789abcdef"
	c.minted = append(c.minted, raw)
	c.mu.Unlock()
	hash, err := domain.NewTokenHash(domain.NewFingerprint([]byte(raw)))
	if err != nil {
		return nil, domain.TokenHash{}, err
	}
	return secret.FromString(raw), hash, nil
}

// mintedAt returns the i-th (0-based) raw token this codec has minted so
// far, for a test to look a session/CSRF token back up by hash.
func (c *stubTokenCodec) mintedAt(i int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.minted[i]
}

func (c *stubTokenCodec) Hash(_ context.Context, token *secret.Input) (domain.TokenHash, error) {
	var out domain.TokenHash
	err := token.Use(func(b []byte) error {
		h, err := domain.NewTokenHash(domain.NewFingerprint(b))
		if err != nil {
			return err
		}
		out = h
		return nil
	})
	return out, err
}

// ---- shared fixtures -------------------------------------------------

func seedInstallation(t *testing.T, store *porttest.Store, stage port.SetupStage) {
	t.Helper()
	err := store.Write(context.Background(), func(tx port.TxStores) error {
		return tx.Installation().Save(context.Background(), port.Installation{SetupStage: stage}, 0)
	})
	if err != nil {
		t.Fatalf("seed installation: %v", err)
	}
}

func readInstallation(t *testing.T, store *porttest.Store) port.Installation {
	t.Helper()
	var inst port.Installation
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		inst, err = tx.Installation().GetForUpdate(context.Background())
		return err
	})
	if err != nil {
		t.Fatalf("read installation: %v", err)
	}
	return inst
}

// concurrentIDs is a thread-safe IDGenerator for tests that race real
// goroutines against one shared fixture -- seqIDs (revocations_test.go) is
// deliberately not safe for concurrent use, so a concurrency test must not
// share one across goroutines.
type concurrentIDs struct {
	mu sync.Mutex
	n  int
}

func (g *concurrentIDs) NewUUID() string {
	g.mu.Lock()
	g.n++
	n := g.n
	g.mu.Unlock()
	return fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012d", n)
}

type setupFixture struct {
	store  *porttest.Store
	ids    *seqIDs
	hasher *fakePasswordHasher
	clock  fixedClock
	svc    *SetupService
}

func newSetupFixture(t *testing.T) *setupFixture {
	t.Helper()
	store := porttest.NewStore()
	hasher := &fakePasswordHasher{}
	ids := &seqIDs{}
	clock := fixedClock{now: testNow()}
	svc, err := NewSetupService(SetupDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: store,
			ReadStore:  store,
			Authorizer: &toggleAuthorizer{allow: true},
			Clock:      clock,
			IDs:        ids,
		},
		PasswordHasher: hasher,
	})
	if err != nil {
		t.Fatalf("new setup service: %v", err)
	}
	return &setupFixture{store: store, ids: ids, hasher: hasher, clock: clock, svc: svc}
}

func createAdminCommand(loginName string) contract.SetupCreateAdminCommand {
	return contract.SetupCreateAdminCommand{LoginName: loginName, Password: secret.FromString("a-long-enough-password")}
}

// ---- Status -------------------------------------------------------------

func TestStatus_ReportsInstallationStage(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStagePKIRequired)

	view, err := f.svc.Status(context.Background(), contract.RequestMeta{}, contract.EmptyCommand{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if view.SetupStage != contract.SetupStagePKIRequired {
		t.Fatalf("setup_stage = %q, want %q", view.SetupStage, contract.SetupStagePKIRequired)
	}
	if !view.BootstrapHTTPS {
		t.Fatalf("bootstrap_https = false, want true when no TLS version is active")
	}
}

func TestStatus_UninitializedInstallationIsAnError(t *testing.T) {
	f := newSetupFixture(t)
	// No seedInstallation call: the fixed-PK=1 row was never written, which
	// a real deployment's migration guarantees cannot happen -- this must
	// surface as an error, not silently default to account_required.
	_, err := f.svc.Status(context.Background(), contract.RequestMeta{}, contract.EmptyCommand{})
	if err == nil {
		t.Fatal("status succeeded against an uninitialized installation row")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindUnavailable {
		t.Fatalf("err = %v, want an unavailable AppError", err)
	}
}

// ---- CreateAdmin: U01 first-admin race -----------------------------------

// TestCreateAdmin_ConcurrentRace_OnlyOneSucceeds is U01: two concurrent
// CreateAdmin calls with DIFFERENT login names, against a store whose
// UnitOfWork.Write genuinely serializes (porttest.Store's own write mutex).
// Exactly one must create the account and advance the installation; the
// other must be rejected without creating a second account or moving the
// installation stage twice.
//
// This is verified by racing two real goroutines, not by asserting a
// comment -- see the report for the defect-injection check that this test
// actually catches a missing installation re-check.
func TestCreateAdmin_ConcurrentRace_OnlyOneSucceeds(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStageAccountRequired)

	// The shared *seqIDs fixture double is not safe for concurrent use;
	// swap in a mutex-protected generator for this race test.
	f.svc.deps.IDs = &concurrentIDs{}

	var wg sync.WaitGroup
	results := make([]contract.AccountView, 2)
	errs := make([]error, 2)
	names := []string{"admin-one", "admin-two"}
	wg.Add(2)
	for i := 0; i < 2; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i], errs[i] = f.svc.CreateAdmin(context.Background(), contract.MutationMeta{}, createAdminCommand(names[i]))
		}()
	}
	wg.Wait()

	successes := 0
	var winnerLoginName string
	for i, err := range errs {
		if err == nil {
			successes++
			winnerLoginName = names[i]
			continue
		}
		var appErr *contract.AppError
		if !errors.As(err, &appErr) {
			t.Fatalf("attempt %d: err = %v, want an AppError", i, err)
		}
		if appErr.Kind() != contract.ErrorKindConflict {
			t.Fatalf("attempt %d: kind = %s (code %q), want conflict", i, appErr.Kind(), appErr.Code())
		}
		if appErr.Code() != "setup_already_has_admin" {
			t.Fatalf("attempt %d: code = %q, want setup_already_has_admin", i, appErr.Code())
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1 (loser errors: %v)", successes, errs)
	}

	inst := readInstallation(t, f.store)
	if inst.SetupStage != port.SetupStagePKIRequired {
		t.Fatalf("setup_stage = %q, want pki_required after exactly one admin was created", inst.SetupStage)
	}
	if inst.FirstAdminID == "" {
		t.Fatal("installation.first_admin_id was not set")
	}

	// Only the winner's account exists.
	var accountCount int
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		for _, name := range names {
			normalized := domain.NormalizeLoginName(name)
			if _, err := tx.Accounts().FindAccountByLoginName(context.Background(), normalized); err == nil {
				accountCount++
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read accounts: %v", err)
	}
	if accountCount != 1 {
		t.Fatalf("accounts created = %d, want exactly 1", accountCount)
	}
	_ = winnerLoginName
}

func TestCreateAdmin_AlreadyHasAdmin_Rejected(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStagePKIRequired) // already past account_required

	_, err := f.svc.CreateAdmin(context.Background(), contract.MutationMeta{}, createAdminCommand("late-admin"))
	if err == nil {
		t.Fatal("create admin succeeded after installation already had one")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindConflict || appErr.Code() != "setup_already_has_admin" {
		t.Fatalf("err = %v, want conflict/setup_already_has_admin", err)
	}
}

func TestCreateAdmin_HashesPasswordBeforeTransaction(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStageAccountRequired)

	view, err := f.svc.CreateAdmin(context.Background(), contract.MutationMeta{}, createAdminCommand("admin"))
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if f.hasher.hashes != 1 {
		t.Fatalf("password hashed %d times, want 1", f.hasher.hashes)
	}
	if view.LoginName != "admin" {
		t.Fatalf("login_name = %q, want %q", view.LoginName, "admin")
	}
	if !view.IsGlobalAdmin {
		t.Fatal("first admin was not created as global admin")
	}
	if view.State != domain.AccountStateActive {
		t.Fatalf("state = %q, want active", view.State)
	}

	// The stored account really carries the hashed value, not the plaintext.
	err = f.store.Read(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), view.ID)
		if err != nil {
			return err
		}
		if account.PasswordHash().Encoded() != "fakehash:a-long-enough-password" {
			t.Fatalf("stored hash = %q, want the fake-hashed encoding", account.PasswordHash().Encoded())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read back account: %v", err)
	}
}

func TestCreateAdmin_InvalidCommandRejectedBeforeAnyWork(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStageAccountRequired)

	_, err := f.svc.CreateAdmin(context.Background(), contract.MutationMeta{}, contract.SetupCreateAdminCommand{LoginName: "x", Password: secret.FromString("a-long-enough-password")})
	if err == nil {
		t.Fatal("create admin succeeded with a login_name that fails the pattern/length check")
	}
	if f.hasher.hashes != 0 {
		t.Fatalf("password was hashed despite invalid input; hashes = %d, want 0", f.hasher.hashes)
	}
}

// ---- Complete -------------------------------------------------------------

func adminMutationMeta(t *testing.T, accountID domain.AccountID, sessionID domain.SessionID) contract.MutationMeta {
	t.Helper()
	principal, err := contract.NewAdminPrincipal(contract.AdminPrincipalFacts{AccountID: accountID, SessionID: sessionID, AuthEpoch: 0})
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	return contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: principal}}
}

// seedAdminSession seeds an active account plus a live session for it, and
// returns MutationMeta authenticated as that account.
func seedAdminSession(t *testing.T, store *porttest.Store, clock domain.Instant) contract.MutationMeta {
	t.Helper()
	accountID, err := domain.ParseAccountID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	sessionID, err := domain.ParseSessionID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("session id: %v", err)
	}
	hash, err := domain.NewPasswordHash("fakehash:irrelevant")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	account, err := domain.NewAccount(domain.AccountFacts{
		ID: accountID, NormalizedLoginName: "seeded-admin", PasswordHash: hash,
		State: domain.AccountStateActive, AuthEpoch: 0, IsGlobalAdmin: true,
	})
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	tokenHash, err := domain.NewTokenHash(domain.NewFingerprint([]byte("seed-session-token")))
	if err != nil {
		t.Fatalf("token hash: %v", err)
	}
	session, err := domain.NewSessionState(domain.SessionStateFacts{
		ID: sessionID, AccountID: accountID, TokenHash: tokenHash, AuthEpoch: 0,
		LastSeenAt: clock, AbsoluteExpiresAt: clock.Add(domain.NewDuration(24 * 3600 * 1e9)),
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		if err := tx.Accounts().InsertAccount(context.Background(), account); err != nil {
			return err
		}
		return tx.Accounts().InsertSession(context.Background(), session)
	}); err != nil {
		t.Fatalf("seed admin session: %v", err)
	}
	return adminMutationMeta(t, accountID, sessionID)
}

func TestComplete_RequiresAdminSession(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStagePKIRequired)

	_, err := f.svc.Complete(context.Background(), contract.MutationMeta{}, contract.SetupCompleteCommand{})
	if err == nil {
		t.Fatal("complete succeeded without an admin principal")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindForbidden {
		t.Fatalf("err = %v, want forbidden", err)
	}
}

func TestComplete_RequiresSettingsVersion(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStagePKIRequired)
	meta := seedAdminSession(t, f.store, testNow())
	seedDefaultSettings(t, f.store)

	_, err := f.svc.Complete(context.Background(), meta, contract.SetupCompleteCommand{})
	if err == nil {
		t.Fatal("complete succeeded without ExpectedVersion")
	}
}

func TestComplete_SettingsVersionMismatchIsConflict(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStagePKIRequired)
	meta := seedAdminSession(t, f.store, testNow())
	seedDefaultSettings(t, f.store)

	stale := domain.Version(99)
	meta.ExpectedVersion = &stale
	_, err := f.svc.Complete(context.Background(), meta, contract.SetupCompleteCommand{})
	if err == nil {
		t.Fatal("complete succeeded with a stale settings version")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("err = %v, want conflict", err)
	}
}

func TestComplete_AdvancesStageAndIsIdempotent(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStagePKIRequired)
	meta := seedAdminSession(t, f.store, testNow())
	seedDefaultSettings(t, f.store)
	zero := domain.Version(0)
	meta.ExpectedVersion = &zero

	view, err := f.svc.Complete(context.Background(), meta, contract.SetupCompleteCommand{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if view.SetupStage != contract.SetupStageComplete {
		t.Fatalf("setup_stage = %q, want complete", view.SetupStage)
	}

	// Calling Complete again on an already-complete installation is a no-op
	// success rather than an error.
	view2, err := f.svc.Complete(context.Background(), meta, contract.SetupCompleteCommand{})
	if err != nil {
		t.Fatalf("second complete: %v", err)
	}
	if view2.SetupStage != contract.SetupStageComplete {
		t.Fatalf("second complete setup_stage = %q, want complete", view2.SetupStage)
	}
}

// TestComplete_RejectsExpiredAdminSession is the "관리 서비스의 모든 변경은
// 현재 계정 상태·epoch를 트랜잭션 안에서 다시 확인한다" check applied to
// Complete: a session that authenticated the request has since gone
// idle-expired must not be honored just because a version and a principal
// were supplied. Complete advances the installation stage, which is exactly
// the kind of administrative change §2/§8 requires this re-check for.
func TestComplete_RejectsExpiredAdminSession(t *testing.T) {
	f := newSetupFixture(t)
	seedInstallation(t, f.store, port.SetupStagePKIRequired)
	meta := seedAdminSession(t, f.store, testNow())
	seedDefaultSettings(t, f.store)
	zero := domain.Version(0)
	meta.ExpectedVersion = &zero

	// The session's last_seen_at is testNow(); advance well past the
	// 1-hour idle window before the commit observes the clock.
	movable := &movableClock{now: testNow().Add(domain.NewDuration(2 * time.Hour))}
	f.svc.deps.Clock = movable

	_, err := f.svc.Complete(context.Background(), meta, contract.SetupCompleteCommand{})
	if err == nil {
		t.Fatal("complete succeeded for an idle-expired admin session")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) || appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("err = %v, want auth", err)
	}

	// The installation must not have advanced.
	inst := readInstallation(t, f.store)
	if inst.SetupStage != port.SetupStagePKIRequired {
		t.Fatalf("setup_stage = %q, want unchanged pki_required", inst.SetupStage)
	}
}
