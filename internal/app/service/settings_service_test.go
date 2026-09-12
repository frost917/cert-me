package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

// fakeURLValidator is a deterministic port.URLValidator: it records every
// URL it was asked to validate and fails only when told to.
type fakeURLValidator struct {
	calls int
	fail  error
}

func (v *fakeURLValidator) Validate(_ context.Context, rawURL string) error {
	v.calls++
	if v.fail != nil {
		return v.fail
	}
	return nil
}

// ---- fixture plumbing ----

type settingsFixture struct {
	store        *porttest.Store
	ids          *seqIDs
	urlValidator *fakeURLValidator
	authorizer   *toggleAuthorizer
	svc          *SettingsService
}

func newSettingsFixture(t *testing.T) *settingsFixture {
	t.Helper()
	store := porttest.NewStore()
	seedDefaultSettings(t, store)
	seedAdminSessionForIssuance(t, store)

	ids := &seqIDs{}
	urlValidator := &fakeURLValidator{}
	authorizer := &toggleAuthorizer{allow: true}

	svc, err := NewSettingsService(SettingsDeps{
		CommonDeps: CommonDeps{
			UnitOfWork: store,
			ReadStore:  store,
			Authorizer: authorizer,
			Clock:      fixedClock{now: testNow()},
			IDs:        ids,
		},
		URLValidator: urlValidator,
	})
	if err != nil {
		t.Fatalf("new settings service: %v", err)
	}
	return &settingsFixture{store: store, ids: ids, urlValidator: urlValidator, authorizer: authorizer, svc: svc}
}

func settingsUpdateMeta(version domain.Version) contract.MutationMeta {
	return contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: mustAdminPrincipal()},
		ExpectedVersion: contract.WithExpectedVersion(version),
	}
}

func settingsGetMeta() contract.RequestMeta {
	return contract.RequestMeta{Principal: mustAdminPrincipal()}
}

// mustAdminPrincipal builds the same admin principal issuance_test.go's
// fixtures use (issuanceTestAdminAccountID/issuanceTestSessionID), so a
// settings/authority test seeded through seedAdminSessionForIssuance
// authenticates against the same account row.
func mustAdminPrincipal() contract.Principal {
	p, err := contract.NewAdminPrincipal(contract.AdminPrincipalFacts{
		AccountID: issuanceTestAdminAccountID,
		SessionID: issuanceTestSessionID,
		AuthEpoch: domain.AuthEpoch(1),
	})
	if err != nil {
		panic(err)
	}
	return p
}

// ---- §8 auth-machinery helpers, shared by settings_service_test.go and
// authority_test.go ----
//
// These exist because a planning-team fault injection found that removing
// requireCurrentAuth entirely from both authority.go and settings_service.go
// left every existing test green: nothing pinned §8's "관리 서비스의 모든
// 변경은 현재 계정 상태·epoch를 트랜잭션 안에서 다시 확인한다". The three
// helpers below reproduce the three ways a session that was live when a
// request STARTED can stop being live before its commit runs, mirroring
// auth.go's authtime_test.go (the B03 precedent for this same property on
// IssuanceService).

// bumpAccountAuthEpoch advances the seeded admin account's auth_epoch via
// the real domain.Account.BeginReset transition -- the same effect a
// concurrent password-reset would have -- so a principal minted under the
// OLD epoch must be rejected by requireCurrentAuth's epoch comparison.
func bumpAccountAuthEpoch(t *testing.T, store *porttest.Store) {
	t.Helper()
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), issuanceTestAdminAccountID)
		if err != nil {
			return err
		}
		outcome, err := account.BeginReset()
		if err != nil {
			return err
		}
		return tx.Accounts().SaveAccount(context.Background(), outcome.Account, account.Version())
	}); err != nil {
		t.Fatalf("bump account auth epoch: %v", err)
	}
}

// disableAccount marks the seeded admin account disabled, leaving its
// auth_epoch untouched, so a test can isolate SessionState.ValidateAt's
// account_not_active check from the epoch check above.
func disableAccount(t *testing.T, store *porttest.Store) {
	t.Helper()
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		account, err := tx.Accounts().GetAccountForUpdate(context.Background(), issuanceTestAdminAccountID)
		if err != nil {
			return err
		}
		disabled, err := domain.NewAccount(domain.AccountFacts{
			ID:                  account.ID(),
			NormalizedLoginName: account.NormalizedLoginName(),
			PasswordHash:        account.PasswordHash(),
			State:               domain.AccountStateDisabled,
			AuthEpoch:           account.AuthEpoch(),
			IsGlobalAdmin:       account.IsGlobalAdmin(),
			Version:             account.Version(),
		})
		if err != nil {
			return err
		}
		return tx.Accounts().SaveAccount(context.Background(), disabled, account.Version())
	}); err != nil {
		t.Fatalf("disable account: %v", err)
	}
}

// touchAdminSession moves the seeded admin session's last_seen_at, the same
// helper authtime_test.go's touchSession provides for issuanceFixture, typed
// here for a *porttest.Store directly so settings/authority fixtures (which
// are not issuanceFixture) can use it too.
func touchAdminSession(t *testing.T, store *porttest.Store, lastSeenAt domain.Instant) {
	t.Helper()
	if err := store.Write(context.Background(), func(tx port.TxStores) error {
		session, err := tx.Accounts().GetSessionForUpdate(context.Background(), issuanceTestSessionID)
		if err != nil {
			return err
		}
		return tx.Accounts().SaveSession(context.Background(), session.Touch(lastSeenAt))
	}); err != nil {
		t.Fatalf("touch admin session: %v", err)
	}
}

// requireAuthError asserts err is an AppError of kind auth carrying exactly
// code -- used throughout this file and authority_test.go to pin which of
// requireCurrentAuth's three checks (epoch, account state, session expiry)
// actually fired, not merely that *some* error came back.
func requireAuthError(t *testing.T, err error, code string) {
	t.Helper()
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() != contract.ErrorKindAuth {
		t.Fatalf("kind = %s (code %q), want auth", appErr.Kind(), appErr.Code())
	}
	if appErr.Code() != code {
		t.Fatalf("code = %q, want %q", appErr.Code(), code)
	}
}

// ---- Get ----

func TestSettingsServiceGetReturnsCurrentSnapshot(t *testing.T) {
	f := newSettingsFixture(t)
	view, err := f.svc.Get(context.Background(), settingsGetMeta(), contract.SettingsGetCommand{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := defaultTestSettingsV1()
	if view.ServiceURL != want.ServiceURL {
		t.Fatalf("service_url = %q, want %q", view.ServiceURL, want.ServiceURL)
	}
	if view.RotateEvery != want.RotateEvery {
		t.Fatalf("rotate_every = %d, want %d", view.RotateEvery, want.RotateEvery)
	}
	if view.Version != 0 {
		t.Fatalf("version = %d, want 0 (seedDefaultSettings inserts at version 0)", view.Version)
	}
}

func TestSettingsServiceGetRequiresAdmin(t *testing.T) {
	f := newSettingsFixture(t)
	_, err := f.svc.Get(context.Background(), contract.RequestMeta{Principal: contract.AnonymousPrincipal()}, contract.SettingsGetCommand{})
	if err == nil {
		t.Fatal("want an error for a non-admin Get")
	}
}

// ---- Update: basic patch/version behavior ----

func TestSettingsServiceUpdatePatchesOnlyGivenFields(t *testing.T) {
	f := newSettingsFixture(t)
	newRotate := 7
	cmd := contract.SettingsUpdateCommand{RotateEvery: &newRotate}

	view, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), cmd)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if view.RotateEvery != newRotate {
		t.Fatalf("rotate_every = %d, want %d", view.RotateEvery, newRotate)
	}
	want := defaultTestSettingsV1()
	if view.ServiceURL != want.ServiceURL {
		t.Fatalf("service_url changed unexpectedly: %q", view.ServiceURL)
	}
	if view.AuditRetentionDays != want.AuditRetentionDays {
		t.Fatalf("audit_retention_days changed unexpectedly: %d", view.AuditRetentionDays)
	}
	if view.Version != 1 {
		t.Fatalf("version = %d, want 1", view.Version)
	}

	// The stored row itself reflects the same merge, not just the response.
	got, err := f.svc.Get(context.Background(), settingsGetMeta(), contract.SettingsGetCommand{})
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got.RotateEvery != newRotate || got.Version != 1 {
		t.Fatalf("stored settings = %+v, want rotate_every=%d version=1", got, newRotate)
	}
}

func TestSettingsServiceUpdateRequiresVersion(t *testing.T) {
	f := newSettingsFixture(t)
	newRotate := 7
	meta := contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: mustAdminPrincipal()}}
	_, err := f.svc.Update(context.Background(), meta, contract.SettingsUpdateCommand{RotateEvery: &newRotate})
	if err == nil {
		t.Fatal("want an error when no version is supplied")
	}
}

func TestSettingsServiceUpdateRejectsVersionConflict(t *testing.T) {
	f := newSettingsFixture(t)
	newRotate := 7
	_, err := f.svc.Update(context.Background(), settingsUpdateMeta(99), contract.SettingsUpdateCommand{RotateEvery: &newRotate})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Kind() != contract.ErrorKindConflict {
		t.Fatalf("kind = %v, want conflict", appErr.Kind())
	}
	// Kind alone does not pin the app-layer version check: the store's own
	// ErrVersionConflict from a rejected SaveSettings maps to the same
	// conflict kind, so a test that stops at Kind() cannot tell "the app
	// checked settings.Version != expectedVersion before ever calling
	// SaveSettings" apart from "the app skipped that check and the store
	// caught it anyway". The code pins which one actually fired.
	if appErr.Code() != "settings_version_conflict" {
		t.Fatalf("code = %q, want settings_version_conflict", appErr.Code())
	}
}

func TestSettingsServiceUpdateRequiresAdmin(t *testing.T) {
	f := newSettingsFixture(t)
	newRotate := 7
	meta := contract.MutationMeta{
		RequestMeta:     contract.RequestMeta{Principal: contract.AnonymousPrincipal()},
		ExpectedVersion: contract.WithExpectedVersion(0),
	}
	_, err := f.svc.Update(context.Background(), meta, contract.SettingsUpdateCommand{RotateEvery: &newRotate})
	if err == nil {
		t.Fatal("want an error for a non-admin Update")
	}
}

// TestSettingsServiceUpdateRecordsAuditEvent confirms Update writes an audit
// row for the change. The stored scope itself cannot be inspected through
// porttest's exported API (Store.AuditEvents drops it, by design -- see
// porttest/audit.go), which is exactly why this developer could not write a
// test asserting the scope value one way or the other; see settingsScope's
// doc comment and this round's report for why that value is an open
// question rather than a decided one.
func TestSettingsServiceUpdateRecordsAuditEvent(t *testing.T) {
	f := newSettingsFixture(t)
	newRotate := 9
	if _, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{RotateEvery: &newRotate}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	events := f.store.AuditEvents()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Action != "settings.update" {
		t.Fatalf("action = %q, want settings.update", events[0].Action)
	}
}

// ---- Update: U04 -- settings changes do not extend an existing delivery's deadline ----

// TestSettingsServiceUpdateDoesNotExtendExistingDeliveryDeadline is the
// direct U04 check (docs/backend-implementation.md §11 "설정 변경이 기존
// 수령 기한을 연장하지 않음"): a delivery already created under the OLD
// private_delivery_seconds keeps its own stored expires_at unchanged after
// Update raises the setting. Update touches only the service_settings row
// (§3 "이전 링크/계보 설정 불변"), so this also stands as the general "no
// other table is touched" check for Update.
func TestSettingsServiceUpdateDoesNotExtendExistingDeliveryDeadline(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()

	deliveryID, err := domain.ParseDeliveryID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("delivery id: %v", err)
	}
	leafKeyGenID, err := domain.ParseLeafKeyGenerationID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("leaf key generation id: %v", err)
	}
	certID, err := domain.ParseCertificateID(f.ids.NewUUID())
	if err != nil {
		t.Fatalf("certificate id: %v", err)
	}
	expiresAt := testNow().Add(domain.NewDuration(time.Duration(defaultTestSettingsV1().PrivateDeliverySeconds) * time.Second))
	delivery, err := domain.NewDelivery(domain.DeliveryFacts{
		ID:                  deliveryID,
		LeafKeyGenerationID: leafKeyGenID,
		CertificateID:       certID,
		ExpiresAt:           expiresAt,
		State:               domain.DeliveryStatePending,
	})
	if err != nil {
		t.Fatalf("delivery: %v", err)
	}
	if err := f.store.Write(ctx, func(tx port.TxStores) error {
		return tx.Delivery().InsertDelivery(ctx, delivery)
	}); err != nil {
		t.Fatalf("seed delivery: %v", err)
	}

	// Raise private_delivery_seconds to the maximum -- if Update ever touched
	// existing deliveries, this is the change that would most obviously leak
	// through as a later expires_at.
	newSeconds := 86400
	if _, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{PrivateDeliverySeconds: &newSeconds}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	var got domain.Delivery
	if err := f.store.Write(ctx, func(tx port.TxStores) error {
		d, err := tx.Delivery().GetDeliveryForUpdate(ctx, deliveryID)
		if err != nil {
			return err
		}
		got = d
		return nil
	}); err != nil {
		t.Fatalf("re-read delivery: %v", err)
	}
	if !got.ExpiresAt().Equal(expiresAt) {
		t.Fatalf("delivery expires_at = %v, want unchanged %v (settings change must not extend an existing delivery)", got.ExpiresAt(), expiresAt)
	}
}

// ---- Update: service_url vs active TLS snapshot ----

func TestSettingsServiceUpdateRejectsInvalidServiceURL(t *testing.T) {
	f := newSettingsFixture(t)
	f.urlValidator.fail = errors.New("unreachable")
	url := "https://new.example.test"
	_, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{ServiceURL: &url})
	if err == nil {
		t.Fatal("want an error when URLValidator rejects the URL")
	}
	if f.urlValidator.calls != 1 {
		t.Fatalf("URLValidator.Validate calls = %d, want 1", f.urlValidator.calls)
	}
}

func TestSettingsServiceUpdateSkipsTLSCheckWhenNoActiveTLSVersion(t *testing.T) {
	f := newSettingsFixture(t)
	url := "https://fresh.example.test"
	view, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{ServiceURL: &url})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if view.ServiceURL != url {
		t.Fatalf("service_url = %q, want %q", view.ServiceURL, url)
	}
}

func TestSettingsServiceUpdateRejectsServiceURLNotMatchingActiveTLS(t *testing.T) {
	f := newSettingsFixture(t)
	seedActiveTLSVersion(t, f.store, f.ids, "https://active.example.test")

	url := "https://different.example.test"
	_, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{ServiceURL: &url})
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError", err)
	}
	if appErr.Code() != "settings_service_url_locked_to_active_tls" {
		t.Fatalf("code = %q, want settings_service_url_locked_to_active_tls", appErr.Code())
	}
}

func TestSettingsServiceUpdateAllowsServiceURLMatchingActiveTLS(t *testing.T) {
	f := newSettingsFixture(t)
	seedActiveTLSVersion(t, f.store, f.ids, "https://active.example.test")

	url := "https://active.example.test"
	view, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{ServiceURL: &url})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if view.ServiceURL != url {
		t.Fatalf("service_url = %q, want %q", view.ServiceURL, url)
	}
}

// TestSettingsServiceUpdateRejectsServiceURLChangedBetweenPrepareAndCommit
// proves the active-TLS comparison is re-checked under lock, not just
// during prepareUpdate's read: the active version changes to a different
// validated_service_url via a UnitOfWork decorator that mutates the store
// right before the real commit runs, and Update must still catch the
// mismatch rather than committing against the value prepareUpdate saw.
func TestSettingsServiceUpdateRejectsServiceURLChangedBetweenPrepareAndCommit(t *testing.T) {
	f := newSettingsFixture(t)
	seedActiveTLSVersion(t, f.store, f.ids, "https://original.example.test")

	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{
		inner: f.store,
		mutate: func() {
			// Between prepareUpdate's read and the commit, the active TLS
			// version is replaced by a candidate validated for a DIFFERENT
			// URL than the one Update is about to request -- simulating an
			// operator activating a new HTTPS candidate mid-request.
			mutated = true
			seedActiveTLSVersion(t, f.store, f.ids, "https://swapped-in.example.test")
		},
	}

	url := "https://original.example.test"
	_, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{ServiceURL: &url})
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	var appErr *contract.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("err = %v, want an AppError (the commit-time re-check should have rejected the now-stale service_url)", err)
	}
	if appErr.Code() != "settings_service_url_locked_to_active_tls" {
		t.Fatalf("code = %q, want settings_service_url_locked_to_active_tls", appErr.Code())
	}
}

// mutateOnceUoW wraps a port.UnitOfWork so a test can inject a store change
// that lands after preparation but before the wrapped Write's own callback
// runs, proving a commit re-checks a fact rather than trusting what
// preparation saw (docs/backend-implementation.md §8's fixed "준비 -> 재확인"
// split). mutate runs exactly once, on the first Write call, so a retried
// commit (e.g. after errRePrepare) sees stable state on its second pass.
type mutateOnceUoW struct {
	inner  port.UnitOfWork
	ran    bool
	mutate func()
}

func (u *mutateOnceUoW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	if !u.ran {
		u.ran = true
		u.mutate()
	}
	return u.inner.Write(ctx, fn)
}

// seedActiveTLSVersion inserts a TLS version and marks it the active one via
// TLSRepository.SaveChange + Installation.Save, the minimum a Settings
// service_url check needs: TLSRepository.GetActiveForUpdate must find a
// TLSChange in the applied phase whose CandidateVersionID resolves to a
// domain.TLSVersion carrying validatedServiceURL.
func seedActiveTLSVersion(t *testing.T, store *porttest.Store, ids *seqIDs, validatedServiceURL string) domain.TLSVersionID {
	t.Helper()
	ctx := context.Background()

	versionID, err := domain.ParseTLSVersionID(ids.NewUUID())
	if err != nil {
		t.Fatalf("tls version id: %v", err)
	}
	keyMaterialID, err := domain.ParseKeyMaterialID(ids.NewUUID())
	if err != nil {
		t.Fatalf("key material id: %v", err)
	}
	version, err := domain.NewTLSVersion(domain.TLSVersionFacts{
		ID:                  versionID,
		Source:              domain.TLSSourceExternal,
		KeyMaterialID:       keyMaterialID,
		LeafDER:             []byte("leaf-der"),
		ChainBundle:         []byte("chain-bundle"),
		ValidatedServiceURL: validatedServiceURL,
		NotAfter:            testNow().Add(domain.NewDuration(24 * 365 * time.Hour)),
	})
	if err != nil {
		t.Fatalf("tls version: %v", err)
	}

	change, err := domain.NewCandidateTLSChange("", versionID)
	if err != nil {
		t.Fatalf("candidate change: %v", err)
	}
	change, err = change.ValidateCandidate(domain.TLSValidationFacts{
		CandidateSource:          domain.TLSSourceExternal,
		KeyMatchesCertificate:    true,
		WithinValidityPeriod:     true,
		PurposeMatchesServerAuth: true,
		ServiceAddressMatches:    true,
		ChainVerified:            true,
	})
	if err != nil {
		t.Fatalf("validate candidate: %v", err)
	}
	change, err = change.Commit(testNow())
	if err != nil {
		t.Fatalf("commit change: %v", err)
	}
	change, err = change.Apply(testNow())
	if err != nil {
		t.Fatalf("apply change: %v", err)
	}

	if err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.TLS().InsertVersion(ctx, version); err != nil {
			return err
		}
		if err := tx.TLS().SaveChange(ctx, change, 0); err != nil {
			return err
		}
		// GetActiveForUpdate resolves the active change through
		// installation.active_tls_version_id, not merely through a change's
		// own applied phase (porttest/tls.go's GetActiveForUpdate doc
		// comment: "the active pointer lives on the installation row and
		// nowhere else"), so the installation row's pointer has to be moved
		// too. A second call in the same test (simulating the active
		// version changing again) must use the row's own current version as
		// SetActive's expectedVersion, not always 0.
		installation, err := tx.Installation().GetForUpdate(ctx)
		if errors.Is(err, port.ErrNotFound) {
			installation = port.Installation{SetupStage: port.SetupStageComplete}
			if err := tx.Installation().Save(ctx, installation, 0); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		return tx.TLS().SetActive(ctx, installation.Version, versionID)
	}); err != nil {
		t.Fatalf("seed active tls version: %v", err)
	}
	return versionID
}

// ---- §8: requireCurrentAuth is not optional ----

func TestSettingsServiceGetRejectsAuthEpochSuperseded(t *testing.T) {
	f := newSettingsFixture(t)
	bumpAccountAuthEpoch(t, f.store)
	_, err := f.svc.Get(context.Background(), settingsGetMeta(), contract.SettingsGetCommand{})
	requireAuthError(t, err, "auth_epoch_superseded")
}

func TestSettingsServiceGetRejectsDisabledAccount(t *testing.T) {
	f := newSettingsFixture(t)
	disableAccount(t, f.store)
	_, err := f.svc.Get(context.Background(), settingsGetMeta(), contract.SettingsGetCommand{})
	requireAuthError(t, err, "account_not_active")
}

func TestSettingsServiceGetRejectsIdleExpiredSession(t *testing.T) {
	f := newSettingsFixture(t)
	touchAdminSession(t, f.store, testNow())
	clock := &movableClock{now: testNow().Add(domain.NewDuration(time.Hour + time.Second))}
	f.svc.deps.Clock = clock
	_, err := f.svc.Get(context.Background(), settingsGetMeta(), contract.SettingsGetCommand{})
	requireAuthError(t, err, "session_idle_expired")
}

// TestSettingsServiceUpdateRejectsAuthEpochBumpedBetweenPrepareAndCommit
// bumps the account's auth_epoch via a UnitOfWork decorator right before the
// real commit runs, after Update was called with a session that was
// genuinely still live at that moment. requireCurrentAuth must catch this
// under lock; nothing in prepareUpdate checks auth at all (by design -- it
// is non-authoritative), so this is the only place §8's rule can bite for
// Update.
func TestSettingsServiceUpdateRejectsAuthEpochBumpedBetweenPrepareAndCommit(t *testing.T) {
	f := newSettingsFixture(t)
	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{inner: f.store, mutate: func() {
		mutated = true
		bumpAccountAuthEpoch(t, f.store)
	}}
	newRotate := 5
	_, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{RotateEvery: &newRotate})
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	requireAuthError(t, err, "auth_epoch_superseded")
}

func TestSettingsServiceUpdateRejectsAccountDisabledBetweenPrepareAndCommit(t *testing.T) {
	f := newSettingsFixture(t)
	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{inner: f.store, mutate: func() {
		mutated = true
		disableAccount(t, f.store)
	}}
	newRotate := 5
	_, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{RotateEvery: &newRotate})
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	requireAuthError(t, err, "account_not_active")
}

// TestSettingsServiceUpdateRejectsSessionIdleExpiredAtCommitTime proves the
// idle-expiry boundary requireCurrentAuth checks is evaluated against the
// clock's value AT COMMIT TIME (after the account/session rows are locked),
// not whatever it read when Update was first called: the clock is advanced
// past the idle window by the same UnitOfWork decorator, between the call to
// Update and the commit's own requireCurrentAuth check.
func TestSettingsServiceUpdateRejectsSessionIdleExpiredAtCommitTime(t *testing.T) {
	f := newSettingsFixture(t)
	clock := &movableClock{now: testNow()}
	f.svc.deps.Clock = clock
	mutated := false
	f.svc.deps.UnitOfWork = &mutateOnceUoW{inner: f.store, mutate: func() {
		mutated = true
		clock.now = clock.now.Add(domain.NewDuration(time.Hour + time.Second))
	}}
	newRotate := 5
	_, err := f.svc.Update(context.Background(), settingsUpdateMeta(0), contract.SettingsUpdateCommand{RotateEvery: &newRotate})
	if !mutated {
		t.Fatal("mutateOnceUoW never ran; test is not exercising the intended race")
	}
	requireAuthError(t, err, "session_idle_expired")
}
