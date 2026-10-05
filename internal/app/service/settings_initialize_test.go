package service

import (
	"context"
	"errors"
	"sync"
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

type initializeURLValidator struct {
	mu   sync.Mutex
	urls []string
	err  error
}

func (v *initializeURLValidator) Validate(ctx context.Context, rawURL string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.urls = append(v.urls, rawURL)
	return v.err
}

func (v *initializeURLValidator) Calls() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.urls...)
}

type settingsInitializeFixture struct {
	store        *porttest.Store
	ids          *seqIDs
	urlValidator *initializeURLValidator
	authorizer   *toggleAuthorizer
	svc          *SettingsService
}

func newSettingsInitializeFixture(t *testing.T, stage port.SetupStage) *settingsInitializeFixture {
	t.Helper()
	store := porttest.NewStore()
	seedInstallation(t, store, stage)
	seedAdminSessionForIssuance(t, store)
	ids := &seqIDs{}
	urlValidator := &initializeURLValidator{}
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
	return &settingsInitializeFixture{store: store, ids: ids, urlValidator: urlValidator, authorizer: authorizer, svc: svc}
}

func settingsInitializeCommandForService() contract.SettingsInitializeCommand {
	serviceURL := "https://explicit.example.test"
	leafValidity := contract.ValidityInput{Value: 2, Unit: "years"}
	rootValidity := contract.ValidityInput{Value: 20, Unit: "years"}
	intermediateValidity := contract.ValidityInput{Value: 8, Unit: "years"}
	rotateEvery := 4
	privateDeliverySeconds := 7200
	publicLinkSeconds := 900
	crlIntervalSeconds := 3600
	crlValiditySeconds := 7200
	auditRetentionDays := 180
	return contract.SettingsInitializeCommand{
		ServiceURL:             &serviceURL,
		LeafValidity:           &leafValidity,
		RootValidity:           &rootValidity,
		IntermediateValidity:   &intermediateValidity,
		RotateEvery:            &rotateEvery,
		PrivateDeliverySeconds: &privateDeliverySeconds,
		PublicLinkSeconds:      &publicLinkSeconds,
		CRLIntervalSeconds:     &crlIntervalSeconds,
		CRLValiditySeconds:     &crlValiditySeconds,
		AuditRetentionDays:     &auditRetentionDays,
	}
}

func settingsInitializeMeta(principal contract.Principal) contract.MutationMeta {
	return contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: principal}}
}

func TestSettingsServiceInitializeCreatesCompleteVersionOneSnapshotAndAudit(t *testing.T) {
	f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
	cmd := settingsInitializeCommandForService()

	view, err := f.svc.Initialize(context.Background(), settingsInitializeMeta(mustAdminPrincipal()), cmd)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if view.ServiceURL != *cmd.ServiceURL {
		t.Fatalf("service_url = %q, want the explicitly supplied URL %q", view.ServiceURL, *cmd.ServiceURL)
	}
	if view.Version != 1 {
		t.Fatalf("version = %d, want initial version 1", view.Version)
	}

	var stored port.Settings
	if err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		stored, err = tx.Installation().GetSettings(context.Background())
		return err
	}); err != nil {
		t.Fatalf("read initialized settings: %v", err)
	}
	got, err := DecodeSettingsV1(stored)
	if err != nil {
		t.Fatalf("decode initialized settings: %v", err)
	}
	leafValidity, _ := domain.NewCalendarValidity(2, domain.ValidityUnitYears)
	rootValidity, _ := domain.NewCalendarValidity(20, domain.ValidityUnitYears)
	intermediateValidity, _ := domain.NewCalendarValidity(8, domain.ValidityUnitYears)
	want := SettingsV1{
		ServiceURL:             *cmd.ServiceURL,
		LeafValidity:           leafValidity,
		RootValidity:           rootValidity,
		IntermediateValidity:   intermediateValidity,
		RotateEvery:            *cmd.RotateEvery,
		PrivateDeliverySeconds: *cmd.PrivateDeliverySeconds,
		PublicLinkSeconds:      *cmd.PublicLinkSeconds,
		CRLIntervalSeconds:     *cmd.CRLIntervalSeconds,
		CRLValiditySeconds:     *cmd.CRLValiditySeconds,
		AuditRetentionDays:     *cmd.AuditRetentionDays,
	}
	if got != want {
		t.Fatalf("initialized settings = %+v, want the complete explicit snapshot %+v", got, want)
	}
	if stored.SchemaVersion != settingsSchemaVersionV1 || stored.Version != 1 || stored.UpdatedBy != issuanceTestAdminAccountID {
		t.Fatalf("stored row metadata = %+v, want schema v1, settings version 1, and the admin actor", stored)
	}

	validated := f.urlValidator.Calls()
	if len(validated) != 1 || validated[0] != *cmd.ServiceURL {
		t.Fatalf("URL validation calls = %v, want exactly the supplied service_url", validated)
	}
	events := f.store.AuditEvents()
	if len(events) != 1 || events[0].Action != "settings.update" || events[0].Details.Fields["operation"] != "initialize" || events[0].TargetType != "settings" || events[0].TargetID != "" {
		t.Fatal("initial settings must use the compatible installation audit action with explicit initialization metadata")
	}
	scopes := f.store.AuditScopes()
	if len(scopes) != 1 || scopes[0].Kind() != port.AuditScopeInstallation {
		t.Fatalf("audit scopes = %+v, want one installation scope", scopes)
	}
}

func TestSettingsServiceInitializeRequiresAnAdminSession(t *testing.T) {
	f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
	_, err := f.svc.Initialize(context.Background(), settingsInitializeMeta(contract.AnonymousPrincipal()), settingsInitializeCommandForService())
	if !hasSettingsInitializeAppError(err, contract.ErrorKindForbidden, "settings_requires_admin") {
		t.Fatalf("Initialize error = %v, want settings_requires_admin", err)
	}
	if calls := f.urlValidator.Calls(); len(calls) != 0 {
		t.Fatalf("URL validator calls = %v, want none for a non-admin", calls)
	}
}

func TestSettingsServiceInitializeRechecksCurrentSessionAndAuthorization(t *testing.T) {
	t.Run("superseded auth epoch", func(t *testing.T) {
		f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
		bumpAccountAuthEpoch(t, f.store)
		_, err := f.svc.Initialize(context.Background(), settingsInitializeMeta(mustAdminPrincipal()), settingsInitializeCommandForService())
		requireAuthError(t, err, "auth_epoch_superseded")
		assertSettingsInitializeUnchanged(t, f.store)
	})

	t.Run("authorization denied", func(t *testing.T) {
		f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
		f.authorizer.allow = false
		_, err := f.svc.Initialize(context.Background(), settingsInitializeMeta(mustAdminPrincipal()), settingsInitializeCommandForService())
		if !hasSettingsInitializeAppError(err, contract.ErrorKindForbidden, "not_authorized") {
			t.Fatalf("Initialize error = %v, want not_authorized", err)
		}
		assertSettingsInitializeUnchanged(t, f.store)
	})
}

func TestSettingsServiceInitializeRequiresPKIRequiredStage(t *testing.T) {
	for _, stage := range []port.SetupStage{port.SetupStageAccountRequired, port.SetupStageComplete} {
		t.Run(string(stage), func(t *testing.T) {
			f := newSettingsInitializeFixture(t, stage)
			_, err := f.svc.Initialize(context.Background(), settingsInitializeMeta(mustAdminPrincipal()), settingsInitializeCommandForService())
			if !hasSettingsInitializeAppError(err, contract.ErrorKindConflict, "setup_settings_unavailable") {
				t.Fatalf("Initialize error = %v, want setup_settings_unavailable", err)
			}
			assertSettingsInitializeUnchanged(t, f.store)
		})
	}
}

func TestSettingsServiceInitializeValidatesURLAndHonorsTLSBinding(t *testing.T) {
	t.Run("URL validation failure", func(t *testing.T) {
		f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
		f.urlValidator.err = errors.New("unreachable")
		_, err := f.svc.Initialize(context.Background(), settingsInitializeMeta(mustAdminPrincipal()), settingsInitializeCommandForService())
		if !hasSettingsInitializeAppError(err, contract.ErrorKindValidation, "settings_service_url_invalid") {
			t.Fatalf("Initialize error = %v, want settings_service_url_invalid", err)
		}
		assertSettingsInitializeUnchanged(t, f.store)
	})

	t.Run("active TLS URL mismatch", func(t *testing.T) {
		f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
		seedActiveTLSVersion(t, f.store, f.ids, "https://active.example.test")
		_, err := f.svc.Initialize(context.Background(), settingsInitializeMeta(mustAdminPrincipal()), settingsInitializeCommandForService())
		if !hasSettingsInitializeAppError(err, contract.ErrorKindConflict, "settings_service_url_locked_to_active_tls") {
			t.Fatalf("Initialize error = %v, want settings_service_url_locked_to_active_tls", err)
		}
		assertSettingsInitializeUnchanged(t, f.store)
	})

	t.Run("bootstrap without an active operational URL", func(t *testing.T) {
		f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
		cmd := settingsInitializeCommandForService()
		if _, err := f.svc.Initialize(context.Background(), settingsInitializeMeta(mustAdminPrincipal()), cmd); err != nil {
			t.Fatalf("Initialize with no active TLS URL: %v", err)
		}
	})
}

func TestSettingsServiceInitializeExistingRowReturnsConflictWithoutOverwriting(t *testing.T) {
	f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
	seedDefaultSettings(t, f.store)
	before, err := f.storeSettings()
	if err != nil {
		t.Fatalf("read existing settings: %v", err)
	}
	_, err = f.svc.Initialize(context.Background(), settingsInitializeMeta(mustAdminPrincipal()), settingsInitializeCommandForService())
	if !hasSettingsInitializeAppError(err, contract.ErrorKindConflict, "settings_already_configured") {
		t.Fatalf("Initialize error = %v, want settings_already_configured", err)
	}
	after, err := f.storeSettings()
	if err != nil {
		t.Fatalf("read settings after conflict: %v", err)
	}
	if string(before.SettingsJSON) != string(after.SettingsJSON) || before.Version != after.Version {
		t.Fatalf("existing settings changed after initialize conflict: before=%+v after=%+v", before, after)
	}
}

func TestSettingsServiceInitializeConcurrentRequestsHaveOneWinner(t *testing.T) {
	f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
	f.svc.deps.IDs = &concurrentIDs{}
	meta := settingsInitializeMeta(mustAdminPrincipal())
	cmd := settingsInitializeCommandForService()
	start := make(chan struct{})
	results := make([]contract.SettingsView, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = f.svc.Initialize(context.Background(), meta, cmd)
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	losers := 0
	for i, err := range errs {
		if err == nil {
			winners++
			if results[i].Version != 1 {
				t.Errorf("winner version = %d, want 1", results[i].Version)
			}
			continue
		}
		if hasSettingsInitializeAppError(err, contract.ErrorKindConflict, "settings_already_configured") {
			losers++
			continue
		}
		t.Errorf("request %d error = %v, want settings_already_configured conflict", i, err)
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("winners=%d losers=%d, want one winner and one configured conflict", winners, losers)
	}
	stored, err := f.storeSettings()
	if err != nil {
		t.Fatalf("read settings after race: %v", err)
	}
	if stored.Version != 1 || len(f.store.AuditEvents()) != 1 {
		t.Fatalf("stored version=%d, audit events=%d; want one version-1 row and one audit", stored.Version, len(f.store.AuditEvents()))
	}
}

func TestSettingsServiceInitializeRollsBackSettingsWhenAuditFails(t *testing.T) {
	f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
	f.svc.deps.UnitOfWork = settingsInitializeFailAuditUOW{UnitOfWork: f.store}
	_, err := f.svc.Initialize(context.Background(), settingsInitializeMeta(mustAdminPrincipal()), settingsInitializeCommandForService())
	if !hasSettingsInitializeAppError(err, contract.ErrorKindUnavailable, "settings_audit_failed") {
		t.Fatalf("Initialize error = %v, want settings_audit_failed", err)
	}
	assertSettingsInitializeUnchanged(t, f.store)
}

func TestSettingsServiceInitializeHonorsCanceledContext(t *testing.T) {
	f := newSettingsInitializeFixture(t, port.SetupStagePKIRequired)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.svc.Initialize(ctx, settingsInitializeMeta(mustAdminPrincipal()), settingsInitializeCommandForService())
	if err == nil {
		t.Fatal("Initialize succeeded with a canceled context")
	}
	if calls := f.urlValidator.Calls(); len(calls) != 0 {
		t.Fatalf("URL validation calls = %v, want none after cancellation", calls)
	}
	assertSettingsInitializeUnchanged(t, f.store)
}

func (f *settingsInitializeFixture) storeSettings() (port.Settings, error) {
	var settings port.Settings
	err := f.store.Read(context.Background(), func(tx port.TxStores) error {
		var err error
		settings, err = tx.Installation().GetSettings(context.Background())
		return err
	})
	return settings, err
}

func assertSettingsInitializeUnchanged(t *testing.T, store *porttest.Store) {
	t.Helper()
	err := store.Read(context.Background(), func(tx port.TxStores) error {
		_, err := tx.Installation().GetSettings(context.Background())
		return err
	})
	if !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("settings lookup error = %v, want no initialized row", err)
	}
	if events := store.AuditEvents(); len(events) != 0 {
		t.Fatalf("audit events = %d, want none after rejected initialization", len(events))
	}
}

func hasSettingsInitializeAppError(err error, kind contract.ErrorKind, code string) bool {
	var appErr *contract.AppError
	return errors.As(err, &appErr) && appErr.Kind() == kind && appErr.Code() == code
}

type settingsInitializeFailAuditUOW struct{ port.UnitOfWork }

func (u settingsInitializeFailAuditUOW) Write(ctx context.Context, fn func(port.TxStores) error) error {
	return u.UnitOfWork.Write(ctx, func(tx port.TxStores) error {
		return fn(settingsInitializeFailAuditTxStores{TxStores: tx})
	})
}

type settingsInitializeFailAuditTxStores struct{ port.TxStores }

func (tx settingsInitializeFailAuditTxStores) Audit() port.AuditRepository {
	return settingsInitializeFailAuditRepository{AuditRepository: tx.TxStores.Audit()}
}

type settingsInitializeFailAuditRepository struct{ port.AuditRepository }

func (settingsInitializeFailAuditRepository) Append(context.Context, port.AuditEvent, port.AuditScope) error {
	return errors.New("injected audit failure")
}
