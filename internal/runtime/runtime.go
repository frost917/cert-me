package runtime

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"cert-me/internal/adapter/http"
	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/app/service"
	"cert-me/internal/authcrypto"
	"cert-me/internal/config"
	"cert-me/internal/cryptoengine"
	"cert-me/internal/cryptoformats"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
	"cert-me/internal/storage/connection"
	"cert-me/internal/storage/executionlock"
	"cert-me/internal/storage/migrate"
	"cert-me/internal/storage/sqlstore"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/tlsruntime"
)

const (
	defaultListenAddress = ":8443"
	shutdownTimeout      = 30 * time.Second
	lockCheckInterval    = 2 * time.Second
	lockCheckTimeout     = 60 * time.Second
	serviceModeStarting  = "starting"
	serviceModeServing   = "serving"
	serviceModeRecovery  = "recovery_required"
)

var ErrStartupRecoveryRequired = errors.New("runtime: startup recovery required")

type Options struct {
	Database          config.Database
	StorageKey        *secret.Input
	TrustedProxyCIDRs []netip.Prefix
	ListenAddress     string
	Logger            *slog.Logger
}

type App struct {
	db                   *connection.DB
	lock                 *executionlock.Lock
	store                *core.Store
	ring                 *cryptoengine.KeyRing
	tlsManager           *tlsruntime.ConfigManager
	gate                 *Gate
	server               *http.Server
	listenAddress        string
	logger               *slog.Logger
	bootstrapFingerprint string
	monitorCancel        context.CancelFunc
	monitorDone          chan struct{}
	closeOnce            sync.Once
	closeErr             error
}

// Open prepares one application instance. An empty, fully migrated schema is
// initialized atomically. Existing installations must authenticate their
// persisted verifier, reconcile TLS state, and install the recorded active
// certificate before a listener can be started.
func Open(ctx context.Context, opts Options) (app *App, err error) {
	if ctx == nil {
		return nil, errors.New("runtime: context is required")
	}
	if opts.StorageKey == nil || opts.StorageKey.Len() != 32 {
		return nil, config.ErrInvalidConfig
	}
	if err := migrateInitialSchema(ctx, opts.Database); err != nil {
		return nil, fmt.Errorf("runtime: prepare database schema: %w", err)
	}

	listenAddress := opts.ListenAddress
	if listenAddress == "" {
		listenAddress = defaultListenAddress
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	app = &App{
		gate:          NewGate(),
		listenAddress: listenAddress,
		logger:        logger,
	}
	preparedApp := app
	defer func() {
		if err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if closeErr := preparedApp.Close(cleanupCtx); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}
	}()

	app.db, err = connection.Open(ctx, opts.Database, connection.Options{})
	if err != nil {
		return nil, fmt.Errorf("runtime: open database: %w", err)
	}
	app.lock, err = executionlock.Acquire(ctx, opts.Database, app.db.WriterConn())
	if err != nil {
		return nil, fmt.Errorf("runtime: acquire execution lock: %w", err)
	}
	app.startOwnershipMonitor()

	newGenerationID, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("runtime: create encryption generation: %w", err)
	}
	app.ring, err = cryptoengine.NewKeyRing(newGenerationID, map[string]*secret.Input{newGenerationID: opts.StorageKey})
	if err != nil {
		return nil, fmt.Errorf("runtime: create encryption key ring: %w", err)
	}
	keyEngine, err := cryptoengine.NewKeyEngine(app.ring)
	if err != nil {
		return nil, fmt.Errorf("runtime: create key engine: %w", err)
	}
	initialVerifier, err := keyEngine.CreateStoreVerifier(ctx)
	if err != nil {
		return nil, fmt.Errorf("runtime: create storage verifier: %w", err)
	}
	initialState, _, err := sqlstore.EnsureInitialInstallation(
		ctx, app.db, opts.Database.Kind, app.lock, newGenerationID, initialVerifier, time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("runtime: initialize installation: %w", err)
	}
	if initialState.ActiveEncryptionGenerationID == "" {
		return nil, fmt.Errorf("runtime: installation has no active encryption generation: %w", ErrStartupRecoveryRequired)
	}
	if initialState.ActiveEncryptionGenerationID != newGenerationID {
		if closeErr := app.ring.Close(); closeErr != nil {
			return nil, fmt.Errorf("runtime: close provisional key ring: %w", closeErr)
		}
		app.ring, err = cryptoengine.NewKeyRing(
			initialState.ActiveEncryptionGenerationID,
			map[string]*secret.Input{initialState.ActiveEncryptionGenerationID: opts.StorageKey},
		)
		if err != nil {
			return nil, fmt.Errorf("runtime: load active encryption key generation: %w", err)
		}
		keyEngine, err = cryptoengine.NewKeyEngine(app.ring)
		if err != nil {
			return nil, fmt.Errorf("runtime: create active key engine: %w", err)
		}
	}

	app.store, err = sqlstore.NewStore(app.db, opts.Database.Kind)
	if err != nil {
		return nil, fmt.Errorf("runtime: create SQL store: %w", err)
	}
	verifier, err := readStoreVerifier(ctx, app.store)
	if err != nil {
		return nil, fmt.Errorf("runtime: read storage verifier: %w", err)
	}
	if verifier.EncryptionGenerationID() != initialState.ActiveEncryptionGenerationID {
		return nil, fmt.Errorf("runtime: storage verifier does not match installation generation: %w", ErrStartupRecoveryRequired)
	}
	if err := keyEngine.VerifyStoreVerifier(ctx, verifier); err != nil {
		return nil, fmt.Errorf("runtime: storage key verification failed: %w", err)
	}
	if err := sqlstore.EnsureNoIncompleteMaintenance(ctx, app.db, opts.Database.Kind, app.lock); err != nil {
		return nil, fmt.Errorf("runtime: operational recovery is required before serving: %w", err)
	}
	if err := app.checkOwnership(ctx); err != nil {
		return nil, fmt.Errorf("runtime: verify execution ownership: %w", err)
	}
	if err := setServiceMode(ctx, app.store, serviceModeStarting); err != nil {
		return nil, fmt.Errorf("runtime: mark installation as starting: %w", err)
	}

	app.tlsManager, err = newTLSManager(app.ring)
	if err != nil {
		return nil, fmt.Errorf("runtime: create TLS manager: %w", err)
	}
	if err := app.prepareServices(ctx, keyEngine, opts.TrustedProxyCIDRs); err != nil {
		return nil, err
	}
	if app.gate.Failed() {
		return nil, fmt.Errorf("runtime: execution ownership was lost during startup: %w", ErrStartupRecoveryRequired)
	}

	return app, nil
}

func (a *App) startOwnershipMonitor() {
	ctx, cancel := context.WithCancel(context.Background())
	a.monitorCancel = cancel
	a.monitorDone = make(chan struct{})
	go func() {
		defer close(a.monitorDone)
		ticker := time.NewTicker(lockCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				checkCtx, checkCancel := context.WithTimeout(ctx, lockCheckTimeout)
				err := a.checkOwnership(checkCtx)
				checkCancel()
				if err != nil {
					a.gate.FailClosed("runtime_execution_lock_lost")
					return
				}
			}
		}
	}()
}

func migrateInitialSchema(ctx context.Context, database config.Database) error {
	runner, err := migrate.NewRunner(database)
	if err != nil {
		return err
	}
	status, err := runner.Status(ctx)
	if err != nil {
		return err
	}
	if status.State == migrate.StateEmpty {
		if err := runner.Migrate(ctx); err != nil {
			return err
		}
		status, err = runner.Status(ctx)
		if err != nil {
			return err
		}
	}
	if status.State != migrate.StateCurrent {
		var stateErr error
		switch status.State {
		case migrate.StateUpgradeRequired, migrate.StateEmpty:
			stateErr = migrate.ErrMigrateRequired
		case migrate.StateResumeRequired:
			stateErr = migrate.ErrResumeRequired
		case migrate.StateBusy:
			stateErr = migrate.ErrBusy
		case migrate.StateIncompatible:
			stateErr = migrate.ErrIncompatible
		default:
			stateErr = migrate.ErrUnavailable
		}
		return fmt.Errorf("runtime: database schema is %s; resolve it with the explicit db command: %w", status.State, stateErr)
	}
	return runner.Close()
}

func readStoreVerifier(ctx context.Context, store *core.Store) (domain.EncryptedSecret, error) {
	var verifier domain.EncryptedSecret
	err := store.Read(ctx, func(tx port.TxStores) error {
		var err error
		verifier, err = tx.Secrets().GetVerifier(ctx)
		return err
	})
	if err != nil {
		return domain.EncryptedSecret{}, err
	}
	return verifier, nil
}

func newTLSManager(ring *cryptoengine.KeyRing) (*tlsruntime.ConfigManager, error) {
	loader, err := cryptoengine.NewTLSKeyLoader(ring)
	if err != nil {
		return nil, err
	}
	return tlsruntime.NewConfigManager(loader)
}

func (a *App) prepareServices(ctx context.Context, keyEngine *cryptoengine.KeyEngine, trusted []netip.Prefix) error {
	common := service.CommonDeps{
		UnitOfWork: a.store,
		ReadStore:  a.store,
		Authorizer: adminAuthorizer{},
		Clock:      systemClock{},
		IDs:        randomIDs{},
	}
	setupService, err := service.NewSetupService(service.SetupDeps{
		CommonDeps:     common,
		PasswordHasher: authcrypto.PasswordHasher{},
	})
	if err != nil {
		return fmt.Errorf("runtime: create setup service: %w", err)
	}
	identityService, err := service.NewIdentityService(service.IdentityDeps{
		CommonDeps:     common,
		PasswordHasher: authcrypto.PasswordHasher{},
		TokenCodec:     authcrypto.TokenCodec{},
	})
	if err != nil {
		return fmt.Errorf("runtime: create identity service: %w", err)
	}
	settingsService, err := service.NewSettingsService(service.SettingsDeps{
		CommonDeps:   common,
		URLValidator: cryptoformats.URLValidator{},
	})
	if err != nil {
		return fmt.Errorf("runtime: create settings service: %w", err)
	}
	deliveryEncoder, err := cryptoengine.NewDeliveryEncoder(a.ring)
	if err != nil {
		return fmt.Errorf("runtime: create delivery encoder: %w", err)
	}
	distributionService, err := service.NewDistributionService(service.DistributionDeps{
		CommonDeps:               common,
		TokenCodec:               authcrypto.TokenCodec{},
		DeliveryEncoder:          deliveryEncoder,
		PublicCertificateEncoder: cryptoformats.NewPublicCertificateEncoder(),
		OperationalLogger:        operationalLogger{logger: a.logger},
		RuntimeGate:              a.gate,
	})
	if err != nil {
		return fmt.Errorf("runtime: create distribution service: %w", err)
	}
	if _, err := distributionService.RecoverInterruptedTransfers(ctx); err != nil {
		return fmt.Errorf("runtime: recover interrupted deliveries: %w", err)
	}

	internalFactory, err := contract.NewInternalPrincipalFactory(
		contract.InternalOperationTLSBootstrap,
		contract.InternalOperationTLSReconcile,
	)
	if err != nil {
		return fmt.Errorf("runtime: create internal principal factory: %w", err)
	}
	bootstrapPrincipal, err := internalFactory.Principal(contract.InternalOperationTLSBootstrap)
	if err != nil {
		return fmt.Errorf("runtime: create TLS bootstrap principal: %w", err)
	}
	reconcilePrincipal, err := internalFactory.Principal(contract.InternalOperationTLSReconcile)
	if err != nil {
		return fmt.Errorf("runtime: create TLS reconcile principal: %w", err)
	}

	certSigner, err := cryptoengine.NewCertificateSigner(a.ring)
	if err != nil {
		return fmt.Errorf("runtime: create certificate signer: %w", err)
	}
	authorityService, err := service.NewAuthorityService(service.AuthorityDeps{
		CommonDeps: common, KeyEngine: keyEngine, CertificateSigner: certSigner,
		SerialGenerator: authcrypto.SerialGenerator{}, ProfileValidator: cryptoformats.ProfileValidator{},
	})
	if err != nil {
		return fmt.Errorf("runtime: create authority service: %w", err)
	}
	issuanceService, err := service.NewIssuanceService(service.IssuanceDeps{
		CommonDeps: common, KeyEngine: keyEngine, CertificateSigner: certSigner,
		SerialGenerator: authcrypto.SerialGenerator{}, ProfileValidator: cryptoformats.ProfileValidator{},
	})
	if err != nil {
		return fmt.Errorf("runtime: create issuance service: %w", err)
	}
	queryService, err := service.NewQueryService(common)
	if err != nil {
		return fmt.Errorf("runtime: create query service: %w", err)
	}
	noFileSource := unavailableTLSFileSource{}
	tlsService, err := service.NewTLSService(service.TLSDeps{
		CommonDeps:        common,
		KeyEngine:         keyEngine,
		CertificateSigner: certSigner,
		SerialGenerator:   authcrypto.SerialGenerator{},
		ChainValidator:    cryptoformats.ChainValidator{},
		TLSInstaller:      a.tlsManager,
		PKIParser:         cryptoformats.NewPKIParser(),
		FileSource:        noFileSource,
		RuntimeGate:       a.gate,
	})
	if err != nil {
		return fmt.Errorf("runtime: create TLS service: %w", err)
	}
	if err := a.prepareTLS(ctx, tlsService, bootstrapPrincipal, reconcilePrincipal); err != nil {
		return err
	}

	serviceURL, serviceURLVersion, err := loadServiceURL(ctx, a.store)
	if err != nil {
		return fmt.Errorf("runtime: read service URL: %w", err)
	}
	handler, err := httpadapter.NewSetupHandler(httpadapter.SetupHandlerConfig{
		Service:           setupService,
		Identity:          identityService,
		Settings:          settingsService,
		Authorities:       authorityService,
		PKIQueries:        queryService,
		Issuance:          issuanceService,
		LeafQueries:       queryService,
		PublicCA:          queryService,
		ServiceURL:        serviceURL,
		ServiceURLVersion: serviceURLVersion,
		TrustedProxies:    trusted,
	})
	if err != nil {
		return fmt.Errorf("runtime: create initial setup handler: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	appHandler := httpadapter.WithSecurityHeaders(a.withAdmission(mux))
	a.server = &http.Server{
		Handler:           appHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return nil
}

func (a *App) prepareTLS(
	ctx context.Context,
	tlsService *service.TLSService,
	bootstrapPrincipal contract.Principal,
	reconcilePrincipal contract.Principal,
) error {
	state, err := readTLSStartupState(ctx, a.store)
	if err != nil {
		return fmt.Errorf("runtime: inspect TLS startup state: %w", err)
	}
	if state.change == nil {
		if state.installation.ActiveTLSVersionID != "" || len(state.versions) != 0 {
			return fmt.Errorf("runtime: TLS history has no active change; %w", ErrStartupRecoveryRequired)
		}
		if _, err := tlsService.Bootstrap(ctx, internalMutation(bootstrapPrincipal), contract.TLSBootstrapCommand{}); err != nil {
			return fmt.Errorf("runtime: create initial bootstrap TLS certificate: %w", err)
		}
	} else if state.change.Phase() == domain.TLSChangePhaseApplied &&
		state.installation.ActiveTLSVersionID == state.change.CandidateVersionID() {
		if err := a.installPersistedTLS(ctx, state.change.CandidateVersionID()); err != nil {
			return err
		}
	} else {
		view, err := tlsService.Reconcile(ctx, internalMutation(reconcilePrincipal), contract.TLSReconcileCommand{})
		if err != nil {
			return fmt.Errorf("runtime: reconcile TLS state: %w", err)
		}
		if view.Active == nil {
			return fmt.Errorf("runtime: TLS reconciliation has no active version: %w", ErrStartupRecoveryRequired)
		}
	}

	active, err := a.readActiveTLS(ctx)
	if err != nil {
		return fmt.Errorf("runtime: read active TLS after preparation: %w", err)
	}
	if active.Source() == domain.TLSSourceBootstrap {
		digest := sha256.Sum256(active.LeafDER())
		a.bootstrapFingerprint = hex.EncodeToString(digest[:])
	}
	return nil
}

type tlsStartupState struct {
	installation port.Installation
	change       *domain.TLSChange
	versions     []domain.TLSVersion
}

func readTLSStartupState(ctx context.Context, store *core.Store) (tlsStartupState, error) {
	var state tlsStartupState
	err := store.Read(ctx, func(tx port.TxStores) error {
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return err
		}
		state.installation = installation
		versions, err := tx.TLS().ListVersions(ctx)
		if err != nil {
			return err
		}
		state.versions = versions
		change, err := tx.TLS().GetActiveForUpdate(ctx)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		state.change = &change
		return nil
	})
	return state, err
}

func (a *App) installPersistedTLS(ctx context.Context, versionID domain.TLSVersionID) error {
	var version domain.TLSVersion
	var encrypted domain.EncryptedSecret
	err := a.store.Read(ctx, func(tx port.TxStores) error {
		var err error
		version, err = tx.TLS().GetVersion(ctx, versionID)
		if err != nil {
			return err
		}
		encrypted, err = tx.Secrets().GetEncrypted(ctx, version.KeyMaterialID(), domain.SecretPurposeInternalTLS)
		return err
	})
	if err != nil {
		return fmt.Errorf("runtime: load active TLS snapshot: %w", err)
	}
	prepared, err := a.tlsManager.Prepare(ctx, version, encrypted)
	if err != nil {
		return fmt.Errorf("runtime: prepare active TLS snapshot: %w", err)
	}
	defer a.tlsManager.Discard(prepared)
	if err := a.tlsManager.Apply(ctx, prepared); err != nil {
		return fmt.Errorf("runtime: install active TLS snapshot: %w", err)
	}
	return nil
}

func (a *App) readActiveTLS(ctx context.Context) (domain.TLSVersion, error) {
	var active domain.TLSVersion
	err := a.store.Read(ctx, func(tx port.TxStores) error {
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return err
		}
		if installation.ActiveTLSVersionID == "" {
			return port.ErrNotFound
		}
		active, err = tx.TLS().GetVersion(ctx, installation.ActiveTLSVersionID)
		return err
	})
	return active, err
}

func loadServiceURL(ctx context.Context, store *core.Store) (string, int64, error) {
	var serviceURL string
	var serviceURLVersion int64
	err := store.Read(ctx, func(tx port.TxStores) error {
		settings, err := tx.Installation().GetSettings(ctx)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		decoded, err := service.DecodeSettingsV1(settings)
		if err != nil {
			return err
		}
		serviceURL = decoded.ServiceURL
		serviceURLVersion = settings.Version.Int64()
		return nil
	})
	return serviceURL, serviceURLVersion, err
}

func internalMutation(principal contract.Principal) contract.MutationMeta {
	return contract.MutationMeta{RequestMeta: contract.RequestMeta{Principal: principal}}
}

func (a *App) withAdmission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.Context().Err(); err != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		release, accepted := a.gate.Admit()
		if !accepted {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		defer release()
		next.ServeHTTP(w, r)
	})
}

// ListenAndServe binds the configured address and serves HTTPS only. The
// dynamic TLS configuration has already been bootstrapped or restored before
// admission opens.
func (a *App) ListenAndServe(ctx context.Context) error {
	if a == nil || a.server == nil || a.tlsManager == nil {
		return errors.New("runtime: application is not prepared")
	}
	if ctx == nil {
		return errors.New("runtime: serve context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", a.listenAddress)
	if err != nil {
		return fmt.Errorf("runtime: open HTTPS listener: %w", err)
	}
	if err := ctx.Err(); err != nil {
		closeErr := listener.Close()
		return errors.Join(err, closeErr)
	}
	if err := a.checkOwnership(ctx); err != nil {
		if ctx.Err() != nil {
			return errors.Join(ctx.Err(), listener.Close())
		}
		a.gate.FailClosed("runtime_execution_lock_lost")
		closeErr := listener.Close()
		return errors.Join(fmt.Errorf("runtime: execution ownership unavailable: %w", err), closeErr)
	}
	if err := setServiceMode(ctx, a.store, serviceModeServing); err != nil {
		_ = listener.Close()
		return fmt.Errorf("runtime: mark installation as serving: %w", err)
	}
	if !a.gate.OpenAdmission() {
		closeErr := listener.Close()
		modeErr := setServiceMode(ctx, a.store, serviceModeRecovery)
		return errors.Join(ErrStartupRecoveryRequired, closeErr, modeErr)
	}
	tlsListener := tls.NewListener(listener, a.tlsManager.ServerConfig())
	serveResult := make(chan error, 1)
	go func() { serveResult <- a.server.Serve(tlsListener) }()

	var serveErr error
	serveResultReceived := false
	select {
	case <-ctx.Done():
	case <-a.gate.StopRequested():
		serveErr = fmt.Errorf("runtime: fail-closed shutdown requested: %s", a.gate.FailureCode())
	case err := <-serveResult:
		serveResultReceived = true
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	}
	a.gate.CloseAdmission()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(shutdownCtx); err != nil {
		serveErr = errors.Join(serveErr, fmt.Errorf("runtime: graceful HTTPS shutdown: %w", err))
		if closeErr := a.server.Close(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
			serveErr = errors.Join(serveErr, fmt.Errorf("runtime: force HTTPS shutdown: %w", closeErr))
		}
	}
	if err := a.gate.WaitIdle(shutdownCtx); err != nil {
		serveErr = errors.Join(serveErr, fmt.Errorf("runtime: drain admitted work: %w", err))
	}
	mode := serviceModeStarting
	if a.gate.Failed() {
		if a.gate.FailureCode() != "runtime_execution_lock_lost" {
			mode = serviceModeRecovery
		} else {
			mode = ""
		}
	}
	if mode != "" {
		if err := setServiceMode(shutdownCtx, a.store, mode); err != nil {
			serveErr = errors.Join(serveErr, fmt.Errorf("runtime: persist shutdown mode: %w", err))
		}
	}
	if !serveResultReceived {
		select {
		case err := <-serveResult:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				serveErr = errors.Join(serveErr, err)
			}
		case <-shutdownCtx.Done():
			serveErr = errors.Join(serveErr, shutdownCtx.Err())
		}
	}
	return serveErr
}

func (a *App) BootstrapFingerprint() string {
	if a == nil {
		return ""
	}
	return a.bootstrapFingerprint
}

func (a *App) checkOwnership(ctx context.Context) error {
	if ctx == nil || a.db == nil || a.lock == nil {
		return errors.New("runtime: execution ownership dependencies are unavailable")
	}
	if err := a.db.CheckWriter(ctx); err != nil {
		return fmt.Errorf("runtime: pinned writer health check: %w", err)
	}
	if err := a.lock.Check(ctx); err != nil {
		return fmt.Errorf("runtime: execution lock check: %w", err)
	}
	return nil
}

func setServiceMode(ctx context.Context, store *core.Store, mode string) error {
	if mode != serviceModeStarting && mode != serviceModeServing && mode != serviceModeRecovery {
		return fmt.Errorf("runtime: invalid service mode %q", mode)
	}
	return store.Write(ctx, func(tx port.TxStores) error {
		installation, err := tx.Installation().GetForUpdate(ctx)
		if err != nil {
			return fmt.Errorf("runtime: read installation mode: %w", err)
		}
		if installation.ServiceMode == mode {
			return nil
		}
		originalVersion := installation.Version
		installation.ServiceMode = mode
		installation.Version = installation.Version.Next()
		if err := tx.Installation().Save(ctx, installation, originalVersion); err != nil {
			return fmt.Errorf("runtime: store installation mode: %w", err)
		}
		return nil
	})
}

// Close releases process resources after the listener is shut down. It is
// safe to call more than once.
func (a *App) Close(ctx context.Context) error {
	if a == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	a.closeOnce.Do(func() {
		a.gate.CloseAdmission()
		if a.server != nil {
			shutdownCtx, cancel := context.WithTimeout(ctx, shutdownTimeout)
			defer cancel()
			if err := a.server.Shutdown(shutdownCtx); err != nil {
				a.closeErr = errors.Join(a.closeErr, err)
				if closeErr := a.server.Close(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
					a.closeErr = errors.Join(a.closeErr, closeErr)
				}
			}
		}
		if a.monitorCancel != nil {
			a.monitorCancel()
			<-a.monitorDone
		}
		if a.tlsManager != nil {
			a.tlsManager.Close()
		}
		if a.ring != nil {
			if err := a.ring.Close(); err != nil {
				a.closeErr = errors.Join(a.closeErr, err)
			}
		}
		if a.lock != nil {
			if ctx == nil {
				ctx = context.Background()
			}
			if err := a.lock.Release(ctx); err != nil {
				a.closeErr = errors.Join(a.closeErr, err)
			}
		}
		if a.db != nil {
			if err := a.db.Close(); err != nil {
				a.closeErr = errors.Join(a.closeErr, err)
			}
		}
	})
	return a.closeErr
}

type unavailableTLSFileSource struct{}

func (unavailableTLSFileSource) Load(ctx context.Context) (port.TLSFileSourceInput, error) {
	if err := ctx.Err(); err != nil {
		return port.TLSFileSourceInput{}, err
	}
	return port.TLSFileSourceInput{}, errors.New("runtime: no external TLS file source is configured")
}
