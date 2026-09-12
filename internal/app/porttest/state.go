// Package porttest is the in-memory port.UnitOfWork test double the B02
// service tests are built against (docs/backend-implementation.md §11: "메모리
// 저장소는 서비스 테스트용으로만 사용한다. UoW 대역은 copy-on-write로
// callback 실패 시 전체 rollback을 구현하며 트랜잭션 없이 각 메서드를 즉시
// 반영하는 단순 map mock을 사용하지 않는다"). It is not wired into any
// non-test code path.
//
// # Design
//
// All durable state lives in one immutable snapshot, *state. Store holds the
// currently published snapshot behind an atomic.Pointer and a plain
// sync.Mutex that serializes Write calls:
//
//   - Write clones the published snapshot into a private working copy,
//     hands that copy to the callback through a txStores, and only
//     publishes it (atomically swapping the pointer) if the callback
//     returns nil. A non-nil error or a panic simply never reaches the
//     publish step, so the previous snapshot stays authoritative -- this
//     is the whole rollback mechanism; there is no separate "undo log" to
//     replay, because nothing under the working copy was ever visible to
//     anyone else.
//   - Read clones the published snapshot the same way but never publishes
//     the result under any outcome, matching port.ReadStore's contract
//     that a read is preparation input only and can never smuggle a commit
//     through a callback that happens to call a Save method.
//   - Serializing Write with a mutex (rather than allowing two callbacks to
//     race against genuinely concurrent working copies) is a deliberate
//     simplification for a test double: it still gives every clause the
//     real store must honor -- no data race (verified with -race), and a
//     "loser" transaction whose expectedVersion was read before a
//     concurrent winner's commit fails with ErrVersionConflict when it
//     tries to Save, exactly as a real WHERE version=expectedVersion
//     update would. What it does not model is two SQL transactions
//     genuinely interleaving their statements; that is out of scope for a
//     package whose only job is to exercise service-level rollback
//     behavior (§11's stated B02 acceptance criterion).
//
// # Copying in and out
//
// Every domain.* value stored here (Account, Revocation, Certificate, ...)
// already follows the immutable-value-with-private-fields pattern: its
// exported byte-slice/collection accessors (e.g. Certificate.DER(),
// EncryptedSecret.Ciphertext()) clone on every call, so copying the struct
// by value (map assignment) can never let a caller reach back into stored
// state through a returned slice. The handful of port-level structs that
// expose a plain public []byte/map field with no such accessor (CRLDocument,
// Job, RevocationRevision, Settings, OperationRequestResult,
// contract.AuditDetails.Fields, and the scopes slice AuditRepository.Append
// takes) are different: this package clones those fields by hand on the way
// into a repository method and again on the way out, in copyIn.go, so that
// clause 8 ("Slices and mutable values are copied on the way in and on the
// way out") holds for them too.
package porttest

import (
	"context"
	"sync"
	"sync/atomic"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// secretKey identifies one private_key_secrets row.
type secretKey struct {
	keyID   domain.KeyMaterialID
	purpose domain.SecretPurpose
}

// revocationKey identifies one revocation ledger row (data-model.md: "폐기의
// 기준 키는 issuer/serial").
type revocationKey struct {
	issuer domain.CAKeyGenerationID
	serial string
}

// impactKey identifies one transition_impacts row.
type impactKey struct {
	transitionID  domain.TransitionID
	certificateID domain.CertificateID
}

// rateLimitKey identifies one auth_rate_limits row.
type rateLimitKey struct {
	kind        string
	subjectHash string
	windowStart int64
}

// revisionKey identifies one revocation_revisions row (revocation + revision
// number).
type revisionKey struct {
	revocationID domain.RevocationID
	revisionNo   int
}

// state is one immutable, fully-populated snapshot of every repository's
// rows. A *state value is never mutated once handed to anyone outside this
// package's Write/Read plumbing -- see the package doc's "Design" section.
type state struct {
	accounts          map[domain.AccountID]domain.Account
	sessions          map[domain.SessionID]domain.SessionState
	sessionsByHash    map[string]domain.SessionID
	resetTokens       map[domain.ResetTokenID]domain.AdminResetToken
	resetTokensByHash map[string]domain.ResetTokenID
	rateLimits        map[rateLimitKey]port.RateLimitRecord

	installationSet bool
	installation    port.Installation
	settingsSet     bool
	settings        port.Settings

	keyMaterials       map[domain.KeyMaterialID]port.KeyMaterial
	keyMaterialsBySPKI map[string]domain.KeyMaterialID
	caKeyGenerations   map[domain.CAKeyGenerationID]port.CAKeyGeneration
	authorities        map[domain.AuthorityID]domain.Authority
	certificates       map[domain.CertificateID]domain.Certificate
	certificatesByDER  map[string]domain.CertificateID
	leafCertRecords    map[domain.CertificateID]port.LeafCertificateRecord
	caCertRecords      map[domain.CertificateID]port.CACertificateRecord
	series             map[domain.SeriesID]domain.LeafSeries
	leafKeyGenerations map[domain.LeafKeyGenerationID]domain.LeafKeyGeneration

	deliveries   map[domain.DeliveryID]domain.Delivery
	grants       map[domain.GrantID]domain.DownloadGrant
	grantsByHash map[string]domain.GrantID

	revocations         map[revocationKey]domain.Revocation
	revocationRevisions map[revisionKey]port.RevocationRevision

	crlStates    map[domain.CAKeyGenerationID]domain.CRLState
	crlDocuments map[domain.CRLDocumentID]port.CRLDocument

	transitions             map[domain.TransitionID]domain.Transition
	impacts                 map[impactKey]domain.TransitionImpact
	deploymentConfirmations []domain.DeploymentConfirmation

	tlsVersions map[domain.TLSVersionID]domain.TLSVersion
	// tlsChanges is keyed by CandidateVersionID: domain.TLSChange exposes no
	// ID() accessor of its own (unlike every other stored entity), but its
	// candidate version id is set once at construction and never reused
	// across rows, so it is a stable synthetic key for this test double.
	tlsChanges map[domain.TLSVersionID]domain.TLSChange

	requestResults map[port.OperationRequestKey]port.OperationRequestResult

	secrets     map[secretKey]domain.EncryptedSecret
	verifierSet bool
	verifier    domain.EncryptedSecret

	jobs       map[domain.JobID]port.Job
	jobByDedup map[string]domain.JobID

	maintenanceRuns            map[domain.JobID]port.MaintenanceRun
	maintenanceCRLRequirements map[maintenanceRequirementKey]port.MaintenanceCRLRequirement

	auditEvents []auditRow

	// importBatches/takeovers back port.ImportRepository (added for the B02
	// contract-completeness round, docs/backend-implementation.md §13
	// closing paragraph: "import batch/takeover 저장·조회"). pendingTakeover
	// indexes the current pending row per CA key generation, the lookup
	// GetPendingTakeoverForUpdate needs and the same shape as the real
	// schema's ix_ca_takeovers_1 (ca_key_generation_id,state) index; it is
	// deleted once a takeover moves off "pending".
	importBatches   map[domain.ImportBatchID]port.ImportBatch
	takeovers       map[domain.TakeoverID]port.Takeover
	pendingTakeover map[domain.CAKeyGenerationID]domain.TakeoverID
}

// auditRow bundles one stored audit event with the scopes it was appended
// under, since AuditRepository.Append takes them as two separate arguments
// (see port.AuditEvent's doc comment on why they are never merged into one
// stored value).
type auditRow struct {
	event  port.AuditEvent
	scopes []domain.AuthorityID
}

type maintenanceRequirementKey struct {
	runID  domain.JobID
	issuer domain.CAKeyGenerationID
}

func newState() *state {
	return &state{
		accounts:                   map[domain.AccountID]domain.Account{},
		sessions:                   map[domain.SessionID]domain.SessionState{},
		sessionsByHash:             map[string]domain.SessionID{},
		resetTokens:                map[domain.ResetTokenID]domain.AdminResetToken{},
		resetTokensByHash:          map[string]domain.ResetTokenID{},
		rateLimits:                 map[rateLimitKey]port.RateLimitRecord{},
		keyMaterials:               map[domain.KeyMaterialID]port.KeyMaterial{},
		keyMaterialsBySPKI:         map[string]domain.KeyMaterialID{},
		caKeyGenerations:           map[domain.CAKeyGenerationID]port.CAKeyGeneration{},
		leafCertRecords:            map[domain.CertificateID]port.LeafCertificateRecord{},
		caCertRecords:              map[domain.CertificateID]port.CACertificateRecord{},
		authorities:                map[domain.AuthorityID]domain.Authority{},
		certificates:               map[domain.CertificateID]domain.Certificate{},
		certificatesByDER:          map[string]domain.CertificateID{},
		series:                     map[domain.SeriesID]domain.LeafSeries{},
		leafKeyGenerations:         map[domain.LeafKeyGenerationID]domain.LeafKeyGeneration{},
		deliveries:                 map[domain.DeliveryID]domain.Delivery{},
		grants:                     map[domain.GrantID]domain.DownloadGrant{},
		grantsByHash:               map[string]domain.GrantID{},
		revocations:                map[revocationKey]domain.Revocation{},
		revocationRevisions:        map[revisionKey]port.RevocationRevision{},
		crlStates:                  map[domain.CAKeyGenerationID]domain.CRLState{},
		crlDocuments:               map[domain.CRLDocumentID]port.CRLDocument{},
		transitions:                map[domain.TransitionID]domain.Transition{},
		impacts:                    map[impactKey]domain.TransitionImpact{},
		tlsVersions:                map[domain.TLSVersionID]domain.TLSVersion{},
		tlsChanges:                 map[domain.TLSVersionID]domain.TLSChange{},
		requestResults:             map[port.OperationRequestKey]port.OperationRequestResult{},
		secrets:                    map[secretKey]domain.EncryptedSecret{},
		jobs:                       map[domain.JobID]port.Job{},
		jobByDedup:                 map[string]domain.JobID{},
		maintenanceRuns:            map[domain.JobID]port.MaintenanceRun{},
		maintenanceCRLRequirements: map[maintenanceRequirementKey]port.MaintenanceCRLRequirement{},
		importBatches:              map[domain.ImportBatchID]port.ImportBatch{},
		takeovers:                  map[domain.TakeoverID]port.Takeover{},
		pendingTakeover:            map[domain.CAKeyGenerationID]domain.TakeoverID{},
	}
}

// clone returns a working copy whose maps are new map headers over copied
// entries, so inserts/deletes/overwrites made through the copy never touch
// s. The values stored in those entries (domain.* objects and the
// port-level structs above) are never mutated in place anywhere in this
// package -- every change replaces a map entry outright -- so copying map
// headers this shallowly is already a full copy-on-write for this snapshot;
// see the package doc for why the individual field values do not also need
// a deep walk here.
func (s *state) clone() *state {
	n := &state{
		accounts:                   make(map[domain.AccountID]domain.Account, len(s.accounts)),
		sessions:                   make(map[domain.SessionID]domain.SessionState, len(s.sessions)),
		sessionsByHash:             make(map[string]domain.SessionID, len(s.sessionsByHash)),
		resetTokens:                make(map[domain.ResetTokenID]domain.AdminResetToken, len(s.resetTokens)),
		resetTokensByHash:          make(map[string]domain.ResetTokenID, len(s.resetTokensByHash)),
		rateLimits:                 make(map[rateLimitKey]port.RateLimitRecord, len(s.rateLimits)),
		installationSet:            s.installationSet,
		installation:               s.installation,
		settingsSet:                s.settingsSet,
		settings:                   s.settings,
		keyMaterials:               make(map[domain.KeyMaterialID]port.KeyMaterial, len(s.keyMaterials)),
		keyMaterialsBySPKI:         make(map[string]domain.KeyMaterialID, len(s.keyMaterialsBySPKI)),
		caKeyGenerations:           make(map[domain.CAKeyGenerationID]port.CAKeyGeneration, len(s.caKeyGenerations)),
		leafCertRecords:            make(map[domain.CertificateID]port.LeafCertificateRecord, len(s.leafCertRecords)),
		caCertRecords:              make(map[domain.CertificateID]port.CACertificateRecord, len(s.caCertRecords)),
		authorities:                make(map[domain.AuthorityID]domain.Authority, len(s.authorities)),
		certificates:               make(map[domain.CertificateID]domain.Certificate, len(s.certificates)),
		certificatesByDER:          make(map[string]domain.CertificateID, len(s.certificatesByDER)),
		series:                     make(map[domain.SeriesID]domain.LeafSeries, len(s.series)),
		leafKeyGenerations:         make(map[domain.LeafKeyGenerationID]domain.LeafKeyGeneration, len(s.leafKeyGenerations)),
		deliveries:                 make(map[domain.DeliveryID]domain.Delivery, len(s.deliveries)),
		grants:                     make(map[domain.GrantID]domain.DownloadGrant, len(s.grants)),
		grantsByHash:               make(map[string]domain.GrantID, len(s.grantsByHash)),
		revocations:                make(map[revocationKey]domain.Revocation, len(s.revocations)),
		revocationRevisions:        make(map[revisionKey]port.RevocationRevision, len(s.revocationRevisions)),
		crlStates:                  make(map[domain.CAKeyGenerationID]domain.CRLState, len(s.crlStates)),
		crlDocuments:               make(map[domain.CRLDocumentID]port.CRLDocument, len(s.crlDocuments)),
		transitions:                make(map[domain.TransitionID]domain.Transition, len(s.transitions)),
		impacts:                    make(map[impactKey]domain.TransitionImpact, len(s.impacts)),
		deploymentConfirmations:    append([]domain.DeploymentConfirmation(nil), s.deploymentConfirmations...),
		tlsVersions:                make(map[domain.TLSVersionID]domain.TLSVersion, len(s.tlsVersions)),
		tlsChanges:                 make(map[domain.TLSVersionID]domain.TLSChange, len(s.tlsChanges)),
		requestResults:             make(map[port.OperationRequestKey]port.OperationRequestResult, len(s.requestResults)),
		secrets:                    make(map[secretKey]domain.EncryptedSecret, len(s.secrets)),
		verifierSet:                s.verifierSet,
		verifier:                   s.verifier,
		jobs:                       make(map[domain.JobID]port.Job, len(s.jobs)),
		jobByDedup:                 make(map[string]domain.JobID, len(s.jobByDedup)),
		maintenanceRuns:            make(map[domain.JobID]port.MaintenanceRun, len(s.maintenanceRuns)),
		maintenanceCRLRequirements: make(map[maintenanceRequirementKey]port.MaintenanceCRLRequirement, len(s.maintenanceCRLRequirements)),
		auditEvents:                append([]auditRow(nil), s.auditEvents...),
		importBatches:              make(map[domain.ImportBatchID]port.ImportBatch, len(s.importBatches)),
		takeovers:                  make(map[domain.TakeoverID]port.Takeover, len(s.takeovers)),
		pendingTakeover:            make(map[domain.CAKeyGenerationID]domain.TakeoverID, len(s.pendingTakeover)),
	}
	for k, v := range s.accounts {
		n.accounts[k] = v
	}
	for k, v := range s.sessions {
		n.sessions[k] = v
	}
	for k, v := range s.sessionsByHash {
		n.sessionsByHash[k] = v
	}
	for k, v := range s.resetTokens {
		n.resetTokens[k] = v
	}
	for k, v := range s.resetTokensByHash {
		n.resetTokensByHash[k] = v
	}
	for k, v := range s.rateLimits {
		n.rateLimits[k] = v
	}
	for k, v := range s.keyMaterials {
		n.keyMaterials[k] = v
	}
	for k, v := range s.keyMaterialsBySPKI {
		n.keyMaterialsBySPKI[k] = v
	}
	for k, v := range s.caKeyGenerations {
		n.caKeyGenerations[k] = v
	}
	for k, v := range s.authorities {
		n.authorities[k] = v
	}
	for k, v := range s.certificates {
		n.certificates[k] = v
	}
	for k, v := range s.certificatesByDER {
		n.certificatesByDER[k] = v
	}
	for k, v := range s.leafCertRecords {
		n.leafCertRecords[k] = cloneLeafCertificateRecord(v)
	}
	for k, v := range s.caCertRecords {
		n.caCertRecords[k] = v
	}
	for k, v := range s.series {
		n.series[k] = v
	}
	for k, v := range s.leafKeyGenerations {
		n.leafKeyGenerations[k] = v
	}
	for k, v := range s.deliveries {
		n.deliveries[k] = v
	}
	for k, v := range s.grants {
		n.grants[k] = v
	}
	for k, v := range s.grantsByHash {
		n.grantsByHash[k] = v
	}
	for k, v := range s.revocations {
		n.revocations[k] = v
	}
	for k, v := range s.revocationRevisions {
		n.revocationRevisions[k] = v
	}
	for k, v := range s.crlStates {
		n.crlStates[k] = v
	}
	for k, v := range s.crlDocuments {
		n.crlDocuments[k] = v
	}
	for k, v := range s.transitions {
		n.transitions[k] = v
	}
	for k, v := range s.impacts {
		n.impacts[k] = v
	}
	for k, v := range s.tlsVersions {
		n.tlsVersions[k] = v
	}
	for k, v := range s.tlsChanges {
		n.tlsChanges[k] = v
	}
	for k, v := range s.requestResults {
		n.requestResults[k] = v
	}
	for k, v := range s.secrets {
		n.secrets[k] = v
	}
	for k, v := range s.jobs {
		n.jobs[k] = v
	}
	for k, v := range s.jobByDedup {
		n.jobByDedup[k] = v
	}
	for k, v := range s.maintenanceRuns {
		n.maintenanceRuns[k] = cloneMaintenanceRun(v)
	}
	for k, v := range s.maintenanceCRLRequirements {
		n.maintenanceCRLRequirements[k] = v
	}
	for k, v := range s.importBatches {
		n.importBatches[k] = v
	}
	for k, v := range s.takeovers {
		n.takeovers[k] = v
	}
	for k, v := range s.pendingTakeover {
		n.pendingTakeover[k] = v
	}
	return n
}

// Store is the port.UnitOfWork/port.ReadStore test double described in the
// package doc.
type Store struct {
	writeMu sync.Mutex
	root    atomic.Pointer[state]
}

// NewStore returns an empty store.
func NewStore() *Store {
	s := &Store{}
	s.root.Store(newState())
	return s
}

var (
	_ port.UnitOfWork = (*Store)(nil)
	_ port.ReadStore  = (*Store)(nil)
)

// Write implements port.UnitOfWork. See the package doc's "Design" section
// for the copy-on-write/rollback mechanics.
func (s *Store) Write(_ context.Context, fn func(port.TxStores) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	cur := s.root.Load()
	working := cur.clone()
	tx := &txStores{s: working}

	err := runCallback(fn, tx)
	if err != nil {
		// working is simply discarded: cur, the published snapshot, was
		// never touched, so every change the callback made -- across all
		// twelve repositories -- is rolled back by construction.
		return err
	}
	s.root.Store(working)
	return nil
}

// Read implements port.ReadStore. It clones the published snapshot exactly
// like Write, but never publishes the result under any outcome: a read is
// preparation input only, and cloning also means it can never observe an
// in-flight Write's uncommitted working copy (clause 6/isolation), only
// whatever was last published.
func (s *Store) Read(_ context.Context, fn func(port.TxStores) error) error {
	cur := s.root.Load()
	working := cur.clone()
	tx := &txStores{s: working}
	return fn(tx)
}

// runCallback invokes fn and lets a panic propagate to the caller after
// this frame's defers (here, none besides Go's own unwind) have run --
// UnitOfWork's contract requires the panic to still reach runtime error
// handling (clause 3). Because working is a private, unpublished clone,
// there is no explicit "undo" step to perform before repanicking: simply
// not calling s.root.Store is the rollback.
func runCallback(fn func(port.TxStores) error, tx port.TxStores) error {
	return fn(tx)
}
