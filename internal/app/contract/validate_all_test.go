package contract

import (
	"reflect"
	"strings"
	"testing"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

// validatable is every command type in this package: §3 requires each one to
// validate itself before a service acts on it.
type validatable interface{ Validate() error }

const (
	uuidA = "11111111-1111-4111-8111-111111111111"
	uuidB = "22222222-2222-4222-8222-222222222222"
	uuidC = "33333333-3333-4333-8333-333333333333"
)

func newSecret(t *testing.T, s string) *secret.Input {
	t.Helper()
	in := secret.FromString(s)
	t.Cleanup(func() { _ = in.Close() })
	return in
}

// validCommands returns one fully valid instance of every command type in the
// package. Adding a command without adding it here makes
// TestEveryCommandTypeIsCovered fail, so this registry cannot silently rot.
func validCommands(t *testing.T) map[string]validatable {
	t.Helper()
	password := func() *secret.Input { return newSecret(t, "a-long-enough-password") }
	token := func() *secret.Input { return newSecret(t, strings.Repeat("t", 43)) }
	subject := SubjectInput{CommonName: "leaf.example.internal"}
	sans := []SANInput{{Type: "dns", Value: "leaf.example.internal"}}

	return map[string]validatable{
		"SetupCreateAdminCommand":     SetupCreateAdminCommand{LoginName: "admin", Password: password()},
		"IdentityLoginCommand":        IdentityLoginCommand{LoginName: "admin", Password: password()},
		"IdentityLogoutCommand":       IdentityLogoutCommand{},
		"IdentityAuthenticateCommand": IdentityAuthenticateCommand{SessionToken: token()},
		"IdentityBeginResetCommand":   IdentityBeginResetCommand{AccountID: domain.AccountID(uuidA)},
		"IdentityCompleteResetCommand": IdentityCompleteResetCommand{
			ResetToken: token(), NewPassword: password(),
		},
		"IdentityIssueCSRFCommand":           IdentityIssueCSRFCommand{},
		"TLSReloadCommand":                   TLSReloadCommand{},
		"TLSBootstrapCommand":                TLSBootstrapCommand{},
		"TLSReconcileCommand":                TLSReconcileCommand{},
		"MaintenanceRecoverTransfersCommand": MaintenanceRecoverTransfersCommand{},
		"SetupCompleteCommand":               SetupCompleteCommand{},
		"SettingsGetCommand":                 SettingsGetCommand{},
		"SettingsUpdateCommand":              SettingsUpdateCommand{RotateEvery: intPtr(5)},

		"AuthorityCreateCommand": AuthorityCreateCommand{
			Kind: "root", Name: "Example Root", Subject: SubjectInput{CommonName: "Example Root"},
		},
		"AuthorityRenameCommand": AuthorityRenameCommand{
			AuthorityID: domain.AuthorityID(uuidA), Name: "Renamed",
		},
		"AuthoritySetIssuanceStateCommand": AuthoritySetIssuanceStateCommand{
			AuthorityID: domain.AuthorityID(uuidA), State: "stopped",
		},
		"AuthorityDestroyKeyCommand": AuthorityDestroyKeyCommand{
			AuthorityID:     domain.AuthorityID(uuidA),
			KeyGenerationID: domain.CAKeyGenerationID(uuidB),
			Justification:   "key destroyed after migration",
		},
		"AuthorityArchiveCommand": AuthorityArchiveCommand{AuthorityID: domain.AuthorityID(uuidA)},

		"IssuanceIssueCommand": IssuanceIssueCommand{
			Name: "web", AuthorityID: domain.AuthorityID(uuidA),
			Profile: "server_tls", Subject: subject, SANs: sans,
		},
		"IssuanceRenewCommand": IssuanceRenewCommand{
			SeriesID: domain.SeriesID(uuidA), SourceCertificateID: domain.CertificateID(uuidB),
		},
		"IssuanceReissueCommand": IssuanceReissueCommand{
			SeriesID: domain.SeriesID(uuidA), SourceCertificateID: domain.CertificateID(uuidB),
			Reason: ReissueReasonManualRotation,
		},
		"IssuanceUpdateSeriesCommand": IssuanceUpdateSeriesCommand{
			SeriesID: domain.SeriesID(uuidA), RotateEvery: intPtr(4),
		},
		"IssuanceArchiveSeriesCommand": IssuanceArchiveSeriesCommand{SeriesID: domain.SeriesID(uuidA)},

		"DistributionCreateLinkCommand": DistributionCreateLinkCommand{
			CertificateID: domain.CertificateID(uuidA), Purpose: DownloadPurposePrivate,
		},
		"DownloadCommand": DownloadCommand{RawToken: token(), Format: DownloadFormatPEM},
		"DistributionReportFailureCommand": DistributionReportFailureCommand{
			DeliveryID: domain.DeliveryID(uuidA), Justification: "storage failed on the operator side",
		},

		"RevocationRevokeCommand": RevocationRevokeCommand{
			CertificateID: domain.CertificateID(uuidA),
			Reason:        RevocationReasonInput("superseded"), Justification: "replaced",
		},
		"RevocationCompromiseCommand": RevocationCompromiseCommand{
			KeyMaterialID: domain.KeyMaterialID(uuidA), Justification: "key leaked",
		},
		"RevocationCorrectCommand": RevocationCorrectCommand{
			RevocationID: domain.RevocationID(uuidA), RevokedAt: "2026-01-02T03:04:05Z",
			Reason: RevocationReasonInput("keyCompromise"), Justification: "corrected reason",
		},

		"TransitionCreateCommand": TransitionCreateCommand{
			SourceAuthorityID: domain.AuthorityID(uuidA), Mode: TransitionModeInput("normal"),
			Reason: "planned rotation",
		},
		"TransitionSetTargetCommand": TransitionSetTargetCommand{
			TransitionID: domain.TransitionID(uuidA), TargetAuthorityID: domain.AuthorityID(uuidB),
		},
		"TransitionConfirmDeploymentCommand": TransitionConfirmDeploymentCommand{
			TransitionID: domain.TransitionID(uuidA), TargetLabel: "edge-1",
			Action: DeploymentActionInputTrustAdded,
		},
		"TransitionCompleteCommand": TransitionCompleteCommand{TransitionID: domain.TransitionID(uuidA)},

		"CRLRequestPublicationCommand": CRLRequestPublicationCommand{AuthorityID: domain.AuthorityID(uuidA)},
		"CRLPublishCommand": CRLPublishCommand{
			JobID: domain.JobID(uuidA), CAKeyGenerationID: domain.CAKeyGenerationID(uuidB),
		},

		"TLSUploadCandidateCommand": TLSUploadCandidateCommand{
			Certificate: []byte("cert"), Key: []byte("key"),
		},
		"TLSIssueCandidateCommand": TLSIssueCandidateCommand{
			AuthorityID: domain.AuthorityID(uuidA), Subject: subject, SANs: sans,
		},
		"TLSActivateCommand": TLSActivateCommand{CandidateID: domain.TLSVersionID(uuidA)},

		"ImportAttachSigningKeyCommand": ImportAttachSigningKeyCommand{
			AuthorityID: domain.AuthorityID(uuidA), Key: []byte("key-der"),
		},
		"ImportConfirmTakeoverCommand": ImportConfirmTakeoverCommand{
			TakeoverInput: TakeoverInput{
				CAKeyGenerationID:       domain.CAKeyGenerationID(uuidA),
				HistoryAssertion:        TakeoverHistoryNoPreviousRevocations,
				PreviousMaxNumberHex:    "0",
				ExternalIssuerStoppedAt: "2026-01-02T03:04:05Z",
				Evidence:                TakeoverEvidence{SchemaVersion: 1, IssuanceRecordsChecked: true, CRLRoutesChecked: true},
			},
		},
		"ImportUploadCommand": ImportUploadCommand{
			Files: []UploadedFile{{FileName: "root.pem", Data: []byte("pem")}},
			Metadata: ImportMetadataInput{
				SchemaVersion: 1,
				Files:         []ImportFileMetadataInput{{FileName: "root.pem", Kind: ImportFileKindCertificate}},
			},
		},

		"MaintenanceRotateCommand": MaintenanceRotateCommand{
			OldEncryptionGenerationID: "gen-1", NewEncryptionGenerationID: "gen-2",
		},
		"MaintenanceFinalizeRestoreCommand": MaintenanceFinalizeRestoreCommand{
			Options: MaintenanceFinalizeRestoreOptions{RunID: domain.JobID(uuidC)},
		},
		"MaintenancePruneAuditCommand": MaintenancePruneAuditCommand{
			Cutoff: domain.InstantFromUnixMicro(1_700_000_000_000_000),
		},
	}
}

// A valid command must produce an error interface that is genuinely nil.
//
// This is not the same assertion as "Validate did not fail". A helper that
// returns a concrete pointer type (*AppError) and is returned directly from an
// error-returning Validate yields a NON-NIL interface holding a nil pointer,
// which reports every valid command as invalid. That trap was hit during B02,
// so it is pinned here for every command at once rather than per file.
func TestValidCommandsReturnATrulyNilError(t *testing.T) {
	for name, cmd := range validCommands(t) {
		t.Run(name, func(t *testing.T) {
			err := cmd.Validate()
			if err == nil {
				return
			}
			if v := reflect.ValueOf(err); v.Kind() == reflect.Ptr && v.IsNil() {
				t.Fatalf("Validate returned a typed-nil pointer boxed in a non-nil error interface (type %T)", err)
			}
			t.Fatalf("a valid command was rejected: %v", err)
		})
	}
}

// Every command must reject its zero value. A command whose zero value passes
// validation would let a handler that forgot to populate it reach a service
// with an empty target id.
func TestZeroCommandsAreRejected(t *testing.T) {
	// These carry no client input at all: §3 lists them as explicit empty
	// commands, so an empty value is legitimately valid for them.
	fieldless := map[string]bool{
		"IdentityLogoutCommand":    true,
		"IdentityIssueCSRFCommand": true,
		"SetupCompleteCommand":     true,
		"SettingsGetCommand":       true,
		// Internal runtime/local commands that take no arguments at all
		// (§3: "인자 없는 명령도 명시적 빈 command를 사용한다").
		"TLSReloadCommand":                   true,
		"TLSBootstrapCommand":                true,
		"TLSReconcileCommand":                true,
		"MaintenanceRecoverTransfersCommand": true,
	}
	for name, cmd := range validCommands(t) {
		if fieldless[name] {
			continue
		}
		t.Run(name, func(t *testing.T) {
			zero := reflect.New(reflect.TypeOf(cmd)).Elem().Interface().(validatable)
			if err := zero.Validate(); err == nil {
				t.Fatal("the zero value of this command passed Validate")
			}
		})
	}
}

// The registry must cover every command type in the package. Counting against
// the Validate implementations found in the source keeps a newly added command
// from escaping both tests above.
func TestEveryCommandTypeIsCovered(t *testing.T) {
	declared := commandTypeNamesFromSource(t)
	covered := validCommands(t)
	for _, name := range declared {
		if _, ok := covered[name]; !ok {
			t.Errorf("command %s has a Validate method but is not in validCommands", name)
		}
	}
	for name := range covered {
		found := false
		for _, d := range declared {
			if d == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("validCommands lists %s, which no longer declares Validate", name)
		}
	}
}
