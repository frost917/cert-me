package revocation

import (
	"testing"

	"cert-me/internal/domain"
)

func TestRevocationReasonDatabaseMappingRoundTrips(t *testing.T) {
	reasons := []domain.RevocationReason{
		domain.RevocationReasonUnspecified,
		domain.RevocationReasonKeyCompromise,
		domain.RevocationReasonCACompromise,
		domain.RevocationReasonAffiliationChanged,
		domain.RevocationReasonSuperseded,
		domain.RevocationReasonCessationOfOperation,
		domain.RevocationReasonPrivilegeWithdrawn,
		domain.RevocationReasonAACompromise,
	}
	for _, reason := range reasons {
		t.Run(string(reason), func(t *testing.T) {
			stored, err := revocationReasonToDB(reason)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := revocationReasonFromDB(stored)
			if err != nil {
				t.Fatal(err)
			}
			if decoded != reason {
				t.Fatalf("reason round trip = %q, want %q", decoded, reason)
			}
		})
	}
}

func TestCRLNumberStorageAndComparisonRemainArbitraryPrecision(t *testing.T) {
	if got := crlNumberForStorage(domain.CRLNumber{}); got != "0" {
		t.Fatalf("empty zero CRL number encoded as %q, want 0", got)
	}
	large, err := domain.ParseCRLNumber("100000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	larger, err := domain.ParseCRLNumber("100000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if large.Compare(larger) >= 0 || larger.Compare(large) <= 0 {
		t.Fatal("large CRL numbers were not compared numerically")
	}
}

func TestMonotonicStateRejectsRegressions(t *testing.T) {
	issuer, err := domain.ParseCAKeyGenerationID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	previous := newTestState(t, issuer, "20", 4, domain.PublicationStateActive)
	closed := newTestState(t, issuer, "20", 4, domain.PublicationStateClosed)
	regressions := map[string]struct {
		previous domain.CRLState
		next     domain.CRLState
	}{
		"reserved number": {previous, newTestState(t, issuer, "1f", 4, domain.PublicationStateActive)},
		"generation":      {previous, newTestState(t, issuer, "20", 3, domain.PublicationStateActive)},
		"generation jump": {previous, newTestState(t, issuer, "20", 6, domain.PublicationStateActive)},
		"closed state":    {closed, newTestState(t, issuer, "20", 4, domain.PublicationStateActive)},
	}
	for name, test := range regressions {
		t.Run(name, func(t *testing.T) {
			if err := monotonicState(test.previous, test.next); err == nil {
				t.Fatal("monotonicState accepted a regressive state")
			}
		})
	}
	valid := newTestState(t, issuer, "21", 5, domain.PublicationStateActive)
	if err := monotonicState(previous, valid); err != nil {
		t.Fatalf("monotonicState rejected one generation and a higher reservation: %v", err)
	}
}

func newTestState(t *testing.T, issuer domain.CAKeyGenerationID, maxNumber string, generation int64, publication domain.PublicationState) domain.CRLState {
	t.Helper()
	number, err := domain.ParseCRLNumber(maxNumber)
	if err != nil {
		t.Fatal(err)
	}
	state, err := domain.NewCRLState(domain.CRLStateFacts{
		CAKeyGenerationID: issuer, MaxReservedNumber: number,
		RevocationGeneration: generation, PublicationState: publication,
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}
