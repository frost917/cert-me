// Package porttest_test is a black-box contract test for porttest.Store's
// PKI repository: it only imports exported API from cert-me/internal/app/port
// and cert-me/internal/app/porttest, the same surface a B03 issuance service
// in another package would use. That is the point the reviewer's finding
// asked for -- a test living inside porttest could accidentally reach into
// package-private fields and paper over a gap the real service could not
// work around.
package porttest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/app/porttest"
	"cert-me/internal/domain"
)

const (
	authorityID  = domain.AuthorityID("11111111-1111-1111-1111-111111111111")
	caKeyMatID   = domain.KeyMaterialID("22222222-2222-2222-2222-222222222222")
	caGenID      = domain.CAKeyGenerationID("33333333-3333-3333-3333-333333333333")
	caCertID     = domain.CertificateID("44444444-4444-4444-4444-444444444444")
	seriesID     = domain.SeriesID("55555555-5555-5555-5555-555555555555")
	leafKeyMatID = domain.KeyMaterialID("66666666-6666-6666-6666-666666666666")
	leafGenID    = domain.LeafKeyGenerationID("77777777-7777-7777-7777-777777777777")
	leafCertID   = domain.CertificateID("88888888-8888-8888-8888-888888888888")

	rotatedKeyMatID = domain.KeyMaterialID("99999999-9999-9999-9999-999999999999")
	rotatedGenID    = domain.LeafKeyGenerationID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	renewedCertID   = domain.CertificateID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
)

func instant(t *testing.T, when time.Time) domain.Instant { t.Helper(); return domain.NewInstant(when) }

func window(t *testing.T, nb, na time.Time) domain.ValidityWindow {
	t.Helper()
	w, err := domain.NewValidityWindow(instant(t, nb), instant(t, na))
	if err != nil {
		t.Fatalf("NewValidityWindow: %v", err)
	}
	return w
}

func publicKey(t *testing.T, spki byte) domain.PublicKey {
	t.Helper()
	// A minimal, distinct SPKI byte string per key so each has its own
	// fingerprint -- the contract test only needs distinct identities, not
	// a real ASN.1 encoding.
	pk, err := domain.NewPublicKey(domain.KeyAlgorithmECDSAP256, []byte{spki, spki, spki})
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return pk
}

func subject(t *testing.T, cn string) domain.Subject {
	t.Helper()
	s, err := domain.NewSubject(domain.SubjectFacts{CommonName: cn})
	if err != nil {
		t.Fatalf("NewSubject: %v", err)
	}
	return s
}

func dnsSAN(t *testing.T, value string) domain.SAN {
	t.Helper()
	s, err := domain.NewSAN(domain.SANTypeDNS, value)
	if err != nil {
		t.Fatalf("NewSAN: %v", err)
	}
	return s
}

func serial(t *testing.T, hex string) domain.SerialNumber {
	t.Helper()
	s, err := domain.ParseSerialNumber(hex)
	if err != nil {
		t.Fatalf("ParseSerialNumber(%q): %v", hex, err)
	}
	return s
}

func calendarValidity(t *testing.T) domain.CalendarValidity {
	t.Helper()
	v, err := domain.NewCalendarValidity(1, domain.ValidityUnitYears)
	if err != nil {
		t.Fatalf("NewCalendarValidity: %v", err)
	}
	return v
}

func newLeafCertificate(t *testing.T, id domain.CertificateID, der byte, keyMaterialID domain.KeyMaterialID, serialHex string, w domain.ValidityWindow) domain.Certificate {
	t.Helper()
	c, err := domain.NewCertificate(domain.CertificateFacts{
		ID:                      id,
		DER:                     []byte{der, der, der},
		KeyMaterialID:           keyMaterialID,
		IssuerCAKeyGenerationID: caGenID,
		Serial:                  serial(t, serialHex),
		Validity:                w,
		Subject:                 subject(t, "leaf.example.internal"),
		SANs:                    []domain.SAN{dnsSAN(t, "leaf.example.internal")},
		Kind:                    domain.CertificateKindLeaf,
		Profile:                 domain.CertificateProfileServerTLS,
		KeyAlgorithm:            domain.KeyAlgorithmECDSAP256,
		Origin:                  domain.CertificateOriginGenerated,
		Version:                 1,
	})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	return c
}

// issueNewSeries drives "new issuance" end to end through TxStores alone:
// key material + CA key generation (pre-existing authority context) +
// certificate + series + leaf key generation, exactly the set the reviewer's
// finding named as unreachable before this fix.
func issueNewSeries(ctx context.Context, t *testing.T, tx port.TxStores) {
	t.Helper()
	pki := tx.PKI()

	if err := pki.InsertKeyMaterial(ctx, port.KeyMaterial{
		ID:        leafKeyMatID,
		PublicKey: publicKey(t, 0x01),
		Origin:    "generated",
	}); err != nil {
		t.Fatalf("InsertKeyMaterial: %v", err)
	}

	leafWindow := window(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	cert := newLeafCertificate(t, leafCertID, 0xC1, leafKeyMatID, "a1", leafWindow)
	if err := pki.InsertCertificate(ctx, cert); err != nil {
		t.Fatalf("InsertCertificate: %v", err)
	}

	gen, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
		ID:            leafGenID,
		SeriesID:      seriesID,
		KeyMaterialID: leafKeyMatID,
		GenerationNo:  1,
		RenewalCount:  0,
		Custody:       domain.KeyCustodyClientHeld,
	})
	if err != nil {
		t.Fatalf("NewLeafKeyGeneration: %v", err)
	}
	if err := pki.InsertLeafKeyGeneration(ctx, gen); err != nil {
		t.Fatalf("InsertLeafKeyGeneration: %v", err)
	}

	series, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
		ID:                     seriesID,
		Name:                   "web-frontend",
		Purpose:                domain.SeriesPurposeDistributed,
		ManagementAuthorityID:  authorityID,
		CurrentCertificateID:   leafCertID,
		CurrentKeyGenerationID: leafGenID,
		Policy: domain.SeriesPolicy{
			RotateEvery:         3,
			CertificateValidity: calendarValidity(t),
		},
		Version: 1,
	})
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	if err := pki.InsertSeries(ctx, series); err != nil {
		t.Fatalf("InsertSeries: %v", err)
	}
}

// TestPKIRepository_IssueRotateRenew_FailsBeforeTheFix is the exact
// reproduction the reviewer asked for: every one of these three assertions
// must fail against the pre-fix code (FindKeyBySPKI/GetSeriesForUpdate/
// GetCertificate all read maps nothing could ever write, and there was no
// GetCertificate at all). Run once BEFORE the fix and capture the output in
// the PR, then again after -- this file only reflects the after state, so
// the "before" run is the git-stashed baseline described in the PR report.
func TestPKIRepository_IssueRotateRenew(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()

	// 1. New issuance.
	if err := store.Write(ctx, func(tx port.TxStores) error {
		issueNewSeries(ctx, t, tx)
		return nil
	}); err != nil {
		t.Fatalf("issuance write: %v", err)
	}

	// Assertion 1: FindKeyBySPKI must find the key material just inserted.
	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.PKI().FindKeyBySPKI(ctx, publicKey(t, 0x01).Fingerprint())
		if err != nil {
			return err
		}
		if got.ID != leafKeyMatID {
			t.Fatalf("FindKeyBySPKI returned id %q, want %q", got.ID, leafKeyMatID)
		}
		return nil
	}); err != nil {
		t.Fatalf("FindKeyBySPKI: %v", err)
	}

	// Assertion 3 (checked here first, before rotation, since the source
	// certificate is the one just issued): GetCertificate must return the
	// stored certificate by id.
	if err := store.Read(ctx, func(tx port.TxStores) error {
		got, err := tx.PKI().GetCertificate(ctx, leafCertID)
		if err != nil {
			return err
		}
		if got.ID() != leafCertID {
			t.Fatalf("GetCertificate returned id %q, want %q", got.ID(), leafCertID)
		}
		return nil
	}); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	// 2. Key rotation: a new leaf key generation, series moves to it.
	if err := store.Write(ctx, func(tx port.TxStores) error {
		pki := tx.PKI()
		if err := pki.InsertKeyMaterial(ctx, port.KeyMaterial{
			ID:        rotatedKeyMatID,
			PublicKey: publicKey(t, 0x02),
			Origin:    "generated",
		}); err != nil {
			return err
		}
		rotatedGen, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
			ID:            rotatedGenID,
			SeriesID:      seriesID,
			KeyMaterialID: rotatedKeyMatID,
			GenerationNo:  2,
			RenewalCount:  0,
			Custody:       domain.KeyCustodyClientHeld,
		})
		if err != nil {
			return err
		}
		if err := pki.InsertLeafKeyGeneration(ctx, rotatedGen); err != nil {
			return err
		}

		snapshot, err := pki.GetSeriesForUpdate(ctx, seriesID)
		if err != nil {
			return err
		}
		updated, err := domain.NewLeafSeries(domain.LeafSeriesFacts{
			ID:                     snapshot.Series.ID(),
			Name:                   snapshot.Series.Name(),
			Purpose:                snapshot.Series.Purpose(),
			ManagementAuthorityID:  snapshot.Series.ManagementAuthorityID(),
			CurrentCertificateID:   snapshot.Series.CurrentCertificateID(),
			CurrentKeyGenerationID: rotatedGenID,
			Policy:                 snapshot.Series.Policy(),
			Version:                snapshot.Series.Version(),
		})
		if err != nil {
			return err
		}
		return pki.SaveSeries(ctx, updated, snapshot.Series.Version())
	}); err != nil {
		t.Fatalf("rotation write: %v", err)
	}

	// Assertion 2: GetSeriesForUpdate must return the series WITH its
	// current generation, and that generation must be the rotated one.
	if err := store.Read(ctx, func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, seriesID)
		if err != nil {
			return err
		}
		if snapshot.Series.CurrentKeyGenerationID() != rotatedGenID {
			t.Fatalf("series current generation = %q, want %q", snapshot.Series.CurrentKeyGenerationID(), rotatedGenID)
		}
		if snapshot.CurrentKeyGeneration.ID() != rotatedGenID {
			t.Fatalf("snapshot generation id = %q, want %q", snapshot.CurrentKeyGeneration.ID(), rotatedGenID)
		}
		if snapshot.CurrentKeyGeneration.KeyMaterialID() != rotatedKeyMatID {
			t.Fatalf("snapshot generation key material = %q, want %q", snapshot.CurrentKeyGeneration.KeyMaterialID(), rotatedKeyMatID)
		}
		return nil
	}); err != nil {
		t.Fatalf("GetSeriesForUpdate after rotation: %v", err)
	}

	// 3. Renewal on the same (rotated) key: series keeps its generation, the
	// generation's renewal_count advances via SaveLeafKeyGeneration, and a
	// new certificate is issued whose source is the rotated key's prior
	// certificate -- but here we only need to prove the generation survives
	// unchanged and the renewal_count save round-trips.
	if err := store.Write(ctx, func(tx port.TxStores) error {
		pki := tx.PKI()
		snapshot, err := pki.GetSeriesForUpdate(ctx, seriesID)
		if err != nil {
			return err
		}
		if snapshot.Series.CurrentKeyGenerationID() != rotatedGenID {
			t.Fatalf("renewal read stale generation %q, want %q", snapshot.Series.CurrentKeyGenerationID(), rotatedGenID)
		}

		bumped, err := domain.NewLeafKeyGeneration(domain.LeafKeyGenerationFacts{
			ID:            snapshot.CurrentKeyGeneration.ID(),
			SeriesID:      snapshot.CurrentKeyGeneration.SeriesID(),
			KeyMaterialID: snapshot.CurrentKeyGeneration.KeyMaterialID(),
			GenerationNo:  snapshot.CurrentKeyGeneration.GenerationNo(),
			RenewalCount:  snapshot.CurrentKeyGeneration.RenewalCount() + 1,
			Custody:       snapshot.CurrentKeyGeneration.Custody(),
		})
		if err != nil {
			return err
		}
		if err := pki.SaveLeafKeyGeneration(ctx, bumped); err != nil {
			return err
		}

		renewedWindow := window(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
		renewedCert := newLeafCertificate(t, renewedCertID, 0xC2, rotatedKeyMatID, "a2", renewedWindow)
		return pki.InsertCertificate(ctx, renewedCert)
	}); err != nil {
		t.Fatalf("renewal write: %v", err)
	}

	// The series must still point at the rotated generation after a renewal
	// that reused the key, and the generation's renewal_count must have
	// persisted.
	if err := store.Read(ctx, func(tx port.TxStores) error {
		snapshot, err := tx.PKI().GetSeriesForUpdate(ctx, seriesID)
		if err != nil {
			return err
		}
		if snapshot.Series.CurrentKeyGenerationID() != rotatedGenID {
			t.Fatalf("after renewal, series generation = %q, want unchanged %q", snapshot.Series.CurrentKeyGenerationID(), rotatedGenID)
		}
		if snapshot.CurrentKeyGeneration.RenewalCount() != 1 {
			t.Fatalf("after renewal, renewal_count = %d, want 1", snapshot.CurrentKeyGeneration.RenewalCount())
		}
		got, err := tx.PKI().GetCertificate(ctx, renewedCertID)
		if err != nil {
			return err
		}
		if got.KeyMaterialID() != rotatedKeyMatID {
			t.Fatalf("renewed certificate key material = %q, want %q", got.KeyMaterialID(), rotatedKeyMatID)
		}
		return nil
	}); err != nil {
		t.Fatalf("final read: %v", err)
	}
}

// TestPKIRepository_InsertKeyMaterial_RollsBackOnCallbackError proves the new
// write path participates in the same copy-on-write rollback every other
// repository already gets: a callback that inserts key material and then
// fails must leave FindKeyBySPKI reporting not-found, exactly like the
// existing TestWrite_CallbackErrorRollsBackEveryRepository in package
// porttest does for other repositories.
func TestPKIRepository_InsertKeyMaterial_RollsBackOnCallbackError(t *testing.T) {
	store := porttest.NewStore()
	ctx := context.Background()
	sentinel := errors.New("callback failed")

	pk := publicKey(t, 0x03)
	err := store.Write(ctx, func(tx port.TxStores) error {
		if err := tx.PKI().InsertKeyMaterial(ctx, port.KeyMaterial{
			ID:        domain.KeyMaterialID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
			PublicKey: pk,
			Origin:    "generated",
		}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the callback's error", err)
	}

	if err := store.Read(ctx, func(tx port.TxStores) error {
		if _, err := tx.PKI().FindKeyBySPKI(ctx, pk.Fingerprint()); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("key material survived rollback (err=%v)", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
}
