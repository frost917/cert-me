package domain

import (
	"errors"
	"testing"
	"time"
)

func TestLeafSeriesArchivePreservesHistoryAndAdvancesVersion(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 4))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	series, err = NewLeafSeries(LeafSeriesFacts{
		ID:                     series.ID(),
		Name:                   series.Name(),
		Purpose:                series.Purpose(),
		ManagementAuthorityID:  series.ManagementAuthorityID(),
		CurrentCertificateID:   CertificateID("99999999-9999-4999-8999-999999999999"),
		CurrentKeyGenerationID: series.CurrentKeyGenerationID(),
		Policy:                 series.Policy(),
		Version:                series.Version(),
	})
	if err != nil {
		t.Fatalf("seed historical series: %v", err)
	}
	archivedAt := NewInstant(time.Date(2026, 10, 5, 1, 2, 3, 0, time.UTC))

	archived, err := series.Archive(archivedAt)
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if !archived.IsArchived() || !archived.ArchivedAt().Equal(archivedAt) {
		t.Fatalf("archive timestamp = %v, want %v", archived.ArchivedAt(), archivedAt)
	}
	if archived.Version() != series.Version().Next() {
		t.Fatalf("version = %d, want %d", archived.Version(), series.Version().Next())
	}
	if archived.ID() != series.ID() || archived.CurrentCertificateID() != series.CurrentCertificateID() ||
		archived.CurrentKeyGenerationID() != series.CurrentKeyGenerationID() || archived.Policy() != series.Policy() {
		t.Fatal("archiving changed the series identity, certificate history, key generation, or policy")
	}
}

func TestLeafSeriesArchiveRejectsZeroTimeAndAlreadyArchived(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	if _, err := series.Archive(Instant{}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("Archive(zero) error = %v, want ErrInvalidValue", err)
	}

	archivedAt := NewInstant(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))
	archived, err := series.Archive(archivedAt)
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if _, err := archived.Archive(archivedAt.Add(NewDuration(time.Second))); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Archive(already archived) error = %v, want ErrInvalidTransition", err)
	}
}
