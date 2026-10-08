package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLeafSeriesRenameChangesOnlyNameAndBumpsVersion(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 4))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	name := "updated leaf"
	renamed, err := series.Rename(name)
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if renamed.Name() != name || renamed.Version() != series.Version().Next() {
		t.Fatalf("renamed series name/version = %q/%d, want %q/%d", renamed.Name(), renamed.Version(), name, series.Version().Next())
	}
	if renamed.ID() != series.ID() || renamed.Policy() != series.Policy() || renamed.CurrentCertificateID() != series.CurrentCertificateID() ||
		renamed.CurrentKeyGenerationID() != series.CurrentKeyGenerationID() || renamed.ManagementAuthorityID() != series.ManagementAuthorityID() {
		t.Fatal("Rename changed series history or policy")
	}

	unchanged, err := renamed.Rename(name)
	if err != nil {
		t.Fatalf("Rename(same name): %v", err)
	}
	if unchanged.Version() != renamed.Version() {
		t.Fatalf("same-name no-op advanced version from %d to %d", renamed.Version(), unchanged.Version())
	}
}

func TestLeafSeriesRenameValidatesNameAndArchiveState(t *testing.T) {
	series, err := NewLeafSeries(baseSeriesFacts(t, 3))
	if err != nil {
		t.Fatalf("NewLeafSeries: %v", err)
	}
	for _, name := range []string{"", strings.Repeat("x", maxSeriesNameLength+1)} {
		if _, err := series.Rename(name); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Rename(%d characters) error = %v, want ErrInvalidValue", len(name), err)
		}
	}
	archived, err := series.Archive(NewInstant(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if _, err := archived.Rename("archived rename"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Rename(archived) error = %v, want ErrInvalidTransition", err)
	}
}
