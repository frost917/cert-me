package pki

import (
	"fmt"

	"cert-me/internal/domain"
)

const LeafCertificatePolicySnapshotSchemaVersion = 1

// LeafCertificatePolicySnapshotJSONV1 mirrors the versioned historical
// policy snapshot stored on each leaf certificate.
type LeafCertificatePolicySnapshotJSONV1 struct {
	SchemaVersion int                              `json:"schema_version"`
	Profile       string                           `json:"profile"`
	SANs          []LeafCertificatePolicySANJSONV1 `json:"sans,omitempty"`
	Validity      ValidityPolicyValueV1            `json:"validity"`
	RotateEvery   int                              `json:"rotate_every"`
}

type LeafCertificatePolicySANJSONV1 struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func DecodeLeafCertificatePolicySnapshotV1(raw []byte) (LeafCertificatePolicySnapshotJSONV1, error) {
	var snapshot LeafCertificatePolicySnapshotJSONV1
	if err := decodeJSONStrict(raw, &snapshot); err != nil {
		return LeafCertificatePolicySnapshotJSONV1{}, fmt.Errorf("invalid leaf certificate policy snapshot JSON: %w", err)
	}
	if snapshot.SchemaVersion != LeafCertificatePolicySnapshotSchemaVersion {
		return LeafCertificatePolicySnapshotJSONV1{}, fmt.Errorf("unsupported leaf certificate policy snapshot schema version %d", snapshot.SchemaVersion)
	}
	profile := domain.CertificateProfile(snapshot.Profile)
	if err := profile.Validate(); err != nil {
		return LeafCertificatePolicySnapshotJSONV1{}, err
	}
	if snapshot.RotateEvery < 1 || snapshot.RotateEvery > 100 {
		return LeafCertificatePolicySnapshotJSONV1{}, fmt.Errorf("invalid leaf policy snapshot rotate_every")
	}
	if _, err := domain.NewCalendarValidity(snapshot.Validity.Value, domain.ValidityUnit(snapshot.Validity.Unit)); err != nil {
		return LeafCertificatePolicySnapshotJSONV1{}, fmt.Errorf("invalid leaf policy snapshot validity: %w", err)
	}
	sans := make([]domain.SAN, len(snapshot.SANs))
	for i, stored := range snapshot.SANs {
		san, err := newStoredSAN(domain.SANType(stored.Type), stored.Value)
		if err != nil {
			return LeafCertificatePolicySnapshotJSONV1{}, fmt.Errorf("invalid leaf policy snapshot SAN: %w", err)
		}
		if san.Value() != stored.Value {
			return LeafCertificatePolicySnapshotJSONV1{}, fmt.Errorf("leaf policy snapshot SAN is not normalized")
		}
		if stored.Type == string(domain.SANTypeDNS) && stored.Value == "cert-me" && profile != domain.CertificateProfileServerTLS {
			return LeafCertificatePolicySnapshotJSONV1{}, fmt.Errorf("bootstrap-only SAN requires the server TLS profile")
		}
		sans[i] = san
	}
	if err := domain.ValidateSANsForProfile(profile, sans); err != nil {
		return LeafCertificatePolicySnapshotJSONV1{}, err
	}
	return snapshot, nil
}
