package contract

import (
	"testing"

	"cert-me/internal/domain"
)

func TestPublicCACertificateQueryValidatesCertificateUUID(t *testing.T) {
	tests := []struct {
		name          string
		certificateID string
		wantErr       bool
	}{
		{name: "canonical UUID", certificateID: "00000000-0000-4000-8000-000000000011"},
		{name: "empty", wantErr: true},
		{name: "malformed", certificateID: "not-a-uuid", wantErr: true},
		{name: "trailing data", certificateID: "00000000-0000-4000-8000-000000000011-extra", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (PublicCACertificateQuery{
				CertificateID: domain.CertificateID(tt.certificateID),
			}).Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
