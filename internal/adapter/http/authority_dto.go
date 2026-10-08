package httpadapter

import (
	"fmt"
	"time"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

type authorityResponse struct {
	ID                    string        `json:"id"`
	Kind                  string        `json:"kind"`
	Name                  string        `json:"name"`
	ManagementParentID    *string       `json:"management_parent_id,omitempty"`
	IssuanceState         string        `json:"issuance_state"`
	IssuanceCertificateID *string       `json:"issuance_certificate_id,omitempty"`
	KeyGenerationID       string        `json:"key_generation_id"`
	KeyAvailable          bool          `json:"key_available"`
	Affected              bool          `json:"affected"`
	NotAfter              *string       `json:"not_after,omitempty"`
	ArchivedAt            *string       `json:"archived_at,omitempty"`
	CRL                   *crlStatusDTO `json:"crl,omitempty"`
	Version               int64         `json:"version"`
	CreatedAt             string        `json:"created_at"`
}

type crlStatusDTO struct {
	NumberHex            *string `json:"number_hex,omitempty"`
	CoveredGeneration    *int64  `json:"covered_generation,omitempty"`
	RevocationGeneration int64   `json:"revocation_generation"`
	NextPublishAt        *string `json:"next_publish_at,omitempty"`
	NextUpdate           *string `json:"next_update,omitempty"`
	PublicationState     string  `json:"publication_state"`
	Pending              bool    `json:"pending"`
	Expired              bool    `json:"expired"`
	LastErrorCode        *string `json:"last_error_code,omitempty"`
	Version              int64   `json:"version"`
}

func toAuthorityResponse(view contract.AuthorityView) (authorityResponse, error) {
	if view.CreatedAt.IsZero() {
		return authorityResponse{}, fmt.Errorf("authority response is missing created_at")
	}
	response := authorityResponse{
		ID:              string(view.ID),
		Kind:            string(view.Kind),
		Name:            view.Name,
		IssuanceState:   string(view.IssuanceState),
		KeyGenerationID: string(view.KeyGenerationID),
		KeyAvailable:    view.KeyAvailable,
		Affected:        view.Affected,
		Version:         view.Version.Int64(),
		CreatedAt:       authorityInstant(view.CreatedAt),
	}
	if view.ManagementParentID != nil {
		value := string(*view.ManagementParentID)
		response.ManagementParentID = &value
	}
	if view.IssuanceCertificateID != nil {
		value := string(*view.IssuanceCertificateID)
		response.IssuanceCertificateID = &value
	}
	if !view.NotAfter.IsZero() {
		value := authorityInstant(view.NotAfter)
		response.NotAfter = &value
	}
	if view.ArchivedAt != nil {
		value := authorityInstant(*view.ArchivedAt)
		response.ArchivedAt = &value
	}
	if view.CRL != nil {
		response.CRL = toCRLStatusDTO(*view.CRL)
	}
	return response, nil
}

func toCRLStatusDTO(view contract.CRLStatusView) *crlStatusDTO {
	response := &crlStatusDTO{
		RevocationGeneration: view.RevocationGeneration,
		PublicationState:     string(view.PublicationState),
		Pending:              view.Pending,
		Expired:              view.Expired,
		Version:              view.Version.Int64(),
	}
	if view.Number != nil {
		value := view.Number.Hex()
		response.NumberHex = &value
	}
	if view.CoveredGeneration != nil {
		value := *view.CoveredGeneration
		response.CoveredGeneration = &value
	}
	if view.NextPublishAt != nil {
		value := authorityInstant(*view.NextPublishAt)
		response.NextPublishAt = &value
	}
	if view.NextUpdate != nil {
		value := authorityInstant(*view.NextUpdate)
		response.NextUpdate = &value
	}
	if view.LastErrorCode != "" {
		value := view.LastErrorCode
		response.LastErrorCode = &value
	}
	return response
}

func authorityInstant(value domain.Instant) string {
	return value.Time().UTC().Format(time.RFC3339Nano)
}
