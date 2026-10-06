package httpadapter

import (
	"fmt"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

type leafSeriesResponse struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name"`
	Purpose              string           `json:"purpose"`
	ManagementAuthority  string           `json:"management_authority_id"`
	CurrentCertificateID *string          `json:"current_certificate_id,omitempty"`
	CurrentKeyGeneration *string          `json:"current_key_generation_id,omitempty"`
	Validity             validityResponse `json:"validity"`
	RotateEvery          int              `json:"rotate_every"`
	RenewalCount         int64            `json:"renewal_count"`
	PriorHistoryUnknown  bool             `json:"prior_history_unknown"`
	Delivery             *deliveryDTO     `json:"delivery"`
	ArchivedAt           *string          `json:"archived_at,omitempty"`
	Version              int64            `json:"version"`
	CreatedAt            string           `json:"created_at"`
}

type deliveryDTO struct {
	ID            string  `json:"id"`
	CertificateID string  `json:"certificate_id"`
	State         string  `json:"state"`
	ExpiresAt     string  `json:"expires_at"`
	ConsumedAt    *string `json:"consumed_at,omitempty"`
	FinishedAt    *string `json:"finished_at,omitempty"`
	FailureCode   *string `json:"failure_code,omitempty"`
	Version       int64   `json:"version"`
}

type subjectDTO struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
}

type sanDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type certificateResponse struct {
	ID                      string       `json:"id"`
	DERSHA256               string       `json:"der_sha256"`
	KeyMaterialID           string       `json:"key_material_id"`
	IssuerCAKeyGenerationID string       `json:"issuer_ca_key_generation_id"`
	SerialHex               string       `json:"serial_hex"`
	NotBefore               string       `json:"not_before"`
	NotAfter                string       `json:"not_after"`
	Subject                 subjectDTO   `json:"subject"`
	SANs                    []sanDTO     `json:"sans"`
	Origin                  string       `json:"origin"`
	SeriesID                *string      `json:"series_id,omitempty"`
	Revoked                 bool         `json:"revoked"`
	Affected                bool         `json:"affected"`
	Expired                 bool         `json:"expired"`
	Delivery                *deliveryDTO `json:"delivery"`
	CreatedAt               string       `json:"created_at"`
}

type issuanceResponse struct {
	SeriesID        string       `json:"series_id"`
	CertificateID   string       `json:"certificate_id"`
	KeyGenerationID string       `json:"key_generation_id"`
	RenewalCount    int64        `json:"renewal_count"`
	KeyRotated      bool         `json:"key_rotated"`
	Delivery        *deliveryDTO `json:"delivery"`
	CertificateURL  string       `json:"certificate_url,omitempty"`
	SeriesURL       string       `json:"series_url,omitempty"`
}

func toDeliveryDTO(view *contract.DeliveryView) *deliveryDTO {
	if view == nil {
		return nil
	}
	response := &deliveryDTO{
		ID:            string(view.ID),
		CertificateID: string(view.CertificateID),
		State:         string(view.State),
		ExpiresAt:     authorityInstant(view.ExpiresAt),
		Version:       view.Version.Int64(),
	}
	if view.ConsumedAt != nil {
		value := authorityInstant(*view.ConsumedAt)
		response.ConsumedAt = &value
	}
	if view.FinishedAt != nil {
		value := authorityInstant(*view.FinishedAt)
		response.FinishedAt = &value
	}
	if view.FailureCode != "" {
		value := view.FailureCode
		response.FailureCode = &value
	}
	return response
}

func toLeafSeriesResponse(view contract.LeafSeriesView) (leafSeriesResponse, error) {
	if view.CreatedAt.IsZero() {
		return leafSeriesResponse{}, fmt.Errorf("leaf series response is missing created_at")
	}
	response := leafSeriesResponse{
		ID:                  string(view.ID),
		Name:                view.Name,
		Purpose:             string(view.Purpose),
		ManagementAuthority: string(view.ManagementAuthorityID),
		Validity: validityResponse{
			Value: view.Validity.Value(),
			Unit:  string(view.Validity.Unit()),
		},
		RotateEvery:         view.RotateEvery,
		RenewalCount:        view.RenewalCount,
		PriorHistoryUnknown: view.PriorHistoryUnknown,
		Delivery:            toDeliveryDTO(view.Delivery),
		Version:             view.Version.Int64(),
		CreatedAt:           authorityInstant(view.CreatedAt),
	}
	if view.CurrentCertificateID != nil {
		value := string(*view.CurrentCertificateID)
		response.CurrentCertificateID = &value
	}
	if view.CurrentKeyGenerationID != nil {
		value := string(*view.CurrentKeyGenerationID)
		response.CurrentKeyGeneration = &value
	}
	if view.ArchivedAt != nil {
		value := authorityInstant(*view.ArchivedAt)
		response.ArchivedAt = &value
	}
	return response, nil
}

func toCertificateResponse(view contract.CertificateView) (certificateResponse, error) {
	if view.CreatedAt.IsZero() {
		return certificateResponse{}, fmt.Errorf("certificate response is missing created_at")
	}
	response := certificateResponse{
		ID:                      string(view.ID),
		DERSHA256:               view.DERSHA256.Hex(),
		KeyMaterialID:           string(view.KeyMaterialID),
		IssuerCAKeyGenerationID: string(view.IssuerCAKeyGenerationID),
		SerialHex:               view.Serial.Hex(),
		NotBefore:               authorityInstant(view.NotBefore),
		NotAfter:                authorityInstant(view.NotAfter),
		Subject: subjectDTO{
			CommonName:         view.Subject.CommonName,
			Organization:       view.Subject.Organization,
			OrganizationalUnit: view.Subject.OrganizationalUnit,
			Country:            view.Subject.Country,
		},
		Origin:    string(view.Origin),
		Revoked:   view.Revoked,
		Affected:  view.Affected,
		Expired:   view.Expired,
		Delivery:  toDeliveryDTO(view.Delivery),
		CreatedAt: authorityInstant(view.CreatedAt),
	}
	response.SANs = make([]sanDTO, 0, len(view.SANs))
	for _, value := range view.SANs {
		response.SANs = append(response.SANs, sanDTO{Type: value.Type, Value: value.Value})
	}
	if view.SeriesID != nil {
		value := string(*view.SeriesID)
		response.SeriesID = &value
	}
	return response, nil
}

func toIssuanceResponse(view contract.IssuanceView) issuanceResponse {
	certificateURL, seriesURL := view.CertificateURL, view.SeriesURL
	if certificateURL == "" && view.CertificateID != "" {
		certificateURL = "/api/v1/certificates/" + string(view.CertificateID)
	}
	if seriesURL == "" && view.SeriesID != "" {
		seriesURL = "/api/v1/leaf-series/" + string(view.SeriesID)
	}
	return issuanceResponse{
		SeriesID:        string(view.SeriesID),
		CertificateID:   string(view.CertificateID),
		KeyGenerationID: string(view.KeyGenerationID),
		RenewalCount:    view.RenewalCount,
		KeyRotated:      view.KeyRotated,
		Delivery:        toDeliveryDTO(view.Delivery),
		CertificateURL:  certificateURL,
		SeriesURL:       seriesURL,
	}
}

func leafSeriesID(raw string) (domain.SeriesID, error) { return domain.ParseSeriesID(raw) }
