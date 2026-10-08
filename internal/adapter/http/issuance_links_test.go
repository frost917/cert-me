package httpadapter

import (
	"testing"

	"cert-me/internal/app/contract"
	"cert-me/internal/domain"
)

func TestIssuanceResponseLinksToProtectedResources(t *testing.T) {
	response := toIssuanceResponse(contract.IssuanceView{
		SeriesID: domain.SeriesID(httpTestSeriesID), CertificateID: domain.CertificateID(httpTestCertificateID),
	})
	if response.CertificateURL != "/api/v1/certificates/"+httpTestCertificateID || response.SeriesURL != "/api/v1/leaf-series/"+httpTestSeriesID {
		t.Fatalf("resource links = %q %q", response.CertificateURL, response.SeriesURL)
	}
}
