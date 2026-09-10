package contract

import "testing"

func intPtr(v int) *int       { return &v }
func strPtr(v string) *string { return &v }

func TestSettingsUpdateCommand_Validate_RejectsEmptyPatch(t *testing.T) {
	if err := (SettingsUpdateCommand{}).Validate(); err == nil {
		t.Fatal("expected an empty patch to be rejected (minProperties: 1)")
	}
}

func TestSettingsUpdateCommand_Validate_EachFieldBound(t *testing.T) {
	cases := map[string]SettingsUpdateCommand{
		"bad service_url":           {ServiceURL: strPtr("http://not-https.example")},
		"rotate_every too low":      {RotateEvery: intPtr(0)},
		"rotate_every too high":     {RotateEvery: intPtr(101)},
		"private_delivery too low":  {PrivateDeliverySeconds: intPtr(299)},
		"private_delivery too high": {PrivateDeliverySeconds: intPtr(86401)},
		"public_link too low":       {PublicLinkSeconds: intPtr(59)},
		"public_link too high":      {PublicLinkSeconds: intPtr(10801)},
		"crl_interval too low":      {CRLIntervalSeconds: intPtr(299)},
		"crl_interval too high":     {CRLIntervalSeconds: intPtr(86401)},
		"crl_validity too low":      {CRLValiditySeconds: intPtr(599)},
		"crl_validity too high":     {CRLValiditySeconds: intPtr(604801)},
		"audit_retention too low":   {AuditRetentionDays: intPtr(29)},
		"audit_retention too high":  {AuditRetentionDays: intPtr(3651)},
		"bad leaf_validity":         {LeafValidity: &ValidityInput{Value: 0, Unit: "years"}},
		"bad leaf_validity unit":    {LeafValidity: &ValidityInput{Value: 1, Unit: "fortnights"}},
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSettingsUpdateCommand_Validate_RejectsCRLValidityBelowTwiceInterval(t *testing.T) {
	cmd := SettingsUpdateCommand{
		CRLIntervalSeconds: intPtr(1000),
		CRLValiditySeconds: intPtr(1999),
	}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected crl_validity_seconds < 2x crl_interval_seconds to be rejected")
	}
}

func TestSettingsUpdateCommand_Validate_AcceptsOneField(t *testing.T) {
	cmd := SettingsUpdateCommand{RotateEvery: intPtr(5)}
	if err := cmd.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSettingsUpdateCommand_Validate_AcceptsCRLValidityAtExactlyTwiceInterval(t *testing.T) {
	cmd := SettingsUpdateCommand{
		CRLIntervalSeconds: intPtr(1000),
		CRLValiditySeconds: intPtr(2000),
	}
	if err := cmd.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
