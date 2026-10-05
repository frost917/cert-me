package contract

import (
	"encoding/json"
	"testing"
)

func validSettingsInitializeCommand() SettingsInitializeCommand {
	serviceURL := "https://explicit.example.test"
	leafValidity := ValidityInput{Value: 2, Unit: "years"}
	rootValidity := ValidityInput{Value: 20, Unit: "years"}
	intermediateValidity := ValidityInput{Value: 8, Unit: "years"}
	rotateEvery := 4
	privateDeliverySeconds := 7200
	publicLinkSeconds := 900
	crlIntervalSeconds := 3600
	crlValiditySeconds := 7200
	auditRetentionDays := 180
	return SettingsInitializeCommand{
		ServiceURL:             &serviceURL,
		LeafValidity:           &leafValidity,
		RootValidity:           &rootValidity,
		IntermediateValidity:   &intermediateValidity,
		RotateEvery:            &rotateEvery,
		PrivateDeliverySeconds: &privateDeliverySeconds,
		PublicLinkSeconds:      &publicLinkSeconds,
		CRLIntervalSeconds:     &crlIntervalSeconds,
		CRLValiditySeconds:     &crlValiditySeconds,
		AuditRetentionDays:     &auditRetentionDays,
	}
}

func TestSettingsInitializeCommandValidateRequiresEverySnapshotField(t *testing.T) {
	tests := []struct {
		name  string
		clear func(*SettingsInitializeCommand)
	}{
		{"service_url", func(c *SettingsInitializeCommand) { c.ServiceURL = nil }},
		{"leaf_validity", func(c *SettingsInitializeCommand) { c.LeafValidity = nil }},
		{"root_validity", func(c *SettingsInitializeCommand) { c.RootValidity = nil }},
		{"intermediate_validity", func(c *SettingsInitializeCommand) { c.IntermediateValidity = nil }},
		{"rotate_every", func(c *SettingsInitializeCommand) { c.RotateEvery = nil }},
		{"private_delivery_seconds", func(c *SettingsInitializeCommand) { c.PrivateDeliverySeconds = nil }},
		{"public_link_seconds", func(c *SettingsInitializeCommand) { c.PublicLinkSeconds = nil }},
		{"crl_interval_seconds", func(c *SettingsInitializeCommand) { c.CRLIntervalSeconds = nil }},
		{"crl_validity_seconds", func(c *SettingsInitializeCommand) { c.CRLValiditySeconds = nil }},
		{"audit_retention_days", func(c *SettingsInitializeCommand) { c.AuditRetentionDays = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := validSettingsInitializeCommand()
			tc.clear(&cmd)
			if err := cmd.Validate(); err == nil {
				t.Fatalf("Validate accepted a snapshot missing %s", tc.name)
			}
		})
	}
}

func TestSettingsInitializeCommandValidateChecksSnapshotValuesAndCRLRelationship(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SettingsInitializeCommand)
	}{
		{"service_url", func(c *SettingsInitializeCommand) { v := "http://invalid.example.test"; c.ServiceURL = &v }},
		{"validity", func(c *SettingsInitializeCommand) { v := ValidityInput{Value: 0, Unit: "years"}; c.LeafValidity = &v }},
		{"rotate_every", func(c *SettingsInitializeCommand) { v := 101; c.RotateEvery = &v }},
		{"private_delivery_seconds", func(c *SettingsInitializeCommand) { v := 299; c.PrivateDeliverySeconds = &v }},
		{"public_link_seconds", func(c *SettingsInitializeCommand) { v := 59; c.PublicLinkSeconds = &v }},
		{"crl_interval_seconds", func(c *SettingsInitializeCommand) { v := 299; c.CRLIntervalSeconds = &v }},
		{"crl_validity_seconds", func(c *SettingsInitializeCommand) { v := 599; c.CRLValiditySeconds = &v }},
		{"crl_validity_less_than_twice_interval", func(c *SettingsInitializeCommand) { v := 7199; c.CRLValiditySeconds = &v }},
		{"audit_retention_days", func(c *SettingsInitializeCommand) { v := 29; c.AuditRetentionDays = &v }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := validSettingsInitializeCommand()
			tc.mutate(&cmd)
			if err := cmd.Validate(); err == nil {
				t.Fatalf("Validate accepted invalid %s", tc.name)
			}
		})
	}
}

func TestSettingsInitializeCommandDecodesAnExplicitFullSettingsSnapshot(t *testing.T) {
	const body = `{"service_url":"https://explicit.example.test","leaf_validity":{"value":2,"unit":"years"},"root_validity":{"value":20,"unit":"years"},"intermediate_validity":{"value":8,"unit":"years"},"rotate_every":4,"private_delivery_seconds":7200,"public_link_seconds":900,"crl_interval_seconds":3600,"crl_validity_seconds":7200,"audit_retention_days":180}`
	var cmd SettingsInitializeCommand
	if err := json.Unmarshal([]byte(body), &cmd); err != nil {
		t.Fatalf("decode initialize body: %v", err)
	}
	if err := cmd.Validate(); err != nil {
		t.Fatalf("Validate decoded snapshot: %v", err)
	}
	encoded, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("encode initialize command: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode encoded command: %v", err)
	}
	want := []string{
		"service_url", "leaf_validity", "root_validity", "intermediate_validity", "rotate_every",
		"private_delivery_seconds", "public_link_seconds", "crl_interval_seconds", "crl_validity_seconds", "audit_retention_days",
	}
	if len(fields) != len(want) {
		t.Fatalf("encoded fields = %d, want all %d settings fields", len(fields), len(want))
	}
	for _, key := range want {
		if _, ok := fields[key]; !ok {
			t.Errorf("encoded snapshot is missing %q", key)
		}
	}
}
