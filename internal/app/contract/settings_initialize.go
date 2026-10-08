package contract

// SettingsInitializeCommand is the JSON decode target for the full initial
// Settings snapshot. Pointers preserve the difference between an omitted or
// null required field and an explicitly supplied zero value.
type SettingsInitializeCommand struct {
	ServiceURL             *string        `json:"service_url,omitempty"`
	LeafValidity           *ValidityInput `json:"leaf_validity,omitempty"`
	RootValidity           *ValidityInput `json:"root_validity,omitempty"`
	IntermediateValidity   *ValidityInput `json:"intermediate_validity,omitempty"`
	RotateEvery            *int           `json:"rotate_every,omitempty"`
	PrivateDeliverySeconds *int           `json:"private_delivery_seconds,omitempty"`
	PublicLinkSeconds      *int           `json:"public_link_seconds,omitempty"`
	CRLIntervalSeconds     *int           `json:"crl_interval_seconds,omitempty"`
	CRLValiditySeconds     *int           `json:"crl_validity_seconds,omitempty"`
	AuditRetentionDays     *int           `json:"audit_retention_days,omitempty"`
}

// Validate requires the complete explicit snapshot, then applies the same
// field and cross-field rules as SettingsUpdateCommand.
func (c SettingsInitializeCommand) Validate() error {
	for _, field := range []struct {
		name    string
		missing bool
	}{
		{"service_url", c.ServiceURL == nil},
		{"leaf_validity", c.LeafValidity == nil},
		{"root_validity", c.RootValidity == nil},
		{"intermediate_validity", c.IntermediateValidity == nil},
		{"rotate_every", c.RotateEvery == nil},
		{"private_delivery_seconds", c.PrivateDeliverySeconds == nil},
		{"public_link_seconds", c.PublicLinkSeconds == nil},
		{"crl_interval_seconds", c.CRLIntervalSeconds == nil},
		{"crl_validity_seconds", c.CRLValiditySeconds == nil},
		{"audit_retention_days", c.AuditRetentionDays == nil},
	} {
		if field.missing {
			return NewAppError(ErrorKindValidation, "missing_settings_field", "all settings fields are required").WithField("field", field.name)
		}
	}
	return c.updateCommand().Validate()
}

func (c SettingsInitializeCommand) updateCommand() SettingsUpdateCommand {
	return SettingsUpdateCommand{
		ServiceURL:             c.ServiceURL,
		LeafValidity:           c.LeafValidity,
		RootValidity:           c.RootValidity,
		IntermediateValidity:   c.IntermediateValidity,
		RotateEvery:            c.RotateEvery,
		PrivateDeliverySeconds: c.PrivateDeliverySeconds,
		PublicLinkSeconds:      c.PublicLinkSeconds,
		CRLIntervalSeconds:     c.CRLIntervalSeconds,
		CRLValiditySeconds:     c.CRLValiditySeconds,
		AuditRetentionDays:     c.AuditRetentionDays,
	}
}
