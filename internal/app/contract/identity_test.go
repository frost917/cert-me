package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"cert-me/internal/domain"
	"cert-me/internal/secret"
)

func validLoginCommand() IdentityLoginCommand {
	return IdentityLoginCommand{LoginName: "admin", Password: secret.FromString("a-valid-password-12")}
}

func TestIdentityLoginCommand_Validate_RejectsMissingRequired(t *testing.T) {
	valid := validLoginCommand()
	defer valid.Password.Close()

	cases := map[string]IdentityLoginCommand{
		"missing login_name": {LoginName: "", Password: valid.Password},
		"missing password":   {LoginName: "admin", Password: nil},
		"short password":     {LoginName: "admin", Password: secret.FromString("short")},
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

// TestIdentityLoginCommand_JSONCannotSetSecret is the malformed-input half of
// the JSON decode guarantee: a body that tries to set Password directly is
// rejected outright by DisallowUnknownFields, since the field carries no
// json tag at all.
func TestIdentityLoginCommand_JSONCannotSetSecret(t *testing.T) {
	body := []byte(`{"login_name":"admin","Password":"hunter2hunter2"}`)
	var cmd IdentityLoginCommand
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected decode to reject the secret field")
	}
}

func TestIdentityLoginCommand_SecretBlockedFromJSONAndLog(t *testing.T) {
	const plaintext = "another-secret-password-1"
	cmd := IdentityLoginCommand{LoginName: "admin", Password: secret.FromString(plaintext)}
	defer cmd.Password.Close()

	out, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("unexpected error marshalling command: %v", err)
	}
	if bytes.Contains(out, []byte(plaintext)) {
		t.Fatalf("plaintext leaked into json: %s", out)
	}
	if _, err := json.Marshal(cmd.Password); err == nil {
		t.Fatal("expected marshalling the secret field itself to fail")
	}
	if rendered := fmt.Sprintf("%v", cmd); bytes.Contains([]byte(rendered), []byte(plaintext)) {
		t.Fatalf("plaintext leaked into %%v: %s", rendered)
	}
}

// TestIdentityBeginResetCommand_Validate_RejectsMalformedID is the B02
// "잘못된 ID... 거부" criterion for the one command in this file that carries
// a target id.
func TestIdentityBeginResetCommand_Validate_RejectsMalformedID(t *testing.T) {
	cases := []string{"", "not-a-uuid", "00000000-0000-0000-0000-00000000000", "00000000-0000-0000-0000-0000000000zz"}
	for _, raw := range cases {
		cmd := IdentityBeginResetCommand{AccountID: domain.AccountID(raw)}
		if err := cmd.Validate(); err == nil {
			t.Fatalf("expected malformed account id %q to be rejected", raw)
		}
	}
}

func TestIdentityBeginResetCommand_JSONCannotSetAccountID(t *testing.T) {
	body := []byte(`{"AccountID":"00000000-0000-4000-8000-000000000001"}`)
	var cmd IdentityBeginResetCommand
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected decode to reject setting the server-filled account id")
	}
	if cmd.AccountID != "" {
		t.Fatal("account id must not have been populated from the body")
	}
}

func TestIdentityCompleteResetCommand_Validate_RejectsMissingRequired(t *testing.T) {
	validToken := secret.FromString("a-valid-reset-token-of-sufficient-length")
	defer validToken.Close()
	validPassword := secret.FromString("a-valid-password-12")
	defer validPassword.Close()

	cases := map[string]IdentityCompleteResetCommand{
		"missing reset_token":  {ResetToken: nil, NewPassword: validPassword},
		"missing new_password": {ResetToken: validToken, NewPassword: nil},
		"short reset_token":    {ResetToken: secret.FromString("short"), NewPassword: validPassword},
		"short new_password":   {ResetToken: validToken, NewPassword: secret.FromString("short")},
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestIdentityCompleteResetCommand_HasNoJSONTaggedFields(t *testing.T) {
	// Both PasswordReset fields are writeOnly secrets, so this command must
	// decode zero fields from JSON no matter what a body contains -- proving
	// there is no path by which either secret is set except the adapter
	// constructing the command directly.
	body := []byte(`{"reset_token":"x","new_password":"y"}`)
	var cmd IdentityCompleteResetCommand
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected decode to reject fields with no json tag on this command")
	}
	if cmd.ResetToken != nil || cmd.NewPassword != nil {
		t.Fatal("secrets must not have been populated from the body")
	}
}

func TestIdentityCompleteResetCommand_SecretBlockedFromJSONAndLog(t *testing.T) {
	const tokenPlaintext = "reset-token-plaintext-value-123456"
	const passwordPlaintext = "brand-new-password-value-12"
	cmd := IdentityCompleteResetCommand{
		ResetToken:  secret.FromString(tokenPlaintext),
		NewPassword: secret.FromString(passwordPlaintext),
	}
	defer secret.CloseAll(cmd.ResetToken, cmd.NewPassword)

	out, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("unexpected error marshalling command: %v", err)
	}
	if bytes.Contains(out, []byte(tokenPlaintext)) || bytes.Contains(out, []byte(passwordPlaintext)) {
		t.Fatalf("plaintext leaked into json: %s", out)
	}
	if _, err := json.Marshal(cmd.ResetToken); err == nil {
		t.Fatal("expected marshalling reset_token secret to fail")
	}
	if _, err := json.Marshal(cmd.NewPassword); err == nil {
		t.Fatal("expected marshalling new_password secret to fail")
	}
	rendered := fmt.Sprintf("%v", cmd)
	if bytes.Contains([]byte(rendered), []byte(tokenPlaintext)) || bytes.Contains([]byte(rendered), []byte(passwordPlaintext)) {
		t.Fatalf("plaintext leaked into %%v: %s", rendered)
	}
}

func TestIdentityAuthenticateCommand_Validate(t *testing.T) {
	if err := (IdentityAuthenticateCommand{SessionToken: nil}).Validate(); err == nil {
		t.Fatal("expected missing token to be rejected")
	}
	tooShort := secret.FromString("short")
	defer tooShort.Close()
	if err := (IdentityAuthenticateCommand{SessionToken: tooShort}).Validate(); err == nil {
		t.Fatal("expected too-short token to be rejected")
	}
	ok := secret.FromString("a-token-of-at-least-thirty-two-characters")
	defer ok.Close()
	if err := (IdentityAuthenticateCommand{SessionToken: ok}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
