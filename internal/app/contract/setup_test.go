package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"cert-me/internal/secret"
)

func TestSetupCreateAdminCommand_Validate_RejectsMissingRequired(t *testing.T) {
	pw := secret.FromString("a-valid-password-12")
	defer pw.Close()
	cases := []struct {
		name string
		cmd  SetupCreateAdminCommand
	}{
		{"missing login_name", SetupCreateAdminCommand{LoginName: "", Password: pw}},
		{"missing password", SetupCreateAdminCommand{LoginName: "admin", Password: nil}},
		{"login_name too short", SetupCreateAdminCommand{LoginName: "ab", Password: pw}},
		{"login_name bad char", SetupCreateAdminCommand{LoginName: "ad min!", Password: pw}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cmd.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSetupCreateAdminCommand_Validate_RejectsShortPassword(t *testing.T) {
	pw := secret.FromString("short")
	defer pw.Close()
	cmd := SetupCreateAdminCommand{LoginName: "admin", Password: pw}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected password length error")
	}
}

// TestSetupCreateAdminCommand_Validate_CountsCharactersNotBytes is F3:
// OpenAPI minLength/maxLength on a JSON string counts characters, not bytes.
// "안녕하세요" is 5 Korean characters but 15 UTF-8 bytes, so a byte-counting
// check wrongly accepts it as satisfying a 12-character minimum.
func TestSetupCreateAdminCommand_Validate_CountsCharactersNotBytes(t *testing.T) {
	pw := secret.FromString("안녕하세요") // 5 runes, 15 bytes
	defer pw.Close()
	if pw.Len() < 12 {
		t.Fatalf("test fixture assumption broken: byte length must be >= 12, got %d", pw.Len())
	}
	cmd := SetupCreateAdminCommand{LoginName: "admin", Password: pw}
	if err := cmd.Validate(); err == nil {
		t.Fatal("expected a 5-character password to be rejected even though it is 15 bytes")
	}
}

func TestSetupCreateAdminCommand_Validate_Accepts(t *testing.T) {
	pw := secret.FromString("a-valid-password-12")
	defer pw.Close()
	cmd := SetupCreateAdminCommand{LoginName: "admin", Password: pw}
	if err := cmd.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSetupCreateAdminCommand_JSONCannotSetSecret proves that a body cannot
// smuggle a plaintext password into the command through the JSON field that
// carries it. Password is tagged json:"-", so DisallowUnknownFields rejects
// any body that names it, and there is no way to set it from JSON at all.
func TestSetupCreateAdminCommand_JSONCannotSetSecret(t *testing.T) {
	body := []byte(`{"login_name":"admin","Password":{"buf":"hunter2hunter2"}}`)
	var cmd SetupCreateAdminCommand
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err == nil {
		t.Fatal("expected decode to reject an attempt to set the secret field")
	}
	if cmd.Password != nil {
		t.Fatal("password must not have been populated")
	}
}

// TestSetupCreateAdminCommand_SecretBlockedFromJSONAndLog is the B02 "비밀
// JSON/로그 차단" criterion: marshalling a command holding a secret must fail,
// and even if it did not, the rendered output must never contain the
// plaintext.
func TestSetupCreateAdminCommand_SecretBlockedFromJSONAndLog(t *testing.T) {
	const plaintext = "super-secret-password-value"
	pw := secret.FromString(plaintext)
	defer pw.Close()
	cmd := SetupCreateAdminCommand{LoginName: "admin", Password: pw}

	// Password is tagged json:"-", so the encoder skips it entirely rather
	// than erroring; that omission is itself the protection. The field is
	// still individually unmarshalable, which is what a handler that tried
	// to bypass the tag (e.g. by marshalling cmd.Password on its own) would
	// hit.
	out, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("unexpected error marshalling the surrounding command: %v", err)
	}
	if bytes.Contains(out, []byte(plaintext)) {
		t.Fatalf("plaintext leaked into json output: %s", out)
	}
	if _, err := json.Marshal(cmd.Password); err == nil {
		t.Fatal("expected json.Marshal of the secret field itself to fail")
	}

	rendered := fmt.Sprintf("%v", cmd)
	if bytes.Contains([]byte(rendered), []byte(plaintext)) {
		t.Fatalf("plaintext leaked into %%v output: %s", rendered)
	}
}

func TestSetupStage_Validate(t *testing.T) {
	valid := []SetupStage{SetupStageAccountRequired, SetupStagePKIRequired, SetupStageComplete}
	for _, s := range valid {
		if err := s.Validate(); err != nil {
			t.Fatalf("expected %q to be valid: %v", s, err)
		}
	}
	if err := SetupStage("bogus").Validate(); err == nil {
		t.Fatal("expected an unsupported stage to be rejected")
	}
}
