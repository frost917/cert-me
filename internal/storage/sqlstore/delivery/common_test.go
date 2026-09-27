package delivery

import (
	"strings"
	"testing"
)

func TestNewUUIDReturnsCanonicalLowercaseUUID(t *testing.T) {
	value, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 36 {
		t.Fatalf("UUID length = %d, want 36", len(value))
	}
	for _, index := range []int{8, 13, 18, 23} {
		if value[index] != '-' {
			t.Fatalf("UUID separator at %d = %q", index, value[index])
		}
	}
	if strings.ToLower(value) != value {
		t.Fatalf("UUID is not lowercase: %q", value)
	}
}

func TestIsDuplicateRecognizesCommonDriverMessages(t *testing.T) {
	for _, message := range []string{
		"UNIQUE constraint failed: operation_requests.actor_key",
		"duplicate entry 'x' for key 'download_tokens.token_hash'",
		"duplicate key value violates unique constraint",
	} {
		if !isDuplicate(testSQLError(message)) {
			t.Errorf("isDuplicate(%q) = false", message)
		}
	}
	if isDuplicate(testSQLError("connection reset")) {
		t.Fatal("isDuplicate classified a non-constraint error")
	}
}

type testSQLError string

func (e testSQLError) Error() string { return string(e) }
