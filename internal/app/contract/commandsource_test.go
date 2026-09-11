package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// validateMethodRe matches a value-receiver Validate method declaration, which
// is the shape every command in this package uses.
var validateMethodRe = regexp.MustCompile(`(?m)^func \((?:\w+ )?\*?(\w+)\) Validate\(\) error \{`)

// commandTypeNamesFromSource scans this package's own .go files for types that
// declare Validate. Deriving the list from source rather than a hand-kept
// constant is what makes TestEveryCommandTypeIsCovered able to notice a
// command someone added without registering it.
func commandTypeNamesFromSource(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	seen := map[string]struct{}{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range validateMethodRe.FindAllStringSubmatch(string(raw), -1) {
			// Only command types are registered; the shared input and enum
			// types (SubjectInput, RevocationReasonInput, ...) validate
			// themselves as part of the command that embeds them.
			if strings.HasSuffix(m[1], "Command") {
				seen[m[1]] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no command types declaring Validate; the scan is broken")
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
