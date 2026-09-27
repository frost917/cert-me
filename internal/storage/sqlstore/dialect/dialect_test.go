package dialect

import (
	"reflect"
	"testing"

	"cert-me/internal/config"
)

func TestPlaceholderAndBuilderArgumentOrder(t *testing.T) {
	tests := []struct {
		kind        config.DatabaseKind
		first, last string
	}{
		{kind: config.SQLite, first: "?", last: "?"},
		{kind: config.Postgres, first: "$1", last: "$3"},
		{kind: config.MySQL, first: "?", last: "?"},
		{kind: config.MariaDB, first: "?", last: "?"},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			d, err := New(test.kind)
			if err != nil {
				t.Fatal(err)
			}
			b := d.NewBuilder()
			if got := b.Add("account"); got != test.first {
				t.Fatalf("first placeholder = %q, want %q", got, test.first)
			}
			_ = b.Add(int64(7))
			if got := b.Add(true); got != test.last {
				t.Fatalf("last placeholder = %q, want %q", got, test.last)
			}
			if got, want := b.Args(), []any{"account", int64(7), true}; !reflect.DeepEqual(got, want) {
				t.Fatalf("Args() = %#v, want %#v", got, want)
			}
			got := b.Args()
			got[0] = "mutated"
			if b.Args()[0] != "account" {
				t.Fatal("Args() exposed the builder's internal slice")
			}
		})
	}
}

func TestNewRejectsUnknownDialect(t *testing.T) {
	if _, err := New("oracle"); err == nil {
		t.Fatal("New accepted an unsupported dialect")
	}
}
