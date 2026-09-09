// Package migrations embeds SQL artifacts. The production runner must separately
// enforce locking, checksums and crash recovery.
package migrations

import "embed"

// Files contains the initial, unreleased schema. 000 bootstraps the runner journal.
//
//go:embed */*.sql manifest.json
var Files embed.FS
