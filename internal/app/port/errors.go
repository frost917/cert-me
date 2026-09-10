package port

import "errors"

// ErrNotFound is returned by a repository lookup that found no row. It is a
// plain storage-layer signal, not a policy decision: services translate a
// missing row into whatever contract.AppError kind the calling method
// requires (usually validation or conflict), the same way every other
// repository error is mapped. Declaring one shared sentinel here keeps every
// implementation (SQL dialect, in-memory test double) reporting "no such
// row" the same way instead of each inventing its own not-found value.
var ErrNotFound = errors.New("port: not found")
