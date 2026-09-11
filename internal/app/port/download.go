package port

import (
	"context"
	"io"

	"cert-me/internal/domain"
)

// FileDescriptor is the response-shaping metadata DistributionService.Deliver
// hands a DownloadSink -- never the payload itself
// (docs/backend-implementation.md §7 "FileDescriptor는 ContentType, 안전하게
// 생성한 Filename, Size만 가진다").
type FileDescriptor struct {
	ContentType string
	Filename    string
	Size        int64
}

// TransferOutcome is the sink's own observation of what actually left the
// server, recorded after Send returns
// (docs/backend-implementation.md §7 "TransferOutcome은 BytesWritten,
// FinishedAt, Completed를 가진다").
type TransferOutcome struct {
	BytesWritten int64
	FinishedAt   domain.Instant
	Completed    bool
}

// DownloadSink writes one prepared payload to the client
// (docs/backend-implementation.md §7). Deliver only calls Send after its
// consuming transaction has committed, and never for the commit's losing
// side of a concurrent request. Send owns writing response headers (with
// the fixed no-store/no-referrer policy), writing the full body and
// observing whatever flush result it can, and must not retain r or hand it
// to another goroutine: r's validity ends when Send returns, matching the
// same non-retention rule secret.Input.Use documents for its callback
// (docs/backend-implementation.md §7 "sink는 Reader를 보관·다른 goroutine으로
// 전달하지 않으며 Send 반환 전에 사용을 종료한다").
type DownloadSink interface {
	Send(ctx context.Context, descriptor FileDescriptor, r io.Reader) (TransferOutcome, error)
}
