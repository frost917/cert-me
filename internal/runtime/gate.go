package runtime

import (
	"context"
	"sync"

	"cert-me/internal/app/port"
)

// Gate controls request and worker admission for one process. It starts
// closed and opens only after storage, TLS recovery, and listener preparation
// have completed.
type Gate struct {
	mu          sync.Mutex
	accepting   bool
	failed      bool
	failureCode string
	inFlight    int
	changed     chan struct{}
	stop        chan struct{}
	stopOnce    sync.Once
}

var _ port.RuntimeGate = (*Gate)(nil)

func NewGate() *Gate {
	return &Gate{
		changed: make(chan struct{}),
		stop:    make(chan struct{}),
	}
}

// OpenAdmission enables new work after startup recovery has finished.
func (g *Gate) OpenAdmission() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed {
		return false
	}
	g.accepting = true
	g.signalLocked()
	return true
}

// CloseAdmission atomically prevents new requests and worker jobs.
func (g *Gate) CloseAdmission() {
	g.mu.Lock()
	if g.accepting {
		g.accepting = false
		g.signalLocked()
	}
	g.mu.Unlock()
}

// Admit acquires one in-flight work slot. The returned release function is
// idempotent and must be called after the handler or job finishes.
func (g *Gate) Admit() (release func(), accepted bool) {
	g.mu.Lock()
	if !g.accepting || g.failed {
		g.mu.Unlock()
		return func() {}, false
	}
	g.inFlight++
	g.signalLocked()
	g.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.inFlight--
			g.signalLocked()
			g.mu.Unlock()
		})
	}, true
}

// WaitIdle waits until admitted work has released its slot or ctx is
// canceled. Call CloseAdmission first to prevent new work racing the drain.
func (g *Gate) WaitIdle(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	for {
		g.mu.Lock()
		if g.inFlight == 0 {
			g.mu.Unlock()
			return nil
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// FailClosed meets port.RuntimeGate's nonblocking contract. It closes new
// admissions before signaling the process supervisor and never waits for the
// caller's own request to finish.
func (g *Gate) FailClosed(code string) {
	g.mu.Lock()
	g.accepting = false
	g.failed = true
	g.failureCode = code
	g.signalLocked()
	g.mu.Unlock()
	g.stopOnce.Do(func() { close(g.stop) })
}

func (g *Gate) StopRequested() <-chan struct{} { return g.stop }

func (g *Gate) FailureCode() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failureCode
}

func (g *Gate) IsAccepting() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.accepting && !g.failed
}

func (g *Gate) Failed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failed
}

func (g *Gate) signalLocked() {
	close(g.changed)
	g.changed = make(chan struct{})
}
