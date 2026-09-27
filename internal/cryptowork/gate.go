// Package cryptowork limits process-wide expensive cryptographic operations.
package cryptowork

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	maxConcurrent = 2
	maxWait       = 5 * time.Second
)

var slots = make(chan struct{}, maxConcurrent)

var ErrBusy = errors.New("cryptographic work admission timed out")

// Acquire admits one expensive cryptographic operation. It returns without
// starting background work when canceled or when the shared wait limit ends.
// The returned release function is idempotent.
func Acquire(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, errors.New("cryptowork: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-slots
			return nil, err
		}
		var once sync.Once
		return func() {
			once.Do(func() { <-slots })
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrBusy
	}
}

// TryAcquire admits one expensive operation only when a shared slot is
// available immediately. It is for KDFs whose contract forbids queueing.
func TryAcquire(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, errors.New("cryptowork: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-slots
			return nil, err
		}
		var once sync.Once
		return func() { once.Do(func() { <-slots }) }, nil
	default:
		return nil, ErrBusy
	}
}
