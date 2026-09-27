// Package cryptoengine contains the concrete at-rest key engine.
package cryptoengine

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"cert-me/internal/secret"
)

const encryptionKeySize = 32

var (
	errKeyRingClosed            = errors.New("cryptoengine: key ring is closed")
	errGenerationKeyUnavailable = errors.New("cryptoengine: encryption generation key is unavailable")
)

// KeyRing owns copies of the configured AES-256 keys. The Input values remain
// caller-owned and are never retained by the ring.
type KeyRing struct {
	mu                 sync.RWMutex
	activeGenerationID string
	keys               map[string][]byte
	closed             bool
}

// NewKeyRing copies each 32-byte key from inputs. The active generation must
// be represented in inputs. Callers retain ownership of, and should close,
// their Input values after this function returns.
func NewKeyRing(activeGenerationID string, inputs map[string]*secret.Input) (*KeyRing, error) {
	if !validGenerationID(activeGenerationID) {
		return nil, errors.New("cryptoengine: active generation id is invalid")
	}
	if len(inputs) == 0 {
		return nil, errors.New("cryptoengine: at least one generation key is required")
	}

	keys := make(map[string][]byte, len(inputs))
	cleanup := func() {
		for _, key := range keys {
			zero(key)
		}
	}
	for generationID, input := range inputs {
		if !validGenerationID(generationID) {
			cleanup()
			return nil, errors.New("cryptoengine: generation id is invalid")
		}
		if input == nil {
			cleanup()
			return nil, errors.New("cryptoengine: generation key is unavailable")
		}
		key := make([]byte, encryptionKeySize)
		err := input.Use(func(value []byte) error {
			if len(value) != encryptionKeySize {
				return errors.New("cryptoengine: generation key must be 32 bytes")
			}
			copy(key, value)
			return nil
		})
		if err != nil {
			zero(key)
			cleanup()
			return nil, err
		}
		keys[generationID] = key
	}
	if _, ok := keys[activeGenerationID]; !ok {
		cleanup()
		return nil, errors.New("cryptoengine: active generation key is unavailable")
	}
	return &KeyRing{activeGenerationID: activeGenerationID, keys: keys}, nil
}

// Close zeroes every owned key copy and makes the ring unusable. It is safe to
// call more than once and waits for in-flight key use to finish.
func (r *KeyRing) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	for generationID, key := range r.keys {
		zero(key)
		delete(r.keys, generationID)
	}
	r.keys = nil
	return nil
}

func (r *KeyRing) withActiveKey(fn func(generationID string, key []byte) error) error {
	if r == nil {
		return errKeyRingClosed
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return errKeyRingClosed
	}
	key, ok := r.keys[r.activeGenerationID]
	if !ok {
		return errGenerationKeyUnavailable
	}
	return fn(r.activeGenerationID, key)
}

func (r *KeyRing) withGenerationKeys(source, target string, fn func(sourceKey, targetKey []byte) error) error {
	if r == nil {
		return errKeyRingClosed
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return errKeyRingClosed
	}
	sourceKey, ok := r.keys[source]
	if !ok {
		return errGenerationKeyUnavailable
	}
	targetKey, ok := r.keys[target]
	if !ok {
		return errGenerationKeyUnavailable
	}
	return fn(sourceKey, targetKey)
}

func validGenerationID(id string) bool {
	return id != "" && strings.TrimSpace(id) == id
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func (r *KeyRing) String() string {
	if r == nil {
		return "KeyRing<nil>"
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	state := "open"
	if r.closed {
		state = "closed"
	}
	return fmt.Sprintf("KeyRing{generations:%d state:%s}", len(r.keys), state)
}
