package verifier

import (
	"context"
	"sync"
	"time"

	oid4vp "github.com/alanh-pyxical/go-oid4vp"
)

// MemorySessionStore is a thread-safe in-memory [SessionStore].
// Suitable for single-process deployments and tests. Replace with a
// persistent implementation (Redis, Postgres, etc.) in production.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]*VerificationSession
}

// NewMemorySessionStore creates a MemorySessionStore.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]*VerificationSession)}
}

// Save implements [SessionStore].
func (s *MemorySessionStore) Save(_ context.Context, session *VerificationSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.State] = session
	return nil
}

// Get implements [SessionStore].
func (s *MemorySessionStore) Get(_ context.Context, state string) (*VerificationSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[state]
	if !ok {
		return nil, oid4vp.ErrSessionNotFound
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, oid4vp.ErrSessionExpired
	}
	return sess, nil
}

// Complete implements [SessionStore].
func (s *MemorySessionStore) Complete(_ context.Context, state string, result *VerificationResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[state]
	if !ok {
		return oid4vp.ErrSessionNotFound
	}
	sess.Result = result
	return nil
}
