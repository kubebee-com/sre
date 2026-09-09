package orchestrator

import (
	"context"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"time"
)

// AuthStore holds shared browser authority. Production servers use PostgreSQL.
type AuthStore interface {
	CreateLoginChallenge(context.Context, string, postgres.LoginChallenge) error
	ConsumeLoginChallenge(context.Context, string) (postgres.LoginChallenge, error)
	CreateBrowserSession(context.Context, string, postgres.BrowserSession) error
	BrowserSession(context.Context, string) (postgres.BrowserSession, error)
	DeleteBrowserSession(context.Context, string) error
}

// memoryAuthStore supports isolated HTTP tests without a database.
type memoryAuthStore struct{ server *Server }

func (m memoryAuthStore) CreateLoginChallenge(_ context.Context, key string, c postgres.LoginChallenge) error {
	s := m.server
	s.authMu.Lock()
	defer s.authMu.Unlock()
	s.pruneAuth(time.Now())
	if len(s.challenges) >= 1000 {
		return postgres.ErrAuthCapacity
	}
	s.challenges[key] = challenge{verifier: c.Verifier, nonce: c.Nonce, expires: c.ExpiresAt}
	return nil
}
func (m memoryAuthStore) ConsumeLoginChallenge(_ context.Context, key string) (postgres.LoginChallenge, error) {
	s := m.server
	s.authMu.Lock()
	defer s.authMu.Unlock()
	c, ok := s.challenges[key]
	delete(s.challenges, key)
	if !ok || !c.expires.After(time.Now()) {
		return postgres.LoginChallenge{}, postgres.ErrNotFound
	}
	return postgres.LoginChallenge{Verifier: c.verifier, Nonce: c.nonce, ExpiresAt: c.expires}, nil
}
func (m memoryAuthStore) CreateBrowserSession(_ context.Context, key string, b postgres.BrowserSession) error {
	s := m.server
	s.authMu.Lock()
	defer s.authMu.Unlock()
	s.pruneAuth(time.Now())
	if !b.Principal.Valid(time.Now()) {
		return postgres.ErrInvalid
	}
	if len(s.sessions) >= 1000 {
		return postgres.ErrAuthCapacity
	}
	s.sessions[key] = browserSession{principal: b.Principal, csrf: b.CSRF}
	return nil
}
func (m memoryAuthStore) BrowserSession(_ context.Context, key string) (postgres.BrowserSession, error) {
	s := m.server
	s.authMu.Lock()
	defer s.authMu.Unlock()
	s.pruneAuth(time.Now())
	b, ok := s.sessions[key]
	if !ok {
		return postgres.BrowserSession{}, postgres.ErrNotFound
	}
	return postgres.BrowserSession{Principal: b.principal, CSRF: b.csrf}, nil
}
func (m memoryAuthStore) DeleteBrowserSession(_ context.Context, key string) error {
	s := m.server
	s.authMu.Lock()
	defer s.authMu.Unlock()
	delete(s.sessions, key)
	return nil
}
