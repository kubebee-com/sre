package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/kubebee-com/sre/pkg/identity"
)

// LoginChallenge is consumed atomically before exchanging an OAuth code.
type LoginChallenge struct {
	Verifier  string
	Nonce     string
	ExpiresAt time.Time
}

type BrowserSession struct {
	Principal identity.Principal
	CSRF      string
}

// Only hashes of bearer session IDs and login state are retained in storage.
func authKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *Store) CreateLoginChallenge(ctx context.Context, key string, c LoginChallenge) error {
	if key == "" || c.Verifier == "" || c.Nonce == "" || !c.ExpiresAt.After(time.Now()) {
		return ErrInvalid
	}
	return s.createAuthRecord(ctx, "login_challenges", func(ctx context.Context, tx authExecutor) error {
		_, err := tx.Exec(ctx, `INSERT INTO enterprise_core.login_challenges(key_hash,verifier,nonce,expires_at) VALUES($1,$2,$3,$4)`, authKey(key), c.Verifier, c.Nonce, c.ExpiresAt)
		return err
	})
}
func (s *Store) ConsumeLoginChallenge(ctx context.Context, key string) (LoginChallenge, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var c LoginChallenge
	err := s.pool.QueryRow(ctx, `DELETE FROM enterprise_core.login_challenges WHERE key_hash=$1 RETURNING verifier,nonce,expires_at`, authKey(key)).Scan(&c.Verifier, &c.Nonce, &c.ExpiresAt)
	if err != nil {
		return LoginChallenge{}, safeError(err)
	}
	if !c.ExpiresAt.After(time.Now()) {
		return LoginChallenge{}, ErrNotFound
	}
	return c, nil
}
func (s *Store) CreateBrowserSession(ctx context.Context, key string, b BrowserSession) error {
	if key == "" || b.CSRF == "" || !b.Principal.Valid(time.Now()) {
		return ErrInvalid
	}
	return s.createAuthRecord(ctx, "browser_sessions", func(ctx context.Context, tx authExecutor) error {
		p := b.Principal
		expires := p.ExpiresAt
		if max := p.IssuedAt.Add(identity.MaxIdentityAge); max.Before(expires) {
			expires = max
		}
		groups := p.Groups
		if groups == nil {
			groups = []string{}
		}
		_, err := tx.Exec(ctx, `INSERT INTO enterprise_core.browser_sessions(key_hash,principal_id,issuer,groups,issued_at,expires_at,csrf) VALUES($1,$2,$3,$4,$5,$6,$7)`, authKey(key), p.ID, p.Issuer, groups, p.IssuedAt, expires, b.CSRF)
		return err
	})
}
func (s *Store) BrowserSession(ctx context.Context, key string) (BrowserSession, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var b BrowserSession
	err := s.pool.QueryRow(ctx, `SELECT principal_id,issuer,groups,issued_at,expires_at,csrf FROM enterprise_core.browser_sessions WHERE key_hash=$1 AND expires_at>clock_timestamp()`, authKey(key)).Scan(&b.Principal.ID, &b.Principal.Issuer, &b.Principal.Groups, &b.Principal.IssuedAt, &b.Principal.ExpiresAt, &b.CSRF)
	if err != nil {
		return BrowserSession{}, safeError(err)
	}
	if !b.Principal.Valid(time.Now()) {
		return BrowserSession{}, ErrNotFound
	}
	return b, nil
}
func (s *Store) DeleteBrowserSession(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	_, err := s.pool.Exec(ctx, `DELETE FROM enterprise_core.browser_sessions WHERE key_hash=$1`, authKey(key))
	return safeError(err)
}
