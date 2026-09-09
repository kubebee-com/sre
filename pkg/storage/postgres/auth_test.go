package postgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/identity"
)

func TestSharedBrowserAuthPersistence(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	a, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	key := identity.NewID()
	if err = a.CreateLoginChallenge(ctx, key, LoginChallenge{Verifier: "pkce", Nonce: "nonce", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := b.ConsumeLoginChallenge(ctx, key)
			if e == nil {
				if c.Verifier != "pkce" || c.Nonce != "nonce" {
					t.Error("challenge corrupted")
				}
				wins.Add(1)
			} else if !errors.Is(e, ErrNotFound) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("challenge consumed %d times", wins.Load())
	}
	session := BrowserSession{Principal: identity.Principal{ID: "engineer", Issuer: "https://idp", Groups: []string{"admins"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, CSRF: "csrf"}
	if err = a.CreateBrowserSession(ctx, key, session); err != nil {
		t.Fatal(err)
	}
	got, err := b.BrowserSession(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Principal.ID != "engineer" || len(got.Principal.Groups) != 1 || got.Principal.Groups[0] != "admins" || got.CSRF != "csrf" {
		t.Fatalf("session lost identity or CSRF: %+v", got)
	}
	if err = b.DeleteBrowserSession(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err = a.BrowserSession(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("logout: %v", err)
	}
	session.Principal.ExpiresAt = time.Now().Add(-time.Second)
	if err = a.CreateBrowserSession(ctx, key, session); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired session accepted: %v", err)
	}
	if err = a.CreateLoginChallenge(ctx, key, LoginChallenge{Verifier: "pkce", Nonce: "nonce", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.pool.Exec(ctx, `UPDATE enterprise_core.login_challenges SET expires_at=clock_timestamp()-interval '1 second' WHERE key_hash=$1`, authKey(key)); err != nil {
		t.Fatal(err)
	}
	if _, err = b.ConsumeLoginChallenge(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired challenge accepted: %v", err)
	}
}
