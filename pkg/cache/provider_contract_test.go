package cache

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
)

func TestSemanticCacheKeyIncludesOperationWireRedactionAndEvidence(t *testing.T) {
	secret := "cache-key-secret"
	sanitizer.ConfigureDefaultRedactor(secret)
	t.Cleanup(func() { sanitizer.ConfigureDefaultRedactor() })
	key := NewSemanticCacheKey("diagnose", "codex", "model-"+secret, "https://provider.example/v1?token="+secret, "responses", "triage-v2", "", "", "prompt "+secret)
	if key.Operation != "diagnose" || key.WireAPI != "responses" || key.RedactionSchema == "" || key.EvidenceDigest == "" {
		t.Fatalf("semantic key omitted required identity: %#v", key)
	}
	canonical, err := key.Canonical()
	if err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}
	if strings.Contains(string(canonical), secret) {
		t.Fatalf("semantic key leaked secret: %s", canonical)
	}
	chat := NewSemanticCacheKey("diagnose", "codex", "model", "https://provider.example/v1", "chat", "triage-v2", sanitizer.RedactionSchema, "", "prompt")
	if key.Digest() == chat.Digest() {
		t.Fatal("chat and responses semantic keys collided")
	}
}

func TestRemoteCacheReturnsSafeBackendErrorAndHonorsCancellation(t *testing.T) {
	backendError := errors.New("driver token=backend-secret")
	store := &contractObjectStore{err: backendError}
	remote, err := NewRemoteCache(store, []byte("remote-cache-key"))
	if err != nil {
		t.Fatalf("NewRemoteCache() error = %v", err)
	}
	key := NewCacheKey("provider", "model", "endpoint", "schema", "prompt")
	if err := remote.Set(context.Background(), key, []byte("value")); !errors.Is(err, ErrCacheBackend) || strings.Contains(err.Error(), "backend-secret") {
		t.Fatalf("Set() error = %v, want safe typed backend error", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := remote.Get(ctx, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get() error = %v, want context cancellation", err)
	}
}

func TestFileCacheRedactsConfiguredLiteralBeforeReturningValue(t *testing.T) {
	secret := "file-cache-secret"
	sanitizer.ConfigureDefaultRedactor(secret)
	t.Cleanup(func() { sanitizer.ConfigureDefaultRedactor() })
	cache, err := NewFileCache(t.TempDir(), []byte("file-cache-key"))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	key := NewCacheKey("provider", "model", "endpoint", "schema", "prompt")
	if err := cache.Set(context.Background(), key, []byte(`{"message":"`+secret+`","safe":"ok"}`)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	value, err := cache.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if strings.Contains(string(value), secret) || !strings.Contains(string(value), "[REDACTED]") {
		t.Fatalf("cache value = %q, want redacted secret", value)
	}
}

type contractObjectStore struct {
	err error
}

func (s *contractObjectStore) Get(context.Context, string) ([]byte, error) { return nil, s.err }
func (s *contractObjectStore) Put(context.Context, string, []byte, time.Time) error {
	return s.err
}
func (s *contractObjectStore) Delete(context.Context, string) error { return s.err }
func (s *contractObjectStore) List(context.Context, string) ([]RemoteObject, error) {
	return nil, s.err
}
