package cache

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestRemoteCacheRoundTripIsEncryptedAndBounded(t *testing.T) {
	store := NewMemoryObjectStore()
	now := time.Now().UTC()
	remote, err := NewRemoteCache(store, []byte("remote-cache-key"),
		WithRemoteDefaultTTL(time.Hour),
		WithRemoteMaxEntries(2),
		WithRemoteMaxValueBytes(128),
		WithRemoteCacheClock(func() time.Time { return now }),
		WithRemotePrefix("tenant-a/cache"),
	)
	if err != nil {
		t.Fatalf("NewRemoteCache() error = %v", err)
	}
	key := NewCacheKey("openai", "model", "https://api.example/v1", "diagnosis-v1", "private prompt")
	value := []byte("private provider response")
	if err := remote.Set(context.Background(), key, value); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := remote.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("Get() = %q, want %q", got, value)
	}

	objects, err := store.List(context.Background(), remote.ObjectPrefix()+"/")
	if err != nil || len(objects) != 1 {
		t.Fatalf("List() = %#v, %v; want one object", objects, err)
	}
	raw, err := store.Get(context.Background(), objects[0].Key)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if bytes.Contains(raw, []byte("private prompt")) || bytes.Contains(raw, value) {
		t.Fatalf("remote object contains plaintext cache material: %q", raw)
	}
	entries, err := remote.List(context.Background())
	if err != nil || len(entries) != 1 || entries[0].Digest != key.Digest() {
		t.Fatalf("remote.List() = %#v, %v; want one digest", entries, err)
	}
	if remote.Stats().Sets != 1 || remote.Stats().Hits != 1 {
		t.Fatalf("remote stats = %#v, want one set and hit", remote.Stats())
	}
}

func TestRemoteCacheEnforcesEntryAndValueLimits(t *testing.T) {
	store := NewMemoryObjectStore()
	remote, err := NewRemoteCache(store, []byte("remote-cache-key"),
		WithRemoteDefaultTTL(time.Hour),
		WithRemoteMaxEntries(1),
		WithRemoteMaxValueBytes(4),
	)
	if err != nil {
		t.Fatalf("NewRemoteCache() error = %v", err)
	}
	first := NewCacheKey("rule", "", "local", "v1", "first")
	second := NewCacheKey("rule", "", "local", "v1", "second")
	if err := remote.Set(context.Background(), first, []byte("1234")); err != nil {
		t.Fatalf("first Set() error = %v", err)
	}
	if err := remote.Set(context.Background(), first, []byte("12345")); !errors.Is(err, ErrCacheValueTooLarge) {
		t.Fatalf("oversized Set() error = %v, want ErrCacheValueTooLarge", err)
	}
	if err := remote.Set(context.Background(), second, []byte("ok")); !errors.Is(err, ErrCacheLimit) {
		t.Fatalf("second Set() error = %v, want ErrCacheLimit", err)
	}
	if err := remote.Set(context.Background(), first, []byte("ok")); err != nil {
		t.Fatalf("same-key replacement error = %v", err)
	}
}

func TestRemoteCacheExpiryAndCorruptionAreMisses(t *testing.T) {
	store := NewMemoryObjectStore()
	now := time.Now().UTC()
	remote, err := NewRemoteCache(store, []byte("remote-cache-key"),
		WithRemoteDefaultTTL(time.Minute),
		WithRemoteCacheClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("NewRemoteCache() error = %v", err)
	}
	key := NewCacheKey("rule", "", "local", "v1", "expire")
	if err := remote.Set(context.Background(), key, []byte("value")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := remote.Get(context.Background(), key); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expired Get() error = %v, want ErrCacheMiss", err)
	}

	corrupt := NewCacheKey("rule", "", "local", "v1", "corrupt")
	if err := remote.Set(context.Background(), corrupt, []byte("value")); err != nil {
		t.Fatalf("corrupt Set() error = %v", err)
	}
	objectKey := remote.objectKey(corrupt)
	if err := store.Put(context.Background(), objectKey, []byte("not encrypted"), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("store.Put(corrupt) error = %v", err)
	}
	if _, err := remote.Get(context.Background(), corrupt); !errors.Is(err, ErrCacheCorrupt) {
		t.Fatalf("corrupt Get() error = %v, want ErrCacheCorrupt", err)
	}
	if _, err := store.Get(context.Background(), objectKey); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("corrupt object remains in store: %v", err)
	}
}

func TestRemoteCacheManagementAndContext(t *testing.T) {
	store := NewMemoryObjectStore()
	remote, err := NewRemoteCache(store, []byte("remote-cache-key"), WithRemoteDefaultTTL(time.Hour))
	if err != nil {
		t.Fatalf("NewRemoteCache() error = %v", err)
	}
	key := NewCacheKey("rule", "", "local", "v1", "management")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := remote.Set(canceled, key, []byte("value")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Set() error = %v, want context.Canceled", err)
	}
	if err := remote.Set(context.Background(), key, []byte("value")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := remote.Remove(context.Background(), key); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := remote.Remove(context.Background(), key); err != nil {
		t.Fatalf("idempotent Remove() error = %v", err)
	}
	if err := remote.Set(context.Background(), key, []byte("value")); err != nil {
		t.Fatalf("second Set() error = %v", err)
	}
	if err := remote.Purge(context.Background()); err != nil {
		t.Fatalf("Purge() error = %v", err)
	}
	entries, err := remote.List(context.Background())
	if err != nil || len(entries) != 0 {
		t.Fatalf("List() after Purge = %#v, %v; want empty", entries, err)
	}
}

func TestRemoteCachePurgeRejectsListingsOverConfiguredLimit(t *testing.T) {
	store := NewMemoryObjectStore()
	remote, err := NewRemoteCache(store, []byte("remote-cache-key"), WithRemoteMaxEntries(2))
	if err != nil {
		t.Fatalf("NewRemoteCache() error = %v", err)
	}

	expiresAt := time.Now().UTC().Add(time.Hour)
	for _, key := range []string{
		remote.ObjectPrefix() + "/entry-a",
		remote.ObjectPrefix() + "/entry-b",
		remote.ObjectPrefix() + "/entry-c",
	} {
		if err := store.Put(context.Background(), key, []byte("value"), expiresAt); err != nil {
			t.Fatalf("store.Put(%q) error = %v", key, err)
		}
	}

	if err := remote.Purge(context.Background()); !errors.Is(err, ErrCacheLimit) {
		t.Fatalf("Purge() error = %v, want ErrCacheLimit", err)
	}
	objects, err := store.List(context.Background(), remote.ObjectPrefix()+"/")
	if err != nil {
		t.Fatalf("store.List() error = %v", err)
	}
	if len(objects) != 3 {
		t.Fatalf("Purge() deleted objects from an over-limit listing: got %d, want 3", len(objects))
	}
}
