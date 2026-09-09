package cache

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileCacheRoundTripTTLStatsPermissionsAndManagement(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	clock := now
	cache, err := NewFileCache(t.TempDir(), []byte("file-cache-key"),
		WithDefaultTTL(time.Minute),
		WithCacheClock(func() time.Time { return clock }),
	)
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	key := NewCacheKey("localai", "model", "http://127.0.0.1:8080/v1", "chat-v1", "safe prompt")
	value := []byte("encrypted provider answer")
	if err := cache.Set(context.Background(), key, value); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	entries, err := cache.List(context.Background())
	if err != nil || len(entries) != 1 || entries[0].Digest != key.Digest() {
		t.Fatalf("List() = %#v, %v; want one key", entries, err)
	}
	files, err := os.ReadDir(cache.Directory())
	if err != nil || len(files) != 1 {
		t.Fatalf("cache files = %v, %v; want one file", files, err)
	}
	info, err := files[0].Info()
	if err != nil {
		t.Fatalf("file info: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("cache file mode = %o, want 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Join(cache.Directory(), files[0].Name()))
	if err != nil {
		t.Fatalf("read cache file: %v", err)
	}
	if strings.Contains(string(raw), string(value)) {
		t.Fatal("cache file contains plaintext value")
	}

	got, err := cache.Get(context.Background(), key)
	if err != nil || string(got) != string(value) {
		t.Fatalf("Get() = %q, %v; want value", got, err)
	}
	if _, err := cache.Get(context.Background(), NewCacheKey("localai", "model", "http://127.0.0.1:8080/v1", "chat-v1", "miss")); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("missing Get() error = %v, want ErrCacheMiss", err)
	}
	stats := cache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Fatalf("Stats() = %#v, want one hit and miss", stats)
	}

	clock = now.Add(2 * time.Minute)
	if _, err := cache.Get(context.Background(), key); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expired Get() error = %v, want ErrCacheMiss", err)
	}
	if err := cache.Remove(context.Background(), key); err != nil && !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := cache.Purge(context.Background()); err != nil {
		t.Fatalf("Purge() error = %v", err)
	}
}

func TestFileCacheReadsEntriesWithinCustomValueLimit(t *testing.T) {
	cache, err := NewFileCache(t.TempDir(), []byte("custom-size-key"), WithMaxValueBytes(2<<20))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	key := NewCacheKey("provider", "model", "endpoint", "schema", "large-prompt")
	want := bytes.Repeat([]byte("x"), 2<<20)
	if err := cache.Set(context.Background(), key, want); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := cache.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get() returned %d bytes, want %d", len(got), len(want))
	}
}

func TestFileCacheCorruptionIsReportedAndRemoved(t *testing.T) {
	directory := t.TempDir()
	cache, err := NewFileCache(directory, []byte("corruption-key"))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	key := NewCacheKey("provider", "model", "endpoint", "schema", "prompt")
	if err := cache.Set(context.Background(), key, []byte("value")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 {
		t.Fatalf("ReadDir() = %v, %v", files, err)
	}
	if err := os.WriteFile(filepath.Join(directory, files[0].Name()), []byte("corrupt"), 0600); err != nil {
		t.Fatalf("corrupt cache: %v", err)
	}
	if _, err := cache.Get(context.Background(), key); !errors.Is(err, ErrCacheCorrupt) {
		t.Fatalf("corrupt Get() error = %v, want ErrCacheCorrupt", err)
	}
	if _, err := os.Stat(filepath.Join(directory, files[0].Name())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt cache file stat error = %v, want removed file", err)
	}
}

func TestFileCacheSupportsConcurrentAccess(t *testing.T) {
	cache, err := NewFileCache(t.TempDir(), []byte("concurrency-key"), WithMaxEntries(64))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			key := NewCacheKey("provider", "model", "endpoint", "schema", "prompt-"+string(rune('a'+index)))
			if err := cache.Set(context.Background(), key, []byte("value")); err != nil {
				t.Errorf("Set(%d) error = %v", index, err)
				return
			}
			if _, err := cache.Get(context.Background(), key); err != nil {
				t.Errorf("Get(%d) error = %v", index, err)
			}
		}(i)
	}
	wg.Wait()
	entries, err := cache.List(context.Background())
	if err != nil || len(entries) != workers {
		t.Fatalf("List() = %d, %v; want %d entries", len(entries), err, workers)
	}
}
