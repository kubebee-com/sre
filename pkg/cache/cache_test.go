package cache

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCacheKeySeparatesSemanticProviderInputs(t *testing.T) {
	base := NewCacheKey("openai", "model-a", "https://api.example/v1", "diagnosis-v1", "prompt")
	if err := base.Validate(); err != nil {
		t.Fatalf("CacheKey.Validate() error = %v", err)
	}
	for name, other := range map[string]CacheKey{
		"provider": NewCacheKey("claude", "model-a", "https://api.example/v1", "diagnosis-v1", "prompt"),
		"model":    NewCacheKey("openai", "model-b", "https://api.example/v1", "diagnosis-v1", "prompt"),
		"endpoint": NewCacheKey("openai", "model-a", "https://other.example/v1", "diagnosis-v1", "prompt"),
		"schema":   NewCacheKey("openai", "model-a", "https://api.example/v1", "diagnosis-v2", "prompt"),
		"prompt":   NewCacheKey("openai", "model-a", "https://api.example/v1", "diagnosis-v1", "other"),
	} {
		if base.Digest() == other.Digest() {
			t.Errorf("%s key reused digest %q", name, base.Digest())
		}
	}
	if len(base.Digest()) != 64 {
		t.Fatalf("CacheKey.Digest() length = %d, want SHA-256 hex", len(base.Digest()))
	}
}

func TestCacheKeySanitizesEndpointURLComponents(t *testing.T) {
	key := NewCacheKey("openai", "model", "https://api.example/v1/?api_key=endpoint-secret#credentials", "schema", "prompt")
	if key.Endpoint != "https://api.example/v1" {
		t.Fatalf("endpoint = %q, want URL path without query or fragment", key.Endpoint)
	}
	canonical, err := key.Canonical()
	if err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}
	if strings.Contains(string(canonical), "endpoint-secret") || strings.Contains(string(canonical), "credentials") {
		t.Fatalf("canonical key leaked endpoint URL data: %s", canonical)
	}

	withOtherQuery := NewCacheKey("openai", "model", "https://api.example/v1?tenant=other", "schema", "prompt")
	if key.Digest() != withOtherQuery.Digest() {
		t.Fatal("endpoint query changed semantic cache identity")
	}
}

func TestDisabledCacheNeverPersists(t *testing.T) {
	cache := NewDisabledCache()
	key := NewCacheKey("rule", "", "local", "v1", "prompt")
	if err := cache.Set(context.Background(), key, []byte("value")); !errors.Is(err, ErrCacheDisabled) {
		t.Fatalf("Set() error = %v, want ErrCacheDisabled", err)
	}
	if _, err := cache.Get(context.Background(), key); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Get() error = %v, want ErrCacheMiss", err)
	}
}

func TestNewFileCacheRequiresExplicitEncryptionKey(t *testing.T) {
	if _, err := NewFileCache(t.TempDir(), nil); !errors.Is(err, ErrEncryptionKeyRequired) {
		t.Fatalf("NewFileCache() error = %v, want ErrEncryptionKeyRequired", err)
	}
}
