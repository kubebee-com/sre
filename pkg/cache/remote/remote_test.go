package remote

import (
	"context"
	"strings"
	"testing"
)

func TestFacadeUsesEncryptedRemoteCacheContract(t *testing.T) {
	store := NewMemoryObjectStore()
	remoteCache, err := New(store, []byte("0123456789abcdef0123456789abcdef"), WithPrefix("tenant-a"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	key := NewKey("openai", "model", "https://api.example.test", "prompt/v1", "diagnostic")
	if err := remoteCache.Set(context.Background(), key, []byte("result")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	value, err := remoteCache.Get(context.Background(), key)
	if err != nil || string(value) != "result" {
		t.Fatalf("Get() = %q, %v; want result", value, err)
	}
	objects, err := store.List(context.Background(), "tenant-a/")
	if err != nil || len(objects) != 1 {
		t.Fatalf("store.List() = %d, %v; want one encrypted object", len(objects), err)
	}
	if !strings.HasPrefix(objects[0].Key, "tenant-a/") || !strings.HasSuffix(objects[0].Key, ".cache") {
		t.Fatal("remote object key exposed cache content")
	}
}
