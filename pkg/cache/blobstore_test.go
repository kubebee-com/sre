package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"gocloud.dev/blob/fileblob"
)

func TestBlobObjectStoreImplementsBoundedCacheObjectContract(t *testing.T) {
	bucket, err := fileblob.OpenBucket(t.TempDir(), &fileblob.Options{NoTempDir: true})
	if err != nil {
		t.Fatalf("fileblob.OpenBucket() error = %v", err)
	}
	defer bucket.Close()
	store, err := NewBlobObjectStore(bucket)
	if err != nil {
		t.Fatalf("NewBlobObjectStore() error = %v", err)
	}
	ctx := context.Background()
	key := "sre-agent/cache/v1/example.cache"
	if err := store.Put(ctx, key, []byte("encrypted-value"), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	value, err := store.Get(ctx, key)
	if err != nil || string(value) != "encrypted-value" {
		t.Fatalf("Get() = %q, %v", value, err)
	}
	objects, err := store.List(ctx, "sre-agent/cache/v1/")
	if err != nil || len(objects) != 1 || objects[0].Key != key {
		t.Fatalf("List() = %#v, %v", objects, err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Get(ctx, key); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("Get() after Delete() error = %v, want ErrObjectNotFound", err)
	}
}

func TestBlobObjectStoreRejectsUnsafeKeysAndInsecureOptions(t *testing.T) {
	bucket, err := fileblob.OpenBucket(t.TempDir(), &fileblob.Options{NoTempDir: true})
	if err != nil {
		t.Fatalf("fileblob.OpenBucket() error = %v", err)
	}
	defer bucket.Close()
	store, err := NewBlobObjectStore(bucket)
	if err != nil {
		t.Fatalf("NewBlobObjectStore() error = %v", err)
	}
	if _, err := store.Get(context.Background(), "../escape"); !errors.Is(err, ErrCacheInvalidKey) {
		t.Fatalf("unsafe Get() error = %v, want ErrCacheInvalidKey", err)
	}
	if _, err := OpenBlobObjectStore(context.Background(), "s3://bucket?disable_https=true"); err == nil {
		t.Fatal("OpenBlobObjectStore() accepted an insecure transport option")
	}
	for _, bucketURL := range []string{
		"s3://user:password@bucket",
		"s3://bucket\r\nX-Injected: value",
	} {
		if _, err := OpenBlobObjectStore(context.Background(), bucketURL); err == nil {
			t.Fatalf("OpenBlobObjectStore(%q) accepted unsafe URL", bucketURL)
		}
	}
}
