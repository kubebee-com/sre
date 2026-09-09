// Package remote exposes the remote cache contract under a dedicated package
// path. The implementation remains in pkg/cache so local and remote caches
// share the same key, envelope, encryption, retention, and metrics behavior.
package remote

import (
	"context"
	"time"

	"github.com/kubebee-com/sre/pkg/cache"
)

type Cache = cache.RemoteCache
type ObjectStore = cache.ObjectStore
type Object = cache.RemoteObject
type CacheKey = cache.CacheKey
type CacheEntry = cache.CacheEntry
type CacheStats = cache.CacheStats
type Option = cache.RemoteCacheOption
type MemoryObjectStore = cache.MemoryObjectStore
type BlobObjectStore = cache.BlobObjectStore

var ErrObjectNotFound = cache.ErrObjectNotFound

func New(store ObjectStore, encryptionKey []byte, options ...Option) (*Cache, error) {
	return cache.NewRemoteCache(store, encryptionKey, options...)
}

func NewMemoryObjectStore() *MemoryObjectStore {
	return cache.NewMemoryObjectStore()
}

// OpenBlobObjectStore exposes the maintained Go Cloud S3, GCS, and Azure Blob
// adapter from the remote-cache package without duplicating driver setup.
func OpenBlobObjectStore(ctx context.Context, bucketURL string) (*BlobObjectStore, error) {
	return cache.OpenBlobObjectStore(ctx, bucketURL)
}

func WithPrefix(prefix string) Option {
	return cache.WithRemotePrefix(prefix)
}

func WithDefaultTTL(ttl time.Duration) Option {
	return cache.WithRemoteDefaultTTL(ttl)
}

func WithMaxEntries(max int) Option {
	return cache.WithRemoteMaxEntries(max)
}

func WithMaxValueBytes(max int) Option {
	return cache.WithRemoteMaxValueBytes(max)
}

func WithClock(clock func() time.Time) Option {
	return cache.WithRemoteCacheClock(clock)
}

func NewKey(provider, model, endpoint, promptSchema, prompt string) CacheKey {
	return cache.NewCacheKey(provider, model, endpoint, promptSchema, prompt)
}

func Get(ctx context.Context, c *Cache, key CacheKey) ([]byte, error) {
	if c == nil {
		return nil, cache.ErrCacheDisabled
	}
	return c.Get(ctx, key)
}
