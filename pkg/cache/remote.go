package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const maxAllowedRemoteEntries = MaxAllowedEntries

var ErrObjectNotFound = errors.New("remote cache object not found")

// RemoteObject is metadata returned by an ObjectStore list operation. Object
// keys are digests and never contain prompts or provider credentials.
type RemoteObject struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// ObjectStore is the minimal remote persistence contract required by
// RemoteCache. Implementations should provide TLS, authentication, deadlines,
// and server-side retention according to their backend's policy.
type ObjectStore interface {
	Get(context.Context, string) ([]byte, error)
	Put(context.Context, string, []byte, time.Time) error
	Delete(context.Context, string) error
	List(context.Context, string) ([]RemoteObject, error)
}

type remoteCacheConfig struct {
	prefix        string
	defaultTTL    time.Duration
	maxEntries    int
	maxValueBytes int
	clock         func() time.Time
}

func defaultRemoteCacheConfig() remoteCacheConfig {
	return remoteCacheConfig{
		prefix:        "sre-agent/cache/v1",
		defaultTTL:    DefaultTTL,
		maxEntries:    DefaultMaxEntries,
		maxValueBytes: DefaultMaxValueBytes,
		clock:         time.Now,
	}
}

type RemoteCacheOption func(*remoteCacheConfig) error

func WithRemotePrefix(prefix string) RemoteCacheOption {
	return func(config *remoteCacheConfig) error {
		prefix = strings.Trim(prefix, "/")
		if prefix == "" || strings.ContainsAny(prefix, "\r\n\x00") || strings.Contains(prefix, "..") {
			return ErrCacheInvalidKey
		}
		config.prefix = prefix
		return nil
	}
}

func WithRemoteDefaultTTL(ttl time.Duration) RemoteCacheOption {
	return func(config *remoteCacheConfig) error {
		if ttl <= 0 {
			return ErrCacheInvalidTTL
		}
		config.defaultTTL = ttl
		return nil
	}
}

func WithRemoteMaxEntries(max int) RemoteCacheOption {
	return func(config *remoteCacheConfig) error {
		if max <= 0 || max > maxAllowedRemoteEntries {
			return ErrCacheLimit
		}
		config.maxEntries = max
		return nil
	}
}

func WithRemoteMaxValueBytes(max int) RemoteCacheOption {
	return func(config *remoteCacheConfig) error {
		if max <= 0 || max > MaxAllowedValueBytes {
			return ErrCacheValueTooLarge
		}
		config.maxValueBytes = max
		return nil
	}
}

func WithRemoteCacheClock(clock func() time.Time) RemoteCacheOption {
	return func(config *remoteCacheConfig) error {
		if clock == nil {
			return errors.New("cache clock is required")
		}
		config.clock = clock
		return nil
	}
}

type remoteEnvelope struct {
	Version   string    `json:"version"`
	Digest    string    `json:"digest"`
	Key       CacheKey  `json:"key"`
	Value     []byte    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RemoteCache is an encrypted, bounded implementation of Cache backed by an
// injected object store. Setup is opt-in and cannot fall back to plaintext.
type RemoteCache struct {
	store     ObjectStore
	encryptor *Encryptor
	config    remoteCacheConfig
	counters  cacheCounters
	lock      chan struct{}
}

func NewRemoteCache(store ObjectStore, encryptionKey []byte, options ...RemoteCacheOption) (*RemoteCache, error) {
	if store == nil {
		return nil, errors.New("remote cache object store is required")
	}
	if len(encryptionKey) == 0 {
		return nil, ErrEncryptionKeyRequired
	}
	config := defaultRemoteCacheConfig()
	for _, option := range options {
		if option != nil {
			if err := option(&config); err != nil {
				return nil, err
			}
		}
	}
	encryptor, err := NewEncryptor(encryptionKey)
	if err != nil {
		return nil, err
	}
	lock := make(chan struct{}, 1)
	lock <- struct{}{}
	return &RemoteCache{store: store, encryptor: encryptor, config: config, lock: lock}, nil
}

// NewObjectStoreCache is an explicit alias for NewRemoteCache.
func NewObjectStoreCache(store ObjectStore, encryptionKey []byte, options ...RemoteCacheOption) (*RemoteCache, error) {
	return NewRemoteCache(store, encryptionKey, options...)
}

func (c *RemoteCache) ObjectPrefix() string {
	if c == nil {
		return ""
	}
	return c.config.prefix
}

func (c *RemoteCache) objectKey(key CacheKey) string {
	return strings.TrimRight(c.config.prefix, "/") + "/" + key.Digest() + ".cache"
}

func (c *RemoteCache) Get(ctx context.Context, key CacheKey) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	key = key.normalized()
	if err := key.Validate(); err != nil {
		return nil, err
	}
	content, err := c.store.Get(ctx, c.objectKey(key))
	if contextErr := checkContext(ctx); contextErr != nil {
		return nil, contextErr
	}
	if errors.Is(err, ErrObjectNotFound) {
		err = ErrCacheMiss
	}
	if err != nil {
		if errors.Is(err, ErrCacheMiss) || errors.Is(err, ErrCacheCorrupt) {
			c.counters.misses.Add(1)
		}
		if errors.Is(err, ErrCacheMiss) {
			return nil, ErrCacheMiss
		}
		return nil, cacheBackendError(CacheErrorRead, "get", err)
	}
	plaintext, err := c.encryptor.Open(content)
	if err != nil {
		_ = c.store.Delete(ctx, c.objectKey(key))
		c.counters.corruptions.Add(1)
		c.counters.misses.Add(1)
		return nil, ErrCacheCorrupt
	}
	var envelope remoteEnvelope
	if err := json.Unmarshal(plaintext, &envelope); err != nil || envelope.Version != KeyVersion || envelope.Digest != key.Digest() || envelope.Key.normalized().Digest() != envelope.Digest || len(envelope.Value) > c.config.maxValueBytes {
		_ = c.store.Delete(ctx, c.objectKey(key))
		c.counters.corruptions.Add(1)
		c.counters.misses.Add(1)
		return nil, ErrCacheCorrupt
	}
	if !envelope.ExpiresAt.After(c.config.clock().UTC()) {
		_ = c.store.Delete(ctx, c.objectKey(key))
		c.counters.misses.Add(1)
		return nil, ErrCacheMiss
	}
	c.counters.hits.Add(1)
	return sanitizeCacheBytes(envelope.Value), nil
}

func (c *RemoteCache) Lookup(ctx context.Context, key CacheKey) ([]byte, bool, error) {
	value, err := c.Get(ctx, key)
	if errors.Is(err, ErrCacheMiss) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (c *RemoteCache) Set(ctx context.Context, key CacheKey, value []byte, ttls ...time.Duration) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	key = key.normalized()
	if err := key.Validate(); err != nil {
		return err
	}
	value = sanitizeCacheBytes(value)
	if len(value) > c.config.maxValueBytes {
		return ErrCacheValueTooLarge
	}
	if len(ttls) > 1 || (len(ttls) == 1 && ttls[0] < 0) {
		return ErrCacheInvalidTTL
	}
	ttl := c.config.defaultTTL
	if len(ttls) == 1 && ttls[0] > 0 {
		ttl = ttls[0]
	}
	now := c.config.clock().UTC()
	envelope := remoteEnvelope{Version: KeyVersion, Digest: key.Digest(), Key: key, Value: append([]byte(nil), value...), CreatedAt: now, ExpiresAt: now.Add(ttl)}
	plaintext, err := json.Marshal(envelope)
	if err != nil {
		return errors.New("cache entry could not be encoded")
	}
	if int64(len(plaintext)) > c.maxPlaintextBytes() {
		return ErrCacheValueTooLarge
	}
	sealed, err := c.encryptor.Seal(plaintext)
	if err != nil {
		return err
	}
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	if err := checkContext(ctx); err != nil {
		return err
	}
	objects, err := c.store.List(ctx, c.config.prefix+"/")
	if err != nil {
		return cacheBackendError(CacheErrorList, "list", err)
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	objectKey := c.objectKey(key)
	if len(objects) >= c.config.maxEntries && !containsRemoteObject(objects, objectKey) {
		return ErrCacheLimit
	}
	if err := c.store.Put(ctx, objectKey, sealed, envelope.ExpiresAt); err != nil {
		return cacheBackendError(CacheErrorWrite, "put", err)
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	c.counters.sets.Add(1)
	return nil
}

func (c *RemoteCache) Remove(ctx context.Context, key CacheKey) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	key = key.normalized()
	if err := key.Validate(); err != nil {
		return err
	}
	err := c.store.Delete(ctx, c.objectKey(key))
	if errors.Is(err, ErrObjectNotFound) {
		return nil
	}
	if err != nil {
		return cacheBackendError(CacheErrorDelete, "delete", err)
	}
	c.counters.removes.Add(1)
	return nil
}

func (c *RemoteCache) List(ctx context.Context) ([]CacheEntry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	objects, err := c.store.List(ctx, c.config.prefix+"/")
	if err != nil {
		return nil, cacheBackendError(CacheErrorList, "list", err)
	}
	if len(objects) > c.config.maxEntries {
		return nil, ErrCacheLimit
	}
	entries := make([]CacheEntry, 0, len(objects))
	for _, object := range objects {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		content, getErr := c.store.Get(ctx, object.Key)
		if contextErr := checkContext(ctx); contextErr != nil {
			return nil, contextErr
		}
		if getErr != nil {
			if errors.Is(getErr, ErrObjectNotFound) {
				continue
			}
			return nil, cacheBackendError(CacheErrorRead, "get", getErr)
		}
		plaintext, openErr := c.encryptor.Open(content)
		if openErr != nil {
			_ = c.store.Delete(ctx, object.Key)
			c.counters.corruptions.Add(1)
			continue
		}
		var envelope remoteEnvelope
		if json.Unmarshal(plaintext, &envelope) != nil || envelope.Version != KeyVersion || envelope.Digest == "" || envelope.Key.Digest() != envelope.Digest || len(envelope.Value) > c.config.maxValueBytes {
			_ = c.store.Delete(ctx, object.Key)
			c.counters.corruptions.Add(1)
			continue
		}
		if !envelope.ExpiresAt.After(c.config.clock().UTC()) {
			_ = c.store.Delete(ctx, object.Key)
			continue
		}
		entries = append(entries, CacheEntry{Digest: envelope.Digest, Key: envelope.Key, Size: len(envelope.Value), CreatedAt: envelope.CreatedAt, ExpiresAt: envelope.ExpiresAt})
	}
	sortEntries(entries)
	return entries, nil
}

func (c *RemoteCache) Purge(ctx context.Context) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	objects, err := c.store.List(ctx, c.config.prefix+"/")
	if err != nil {
		return cacheBackendError(CacheErrorList, "list", err)
	}
	if len(objects) > c.config.maxEntries {
		return ErrCacheLimit
	}
	for _, object := range objects {
		if err := checkContext(ctx); err != nil {
			return err
		}
		if err := c.store.Delete(ctx, object.Key); err != nil && !errors.Is(err, ErrObjectNotFound) {
			return cacheBackendError(CacheErrorDelete, "delete", err)
		}
	}
	return nil
}

func (c *RemoteCache) acquire(ctx context.Context) error {
	ctx = normalizeCacheContext(ctx)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.lock:
		return nil
	}
}

func (c *RemoteCache) release() {
	if c != nil && c.lock != nil {
		c.lock <- struct{}{}
	}
}

func (c *RemoteCache) Stats() CacheStats {
	if c == nil {
		return CacheStats{}
	}
	return c.counters.stats()
}

func (c *RemoteCache) maxPlaintextBytes() int64 {
	return int64(c.config.maxValueBytes)*2 + cacheEnvelopeOverhead
}

func containsRemoteObject(objects []RemoteObject, key string) bool {
	for _, object := range objects {
		if object.Key == key {
			return true
		}
	}
	return false
}

// MemoryObjectStore is a deterministic object-store fixture and a useful
// embedded backend for tests or single-process development. It enforces
// caller context and expiration but has no network or credential behavior.
type MemoryObjectStore struct {
	mu      sync.RWMutex
	objects map[string]memoryObject
}

type memoryObject struct {
	data       []byte
	expiresAt  time.Time
	modifiedAt time.Time
}

func NewMemoryObjectStore() *MemoryObjectStore {
	return &MemoryObjectStore{objects: make(map[string]memoryObject)}
}

func (s *MemoryObjectStore) Get(ctx context.Context, key string) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	object, ok := s.objects[key]
	s.mu.RUnlock()
	if !ok || !object.expiresAt.After(time.Now().UTC()) {
		if ok {
			_ = s.Delete(ctx, key)
		}
		return nil, ErrObjectNotFound
	}
	return append([]byte(nil), object.data...), nil
}

func (s *MemoryObjectStore) Put(ctx context.Context, key string, data []byte, expiresAt time.Time) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(key) == "" || !expiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("remote cache object is invalid")
	}
	s.mu.Lock()
	s.objects[key] = memoryObject{data: append([]byte(nil), data...), expiresAt: expiresAt.UTC(), modifiedAt: time.Now().UTC()}
	s.mu.Unlock()
	return nil
}

func (s *MemoryObjectStore) Delete(ctx context.Context, key string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	_, ok := s.objects[key]
	delete(s.objects, key)
	s.mu.Unlock()
	if !ok {
		return ErrObjectNotFound
	}
	return nil
}

func (s *MemoryObjectStore) List(ctx context.Context, prefix string) ([]RemoteObject, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	result := make([]RemoteObject, 0, len(s.objects))
	for key, object := range s.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if !object.expiresAt.After(now) {
			delete(s.objects, key)
			continue
		}
		result = append(result, RemoteObject{Key: key, Size: int64(len(object.data)), LastModified: object.modifiedAt})
	}
	s.mu.Unlock()
	return result, nil
}
