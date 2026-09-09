package cache

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	cacheFileSuffix       = ".cache"
	cacheTempPrefix       = ".cache-tmp-"
	cacheEnvelopeOverhead = 256 * 1024
)

// FileCache is a process-concurrency-safe encrypted local cache.
type FileCache struct {
	directory string
	encryptor *Encryptor
	options   cacheOptions
	lock      chan struct{}
	counters  cacheCounters
}

type fileEnvelope struct {
	Version   string    `json:"version"`
	Digest    string    `json:"digest"`
	Key       CacheKey  `json:"key"`
	Value     []byte    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewFileCache constructs the durable cache. Passing no key is an error: the
// durable cache is intentionally opt-in and never falls back to plaintext.
func NewFileCache(directory string, encryptionKey []byte, options ...CacheOption) (*FileCache, error) {
	if len(encryptionKey) == 0 {
		return nil, ErrEncryptionKeyRequired
	}
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("cache directory is required")
	}
	configured := defaultCacheOptions()
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&configured); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errors.New("cache directory could not be created")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, errors.New("cache directory permissions could not be restricted")
	}
	encryptor, err := NewEncryptor(encryptionKey)
	if err != nil {
		return nil, err
	}
	lock := make(chan struct{}, 1)
	lock <- struct{}{}
	return &FileCache{
		directory: directory,
		encryptor: encryptor,
		options:   configured,
		lock:      lock,
	}, nil
}

// NewEncryptedFileCache is an explicit alias for NewFileCache.
func NewEncryptedFileCache(directory string, encryptionKey []byte, options ...CacheOption) (*FileCache, error) {
	return NewFileCache(directory, encryptionKey, options...)
}

func (c *FileCache) Directory() string {
	if c == nil {
		return ""
	}
	return c.directory
}

// Path returns the deterministic digest-based path for a valid key.
func (c *FileCache) Path(key CacheKey) string {
	if c == nil || key.Digest() == "" {
		return ""
	}
	return filepath.Join(c.directory, key.Digest()+cacheFileSuffix)
}

// FilePath is an alias for Path.
func (c *FileCache) FilePath(key CacheKey) string { return c.Path(key) }

func (c *FileCache) Get(ctx context.Context, key CacheKey) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	key = key.normalized()
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	defer c.release()
	value, err := c.readEntryLocked(key)
	if err == nil {
		c.counters.hits.Add(1)
		return sanitizeCacheBytes(value), nil
	}
	if errors.Is(err, ErrCacheCorrupt) {
		c.counters.corruptions.Add(1)
	}
	if errors.Is(err, ErrCacheMiss) || errors.Is(err, ErrCacheCorrupt) {
		c.counters.misses.Add(1)
	}
	return nil, err
}

func (c *FileCache) Lookup(ctx context.Context, key CacheKey) ([]byte, bool, error) {
	value, err := c.Get(ctx, key)
	if errors.Is(err, ErrCacheMiss) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (c *FileCache) Set(ctx context.Context, key CacheKey, value []byte, ttls ...time.Duration) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	key = key.normalized()
	if err := key.Validate(); err != nil {
		return err
	}
	value = sanitizeCacheBytes(value)
	if len(value) > c.options.maxValueBytes {
		return ErrCacheValueTooLarge
	}
	ttl := c.options.defaultTTL
	if len(ttls) > 1 {
		return ErrCacheInvalidTTL
	}
	if len(ttls) == 1 {
		if ttls[0] < 0 {
			return ErrCacheInvalidTTL
		}
		if ttls[0] > 0 {
			ttl = ttls[0]
		}
	}
	now := c.options.clock().UTC()
	envelope := fileEnvelope{
		Version:   KeyVersion,
		Digest:    key.Digest(),
		Key:       key,
		Value:     append([]byte(nil), value...),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
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
	path := c.Path(key)
	if path == "" {
		return ErrCacheInvalidKey
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		count, countErr := c.countEntriesLocked()
		if countErr != nil {
			return countErr
		}
		if count >= c.options.maxEntries {
			return ErrCacheLimit
		}
	} else if err != nil {
		return errors.New("cache entry could not be inspected")
	}
	if err := c.writeAtomicLocked(path, sealed); err != nil {
		return err
	}
	c.counters.sets.Add(1)
	return nil
}

func (c *FileCache) Remove(ctx context.Context, key CacheKey) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	key = key.normalized()
	if err := key.Validate(); err != nil {
		return err
	}
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	err := os.Remove(c.Path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("cache entry could not be removed")
	}
	c.counters.removes.Add(1)
	return nil
}

// Delete is an alias for Remove.
func (c *FileCache) Delete(ctx context.Context, key CacheKey) error { return c.Remove(ctx, key) }

func (c *FileCache) List(ctx context.Context) ([]CacheEntry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	defer c.release()
	files, err := os.ReadDir(c.directory)
	if err != nil {
		return nil, errors.New("cache directory could not be read")
	}
	entries := make([]CacheEntry, 0, len(files))
	for _, file := range files {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		if file.IsDir() || !strings.HasSuffix(file.Name(), cacheFileSuffix) {
			continue
		}
		path := filepath.Join(c.directory, file.Name())
		envelope, readErr := c.readEnvelopeLocked(path)
		if readErr != nil {
			if errors.Is(readErr, ErrCacheMiss) || errors.Is(readErr, ErrCacheCorrupt) {
				_ = os.Remove(path)
				if errors.Is(readErr, ErrCacheCorrupt) {
					c.counters.corruptions.Add(1)
				}
				continue
			}
			return nil, readErr
		}
		if !envelope.ExpiresAt.After(c.options.clock().UTC()) {
			_ = os.Remove(path)
			continue
		}
		entries = append(entries, CacheEntry{
			Digest:    envelope.Digest,
			Key:       envelope.Key,
			Size:      len(envelope.Value),
			CreatedAt: envelope.CreatedAt,
			ExpiresAt: envelope.ExpiresAt,
		})
	}
	sortEntries(entries)
	return entries, nil
}

func (c *FileCache) Purge(ctx context.Context) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	files, err := os.ReadDir(c.directory)
	if err != nil {
		return errors.New("cache directory could not be read")
	}
	for _, file := range files {
		if err := checkContext(ctx); err != nil {
			return err
		}
		if file.IsDir() || !strings.HasSuffix(file.Name(), cacheFileSuffix) {
			continue
		}
		if err := os.Remove(filepath.Join(c.directory, file.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("cache entry could not be purged")
		}
	}
	return nil
}

func (c *FileCache) Stats() CacheStats {
	if c == nil {
		return CacheStats{}
	}
	return c.counters.stats()
}

func (c *FileCache) acquire(ctx context.Context) error {
	ctx = normalizeCacheContext(ctx)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.lock:
		return nil
	}
}

func (c *FileCache) release() {
	if c != nil && c.lock != nil {
		c.lock <- struct{}{}
	}
}

// Close exists so callers can use the same lifecycle contract for memory and
// durable caches. FileCache has no open descriptors to release.
func (c *FileCache) Close() error { return nil }

func (c *FileCache) countEntriesLocked() (int, error) {
	files, err := os.ReadDir(c.directory)
	if err != nil {
		return 0, errors.New("cache directory could not be read")
	}
	count := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), cacheFileSuffix) {
			count++
		}
	}
	return count, nil
}

func (c *FileCache) writeAtomicLocked(path string, content []byte) error {
	temporary, err := os.CreateTemp(c.directory, cacheTempPrefix)
	if err != nil {
		return errors.New("cache temporary file could not be created")
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}()
	if err := temporary.Chmod(0600); err != nil {
		return errors.New("cache temporary file permissions could not be restricted")
	}
	if _, err := temporary.Write(content); err != nil {
		return errors.New("cache entry could not be written")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("cache entry could not be synchronized")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("cache temporary file could not be closed")
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return errors.New("cache entry could not be installed")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return errors.New("cache entry permissions could not be restricted")
	}
	return nil
}

func (c *FileCache) readEntryLocked(key CacheKey) ([]byte, error) {
	path := c.Path(key)
	envelope, err := c.readEnvelopeLocked(path)
	if err != nil {
		return nil, err
	}
	if envelope.Digest != key.Digest() || envelope.Version != KeyVersion || envelope.Key.normalized().Digest() != key.Digest() {
		_ = os.Remove(path)
		return nil, ErrCacheCorrupt
	}
	if !envelope.ExpiresAt.After(c.options.clock().UTC()) {
		_ = os.Remove(path)
		return nil, ErrCacheMiss
	}
	if len(envelope.Value) > c.options.maxValueBytes {
		_ = os.Remove(path)
		return nil, ErrCacheCorrupt
	}
	return append([]byte(nil), envelope.Value...), nil
}

func (c *FileCache) readEnvelopeLocked(path string) (*fileEnvelope, error) {
	maxBytes := c.maxCiphertextBytes()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrCacheMiss
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxBytes {
		_ = os.Remove(path)
		return nil, ErrCacheCorrupt
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrCacheCorrupt
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(content)) > maxBytes {
		_ = os.Remove(path)
		return nil, ErrCacheCorrupt
	}
	plaintext, err := c.encryptor.Open(content)
	if err != nil {
		_ = os.Remove(path)
		return nil, ErrCacheCorrupt
	}
	var envelope fileEnvelope
	if err := json.Unmarshal(plaintext, &envelope); err != nil || envelope.Version != KeyVersion || envelope.Digest == "" || envelope.Key.Digest() != envelope.Digest {
		_ = os.Remove(path)
		return nil, ErrCacheCorrupt
	}
	return &envelope, nil
}

func (c *FileCache) maxPlaintextBytes() int64 {
	if c == nil {
		return int64(DefaultMaxValueBytes)*2 + cacheEnvelopeOverhead
	}
	return int64(c.options.maxValueBytes)*2 + cacheEnvelopeOverhead
}

func (c *FileCache) maxCiphertextBytes() int64 {
	// JSON encodes []byte as base64, so allow conservative expansion while
	// retaining a fixed metadata bound.
	return c.maxPlaintextBytes()*2 + 64
}
