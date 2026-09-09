// Package cache provides opt-in, bounded caches for provider results.
//
// The package deliberately has no enabled-by-default global cache. Callers
// must provide an encryption key to construct a durable file cache.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
)

const (
	// KeyVersion is part of every semantic cache key. Bump it when the key
	// fields or canonicalization rules change.
	KeyVersion = "v2"

	DefaultTTL           = 15 * time.Minute
	DefaultMaxEntries    = 256
	MaxAllowedEntries    = 1 << 20
	DefaultMaxValueBytes = 1 << 20
	MaxAllowedValueBytes = 16 << 20
)

var (
	ErrCacheDisabled         = errors.New("cache is disabled")
	ErrCacheMiss             = errors.New("cache miss")
	ErrCacheCorrupt          = errors.New("cache entry is corrupt")
	ErrCacheInvalidKey       = errors.New("cache key is invalid")
	ErrCacheValueTooLarge    = errors.New("cache value exceeds limit")
	ErrCacheLimit            = errors.New("cache entry limit reached")
	ErrCacheInvalidTTL       = errors.New("cache ttl is invalid")
	ErrEncryptionKeyRequired = errors.New("cache encryption key is required")
	ErrAuthentication        = errors.New("cache authentication failed")
	ErrCacheBackend          = errors.New("cache backend operation failed")
)

type CacheErrorKind string

const (
	CacheErrorSetup     CacheErrorKind = "setup"
	CacheErrorRead      CacheErrorKind = "read"
	CacheErrorWrite     CacheErrorKind = "write"
	CacheErrorDelete    CacheErrorKind = "delete"
	CacheErrorList      CacheErrorKind = "list"
	CacheErrorTransport CacheErrorKind = "transport"
)

// CacheError keeps backend details out of public diagnostics while preserving
// errors.Is/errors.As behavior for callers that need to classify cancellation
// or a driver-specific cause.
type CacheError struct {
	Kind      CacheErrorKind
	Operation string
	Cause     error
}

func (e *CacheError) Error() string {
	if e == nil {
		return "cache backend operation failed"
	}
	operation := strings.TrimSpace(e.Operation)
	if operation == "" {
		operation = "operation"
	}
	return "cache backend " + operation + " failed"
}

func (e *CacheError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func cacheBackendError(kind CacheErrorKind, operation string, cause error) error {
	if cause == nil {
		return nil
	}
	if errors.Is(cause, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return &CacheError{Kind: kind, Operation: operation, Cause: fmt.Errorf("%w: %v", ErrCacheBackend, cause)}
}

// Cache is the common provider-result cache contract. A cache implementation
// must not mutate the supplied key or value. Set accepts an optional TTL; when
// omitted or zero, the implementation's configured default is used.
type Cache interface {
	Get(context.Context, CacheKey) ([]byte, error)
	Set(context.Context, CacheKey, []byte, ...time.Duration) error
	Lookup(context.Context, CacheKey) ([]byte, bool, error)
	Remove(context.Context, CacheKey) error
	List(context.Context) ([]CacheEntry, error)
	Purge(context.Context) error
	Stats() CacheStats
}

// CacheKey identifies the complete semantic input to a provider request.
// Prompt is accepted for construction convenience and is never serialized in
// the durable key; PromptHash is used instead.
type CacheKey struct {
	Version         string `json:"version"`
	Operation       string `json:"operation,omitempty"`
	Provider        string `json:"provider"`
	Model           string `json:"model,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	WireAPI         string `json:"wire_api,omitempty"`
	PromptSchema    string `json:"prompt_schema"`
	RedactionSchema string `json:"redaction_schema,omitempty"`
	EvidenceDigest  string `json:"evidence_digest,omitempty"`
	PromptHash      string `json:"prompt_hash,omitempty"`
	Prompt          string `json:"-"`
}

// Key is a short alias for callers that prefer the generic name.
type Key = CacheKey

// NewCacheKey creates a versioned semantic key. The prompt content is hashed
// before it can reach a filename or cache listing.
func NewCacheKey(provider, model, endpoint, promptSchema, prompt string) CacheKey {
	return NewSemanticCacheKey("", provider, model, endpoint, "", promptSchema, "", "", prompt)
}

// NewSemanticCacheKey creates the full identity used by provider result
// caching. Prompt bytes never enter the serialized key; only digests do.
func NewSemanticCacheKey(operation, provider, model, endpoint, wireAPI, promptSchema, redactionSchema, evidenceDigest, prompt string) CacheKey {
	redactor := sanitizer.DefaultRedactor()
	sanitizedPrompt := redactor.SanitizeText(prompt)
	promptDigest := sha256.Sum256([]byte(sanitizedPrompt))
	if strings.TrimSpace(evidenceDigest) == "" {
		evidence := sha256.Sum256([]byte(sanitizedPrompt))
		evidenceDigest = hex.EncodeToString(evidence[:])
	} else {
		evidenceDigest = strings.ToLower(strings.TrimSpace(redactor.SanitizeText(evidenceDigest)))
		if len(evidenceDigest) != sha256.Size*2 || !isLowerHex(evidenceDigest) {
			evidence := sha256.Sum256([]byte(evidenceDigest))
			evidenceDigest = hex.EncodeToString(evidence[:])
		}
	}
	if strings.TrimSpace(redactionSchema) == "" {
		redactionSchema = sanitizer.RedactionSchema
	}
	return CacheKey{
		Version:         KeyVersion,
		Operation:       redactor.SanitizeText(strings.ToLower(strings.TrimSpace(operation))),
		Provider:        redactor.SanitizeText(strings.TrimSpace(provider)),
		Model:           redactor.SanitizeText(strings.TrimSpace(model)),
		Endpoint:        normalizeEndpoint(endpoint),
		WireAPI:         redactor.SanitizeText(strings.ToLower(strings.TrimSpace(wireAPI))),
		PromptSchema:    redactor.SanitizeText(strings.TrimSpace(promptSchema)),
		RedactionSchema: redactor.SanitizeText(strings.TrimSpace(redactionSchema)),
		EvidenceDigest:  strings.TrimSpace(evidenceDigest),
		PromptHash:      hex.EncodeToString(promptDigest[:]),
	}
}

// NewKey is an alias for NewCacheKey.
func NewKey(provider, model, endpoint, promptSchema, prompt string) CacheKey {
	return NewCacheKey(provider, model, endpoint, promptSchema, prompt)
}

func (k CacheKey) normalized() CacheKey {
	if strings.TrimSpace(k.Version) == "" {
		k.Version = KeyVersion
	}
	k.Version = strings.TrimSpace(k.Version)
	redactor := sanitizer.DefaultRedactor()
	k.Operation = redactor.SanitizeText(strings.ToLower(strings.TrimSpace(k.Operation)))
	k.Provider = redactor.SanitizeText(strings.ToLower(strings.TrimSpace(k.Provider)))
	k.Model = redactor.SanitizeText(strings.TrimSpace(k.Model))
	k.Endpoint = normalizeEndpoint(k.Endpoint)
	k.WireAPI = redactor.SanitizeText(strings.ToLower(strings.TrimSpace(k.WireAPI)))
	k.PromptSchema = redactor.SanitizeText(strings.TrimSpace(k.PromptSchema))
	k.RedactionSchema = redactor.SanitizeText(strings.TrimSpace(k.RedactionSchema))
	k.EvidenceDigest = strings.ToLower(strings.TrimSpace(redactor.SanitizeText(k.EvidenceDigest)))
	if k.EvidenceDigest != "" && (len(k.EvidenceDigest) != sha256.Size*2 || !isLowerHex(k.EvidenceDigest)) {
		digest := sha256.Sum256([]byte(k.EvidenceDigest))
		k.EvidenceDigest = hex.EncodeToString(digest[:])
	}
	k.PromptHash = strings.TrimSpace(k.PromptHash)
	if k.PromptHash == "" && k.Prompt != "" {
		digest := sha256.Sum256([]byte(redactor.SanitizeText(k.Prompt)))
		k.PromptHash = hex.EncodeToString(digest[:])
	}
	if k.EvidenceDigest == "" && k.PromptHash != "" {
		k.EvidenceDigest = k.PromptHash
	}
	if k.RedactionSchema == "" {
		k.RedactionSchema = sanitizer.RedactionSchema
	}
	k.Prompt = ""
	return k
}

// Validate checks the stable fields used to identify a cache entry.
func (k CacheKey) Validate() error {
	k = k.normalized()
	if k.Version != KeyVersion || k.Provider == "" || k.PromptSchema == "" {
		return ErrCacheInvalidKey
	}
	if k.PromptHash != "" && (len(k.PromptHash) != sha256.Size*2 || !isLowerHex(k.PromptHash)) {
		return ErrCacheInvalidKey
	}
	if k.EvidenceDigest != "" && (len(k.EvidenceDigest) != sha256.Size*2 || !isLowerHex(k.EvidenceDigest)) {
		return ErrCacheInvalidKey
	}
	return nil
}

// Canonical returns the exact versioned key material used for hashing.
func (k CacheKey) Canonical() ([]byte, error) {
	k = k.normalized()
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(k)
}

// Digest returns the SHA-256 identifier used for filenames and lookups.
// Invalid keys return an empty digest.
func (k CacheKey) Digest() string {
	canonical, err := k.Canonical()
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

// String is equivalent to Digest and is useful when logging cache metadata.
func (k CacheKey) String() string { return k.Digest() }

// CacheEntry is safe metadata for a stored result. It contains no prompt
// content or encryption key.
type CacheEntry struct {
	Digest    string    `json:"digest"`
	Key       CacheKey  `json:"key"`
	Size      int       `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Entry is a short alias for CacheEntry.
type Entry = CacheEntry

// CacheStats contains process-local counters for cache operations.
type CacheStats struct {
	Hits        uint64 `json:"hits"`
	Misses      uint64 `json:"misses"`
	Sets        uint64 `json:"sets"`
	Removes     uint64 `json:"removes"`
	Corruptions uint64 `json:"corruptions"`
}

type cacheCounters struct {
	hits        atomic.Uint64
	misses      atomic.Uint64
	sets        atomic.Uint64
	removes     atomic.Uint64
	corruptions atomic.Uint64
}

func (c *cacheCounters) stats() CacheStats {
	return CacheStats{
		Hits:        c.hits.Load(),
		Misses:      c.misses.Load(),
		Sets:        c.sets.Load(),
		Removes:     c.removes.Load(),
		Corruptions: c.corruptions.Load(),
	}
}

type cacheOptions struct {
	defaultTTL    time.Duration
	maxEntries    int
	maxValueBytes int
	clock         func() time.Time
}

func defaultCacheOptions() cacheOptions {
	return cacheOptions{
		defaultTTL:    DefaultTTL,
		maxEntries:    DefaultMaxEntries,
		maxValueBytes: DefaultMaxValueBytes,
		clock:         time.Now,
	}
}

// CacheOption configures a file cache without changing its security defaults.
type CacheOption func(*cacheOptions) error

func WithDefaultTTL(ttl time.Duration) CacheOption {
	return func(options *cacheOptions) error {
		if ttl <= 0 {
			return ErrCacheInvalidTTL
		}
		options.defaultTTL = ttl
		return nil
	}
}

func WithMaxEntries(max int) CacheOption {
	return func(options *cacheOptions) error {
		if max <= 0 || max > MaxAllowedEntries {
			return ErrCacheLimit
		}
		options.maxEntries = max
		return nil
	}
}

func WithMaxValueBytes(max int) CacheOption {
	return func(options *cacheOptions) error {
		if max <= 0 || max > MaxAllowedValueBytes {
			return ErrCacheValueTooLarge
		}
		options.maxValueBytes = max
		return nil
	}
}

func WithCacheClock(clock func() time.Time) CacheOption {
	return func(options *cacheOptions) error {
		if clock == nil {
			return errors.New("cache clock is required")
		}
		options.clock = clock
		return nil
	}
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func normalizeCacheContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func sanitizeCacheBytes(value []byte) []byte {
	return sanitizer.SanitizeBytes(value)
}

func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if parsed, err := url.Parse(endpoint); err == nil && parsed != nil && parsed.Scheme != "" && parsed.Host != "" {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		parsed.RawFragment = ""
		endpoint = parsed.String()
	}
	endpoint = sanitizer.DefaultRedactor().SanitizeText(endpoint)
	return strings.TrimRight(endpoint, "/")
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

type disabledCache struct {
	counters cacheCounters
}

// DisabledCache is an explicit no-persistence cache implementation.
type DisabledCache = disabledCache

func NewDisabledCache() *DisabledCache { return &disabledCache{} }

// NewNoopCache is an alias for NewDisabledCache.
func NewNoopCache() *DisabledCache { return NewDisabledCache() }

func (c *disabledCache) Get(ctx context.Context, _ CacheKey) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	c.counters.misses.Add(1)
	return nil, ErrCacheMiss
}

func (c *disabledCache) Lookup(ctx context.Context, key CacheKey) ([]byte, bool, error) {
	value, err := c.Get(ctx, key)
	return value, false, err
}

func (c *disabledCache) Set(ctx context.Context, _ CacheKey, _ []byte, _ ...time.Duration) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	return ErrCacheDisabled
}

func (c *disabledCache) Remove(ctx context.Context, _ CacheKey) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	return ErrCacheDisabled
}

func (c *disabledCache) List(ctx context.Context) ([]CacheEntry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return nil, nil
}

func (c *disabledCache) Purge(ctx context.Context) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	return ErrCacheDisabled
}

func (c *disabledCache) Stats() CacheStats { return c.counters.stats() }

func sortEntries(entries []CacheEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Digest < entries[j].Digest })
}
