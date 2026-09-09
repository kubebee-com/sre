package cache

import (
	"context"
	"errors"
	"time"
)

// OperationObserver receives bounded cache operation outcomes. Implementations
// should treat operation and status as low-cardinality labels.
type OperationObserver interface {
	ObserveCacheOperation(operation, status string)
}

// ObservedCache decorates a cache with operation notifications without
// changing its persistence or error behavior.
type ObservedCache struct {
	delegate Cache
	observer OperationObserver
}

// NewObservedCache adds an observer when both dependencies are present. A
// cache without an observer is returned unchanged so instrumentation remains
// optional for library callers and command-line use.
func NewObservedCache(delegate Cache, observer OperationObserver) Cache {
	if delegate == nil || observer == nil {
		return delegate
	}
	return &ObservedCache{delegate: delegate, observer: observer}
}

func (c *ObservedCache) Get(ctx context.Context, key CacheKey) ([]byte, error) {
	value, err := c.delegate.Get(ctx, key)
	c.observeLookup(err == nil, err)
	return value, err
}

func (c *ObservedCache) Set(ctx context.Context, key CacheKey, value []byte, ttl ...time.Duration) error {
	err := c.delegate.Set(ctx, key, value, ttl...)
	c.observe("set", operationStatus(err))
	return err
}

func (c *ObservedCache) Lookup(ctx context.Context, key CacheKey) ([]byte, bool, error) {
	value, found, err := c.delegate.Lookup(ctx, key)
	if err != nil {
		c.observe("lookup", operationStatus(err))
	} else if found {
		c.observe("lookup", "hit")
	} else {
		c.observe("lookup", "miss")
	}
	return value, found, err
}

func (c *ObservedCache) Remove(ctx context.Context, key CacheKey) error {
	err := c.delegate.Remove(ctx, key)
	c.observe("remove", operationStatus(err))
	return err
}

func (c *ObservedCache) List(ctx context.Context) ([]CacheEntry, error) {
	entries, err := c.delegate.List(ctx)
	c.observe("list", operationStatus(err))
	return entries, err
}

func (c *ObservedCache) Purge(ctx context.Context) error {
	err := c.delegate.Purge(ctx)
	c.observe("purge", operationStatus(err))
	return err
}

func (c *ObservedCache) Stats() CacheStats { return c.delegate.Stats() }

func (c *ObservedCache) observeLookup(hit bool, err error) {
	if err != nil {
		c.observe("get", operationStatus(err))
		return
	}
	if hit {
		c.observe("get", "hit")
		return
	}
	c.observe("get", "miss")
}

func (c *ObservedCache) observe(operation, status string) {
	if c == nil || c.observer == nil {
		return
	}
	// Metrics are a side effect and must never alter cache behavior if an
	// embedding observer has a bug.
	defer func() { _ = recover() }()
	c.observer.ObserveCacheOperation(operation, status)
}

func operationStatus(err error) string {
	if err == nil {
		return "success"
	}
	if errors.Is(err, ErrCacheMiss) {
		return "miss"
	}
	return "error"
}
