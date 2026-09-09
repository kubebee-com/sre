package cache

import (
	"context"
	"testing"
)

type operationObserver struct {
	operations [][2]string
}

func (o *operationObserver) ObserveCacheOperation(operation, status string) {
	o.operations = append(o.operations, [2]string{operation, status})
}

func TestObservedCacheReportsLookupOutcomesWithoutChangingResults(t *testing.T) {
	delegate, err := NewFileCache(t.TempDir(), []byte("cache-test-key"))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	observer := &operationObserver{}
	observed := NewObservedCache(delegate, observer)
	key := NewCacheKey("provider", "model", "endpoint", "schema", "prompt")

	if _, found, err := observed.Lookup(context.Background(), key); found || err != nil {
		t.Fatalf("Lookup() = found %v, err %v; want miss", found, err)
	}
	if err := observed.Set(context.Background(), key, []byte("value")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	value, found, err := observed.Lookup(context.Background(), key)
	if err != nil || !found || string(value) != "value" {
		t.Fatalf("Lookup() = %q, %v, %v; want value hit", value, found, err)
	}

	want := [][2]string{{"lookup", "miss"}, {"set", "success"}, {"lookup", "hit"}}
	if len(observer.operations) != len(want) {
		t.Fatalf("observed operations = %#v, want %#v", observer.operations, want)
	}
	for index := range want {
		if observer.operations[index] != want[index] {
			t.Errorf("operation %d = %#v, want %#v", index, observer.operations[index], want[index])
		}
	}
}

func TestObservedCacheObserverPanicDoesNotChangeCacheBehavior(t *testing.T) {
	delegate, err := NewFileCache(t.TempDir(), []byte("cache-test-key"))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	observed := NewObservedCache(delegate, panicObserver{})
	key := NewCacheKey("provider", "model", "endpoint", "schema", "prompt")
	if err := observed.Set(context.Background(), key, []byte("value")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if value, err := observed.Get(context.Background(), key); err != nil || string(value) != "value" {
		t.Fatalf("Get() = %q, %v; want value", value, err)
	}
}

type panicObserver struct{}

func (panicObserver) ObserveCacheOperation(string, string) { panic("observer failure") }
