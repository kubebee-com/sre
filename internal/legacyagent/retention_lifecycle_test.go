package legacyagent

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleRetentionStore struct {
	calls     atomic.Int32
	failFirst bool
}

func (s *lifecycleRetentionStore) PruneRetention(time.Time) (int, error) {
	n := s.calls.Add(1)
	if s.failFirst && n == 1 {
		return 0, errors.New("transient write failure")
	}
	return int(n), nil
}

func TestRetentionLifecycleSweepsIdleStoresAndRetriesErrors(t *testing.T) {
	store := &lifecycleRetentionStore{failFirst: true}
	results := make(chan error, 8)
	stop, err := startRetentionWorkers(context.Background(), map[string]any{"history": store, "unavailable": nil}, 10*time.Millisecond,
		func(_ string, _ int, err error) { results <- err })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if (i == 0) != (err != nil) {
				t.Fatalf("sweep %d: %v", i, err)
			}
		case <-time.After(time.Second):
			t.Fatal("idle store was not swept")
		}
	}
	stop()
	count := store.calls.Load()
	time.Sleep(25 * time.Millisecond)
	if store.calls.Load() != count {
		t.Fatal("sweep continued after shutdown")
	}
}

func TestRetentionLifecycleAlreadyCanceledDoesNotMutate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &lifecycleRetentionStore{}
	stop, err := startRetentionWorkers(ctx, map[string]any{"history": store}, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if store.calls.Load() != 0 {
		t.Fatal("canceled lifecycle mutated the store")
	}
}

func TestRetentionLifecycleRejectsUnboundedSchedule(t *testing.T) {
	if _, err := startRetentionWorkers(context.Background(), nil, 0, nil); err == nil {
		t.Fatal("zero interval accepted")
	}
}

func TestStandaloneEntrypointWiresRetentionBeforeClosingStores(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	start := strings.Index(s, "startRetentionWorkers(ctx,")
	shutdown := strings.Index(s, "Received termination signal")
	if start < 0 || shutdown < 0 {
		t.Fatal("standalone runtime has no retention lifecycle")
	}
	tail := s[shutdown:]
	stop := strings.Index(tail, "stopRetention()")
	closeStore := strings.Index(tail, "proposalStore.Close()")
	if stop < 0 || closeStore < stop {
		t.Fatal("retention must stop before storage closes")
	}
}
