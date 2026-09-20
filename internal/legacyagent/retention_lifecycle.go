package legacyagent

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// These stores own their locking and atomic persistence. No external file
// cleaner is permitted to race the scanner or pending remediation approvals.
type retentionSweeper interface {
	PruneRetention(time.Time) (int, error)
}

const retentionSweepInterval = 5 * time.Minute

// startRetentionWorkers sweeps even while no requests or scans arrive. A failed
// write is reported and retried on the next interval, never treated as success.
// The returned stop function is idempotent and joins before stores are closed.
func startRetentionWorkers(parent context.Context, stores map[string]any, interval time.Duration, report func(string, int, error)) (func(), error) {
	if interval <= 0 {
		return nil, fmt.Errorf("retention interval must be positive")
	}
	ctx, cancel := context.WithCancel(parent)
	names := make([]string, 0, len(stores))
	sweepers := make(map[string]retentionSweeper)
	for name, store := range stores {
		if sweeper, ok := store.(retentionSweeper); ok {
			names = append(names, name)
			sweepers[name] = sweeper
		}
	}
	sort.Strings(names)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			for _, name := range names {
				if ctx.Err() != nil {
					return
				}
				removed, err := sweepers[name].PruneRetention(time.Now().UTC())
				if report != nil {
					report(name, removed, err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); workers.Wait() }, nil
}
