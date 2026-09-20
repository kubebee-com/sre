package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const resolvedHistoryTTL = 72 * time.Hour
const maxInactiveHistoryEntries = 10000
const maxInactiveHistoryBytes = 128 << 20

func markHistoryResolved(entry HistoryEntry, now time.Time) HistoryEntry {
	if !entry.Resolved || entry.ResolvedAt.IsZero() {
		entry.ResolvedAt = now
	}
	entry.Resolved = true
	return entry
}

// pruneHistory modifies a caller-owned copy. Active findings and coverage
// watermarks remain untouched so an old scan cannot resurrect a removed finding.
// Legacy resolved rows receive a full grace period rather than immediate expiry.
func pruneHistory(entries map[string]HistoryEntry, now time.Time) (int, bool, error) {
	type candidate struct {
		key  string
		at   time.Time
		size int
	}
	candidates := make([]candidate, 0)
	removed, bytes, changed := 0, 0, false
	for key, entry := range entries {
		if !entry.Resolved {
			continue
		}
		if entry.ResolvedAt.IsZero() {
			entry.ResolvedAt = now
			entries[key] = entry
			changed = true
		}
		if entry.ResolvedAt.After(now) {
			continue
		}
		if now.Sub(entry.ResolvedAt) >= resolvedHistoryTTL {
			delete(entries, key)
			removed++
			changed = true
			continue
		}
		data, err := json.MarshalIndent(entry, "    ", "  ")
		if err != nil {
			return 0, false, fmt.Errorf("measure inactive history: %w", err)
		}
		encodedKey, _ := json.Marshal(key)
		size := len(data) + len(encodedKey) + 12
		candidates = append(candidates, candidate{key, entry.ResolvedAt, size})
		bytes += size
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].key < candidates[j].key
		}
		return candidates[i].at.Before(candidates[j].at)
	})
	remaining := len(candidates)
	for _, c := range candidates {
		if remaining <= maxInactiveHistoryEntries && bytes <= maxInactiveHistoryBytes {
			break
		}
		delete(entries, c.key)
		removed++
		remaining--
		bytes -= c.size
		changed = true
	}
	return removed, changed, nil
}

func (s *FileHistoryStore) pruneRetentionLocked(now time.Time) (int, error) {
	entries := copyHistoryMap(s.entries)
	removed, changed, err := pruneHistory(entries, now)
	if err != nil || !changed {
		return removed, err
	}
	if err := s.writeLocked(entries, s.coverage); err != nil {
		return 0, err
	}
	s.entries = entries
	return removed, nil
}

// PruneRetention persists expiry without depending on a subsequent scan/write.
func (s *FileHistoryStore) PruneRetention(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneRetentionLocked(now)
}

func (s *MemoryHistoryStore) PruneRetention(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := copyHistoryMap(s.entries)
	removed, _, err := pruneHistory(entries, now)
	if err == nil {
		s.entries = entries
	}
	return removed, err
}

// RunRetention is started by the owner with its lifecycle context. Returning an
// error prevents a persistence failure being mistaken for successful expiry.
func (s *FileHistoryStore) RunRetention(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("retention interval must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := s.PruneRetention(time.Now().UTC()); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
