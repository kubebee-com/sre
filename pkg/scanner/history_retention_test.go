package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type historySweeper interface{ PruneRetention(time.Time) (int, error) }

func TestHistoryRetentionCanceledWorkerDoesNotPrune(t *testing.T) {
	s, err := NewFileHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.entries["old"] = HistoryEntry{Resolved: true, ResolvedAt: time.Now().Add(-73 * time.Hour)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.RunRetention(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation: %v", err)
	}
	if len(s.entries) != 1 {
		t.Fatal("canceled worker still changed history")
	}
}

func TestHistoryRetentionCountBudgetKeepsActiveFinding(t *testing.T) {
	s := NewMemoryHistoryStore()
	now := time.Now().UTC()
	s.entries["active"] = HistoryEntry{Resolved: false, LastSeen: now.Add(-30 * 24 * time.Hour)}
	for i := 0; i < maxInactiveHistoryEntries+1; i++ {
		s.entries[fmt.Sprintf("resolved-%05d", i)] = HistoryEntry{Resolved: true, ResolvedAt: now.Add(-time.Hour)}
	}
	removed, err := s.PruneRetention(now)
	if err != nil || removed != 1 || len(s.entries) != maxInactiveHistoryEntries+1 {
		t.Fatalf("budget result removed=%d err=%v", removed, err)
	}
	if _, ok := s.entries["active"]; !ok {
		t.Fatal("active finding was discarded")
	}
}

func TestHistoryRetentionRecordsFirstResolutionAndClearsOnReappearance(t *testing.T) {
	s := NewMemoryHistoryStore()
	issue := &Issue{ID: "one", Category: CategoryPodFailed}
	if err := s.Record([]*Issue{issue}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(nil); err != nil {
		t.Fatal(err)
	}
	entries, _ := s.List()
	raw, _ := json.Marshal(entries[0])
	var row map[string]interface{}
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	first, ok := row["resolved_at"].(string)
	if !ok || first == "" || first == "0001-01-01T00:00:00Z" {
		t.Fatal("first resolution timestamp is missing")
	}
	if err := s.Record(nil); err != nil {
		t.Fatal(err)
	}
	entries, _ = s.List()
	raw, _ = json.Marshal(entries[0])
	_ = json.Unmarshal(raw, &row)
	if row["resolved_at"] != first {
		t.Fatal("repeated absence reset the TTL")
	}
	if err := s.Record([]*Issue{issue}); err != nil {
		t.Fatal(err)
	}
	entries, _ = s.List()
	raw, _ = json.Marshal(entries[0])
	row = nil
	_ = json.Unmarshal(raw, &row)
	if entries[0].Resolved || (row["resolved_at"] != nil && row["resolved_at"] != "0001-01-01T00:00:00Z") {
		t.Fatal("reappearance retained a resolution timestamp")
	}
}

func TestHistoryRetentionPersistsExpiryWithoutDeletingActiveOrLegacyRows(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	row := func(resolved bool, at interface{}) map[string]interface{} {
		return map[string]interface{}{"schema_version": historySchemaVersion, "resolved": resolved, "resolved_at": at, "last_seen": now.Add(-30 * 24 * time.Hour)}
	}
	state := map[string]interface{}{"schema_version": historySchemaVersion, "entries": map[string]interface{}{
		"old": row(true, now.Add(-73*time.Hour)), "recent": row(true, now.Add(-2*time.Hour)),
		"active": row(false, time.Time{}), "legacy": row(true, time.Time{}), "future": row(true, now.Add(time.Hour)),
	}}
	raw, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(dir, "scan-history.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewFileHistoryStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sweeper, ok := interface{}(s).(historySweeper)
	if !ok {
		t.Fatal("atomic history retention sweep missing")
	}
	if _, err := sweeper.PruneRetention(now); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "scan-history.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored historyState
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if _, exists := stored.Entries["old"]; exists {
		t.Fatal("expired finding still persisted")
	}
	for _, key := range []string{"recent", "active", "legacy", "future"} {
		if _, exists := stored.Entries[key]; !exists {
			t.Fatalf("deleted protected row %s", key)
		}
	}
}

func TestHistoryRetentionFailureLeavesMemoryAndDiskUnchanged(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileHistoryStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	sweeper, ok := interface{}(s).(historySweeper)
	if !ok {
		t.Fatal("retention sweep missing")
	}
	raw := []byte(`{"schema_version":"scan-history/v1","resolved":true,"resolved_at":"2020-01-01T00:00:00Z"}`)
	var entry HistoryEntry
	_ = json.Unmarshal(raw, &entry)
	s.entries["old"] = entry
	s.path = filepath.Join(dir, "missing-parent", "state.json")
	if _, err := sweeper.PruneRetention(time.Now()); err == nil {
		t.Fatal("persistence failure was hidden")
	}
	if _, ok := s.entries["old"]; !ok {
		t.Fatal("memory changed although persistence failed")
	}
}
