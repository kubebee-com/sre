package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileHistoryStorePersistsSanitizedResolvedFindings(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFileHistoryStore(directory)
	if err != nil {
		t.Fatalf("NewFileHistoryStore() error = %v", err)
	}
	issue := &Issue{ID: "finding-1", Namespace: "prod", Kind: "Pod", Name: "worker", Category: CategoryCrashLoop, Summary: "token=history-secret"}
	if err := store.Record([]*Issue{issue}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	entries, err := store.List()
	if err != nil || len(entries) != 1 {
		t.Fatalf("List() = %#v, %v", entries, err)
	}
	if strings.Contains(entries[0].Issue.Summary, "history-secret") {
		t.Fatal("history stored an unsanitized finding")
	}
	mode, err := os.Stat(filepath.Join(directory, "scan-history.json"))
	if err != nil {
		t.Fatalf("stat history file: %v", err)
	}
	if mode.Mode().Perm() != 0o600 {
		t.Fatalf("history file mode = %o, want 600", mode.Mode().Perm())
	}

	reopened, err := NewFileHistoryStore(directory)
	if err != nil {
		t.Fatalf("reopen history: %v", err)
	}
	if err := reopened.Record(nil); err != nil {
		t.Fatalf("Record(nil) error = %v", err)
	}
	entries, err = reopened.List()
	if err != nil || len(entries) != 1 || !entries[0].Resolved {
		t.Fatalf("resolved history = %#v, %v", entries, err)
	}
}

func TestMemoryHistoryStoreIncrementsOccurrences(t *testing.T) {
	store := NewMemoryHistoryStore()
	issue := &Issue{ID: "finding-1", Category: CategoryPodFailed}
	if err := store.Record([]*Issue{issue}); err != nil {
		t.Fatal(err)
	}
	if err := store.Record([]*Issue{issue}); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil || len(entries) != 1 || entries[0].Occurrences != 2 {
		t.Fatalf("history entries = %#v, %v", entries, err)
	}
}

func TestHistoryStoreListLimitBoundsProjection(t *testing.T) {
	store := NewMemoryHistoryStore()
	for _, id := range []string{"finding-a", "finding-b", "finding-c"} {
		if err := store.Record([]*Issue{{ID: id, Category: CategoryPodFailed}}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := store.ListLimit(2)
	if err != nil || len(entries) != 2 {
		t.Fatalf("ListLimit() = %#v, %v; want two bounded entries", entries, err)
	}
}
