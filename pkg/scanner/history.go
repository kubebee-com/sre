package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

const historySchemaVersion = "scan-history/v1"

type HistoryEntry struct {
	SchemaVersion       string          `json:"schema_version"`
	Fingerprint         string          `json:"fingerprint"`
	Issue               *SanitizedIssue `json:"issue"`
	FirstSeen           time.Time       `json:"first_seen"`
	LastSeen            time.Time       `json:"last_seen"`
	Occurrences         int             `json:"occurrences"`
	LastReportStartedAt time.Time       `json:"last_report_started_at,omitempty"`
	Resolved            bool            `json:"resolved"`
}

type HistoryStore interface {
	Record([]*Issue) error
	List() ([]HistoryEntry, error)
	Close() error
}

// ReportHistoryStore reconciles only successfully observed scan coverage.
type ReportHistoryStore interface {
	HistoryStore
	RecordReport(*ScanReport) error
}

// HistoryCoverage exposes the most recent execution for each distinct scope.
// Failed executions remain visible but cannot resolve findings.
type HistoryCoverage struct {
	Scope      scanplan.EffectiveScope `json:"scope"`
	Analyzers  []AnalyzerRun           `json:"analyzers"`
	StartedAt  time.Time               `json:"started_at"`
	FinishedAt time.Time               `json:"finished_at"`
	Error      string                  `json:"error,omitempty"`
}

type historyState struct {
	Coverage      map[string]HistoryCoverage `json:"coverage,omitempty"`
	SchemaVersion string                     `json:"schema_version"`
	Entries       map[string]HistoryEntry    `json:"entries"`
}

type MemoryHistoryStore struct {
	mu       sync.RWMutex
	entries  map[string]HistoryEntry
	coverage map[string]HistoryCoverage
}

func NewMemoryHistoryStore() *MemoryHistoryStore {
	return &MemoryHistoryStore{entries: make(map[string]HistoryEntry)}
}

func (s *MemoryHistoryStore) Record(issues []*Issue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return recordHistory(s.entries, issues)
}

func (s *MemoryHistoryStore) List() ([]HistoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneHistoryEntries(s.entries), nil
}

func (s *MemoryHistoryStore) ListLimit(limit int) ([]HistoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneHistoryEntriesLimit(s.entries, limit), nil
}

func (s *MemoryHistoryStore) Close() error { return nil }

type FileHistoryStore struct {
	mu       sync.RWMutex
	path     string
	entries  map[string]HistoryEntry
	coverage map[string]HistoryCoverage
}

func NewFileHistoryStore(directory string) (*FileHistoryStore, error) {
	if directory == "" {
		return nil, fmt.Errorf("history directory is required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create history directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("restrict history directory: %w", err)
	}
	store := &FileHistoryStore{path: filepath.Join(directory, "scan-history.json"), entries: make(map[string]HistoryEntry)}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileHistoryStore) Record(issues []*Issue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := copyHistoryMap(s.entries)
	if err := recordHistory(entries, issues); err != nil {
		return err
	}
	if err := s.writeLocked(entries, s.coverage); err != nil {
		return err
	}
	s.entries = entries
	return nil
}

func (s *FileHistoryStore) List() ([]HistoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneHistoryEntries(s.entries), nil
}

func (s *FileHistoryStore) ListLimit(limit int) ([]HistoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneHistoryEntriesLimit(s.entries, limit), nil
}

func (s *FileHistoryStore) Close() error { return nil }

func (s *FileHistoryStore) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read scan history: %w", err)
	}
	var state historyState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode scan history: %w", err)
	}
	if state.SchemaVersion != historySchemaVersion {
		return fmt.Errorf("unsupported scan history schema %q", state.SchemaVersion)
	}
	s.coverage = state.Coverage
	if state.Entries != nil {
		s.entries = state.Entries
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("restrict scan history: %w", err)
	}
	return nil
}

func (s *FileHistoryStore) writeLocked(entries map[string]HistoryEntry, coverage map[string]HistoryCoverage) error {
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".scan-history-*.tmp")
	if err != nil {
		return fmt.Errorf("create scan history temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("restrict scan history temporary file: %w", err)
	}
	state := historyState{SchemaVersion: historySchemaVersion, Entries: entries, Coverage: coverage}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(state); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("encode scan history: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync scan history: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close scan history: %w", err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		return fmt.Errorf("replace scan history: %w", err)
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return fmt.Errorf("open history directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync history directory: %w", err)
	}
	return nil
}

func recordHistory(entries map[string]HistoryEntry, issues []*Issue) error {
	now := time.Now().UTC()
	for fingerprint, entry := range entries {
		entry.Resolved = true
		entries[fingerprint] = entry
	}
	for _, issue := range issues {
		if issue == nil {
			continue
		}
		fingerprint := issueFingerprint(issue)
		entry, ok := entries[fingerprint]
		if !ok {
			entry = HistoryEntry{SchemaVersion: historySchemaVersion, Fingerprint: fingerprint, FirstSeen: now}
		}
		entry.SchemaVersion = historySchemaVersion
		entry.LastSeen = now
		entry.Occurrences++
		entry.Resolved = false
		entry.Issue = SanitizeIssue(issue)
		entries[fingerprint] = entry
	}
	return nil
}

func cloneHistoryEntries(entries map[string]HistoryEntry) []HistoryEntry {
	return cloneHistoryEntriesLimit(entries, 0)
}

func cloneHistoryEntriesLimit(entries map[string]HistoryEntry, limit int) []HistoryEntry {
	keys := make([]string, 0, len(entries))
	for fingerprint := range entries {
		keys = append(keys, fingerprint)
	}
	sort.Strings(keys)
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	result := make([]HistoryEntry, 0, len(keys))
	for _, fingerprint := range keys {
		entry := entries[fingerprint]
		if entry.Issue != nil {
			copy := *entry.Issue
			copy.AnalyzerNames = append([]string(nil), entry.Issue.AnalyzerNames...)
			copy.Events = append([]string(nil), entry.Issue.Events...)
			if entry.Issue.Parent != nil {
				parent := *entry.Issue.Parent
				copy.Parent = &parent
			}
			entry.Issue = &copy
		}
		result = append(result, entry)
	}
	return result
}

func issueFingerprint(issue *Issue) string {
	if issue.ID != "" {
		digest := sha256.Sum256([]byte(issue.ID + "\x00" + string(issue.Category) + uidFingerprintSuffix(issue.TargetUID)))
		return hex.EncodeToString(digest[:])
	}
	digest := sha256.Sum256([]byte(issue.Namespace + "\x00" + issue.Kind + "\x00" + issue.Name + "\x00" + string(issue.Category) + uidFingerprintSuffix(issue.TargetUID)))
	return hex.EncodeToString(digest[:])
}
