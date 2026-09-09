package scanner

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

func uidFingerprintSuffix(uid string) string {
	if uid == "" {
		return ""
	}
	return "\x00" + uid
}
func copyHistoryMap(entries map[string]HistoryEntry) map[string]HistoryEntry {
	result := make(map[string]HistoryEntry, len(entries))
	for k, v := range entries {
		result[k] = v
	}
	return result
}
func copyCoverage(coverage map[string]HistoryCoverage) map[string]HistoryCoverage {
	result := make(map[string]HistoryCoverage, len(coverage))
	for k, v := range coverage {
		result[k] = v
	}
	return result
}
func (s *MemoryHistoryStore) RecordReport(report *ScanReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coverage == nil {
		s.coverage = map[string]HistoryCoverage{}
	}
	reconcileReport(s.entries, s.coverage, report)
	return nil
}
func (s *FileHistoryStore) RecordReport(report *ScanReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, coverage := copyHistoryMap(s.entries), copyCoverage(s.coverage)
	if !reconcileReport(entries, coverage, report) {
		return nil
	}
	if err := s.writeLocked(entries, coverage); err != nil {
		return err
	}
	s.entries, s.coverage = entries, coverage
	return nil
}

// Coverage includes unsuccessful execution attempts for freshness displays.
func (s *MemoryHistoryStore) Coverage() []HistoryCoverage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCoverage(s.coverage)
}
func (s *FileHistoryStore) Coverage() []HistoryCoverage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCoverage(s.coverage)
}
func cloneCoverage(coverage map[string]HistoryCoverage) []HistoryCoverage {
	keys := make([]string, 0, len(coverage))
	for k := range coverage {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	result := make([]HistoryCoverage, 0, len(keys))
	for _, k := range keys {
		var c HistoryCoverage
		b, _ := json.Marshal(coverage[k])
		_ = json.Unmarshal(b, &c)
		result = append(result, c)
	}
	return result
}
func coveragePlan(c HistoryCoverage) scanplan.Plan {
	return scanplan.Plan{IncludeNamespaces: c.Scope.IncludeNamespaces, ExcludeNamespaces: c.Scope.ExcludeNamespaces, Kinds: c.Scope.Kinds, Names: c.Scope.Names, Analyzers: c.Scope.Analyzers, LabelSelector: c.Scope.LabelSelector}
}

// coveredBy requires successful coverage of every contributing analyzer.
func coveredBy(c HistoryCoverage, issue *Issue) bool {
	if c.Scope.SchemaVersion != scanplan.SchemaVersion || c.Error != "" || c.Scope.LabelSelector != "" || len(issue.AnalyzerNames) == 0 || !issueMatchesPlan(coveragePlan(c), issue) {
		return false
	}
	observed := 0
	for _, name := range issue.AnalyzerNames {
		for _, run := range c.Analyzers {
			if run.Error == "" && strings.EqualFold(run.Info.Name, name) && coveragePlan(c).IncludesAnalyzer(name) {
				observed++
				break
			}
		}
	}
	return observed == len(issue.AnalyzerNames)
}
func reconcileReport(entries map[string]HistoryEntry, coverage map[string]HistoryCoverage, report *ScanReport) bool {
	if report == nil {
		return false
	}
	// Missing ordering metadata cannot safely replace existing observations.
	if report.StartedAt.IsZero() {
		return false
	}
	scopeJSON, _ := json.Marshal(report.Scope)
	// Runs are part of the key: a failed execution must not erase a successful
	// observation needed to reject an older completion.
	runs := append([]AnalyzerRun(nil), report.Analyzers...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].Info.Name < runs[j].Info.Name })
	key := string(scopeJSON) + "|" + report.Error
	for _, run := range runs {
		key += "|" + run.Info.Name + ":" + run.Error
	}
	if previous, ok := coverage[key]; ok && !report.StartedAt.After(previous.StartedAt) {
		return false
	}
	c := HistoryCoverage{Scope: report.Scope, Analyzers: runs, StartedAt: report.StartedAt, FinishedAt: report.FinishedAt, Error: report.Error}
	// Detach caller-owned slices, including scope, before publishing metadata.
	data, _ := json.Marshal(c)
	var detached HistoryCoverage
	_ = json.Unmarshal(data, &detached)
	c = detached
	for key, entry := range entries {
		if entry.Issue != nil && report.StartedAt.After(entry.LastReportStartedAt) && coveredBy(c, entry.Issue.AsIssue()) {
			entry.Resolved = true
			entry.LastReportStartedAt = report.StartedAt
			entries[key] = entry
		}
	}
	for _, raw := range deduplicateIssuesCopy(report.Issues) {
		fingerprint := issueFingerprint(raw)
		entry, exists := entries[fingerprint]
		if exists && entry.LastReportStartedAt.After(report.StartedAt) {
			continue
		}
		stale := false
		// A newer positive observation identifies the object even when selector
		// membership is unavailable and the UID changed between executions.
		for _, newer := range entries {
			if newer.Issue != nil && newer.LastReportStartedAt.After(report.StartedAt) &&
				newer.Issue.Namespace == raw.Namespace && newer.Issue.Kind == raw.Kind &&
				newer.Issue.Name == raw.Name && newer.Issue.TargetUID != "" && raw.TargetUID != "" && newer.Issue.TargetUID != raw.TargetUID {
				stale = true
				break
			}
		}
		for _, newer := range coverage {
			if !newer.StartedAt.Before(report.StartedAt) && coveredBy(newer, raw) {
				stale = true
				break
			}
		}
		if stale {
			continue
		}
		if !exists {
			entry = HistoryEntry{SchemaVersion: historySchemaVersion, Fingerprint: fingerprint, FirstSeen: report.FinishedAt}
		}
		if entry.Issue != nil {
			raw.AnalyzerNames = appendUniqueField(raw.AnalyzerNames, entry.Issue.AnalyzerNames...)
		}
		entry.Issue = SanitizeIssue(raw)
		entry.Resolved = false
		entry.LastSeen = report.FinishedAt
		entry.LastReportStartedAt = report.StartedAt
		entry.Occurrences++
		entries[fingerprint] = entry
	}
	coverage[key] = c
	return true
}
func deduplicateIssuesCopy(issues []*Issue) []*Issue {
	copies := make([]*Issue, 0, len(issues))
	for _, issue := range issues {
		copies = append(copies, cloneIssue(issue))
	}
	return deduplicateIssues(copies)
}

// Legacy implementations have no coverage contract. Preserve unresolved rows
// and submit a conservative snapshot rather than guessing which rows resolved.
func recordScanReport(store HistoryStore, report *ScanReport) error {
	if store == nil {
		return nil
	}
	if aware, ok := store.(ReportHistoryStore); ok {
		return aware.RecordReport(report)
	}
	rows, err := store.List()
	if err != nil {
		return err
	}
	byFingerprint := make(map[string]*Issue)
	for _, issue := range report.Issues {
		if issue != nil {
			byFingerprint[issueFingerprint(issue)] = cloneIssue(issue)
		}
	}
	for _, row := range rows {
		if row.Resolved || row.Issue == nil {
			continue
		}
		previous := row.Issue.AsIssue()
		key := issueFingerprint(previous)
		incoming, exists := byFingerprint[key]
		if !exists || !report.StartedAt.After(row.LastSeen) {
			byFingerprint[key] = previous
		} else {
			incoming.AnalyzerNames = appendUniqueField(incoming.AnalyzerNames, previous.AnalyzerNames...)
		}
	}
	issues := make([]*Issue, 0, len(byFingerprint))
	for _, issue := range byFingerprint {
		issues = append(issues, issue)
	}
	return store.Record(deduplicateIssuesCopy(issues))
}

// Serialize the legacy List/Record transaction across typed and dynamic entry points.
func (s *ClusterScanner) recordReport(report *ScanReport) error {
	s.historyRecordMu.Lock()
	defer s.historyRecordMu.Unlock()
	return recordScanReport(s.history, report)
}
