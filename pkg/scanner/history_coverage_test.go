package scanner

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/scanplan"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The assertion keeps this reproduction runnable against legacy stores.
func recordCoverage(t *testing.T, s HistoryStore, r *ScanReport) {
	t.Helper()
	aware, ok := s.(interface{ RecordReport(*ScanReport) error })
	if !ok {
		t.Fatal("history cannot record observed report coverage")
	}
	if err := aware.RecordReport(r); err != nil {
		t.Fatal(err)
	}
}
func coverageReport(at int64, p scanplan.Plan, issues ...*Issue) *ScanReport {
	return &ScanReport{Scope: p.EffectiveScope(), Issues: issues, StartedAt: time.Unix(at, 0), FinishedAt: time.Unix(at+1, 0), Analyzers: []AnalyzerRun{{Info: AnalyzerInfo{Name: "PodAnalyzer", Resource: "Pod"}}}}
}
func coverageIssue(ns, name string) *Issue {
	return &Issue{AnalyzerNames: []string{"PodAnalyzer"}, ID: ns + "/" + name, Namespace: ns, Kind: "Pod", Name: name, Category: CategoryPodFailed}
}
func activeHistory(t *testing.T, s HistoryStore) map[string]*SanitizedIssue {
	t.Helper()
	rows, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*SanitizedIssue{}
	for _, row := range rows {
		if !row.Resolved {
			out[row.Issue.Namespace+"/"+row.Issue.Name] = row.Issue
		}
	}
	return out
}
func TestCoverageHistoryPreservesUnobserved(t *testing.T) {
	for _, tc := range []struct {
		name    string
		plan    scanplan.Plan
		failure bool
		want    int
	}{
		{"namespace", scanplan.Plan{IncludeNamespaces: []string{"a"}}, false, 1},
		{"name", scanplan.Plan{Names: []string{"one"}}, false, 1},
		{"excluded", scanplan.Plan{ExcludeNamespaces: []string{"b"}}, false, 1},
		{"kind", scanplan.Plan{Kinds: []string{"Service"}}, false, 2},
		{"analyzer", scanplan.Plan{Analyzers: []string{"LogAnalyzer"}}, false, 2},
		{"label", scanplan.Plan{LabelSelector: "app=one"}, false, 2},
		{"failed", scanplan.Default(), true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMemoryHistoryStore()
			recordCoverage(t, s, coverageReport(10, scanplan.Default(), coverageIssue("a", "one"), coverageIssue("b", "two")))
			r := coverageReport(20, tc.plan)
			if tc.failure {
				r.Analyzers[0].Error = "forbidden"
			}
			recordCoverage(t, s, r)
			if got := len(activeHistory(t, s)); got != tc.want {
				t.Fatalf("active = %d, want %d", got, tc.want)
			}
		})
	}
}
func TestCoverageHistoryRepeatedAndOldReports(t *testing.T) {
	s := NewMemoryHistoryStore()
	r := coverageReport(10, scanplan.Default(), coverageIssue("a", "one"))
	recordCoverage(t, s, r)
	recordCoverage(t, s, r)
	rows, _ := s.List()
	if rows[0].Occurrences != 1 {
		t.Fatal("repeated report incremented occurrence")
	}
	recordCoverage(t, s, coverageReport(20, scanplan.Default()))
	recordCoverage(t, s, r)
	if len(activeHistory(t, s)) != 0 {
		t.Fatal("older report resurrected resolved issue")
	}
}
func TestFileHistoryFailedWriteDoesNotPublish(t *testing.T) {
	s, err := NewFileHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Record([]*Issue{coverageIssue("a", "one")}); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(t.TempDir(), "missing", "history.json")
	if err = s.Record(nil); err == nil {
		t.Fatal("expected failed persistence")
	}
	if len(activeHistory(t, s)) != 1 {
		t.Fatal("failed write mutated published history")
	}

}

type coverageAnalyzer struct {
	issues []*Issue
	err    error
}

func (a *coverageAnalyzer) Info() AnalyzerInfo {
	return AnalyzerInfo{Name: "CoverageTestAnalyzer", Resource: "Pod", Description: "coverage test"}
}
func (a *coverageAnalyzer) Analyze(context.Context, string) ([]*Issue, error) { return a.issues, a.err }
func TestRuntimeCoveragePreservesOtherNamespaceAndFailure(t *testing.T) {
	store := NewMemoryHistoryStore()
	s := NewClusterScannerWithHistory(nil, store)
	a := &coverageAnalyzer{issues: []*Issue{coverageIssue("a", "one"), coverageIssue("b", "two")}}
	for _, i := range a.issues {
		i.AnalyzerNames = nil
	}
	if err := s.RegisterAnalyzer(a); err != nil {
		t.Fatal(err)
	}
	p := scanPlanForAnalyzer(a.Info().Name)
	if _, err := s.ScanWithPlan(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p.IncludeNamespaces = []string{"a"}
	a.issues = nil
	if _, err := s.ScanWithPlan(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	active := activeHistory(t, store)
	if len(active) != 1 || active["b/two"] == nil {
		t.Fatalf("targeted scan lost unrelated finding: %#v", active)
	}
	p.IncludeNamespaces = nil
	a.err = errors.New("forbidden")
	if _, err := s.ScanWithPlan(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(activeHistory(t, store)) != 1 {
		t.Fatal("failed analyzer resolved finding")
	}
}
func TestCoverageProvenanceUnionAndCopy(t *testing.T) {
	a, b := coverageIssue("a", "one"), coverageIssue("a", "one")
	b.AnalyzerNames = []string{"EventAnalyzer"}
	issues := deduplicateIssues([]*Issue{a, b})
	if len(issues) != 1 || len(issues[0].AnalyzerNames) != 2 {
		t.Fatalf("lost analyzer provenance: %#v", issues)
	}
	c := cloneIssue(issues[0])
	c.AnalyzerNames[0] = "changed"
	if issues[0].AnalyzerNames[0] == "changed" {
		t.Fatal("copy aliases provenance")
	}
}
func TestCoverageRestartUIDAndWriteFailure(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileHistoryStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := coverageIssue("a", "one")
	old.TargetUID = "old"
	recordCoverage(t, store, coverageReport(10, scanplan.Default(), old))
	recreated := coverageIssue("a", "one")
	recreated.TargetUID = "new"
	recordCoverage(t, store, coverageReport(20, scanplan.Default(), recreated))
	store, err = NewFileHistoryStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	recordCoverage(t, store, coverageReport(10, scanplan.Default(), old))
	rows, _ := store.List()
	if len(rows) != 2 || len(activeHistory(t, store)) != 1 || activeHistory(t, store)["a/one"].TargetUID != "new" {
		t.Fatalf("recreation/restart state = %#v", rows)
	}
	store.path = filepath.Join(t.TempDir(), "missing", "history.json")
	if err := store.RecordReport(coverageReport(30, scanplan.Default())); err == nil {
		t.Fatal("expected persistence failure")
	}
	if len(activeHistory(t, store)) != 1 {
		t.Fatal("report write failure changed published state")
	}
}

type countedReportHistory struct {
	*MemoryHistoryStore
	reports int
	legacy  int
	last    *ScanReport
}

func (s *countedReportHistory) RecordReport(r *ScanReport) error {
	s.reports++
	s.last = r
	return s.MemoryHistoryStore.RecordReport(r)
}
func (s *countedReportHistory) Record(i []*Issue) error {
	s.legacy++
	return s.MemoryHistoryStore.Record(i)
}
func TestDynamicFacadePersistsCombinedReportOnce(t *testing.T) {
	s := NewClusterScannerWithDynamicClient(nil, newDynamicTestClient(dynamicObject(gatewayClassGVR, "", "edge", map[string]interface{}{"spec": map[string]interface{}{"controllerName": "example.net/controller"}, "status": map[string]interface{}{"conditions": []interface{}{map[string]interface{}{"type": "Accepted", "status": "False"}}}})))
	store := &countedReportHistory{MemoryHistoryStore: NewMemoryHistoryStore()}
	s.SetHistoryStore(store)
	if err := s.RegisterAnalyzer(registryTestAnalyzer{name: "CustomAnalyzer"}); err != nil {
		t.Fatal(err)
	}
	p := scanplan.Default()
	p.Analyzers = []string{"CustomAnalyzer", "GatewayClassAnalyzer"}
	r, err := s.ScanWithPlan(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Issues) < 2 {
		t.Fatalf("fixture expected typed and dynamic findings: %#v", r)
	}
	if store.reports != 1 || store.legacy != 0 || store.last == nil || len(store.last.Issues) != len(r.Issues) {
		t.Fatalf("persisted reports=%d legacy=%d last=%#v", store.reports, store.legacy, store.last)
	}
	// A disabled client is unobserved coverage, not evidence of recovery.
	s.SetDynamicClient(nil)
	if _, err = s.ScanWithPlan(context.Background(), scanPlanForAnalyzer("CustomAnalyzer")); err != nil {
		t.Fatal(err)
	}
	if len(activeHistory(t, store)) < 2 {
		t.Fatal("disabled dynamic client cleared active dynamic findings")
	}
}

func TestCoverageOutOfOrderIndependentScopes(t *testing.T) {
	s := NewMemoryHistoryStore()
	a := scanplan.Plan{IncludeNamespaces: []string{"a"}}
	b := scanplan.Plan{IncludeNamespaces: []string{"b"}}
	recordCoverage(t, s, coverageReport(30, a))
	recordCoverage(t, s, coverageReport(20, b, coverageIssue("b", "two")))
	recordCoverage(t, s, coverageReport(10, a, coverageIssue("a", "one")))
	active := activeHistory(t, s)
	if len(active) != 1 || active["b/two"] == nil {
		t.Fatalf("scope ordering = %#v", active)
	}
}
func TestCoverageUnknownProvenanceAndCancellationPreserve(t *testing.T) {
	s := NewMemoryHistoryStore()
	unknown := coverageIssue("a", "one")
	unknown.AnalyzerNames = nil
	if err := s.Record([]*Issue{unknown}); err != nil {
		t.Fatal(err)
	}
	recordCoverage(t, s, coverageReport(10, scanplan.Default()))
	if len(activeHistory(t, s)) != 1 {
		t.Fatal("guessed legacy provenance")
	}
	known := coverageIssue("b", "two")
	recordCoverage(t, s, coverageReport(20, scanplan.Default(), known))
	r := coverageReport(30, scanplan.Default())
	r.Error = "context canceled"
	recordCoverage(t, s, r)
	if len(activeHistory(t, s)) != 2 {
		t.Fatal("canceled scan resolved findings")
	}
}
func TestDynamicUnavailableCoveragePreservesFindings(t *testing.T) {
	client := newDynamicTestClient(dynamicObject(gatewayClassGVR, "", "edge", map[string]interface{}{"spec": map[string]interface{}{"controllerName": "example.net/controller"}, "status": map[string]interface{}{"conditions": []interface{}{map[string]interface{}{"type": "Accepted", "status": "False"}}}}))
	s := NewClusterScannerWithDynamicClient(nil, client)
	store := NewMemoryHistoryStore()
	s.SetHistoryStore(store)
	p := scanPlanForAnalyzer("GatewayClassAnalyzer")
	if _, err := s.ScanWithPlan(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	before := len(activeHistory(t, store))
	if before == 0 {
		t.Fatal("missing fixture finding")
	}
	client.PrependReactor("list", "gatewayclasses", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(gatewayClassGVR.GroupResource(), "", errors.New("denied"))
	})
	r, err := s.ScanWithPlan(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Analyzers) != 1 || r.Analyzers[0].Error == "" {
		t.Fatalf("unavailable coverage missing: %#v", r.Analyzers)
	}
	if len(activeHistory(t, store)) != before {
		t.Fatal("forbidden dynamic scan resolved findings")
	}
}

// This wrapper deliberately exposes only the original HistoryStore contract.
type legacyOnlyHistory struct{ store *MemoryHistoryStore }

func (s *legacyOnlyHistory) Record(i []*Issue) error       { return s.store.Record(i) }
func (s *legacyOnlyHistory) List() ([]HistoryEntry, error) { return s.store.List() }
func (s *legacyOnlyHistory) Close() error                  { return nil }
func TestLegacyHistoryConservativelyMergesRuntimeReports(t *testing.T) {
	legacy := &legacyOnlyHistory{store: NewMemoryHistoryStore()}
	a := &coverageAnalyzer{issues: []*Issue{coverageIssue("a", "one"), coverageIssue("b", "two")}}
	s := NewClusterScannerWithHistory(nil, legacy)
	if err := s.RegisterAnalyzer(a); err != nil {
		t.Fatal(err)
	}
	p := scanPlanForAnalyzer(a.Info().Name)
	if _, err := s.ScanWithPlan(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	a.issues = nil
	p.IncludeNamespaces = []string{"a"}
	if _, err := s.ScanWithPlan(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(activeHistory(t, legacy)) != 2 {
		t.Fatal("legacy store lost unresolved findings")
	}
}
func TestLegacyHistoryOldReportDoesNotOverwriteNewerFinding(t *testing.T) {
	legacy := &legacyOnlyHistory{store: NewMemoryHistoryStore()}
	issue := coverageIssue("a", "one")
	issue.Summary = "new"
	if err := legacy.Record([]*Issue{issue}); err != nil {
		t.Fatal(err)
	}
	old := coverageIssue("a", "one")
	old.Summary = "ancient"
	if err := recordScanReport(legacy, coverageReport(1, scanplan.Default(), old)); err != nil {
		t.Fatal(err)
	}
	if activeHistory(t, legacy)["a/one"].Summary != "new" {
		t.Fatal("old report overwrote newer legacy finding")
	}
}
func TestCoverageMetadataDoesNotAliasReport(t *testing.T) {
	s := NewMemoryHistoryStore()
	r := coverageReport(10, scanplan.Plan{IncludeNamespaces: []string{"a"}})
	recordCoverage(t, s, r)
	r.Scope.IncludeNamespaces[0] = "b"
	recordCoverage(t, s, coverageReport(5, scanplan.Default(), coverageIssue("a", "one")))
	if len(activeHistory(t, s)) != 0 {
		t.Fatal("caller mutation changed previously observed coverage")
	}
}

type delayedLegacyHistory struct{ legacyOnlyHistory }

func (s *delayedLegacyHistory) List() ([]HistoryEntry, error) {
	rows, err := s.legacyOnlyHistory.List()
	time.Sleep(5 * time.Millisecond)
	return rows, err
}
func TestLegacyConcurrentRuntimeReportsPreserveAllScopes(t *testing.T) {
	store := &delayedLegacyHistory{legacyOnlyHistory{store: NewMemoryHistoryStore()}}
	s := NewClusterScannerWithHistory(nil, store)
	a := &coverageAnalyzer{issues: []*Issue{coverageIssue("a", "one"), coverageIssue("b", "two")}}
	if err := s.RegisterAnalyzer(a); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, ns := range []string{"a", "b"} {
		wg.Add(1)
		go func(ns string) {
			defer wg.Done()
			p := scanPlanForAnalyzer(a.Info().Name)
			p.IncludeNamespaces = []string{ns}
			if _, err := s.ScanWithPlan(context.Background(), p); err != nil {
				t.Error(err)
			}
		}(ns)
	}
	wg.Wait()
	if len(activeHistory(t, store)) != 2 {
		t.Fatal("concurrent legacy scans lost unrelated scope")
	}
}
func TestCoverageOldUIDCannotResurrectAfterFilteredObservation(t *testing.T) {
	s := NewMemoryHistoryStore()
	newIssue := coverageIssue("a", "one")
	newIssue.TargetUID = "new"
	recordCoverage(t, s, coverageReport(20, scanplan.Plan{LabelSelector: "app=one"}, newIssue))
	old := coverageIssue("a", "one")
	old.TargetUID = "old"
	recordCoverage(t, s, coverageReport(10, scanplan.Default(), old))
	rows, _ := s.List()
	if len(rows) != 1 || rows[0].Issue.TargetUID != "new" {
		t.Fatalf("old UID reappeared: %#v", rows)
	}
}
func TestDynamicLegacyScanRetainsOperationalErrors(t *testing.T) {
	client := newDynamicTestClient()
	client.PrependReactor("list", "gatewayclasses", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("transport failure")
	})
	s := NewClusterScannerWithDynamicClient(nil, client)
	if _, err := s.Scan(context.Background(), ""); err == nil {
		t.Fatal("legacy Scan dropped dynamic operational error")
	}
}
