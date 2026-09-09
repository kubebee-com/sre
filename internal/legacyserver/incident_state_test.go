package legacyserver

import (
	"github.com/kubebee-com/sre/pkg/scanner"
	"testing"
)

func TestIssueSnapshotTargetedNonemptyScanPreservesHistory(t *testing.T) {
	store := scanner.NewMemoryHistoryStore()
	a := &scanner.Issue{ID: "a", Namespace: "a", Kind: "Pod", Name: "one"}
	b := &scanner.Issue{ID: "b", Namespace: "b", Kind: "Pod", Name: "two"}
	if err := store.Record([]*scanner.Issue{a, b}); err != nil {
		t.Fatal(err)
	}
	s := NewServer(0, scanner.NewClusterScannerWithHistory(nil, store), nil, nil, nil)
	s.UpdateScanResults([]*scanner.Issue{a})
	if got := len(s.issueSnapshot()); got != 2 {
		t.Fatalf("targeted nonempty scan hides other active findings: got %d", got)
	}
	s.SetActiveIssues([]*scanner.Issue{a})
	if got := len(s.issueSnapshot()); got != 1 {
		t.Fatalf("explicit active override ignored: %d", got)
	}
	s.SetActiveIssues(nil)
	if got := len(s.issueSnapshot()); got != 0 {
		t.Fatalf("explicit empty override ignored: %d", got)
	}
}
