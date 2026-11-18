package triage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

// memoTestProvider numbers its diagnoses, so a test can tell a reused
// diagnosis from a new one.
type memoTestProvider struct {
	mu           sync.Mutex
	calls        int
	err          error
	nilDiagnosis bool
}

func (p *memoTestProvider) Name() string { return "memo-test-provider" }

func (p *memoTestProvider) Diagnose(_ context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	if p.nilDiagnosis {
		return nil, nil
	}
	replicas := int32(2)
	return &Diagnosis{
		IssueID:         issue.ID,
		Summary:         "summary",
		RootCause:       fmt.Sprintf("diagnosis %d from %q", p.calls, issue.Details),
		Severity:        issue.Severity,
		RemediationPlan: "plan",
		ActionType:      ActionScaleWorkload,
		ProposedCommand: "kubectl scale deployment/worker --replicas=2 -n prod",
		TargetReplicas:  &replicas,
		ConfidenceScore: 0.9,
		ProviderName:    p.Name(),
	}, nil
}

func (p *memoTestProvider) Explain(_ context.Context, query string, _ *scanner.Issue) (string, error) {
	return "explained " + query, nil
}

func (p *memoTestProvider) asked() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// memoStructuredTestProvider also runs structured tasks.
type memoStructuredTestProvider struct {
	memoTestProvider
}

func (p *memoStructuredTestProvider) RunStructured(_ context.Context, task StructuredTask) (StructuredTaskResult, error) {
	return StructuredTaskResult{Text: "ran " + task.Operation}, nil
}

// newTestMemo wraps provider and returns the clock the memo reads.
func newTestMemo(t *testing.T, provider TriageProvider) (*MemoizedProvider, *time.Time) {
	t.Helper()
	memo, ok := NewMemoizedProvider(provider).(*MemoizedProvider)
	if !ok {
		t.Fatalf("NewMemoizedProvider(%T) is not a *MemoizedProvider", provider)
	}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	memo.now = func() time.Time { return now }
	return memo, &now
}

func memoTestIssue() *scanner.Issue {
	return &scanner.Issue{
		ID: "prod/Pod/worker-0/CrashLoop", Namespace: "prod", Kind: "Pod", Name: "worker-0",
		TargetResourceVersion: "100", Severity: scanner.SeverityHigh, Category: scanner.CategoryCrashLoop,
		Summary: "Pod worker-0 is in CrashLoopBackOff", Details: "exit code 1",
		Events: []string{"Back-off restarting failed container"},
	}
}

func mustDiagnose(t *testing.T, provider TriageProvider, issue *scanner.Issue) *Diagnosis {
	t.Helper()
	diagnosis, err := provider.Diagnose(context.Background(), issue)
	if err != nil || diagnosis == nil {
		t.Fatalf("Diagnose() = %#v, %v", diagnosis, err)
	}
	return diagnosis
}

func TestMemoizedProviderAsksOnceWhileEvidenceIsUnchanged(t *testing.T) {
	provider := &memoTestProvider{}
	memo, now := newTestMemo(t, provider)
	issue := memoTestIssue()
	if _, ok := memo.Remembered(issue); ok || provider.asked() != 0 {
		t.Fatalf("Remembered() answered before any diagnosis (%d calls)", provider.asked())
	}
	first := mustDiagnose(t, memo, issue)
	if remembered, ok := memo.Remembered(issue); !ok || remembered.RootCause != first.RootCause || provider.asked() != 1 {
		t.Fatalf("Remembered() = %#v, %t after %d calls, want the diagnosis without another call", remembered, ok, provider.asked())
	}

	// A later scan stamps new observation times and sees a newer
	// resourceVersion, but shows the provider nothing new.
	rescanned := *issue
	rescanned.FirstObserved, rescanned.LastObserved = now.Add(2*time.Minute), now.Add(2*time.Minute)
	rescanned.TargetResourceVersion = "101"
	*now = now.Add(diagnosisReuseUnchanged - time.Second)
	if again := mustDiagnose(t, memo, &rescanned); again.RootCause != first.RootCause || provider.asked() != 1 {
		t.Fatalf("an unchanged finding was diagnosed %d times, want once (got %q)", provider.asked(), again.RootCause)
	}

	*now = now.Add(time.Second)
	if _, ok := memo.Remembered(&rescanned); ok {
		t.Fatalf("Remembered() answered with a diagnosis older than %s", diagnosisReuseUnchanged)
	}
	if refreshed := mustDiagnose(t, memo, &rescanned); refreshed.RootCause == first.RootCause || provider.asked() != 2 {
		t.Fatalf("a diagnosis older than %s was reused (%d calls)", diagnosisReuseUnchanged, provider.asked())
	}
}

func TestMemoizedProviderHoldsBackWhileEvidenceKeepsChanging(t *testing.T) {
	provider := &memoTestProvider{}
	memo, now := newTestMemo(t, provider)
	issue := memoTestIssue()
	first := mustDiagnose(t, memo, issue)

	// A failing pod has new log lines on every scan. The provider is not
	// asked about each of them.
	for scan := 1; scan <= 5; scan++ {
		*now = now.Add(2 * time.Minute)
		changed := *issue
		changed.LogsSnippet = "panic at scan " + strconv.Itoa(scan)
		if held := mustDiagnose(t, memo, &changed); held.RootCause != first.RootCause {
			t.Fatalf("scan %d: changed evidence was diagnosed again after %s", scan, now.Sub(time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)))
		}
	}
	if provider.asked() != 1 {
		t.Fatalf("provider was asked %d times within %s, want once", provider.asked(), diagnosisReuseChanged)
	}

	// Once the diagnosis is old enough, the changed evidence is diagnosed,
	// and that diagnosis then stands while the evidence stays as it is.
	*now = now.Add(diagnosisReuseChanged)
	changed := *issue
	changed.Details = "OOMKilled"
	current := mustDiagnose(t, memo, &changed)
	if current.RootCause != `diagnosis 2 from "OOMKilled"` {
		t.Fatalf("changed evidence was not diagnosed afresh: %q", current.RootCause)
	}
	*now = now.Add(diagnosisReuseChanged)
	if again := mustDiagnose(t, memo, &changed); again.RootCause != current.RootCause || provider.asked() != 2 {
		t.Fatalf("an unchanged finding was diagnosed again (%d calls)", provider.asked())
	}
}

func TestMemoizedProviderDiagnosesEscalatedFindingAtOnce(t *testing.T) {
	provider := &memoTestProvider{}
	memo, _ := newTestMemo(t, provider)
	issue := memoTestIssue()
	mustDiagnose(t, memo, issue)

	escalated := *issue
	escalated.Severity = scanner.SeverityCritical
	if diagnosis := mustDiagnose(t, memo, &escalated); diagnosis.Severity != scanner.SeverityCritical || provider.asked() != 2 {
		t.Fatalf("an escalated finding reused its earlier diagnosis: %#v after %d calls", diagnosis, provider.asked())
	}
	another := *issue
	another.ID = "prod/Pod/worker-1/CrashLoop"
	if mustDiagnose(t, memo, &another); provider.asked() != 3 {
		t.Fatalf("another finding reused a diagnosis (%d calls)", provider.asked())
	}
}

func TestMemoizedProviderKeepsOnlySuccessfulDiagnoses(t *testing.T) {
	provider := &memoTestProvider{err: errors.New("provider unavailable")}
	memo, _ := newTestMemo(t, provider)
	issue := memoTestIssue()
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := memo.Diagnose(context.Background(), issue); err == nil || provider.asked() != attempt {
			t.Fatalf("attempt %d: error = %v after %d calls, want the provider asked again", attempt, err, provider.asked())
		}
	}
	provider.err, provider.nilDiagnosis = nil, true
	for attempt := 3; attempt <= 4; attempt++ {
		if diagnosis, err := memo.Diagnose(context.Background(), issue); diagnosis != nil || err != nil || provider.asked() != attempt {
			t.Fatalf("attempt %d: empty diagnosis was kept (%#v, %v, %d calls)", attempt, diagnosis, err, provider.asked())
		}
	}

	// Without an ID one finding cannot be told from another.
	provider.nilDiagnosis = false
	anonymous := memoTestIssue()
	anonymous.ID = ""
	mustDiagnose(t, memo, anonymous)
	mustDiagnose(t, memo, anonymous)
	if provider.asked() != 6 {
		t.Fatalf("a finding without an ID was memoized (%d calls)", provider.asked())
	}
}

func TestMemoizedProviderReturnsCopies(t *testing.T) {
	memo, _ := newTestMemo(t, &memoTestProvider{})
	issue := memoTestIssue()
	first := mustDiagnose(t, memo, issue)
	original := first.RootCause
	first.RootCause = "changed by the caller"
	*first.TargetReplicas = 99

	reused := mustDiagnose(t, memo, issue)
	if reused.RootCause != original || *reused.TargetReplicas != 2 {
		t.Fatalf("a caller changed the kept diagnosis: %q, %d replicas", reused.RootCause, *reused.TargetReplicas)
	}
	reused.RootCause = "changed again"
	if again := mustDiagnose(t, memo, issue); again.RootCause != original {
		t.Fatalf("a caller changed the kept diagnosis through a reused copy: %q", again.RootCause)
	}
}

func TestMemoizedProviderIsBounded(t *testing.T) {
	provider := &memoTestProvider{}
	memo, now := newTestMemo(t, provider)
	issueNumber := func(number int) *scanner.Issue {
		issue := memoTestIssue()
		issue.ID = "issue-" + strconv.Itoa(number)
		return issue
	}
	for number := 1; number <= maxMemoizedDiagnoses+1; number++ {
		*now = now.Add(time.Second)
		mustDiagnose(t, memo, issueNumber(number))
	}
	if len(memo.diagnoses) != maxMemoizedDiagnoses {
		t.Fatalf("memo keeps %d diagnoses, want the bound of %d", len(memo.diagnoses), maxMemoizedDiagnoses)
	}
	asked := provider.asked()
	if mustDiagnose(t, memo, issueNumber(maxMemoizedDiagnoses+1)); provider.asked() != asked {
		t.Fatal("the newest diagnosis was evicted")
	}
	if mustDiagnose(t, memo, issueNumber(1)); provider.asked() != asked+1 {
		t.Fatal("the oldest diagnosis survived a full memo")
	}
}

func TestMemoizedProviderPassesTheRestThrough(t *testing.T) {
	plain := NewMemoizedProvider(&memoTestProvider{})
	if plain.Name() != "memo-test-provider" {
		t.Fatalf("Name() = %q, want the wrapped provider's name", plain.Name())
	}
	if reply, err := plain.Explain(context.Background(), "why", nil); err != nil || reply != "explained why" {
		t.Fatalf("Explain() = %q, %v", reply, err)
	}
	// A caller finds a structured-task runner by type assertion, so the memo
	// is one exactly when its provider is.
	if _, runs := plain.(StructuredTaskRunner); runs {
		t.Fatal("memo over a plain provider claims to run structured tasks")
	}
	runner, runs := NewMemoizedProvider(&memoStructuredTestProvider{}).(StructuredTaskRunner)
	if !runs {
		t.Fatal("memo hides its provider's structured tasks")
	}
	if result, err := runner.RunStructured(context.Background(), StructuredTask{Operation: "digest"}); err != nil || result.Text != "ran digest" {
		t.Fatalf("RunStructured() = %#v, %v", result, err)
	}
}

func TestMemoizedProviderIsSafeForConcurrentUse(t *testing.T) {
	provider := &memoTestProvider{}
	memo := NewMemoizedProvider(provider)
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			issue := memoTestIssue()
			issue.ID = "issue-" + strconv.Itoa(worker%4)
			for range 50 {
				if _, err := memo.Diagnose(context.Background(), issue); err != nil {
					t.Errorf("Diagnose() error = %v", err)
				}
			}
		}()
	}
	workers.Wait()
	if asked := provider.asked(); asked < 4 || asked > 8 {
		t.Fatalf("provider was asked %d times for 4 findings from 8 workers", asked)
	}
}
