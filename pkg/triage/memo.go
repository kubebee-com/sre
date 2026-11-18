package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

const (
	// diagnosisReuseUnchanged is how long a diagnosis stands for a finding
	// whose evidence has not changed.
	diagnosisReuseUnchanged = 6 * time.Hour
	// diagnosisReuseChanged is how long it stands once the evidence has
	// changed. A failing workload logs new lines between any two scans, so
	// asking again on every change would ask about it on every scan.
	diagnosisReuseChanged = 30 * time.Minute
	maxMemoizedDiagnoses  = 2048
)

// MemoizedProvider reuses the diagnosis of a finding rather than asking its
// provider again on every scan: for diagnosisReuseUnchanged while the
// finding's evidence is the same, and for diagnosisReuseChanged once the
// evidence has changed. A provider that costs seconds and quota per call is
// then asked about a finding a few times a day, not every few minutes.
//
// Only successful diagnoses are kept, in memory. Explain is passed through.
type MemoizedProvider struct {
	provider TriageProvider
	now      func() time.Time

	mu        sync.Mutex
	diagnoses map[string]memoizedDiagnosis
}

type memoizedDiagnosis struct {
	evidence    string
	diagnosis   *Diagnosis
	diagnosedAt time.Time
}

// memoizedStructuredProvider is a MemoizedProvider over a provider that also
// runs structured tasks, which a caller detects by type assertion.
type memoizedStructuredProvider struct {
	*MemoizedProvider
	runner StructuredTaskRunner
}

func (p *memoizedStructuredProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	return p.runner.RunStructured(ctx, task)
}

// NewMemoizedProvider wraps provider. The result runs structured tasks
// exactly when provider does.
func NewMemoizedProvider(provider TriageProvider) TriageProvider {
	memo := &MemoizedProvider{
		provider:  provider,
		now:       time.Now,
		diagnoses: make(map[string]memoizedDiagnosis),
	}
	if runner, ok := provider.(StructuredTaskRunner); ok {
		return &memoizedStructuredProvider{MemoizedProvider: memo, runner: runner}
	}
	return memo
}

func (p *MemoizedProvider) Name() string {
	return p.provider.Name()
}

func (p *MemoizedProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	return p.provider.Explain(ctx, query, issue)
}

func (p *MemoizedProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	if diagnosis, ok := p.Remembered(issue); ok {
		return diagnosis, nil
	}
	diagnosis, err := p.provider.Diagnose(ctx, issue)
	if err == nil && diagnosis != nil {
		p.remember(issue, diagnosis)
	}
	return diagnosis, err
}

// Remembered returns a copy of the diagnosis that Diagnose would reuse for a
// finding, without asking the provider when there is none.
func (p *MemoizedProvider) Remembered(issue *scanner.Issue) (*Diagnosis, bool) {
	if !memoizable(issue) {
		return nil, false
	}
	finding, evidence := findingKey(issue), evidenceDigest(issue)
	p.mu.Lock()
	defer p.mu.Unlock()
	kept, known := p.diagnoses[finding]
	if !known {
		return nil, false
	}
	reuse := diagnosisReuseChanged
	if kept.evidence == evidence {
		reuse = diagnosisReuseUnchanged
	}
	if p.now().Sub(kept.diagnosedAt) >= reuse {
		return nil, false
	}
	return cloneDiagnosis(kept.diagnosis), true
}

func (p *MemoizedProvider) remember(issue *scanner.Issue, diagnosis *Diagnosis) {
	if !memoizable(issue) {
		return
	}
	finding, evidence, now := findingKey(issue), evidenceDigest(issue), p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, known := p.diagnoses[finding]; !known && len(p.diagnoses) >= maxMemoizedDiagnoses {
		p.evictLocked(now)
	}
	p.diagnoses[finding] = memoizedDiagnosis{evidence: evidence, diagnosis: cloneDiagnosis(diagnosis), diagnosedAt: now}
}

// evictLocked makes room for one more diagnosis: it drops every diagnosis
// that can no longer be reused and, when all still can, the oldest.
func (p *MemoizedProvider) evictLocked(now time.Time) {
	oldest := ""
	for finding, kept := range p.diagnoses {
		if now.Sub(kept.diagnosedAt) >= diagnosisReuseUnchanged {
			delete(p.diagnoses, finding)
			continue
		}
		if oldest == "" || kept.diagnosedAt.Before(p.diagnoses[oldest].diagnosedAt) {
			oldest = finding
		}
	}
	if len(p.diagnoses) >= maxMemoizedDiagnoses {
		delete(p.diagnoses, oldest)
	}
}

// memoizable reports whether a finding can be told from every other one.
// Without an ID it cannot.
func memoizable(issue *scanner.Issue) bool {
	return issue != nil && issue.ID != ""
}

// findingKey identifies a finding across scans. A change of severity or
// category makes it a different finding, which is diagnosed afresh.
func findingKey(issue *scanner.Issue) string {
	return issue.ID + "\x00" + string(issue.Severity) + "\x00" + string(issue.Category)
}

// evidenceDigest identifies the evidence a provider is shown for a finding.
// Observation times and the target's resourceVersion are left out on purpose:
// analyzers stamp them on every scan and status heartbeats bump them without
// changing what there is to diagnose.
func evidenceDigest(issue *scanner.Issue) string {
	hash := sha256.New()
	write := func(values ...string) {
		for _, value := range values {
			_, _ = io.WriteString(hash, strconv.Itoa(len(value))+":"+value)
		}
	}
	write(issue.Namespace, issue.Kind, issue.Name, issue.Summary, issue.Details, issue.LogsSnippet, issue.SpecSnippet)
	write(issue.Events...)
	return hex.EncodeToString(hash.Sum(nil))
}
