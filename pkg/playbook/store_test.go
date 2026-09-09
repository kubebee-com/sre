package playbook

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func catalogFixture(id string) NormalizedPlaybook {
	return NormalizedPlaybook{ID: id, Version: 1, Lifecycle: LifecycleNormalized, Title: "Inspect pod", Summary: "Inspect the affected pod", Confidence: 0.9, FailureCategories: []string{"CrashLoop"}, Applicability: []ResourceSelector{{Namespace: "payments", Kind: "Pod", LabelSelector: "app=api"}}, Steps: []NormalizedStep{{ID: "inspect", Order: 1, Action: "Manual", Confidence: 0.9}}}
}
func catalogContract(t *testing.T, c Catalog) {
	ctx := context.Background()
	suffix := fmt.Sprintf("%x", time.Now().UnixNano())
	id := "pb-" + suffix
	category := "CrashLoop-" + suffix
	fixture := func(id string) NormalizedPlaybook {
		p := catalogFixture(id)
		p.FailureCategories = []string{category}
		return p
	}
	p := fixture(id)
	if err := c.SavePlaybook(ctx, p); err != nil {
		t.Fatal(err)
	}
	p.Summary = "changed"
	if err := c.SavePlaybook(ctx, p); !errors.Is(err, ErrCatalogConflict) {
		t.Fatalf("immutable write: %v", err)
	}
	p = fixture(id + "-active")
	p.Lifecycle = LifecycleActive
	if err := c.SavePlaybook(ctx, p); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("direct active insertion: %v", err)
	}
	if err := c.Transition(ctx, id, 1, LifecycleActive, "reviewer"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("skip review: %v", err)
	}
	if err := c.Transition(ctx, id, 1, LifecycleReview, ""); err == nil {
		t.Fatal("blank actor accepted")
	}
	for _, state := range []LifecycleState{LifecycleReview, LifecycleActive} {
		if err := c.Transition(ctx, id, 1, state, "reviewer"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := c.GetPlaybook(ctx, id, 1)
	if err != nil || got.Lifecycle != LifecycleActive {
		t.Fatalf("get: %+v %v", got, err)
	}
	wantHash, _ := CanonicalHash(fixture(id))
	if got.CanonicalHash != wantHash {
		t.Fatal("hash changed during transitions")
	}
	for _, q := range []MatchQuery{{FailureCategory: "Other", Namespace: "payments", Kind: "Pod", Labels: map[string]string{"app": "api"}}, {FailureCategory: category, Namespace: "other", Kind: "Pod", Labels: map[string]string{"app": "api"}}, {FailureCategory: category, Namespace: "payments", Kind: "Pod"}} {
		matches, err := c.ListActive(ctx, q)
		if err != nil || len(matches) != 0 {
			t.Fatalf("false positive: %+v %v", matches, err)
		}
	}
	matches, err := c.ListActive(ctx, MatchQuery{FailureCategory: category, Namespace: "payments", Kind: "Pod", Labels: map[string]string{"app": "api"}})
	if err != nil || len(matches) != 1 {
		t.Fatalf("matching: %+v %v", matches, err)
	}
	if err := c.Transition(ctx, id, 1, LifecycleRetired, "reviewer"); err != nil {
		t.Fatal(err)
	}
	matches, err = c.ListActive(ctx, MatchQuery{FailureCategory: category, Namespace: "payments", Kind: "Pod", Labels: map[string]string{"app": "api"}})
	if err != nil || len(matches) != 0 {
		t.Fatalf("retired match: %+v %v", matches, err)
	}
	if _, err := c.List(ctx, MaxCollectionItems+1); err == nil {
		t.Fatal("unbounded list accepted")
	}
}
func TestMemoryCatalogContract(t *testing.T) { catalogContract(t, NewMemoryCatalog()) }
func TestMemoryLearningAtomicDedup(t *testing.T) {
	c := NewMemoryCatalog()
	ctx := context.Background()
	p := validPlaybookForValidation()
	if err := c.SavePlaybook(ctx, p); err != nil {
		t.Fatal(err)
	}
	plan := validResolutionPlanForValidation()
	plan.ID = "run"
	if err := c.RecordFinding(ctx, FindingRecord{ID: plan.FindingID, Evidence: plan.Evidence}); err != nil {
		t.Fatal(err)
	}
	if err := c.RecordResolution(ctx, plan); err != nil {
		t.Fatal(err)
	}
	candidate := LearningCandidate{ID: "candidate", SourceRunID: "run", Outcome: LearningOutcomeVerifiedSuccess, Playbook: catalogFixture("learned"), IdempotencyKey: "event"}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.RecordLearningCandidate(ctx, candidate); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	stats, err := c.Stats(ctx)
	if err != nil || stats.LearningCandidates != 1 || stats.Playbooks != 2 || stats.ReviewPlaybooks != 1 {
		t.Fatalf("stats: %+v %v", stats, err)
	}
	got, err := c.GetLearningCandidate(ctx, "event")
	if err != nil || got.ID != "candidate" {
		t.Fatalf("candidate: %+v %v", got, err)
	}
}
func TestMemorySanitizesAndComputesSourceChecksum(t *testing.T) {
	c := NewMemoryCatalog(WithCatalogSecrets("literal-secret"))
	ctx := context.Background()
	s := SourceArtifact{ID: "first", Kind: "markdown", Origin: "upload", MediaType: "text/plain", ParserVersion: "v1", Checksum: "forged", SanitizedContent: "inspect literal-secret"}
	if err := c.SaveSource(ctx, s); err != nil {
		t.Fatal(err)
	}
	checksum := SourceChecksum("inspect [REDACTED]")
	got, err := c.GetSourceByChecksum(ctx, checksum)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.SanitizedContent, "literal-secret") || got.Checksum == "forged" {
		t.Fatalf("unsafe source: %+v", got)
	}
	s.ID = "second"
	if err := c.SaveSource(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err = c.GetSourceByChecksum(ctx, checksum)
	if err != nil || got.ID != "first" {
		t.Fatalf("canonical source: %+v %v", got, err)
	}
}

func TestCatalogIngressRedactsURLsAndCombinesSecretOptions(t *testing.T) {
	c := NewMemoryCatalog(WithCatalogSecrets("first-secret"), WithCatalogSecrets("second-secret"))
	s := SourceArtifact{ID: "url-source", Kind: "markdown", Origin: "https://operator:origin-password@example.test/path?token=url-token", MediaType: "text/plain", ParserVersion: "v1", SanitizedContent: "first-secret second-secret postgres://user:dsn-password@database.test/sre"}
	if err := c.SaveSource(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	backend := c.backend.(*memoryBackend)
	for _, row := range backend.tables["sources"] {
		for _, secret := range []string{"first-secret", "second-secret", "origin-password", "url-token", "dsn-password"} {
			if strings.Contains(string(row.Payload), secret) {
				t.Fatalf("ingress retained %q", secret)
			}
		}
	}
}
func TestCatalogMatchingHonorsObservedQuerySelectors(t *testing.T) {
	p := catalogFixture("match")
	p.Lifecycle = LifecycleActive
	q := MatchQuery{FailureCategory: "CrashLoop", Namespace: "payments", Kind: "Pod", Labels: map[string]string{"app": "api"}, Selectors: []ResourceSelector{{Kind: "Pod", LabelSelector: "app=api"}}}
	if !matchesPlaybook(p, q) {
		t.Fatal("matching query selector was rejected")
	}
	q.Selectors[0].Namespace = "other"
	if matchesPlaybook(p, q) {
		t.Fatal("contradictory query selector was accepted")
	}
}

func TestPrepareSourceUsesRepositoryRedactionAndChecksum(t *testing.T) {
	c := NewMemoryCatalog(WithCatalogSecrets("source-literal-secret"))
	input := SourceArtifact{ID: "prepared", Kind: "markdown", Origin: "https://user:origin-password@example.test/runbook", MediaType: "text/plain", ParserVersion: "v1", Checksum: "caller-supplied", SanitizedContent: "Inspect source-literal-secret at postgres://user:database-password@database.test/sre?token=query-secret"}
	prepared, err := c.PrepareSource(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"source-literal-secret", "origin-password", "database-password", "query-secret"} {
		if strings.Contains(prepared.SanitizedContent+prepared.Origin, secret) {
			t.Fatalf("preparation retained %q", secret)
		}
	}
	if prepared.Checksum != SourceChecksum(prepared.SanitizedContent) || prepared.Checksum == input.Checksum {
		t.Fatal("preparation did not compute sanitized checksum")
	}
	if err := c.SaveSource(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	stored, err := c.GetSourceByChecksum(context.Background(), prepared.Checksum)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SanitizedContent != prepared.SanitizedContent || stored.Origin != prepared.Origin {
		t.Fatal("save and prepare disagree")
	}
	again, err := c.PrepareSource(prepared)
	if err != nil || again.Checksum != prepared.Checksum {
		t.Fatal("source preparation is not idempotent")
	}
	input.ID = ""
	if _, err := c.PrepareSource(input); !errors.Is(err, ErrCatalogInvalid) {
		t.Fatalf("invalid source preparation: %v", err)
	}
}

func TestFindingRefreshPreservesResolutionSnapshots(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCatalog()
	p := validPlaybookForValidation()
	p.Lifecycle = LifecycleNormalized
	if err := c.SavePlaybook(ctx, p); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		plan := validResolutionPlanForValidation()
		plan.ID = fmt.Sprintf("run-%d", i)
		plan.ResourceVersion = fmt.Sprintf("rv-%d", i)
		plan.Evidence[0].ID = fmt.Sprintf("evidence-%d", i)
		plan.Evidence[0].ResourceVersion = plan.ResourceVersion
		for j := range plan.Steps {
			plan.Steps[j].EvidenceRefs = []string{plan.Evidence[0].ID}
		}
		finding := FindingRecord{ID: plan.FindingID, Summary: fmt.Sprintf("observation %d", i), Evidence: plan.Evidence}
		if err := c.RecordFinding(ctx, finding); err != nil {
			t.Fatalf("finding observation %d: %v", i, err)
		}
		if err := c.RecordResolution(ctx, plan); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 2; i++ {
		plan, err := c.GetResolution(ctx, fmt.Sprintf("run-%d", i))
		if err != nil || plan.ResourceVersion != fmt.Sprintf("rv-%d", i) || plan.Evidence[0].ID != fmt.Sprintf("evidence-%d", i) {
			t.Fatalf("snapshot %d changed: %+v %v", i, plan, err)
		}
	}
	current := c.backend.(*memoryBackend).tables["findings"][memoryKey("finding-1", 0)]
	var finding FindingRecord
	if err := decodeRow(current, &finding); err != nil || finding.Summary != "observation 2" {
		t.Fatalf("current finding: %+v %v", finding, err)
	}
	old, err := c.GetResolution(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	old.ResourceVersion = "changed"
	if err := c.RecordResolution(ctx, old); !errors.Is(err, ErrCatalogConflict) {
		t.Fatalf("resolution overwrite: %v", err)
	}
}
