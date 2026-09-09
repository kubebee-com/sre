package playbook

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCatalogCanonicalVersionDeduplication(t *testing.T) {
	c := NewMemoryCatalog()
	p := catalogFixture("duplicate")
	ctx := context.Background()
	if err := c.SavePlaybook(ctx, p); err != nil {
		t.Fatal(err)
	}
	p.Version = 2
	if err := c.SavePlaybook(ctx, p); !errors.Is(err, ErrCatalogConflict) {
		t.Fatalf("duplicate canonical version accepted: %v", err)
	}
	hash, _ := CanonicalHash(p)
	existing, err := c.GetPlaybookByHash(ctx, hash)
	if err != nil || existing.ID != p.ID || existing.Version != 1 {
		t.Fatalf("canonical duplicate cannot link to original: %+v %v", existing, err)
	}
}

func TestCatalogStepTupleIdentityHasNoSeparatorCollisions(t *testing.T) {
	c := NewMemoryCatalog()
	a, b := catalogFixture("a:b"), catalogFixture("a")
	a.Steps[0].ID = "c"
	b.Steps[0].ID = "b:c"
	for _, p := range []NormalizedPlaybook{a, b} {
		if err := c.SavePlaybook(context.Background(), p); err != nil {
			t.Fatalf("distinct tuple collided: %v", err)
		}
	}
}

func TestCatalogRejectsMissingSourceLineage(t *testing.T) {
	p := catalogFixture("missing-source")
	p.SourceIDs = []string{"missing"}
	if err := NewMemoryCatalog().SavePlaybook(context.Background(), p); !errors.Is(err, ErrCatalogNotFound) {
		t.Fatalf("missing source accepted: %v", err)
	}
}

func TestCatalogRejectsMissingLearningRun(t *testing.T) {
	c := LearningCandidate{ID: "candidate", SourceRunID: "missing", Outcome: LearningOutcomeVerifiedSuccess, Playbook: catalogFixture("candidate"), IdempotencyKey: "event"}
	if err := NewMemoryCatalog().RecordLearningCandidate(context.Background(), c); !errors.Is(err, ErrCatalogNotFound) {
		t.Fatalf("missing run accepted: %v", err)
	}
}

func TestCatalogRejectsNonterminalOrContradictoryOutcome(t *testing.T) {
	for _, outcome := range []ResolutionOutcomeRecord{
		{RunID: "run", ProposalID: "proposal", Status: "PENDING_APPROVAL"},
		{RunID: "run", ProposalID: "proposal", Status: "FAILED", Verification: "VERIFIED"},
		{RunID: "run", ProposalID: "proposal", Status: "COMPLETED", Verification: "made-up"},
	} {
		if err := NewMemoryCatalog().RecordResolutionOutcome(context.Background(), outcome); !errors.Is(err, ErrCatalogInvalid) {
			t.Fatalf("invalid outcome was not rejected before storage: %v", err)
		}
	}
}

func TestCatalogPreparesStructuredSourceSecrets(t *testing.T) {
	c := NewMemoryCatalog()
	for _, content := range []string{`{"env":[{"name":"DB_PASSWORD","value":"opaque-private-value"}]}`, "env:\n  - name: DB_PASSWORD\n    value: opaque-private-value\n"} {
		source := SourceArtifact{ID: "structured", Kind: "import", Origin: "upload", MediaType: "application/json", ParserVersion: "v1", SanitizedContent: content}
		prepared, err := c.PrepareSource(source)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(prepared.SanitizedContent, "opaque-private-value") {
			t.Fatal("structured source leaked secret")
		}
		again, err := c.PrepareSource(prepared)
		if err != nil || again.Checksum != prepared.Checksum {
			t.Fatal("source preparation is not idempotent")
		}
	}
}

func TestCatalogPreparesEveryMarkdownDocument(t *testing.T) {
	c := NewMemoryCatalog()
	content := "First\n~~~yaml\nenv:\n  - name: DB_PASSWORD\n    value: first-private-value\n~~~\nSecond\n~~~yaml\nenv:\n  - name: DB_PASSWORD\n    value: second-private-value\n~~~\n"
	source := SourceArtifact{ID: "fenced", Kind: "import", Origin: "upload", MediaType: "text/markdown", ParserVersion: "v1", SanitizedContent: content}
	prepared, err := c.PrepareSource(source)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prepared.SanitizedContent, "private-value") {
		t.Fatal("catalog Markdown source leaked secret")
	}
	again, err := c.PrepareSource(prepared)
	if err != nil || again.Checksum != prepared.Checksum {
		t.Fatal("fenced preparation not idempotent")
	}
}
