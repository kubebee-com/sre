package remediation

import (
	"context"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEngineProposals(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	engine := NewEngine(fakeClient)

	now := time.Now()
	issue := &scanner.Issue{
		ID:            "test-issue-1",
		Namespace:     "default",
		Kind:          "Pod",
		Name:          "api-server-xyz",
		Severity:      scanner.SeverityHigh,
		Category:      scanner.CategoryCrashLoop,
		Summary:       "Pod crashing repeatedly",
		FirstObserved: now,
		LastObserved:  now,
	}

	diag := &triage.Diagnosis{
		IssueID:         issue.ID,
		Summary:         "Crashing due to missing DB config",
		RootCause:       "ConfigMap missing key",
		Severity:        scanner.SeverityHigh,
		RemediationPlan: "Manual intervention required",
		ActionType:      triage.ActionManual,
		ProposedCommand: "kubectl get configmap",
		ConfidenceScore: 0.95,
		ProviderName:    "TestProvider",
	}

	prop := engine.CreateProposal(issue, diag)
	if prop == nil {
		t.Fatal("expected proposal to be created, got nil")
	}

	if prop.Status != StatusPending {
		t.Fatalf("expected status %s, got %s", StatusPending, prop.Status)
	}

	// Test list proposals
	props := engine.ListProposals()
	if len(props) != 1 {
		t.Fatalf("expected 1 proposal, got %d", len(props))
	}

	// Test reject proposal
	_, err := engine.Reject(prop.ID, "false alarm")
	if err != nil {
		t.Fatalf("reject returned error: %v", err)
	}

	p, ok := engine.GetProposal(prop.ID)
	if !ok {
		t.Fatalf("get proposal failed")
	}
	if p.Status != StatusRejected {
		t.Fatalf("expected status %s, got %s", StatusRejected, p.Status)
	}

	// Test approve Manual action
	prop2 := engine.CreateProposal(issue, diag)
	_, err = engine.Approve(context.Background(), prop2.ID, "admin-user")
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}

	// Give async execution a moment
	time.Sleep(50 * time.Millisecond)

	p2, ok := engine.GetProposal(prop2.ID)
	if !ok {
		t.Fatalf("get proposal 2 failed")
	}
	if p2.Status != StatusCompleted {
		t.Fatalf("expected status %s for manual proposal after approval, got %s", StatusCompleted, p2.Status)
	}
}
