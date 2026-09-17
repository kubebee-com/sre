package triage

import (
	"context"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestFalcoSecurityTriage(t *testing.T) {
	provider := NewRuleBasedProvider()

	issue := &scanner.Issue{
		ID:            "issue-falco-1",
		Namespace:     "production",
		Kind:          "Pod",
		Name:          "payment-backend-5c8bf-xyz",
		Severity:      scanner.SeverityCritical,
		Category:      scanner.CategoryFalcoSecurityAlert,
		Summary:       "Falco runtime security alert: Terminal shell in container on Pod payment-backend-5c8bf-xyz",
		Details:       "Critical: /bin/bash spawned in container payment-backend with suspicious privilege",
		FirstObserved: time.Now(),
		LastObserved:  time.Now(),
	}

	diag, err := provider.Diagnose(context.Background(), issue)
	if err != nil {
		t.Fatalf("Diagnose failed: %v", err)
	}

	if diag.ActionType != ActionRestartPod {
		t.Errorf("expected ActionRestartPod for container intrusion, got %v", diag.ActionType)
	}
	if diag.Severity != scanner.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", diag.Severity)
	}
	if diag.RootCause == "" || diag.RemediationPlan == "" {
		t.Error("expected non-empty root cause and remediation plan")
	}
}
