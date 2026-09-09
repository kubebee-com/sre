package triage

import (
	"context"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestRuleBasedTriage(t *testing.T) {
	provider := NewRuleBasedProvider()
	if provider.Name() != "Rule-Based SRE Engine" {
		t.Fatalf("unexpected provider name: %s", provider.Name())
	}

	tests := []struct {
		category       scanner.IssueCategory
		expectedAction ActionType
	}{
		{scanner.CategoryCrashLoop, ActionRestartPod},
		{scanner.CategoryOOMKilled, ActionGitOpsPR},
		{scanner.CategoryImagePull, ActionManual},
		{scanner.CategoryHighRestarts, ActionManual},
		{scanner.CategoryNodePressure, ActionCordonNode},
		{scanner.CategoryPVCPending, ActionManual},
		{scanner.CategoryServiceNoEndpoint, ActionManual},
	}

	for _, tc := range tests {
		t.Run(string(tc.category), func(t *testing.T) {
			now := time.Now()
			issue := &scanner.Issue{
				ID:            "test-" + string(tc.category),
				Namespace:     "default",
				Kind:          "Pod",
				Name:          "test-pod",
				Severity:      scanner.SeverityHigh,
				Category:      tc.category,
				Summary:       "Issue summary for " + string(tc.category),
				FirstObserved: now,
				LastObserved:  now,
			}

			diag, err := provider.Diagnose(context.Background(), issue)
			if err != nil {
				t.Fatalf("diagnose failed: %v", err)
			}
			if diag.ActionType != tc.expectedAction {
				t.Errorf("expected action %s, got %s", tc.expectedAction, diag.ActionType)
			}
		})
	}
}
