package notifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

func TestWebhookNotifier(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		receivedBody = buf[:n]
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, "https://sre.kubebee.com")

	proposal := &remediation.Proposal{
		ID:        "prop-12345",
		Namespace: "default",
		Kind:      "Pod",
		Name:      "test-pod",
		Diagnosis: &triage.Diagnosis{
			Summary:         "CrashLoopBackOff in test-pod",
			RootCause:       "Application panic during bootstrap",
			Severity:        scanner.SeverityCritical,
			ActionType:      triage.ActionRestartPod,
			ProposedCommand: "kubectl delete pod test-pod -n default",
			ConfidenceScore: 0.95,
			ProviderName:    "Claude",
		},
		Status: remediation.StatusPending,
	}

	ctx := context.Background()

	// Test NotifyProposalCreated
	err := notifier.NotifyProposalCreated(ctx, proposal)
	if err != nil {
		t.Fatalf("NotifyProposalCreated failed: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Fatal("expected server to receive webhook payload")
	}

	// Test Test Notification
	err = notifier.SendTestNotification(ctx, server.URL)
	if err != nil {
		t.Fatalf("SendTestNotification failed: %v", err)
	}

	// Test Execution Result
	proposal.Status = remediation.StatusCompleted
	proposal.ExecutionResult = "Successfully restarted pod"
	err = notifier.NotifyExecutionResult(ctx, proposal)
	if err != nil {
		t.Fatalf("NotifyExecutionResult failed: %v", err)
	}
}
