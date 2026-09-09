package notifier

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestWebhookNotifierRedactsProposalAndExecutionPayloads(t *testing.T) {
	secret := "webhook.literal.[secret]+"
	var received []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read webhook payload: %v", err)
		}
		received = append(received, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, "https://sre.kubebee.com", secret)
	proposal := &remediation.Proposal{
		ID:        "prop-secret",
		Namespace: "default",
		Kind:      "Pod",
		Name:      "payments",
		Diagnosis: &triage.Diagnosis{
			Summary:         "summary " + secret,
			RootCause:       "root " + secret,
			Severity:        scanner.SeverityHigh,
			RemediationPlan: "plan " + secret,
			ActionType:      triage.ActionManual,
			ProposedCommand: "kubectl get pods --token=" + secret,
			ConfidenceScore: 0.5,
			ProviderName:    "test-provider",
		},
		Status:          remediation.StatusFailed,
		ExecutionResult: "result " + secret,
		ExecutionError:  "error " + secret,
	}

	if err := notifier.NotifyProposalCreated(context.Background(), proposal); err != nil {
		t.Fatalf("NotifyProposalCreated() error = %v", err)
	}
	if err := notifier.NotifyExecutionResult(context.Background(), proposal); err != nil {
		t.Fatalf("NotifyExecutionResult() error = %v", err)
	}
	if len(received) != 2 {
		t.Fatalf("received %d webhook payloads, want 2", len(received))
	}
	for _, body := range received {
		if strings.Contains(body, secret) {
			t.Fatalf("webhook payload leaked configured secret: %s", body)
		}
	}
}

func TestWebhookURLGetterDoesNotExposeConfiguredSecret(t *testing.T) {
	secret := "webhook-url-secret"
	notifier := NewWebhookNotifier("https://hooks.example.invalid/path?token="+secret, "https://sre.kubebee.com", secret)
	if got := notifier.GetWebhookURL(); strings.Contains(got, secret) {
		t.Fatalf("GetWebhookURL() exposed configured secret: %q", got)
	}
}

func TestWebhookNotifierRejectsProposalWithoutDiagnosis(t *testing.T) {
	notifier := NewWebhookNotifier("https://hooks.example.invalid", "https://sre.kubebee.com")
	if err := notifier.NotifyProposalCreated(context.Background(), &remediation.Proposal{}); err == nil {
		t.Fatal("NotifyProposalCreated() accepted a proposal without diagnosis")
	}
}

func TestWebhookNotifierRejectsUnsafeDestinations(t *testing.T) {
	for _, destination := range []string{
		"http://example.com/hook",
		"https://10.0.0.4/hook",
		"file:///tmp/webhook",
		"http://user:password@127.0.0.1/hook",
	} {
		notifier := NewWebhookNotifier("", "https://sre.example.test")
		if err := notifier.SetWebhookURL(destination); err == nil {
			t.Fatalf("SetWebhookURL(%q) accepted unsafe destination", destination)
		}
		if notifier.HasWebhookURL() {
			t.Fatalf("unsafe destination %q was retained", destination)
		}
	}
}

func TestWebhookNotifierAllowsLoopbackFixture(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	notifier := NewWebhookNotifier("", "https://sre.example.test")
	if err := notifier.SetWebhookURL(server.URL); err != nil {
		t.Fatalf("SetWebhookURL(loopback) error = %v", err)
	}
	if err := notifier.SendTestNotification(context.Background(), ""); err != nil {
		t.Fatalf("SendTestNotification(loopback) error = %v", err)
	}
}
