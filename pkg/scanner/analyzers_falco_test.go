package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFalcoSecurityAnalyzer(t *testing.T) {
	now := metav1.NewTime(time.Now())
	client := fake.NewSimpleClientset(
		&corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "falco-event-1",
				Namespace: "production",
			},
			InvolvedObject: corev1.ObjectReference{
				Kind:      "Pod",
				Name:      "api-server-xyz",
				Namespace: "production",
				UID:       "11112222-3333-4444-5555-666677778888",
			},
			Reason:  "FalcoRuleViolation",
			Message: "Notice Shell spawned in container with Bearer secret_bearer_token_12345",
			Source: corev1.EventSource{
				Component: "falco",
			},
			LastTimestamp: now,
		},
		&corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "falco-critical-2",
				Namespace: "production",
			},
			InvolvedObject: corev1.ObjectReference{
				Kind:      "Pod",
				Name:      "database-master-0",
				Namespace: "production",
				UID:       "99998888-7777-6666-5555-444433332222",
			},
			Reason:  "FalcoAlert",
			Message: "Critical Sensitive file /etc/shadow opened for writing",
			Source: corev1.EventSource{
				Component: "falco",
			},
			LastTimestamp: now,
		},
		&corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "normal-k8s-warning",
				Namespace: "production",
			},
			InvolvedObject: corev1.ObjectReference{
				Kind:      "Pod",
				Name:      "worker-pod-1",
				Namespace: "production",
			},
			Reason:        "FailedScheduling",
			Message:       "0/3 nodes are available: insufficient cpu",
			Source:        corev1.EventSource{Component: "default-scheduler"},
			LastTimestamp: now,
		},
	)

	analyzer := NewFalcoSecurityAnalyzer(client)
	issues, err := analyzer.Analyze(context.Background(), "production")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(issues) != 2 {
		t.Fatalf("expected 2 Falco security issues, got %d", len(issues))
	}

	// Verify normal warning event is not included in Falco security analyzer
	for _, issue := range issues {
		if issue.Name == "worker-pod-1" {
			t.Errorf("worker-pod-1 (non-Falco event) should not be captured by Falco analyzer")
		}
	}

	// Check issue 1 (sanitization of bearer token)
	var shellIssue, critIssue *Issue
	for _, issue := range issues {
		if issue.Name == "api-server-xyz" {
			shellIssue = issue
		}
		if issue.Name == "database-master-0" {
			critIssue = issue
		}
	}

	if shellIssue == nil {
		t.Fatal("expected issue for api-server-xyz")
	}
	if shellIssue.Category != CategoryFalcoSecurityAlert {
		t.Errorf("expected CategoryFalcoSecurityAlert, got %v", shellIssue.Category)
	}
	if strings.Contains(shellIssue.Details, "secret_bearer_token_12345") {
		t.Errorf("bearer token was not sanitized from details: %s", shellIssue.Details)
	}

	// Check issue 2 (critical severity)
	if critIssue == nil {
		t.Fatal("expected issue for database-master-0")
	}
	if critIssue.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", critIssue.Severity)
	}
}
