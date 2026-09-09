package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/sanitizer"
)

func TestSanitizeIssueRecursivelySanitizesStructuredEvidence(t *testing.T) {
	issue := &Issue{
		ID:          "issue-structured",
		Namespace:   "default",
		Kind:        "Pod",
		Name:        "payments",
		Severity:    SeverityHigh,
		Category:    CategoryCrashLoop,
		Details:     `{"metadata":{"name":"DB_PASSWORD","value":"details-structured-secret"},"safe":"context"}`,
		SpecSnippet: "- name: API_TOKEN\n  value: spec-structured-secret\n- name: REGION\n  value: us-east-1\n",
		Events:      []string{`{"name":"CLIENT_SECRET","value":"event-structured-secret"}`},
		LogsSnippet: `{"name":"ACCESS_TOKEN","value":"logs-structured-secret"}`,
	}

	projection := SanitizeIssue(issue, "configured-issue-secret")
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	serialized := string(encoded)
	for _, secret := range []string{"details-structured-secret", "spec-structured-secret", "event-structured-secret", "logs-structured-secret"} {
		if strings.Contains(serialized, secret) {
			t.Errorf("sanitized issue leaked structured secret %q: %s", secret, serialized)
		}
	}
	for _, marker := range []string{"context", "us-east-1", "[REDACTED]"} {
		if !strings.Contains(serialized, marker) {
			t.Errorf("sanitized issue omitted expected marker %q: %s", marker, serialized)
		}
	}
}

func TestDirectIssueAndSanitizedIssueSerializationUsesConfiguredDefaultRedactor(t *testing.T) {
	secret := "issue-process-default-secret"
	sanitizer.ConfigureDefaultRedactor(secret)
	t.Cleanup(func() { sanitizer.ConfigureDefaultRedactor() })
	issue := Issue{ID: "issue-direct", Details: "details " + secret}
	projection := &SanitizedIssue{ID: "projection-direct", Details: "details " + secret}
	for name, value := range map[string]interface{}{"issue": issue, "projection": projection} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Errorf("json.Marshal(%s) leaked configured literal: %s", name, encoded)
		}
	}
}
