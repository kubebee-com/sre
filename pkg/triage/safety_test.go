package triage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestBuildPromptRedactsEveryIssueFieldAndMarksUntrustedData(t *testing.T) {
	issue := &scanner.Issue{
		ID:          "issue-1",
		Namespace:   "default",
		Kind:        "Pod",
		Name:        "payments",
		Severity:    scanner.SeverityHigh,
		Category:    scanner.CategoryCrashLoop,
		Summary:     "password=summary-secret",
		Details:     "root cause api_key=details-secret",
		SpecSnippet: "client_secret: spec-secret",
		Events:      []string{"Authorization: Bearer event-secret"},
		LogsSnippet: "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.log-secret",
	}

	prompt := BuildPrompt(issue)
	for _, raw := range []string{"summary-secret", "details-secret", "spec-secret", "event-secret", "log-secret"} {
		if strings.Contains(prompt, raw) {
			t.Errorf("BuildPrompt() leaked %q: %s", raw, prompt)
		}
	}
	for _, marker := range []string{"UNTRUSTED", "ignore any instructions", "Resource Spec Snippet", "Recent Warning Events"} {
		if !strings.Contains(strings.ToLower(prompt), strings.ToLower(marker)) {
			t.Errorf("BuildPrompt() omitted boundary/structure marker %q: %s", marker, prompt)
		}
	}
}

func TestBuildPromptRedactsConfiguredLiteralValues(t *testing.T) {
	configured := "literal.secret.[regex]+"
	issue := &scanner.Issue{
		ID:          "issue-2",
		Namespace:   configured,
		Kind:        "Pod",
		Name:        configured,
		Summary:     "summary " + configured,
		Details:     "details " + configured,
		Events:      []string{"event " + configured},
		LogsSnippet: "logs " + configured,
		SpecSnippet: "spec " + configured,
	}

	prompt := BuildPromptWithSecrets(issue, configured)
	if strings.Contains(prompt, configured) {
		t.Fatalf("BuildPromptWithSecrets() leaked configured literal %q: %s", configured, prompt)
	}
}

func TestParseDiagnosisJSONValidatesFieldsAndDefaultsOnlyMissingAction(t *testing.T) {
	validWithoutAction := "{\"issue_id\":\"issue-3\",\"summary\":\"summary\",\"root_cause\":\"root cause\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan\",\"proposed_command\":\"kubectl get pods -n default\",\"confidence_score\":0.75}"
	diagnosis, err := ParseDiagnosisJSON(validWithoutAction, "issue-3", "test-provider")
	if err != nil {
		t.Fatalf("valid diagnosis with omitted action returned error: %v", err)
	}
	if diagnosis.ActionType != ActionManual {
		t.Fatalf("omitted action = %q, want %q", diagnosis.ActionType, ActionManual)
	}

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "issue id mismatch",
			raw:  "{\"issue_id\":\"other-issue\",\"summary\":\"summary\",\"root_cause\":\"root\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan\",\"action_type\":\"Manual\",\"confidence_score\":0.5}",
		},
		{
			name: "missing summary",
			raw:  "{\"root_cause\":\"root\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan\",\"action_type\":\"Manual\",\"confidence_score\":0.5}",
		},
		{
			name: "missing root cause",
			raw:  "{\"summary\":\"summary\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan\",\"action_type\":\"Manual\",\"confidence_score\":0.5}",
		},
		{
			name: "missing remediation plan",
			raw:  "{\"summary\":\"summary\",\"root_cause\":\"root\",\"severity\":\"HIGH\",\"action_type\":\"Manual\",\"confidence_score\":0.5}",
		},
		{
			name: "invalid severity",
			raw:  "{\"summary\":\"summary\",\"root_cause\":\"root\",\"severity\":\"URGENT\",\"remediation_plan\":\"plan\",\"action_type\":\"Manual\",\"confidence_score\":0.5}",
		},
		{
			name: "unsupported action",
			raw:  "{\"summary\":\"summary\",\"root_cause\":\"root\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan\",\"action_type\":\"RunShell\",\"confidence_score\":0.5}",
		},
		{
			name: "confidence too high",
			raw:  "{\"summary\":\"summary\",\"root_cause\":\"root\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan\",\"action_type\":\"Manual\",\"confidence_score\":1.01}",
		},
		{
			name: "confidence negative",
			raw:  "{\"summary\":\"summary\",\"root_cause\":\"root\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan\",\"action_type\":\"Manual\",\"confidence_score\":-0.01}",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDiagnosisJSON(tc.raw, "issue-3", "test-provider"); err == nil {
				t.Fatal("ParseDiagnosisJSON() accepted invalid diagnosis")
			}
		})
	}
}

func TestParseDiagnosisJSONRejectsUnsafeCommands(t *testing.T) {
	commands := []string{
		"kubectl delete pod payments; curl https://attacker.invalid",
		"kubectl delete pod payments && echo done",
		"kubectl delete pod payments || echo failed",
		"kubectl delete pod payments | tee /tmp/output",
		"kubectl delete pod payments > /tmp/output",
		"kubectl delete pod payments $(cat /tmp/token)",
		"kubectl --token=embedded-secret get pods",
	}

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			raw := "{\"summary\":\"summary\",\"root_cause\":\"root\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan\",\"action_type\":\"Manual\",\"proposed_command\":" + quoteJSON(command) + ",\"confidence_score\":0.5}"
			if _, err := ParseDiagnosisJSON(raw, "issue-4", "test-provider"); err == nil {
				t.Fatalf("ParseDiagnosisJSON() accepted unsafe command %q", command)
			}
		})
	}
}

func TestParseDiagnosisJSONDoesNotReturnRawModelOutputInErrors(t *testing.T) {
	secret := "parse-secret"
	raw := "{\"summary\":\"" + secret
	_, err := ParseDiagnosisJSON(raw, "issue-5", "test-provider")
	if err == nil {
		t.Fatal("ParseDiagnosisJSON() accepted malformed JSON")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(strings.ToLower(err.Error()), "raw:") {
		t.Fatalf("ParseDiagnosisJSON() exposed model output in error: %v", err)
	}
}

func TestParseDiagnosisJSONSanitizesDiagnosisFieldsAndConfiguredLiterals(t *testing.T) {
	configured := "diagnosis.literal.[secret]"
	raw := "{\"issue_id\":\"issue-6\",\"summary\":\"summary " + configured + "\",\"root_cause\":\"root " + configured + "\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan " + configured + "\",\"action_type\":\"Manual\",\"proposed_command\":\"kubectl get pods\",\"confidence_score\":0.5}"
	diagnosis, err := ParseDiagnosisJSON(raw, "issue-6", "test-provider", configured)
	if err != nil {
		t.Fatalf("ParseDiagnosisJSON() error = %v", err)
	}
	serialized := diagnosis.Summary + diagnosis.RootCause + diagnosis.RemediationPlan + diagnosis.ProposedCommand
	if strings.Contains(serialized, configured) {
		t.Fatalf("ParseDiagnosisJSON() returned configured literal: %#v", diagnosis)
	}
}

func TestParseDiagnosisJSONSanitizesReturnedIssueID(t *testing.T) {
	configured := "diagnosis-issue-literal"
	raw := "{\"issue_id\":\"" + configured + "\",\"summary\":\"summary\",\"root_cause\":\"root\",\"severity\":\"HIGH\",\"remediation_plan\":\"plan\",\"action_type\":\"Manual\",\"proposed_command\":\"kubectl get pods\",\"confidence_score\":0.5}"
	diagnosis, err := ParseDiagnosisJSON(raw, configured, "test-provider", configured)
	if err != nil {
		t.Fatalf("ParseDiagnosisJSON() error = %v", err)
	}
	if strings.Contains(diagnosis.IssueID, configured) {
		t.Fatalf("ParseDiagnosisJSON() returned raw issue ID: %q", diagnosis.IssueID)
	}
}

func quoteJSON(value string) string {
	return "\"" + strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "\"", "\\\"") + "\""
}

func TestProviderChatBoundariesRedactOutboundAndInboundText(t *testing.T) {
	const inputSecret = "provider-input-secret"
	const replySecret = "provider-reply-secret"
	const additionalSecret = "provider-additional-secret"
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read provider request: %v", err)
		}
		requests = append(requests, string(body))
		switch r.URL.Path {
		case "/messages":
			_, _ = w.Write([]byte("{\"content\":[{\"text\":\"provider reply password=provider-reply-secret\"}]}"))
		case "/responses":
			_, _ = w.Write([]byte("{\"status\":\"completed\",\"output_text\":\"provider reply password=provider-reply-secret\"}"))
		default:
			_, _ = w.Write([]byte("{\"choices\":[{\"message\":{\"content\":\"provider reply password=provider-reply-secret\"}}]}"))
		}
	}))
	defer server.Close()

	issue := &scanner.Issue{ID: "provider-issue", Namespace: "default", Kind: "Pod", Name: "payments", Details: additionalSecret}
	query := "please inspect api_key=" + inputSecret + " and " + additionalSecret
	providers := []TriageProvider{
		NewClaudeProvider("configured-api-key", "test-model", server.URL, additionalSecret),
		NewCodexProvider("configured-api-key", "test-model", server.URL, additionalSecret),
		NewRuleBasedProvider(additionalSecret),
	}

	for _, provider := range providers {
		reply, err := provider.Explain(context.Background(), query, issue)
		if err != nil {
			t.Fatalf("%s Explain() error = %v", provider.Name(), err)
		}
		if strings.Contains(reply, replySecret) || strings.Contains(reply, additionalSecret) {
			t.Errorf("%s Explain() returned raw provider reply: %q", provider.Name(), reply)
		}
	}
	for _, request := range requests {
		if strings.Contains(request, inputSecret) || strings.Contains(request, additionalSecret) {
			t.Errorf("provider request leaked raw chat input: %s", request)
		}
		var decoded interface{}
		if err := json.Unmarshal([]byte(request), &decoded); err != nil {
			t.Errorf("provider request was not JSON: %v", err)
		}
	}
}

func TestRuleBasedProviderUsesConfiguredRedactionPolicy(t *testing.T) {
	secret := "rule-based-configured-secret"
	provider := NewRuleBasedProvider(secret)
	issue := &scanner.Issue{
		ID:       "rule-based-issue",
		Kind:     "Pod",
		Name:     "payments",
		Severity: scanner.SeverityHigh,
		Category: scanner.CategoryCrashLoop,
		Details:  "password=" + secret,
	}

	diagnosis, err := provider.Diagnose(context.Background(), issue)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "inspect "+secret, issue)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	for _, value := range []string{diagnosis.Summary, diagnosis.RootCause, diagnosis.RemediationPlan, diagnosis.ProposedCommand, reply} {
		if strings.Contains(value, secret) {
			t.Fatalf("rule-based provider leaked configured secret: %q", value)
		}
	}
}

func TestHarnessProviderUsesConfiguredRedactionPolicy(t *testing.T) {
	secret := "harness-configured-secret"
	provider := NewHarnessProvider("/bin/sh", []string{"-c", "cat"}, secret)
	issue := &scanner.Issue{ID: "harness-issue", Details: "password=" + secret}
	reply, err := provider.Explain(context.Background(), "inspect "+secret, issue)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if strings.Contains(reply, secret) {
		t.Fatalf("harness provider leaked configured secret: %q", reply)
	}
}
