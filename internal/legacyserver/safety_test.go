package legacyserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

type boundaryTestProvider struct {
	query string
	issue *scanner.Issue
	reply string
	err   error
}

func (p *boundaryTestProvider) Name() string {
	return "boundary-test-provider"
}

func (p *boundaryTestProvider) Diagnose(context.Context, *scanner.Issue) (*triage.Diagnosis, error) {
	return nil, nil
}

func (p *boundaryTestProvider) Explain(_ context.Context, query string, issue *scanner.Issue) (string, error) {
	p.query = query
	p.issue = issue
	return p.reply, p.err
}

func serveJSONRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestIssueAPIUsesSanitizedProjection(t *testing.T) {
	provider := &boundaryTestProvider{}
	s := NewServer(0, nil, provider, remediation.NewEngine(k8sfake.NewSimpleClientset()), nil)
	s.SetActiveIssues([]*scanner.Issue{{
		ID:          "issue-api",
		Namespace:   "default",
		Kind:        "Pod",
		Name:        "payments",
		Severity:    scanner.SeverityHigh,
		Category:    scanner.CategoryCrashLoop,
		Summary:     "password=api-summary-secret",
		Details:     "details api-key=api-details-secret",
		LogsSnippet: "Authorization: Bearer api-log-secret",
		Events:      []string{"secret=api-event-secret"},
		SpecSnippet: "client_secret: api-spec-secret",
	}})

	rr := serveTestRequest(testHandler(t, s), http.MethodGet, "/api/issues", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/issues status = %d: %s", rr.Code, rr.Body.String())
	}
	for _, raw := range []string{"api-summary-secret", "api-details-secret", "api-log-secret", "api-event-secret", "api-spec-secret"} {
		if strings.Contains(rr.Body.String(), raw) {
			t.Errorf("GET /api/issues leaked %q: %s", raw, rr.Body.String())
		}
	}
	if !strings.Contains(rr.Body.String(), "[REDACTED]") {
		t.Fatalf("GET /api/issues omitted redaction marker: %s", rr.Body.String())
	}
}

func TestChatSanitizesInputIssueAndReplyAtBothBoundaries(t *testing.T) {
	provider := &boundaryTestProvider{
		reply: "provider reply password=chat-reply-secret",
	}
	s := NewServer(0, nil, provider, remediation.NewEngine(k8sfake.NewSimpleClientset()), nil)
	s.SetActiveIssues([]*scanner.Issue{{
		ID:        "issue-chat",
		Namespace: "default",
		Kind:      "Pod",
		Name:      "payments",
		Severity:  scanner.SeverityHigh,
		Category:  scanner.CategoryCrashLoop,
		Details:   "token=chat-issue-secret",
	}})

	body := "{\"message\":\"please inspect api_key=chat-input-secret\",\"issue_id\":\"issue-chat\"}"
	rr := serveJSONRequest(testHandler(t, s), http.MethodPost, "/api/chat", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/chat status = %d: %s", rr.Code, rr.Body.String())
	}
	for _, raw := range []string{"chat-input-secret", "chat-issue-secret", "chat-reply-secret"} {
		if strings.Contains(provider.query, raw) || (provider.issue != nil && strings.Contains(provider.issue.Details, raw)) || strings.Contains(rr.Body.String(), raw) {
			t.Errorf("POST /api/chat leaked %q across a boundary: query=%q issue=%#v response=%s", raw, provider.query, provider.issue, rr.Body.String())
		}
	}
}

func TestChatErrorResponseDoesNotExposeProviderSecret(t *testing.T) {
	secret := "chat-error-secret"
	provider := &boundaryTestProvider{err: fmt.Errorf("provider rejected password=%s", secret)}
	s := NewServer(0, nil, provider, remediation.NewEngine(k8sfake.NewSimpleClientset()), nil)

	rr := serveJSONRequest(testHandler(t, s), http.MethodPost, "/api/chat", "{\"message\":\"hello\"}")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("POST /api/chat error status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rr.Body.String(), secret) {
		t.Fatalf("POST /api/chat error exposed provider secret: %s", rr.Body.String())
	}
}

func TestServerRedactsConfiguredLiteralsAtResponseAndErrorSinks(t *testing.T) {
	secret := "configured-literal-only-secret"
	provider := &boundaryTestProvider{reply: "reply " + secret}
	s := NewServer(0, nil, provider, remediation.NewEngine(k8sfake.NewSimpleClientset()), nil, ServerOptions{
		RedactionSecrets: []string{secret},
	})
	s.SetActiveIssues([]*scanner.Issue{{
		ID:       "configured-issue",
		Summary:  "summary " + secret,
		Details:  "details " + secret,
		Severity: scanner.SeverityHigh,
		Category: scanner.CategoryCrashLoop,
	}})

	issueResponse := serveTestRequest(testHandler(t, s), http.MethodGet, "/api/issues", "", "")
	chatResponse := serveJSONRequest(testHandler(t, s), http.MethodPost, "/api/chat", "{\"message\":\"question "+secret+"\"}")
	if issueResponse.Code != http.StatusOK || chatResponse.Code != http.StatusOK {
		t.Fatalf("configured-secret requests failed: issues=%d chat=%d", issueResponse.Code, chatResponse.Code)
	}
	if strings.Contains(issueResponse.Body.String(), secret) || strings.Contains(chatResponse.Body.String(), secret) || strings.Contains(provider.query, secret) {
		t.Fatalf("configured secret crossed response/provider boundary: issues=%s chat=%s query=%q", issueResponse.Body.String(), chatResponse.Body.String(), provider.query)
	}

	provider.err = fmt.Errorf("provider failure contains %s", secret)
	errorResponse := serveJSONRequest(testHandler(t, s), http.MethodPost, "/api/chat", "{\"message\":\"hello\"}")
	if errorResponse.Code != http.StatusInternalServerError {
		t.Fatalf("configured-secret error status = %d, want %d", errorResponse.Code, http.StatusInternalServerError)
	}
	if strings.Contains(errorResponse.Body.String(), secret) {
		t.Fatalf("configured secret crossed error boundary: %s", errorResponse.Body.String())
	}
}

func TestProposalAPIUsesSanitizedDiagnosisAndExecutionProjection(t *testing.T) {
	engine := remediation.NewEngine(k8sfake.NewSimpleClientset())
	proposal := engine.CreateProposal(&scanner.Issue{
		ID:        "issue-proposal",
		Namespace: "default",
		Kind:      "Pod",
		Name:      "payments",
	}, &triage.Diagnosis{
		IssueID:         "issue-proposal",
		Summary:         "summary password=proposal-summary-secret",
		RootCause:       "root api_key=proposal-root-secret",
		Severity:        scanner.SeverityHigh,
		RemediationPlan: "plan client_secret=proposal-plan-secret",
		ActionType:      triage.ActionManual,
		ProposedCommand: "kubectl get pods -n default",
		ConfidenceScore: 0.5,
		ProviderName:    "test-provider",
	})
	proposal.ExecutionResult = "result secret=proposal-result-secret"
	proposal.ExecutionError = "error password=proposal-error-secret"

	s := NewServer(0, nil, &boundaryTestProvider{}, engine, nil)
	rr := serveTestRequest(testHandler(t, s), http.MethodGet, "/api/proposals", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/proposals status = %d: %s", rr.Code, rr.Body.String())
	}
	for _, raw := range []string{"proposal-summary-secret", "proposal-root-secret", "proposal-plan-secret", "proposal-command-secret", "proposal-result-secret", "proposal-error-secret"} {
		if strings.Contains(rr.Body.String(), raw) {
			t.Errorf("GET /api/proposals leaked %q: %s", raw, rr.Body.String())
		}
	}
}
