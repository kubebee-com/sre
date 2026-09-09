package legacyserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestChatSessionRoutesAuthorizeRememberAndQueryReadOnlyData(t *testing.T) {
	provider := &boundaryTestProvider{reply: "reply password=session-reply-secret"}
	client := k8sfake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "ops"}})
	s := NewServer(0, scanner.NewClusterScanner(client), provider, remediation.NewEngine(client), nil, ServerOptions{
		APIToken:         testAPIToken,
		RedactionSecrets: []string{"session-input-secret"},
	})
	s.SetActiveIssues([]*scanner.Issue{{
		ID:        "session-issue",
		Namespace: "ops",
		Kind:      "Pod",
		Name:      "worker",
		Severity:  scanner.SeverityHigh,
		Category:  scanner.CategoryCrashLoop,
		Details:   "token=session-input-secret",
	}})
	h := testHandler(t, s)

	create := serveJSONWithToken(h, http.MethodPost, "/api/v1/chat/sessions", `{"issue_id":"session-issue"}`, testAPIToken)
	if create.Code != http.StatusCreated {
		t.Fatalf("create session status = %d: %s", create.Code, create.Body.String())
	}
	var created chatSessionResponse
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Session == nil || created.Session.ID == "" || created.Session.Issue == nil {
		t.Fatalf("create response missing session or issue: %#v", created)
	}
	if strings.Contains(create.Body.String(), "session-input-secret") {
		t.Fatal("create response leaked configured secret")
	}

	unauthorized := serveTestRequest(h, http.MethodGet, "/api/v1/chat/sessions/"+created.Session.ID, "", "")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized session get status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	reply := serveJSONWithToken(h, http.MethodPost, "/api/chat", `{"session_id":"`+created.Session.ID+`","message":"inspect password=session-input-secret"}`, testAPIToken)
	if reply.Code != http.StatusOK {
		t.Fatalf("session message status = %d: %s", reply.Code, reply.Body.String())
	}
	if strings.Contains(reply.Body.String(), "session-input-secret") || strings.Contains(provider.query, "session-input-secret") {
		t.Fatalf("session secret crossed boundary: response=%s query=%q", reply.Body.String(), provider.query)
	}

	query := serveJSONWithToken(h, http.MethodPost, "/api/v1/chat/sessions/"+created.Session.ID+"/query", `{"tool":"resource.get","request":{"resource":"pod","namespace":"ops","name":"worker"}}`, testAPIToken)
	if query.Code != http.StatusOK {
		t.Fatalf("session query status = %d: %s", query.Code, query.Body.String())
	}
	if strings.Contains(query.Body.String(), "delete") {
		t.Fatal("query response unexpectedly exposed a mutation operation")
	}

	closed := serveJSONWithToken(h, http.MethodDelete, "/api/v1/chat/sessions/"+created.Session.ID, "", testAPIToken)
	if closed.Code != http.StatusOK {
		t.Fatalf("close session status = %d: %s", closed.Code, closed.Body.String())
	}
	missing := serveTestRequest(h, http.MethodGet, "/api/v1/chat/sessions/"+created.Session.ID, "", testAPIToken)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("closed session get status = %d, want %d", missing.Code, http.StatusNotFound)
	}
}

func TestMetricsRouteUsesProtectedServerRegistry(t *testing.T) {
	s := NewServer(0, nil, triage.NewRuleBasedProvider(), remediation.NewEngine(k8sfake.NewSimpleClientset()), nil, ServerOptions{APIToken: testAPIToken})
	h := testHandler(t, s)

	unauthorized := serveTestRequest(h, http.MethodGet, "/metrics", "", "")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized metrics status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}
	authorized := serveTestRequest(h, http.MethodGet, "/metrics", "", testAPIToken)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized metrics status = %d: %s", authorized.Code, authorized.Body.String())
	}
	if !strings.Contains(authorized.Body.String(), "sre_scans_total") {
		t.Fatalf("metrics response omitted scan counter: %s", authorized.Body.String())
	}
}

func serveJSONWithToken(handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	req := newJSONRequest(method, path, body, token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func newJSONRequest(method, path, body, token string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}
