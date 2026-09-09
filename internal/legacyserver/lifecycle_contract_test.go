package legacyserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/metrics"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/kubebee-com/sre/pkg/triage"
)

type lifecycleQueryScanner struct {
	calls   int
	history scanner.HistoryStore
}

func TestStatusUsesProviderSnapshotAndSafeRuntimeSettings(t *testing.T) {
	registry := metrics.NewRegistry()
	registry.ObserveProviderUsage("codex", 12, 8, 20)
	server := NewServer(0, nil, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{
		APIToken: "test-token",
		Metrics:  registry,
		Runtime: RuntimeSettings{
			LLMProvider:         "codex",
			LLMMode:             "remote",
			LLMWireAPI:          "responses",
			LLMModel:            "gpt-5.6-luna",
			LLMBaseURLDisplay:   "https://llm.example.test",
			ScanInterval:        "5s",
			ScanJitter:          "0s",
			EventDrivenScanning: true,
			EventQueueCapacity:  64,
			EventDebounce:       "250ms",
			CacheEnabled:        true,
			CacheConfigured:     true,
		},
	})
	handler, err := server.newHandler()
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/metrics/status", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var status StatusResponse
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if status.TokenUsage != (TokenUsageStatus{InputTokens: 12, OutputTokens: 8, TotalTokens: 20}) {
		t.Fatalf("token usage = %#v, want provider-reported usage", status.TokenUsage)
	}
	if status.Settings.LLMProvider != "codex" || status.Settings.LLMWireAPI != "responses" || status.Settings.LLMBaseURLDisplay != "https://llm.example.test" || !status.Settings.CacheEnabled || !status.Settings.EventDrivenScanning || status.Settings.EventQueueCapacity != 64 || status.Settings.EventDebounce != "250ms" {
		t.Fatalf("runtime settings = %#v", status.Settings)
	}
	if strings.Contains(response.Body.String(), "api_key") || strings.Contains(response.Body.String(), "gpt-5.6-luna-secret") {
		t.Fatalf("status response exposed a secret value: %s", response.Body.String())
	}
}

type boundedHistoryStore struct {
	entries    []scanner.HistoryEntry
	listCalls  int
	limitCalls int
}

func (s *boundedHistoryStore) Record([]*scanner.Issue) error { return nil }

func (s *boundedHistoryStore) List() ([]scanner.HistoryEntry, error) {
	s.listCalls++
	return nil, errors.New("unbounded history listing was used")
}

func (s *boundedHistoryStore) ListLimit(limit int) ([]scanner.HistoryEntry, error) {
	s.limitCalls++
	if limit < len(s.entries) {
		return append([]scanner.HistoryEntry(nil), s.entries[:limit]...), nil
	}
	return append([]scanner.HistoryEntry(nil), s.entries...), nil
}

func (s *boundedHistoryStore) Close() error { return nil }

func (s *lifecycleQueryScanner) Scan(context.Context, string) ([]*scanner.Issue, error) {
	return nil, nil
}

func (s *lifecycleQueryScanner) ScanWithPlan(context.Context, scanplan.Plan) (*scanner.ScanReport, error) {
	return &scanner.ScanReport{}, nil
}

func (s *lifecycleQueryScanner) GetAnalyzers() []scanner.AnalyzerInfo {
	return nil
}

func (s *lifecycleQueryScanner) GetPodCleaner() *scanner.PodCleaner {
	return nil
}

func (s *lifecycleQueryScanner) History() scanner.HistoryStore {
	return s.history
}

func (s *lifecycleQueryScanner) QueryResource(context.Context, string, string, string) (interface{}, error) {
	s.calls++
	return map[string]any{"kind": "Event"}, nil
}

func TestVersionedQueryRejectsUnallowlistedKindBeforeBackend(t *testing.T) {
	backend := &lifecycleQueryScanner{}
	server := NewServer(0, backend, triage.NewRuleBasedProvider(), (*remediation.Engine)(nil), nil, ServerOptions{
		APIToken:        "test-token",
		RequireAPIToken: true,
	})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(`{"kind":"Event","name":"audit"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()

	handler, err := server.newHandler()
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if backend.calls != 0 {
		t.Fatalf("backend calls = %d, want 0", backend.calls)
	}
}

func TestStatusExposesSanitizedErrorUsageAndSettings(t *testing.T) {
	backend := &lifecycleQueryScanner{}
	server := NewServer(0, backend, triage.NewRuleBasedProvider(), (*remediation.Engine)(nil), nil, ServerOptions{
		APIToken:          "test-token",
		AllowedOrigins:    []string{"https://dashboard.example.test"},
		MaxBodyBytes:      4096,
		RequestsPerMinute: 120,
		RequestBurst:      7,
	})
	handler, err := server.newHandler()
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}

	invalidQuery := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(`{"kind":"Event","name":"audit"}`))
	invalidQuery.Header.Set("Content-Type", "application/json")
	invalidQuery.Header.Set("Authorization", "Bearer test-token")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalidQuery)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid query status = %d, want %d", invalidResponse.Code, http.StatusBadRequest)
	}

	chat := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"inspect the workload"}`))
	chat.Header.Set("Content-Type", "application/json")
	chat.Header.Set("Authorization", "Bearer test-token")
	chatResponse := httptest.NewRecorder()
	handler.ServeHTTP(chatResponse, chat)
	if chatResponse.Code != http.StatusOK {
		t.Fatalf("chat status = %d, want %d; body = %s", chatResponse.Code, http.StatusOK, chatResponse.Body.String())
	}
	beforeSessionTokens := server.tokenUsageStatus().TotalTokens
	createdResponse := serveJSONWithToken(handler, http.MethodPost, "/api/chat/sessions", `{}`, "test-token")
	if createdResponse.Code != http.StatusCreated {
		t.Fatalf("session create status = %d, want %d; body = %s", createdResponse.Code, http.StatusCreated, createdResponse.Body.String())
	}
	var created chatSessionResponse
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &created); err != nil || created.Session == nil {
		t.Fatalf("decode created session: %v; body = %s", err, createdResponse.Body.String())
	}
	sessionMessage := serveJSONWithToken(handler, http.MethodPost, "/api/chat/sessions/"+created.Session.ID+"/messages", `{"message":"summarize the issue"}`, "test-token")
	if sessionMessage.Code != http.StatusOK {
		t.Fatalf("session message status = %d, want %d; body = %s", sessionMessage.Code, http.StatusOK, sessionMessage.Body.String())
	}
	if server.tokenUsageStatus().TotalTokens <= beforeSessionTokens {
		t.Fatal("session message did not contribute to token usage")
	}

	statusRequest := httptest.NewRequest(http.MethodGet, "/api/metrics/status", nil)
	statusRequest.Header.Set("Authorization", "Bearer test-token")
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status endpoint code = %d, want %d", statusResponse.Code, http.StatusOK)
	}
	var status StatusResponse
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if status.ErrorCounts["bad_request"] != 1 {
		t.Fatalf("error counts = %#v, want one bad_request", status.ErrorCounts)
	}
	if status.TokenUsage.TotalTokens == 0 || !status.TokenUsage.Estimated {
		t.Fatalf("token usage = %#v, want bounded estimated usage", status.TokenUsage)
	}
	if !status.Settings.APITokenRequired || status.Settings.MaxRequestBytes != 4096 || status.Settings.RequestsPerMinute != 120 || status.Settings.RequestBurst != 7 {
		t.Fatalf("settings = %#v, want authenticated bounded settings", status.Settings)
	}
	if strings.Contains(statusResponse.Body.String(), "test-token") {
		t.Fatal("status response exposed the API token")
	}
}

func TestAuthenticatedBoundaryUsesStructuredErrorEnvelope(t *testing.T) {
	server := NewServer(0, nil, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{APIToken: "test-token"})
	handler, err := server.newHandler()
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode structured error: %v; body = %s", err, response.Body.String())
	}
	if envelope["schema_version"] != "error/v1" || envelope["code"] != "unauthorized" || envelope["status"] != float64(http.StatusUnauthorized) {
		t.Fatalf("error envelope = %#v, want error/v1 unauthorized", envelope)
	}
}

func TestHTTPResponsesAreBoundedBeforeSerialization(t *testing.T) {
	server := NewServer(0, nil, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{MaxResponseBytes: 128})
	server.UpdateScanResults([]*scanner.Issue{{
		ID: "large", Kind: "Pod", Name: "worker", Summary: strings.Repeat("x", 512),
	}})
	handler, err := server.newHandler()
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	response := serveTestRequest(handler, http.MethodGet, "/api/issues", "", "")
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large response status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestIssueReadsRecoverFromDurableScannerHistory(t *testing.T) {
	history := scanner.NewMemoryHistoryStore()
	if err := history.Record([]*scanner.Issue{{
		ID: "durable-issue", Kind: "Pod", Name: "worker", Severity: scanner.SeverityHigh,
	}}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	server := NewServer(0, &lifecycleQueryScanner{history: history}, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{})
	response := serveTestRequest(testHandler(t, server), http.MethodGet, "/api/issues", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("durable issue status = %d, want %d", response.Code, http.StatusOK)
	}
	var issues []scanner.SanitizedIssue
	if err := json.Unmarshal(response.Body.Bytes(), &issues); err != nil {
		t.Fatalf("decode durable issues: %v", err)
	}
	if len(issues) != 1 || issues[0].ID != "durable-issue" {
		t.Fatalf("durable issues = %#v, want durable-issue", issues)
	}
}

func TestRESTHistoryUsesBoundedStoreBeforeResponseMaterialization(t *testing.T) {
	history := &boundedHistoryStore{entries: []scanner.HistoryEntry{{Fingerprint: "bounded"}}}
	server := NewServer(0, &lifecycleQueryScanner{history: history}, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{})
	response := serveTestRequest(testHandler(t, server), http.MethodGet, "/api/v1/history", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("history status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	if history.limitCalls != 1 || history.listCalls != 0 {
		t.Fatalf("history calls = ListLimit:%d List:%d, want bounded retrieval only", history.limitCalls, history.listCalls)
	}
}

func TestRESTHistoryRetainsLegacyHistoryStoreCompatibility(t *testing.T) {
	history := scanner.NewMemoryHistoryStore()
	if err := history.Record([]*scanner.Issue{{ID: "legacy-history", Kind: "Pod", Name: "worker"}}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	server := NewServer(0, &lifecycleQueryScanner{history: history}, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{})
	response := serveTestRequest(testHandler(t, server), http.MethodGet, "/api/v1/history", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("legacy history status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
}
