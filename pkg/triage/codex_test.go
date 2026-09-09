package triage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestCodexProviderReturnsSafeErrorForOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxProviderResponseBytes+1))
	}))
	defer server.Close()

	provider := NewCodexProvider("api-key", "model", server.URL)
	_, err := provider.Explain(context.Background(), "hello", nil)
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorLimit {
		t.Fatalf("Explain() error = %#v, want response limit ProviderError", err)
	}
}

func TestNewCodexProviderUsesResponsesAndReportsUsageAndErrors(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("request path = %q, want /responses", r.URL.Path)
		}
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		var request map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		var model string
		if err := json.Unmarshal(request["model"], &model); err != nil || model != "codex-model" {
			t.Errorf("model = %q, want codex-model", model)
		}
		if _, ok := request["messages"]; ok {
			t.Error("Responses request unexpectedly included chat messages")
		}
		if _, ok := request["instructions"]; !ok {
			t.Error("Responses request omitted instructions")
		}
		if _, ok := request["input"]; !ok {
			t.Error("Responses request omitted input")
		}
		var textConfig map[string]json.RawMessage
		if err := json.Unmarshal(request["text"], &textConfig); err != nil {
			t.Errorf("structured Responses request omitted text format: %v", err)
		}
		_, _ = io.WriteString(w, `{"status":"completed","output_text":"{\"issue_id\":\"issue-1\",\"summary\":\"safe\",\"root_cause\":\"test\",\"severity\":\"HIGH\",\"remediation_plan\":\"inspect\",\"action_type\":\"Manual\",\"proposed_command\":\"kubectl get pods -n default\",\"confidence_score\":0.8}","usage":{"input_tokens":4,"output_tokens":3,"total_tokens":7}}`)
	}))
	defer server.Close()

	provider := NewCodexProvider("api-key", "codex-model", server.URL)
	capture := &providerObserverCapture{}
	ctx := WithProviderObserver(context.Background(), capture)
	diagnosis, err := provider.Diagnose(ctx, &scanner.Issue{ID: "issue-1"})
	if err != nil || diagnosis == nil || diagnosis.IssueID != "issue-1" {
		t.Fatalf("Diagnose() = %#v, %v; want Responses diagnosis", diagnosis, err)
	}
	if len(capture.usages) != 1 || capture.usages[0] != (ProviderTokenUsage{InputTokens: 4, OutputTokens: 3, TotalTokens: 7}) {
		t.Fatalf("usage events = %#v, want one Responses usage event", capture.usages)
	}

	fail.Store(true)
	if _, err := provider.Explain(ctx, "hello", nil); err == nil {
		t.Fatal("Explain() error = nil, want upstream HTTP error")
	}
	if len(capture.errors) != 1 || capture.errors[0] != ProviderErrorHTTP {
		t.Fatalf("error events = %#v, want one HTTP error event", capture.errors)
	}
}

func TestCodexProviderRunStructuredUsesResponsesJSONModeAndUsage(t *testing.T) {
	var requestBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("request path = %q, want /responses", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if _, ok := requestBody["messages"]; ok {
			t.Error("structured Responses request unexpectedly included chat messages")
		}
		var textConfig struct {
			Format responseFormat `json:"format"`
		}
		if err := json.Unmarshal(requestBody["text"], &textConfig); err != nil || textConfig.Format.Type != "json_object" {
			t.Errorf("structured Responses text config = %#v, %v; want json_object", textConfig, err)
		}
		_, _ = io.WriteString(w, `{"status":"completed","output_text":"{\"ok\":true}","usage":{"input_tokens":8,"output_tokens":5,"total_tokens":13}}`)
	}))
	defer server.Close()

	provider := NewCodexProvider("api-key", "codex-model", server.URL)
	capture := &providerObserverCapture{}
	result, err := provider.RunStructured(WithProviderObserver(context.Background(), capture), StructuredTask{
		Operation:    "playbook.digest",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if err != nil {
		t.Fatalf("RunStructured() error = %v", err)
	}
	if result.Text != `{"ok":true}` {
		t.Fatalf("RunStructured() text = %q, want JSON object text", result.Text)
	}
	if result.Usage != (ProviderTokenUsage{InputTokens: 8, OutputTokens: 5, TotalTokens: 13}) {
		t.Fatalf("RunStructured() usage = %#v, want Responses usage", result.Usage)
	}
	if len(capture.usages) != 1 || capture.usages[0] != result.Usage {
		t.Fatalf("usage events = %#v, want one structured usage event", capture.usages)
	}
	if len(capture.labels) != 1 || !strings.HasSuffix(capture.labels[0], "/playbook.digest") {
		t.Fatalf("usage labels = %#v, want playbook.digest", capture.labels)
	}
}
