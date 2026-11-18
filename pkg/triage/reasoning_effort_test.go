package triage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestProviderProfileNormalizesAndValidatesReasoningEffort(t *testing.T) {
	for effort, want := range map[string]string{
		"": "", "none": "none", "minimal": "minimal", "low": "low", "medium": "medium",
		"high": "high", "xhigh": "xhigh", "max": "max", " MAX ": "max", "XHigh": "xhigh",
	} {
		normalized, err := ProviderProfile{Provider: "codex", APIKey: "key", ReasoningEffort: effort}.Normalize()
		if err != nil {
			t.Errorf("Normalize() rejected reasoning effort %q: %v", effort, err)
			continue
		}
		if normalized.ReasoningEffort != want {
			t.Errorf("reasoning effort %q normalized to %q, want %q", effort, normalized.ReasoningEffort, want)
		}
	}
	for _, effort := range []string{"maximum", "ultra", "3", "max,high"} {
		if _, err := (ProviderProfile{Provider: "codex", APIKey: "key", ReasoningEffort: effort}).Normalize(); !errors.Is(err, ErrProviderValidation) {
			t.Errorf("Normalize() error for reasoning effort %q = %v, want ErrProviderValidation", effort, err)
		}
	}
	// A deployment may set the effort once and switch providers; a provider
	// that has no use for it still starts.
	if _, err := (ProviderProfile{Provider: "rule", ReasoningEffort: "max"}).Normalize(); err != nil {
		t.Errorf("Normalize() rejected a reasoning effort on the rule engine: %v", err)
	}
}

func TestResponsesRequestCarriesReasoningEffort(t *testing.T) {
	requestJSON := func(t *testing.T, profile ProviderProfile) string {
		t.Helper()
		profile.Provider, profile.Model, profile.APIKey = "codex", "codex-model", "key"
		provider, err := NewOpenAICompatibleProvider(profile)
		if err != nil {
			t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
		}
		encoded, err := json.Marshal(provider.newResponsesRequest("system", "user", true))
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		return string(encoded)
	}

	// Without an effort the request is what it always was, byte for byte.
	const unset = `{"model":"codex-model","instructions":"system","input":"user","max_output_tokens":2048,"text":{"format":{"type":"json_object"}}}`
	if got := requestJSON(t, ProviderProfile{}); got != unset {
		t.Fatalf("request without reasoning effort = %s, want %s", got, unset)
	}

	// Reasoning tokens count against max_output_tokens, so a reasoning
	// request gets room to finish its answer.
	const reasoning = `{"model":"codex-model","instructions":"system","input":"user","max_output_tokens":8192,"reasoning":{"effort":"max"},"text":{"format":{"type":"json_object"}}}`
	if got := requestJSON(t, ProviderProfile{ReasoningEffort: " MAX "}); got != reasoning {
		t.Fatalf("request with reasoning effort max = %s, want %s", got, reasoning)
	}
	if got := requestJSON(t, ProviderProfile{ReasoningEffort: "high", MaxTokens: 16384}); !strings.Contains(got, `"max_output_tokens":16384,"reasoning":{"effort":"high"}`) {
		t.Fatalf("request lowered a larger output budget: %s", got)
	}
	// Effort none spends no reasoning tokens and needs no extra room.
	if got := requestJSON(t, ProviderProfile{ReasoningEffort: "none"}); !strings.Contains(got, `"max_output_tokens":2048,"reasoning":{"effort":"none"}`) {
		t.Fatalf("request with reasoning effort none = %s", got)
	}
}

func TestChatRequestIgnoresReasoningEffort(t *testing.T) {
	provider, err := NewOpenAICompatibleProvider(ProviderProfile{Provider: "openai", WireAPI: WireAPIChat, Model: "chat-model", APIKey: "key", ReasoningEffort: "high"})
	if err != nil {
		t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
	}
	encoded, err := json.Marshal(provider.newRequest("system", "user", true))
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if strings.Contains(string(encoded), "reasoning") || !strings.Contains(string(encoded), `"max_tokens":2048`) {
		t.Fatalf("chat request changed with a reasoning effort: %s", encoded)
	}
}

func TestOpenAICompatibleResponsesWireSendsReasoningEffort(t *testing.T) {
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("request path = %q, want /responses", r.URL.Path)
		}
		body, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"status":"completed","output_text":"{\"issue_id\":\"issue-1\",\"summary\":\"pod is unhealthy\",\"root_cause\":\"container crashed\",\"severity\":\"HIGH\",\"remediation_plan\":\"inspect the pod\",\"action_type\":\"Manual\",\"proposed_command\":\"kubectl describe pod worker -n default\",\"confidence_score\":0.8}"}`)
	}))
	defer server.Close()

	provider, err := NewProviderFromProfile(ProviderProfile{
		Provider: "codex", Endpoint: server.URL, Model: "gpt-6-luna", APIKey: "key",
		ReasoningEffort: "max", AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewProviderFromProfile() error = %v", err)
	}
	if _, err := provider.Diagnose(context.Background(), &scanner.Issue{ID: "issue-1", Namespace: "default", Kind: "Pod", Name: "worker"}); err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	var request struct {
		Model           string `json:"model"`
		MaxOutputTokens int    `json:"max_output_tokens"`
		Reasoning       struct {
			Effort string `json:"effort"`
		} `json:"reasoning"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if request.Model != "gpt-6-luna" || request.Reasoning.Effort != "max" || request.MaxOutputTokens != minReasoningOutputTokens {
		t.Fatalf("request = %s, want model gpt-6-luna with reasoning effort max and a %d token budget", body, minReasoningOutputTokens)
	}
}
