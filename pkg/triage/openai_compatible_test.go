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
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestOpenAICompatibleProviderSendsBoundedConfiguredRequest(t *testing.T) {
	const secret = "compatible-provider-secret"
	var request compatibleRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("request path = %q, want /v1/chat/completions", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+secret {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("OpenAI-Organization"); got != "org-test" {
			t.Errorf("OpenAI-Organization = %q", got)
		}
		if got := r.Header.Get("X-Request-Tag"); got != "triage" {
			t.Errorf("X-Request-Tag = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		if len(body) > 4096 {
			t.Errorf("request body length = %d, want bounded body", len(body))
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"password=compatible-provider-secret"}}]}`)
	}))
	defer server.Close()

	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:          "custom",
		Endpoint:          server.URL + "/v1",
		EndpointAllowlist: []string{server.URL},
		Model:             "test-model",
		APIKey:            secret,
		Organization:      "org-test",
		Headers:           map[string]string{"X-Request-Tag": "triage"},
		MaxTokens:         123,
		Temperature:       0.2,
		TopP:              0.7,
		Stop:              []string{"DONE"},
		Timeout:           time.Second,
		SecretValues:      []string{secret},
	})
	if err != nil {
		t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
	}

	reply, err := provider.Explain(context.Background(), "inspect "+secret, nil)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if strings.Contains(reply, secret) {
		t.Fatalf("Explain() leaked response secret: %q", reply)
	}
	if request.Model != "test-model" || request.MaxTokens != 123 || request.Temperature == nil || *request.Temperature != 0.2 || request.TopP == nil || *request.TopP != 0.7 {
		t.Fatalf("request options = %#v", request)
	}
	if len(request.Stop) != 1 || request.Stop[0] != "DONE" {
		t.Fatalf("request stop = %#v", request.Stop)
	}
	if len(request.Messages) != 2 || strings.Contains(request.Messages[1].Content, secret) {
		t.Fatalf("request messages = %#v", request.Messages)
	}
}

func TestOpenAICompatibleProviderPreservesSecretCustomHeaderOnWire(t *testing.T) {
	const headerValue = "header-secret-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Provider-Secret"); got != headerValue {
			t.Errorf("X-Provider-Secret = %q, want %q", got, headerValue)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer server.Close()

	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:     "custom",
		Mode:         ProviderModeLocal,
		Endpoint:     server.URL,
		Model:        "test-model",
		APIKey:       "api-key",
		Headers:      map[string]string{"X-Provider-Secret": headerValue},
		SecretValues: []string{headerValue},
	})
	if err != nil {
		t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
	}
	if _, err := provider.Explain(context.Background(), "hello", nil); err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
}

func TestOpenAICompatibleProviderDiagnoseValidatesAndSanitizesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"issue_id\":\"issue-1\",\"summary\":\"bad\",\"root_cause\":\"password=provider-secret\",\"severity\":\"HIGH\",\"remediation_plan\":\"kubectl get pods -n default\",\"action_type\":\"Manual\",\"proposed_command\":\"kubectl get pods -n default\",\"confidence_score\":0.8}"}}]}`)
	}))
	defer server.Close()

	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:     "localai",
		Endpoint:     server.URL + "/v1",
		Model:        "local-model",
		SecretValues: []string{"provider-secret"},
	})
	if err != nil {
		t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
	}
	diagnosis, err := provider.Diagnose(context.Background(), &scanner.Issue{ID: "issue-1", Kind: "Pod", Name: "worker"})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if diagnosis.IssueID != "issue-1" || strings.Contains(diagnosis.RootCause, "provider-secret") {
		t.Fatalf("Diagnose() = %#v", diagnosis)
	}
}

func TestOpenAICompatibleProviderNormalizesBoundedErrors(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		status     int
		want       ProviderErrorKind
		maxBody    int
		wantSecret string
	}{
		{name: "empty choices", body: `{"choices":[]}`, status: http.StatusOK, want: ProviderErrorResponse},
		{name: "large body", body: strings.Repeat("x", 128), status: http.StatusOK, want: ProviderErrorLimit, maxBody: 32},
		{name: "http error", body: `{"error":{"message":"api_key=do-not-return"}}`, status: http.StatusBadGateway, want: ProviderErrorHTTP, wantSecret: "do-not-return"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			provider, err := NewOpenAICompatibleProvider(ProviderProfile{
				Provider:         "localai",
				Endpoint:         server.URL,
				Model:            "model",
				MaxResponseBytes: tc.maxBody,
				SecretValues:     []string{"do-not-return"},
			})
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}
			_, err = provider.Explain(context.Background(), "hello", nil)
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) || providerErr.Kind != tc.want {
				t.Fatalf("Explain() error = %#v, want kind %s", err, tc.want)
			}
			if tc.wantSecret != "" && strings.Contains(err.Error(), tc.wantSecret) {
				t.Fatalf("error leaked response body secret: %v", err)
			}
		})
	}
}

func TestOpenAICompatibleProviderHonorsCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer server.Close()
	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider: "localai",
		Endpoint: server.URL,
		Model:    "model",
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("constructor error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = provider.Explain(ctx, "hello", nil)
	<-started
	if !errors.Is(err, context.DeadlineExceeded) {
		var providerErr *ProviderError
		if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorTimeout {
			t.Fatalf("Explain() error = %#v, want deadline/timeout", err)
		}
	}
}

func TestNewOpenAICompatibleProviderEnforcesProviderWireMatrix(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wireAPI  WireAPI
		wantErr  error
	}{
		{name: "openai chat", provider: "openai", wireAPI: WireAPIChat},
		{name: "openai responses", provider: "openai", wireAPI: WireAPIResponses},
		{name: "codex chat", provider: "codex", wireAPI: WireAPIChat},
		{name: "codex responses", provider: "codex", wireAPI: WireAPIResponses},
		{name: "localai chat", provider: "localai", wireAPI: WireAPIChat},
		{name: "ollama chat", provider: "ollama", wireAPI: WireAPIChat},
		{name: "litellm chat", provider: "litellm", wireAPI: WireAPIChat},
		{name: "groq chat", provider: "groq", wireAPI: WireAPIChat},
		{name: "deepseek chat", provider: "deepseek", wireAPI: WireAPIChat},
		{name: "custom chat", provider: "custom", wireAPI: WireAPIChat},
		{name: "localai responses", provider: "localai", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "ollama responses", provider: "ollama", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "litellm responses", provider: "litellm", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "groq responses", provider: "groq", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "deepseek responses", provider: "deepseek", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "custom responses", provider: "custom", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "cloud provider", provider: "azureopenai", wireAPI: WireAPIChat, wantErr: ErrProviderValidation},
		{name: "native provider", provider: "claude", wireAPI: WireAPIChat, wantErr: ErrProviderValidation},
		{name: "unknown provider", provider: "unknown-compatible", wireAPI: WireAPIChat, wantErr: ErrUnknownProvider},
		{name: "unknown wire", provider: "openai", wireAPI: WireAPI("legacy"), wantErr: ErrProviderValidation},
	}

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := requests.Load()
			provider, err := NewOpenAICompatibleProvider(ProviderProfile{
				Provider:      tc.provider,
				WireAPI:       tc.wireAPI,
				Endpoint:      server.URL,
				Model:         "model",
				APIKey:        "key",
				AllowLoopback: true,
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("NewOpenAICompatibleProvider() error = %v, want %v", err, tc.wantErr)
				}
				var providerErr *ProviderError
				if !errors.As(err, &providerErr) {
					t.Fatalf("NewOpenAICompatibleProvider() error = %#v, want ProviderError", err)
				}
				wantKind := ProviderErrorValidation
				if errors.Is(tc.wantErr, ErrUnknownProvider) {
					wantKind = ProviderErrorUnknown
				}
				if providerErr.Kind != wantKind {
					t.Fatalf("NewOpenAICompatibleProvider() error kind = %s, want %s", providerErr.Kind, wantKind)
				}
				if provider != nil {
					t.Fatalf("NewOpenAICompatibleProvider() provider = %T, want nil", provider)
				}
				if got := requests.Load(); got != before {
					t.Fatalf("rejected constructor made %d HTTP requests, want 0", got-before)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
			}
			if provider == nil {
				t.Fatal("NewOpenAICompatibleProvider() provider = nil")
			}
		})
	}
}

func TestOpenAICompatibleProviderRunStructuredRejectsUnsupportedProviderWireMatrix(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wireAPI  WireAPI
	}{
		{name: "deepseek responses", provider: "deepseek", wireAPI: WireAPIResponses},
		{name: "groq responses", provider: "groq", wireAPI: WireAPIResponses},
		{name: "cloud provider", provider: "azureopenai", wireAPI: WireAPIChat},
		{name: "unknown provider", provider: "unknown-compatible", wireAPI: WireAPIChat},
		{name: "unknown wire", provider: "openai", wireAPI: WireAPI("legacy")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			defer server.Close()

			provider, err := NewOpenAICompatibleProvider(ProviderProfile{
				Provider:      "openai",
				WireAPI:       WireAPIChat,
				Endpoint:      server.URL,
				Model:         "model",
				APIKey:        "key",
				AllowLoopback: true,
			})
			if err != nil {
				t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
			}
			provider.profile.Provider = tc.provider
			provider.profile.WireAPI = tc.wireAPI

			_, err = provider.RunStructured(context.Background(), StructuredTask{
				Operation:    "playbook.digest",
				SystemPrompt: "system",
				UserPrompt:   "user",
			})
			if !errors.Is(err, ErrStructuredTaskUnsupported) {
				t.Fatalf("RunStructured() error = %v, want ErrStructuredTaskUnsupported", err)
			}
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorDisabled {
				t.Fatalf("RunStructured() error = %#v, want disabled ProviderError", err)
			}
			if requests.Load() != 0 {
				t.Fatalf("rejected structured task made %d HTTP requests, want 0", requests.Load())
			}
		})
	}
}

type compatibleRequest struct {
	Model       string              `json:"model"`
	Messages    []compatibleMessage `json:"messages"`
	MaxTokens   int                 `json:"max_tokens"`
	Temperature *float64            `json:"temperature"`
	TopP        *float64            `json:"top_p"`
	Stop        []string            `json:"stop"`
}
