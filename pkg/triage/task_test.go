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

func TestStructuredTaskValidatesBoundsAndUnsupportedProviders(t *testing.T) {
	t.Run("invalid operation", func(t *testing.T) {
		_, err := NewNoOpProvider().RunStructured(context.Background(), StructuredTask{
			Operation:    "playbook.digest\nleak",
			SystemPrompt: "system",
			UserPrompt:   "user",
		})
		if !errors.Is(err, ErrProviderValidation) {
			t.Fatalf("RunStructured() error = %v, want ErrProviderValidation", err)
		}
	})

	t.Run("oversized prompt", func(t *testing.T) {
		_, err := NewNoOpProvider().RunStructured(context.Background(), StructuredTask{
			Operation:    "playbook.digest",
			SystemPrompt: strings.Repeat("s", defaultMaxRequestBytes),
			UserPrompt:   strings.Repeat("u", defaultMaxRequestBytes),
		})
		if !errors.Is(err, ErrProviderResponseTooLarge) {
			t.Fatalf("RunStructured() error = %v, want ErrProviderResponseTooLarge", err)
		}
	})

	t.Run("unsupported deterministic provider", func(t *testing.T) {
		_, err := NewRuleBasedProvider("secret").RunStructured(context.Background(), StructuredTask{
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
	})
}

func TestStructuredTaskValidationErrorsUseSafeObserverOperationLabel(t *testing.T) {
	secret := "operation-secret"
	capture := &structuredObserverCapture{}
	_, err := NewRuleBasedProvider(secret).RunStructured(WithProviderErrorObserver(context.Background(), capture), StructuredTask{
		Operation:    "playbook.digest\n" + secret,
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if !errors.Is(err, ErrProviderValidation) {
		t.Fatalf("RunStructured() error = %v, want ErrProviderValidation", err)
	}
	if len(capture.errorOperations) != 1 {
		t.Fatalf("error operations = %#v, want one observation", capture.errorOperations)
	}
	if capture.errorOperations[0] != "structured" {
		t.Fatalf("error operation = %q, want safe structured label", capture.errorOperations[0])
	}
	if strings.Contains(capture.errorOperations[0], secret) || strings.ContainsAny(capture.errorOperations[0], "\r\n") {
		t.Fatalf("unsafe error operation label: %q", capture.errorOperations[0])
	}
}

func TestStructuredTaskFinalizationRedactsJSONEscapedSecrets(t *testing.T) {
	secret := "line\nquote\"secret"
	output, err := json.Marshal(map[string]string{"safe": "ok", "value": secret})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	provider := NewHarnessProvider("/bin/sh", []string{"-c", "printf '%s' \"$1\"", "sh", string(output)}, secret)

	result, err := provider.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.digest",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if err != nil {
		t.Fatalf("RunStructured() error = %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(result.Text), &decoded); err != nil {
		t.Fatalf("decode structured output: %v; text=%s", err, result.Text)
	}
	if decoded["safe"] != "ok" {
		t.Fatalf("safe value = %q, want ok; output=%s", decoded["safe"], result.Text)
	}
	if decoded["value"] == secret || strings.Contains(decoded["value"], "quote") {
		t.Fatalf("structured secret survived JSON-aware redaction: %#v", decoded)
	}
}

func TestHarnessProviderRunStructuredBoundsAndRedactsOutputAndStderr(t *testing.T) {
	secret := "configured-secret"
	provider := NewHarnessProvider("/bin/sh", []string{"-c", "echo '{\"value\":\"configured-secret\",\"ok\":true}'; echo configured-secret >&2"}, secret)

	result, err := provider.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.digest",
		SystemPrompt: "system configured-secret",
		UserPrompt:   "user configured-secret",
	})
	if err != nil {
		t.Fatalf("RunStructured() error = %v", err)
	}
	if strings.Contains(result.Text, secret) {
		t.Fatalf("RunStructured() leaked secret in output: %s", result.Text)
	}
	if !json.Valid([]byte(result.Text)) {
		t.Fatalf("RunStructured() text is not JSON: %s", result.Text)
	}

	oversized := NewHarnessProvider("/bin/sh", []string{"-c", "dd if=/dev/zero bs=1 count=33 2>/dev/null"})
	_, err = oversized.RunStructured(context.Background(), StructuredTask{
		Operation:      "playbook.digest",
		SystemPrompt:   "system",
		UserPrompt:     "user",
		MaxOutputBytes: 32,
	})
	if !errors.Is(err, ErrProviderResponseTooLarge) {
		t.Fatalf("RunStructured() error = %v, want ErrProviderResponseTooLarge", err)
	}
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Fatalf("RunStructured() error leaked stderr secret: %v", err)
	}
}

func TestOpenAICompatibleProviderRunStructuredUsesProfileBoundsRedactionAndUsage(t *testing.T) {
	secret := "profile-secret"
	var bodySeen atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("request path = %q, want /chat/completions", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		bodySeen.Store(true)
		if strings.Contains(string(body), secret) {
			t.Errorf("request body leaked configured secret: %s", body)
		}
		var request compatibleChatRequest
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request.ResponseFormat == nil || request.ResponseFormat.Type != "json_object" {
			t.Errorf("structured request response_format = %#v, want json_object", request.ResponseFormat)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"safe\":true,\"secret\":\"profile-secret\"}"}}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}`)
	}))
	defer server.Close()

	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:         "custom",
		Mode:             ProviderModeLocal,
		Model:            "local-model",
		Endpoint:         server.URL,
		MaxResponseBytes: 256,
		SecretValues:     []string{secret},
	})
	if err != nil {
		t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
	}
	capture := &providerObserverCapture{}
	result, err := provider.RunStructured(WithProviderObserver(context.Background(), capture), StructuredTask{
		Operation:    "playbook.normalize",
		SystemPrompt: "system " + secret,
		UserPrompt:   "user " + secret,
	})
	if err != nil {
		t.Fatalf("RunStructured() error = %v", err)
	}
	if !bodySeen.Load() {
		t.Fatal("server did not receive request")
	}
	if strings.Contains(result.Text, secret) {
		t.Fatalf("RunStructured() leaked secret in output: %s", result.Text)
	}
	if result.Usage != (ProviderTokenUsage{InputTokens: 2, OutputTokens: 3, TotalTokens: 5}) {
		t.Fatalf("RunStructured() usage = %#v, want provider usage", result.Usage)
	}
	if len(capture.usages) != 1 || capture.usages[0] != result.Usage {
		t.Fatalf("observer usages = %#v, want structured usage", capture.usages)
	}
	if len(capture.labels) != 1 || !strings.HasSuffix(capture.labels[0], "/playbook.normalize") {
		t.Fatalf("observer labels = %#v, want bounded task operation", capture.labels)
	}
}

func TestClaudeProviderRunStructuredFailsClosedUntilNativeStructuredOutputExists(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, `{"content":[{"text":"{\"ok\":true}"}],"usage":{"input_tokens":4,"output_tokens":6}}`)
	}))
	defer server.Close()

	provider := NewClaudeProvider("api-key", "claude-model", server.URL)
	_, err := provider.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.learn",
		SystemPrompt: "task system",
		UserPrompt:   "task user",
	})
	if !errors.Is(err, ErrStructuredTaskUnsupported) {
		t.Fatalf("RunStructured() error = %v, want ErrStructuredTaskUnsupported", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("Claude structured task made %d HTTP requests, want 0 until native structured output exists", requests.Load())
	}
}

func TestCloudProviderRunStructuredUsesStructuredPayloadAndUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("request path = %q, want /chat/completions", r.URL.Path)
		}
		var request map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		var messages []compatibleMessage
		if err := json.Unmarshal(request["messages"], &messages); err != nil {
			t.Errorf("decode messages: %v", err)
		}
		if len(messages) != 2 || messages[0].Content != "cloud system" || messages[1].Content != "cloud user" {
			t.Errorf("messages = %#v, want task prompts", messages)
		}
		var responseFormat responseFormat
		if err := json.Unmarshal(request["response_format"], &responseFormat); err != nil || responseFormat.Type != "json_object" {
			t.Errorf("response_format = %#v, %v; want json_object", responseFormat, err)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"ok\":true}"}}],"usage":{"prompt_tokens":7,"completion_tokens":8,"total_tokens":15}}`)
	}))
	defer server.Close()

	provider, err := NewCloudProvider(ProviderProfile{
		Provider:      "azureopenai",
		Endpoint:      server.URL,
		Model:         "cloud-model",
		APIKey:        "api-key",
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewCloudProvider() error = %v", err)
	}
	result, err := provider.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.resolve",
		SystemPrompt: "cloud system",
		UserPrompt:   "cloud user",
	})
	if err != nil {
		t.Fatalf("RunStructured() error = %v", err)
	}
	if result.Text != `{"ok":true}` {
		t.Fatalf("RunStructured() text = %q, want JSON output", result.Text)
	}
	if result.Usage != (ProviderTokenUsage{InputTokens: 7, OutputTokens: 8, TotalTokens: 15}) {
		t.Fatalf("RunStructured() usage = %#v, want cloud usage", result.Usage)
	}
}

func TestCloudProviderRunStructuredRejectsUnsupportedStructuredWireFormat(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, `{"text":"{\"ok\":true}"}`)
	}))
	defer server.Close()

	provider, err := NewCloudProvider(ProviderProfile{
		Provider:      "cohere",
		Endpoint:      server.URL,
		Model:         "command-r",
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewCloudProvider() error = %v", err)
	}
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
		t.Fatalf("unsupported structured task made %d HTTP requests, want 0", requests.Load())
	}
}

func TestHTTPStructuredTasksEnforceMaxOutputBytesAtReadBoundary(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		provider func(string) StructuredTaskRunner
	}{
		{
			name: "codex responses",
			body: `{"status":"completed","output_text":"{\"ok\":true}"}` + strings.Repeat(" ", 128),
			provider: func(endpoint string) StructuredTaskRunner {
				return NewCodexProvider("api-key", "codex-model", endpoint)
			},
		},
		{
			name: "openai compatible chat",
			body: `{"choices":[{"message":{"content":"{\"ok\":true}"}}]}` + strings.Repeat(" ", 128),
			provider: func(endpoint string) StructuredTaskRunner {
				provider, err := NewOpenAICompatibleProvider(ProviderProfile{
					Provider:      "custom",
					Mode:          ProviderModeLocal,
					Model:         "local-model",
					Endpoint:      endpoint,
					AllowLoopback: true,
				})
				if err != nil {
					t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
				}
				return provider
			},
		},
		{
			name: "azure cloud",
			body: `{"choices":[{"message":{"content":"{\"ok\":true}"}}]}` + strings.Repeat(" ", 128),
			provider: func(endpoint string) StructuredTaskRunner {
				provider, err := NewCloudProvider(ProviderProfile{
					Provider:      "azureopenai",
					Endpoint:      endpoint,
					Model:         "cloud-model",
					APIKey:        "api-key",
					AllowLoopback: true,
				})
				if err != nil {
					t.Fatalf("NewCloudProvider() error = %v", err)
				}
				return provider
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()

			_, err := tc.provider(server.URL).RunStructured(context.Background(), StructuredTask{
				Operation:      "playbook.digest",
				SystemPrompt:   "system",
				UserPrompt:     "user",
				MaxOutputBytes: 32,
			})
			if !errors.Is(err, ErrProviderResponseTooLarge) {
				t.Fatalf("RunStructured() error = %v, want ErrProviderResponseTooLarge", err)
			}
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorLimit {
				t.Fatalf("RunStructured() error = %#v, want limit ProviderError", err)
			}
		})
	}
}

func TestStructuredTasksRejectInvalidJSONResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"not-json"}}]}`)
	}))
	defer server.Close()

	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:      "custom",
		Mode:          ProviderModeLocal,
		Model:         "local-model",
		Endpoint:      server.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
	}
	_, err = provider.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.normalize",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorResponse {
		t.Fatalf("RunStructured() error = %#v, want response ProviderError", err)
	}
}

func TestNewProviderFromProfileReturnsStructuredTaskRunners(t *testing.T) {
	profiles := []ProviderProfile{
		{Provider: "custom", Mode: ProviderModeLocal, Model: "local-model", Endpoint: "http://127.0.0.1:11435/v1"},
		{Provider: "noop"},
		{Provider: "rule"},
	}
	for _, profile := range profiles {
		t.Run(profile.Provider, func(t *testing.T) {
			provider, err := NewProviderFromProfile(profile)
			if err != nil {
				t.Fatalf("NewProviderFromProfile() error = %v", err)
			}
			if _, ok := provider.(StructuredTaskRunner); !ok {
				t.Fatalf("%T does not implement StructuredTaskRunner", provider)
			}
		})
	}
}

func TestDeepSeekProviderRunStructuredDelegatesToChatJSONMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("request path = %q, want /chat/completions", r.URL.Path)
		}
		var request openAIRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if request.ResponseFormat == nil || request.ResponseFormat.Type != "json_object" {
			t.Errorf("response_format = %#v, want json_object", request.ResponseFormat)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"ok\":true}"}}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	}))
	defer server.Close()

	provider := NewDeepSeekProvider("api-key", "deepseek-model", server.URL)
	result, err := provider.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.digest",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if err != nil {
		t.Fatalf("RunStructured() error = %v", err)
	}
	if result.Text != `{"ok":true}` {
		t.Fatalf("RunStructured() text = %q, want delegated JSON output", result.Text)
	}
	if result.Usage != (ProviderTokenUsage{InputTokens: 3, OutputTokens: 2, TotalTokens: 5}) {
		t.Fatalf("RunStructured() usage = %#v, want delegated usage", result.Usage)
	}
}

func TestStructuredTaskDelegatesThroughCachedAndDeadlineProviders(t *testing.T) {
	runner := &recordingStructuredProvider{result: StructuredTaskResult{Text: `{"ok":true}`}}

	cached := &CachedProvider{provider: runner, name: "cached"}
	result, err := cached.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.resolve",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if err != nil {
		t.Fatalf("cached RunStructured() error = %v", err)
	}
	if result.Text != `{"ok":true}` || runner.calls.Load() != 1 {
		t.Fatalf("cached RunStructured() = %#v, calls=%d; want delegated result", result, runner.calls.Load())
	}

	deadline := &deadlineProvider{provider: runner, timeout: time.Second}
	_, err = deadline.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.learn",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if err != nil {
		t.Fatalf("deadline RunStructured() error = %v", err)
	}
	if runner.lastDeadline.IsZero() {
		t.Fatal("deadline RunStructured() did not pass a context deadline")
	}
	if runner.lastTask.MaxOutputBytes != maxProviderResponseBytes {
		t.Fatalf("deadline forwarded MaxOutputBytes = %d, want default %d", runner.lastTask.MaxOutputBytes, maxProviderResponseBytes)
	}
}

func TestDeadlineProviderRunStructuredValidatesDelegatedResult(t *testing.T) {
	secret := "deadline-secret"
	deadline := &deadlineProvider{
		provider: &recordingStructuredProvider{result: StructuredTaskResult{
			Text:  `{"password":"deadline-secret"}`,
			Usage: ProviderTokenUsage{InputTokens: -1, OutputTokens: 2},
		}},
		timeout: time.Second,
	}
	result, err := deadline.RunStructured(context.Background(), StructuredTask{
		Operation:      "playbook.learn",
		SystemPrompt:   "system",
		UserPrompt:     "user",
		MaxOutputBytes: 64,
	})
	if err != nil {
		t.Fatalf("RunStructured() error = %v", err)
	}
	if strings.Contains(result.Text, secret) {
		t.Fatalf("RunStructured() leaked delegated secret: %s", result.Text)
	}
	if result.Usage.InputTokens != 0 || result.Usage.OutputTokens != 2 || result.Usage.TotalTokens != 2 {
		t.Fatalf("RunStructured() usage = %#v, want normalized usage", result.Usage)
	}

	deadline.provider = &recordingStructuredProvider{result: StructuredTaskResult{Text: "not-json"}}
	_, err = deadline.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.learn",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorResponse {
		t.Fatalf("RunStructured() error = %#v, want response ProviderError", err)
	}
}

func TestStructuredTaskContextCancellation(t *testing.T) {
	provider := NewHarnessProvider("/bin/sh", []string{"-c", "sleep 5"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := provider.RunStructured(ctx, StructuredTask{
		Operation:    "playbook.digest",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunStructured() error = %v, want context.Canceled", err)
	}
}

type recordingStructuredProvider struct {
	calls        atomic.Int64
	lastDeadline time.Time
	lastTask     StructuredTask
	result       StructuredTaskResult
	err          error
}

func (p *recordingStructuredProvider) Name() string { return "recording" }

func (p *recordingStructuredProvider) Diagnose(context.Context, *scanner.Issue) (*Diagnosis, error) {
	return nil, nil
}

func (p *recordingStructuredProvider) Explain(context.Context, string, *scanner.Issue) (string, error) {
	return "", nil
}

func (p *recordingStructuredProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	p.calls.Add(1)
	p.lastTask = task
	if deadline, ok := ctx.Deadline(); ok {
		p.lastDeadline = deadline
	}
	return p.result, p.err
}

type structuredObserverCapture struct {
	errorOperations []string
}

func (capture *structuredObserverCapture) ObserveProviderError(_ string, operation string, _ ProviderErrorKind) {
	capture.errorOperations = append(capture.errorOperations, operation)
}
