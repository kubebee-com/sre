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

func TestOpenAICompatibleResponsesWireUsesResponsesEndpoint(t *testing.T) {
	const apiKey = "codex-test-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Fatalf("request path = %q, want /responses", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
			t.Fatalf("authorization = %q, want bearer token", got)
		}
		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request["model"] != "codex-host-model" {
			t.Fatalf("model = %#v, want codex-host-model", request["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"completed","output_text":"{\"issue_id\":\"issue-1\",\"summary\":\"pod is unhealthy\",\"root_cause\":\"container crashed\",\"severity\":\"HIGH\",\"remediation_plan\":\"inspect the pod\",\"action_type\":\"Manual\",\"proposed_command\":\"kubectl describe pod worker -n default\",\"confidence_score\":0.8}"}`))
	}))
	defer server.Close()

	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:      "codex",
		Endpoint:      server.URL,
		Model:         "codex-host-model",
		APIKey:        apiKey,
		WireAPI:       WireAPIResponses,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
	}

	diagnosis, err := provider.Diagnose(context.Background(), &scanner.Issue{
		ID:        "issue-1",
		Namespace: "default",
		Kind:      "Pod",
		Name:      "worker",
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if diagnosis == nil || diagnosis.IssueID != "issue-1" {
		t.Fatalf("diagnosis = %#v, want issue-1", diagnosis)
	}
}

func TestProviderFactoryRoutesCodexAliasToResponsesAPI(t *testing.T) {
	const apiKey = "codex-factory-key"
	var request compatibleResponsesRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("request path = %q, want /responses", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode Responses request: %v", err)
		}
		_, _ = io.WriteString(w, `{"status":"completed","output_text":"factory response"}`)
	}))
	defer server.Close()

	provider, err := NewProviderFromProfile(ProviderProfile{
		Provider:      "codex",
		Endpoint:      server.URL,
		Model:         "codex-model",
		APIKey:        apiKey,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewProviderFromProfile() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "hello", nil)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if reply != "factory response" {
		t.Fatalf("Explain() = %q, want factory response", reply)
	}
	if request.Model != "codex-model" {
		t.Fatalf("Responses model = %q, want codex-model", request.Model)
	}
}

func TestOpenAICompatibleResponsesWireParsesMessageOutputItems(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"safe explanation"}]}]}`))
	}))
	defer server.Close()

	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:      "codex",
		Endpoint:      server.URL,
		Model:         "codex-host-model",
		APIKey:        "codex-test-key",
		WireAPI:       WireAPIResponses,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewOpenAICompatibleProvider() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "explain this", nil)
	if err != nil || reply != "safe explanation" {
		t.Fatalf("Explain() = %q, %v; want safe explanation", reply, err)
	}
}

func TestOpenAICompatibleResponsesWireRequiresCompletedStatus(t *testing.T) {
	tests := []struct {
		name   string
		status string
		wantOK bool
	}{
		{name: "missing", wantOK: false},
		{name: "failed", status: "failed", wantOK: false},
		{name: "in progress", status: "in_progress", wantOK: false},
		{name: "completed", status: "completed", wantOK: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := `{"output_text":"safe explanation"}`
				if tc.status != "" {
					body = `{"status":"` + tc.status + `","output_text":"safe explanation"}`
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			provider, err := NewOpenAICompatibleProvider(ProviderProfile{
				Provider:      "codex",
				Endpoint:      server.URL,
				Model:         "model",
				APIKey:        "key",
				WireAPI:       WireAPIResponses,
				AllowLoopback: true,
			})
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}
			reply, err := provider.Explain(context.Background(), "hello", nil)
			if tc.wantOK {
				if err != nil || reply != "safe explanation" {
					t.Fatalf("Explain() = %q, %v; want completed response", reply, err)
				}
				return
			}
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorResponse {
				t.Fatalf("Explain() error = %#v, want response ProviderError", err)
			}
		})
	}
}

func TestOpenAICompatibleResponsesWireRejectsMalformedAndEmptyOutput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed", body: `{"output":[`},
		{name: "empty", body: `{"output":[{"type":"message","content":[]}]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			provider, err := NewOpenAICompatibleProvider(ProviderProfile{
				Provider:      "codex",
				Endpoint:      server.URL,
				Model:         "model",
				APIKey:        "key",
				WireAPI:       WireAPIResponses,
				AllowLoopback: true,
			})
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}
			_, err = provider.Explain(context.Background(), "hello", nil)
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorResponse {
				t.Fatalf("Explain() error = %#v, want response ProviderError", err)
			}
		})
	}
}

func TestProviderProfileValidatesWireAPIAndDefaultsCodexToResponses(t *testing.T) {
	profile, err := (ProviderProfile{Provider: "codex", APIKey: "key", Endpoint: "https://api.openai.com/v1"}).Normalize()
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if profile.WireAPI != WireAPIResponses {
		t.Fatalf("codex wire API = %q, want responses", profile.WireAPI)
	}
	if err := (ProviderProfile{Provider: "openai", WireAPI: WireAPI("unsupported"), APIKey: "key"}).Validate(); !errors.Is(err, ErrProviderValidation) {
		t.Fatalf("invalid wire API error = %v, want ErrProviderValidation", err)
	}
	if err := (ProviderProfile{Provider: "not-a-provider", Name: "openai"}).Validate(); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("unknown provider error = %v, want ErrUnknownProvider", err)
	}
}

func TestProviderErrorsDoNotExposeResponseSecrets(t *testing.T) {
	secret := "response-error-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"message":"token=` + secret + `"}}`))
	}))
	defer server.Close()
	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:      "codex",
		Endpoint:      server.URL,
		Model:         "model",
		APIKey:        "key",
		WireAPI:       WireAPIResponses,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("constructor error = %v", err)
	}
	_, err = provider.Explain(context.Background(), "hello", nil)
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("provider error leaked response secret: %v", err)
	}
}

func TestOpenAICompatibleProviderRedactsConfiguredHeaderValuesInResponses(t *testing.T) {
	const mapHeaderSecret = "map-header-secret"
	const customHeaderSecret = "custom-header-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"`+mapHeaderSecret+` `+customHeaderSecret+`"}}]}`)
	}))
	defer server.Close()

	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:      "custom",
		Mode:          ProviderModeLocal,
		Endpoint:      server.URL,
		Model:         "model",
		Headers:       map[string]string{"X-Map-Secret": mapHeaderSecret},
		CustomHeaders: http.Header{"X-Custom-Secret": []string{customHeaderSecret}},
	})
	if err != nil {
		t.Fatalf("constructor error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "hello", nil)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if strings.Contains(reply, mapHeaderSecret) || strings.Contains(reply, customHeaderSecret) {
		t.Fatalf("Explain() leaked configured header value: %q", reply)
	}
}

type providerObserverCapture struct {
	usages []ProviderTokenUsage
	labels []string
	errors []ProviderErrorKind
}

func (capture *providerObserverCapture) ObserveProviderUsage(provider, operation string, usage ProviderTokenUsage) {
	capture.labels = append(capture.labels, provider+"/"+operation)
	capture.usages = append(capture.usages, usage)
}

func (capture *providerObserverCapture) ObserveProviderError(_ string, _ string, kind ProviderErrorKind) {
	capture.errors = append(capture.errors, kind)
}

func TestNoOpProviderReportsDisabledAndCanceledErrors(t *testing.T) {
	provider := NewNoOpProvider()
	capture := &providerObserverCapture{}
	ctx := WithProviderErrorObserver(context.Background(), capture)
	if _, err := provider.Explain(ctx, "hello", nil); !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("Explain() error = %v, want ErrProviderDisabled", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := provider.Diagnose(canceled, &scanner.Issue{ID: "issue"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Diagnose() error = %v, want context.Canceled", err)
	}
	if len(capture.errors) != 2 || capture.errors[0] != ProviderErrorDisabled || capture.errors[1] != ProviderErrorCanceled {
		t.Fatalf("observer errors = %#v, want disabled and canceled", capture.errors)
	}
}

func TestHarnessProviderReportsFailureKinds(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		diagnose bool
		wantKind ProviderErrorKind
	}{
		{name: "command failure", args: []string{"-c", "exit 1"}, wantKind: ProviderErrorTransport},
		{name: "malformed diagnosis", args: []string{"-c", "printf invalid"}, diagnose: true, wantKind: ProviderErrorResponse},
		{name: "output limit", args: []string{"-c", "dd if=/dev/zero bs=1 count=1048577 2>/dev/null"}, wantKind: ProviderErrorLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider := NewHarnessProvider("/bin/sh", tc.args)
			capture := &providerObserverCapture{}
			ctx := WithProviderErrorObserver(context.Background(), capture)
			var err error
			if tc.diagnose {
				_, err = provider.Diagnose(ctx, &scanner.Issue{ID: "issue"})
			} else {
				_, err = provider.Explain(ctx, "hello", nil)
			}
			if err == nil {
				t.Fatal("provider call error = nil")
			}
			if len(capture.errors) != 1 || capture.errors[0] != tc.wantKind {
				t.Fatalf("observer errors = %#v, want %s", capture.errors, tc.wantKind)
			}
		})
	}
}

func TestOpenAICompatibleProviderReportsBoundedUsageAndErrors(t *testing.T) {
	secret := "observer-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/responses" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"completed","output_text":"safe result","usage":{"input_tokens":12,"output_tokens":7,"total_tokens":19}}`))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"message":"token=` + secret + `"}}`))
	}))
	defer server.Close()

	provider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:      "codex",
		Endpoint:      server.URL,
		Model:         "model",
		APIKey:        secret,
		WireAPI:       WireAPIResponses,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("constructor error = %v", err)
	}
	capture := &providerObserverCapture{}
	ctx := WithProviderObserver(context.Background(), capture)
	if result, err := provider.Explain(ctx, "hello", nil); err != nil || result != "safe result" {
		t.Fatalf("Explain() = %q, %v; want safe result", result, err)
	}
	if len(capture.usages) != 1 || capture.usages[0] != (ProviderTokenUsage{InputTokens: 12, OutputTokens: 7, TotalTokens: 19}) {
		t.Fatalf("usage events = %#v, want one bounded usage event", capture.usages)
	}
	if len(capture.labels) != 1 || strings.Contains(capture.labels[0], secret) || !strings.HasSuffix(capture.labels[0], "/explain") {
		t.Fatalf("usage labels = %#v, want sanitized explain label", capture.labels)
	}

	chatProvider, err := NewOpenAICompatibleProvider(ProviderProfile{
		Provider:      "openai",
		Endpoint:      server.URL,
		Model:         "model",
		APIKey:        secret,
		WireAPI:       WireAPIChat,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("chat constructor error = %v", err)
	}
	if _, err := chatProvider.Explain(ctx, "hello", nil); err == nil {
		t.Fatal("Explain() error = nil, want upstream error")
	}
	if len(capture.errors) != 1 || capture.errors[0] != ProviderErrorHTTP {
		t.Fatalf("error events = %#v, want one HTTP error event", capture.errors)
	}
}
