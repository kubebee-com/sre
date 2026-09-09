package triage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestProviderProfileValidationRejectsUnknownAndUnallowlistedProviders(t *testing.T) {
	if err := ValidateProviderProfile(ProviderProfile{Provider: "unknown-provider"}); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("ValidateProviderProfile() error = %v, want ErrUnknownProvider", err)
	}

	if err := ValidateProviderProfile(ProviderProfile{
		Provider: "custom",
		Endpoint: "https://untrusted.example/v1",
		Model:    "model",
	}); !errors.Is(err, ErrEndpointNotAllowed) {
		t.Fatalf("ValidateProviderProfile() error = %v, want ErrEndpointNotAllowed", err)
	}
}

func TestProviderProfileValidationAllowsExplicitLocalLoopbackAndRemoteAllowlist(t *testing.T) {
	local := ProviderProfile{
		Provider: "localai",
		Endpoint: "http://127.0.0.1:18080/v1",
		Model:    "local-model",
	}
	if err := ValidateProviderProfile(local); err != nil {
		t.Fatalf("local profile rejected: %v", err)
	}

	remote := ProviderProfile{
		Provider:          "custom",
		Endpoint:          "https://untrusted.example/v1",
		EndpointAllowlist: []string{"https://untrusted.example"},
		Model:             "remote-model",
		APIKey:            "secret",
	}
	if err := ValidateProviderProfile(remote); err != nil {
		t.Fatalf("allow-listed remote profile rejected: %v", err)
	}
}

func TestProviderFactoryKeepsModesExplicit(t *testing.T) {
	rule, err := NewProviderFromProfile(ProviderProfile{Provider: "rule"})
	if err != nil {
		t.Fatalf("rule provider construction failed: %v", err)
	}
	if !strings.Contains(strings.ToLower(rule.Name()), "rule") {
		t.Fatalf("rule provider name = %q, want visible rule mode", rule.Name())
	}

	noOp, err := NewProviderFromProfile(ProviderProfile{Provider: "noop"})
	if err != nil {
		t.Fatalf("noop provider construction failed: %v", err)
	}
	if !strings.Contains(strings.ToLower(noOp.Name()), "noop") {
		t.Fatalf("noop provider name = %q, want visible noop mode", noOp.Name())
	}

	if _, err := NewProviderFromProfile(ProviderProfile{Provider: "not-supported"}); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("unknown provider error = %v, want ErrUnknownProvider", err)
	}
}

func TestNewProviderFromProfileEnforcesOpenAICompatibleProviderWireMatrix(t *testing.T) {
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
		{name: "deepseek chat", provider: "deepseek", wireAPI: WireAPIChat},
		{name: "groq chat", provider: "groq", wireAPI: WireAPIChat},
		{name: "custom chat", provider: "custom", wireAPI: WireAPIChat},
		{name: "localai responses", provider: "localai", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "ollama responses", provider: "ollama", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "litellm responses", provider: "litellm", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "deepseek responses", provider: "deepseek", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "groq responses", provider: "groq", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "custom responses", provider: "custom", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
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
			provider, err := NewProviderFromProfile(ProviderProfile{
				Provider:      tc.provider,
				WireAPI:       tc.wireAPI,
				Endpoint:      server.URL,
				Model:         "model",
				APIKey:        "key",
				AllowLoopback: true,
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("NewProviderFromProfile() error = %v, want %v", err, tc.wantErr)
				}
				var providerErr *ProviderError
				if !errors.As(err, &providerErr) {
					t.Fatalf("NewProviderFromProfile() error = %#v, want ProviderError", err)
				}
				wantKind := ProviderErrorValidation
				if errors.Is(tc.wantErr, ErrUnknownProvider) {
					wantKind = ProviderErrorUnknown
				}
				if providerErr.Kind != wantKind {
					t.Fatalf("NewProviderFromProfile() error kind = %s, want %s", providerErr.Kind, wantKind)
				}
				if provider != nil {
					t.Fatalf("NewProviderFromProfile() provider = %T, want nil", provider)
				}
				if got := requests.Load(); got != before {
					t.Fatalf("rejected profile made %d HTTP requests, want 0", got-before)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewProviderFromProfile() error = %v", err)
			}
			if _, ok := provider.(*OpenAICompatibleProvider); !ok {
				t.Fatalf("NewProviderFromProfile() provider = %T, want *OpenAICompatibleProvider", provider)
			}
		})
	}
}

func TestProfileStoreCRUDAndDefaultAreConcurrencySafe(t *testing.T) {
	store := NewProfileStore()
	profile := ProviderProfile{Provider: "rule", Name: "rules"}
	if err := store.Add(profile); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := store.SetDefault("rules"); err != nil {
		t.Fatalf("SetDefault() error = %v", err)
	}
	got, ok := store.Default()
	if !ok || got.Name != "rules" {
		t.Fatalf("Default() = %#v, %t; want rules profile", got, ok)
	}

	const workers = 12
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			candidate := ProviderProfile{Provider: "rule", Name: "profile-" + string(rune('a'+index))}
			_ = store.Upsert(candidate)
			_, _ = store.Get(candidate.Name)
			_ = store.List()
		}(i)
	}
	wg.Wait()

	if err := store.Remove("rules"); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, ok := store.Default(); ok {
		t.Fatal("Default() returned removed profile")
	}
}

type sessionTestProvider struct {
	mu       sync.Mutex
	queries  []string
	issueIDs []string
}

func (p *sessionTestProvider) Name() string { return "session-test" }

func (p *sessionTestProvider) Diagnose(context.Context, *scanner.Issue) (*Diagnosis, error) {
	return nil, errors.New("diagnose is not used")
}

func (p *sessionTestProvider) Explain(_ context.Context, query string, issue *scanner.Issue) (string, error) {
	p.mu.Lock()
	p.queries = append(p.queries, query)
	if issue != nil {
		p.issueIDs = append(p.issueIDs, issue.ID)
	}
	p.mu.Unlock()
	return "safe reply", nil
}

func TestChatSessionManagerAuthenticatesBoundsExpiresAndSanitizesContext(t *testing.T) {
	provider := &sessionTestProvider{}
	now := time.Unix(100, 0).UTC()
	clock := now
	manager := NewChatSessionManager(provider,
		WithChatSessionTTL(2*time.Second),
		WithChatSessionMaxTurns(1),
		WithChatSessionClock(func() time.Time { return clock }),
		WithChatSessionSecrets("session-secret"),
	)

	session, err := manager.Create(context.Background(), "alice", &scanner.Issue{
		ID:      "issue-1",
		Kind:    "Pod",
		Name:    "worker",
		Details: "password=session-secret",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if session.ID == "" || session.ExpiresAt.IsZero() {
		t.Fatalf("Create() returned incomplete session: %#v", session)
	}

	if _, err := manager.Send(context.Background(), "mallory", session.ID, "hello"); !errors.Is(err, ErrChatUnauthorized) {
		t.Fatalf("unauthorized Send() error = %v, want ErrChatUnauthorized", err)
	}
	reply, err := manager.Send(context.Background(), "alice", session.ID, "hello")
	if err != nil || reply != "safe reply" {
		t.Fatalf("authorized Send() = %q, %v; want safe reply", reply, err)
	}
	if _, err := manager.Send(context.Background(), "alice", session.ID, "again"); !errors.Is(err, ErrChatTurnLimit) {
		t.Fatalf("second Send() error = %v, want ErrChatTurnLimit", err)
	}

	provider.mu.Lock()
	if len(provider.queries) != 1 || strings.Contains(provider.queries[0], "session-secret") {
		t.Fatalf("provider received unsafe session query: %#v", provider.queries)
	}
	if len(provider.issueIDs) != 1 || provider.issueIDs[0] != "issue-1" {
		t.Fatalf("provider received wrong issue context: %#v", provider.issueIDs)
	}
	provider.mu.Unlock()

	clock = now.Add(3 * time.Second)
	if _, err := manager.Send(context.Background(), "alice", session.ID, "expired"); !errors.Is(err, ErrChatSessionExpired) {
		t.Fatalf("expired Send() error = %v, want ErrChatSessionExpired", err)
	}
}

type readOnlySessionTool struct{}

func (readOnlySessionTool) Name() string { return "pods.get" }

func (readOnlySessionTool) Query(_ context.Context, request ReadOnlyQueryRequest) (ReadOnlyQueryResult, error) {
	return ReadOnlyQueryResult{Resource: request.Resource, Name: request.Name, Data: "read-only"}, nil
}

func TestChatSessionManagerExposesOnlyRegisteredReadOnlyTools(t *testing.T) {
	manager := NewChatSessionManager(&sessionTestProvider{})
	if err := manager.RegisterReadOnlyTool(readOnlySessionTool{}); err != nil {
		t.Fatalf("RegisterReadOnlyTool() error = %v", err)
	}
	session, err := manager.Create(context.Background(), "alice", nil)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	result, err := manager.Query(context.Background(), "alice", session.ID, "pods.get", ReadOnlyQueryRequest{
		Resource: "pods",
		Name:     "worker",
	})
	if err != nil || result.Data != "read-only" {
		t.Fatalf("Query() = %#v, %v; want read-only result", result, err)
	}
	if _, err := manager.Query(context.Background(), "alice", session.ID, "pods.delete", ReadOnlyQueryRequest{}); !errors.Is(err, ErrChatToolNotAllowed) {
		t.Fatalf("unknown tool error = %v, want ErrChatToolNotAllowed", err)
	}
}
