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
)

func TestCloudProviderUsesProviderWireShapeAndRedacts(t *testing.T) {
	const secret = "cloud-provider-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-model:generateContent" {
			t.Errorf("request path = %q, want Gemini generateContent path", r.URL.Path)
		}
		if got := r.Header.Get("x-goog-api-key"); got != secret {
			t.Errorf("x-goog-api-key = %q, want configured key", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if strings.Contains(string(body), secret) {
			t.Errorf("request body leaked API key: %s", body)
		}
		_, _ = io.WriteString(w, `{"candidates":[{"content":{"parts":[{"text":"reply password=cloud-provider-secret"}]}}]}`)
	}))
	defer server.Close()

	provider, err := NewCloudProvider(ProviderProfile{
		Provider:          "gemini",
		Endpoint:          server.URL + "/v1beta",
		EndpointAllowlist: []string{server.URL},
		Model:             "gemini-model",
		APIKey:            secret,
		SecretValues:      []string{secret},
	})
	if err != nil {
		t.Fatalf("NewCloudProvider() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "inspect "+secret, nil)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if strings.Contains(reply, secret) {
		t.Fatalf("Explain() leaked configured secret: %q", reply)
	}
}

func TestCloudProviderSupportsCohereResponseAndTypedErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/chat" {
			t.Errorf("request path = %q, want /v2/chat", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"message":{"content":[{"text":"cohere reply"}]}}`)
	}))
	defer server.Close()
	provider, err := NewProviderFromProfile(ProviderProfile{
		Provider:          "cohere",
		Endpoint:          server.URL + "/v2",
		EndpointAllowlist: []string{server.URL},
		Model:             "command-test",
		APIKey:            "key",
	})
	if err != nil {
		t.Fatalf("NewProviderFromProfile() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "hello", nil)
	if err != nil || reply != "cohere reply" {
		t.Fatalf("Explain() = %q, %v; want cohere reply", reply, err)
	}

	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":"token=must-not-leak"}`)
	}))
	defer errorServer.Close()
	failed, err := NewCloudProvider(ProviderProfile{
		Provider:          "oci",
		Endpoint:          errorServer.URL,
		EndpointAllowlist: []string{errorServer.URL},
		Model:             "command",
	})
	if err != nil {
		t.Fatalf("OCI constructor error = %v", err)
	}
	_, err = failed.Explain(context.Background(), "hello", nil)
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorHTTP || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("cloud HTTP error = %v, want typed safe HTTP error", err)
	}
}

func TestAzureExplainUsesExistingDiagnosisSystemPrompt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		var messages []compatibleMessage
		if err := json.Unmarshal(request["messages"], &messages); err != nil {
			t.Errorf("decode messages: %v", err)
			return
		}
		if len(messages) == 0 || messages[0].Content != SystemPrompt {
			t.Errorf("azure Explain system prompt = %#v, want existing SystemPrompt", messages)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"azure explain reply"}}]}`)
	}))
	defer server.Close()

	provider, err := NewCloudProvider(ProviderProfile{
		Provider:      "azureopenai",
		Endpoint:      server.URL,
		Model:         "azure-model",
		APIKey:        "key",
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewCloudProvider() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "hello", nil)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if reply != "azure explain reply" {
		t.Fatalf("Explain() reply = %q, want azure explain reply", reply)
	}
}

func TestCloudProviderRejectsUnallowlistedEndpoint(t *testing.T) {
	_, err := NewCloudProvider(ProviderProfile{
		Provider: "vertex",
		Endpoint: "https://vertex.example.test/v1",
		Model:    "model",
	})
	if !errors.Is(err, ErrEndpointNotAllowed) {
		t.Fatalf("NewCloudProvider() error = %v, want ErrEndpointNotAllowed", err)
	}
}

func TestNewCloudProviderEnforcesProviderWireMatrix(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wireAPI  WireAPI
		wantErr  error
	}{
		{name: "azure chat", provider: "azureopenai", wireAPI: WireAPIChat},
		{name: "bedrock chat", provider: "bedrock", wireAPI: WireAPIChat},
		{name: "cohere chat", provider: "cohere", wireAPI: WireAPIChat},
		{name: "gemini chat", provider: "gemini", wireAPI: WireAPIChat},
		{name: "huggingface chat", provider: "huggingface", wireAPI: WireAPIChat},
		{name: "ibm chat", provider: "ibm", wireAPI: WireAPIChat},
		{name: "oci chat", provider: "oci", wireAPI: WireAPIChat},
		{name: "sagemaker chat", provider: "sagemaker", wireAPI: WireAPIChat},
		{name: "vertex chat", provider: "vertex", wireAPI: WireAPIChat},
		{name: "azure responses", provider: "azureopenai", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "bedrock responses", provider: "bedrock", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "cohere responses", provider: "cohere", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "gemini responses", provider: "gemini", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "huggingface responses", provider: "huggingface", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "ibm responses", provider: "ibm", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "oci responses", provider: "oci", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "sagemaker responses", provider: "sagemaker", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "vertex responses", provider: "vertex", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "azure omitted wire defaults to chat", provider: "azureopenai"},
		{name: "non-cloud provider", provider: "openai", wireAPI: WireAPIChat, wantErr: ErrProviderValidation},
		{name: "unknown provider", provider: "unknown-cloud", wireAPI: WireAPIChat, wantErr: ErrUnknownProvider},
		{name: "unknown wire", provider: "azureopenai", wireAPI: WireAPI("legacy"), wantErr: ErrProviderValidation},
	}

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := requests.Load()
			provider, err := NewCloudProvider(ProviderProfile{
				Provider:      tc.provider,
				WireAPI:       tc.wireAPI,
				Endpoint:      server.URL,
				Model:         "model",
				AllowLoopback: true,
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("NewCloudProvider() error = %v, want %v", err, tc.wantErr)
				}
				var providerErr *ProviderError
				if !errors.As(err, &providerErr) {
					t.Fatalf("NewCloudProvider() error = %#v, want ProviderError", err)
				}
				wantKind := ProviderErrorValidation
				if errors.Is(tc.wantErr, ErrUnknownProvider) {
					wantKind = ProviderErrorUnknown
				}
				if providerErr.Kind != wantKind {
					t.Fatalf("NewCloudProvider() error kind = %s, want %s", providerErr.Kind, wantKind)
				}
				if provider != nil {
					t.Fatalf("NewCloudProvider() provider = %T, want nil", provider)
				}
				if got := requests.Load(); got != before {
					t.Fatalf("rejected constructor made %d HTTP requests, want 0", got-before)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewCloudProvider() error = %v", err)
			}
			if provider == nil || provider.profile.WireAPI != WireAPIChat {
				t.Fatalf("NewCloudProvider() provider = %#v, want chat CloudProvider", provider)
			}
		})
	}
}

func TestNewProviderFromProfileWithAWSEnforcesCloudProviderWireMatrix(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		mode     ProviderMode
		wireAPI  WireAPI
		wantType string
		wantErr  error
	}{
		{name: "azure chat", provider: "azureopenai", wireAPI: WireAPIChat, wantType: "cloud"},
		{name: "cohere chat", provider: "cohere", wireAPI: WireAPIChat, wantType: "cloud"},
		{name: "gemini chat", provider: "gemini", wireAPI: WireAPIChat, wantType: "cloud"},
		{name: "huggingface chat", provider: "huggingface", wireAPI: WireAPIChat, wantType: "cloud"},
		{name: "ibm chat", provider: "ibm", wireAPI: WireAPIChat, wantType: "cloud"},
		{name: "oci chat", provider: "oci", wireAPI: WireAPIChat, wantType: "cloud"},
		{name: "vertex chat", provider: "vertex", wireAPI: WireAPIChat, wantType: "cloud"},
		{name: "bedrock HTTP chat", provider: "bedrock", wireAPI: WireAPIChat, wantType: "cloud"},
		{name: "sagemaker HTTP chat", provider: "sagemaker", wireAPI: WireAPIChat, wantType: "cloud"},
		{name: "bedrock native chat", provider: "bedrock", mode: ProviderModeAWS, wireAPI: WireAPIChat, wantType: "bedrock"},
		{name: "sagemaker native chat", provider: "sagemaker", mode: ProviderModeAWS, wireAPI: WireAPIChat, wantType: "sagemaker"},
		{name: "azure responses", provider: "azureopenai", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "cohere responses", provider: "cohere", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "gemini responses", provider: "gemini", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "huggingface responses", provider: "huggingface", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "ibm responses", provider: "ibm", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "oci responses", provider: "oci", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "vertex responses", provider: "vertex", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "bedrock HTTP responses", provider: "bedrock", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "sagemaker HTTP responses", provider: "sagemaker", wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "bedrock native responses", provider: "bedrock", mode: ProviderModeAWS, wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "sagemaker native responses", provider: "sagemaker", mode: ProviderModeAWS, wireAPI: WireAPIResponses, wantErr: ErrProviderValidation},
		{name: "azure omitted wire defaults to chat", provider: "azureopenai", wantType: "cloud"},
		{name: "bedrock native omitted wire defaults to chat", provider: "bedrock", mode: ProviderModeAWS, wantType: "bedrock"},
		{name: "unknown wire", provider: "azureopenai", wireAPI: WireAPI("legacy"), wantErr: ErrProviderValidation},
	}

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	bedrockClient := &fakeBedrockRuntimeClient{}
	sageMakerClient := &fakeSageMakerRuntimeClient{}
	options := AWSProviderOptions{BedrockClient: bedrockClient, SageMakerClient: sageMakerClient}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile := ProviderProfile{
				Provider:      tc.provider,
				Mode:          tc.mode,
				WireAPI:       tc.wireAPI,
				Endpoint:      server.URL,
				Model:         "model",
				AllowLoopback: true,
			}
			if tc.mode == ProviderModeAWS {
				profile.Endpoint = ""
				if tc.provider == "sagemaker" {
					profile.Endpoint = "native-endpoint"
				}
			}
			before := requests.Load()
			provider, err := NewProviderFromProfileWithAWS(profile, options)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("NewProviderFromProfileWithAWS() error = %v, want %v", err, tc.wantErr)
				}
				var providerErr *ProviderError
				if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorValidation {
					t.Fatalf("NewProviderFromProfileWithAWS() error = %#v, want validation ProviderError", err)
				}
				if provider != nil {
					t.Fatalf("NewProviderFromProfileWithAWS() provider = %T, want nil", provider)
				}
				if got := requests.Load(); got != before {
					t.Fatalf("rejected profile made %d HTTP requests, want 0", got-before)
				}
				if bedrockClient.input != nil || sageMakerClient.input != nil {
					t.Fatalf("rejected profile invoked native client: bedrock=%#v sagemaker=%#v", bedrockClient.input, sageMakerClient.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewProviderFromProfileWithAWS() error = %v", err)
			}
			switch tc.wantType {
			case "cloud":
				if _, ok := provider.(*CloudProvider); !ok {
					t.Fatalf("NewProviderFromProfileWithAWS() provider = %T, want *CloudProvider", provider)
				}
			case "bedrock":
				if _, ok := provider.(*BedrockProvider); !ok {
					t.Fatalf("NewProviderFromProfileWithAWS() provider = %T, want *BedrockProvider", provider)
				}
			case "sagemaker":
				if _, ok := provider.(*SageMakerProvider); !ok {
					t.Fatalf("NewProviderFromProfileWithAWS() provider = %T, want *SageMakerProvider", provider)
				}
			}
		})
	}
}

func TestCloudProviderRunStructuredRejectsInvalidProviderWireMatrix(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wireAPI  WireAPI
	}{
		{name: "azure responses", provider: "azureopenai", wireAPI: WireAPIResponses},
		{name: "azure missing wire", provider: "azureopenai"},
		{name: "azure unknown wire", provider: "azureopenai", wireAPI: WireAPI("legacy")},
		{name: "unsupported structured provider", provider: "cohere", wireAPI: WireAPIChat},
		{name: "unknown provider", provider: "unknown-cloud", wireAPI: WireAPIChat},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			defer server.Close()

			provider := &CloudProvider{
				profile: ProviderProfile{
					Provider: tc.provider,
					WireAPI:  tc.wireAPI,
					Model:    "model",
				},
				client:   server.Client(),
				endpoint: server.URL,
			}

			_, err := provider.RunStructured(context.Background(), StructuredTask{
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
