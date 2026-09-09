package investigation

import (
	"errors"
	"github.com/kubebee-com/sre/pkg/triage"
	"net/url"
	"os"
	"regexp"
	"time"
)

// ProviderMetadata is governed configuration, never provider credentials.
// APIKeyEnv is a local secret reference resolved only by an enrolled agent.
type ProviderMetadata struct {
	Provider  string              `json:"provider"`
	Model     string              `json:"model,omitempty"`
	Endpoint  string              `json:"endpoint,omitempty"`
	Mode      triage.ProviderMode `json:"mode,omitempty"`
	WireAPI   triage.WireAPI      `json:"wire_api,omitempty"`
	AWSRegion string              `json:"aws_region,omitempty"`
	APIKeyEnv string              `json:"api_key_env,omitempty"`
}

var ErrProvider = errors.New("authorized local provider unavailable")
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func (m ProviderMetadata) profile(key string) (triage.ProviderProfile, error) {
	if m.APIKeyEnv != "" && !envName.MatchString(m.APIKeyEnv) {
		return triage.ProviderProfile{}, ErrProvider
	}
	// Command/harness providers are intentionally unavailable to remote jobs.
	switch m.Provider {
	case "openai", "claude", "gemini", "azureopenai", "bedrock", "sagemaker", "cohere", "custom", "ollama", "localai", "litellm", "groq", "deepseek", "vertex", "ibm", "oci", "huggingface":
	default:
		return triage.ProviderProfile{}, ErrProvider
	}
	p := triage.ProviderProfile{Name: "agent-diagnostics", Provider: m.Provider, Model: m.Model, Endpoint: m.Endpoint, Mode: m.Mode, WireAPI: m.WireAPI, AWSRegion: m.AWSRegion, APIKey: key, Timeout: 20 * time.Second, MaxTokens: 2048, MaxRequestBytes: 65536, MaxResponseBytes: 16384}
	p, err := p.Normalize()
	if err != nil {
		return p, ErrProvider
	}
	if p.Endpoint != "" {
		u, err := url.Parse(p.Endpoint)
		if err != nil || u.Scheme != "https" || u.User != nil {
			return p, ErrProvider
		}
		p.EndpointAllowlist = []string{p.Endpoint}
	}
	return p, nil
}
func (m ProviderMetadata) Validate() error {
	if m.Provider == "rule" {
		if m.APIKeyEnv != "" || m.Endpoint != "" {
			return ErrProvider
		}
		return nil
	}
	key := ""
	if m.APIKeyEnv != "" {
		key = "metadata-validation-only"
	}
	_, err := m.profile(key)
	return err
}

// ResolveLocalProvider reads credentials on the agent, after metadata validation.
func ResolveLocalProvider(m ProviderMetadata) (triage.StructuredTaskRunner, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if m.Provider == "rule" {
		return nil, nil
	}
	key := ""
	if m.APIKeyEnv != "" {
		key = os.Getenv(m.APIKeyEnv)
		if key == "" {
			return nil, ErrProvider
		}
	}
	p, err := m.profile(key)
	if err != nil {
		return nil, err
	}
	provider, err := triage.NewProviderFromProfile(p)
	if err != nil {
		return nil, ErrProvider
	}
	runner, ok := provider.(triage.StructuredTaskRunner)
	if !ok {
		return nil, ErrProvider
	}
	return runner, nil
}
