package orchestrator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/delivery"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/messaging"
	"github.com/kubebee-com/sre/pkg/ownership"
	"github.com/kubebee-com/sre/pkg/triage"
	"io"
	"net/url"
	"os"
	"time"
)

type ProviderConfig struct {
	ID                string              `json:"id"`
	Provider          string              `json:"provider"`
	Model             string              `json:"model,omitempty"`
	Endpoint          string              `json:"endpoint,omitempty"`
	Mode              triage.ProviderMode `json:"mode,omitempty"`
	WireAPI           triage.WireAPI      `json:"wire_api,omitempty"`
	AWSRegion         string              `json:"aws_region,omitempty"`
	APIKeyEnv         string              `json:"api_key_env,omitempty"`
	CredentialVersion string              `json:"credential_version,omitempty"`
	Scopes            []identity.Scope    `json:"scopes"`
}
type DeploymentConfig struct {
	Messaging     []messaging.Config      `json:"messaging,omitempty"`
	RetentionDays int                     `json:"retention_days,omitempty"`
	Notifications []delivery.Route        `json:"notifications,omitempty"`
	Applications  []ownership.Application `json:"applications"`
	Bindings      []authorization.Binding `json:"bindings"`
	Providers     []ProviderConfig        `json:"providers"`
}

var ErrDeploymentConfig = errors.New("invalid orchestrator deployment configuration")

func ReadDeploymentConfig(reader io.Reader) (DeploymentConfig, error) {
	var config DeploymentConfig
	data, err := io.ReadAll(io.LimitReader(reader, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return config, ErrDeploymentConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return config, ErrDeploymentConfig
	}
	if decoder.Decode(new(any)) != io.EOF {
		return config, ErrDeploymentConfig
	}
	if config.RetentionDays == 0 {
		config.RetentionDays = 90
	}
	if config.RetentionDays < 7 || config.RetentionDays > 3650 {
		return config, ErrDeploymentConfig
	}
	registry, err := ownership.NewRegistry(config.Applications)
	if err != nil || len(config.Applications) == 0 {
		return config, ErrDeploymentConfig
	}
	for _, binding := range config.Bindings {
		app, ok := registry.Application(binding.Scope)
		if !ok || (binding.Role == authorization.Owner && binding.Group != app.OwnerGroup) {
			return config, ErrDeploymentConfig
		}
	}
	for _, route := range config.Notifications {
		if _, ok := registry.Application(route.Scope); !ok {
			return config, ErrDeploymentConfig
		}
	}
	ids := map[string]bool{}
	for _, provider := range config.Providers {
		switch provider.Provider {
		case "rule", "openai", "claude", "gemini", "azureopenai", "bedrock", "sagemaker", "cohere", "custom", "ollama", "localai", "litellm", "groq", "deepseek", "vertex", "ibm", "oci", "huggingface":
		default:
			return config, ErrDeploymentConfig
		}
		if !identity.ValidID(provider.ID) || ids[provider.ID] || len(provider.Scopes) == 0 {
			return config, ErrDeploymentConfig
		}
		ids[provider.ID] = true
		for _, scope := range provider.Scopes {
			if _, ok := registry.Application(scope); !ok {
				return config, ErrDeploymentConfig
			}
		}
		if provider.APIKeyEnv != "" && (!identity.ValidID(provider.APIKeyEnv) || !identity.ValidID(provider.CredentialVersion)) {
			return config, ErrDeploymentConfig
		}
		if provider.Endpoint != "" {
			endpoint, err := url.Parse(provider.Endpoint)
			if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
				return config, ErrDeploymentConfig
			}
		}
	}
	policy, err := config.Policy()
	if err != nil {
		return config, ErrDeploymentConfig
	}
	for _, channel := range config.Messaging {
		if _, ok := registry.Application(channel.Scope); !ok {
			return config, ErrDeploymentConfig
		}
		for _, user := range channel.Users {
			p := identity.Principal{ID: user.PrincipalID, Issuer: "messaging-config", Groups: user.Groups, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
			if policy.Authorize(p, channel.Scope, authorization.Read) != nil {
				return config, ErrDeploymentConfig
			}
		}
	}
	return config, nil
}
func (c DeploymentConfig) Policy() (*authorization.Policy, error) {
	bindings := append([]authorization.Binding(nil), c.Bindings...)
	for _, app := range c.Applications {
		bindings = append(bindings, authorization.Binding{Scope: app.Scope, Group: app.OwnerGroup, Role: authorization.Owner})
		for _, group := range app.ApproverGroups {
			bindings = append(bindings, authorization.Binding{Scope: app.Scope, Group: group, Role: authorization.Approver})
		}
	}
	return authorization.NewPolicy(bindings)
}
func (c DeploymentConfig) BuildProfiles() ([]investigation.Profile, error) {
	profiles := []investigation.Profile{}
	for _, config := range c.Providers {
		encoded, _ := json.Marshal(config)
		digest := sha256.Sum256(encoded)
		profile := investigation.Profile{ID: config.ID, Version: hex.EncodeToString(digest[:]), Scopes: append([]identity.Scope(nil), config.Scopes...)}
		if config.Provider != "rule" {
			key := ""
			if config.APIKeyEnv != "" {
				key = os.Getenv(config.APIKeyEnv)
				if key == "" {
					return nil, ErrDeploymentConfig
				}
			}
			providerProfile := triage.ProviderProfile{Name: config.ID, Provider: config.Provider, Model: config.Model, Endpoint: config.Endpoint, Mode: config.Mode, WireAPI: config.WireAPI, AWSRegion: config.AWSRegion, APIKey: key, Timeout: 20 * time.Second, MaxTokens: 2048, MaxRequestBytes: 65536, MaxResponseBytes: 16384}
			normalized, err := providerProfile.Normalize()
			if err != nil {
				return nil, ErrDeploymentConfig
			}
			if normalized.Endpoint != "" {
				endpoint, err := url.Parse(normalized.Endpoint)
				if err != nil || endpoint.Scheme != "https" {
					return nil, ErrDeploymentConfig
				}
				normalized.EndpointAllowlist = []string{normalized.Endpoint}
			}
			provider, err := triage.NewProviderFromProfile(normalized)
			if err != nil {
				return nil, ErrDeploymentConfig
			}
			runner, ok := provider.(triage.StructuredTaskRunner)
			if !ok {
				return nil, ErrDeploymentConfig
			}
			profile.Runner = runner
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

// BuildRemoteProfiles builds immutable governance metadata without reading provider
// secrets or constructing an inference adapter in the orchestrator.
func (c DeploymentConfig) BuildRemoteProfiles() ([]investigation.Profile, error) {
	profiles := []investigation.Profile{}
	for _, config := range c.Providers {
		encoded, _ := json.Marshal(config)
		digest := sha256.Sum256(encoded)
		metadata := investigation.ProviderMetadata{Provider: config.Provider, Model: config.Model, Endpoint: config.Endpoint, Mode: config.Mode, WireAPI: config.WireAPI, AWSRegion: config.AWSRegion, APIKeyEnv: config.APIKeyEnv}
		if metadata.Validate() != nil {
			return nil, ErrDeploymentConfig
		}
		profiles = append(profiles, investigation.Profile{ID: config.ID, Version: hex.EncodeToString(digest[:]), Scopes: append([]identity.Scope(nil), config.Scopes...), Metadata: metadata})
	}
	return profiles, nil
}
