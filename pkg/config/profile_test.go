package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStoreMigratesLegacyConfigurationAndDropsSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	legacy := `llm_provider: ollama
llm_model: llama3
llm_base_url: http://127.0.0.1:11434/v1
llm_api_key: legacy-api-key
api_token: legacy-api-token
namespace: payments
analyzers: PodAnalyzer, ServiceAnalyzer
`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.SchemaVersion != UserConfigSchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", got.SchemaVersion, UserConfigSchemaVersion)
	}
	if got.DefaultProfile != "default" {
		t.Fatalf("DefaultProfile = %q, want default", got.DefaultProfile)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].Provider != "ollama" {
		t.Fatalf("Profiles = %#v, want migrated ollama profile", got.Profiles)
	}
	if got.Settings.Namespace != "payments" || len(got.Settings.Analyzers) != 2 {
		t.Fatalf("Settings = %#v, want migrated scan settings", got.Settings)
	}

	rewritten, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	text := string(rewritten)
	for _, secret := range []string{"legacy-api-key", "legacy-api-token", "llm_api_key", "api_token"} {
		if strings.Contains(text, secret) {
			t.Fatalf("migrated config contains secret material %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, "schema_version: "+UserConfigSchemaVersion) {
		t.Fatalf("migrated config missing schema version: %s", text)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat migrated config: %v", err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0600 {
		t.Fatalf("migrated config mode = %o, want 600", gotMode)
	}
}

func TestResolveConfigUsesFlagEnvironmentAndFilePrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	fileConfig := NewUserConfig()
	fileConfig.DefaultProfile = "local"
	fileConfig.Profiles = []ProviderProfile{{
		Name:     "local",
		Provider: "file-provider",
		Model:    "file-model",
		BaseURL:  "http://127.0.0.1:8080/v1",
	}}
	fileConfig.Settings.Namespace = "file-namespace"
	fileConfig.Settings.LabelSelector = "team=file"
	fileConfig.Settings.ScanJitter = "3s"
	fileConfig.Settings.LeaderElection = true
	fileConfig.Settings.LeaderElectionNamespace = "sre"
	fileConfig.Settings.LeaderElectionID = "lease-file"
	fileConfig.Settings.LeaderElectionIdentity = "worker-a"
	if err := store.Save(fileConfig); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	resolved, _, err := ResolveConfig(ResolveOptions{
		Path: path,
		Environment: map[string]string{
			"LLM_PROVIDER":           "env-provider",
			"LLM_MODEL":              "env-model",
			"NAMESPACE":              "env-namespace",
			"SRE_LABEL_SELECTOR":     "team=env",
			"LLM_ENDPOINT_ALLOWLIST": "https://llm.example.test/backend-api/codex",
			"LLM_API_KEY":            "env-api-key",
		},
		Flags: map[string]string{
			"llm-provider": "flag-provider",
			"namespace":    "flag-namespace",
		},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if resolved.LLMProvider != "flag-provider" || resolved.Namespace != "flag-namespace" {
		t.Fatalf("flag precedence result = provider %q namespace %q", resolved.LLMProvider, resolved.Namespace)
	}
	if resolved.LLMModel != "env-model" || resolved.LabelSelector != "team=env" {
		t.Fatalf("environment precedence result = model %q selector %q", resolved.LLMModel, resolved.LabelSelector)
	}
	if resolved.LLMBaseURL != "http://127.0.0.1:8080/v1" {
		t.Fatalf("file profile base URL = %q, want file value", resolved.LLMBaseURL)
	}
	if resolved.LLMAPIKey != "env-api-key" {
		t.Fatalf("environment API key = %q, want env-api-key", resolved.LLMAPIKey)
	}
	if !reflect.DeepEqual(resolved.LLMEndpointAllowlist, []string{"https://llm.example.test/backend-api/codex"}) {
		t.Fatalf("environment endpoint allowlist = %#v", resolved.LLMEndpointAllowlist)
	}
	if resolved.ScanJitter != 3*time.Second || !resolved.LeaderElection || resolved.LeaderElectionNamespace != "sre" || resolved.LeaderElectionID != "lease-file" || resolved.LeaderElectionIdentity != "worker-a" {
		t.Fatalf("resolved scheduler settings = %#v", resolved)
	}
}

func TestResolveConfigReadsEventTriggerSettingsWithFlagPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("schema_version: config/v1\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	resolved, _, err := ResolveConfig(ResolveOptions{
		Path: path,
		Environment: map[string]string{
			"SRE_EVENT_DRIVEN_SCANNING": "false",
			"SRE_EVENT_QUEUE_CAPACITY":  "32",
			"SRE_EVENT_DEBOUNCE":        "750ms",
		},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() environment error = %v", err)
	}
	if resolved.EventDrivenScanning || resolved.EventQueueCapacity != 32 || resolved.EventDebounce != 750*time.Millisecond {
		t.Fatalf("environment event settings = enabled %t capacity %d debounce %s", resolved.EventDrivenScanning, resolved.EventQueueCapacity, resolved.EventDebounce)
	}

	resolved, _, err = ResolveConfig(ResolveOptions{
		Path: path,
		Environment: map[string]string{
			"SRE_EVENT_DRIVEN_SCANNING": "false",
			"SRE_EVENT_QUEUE_CAPACITY":  "32",
			"SRE_EVENT_DEBOUNCE":        "750ms",
		},
		Flags: map[string]string{
			"event-driven-scanning": "true",
			"event-queue-capacity":  "64",
			"event-debounce":        "2s",
		},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() flag error = %v", err)
	}
	if !resolved.EventDrivenScanning || resolved.EventQueueCapacity != 64 || resolved.EventDebounce != 2*time.Second {
		t.Fatalf("flag event settings = enabled %t capacity %d debounce %s", resolved.EventDrivenScanning, resolved.EventQueueCapacity, resolved.EventDebounce)
	}

	resolved, _, err = ResolveConfig(ResolveOptions{Path: path, Environment: map[string]string{}})
	if err != nil {
		t.Fatalf("ResolveConfig() defaults error = %v", err)
	}
	if !resolved.EventDrivenScanning || resolved.EventQueueCapacity <= 0 || resolved.EventDebounce <= 0 {
		t.Fatalf("default event settings = enabled %t capacity %d debounce %s", resolved.EventDrivenScanning, resolved.EventQueueCapacity, resolved.EventDebounce)
	}

	resolved, _, err = ResolveConfig(ResolveOptions{
		Path:        path,
		Environment: map[string]string{"SRE_EVENT_DEBOUNCE": "0"},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() zero-debounce error = %v", err)
	}
	if resolved.EventDebounce != 0 {
		t.Fatalf("explicit zero debounce = %s, want immediate event handling", resolved.EventDebounce)
	}
}

func TestResolveConfigUsesProviderModePrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	userConfig := NewUserConfig()
	userConfig.DefaultProfile = "aws"
	userConfig.Profiles = []ProviderProfile{{
		Name:     "aws",
		Provider: "bedrock",
		Mode:     "aws",
	}}
	userConfig.Settings.LLMMode = "local"
	if err := store.Save(userConfig); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	resolved, _, err := ResolveConfig(ResolveOptions{
		Path:        path,
		Environment: map[string]string{"LLM_MODE": "remote"},
		Flags:       map[string]string{"llm-mode": "aws"},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if resolved.LLMMode != "aws" {
		t.Fatalf("flag LLMMode = %q, want aws", resolved.LLMMode)
	}

	resolved, _, err = ResolveConfig(ResolveOptions{
		Path:        path,
		Environment: map[string]string{"LLM_MODE": "remote"},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() environment error = %v", err)
	}
	if resolved.LLMMode != "remote" {
		t.Fatalf("environment LLMMode = %q, want remote", resolved.LLMMode)
	}

	resolved, _, err = ResolveConfig(ResolveOptions{Path: path, Environment: map[string]string{}})
	if err != nil {
		t.Fatalf("ResolveConfig() profile error = %v", err)
	}
	if resolved.LLMMode != "aws" {
		t.Fatalf("profile LLMMode = %q, want aws", resolved.LLMMode)
	}
}

func TestResolveConfigUsesTransientProviderHeadersAndProfileTransportSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	userConfig := NewUserConfig()
	userConfig.DefaultProfile = "remote"
	userConfig.Profiles = []ProviderProfile{{
		Name:         "remote",
		Provider:     "custom",
		Model:        "model",
		BaseURL:      "https://provider.example.test/v1",
		Organization: "profile-org",
		ProxyURL:     "https://profile-proxy.example.test",
	}}
	if err := store.Save(userConfig); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	resolved, persisted, err := ResolveConfig(ResolveOptions{
		Path:        path,
		Environment: map[string]string{"LLM_CUSTOM_HEADERS": "X-Env:env", "LLM_ORGANIZATION": "env-org"},
		Flags:       map[string]string{"llm-headers": "X-Flag:flag", "llm-organization": "flag-org"},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if !reflect.DeepEqual(resolved.LLMHeaders, []string{"X-Flag:flag"}) {
		t.Fatalf("flag LLMHeaders = %#v", resolved.LLMHeaders)
	}
	if resolved.LLMOrganization != "flag-org" || resolved.LLMProxyURL != "https://profile-proxy.example.test" {
		t.Fatalf("resolved provider transport settings = organization %q proxy %q", resolved.LLMOrganization, resolved.LLMProxyURL)
	}
	if len(persisted.Settings.AllowedOrigins) != 0 {
		t.Fatalf("unexpected unrelated persisted settings = %#v", persisted.Settings)
	}

	resolved, _, err = ResolveConfig(ResolveOptions{
		Path:        path,
		Environment: map[string]string{"LLM_CUSTOM_HEADERS": "X-Env:env", "LLM_ORGANIZATION": "env-org"},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() environment error = %v", err)
	}
	if !reflect.DeepEqual(resolved.LLMHeaders, []string{"X-Env:env"}) || resolved.LLMOrganization != "env-org" {
		t.Fatalf("environment provider settings = headers %#v organization %q", resolved.LLMHeaders, resolved.LLMOrganization)
	}

	resolved, _, err = ResolveConfig(ResolveOptions{Path: path, Environment: map[string]string{}})
	if err != nil {
		t.Fatalf("ResolveConfig() profile error = %v", err)
	}
	if resolved.LLMOrganization != "profile-org" || resolved.LLMProxyURL != "https://profile-proxy.example.test" || len(resolved.LLMHeaders) != 0 {
		t.Fatalf("profile provider settings = headers %#v organization %q proxy %q", resolved.LLMHeaders, resolved.LLMOrganization, resolved.LLMProxyURL)
	}
}

func TestResolveConfigAWSEKSUsesFlagEnvironmentAndProfilePrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	userConfig := NewUserConfig()
	userConfig.DefaultProfile = "production"
	userConfig.Profiles = []ProviderProfile{{
		Name:     "production",
		Provider: "openai",
		Model:    "gpt-4o",
	}}
	userConfig.Settings.EnableAWSEKS = false
	userConfig.Settings.AWSRegion = "profile-region"
	userConfig.Settings.EKSClusterName = "profile-cluster"
	if err := store.Save(userConfig); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	environment := map[string]string{
		"SRE_ENABLE_AWS_EKS":   "true",
		"AWS_REGION":           "env-region",
		"SRE_EKS_CLUSTER_NAME": "env-cluster",
	}
	flags := map[string]string{
		"enable-aws-eks":   "false",
		"aws-region":       "flag-region",
		"eks-cluster-name": "flag-cluster",
	}

	resolved, _, err := ResolveConfig(ResolveOptions{Path: path, Environment: environment, Flags: flags})
	if err != nil {
		t.Fatalf("ResolveConfig() with flags error = %v", err)
	}
	if resolved.EnableAWSEKS || resolved.AWSRegion != "flag-region" || resolved.EKSClusterName != "flag-cluster" {
		t.Fatalf("flag AWS/EKS settings = enabled %t region %q cluster %q", resolved.EnableAWSEKS, resolved.AWSRegion, resolved.EKSClusterName)
	}

	resolved, _, err = ResolveConfig(ResolveOptions{Path: path, Environment: environment})
	if err != nil {
		t.Fatalf("ResolveConfig() with environment error = %v", err)
	}
	if !resolved.EnableAWSEKS || resolved.AWSRegion != "env-region" || resolved.EKSClusterName != "env-cluster" {
		t.Fatalf("environment AWS/EKS settings = enabled %t region %q cluster %q", resolved.EnableAWSEKS, resolved.AWSRegion, resolved.EKSClusterName)
	}

	resolved, _, err = ResolveConfig(ResolveOptions{Path: path, Environment: map[string]string{}})
	if err != nil {
		t.Fatalf("ResolveConfig() with profile error = %v", err)
	}
	if resolved.EnableAWSEKS || resolved.AWSRegion != "profile-region" || resolved.EKSClusterName != "profile-cluster" {
		t.Fatalf("profile AWS/EKS settings = enabled %t region %q cluster %q", resolved.EnableAWSEKS, resolved.AWSRegion, resolved.EKSClusterName)
	}
}

func TestResolveConfigAWSEKSProfileSettingsRemainSecretFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	profileSecret := "profile-api-key-secret"
	userConfig := NewUserConfig()
	userConfig.DefaultProfile = "production"
	userConfig.Profiles = []ProviderProfile{{
		Name:     "production",
		Provider: "openai",
		APIKey:   profileSecret,
	}}
	userConfig.Settings.EnableAWSEKS = true
	userConfig.Settings.AWSRegion = "us-west-2"
	userConfig.Settings.EKSClusterName = "sre-prod"
	if err := store.Save(userConfig); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	llmSecret := "runtime-llm-secret"
	apiSecret := "runtime-api-secret"
	resolved, persisted, err := ResolveConfig(ResolveOptions{
		Path: path,
		Environment: map[string]string{
			"LLM_API_KEY":   llmSecret,
			"SRE_API_TOKEN": apiSecret,
		},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if resolved.LLMAPIKey != llmSecret || resolved.APIToken != apiSecret {
		t.Fatalf("runtime credentials = LLMAPIKey %q APIToken %q", resolved.LLMAPIKey, resolved.APIToken)
	}
	if !resolved.EnableAWSEKS || resolved.AWSRegion != "us-west-2" || resolved.EKSClusterName != "sre-prod" {
		t.Fatalf("runtime AWS/EKS settings = enabled %t region %q cluster %q", resolved.EnableAWSEKS, resolved.AWSRegion, resolved.EKSClusterName)
	}
	if len(persisted.Profiles) != 1 || persisted.Profiles[0].APIKey != "" {
		t.Fatalf("persisted profile retained API key: %#v", persisted.Profiles)
	}

	encoded, err := json.Marshal(persisted)
	if err != nil {
		t.Fatalf("marshal persisted config: %v", err)
	}
	for _, secret := range []string{profileSecret, llmSecret, apiSecret} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("persisted runtime config contains secret %q: %s", secret, encoded)
		}
	}
	if !strings.Contains(string(encoded), `"enable_aws_eks":true`) || !strings.Contains(string(encoded), `"aws_region":"us-west-2"`) || !strings.Contains(string(encoded), `"eks_cluster_name":"sre-prod"`) {
		t.Fatalf("persisted runtime config omitted AWS/EKS settings: %s", encoded)
	}
}

func TestResolveConfigPlaybookSettingsUsePrecedenceAndKeepDatabaseRuntimeOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	enabled := false
	fileConfidence := 0.55
	fileSourceBytes := 1024
	fileStepCount := 2
	fileTotalTextBytes := 4096
	userConfig := NewUserConfig()
	userConfig.Settings.PlaybookEnabled = &enabled
	userConfig.Settings.PlaybookLearningMode = "OBSERVE_ONLY"
	userConfig.Settings.PlaybookMinConfidence = &fileConfidence
	userConfig.Settings.PlaybookAllowedActions = []string{"Manual"}
	userConfig.Settings.PlaybookAllowedNamespaces = []string{"file"}
	userConfig.Settings.PlaybookAllowedKinds = []string{"Pod"}
	userConfig.Settings.PlaybookMaxSourceBytes = &fileSourceBytes
	userConfig.Settings.PlaybookMaxStepCount = &fileStepCount
	userConfig.Settings.PlaybookMaxTotalTextBytes = &fileTotalTextBytes
	if err := store.Save(userConfig); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	secretURL := "postgres://user:runtime-secret@db.example.test:5432/sre"
	resolved, persisted, err := ResolveConfig(ResolveOptions{
		Path: path,
		Environment: map[string]string{
			"SRE_DATABASE_URL":                  secretURL,
			"SRE_PLAYBOOK_ENABLED":              "true",
			"SRE_PLAYBOOK_LEARNING_MODE":        "AUTO_DRAFT",
			"SRE_PLAYBOOK_MIN_CONFIDENCE":       "0.7",
			"SRE_PLAYBOOK_ALLOWED_ACTIONS":      "Manual,GitOpsPR",
			"SRE_PLAYBOOK_ALLOWED_NAMESPACES":   "env",
			"SRE_PLAYBOOK_ALLOWED_KINDS":        "Deployment",
			"SRE_PLAYBOOK_MAX_SOURCE_BYTES":     "2048",
			"SRE_PLAYBOOK_MAX_STEP_COUNT":       "4",
			"SRE_PLAYBOOK_MAX_TOTAL_TEXT_BYTES": "8192",
		},
		Flags: map[string]string{
			"playbook-learning-mode":        "DISABLED",
			"playbook-min-confidence":       "0.9",
			"playbook-allowed-actions":      "Manual",
			"playbook-max-step-count":       "1",
			"playbook-max-total-text-bytes": "16384",
		},
	})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if resolved.DatabaseURL != secretURL || !resolved.PlaybookEnabled {
		t.Fatalf("resolved database/playbook enablement = url %q enabled %t", resolved.DatabaseURL, resolved.PlaybookEnabled)
	}
	if resolved.PlaybookLearningMode != "DISABLED" || resolved.PlaybookMinConfidence != 0.9 || resolved.PlaybookMaxSourceBytes != 2048 || resolved.PlaybookMaxStepCount != 1 || resolved.PlaybookMaxTotalTextBytes != 16384 {
		t.Fatalf("resolved playbook scalars = mode %q confidence %v source bytes %d step count %d total text bytes %d", resolved.PlaybookLearningMode, resolved.PlaybookMinConfidence, resolved.PlaybookMaxSourceBytes, resolved.PlaybookMaxStepCount, resolved.PlaybookMaxTotalTextBytes)
	}
	if !reflect.DeepEqual(resolved.PlaybookAllowedActions, []string{"Manual"}) {
		t.Fatalf("resolved PlaybookAllowedActions = %#v", resolved.PlaybookAllowedActions)
	}
	if !reflect.DeepEqual(resolved.PlaybookAllowedNamespaces, []string{"env"}) || !reflect.DeepEqual(resolved.PlaybookAllowedKinds, []string{"Deployment"}) {
		t.Fatalf("resolved playbook scope = namespaces %#v kinds %#v", resolved.PlaybookAllowedNamespaces, resolved.PlaybookAllowedKinds)
	}

	encoded, err := json.Marshal(persisted)
	if err != nil {
		t.Fatalf("marshal persisted config: %v", err)
	}
	if strings.Contains(string(encoded), "runtime-secret") || strings.Contains(string(encoded), "database_url") {
		t.Fatalf("persisted runtime config contains database material: %s", encoded)
	}
}

func TestResolveConfigRejectsExplicitNonpositivePlaybookLimits(t *testing.T) {
	tests := []struct {
		name           string
		flagKey        string
		environmentKey string
	}{
		{name: "source bytes", flagKey: "playbook-max-source-bytes", environmentKey: "SRE_PLAYBOOK_MAX_SOURCE_BYTES"},
		{name: "step count", flagKey: "playbook-max-step-count", environmentKey: "SRE_PLAYBOOK_MAX_STEP_COUNT"},
		{name: "total text bytes", flagKey: "playbook-max-total-text-bytes", environmentKey: "SRE_PLAYBOOK_MAX_TOTAL_TEXT_BYTES"},
	}

	for _, test := range tests {
		t.Run(test.name+" from flag", func(t *testing.T) {
			_, _, err := ResolveConfig(ResolveOptions{
				Path:        filepath.Join(t.TempDir(), "config.yaml"),
				Environment: map[string]string{},
				Flags:       map[string]string{test.flagKey: "-1"},
			})
			if err == nil {
				t.Fatal("ResolveConfig() accepted an explicit negative flag value")
			}
		})

		t.Run(test.name+" from environment", func(t *testing.T) {
			_, _, err := ResolveConfig(ResolveOptions{
				Path:        filepath.Join(t.TempDir(), "config.yaml"),
				Environment: map[string]string{test.environmentKey: "0"},
			})
			if err == nil {
				t.Fatal("ResolveConfig() accepted an explicit zero environment value")
			}
		})
	}
}

func TestResolveConfigRejectsExplicitZeroPlaybookLimitFromProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`schema_version: config/v1
settings:
  playbook_max_step_count: 0
`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, _, err := ResolveConfig(ResolveOptions{Path: path, Environment: map[string]string{}}); err == nil {
		t.Fatal("ResolveConfig() accepted an explicit zero profile limit")
	}
}

func TestStorePersistsPlaybookPolicyAndRejectsUnsafeBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	enabled := true
	confidence := 0.67
	maxSourceBytes := 4096
	maxStepCount := 5
	maxTotalTextBytes := 32768
	cfg := NewUserConfig()
	cfg.Settings.PlaybookEnabled = &enabled
	cfg.Settings.PlaybookLearningMode = "auto_draft"
	cfg.Settings.PlaybookMinConfidence = &confidence
	cfg.Settings.PlaybookAllowedActions = []string{"GitOpsPR", "Manual", "manual"}
	cfg.Settings.PlaybookAllowedNamespaces = []string{"payments", "platform"}
	cfg.Settings.PlaybookAllowedKinds = []string{"Deployment", "StatefulSet"}
	cfg.Settings.PlaybookMaxSourceBytes = &maxSourceBytes
	cfg.Settings.PlaybookMaxStepCount = &maxStepCount
	cfg.Settings.PlaybookMaxTotalTextBytes = &maxTotalTextBytes
	if err := SaveUserConfig(path, cfg); err != nil {
		t.Fatalf("SaveUserConfig() error = %v", err)
	}

	loaded, err := LoadUserConfig(path)
	if err != nil {
		t.Fatalf("LoadUserConfig() error = %v", err)
	}
	if loaded.Settings.PlaybookEnabled == nil || !*loaded.Settings.PlaybookEnabled {
		t.Fatalf("loaded PlaybookEnabled = %#v, want true pointer", loaded.Settings.PlaybookEnabled)
	}
	if loaded.Settings.PlaybookLearningMode != "AUTO_DRAFT" || loaded.Settings.PlaybookMinConfidence == nil || *loaded.Settings.PlaybookMinConfidence != 0.67 ||
		loaded.Settings.PlaybookMaxSourceBytes == nil || *loaded.Settings.PlaybookMaxSourceBytes != 4096 ||
		loaded.Settings.PlaybookMaxStepCount == nil || *loaded.Settings.PlaybookMaxStepCount != 5 ||
		loaded.Settings.PlaybookMaxTotalTextBytes == nil || *loaded.Settings.PlaybookMaxTotalTextBytes != 32768 {
		t.Fatalf("loaded playbook scalars = %#v", loaded.Settings)
	}
	if !reflect.DeepEqual(loaded.Settings.PlaybookAllowedActions, []string{"GitOpsPR", "Manual"}) {
		t.Fatalf("loaded PlaybookAllowedActions = %#v", loaded.Settings.PlaybookAllowedActions)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	text := string(data)
	for _, unsafe := range []string{"database_url", "SRE_DATABASE_URL", "postgres://"} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("saved config contains runtime database material %q: %s", unsafe, text)
		}
	}
	if !strings.Contains(text, "playbook_learning_mode: AUTO_DRAFT") || !strings.Contains(text, "playbook_allowed_actions:") {
		t.Fatalf("saved config omitted playbook policy: %s", text)
	}

	cfg.Settings.PlaybookAllowedNamespaces = make([]string, MaxPlaybookPolicyListItems+1)
	for index := range cfg.Settings.PlaybookAllowedNamespaces {
		cfg.Settings.PlaybookAllowedNamespaces[index] = "namespace-" + strconv.Itoa(index)
	}
	if err := SaveUserConfig(filepath.Join(t.TempDir(), "too-many.yaml"), cfg); err == nil || !strings.Contains(err.Error(), "playbook allowed namespaces") {
		t.Fatalf("SaveUserConfig() error = %v, want list bound", err)
	}

	cfg.Settings.PlaybookAllowedNamespaces = []string{"payments", "platform"}
	cfg.Settings.PlaybookAllowedActions = []string{strings.Repeat("a", MaxPlaybookPolicyTextBytes+1)}
	if err := SaveUserConfig(filepath.Join(t.TempDir(), "too-long.yaml"), cfg); err == nil || !strings.Contains(err.Error(), "playbook allowed actions") {
		t.Fatalf("SaveUserConfig() error = %v, want text bound", err)
	}
}

func TestResolveConfigPreservesExplicitZeroPlaybookConfidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := `schema_version: config/v1
settings:
  playbook_min_confidence: 0
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	resolved, persisted, err := ResolveConfig(ResolveOptions{Path: path, Environment: map[string]string{}})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if resolved.PlaybookMinConfidence != 0 {
		t.Fatalf("resolved PlaybookMinConfidence = %v, want explicit zero", resolved.PlaybookMinConfidence)
	}
	if persisted.Settings.PlaybookMinConfidence == nil || *persisted.Settings.PlaybookMinConfidence != 0 {
		t.Fatalf("persisted PlaybookMinConfidence = %v, want explicit zero", persisted.Settings.PlaybookMinConfidence)
	}
}

func TestLoadUserConfigRejectsNonFinitePlaybookConfidence(t *testing.T) {
	for _, value := range []string{".nan", ".inf"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		data := `schema_version: config/v1
settings:
  playbook_learning_mode: AUTO_DRAFT
  playbook_min_confidence: ` + value + `
`
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		if _, err := LoadUserConfig(path); err == nil || !strings.Contains(err.Error(), "confidence") {
			t.Fatalf("LoadUserConfig() with playbook_min_confidence %s error = %v, want confidence bounds", value, err)
		}
	}
}

func TestResolveConfigRejectsPlaybookEnablementWithoutDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	enabled := true
	cfg := NewUserConfig()
	cfg.Settings.PlaybookEnabled = &enabled
	if err := SaveUserConfig(path, cfg); err != nil {
		t.Fatalf("SaveUserConfig() error = %v", err)
	}

	if _, _, err := ResolveConfig(ResolveOptions{Path: path, Environment: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "database URL") {
		t.Fatalf("ResolveConfig() error = %v, want missing database URL", err)
	}
}

func TestResolveConfigUsesPersistedProviderWhenNoOverrideExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	cfg := NewUserConfig()
	cfg.DefaultProfile = "local"
	cfg.Profiles = []ProviderProfile{{
		Name:     "local",
		Provider: "ollama",
		Model:    "llama3",
		BaseURL:  "http://127.0.0.1:11434/v1",
	}}
	cfg.Settings.PublicURL = "https://sre.example.test"
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	resolved, _, err := ResolveConfig(ResolveOptions{Path: path, Environment: map[string]string{}})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if resolved.LLMProvider != "ollama" || resolved.LLMModel != "llama3" || resolved.LLMBaseURL != "http://127.0.0.1:11434/v1" {
		t.Fatalf("resolved provider = %#v", resolved)
	}
	if resolved.PublicURL != "https://sre.example.test" {
		t.Fatalf("resolved public URL = %q, want persisted setting", resolved.PublicURL)
	}
}

func TestStoreProviderAndFilterCRUDAndDefaults(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	if _, err := store.Load(); err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	if err := store.CreateProfile(ProviderProfile{Name: "local", Provider: "ollama", BaseURL: "http://localhost:11434/v1"}); err != nil {
		t.Fatalf("CreateProfile() error = %v", err)
	}
	if err := store.SetDefaultProfile("local"); err != nil {
		t.Fatalf("SetDefaultProfile() error = %v", err)
	}
	if err := store.CreateFilter(AnalyzerFilter{Name: "workloads", Analyzers: []string{"PodAnalyzer", "DeploymentAnalyzer"}}); err != nil {
		t.Fatalf("CreateFilter() error = %v", err)
	}
	if err := store.SetDefaultFilter("workloads"); err != nil {
		t.Fatalf("SetDefaultFilter() error = %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after CRUD error = %v", err)
	}
	if got.DefaultProfile != "local" || got.DefaultFilter != "workloads" {
		t.Fatalf("defaults = profile %q filter %q", got.DefaultProfile, got.DefaultFilter)
	}
	if len(got.Profiles) != 1 || len(got.Filters) != 1 {
		t.Fatalf("CRUD collections = %d profiles, %d filters", len(got.Profiles), len(got.Filters))
	}
	if err := store.DeleteProfile("local"); err != nil {
		t.Fatalf("DeleteProfile() error = %v", err)
	}
	if err := store.DeleteFilter("workloads"); err != nil {
		t.Fatalf("DeleteFilter() error = %v", err)
	}
	got, err = store.Load()
	if err != nil {
		t.Fatalf("final Load() error = %v", err)
	}
	if got.DefaultProfile != "" || got.DefaultFilter != "" || len(got.Profiles) != 0 || len(got.Filters) != 0 {
		t.Fatalf("deleted state = %#v", got)
	}
}
