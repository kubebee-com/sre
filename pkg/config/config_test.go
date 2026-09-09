package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestLoadConfigReadsSafetyEnvironment(t *testing.T) {
	t.Setenv("SRE_API_TOKEN", "env-api-token")
	t.Setenv("SRE_REQUIRE_API_TOKEN", "true")
	t.Setenv("SRE_ALLOWED_ORIGINS", "https://one.example, https://two.example")
	t.Setenv("SRE_MAX_BODY_BYTES", "2048")
	t.Setenv("SRE_REQUESTS_PER_MINUTE", "120")
	t.Setenv("SRE_REQUEST_BURST", "7")
	t.Setenv("SRE_DATA_DIR", "/var/lib/sre-agent")
	t.Setenv("SRE_TRUSTED_CLIENT_IP_HEADER", "X-Forwarded-For")
	t.Setenv("SRE_TRUSTED_PROXY_CIDRS", "10.244.0.0/16, 10.245.0.0/16")

	originalArgs := os.Args
	originalCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalCommandLine
	})
	os.Args = []string{originalArgs[0]}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	cfg := LoadConfig()
	if cfg.APIToken != "env-api-token" {
		t.Fatalf("APIToken = %q, want env-api-token", cfg.APIToken)
	}
	if !cfg.RequireAPIToken {
		t.Fatal("RequireAPIToken = false, want true")
	}
	if want := []string{"https://one.example", "https://two.example"}; !reflect.DeepEqual(cfg.AllowedOrigins, want) {
		t.Fatalf("AllowedOrigins = %#v, want %#v", cfg.AllowedOrigins, want)
	}
	if cfg.MaxBodyBytes != 2048 {
		t.Fatalf("MaxBodyBytes = %d, want 2048", cfg.MaxBodyBytes)
	}
	if cfg.RequestsPerMinute != 120 {
		t.Fatalf("RequestsPerMinute = %d, want 120", cfg.RequestsPerMinute)
	}
	if cfg.RequestBurst != 7 {
		t.Fatalf("RequestBurst = %d, want 7", cfg.RequestBurst)
	}
	if cfg.DataDir != "/var/lib/sre-agent" {
		t.Fatalf("DataDir = %q, want /var/lib/sre-agent", cfg.DataDir)
	}
	if cfg.TrustedClientIPHeader != "X-Forwarded-For" {
		t.Fatalf("TrustedClientIPHeader = %q, want X-Forwarded-For", cfg.TrustedClientIPHeader)
	}
	if want := []string{"10.244.0.0/16", "10.245.0.0/16"}; !reflect.DeepEqual(cfg.TrustedProxyCIDRs, want) {
		t.Fatalf("TrustedProxyCIDRs = %#v, want %#v", cfg.TrustedProxyCIDRs, want)
	}
}

func TestLoadConfigReadsScanPlanEnvironment(t *testing.T) {
	t.Setenv("SRE_INCLUDE_NAMESPACES", "payments, platform")
	t.Setenv("SRE_EXCLUDE_NAMESPACES", "kube-system")
	t.Setenv("SRE_LABEL_SELECTOR", "team=sre")
	t.Setenv("SRE_RESOURCE_KINDS", "Pod,Deployment")
	t.Setenv("SRE_RESOURCE_NAMES", "checkout")
	t.Setenv("SRE_ANALYZERS", "PodAnalyzer")
	t.Setenv("SRE_SCAN_CONCURRENCY", "3")
	t.Setenv("SRE_SCAN_TIMEOUT", "2m")
	t.Setenv("SRE_SCAN_JITTER", "5s")
	t.Setenv("SRE_LEADER_ELECTION", "true")
	t.Setenv("SRE_LEADER_ELECTION_NAMESPACE", "sre")
	t.Setenv("SRE_LEADER_ELECTION_ID", "scan-lease")
	t.Setenv("SRE_LEADER_ELECTION_IDENTITY", "pod-a")

	originalArgs := os.Args
	originalCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalCommandLine
	})
	os.Args = []string{originalArgs[0]}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	cfg := LoadConfig()
	if !reflect.DeepEqual(cfg.IncludeNamespaces, []string{"payments", "platform"}) || !reflect.DeepEqual(cfg.ExcludeNamespaces, []string{"kube-system"}) {
		t.Fatalf("namespace scan scope = %#v / %#v", cfg.IncludeNamespaces, cfg.ExcludeNamespaces)
	}
	if cfg.LabelSelector != "team=sre" || cfg.ScanConcurrency != 3 || cfg.ScanTimeout != 2*time.Minute || cfg.ScanJitter != 5*time.Second {
		t.Fatalf("scan settings = selector %q concurrency %d timeout %s jitter %s", cfg.LabelSelector, cfg.ScanConcurrency, cfg.ScanTimeout, cfg.ScanJitter)
	}
	if !cfg.LeaderElection || cfg.LeaderElectionNamespace != "sre" || cfg.LeaderElectionID != "scan-lease" || cfg.LeaderElectionIdentity != "pod-a" {
		t.Fatalf("leader election settings = enabled %t namespace %q id %q identity %q", cfg.LeaderElection, cfg.LeaderElectionNamespace, cfg.LeaderElectionID, cfg.LeaderElectionIdentity)
	}
	plan := cfg.ScanPlan()
	if plan.LabelSelector != "team=sre" || len(plan.Kinds) != 2 || len(plan.Analyzers) != 1 {
		t.Fatalf("ScanPlan() = %#v", plan)
	}
}

func TestLoadConfigReadsEventTriggerSettingsWithFlagPrecedence(t *testing.T) {
	t.Setenv("SRE_EVENT_DRIVEN_SCANNING", "false")
	t.Setenv("SRE_EVENT_QUEUE_CAPACITY", "32")
	t.Setenv("SRE_EVENT_DEBOUNCE", "750ms")

	cfg := LoadConfigArgs(nil)
	if cfg.EventDrivenScanning || cfg.EventQueueCapacity != 32 || cfg.EventDebounce != 750*time.Millisecond {
		t.Fatalf("environment event settings = enabled %t capacity %d debounce %s", cfg.EventDrivenScanning, cfg.EventQueueCapacity, cfg.EventDebounce)
	}

	cfg = LoadConfigArgs([]string{
		"--event-driven-scanning=true",
		"--event-queue-capacity=64",
		"--event-debounce=2s",
	})
	if !cfg.EventDrivenScanning || cfg.EventQueueCapacity != 64 || cfg.EventDebounce != 2*time.Second {
		t.Fatalf("flag event settings = enabled %t capacity %d debounce %s", cfg.EventDrivenScanning, cfg.EventQueueCapacity, cfg.EventDebounce)
	}
}

func TestLoadConfigReadsAWSEKSSettingsWithFlagPrecedence(t *testing.T) {
	t.Setenv("SRE_ENABLE_AWS_EKS", "true")
	t.Setenv("AWS_REGION", "env-region")
	t.Setenv("AWS_DEFAULT_REGION", "fallback-region")
	t.Setenv("SRE_EKS_CLUSTER_NAME", "env-cluster")

	cfg := LoadConfigArgs(nil)
	if !cfg.EnableAWSEKS || cfg.AWSRegion != "env-region" || cfg.EKSClusterName != "env-cluster" {
		t.Fatalf("environment AWS/EKS settings = enabled %t region %q cluster %q", cfg.EnableAWSEKS, cfg.AWSRegion, cfg.EKSClusterName)
	}

	t.Setenv("AWS_REGION", "")
	cfg = LoadConfigArgs(nil)
	if cfg.AWSRegion != "fallback-region" {
		t.Fatalf("AWS region fallback = %q, want fallback-region", cfg.AWSRegion)
	}

	cfg = LoadConfigArgs([]string{
		"--enable-aws-eks=false",
		"--aws-region=flag-region",
		"--eks-cluster-name=flag-cluster",
	})
	if cfg.EnableAWSEKS || cfg.AWSRegion != "flag-region" || cfg.EKSClusterName != "flag-cluster" {
		t.Fatalf("flag AWS/EKS settings = enabled %t region %q cluster %q", cfg.EnableAWSEKS, cfg.AWSRegion, cfg.EKSClusterName)
	}
}

func TestLoadConfigReadsLLMModeWithFlagPrecedence(t *testing.T) {
	t.Setenv("LLM_MODE", "aws")

	cfg := LoadConfigArgs(nil)
	if cfg.LLMMode != "aws" {
		t.Fatalf("environment LLMMode = %q, want aws", cfg.LLMMode)
	}

	cfg = LoadConfigArgs([]string{"--llm-mode=remote"})
	if cfg.LLMMode != "remote" {
		t.Fatalf("flag LLMMode = %q, want remote", cfg.LLMMode)
	}
}

func TestLoadConfigReadsLLMWireAPIWithFlagPrecedence(t *testing.T) {
	t.Setenv("LLM_WIRE_API", "responses")

	cfg := LoadConfigArgs(nil)
	if cfg.LLMWireAPI != "responses" {
		t.Fatalf("environment LLMWireAPI = %q, want responses", cfg.LLMWireAPI)
	}

	cfg = LoadConfigArgs([]string{"--llm-wire-api=chat"})
	if cfg.LLMWireAPI != "chat" {
		t.Fatalf("flag LLMWireAPI = %q, want chat", cfg.LLMWireAPI)
	}
}

func TestLoadConfigReadsLLMEndpointAllowlistWithFlagPrecedence(t *testing.T) {
	t.Setenv("LLM_ENDPOINT_ALLOWLIST", "https://env.example.test/v1,https://env-two.example.test")

	cfg := LoadConfigArgs(nil)
	if !reflect.DeepEqual(cfg.LLMEndpointAllowlist, []string{"https://env.example.test/v1", "https://env-two.example.test"}) {
		t.Fatalf("environment endpoint allowlist = %#v", cfg.LLMEndpointAllowlist)
	}

	cfg = LoadConfigArgs([]string{"--llm-endpoint-allowlist=https://flag.example.test/v1"})
	if !reflect.DeepEqual(cfg.LLMEndpointAllowlist, []string{"https://flag.example.test/v1"}) {
		t.Fatalf("flag endpoint allowlist = %#v", cfg.LLMEndpointAllowlist)
	}
}

func TestLoadConfigReadsProviderHeadersAndTransportSettingsWithFlagPrecedence(t *testing.T) {
	t.Setenv("LLM_CUSTOM_HEADERS", "X-Env:env-value,Authorization:Bearer env-token")
	t.Setenv("LLM_ORGANIZATION", "env-org")
	t.Setenv("LLM_PROXY_URL", "https://proxy.example.test")

	cfg := LoadConfigArgs(nil)
	if !reflect.DeepEqual(cfg.LLMHeaders, []string{"X-Env:env-value", "Authorization:Bearer env-token"}) {
		t.Fatalf("environment LLMHeaders = %#v", cfg.LLMHeaders)
	}
	if cfg.LLMOrganization != "env-org" || cfg.LLMProxyURL != "https://proxy.example.test" {
		t.Fatalf("environment provider transport settings = organization %q proxy %q", cfg.LLMOrganization, cfg.LLMProxyURL)
	}

	cfg = LoadConfigArgs([]string{
		"--llm-headers", "X-Flag:first",
		"--custom-headers=X-Flag:second",
		"--llm-organization=flag-org",
		"--llm-proxy-url", "https://flag-proxy.example.test",
	})
	if !reflect.DeepEqual(cfg.LLMHeaders, []string{"X-Flag:first", "X-Flag:second"}) {
		t.Fatalf("flag LLMHeaders = %#v", cfg.LLMHeaders)
	}
	if cfg.LLMOrganization != "flag-org" || cfg.LLMProxyURL != "https://flag-proxy.example.test" {
		t.Fatalf("flag provider transport settings = organization %q proxy %q", cfg.LLMOrganization, cfg.LLMProxyURL)
	}
}

func TestLoadConfigReadsCacheAndGRPCTLSSettingsWithFlagPrecedence(t *testing.T) {
	t.Setenv("SRE_CACHE_DIR", "/var/lib/sre-agent/cache")
	t.Setenv("SRE_CACHE_ENCRYPTION_KEY", "cache-secret")
	t.Setenv("SRE_CACHE_TTL", "10m")
	t.Setenv("SRE_CACHE_MAX_ENTRIES", "64")
	t.Setenv("SRE_CACHE_MAX_VALUE_BYTES", "65536")
	t.Setenv("SRE_GRPC_TLS_CERT_FILE", "/etc/tls/env.crt")
	t.Setenv("SRE_GRPC_TLS_KEY_FILE", "/etc/tls/env.key")
	t.Setenv("SRE_GRPC_TLS_CLIENT_CA_FILE", "/etc/tls/env-ca.crt")
	t.Setenv("SRE_GRPC_REFLECTION", "true")

	cfg := LoadConfigArgs(nil)
	if cfg.CacheDir != "/var/lib/sre-agent/cache" || cfg.CacheEncryptionKey != "cache-secret" || cfg.CacheTTL != 10*time.Minute || cfg.CacheMaxEntries != 64 || cfg.CacheMaxValueBytes != 65536 {
		t.Fatalf("environment cache settings = dir %q key %q ttl %s entries %d bytes %d", cfg.CacheDir, cfg.CacheEncryptionKey, cfg.CacheTTL, cfg.CacheMaxEntries, cfg.CacheMaxValueBytes)
	}
	if cfg.GRPCTLSCertFile != "/etc/tls/env.crt" || cfg.GRPCTLSKeyFile != "/etc/tls/env.key" || cfg.GRPCTLSClientCAFile != "/etc/tls/env-ca.crt" || !cfg.GRPCReflection {
		t.Fatalf("environment gRPC TLS settings = cert %q key %q ca %q reflection %t", cfg.GRPCTLSCertFile, cfg.GRPCTLSKeyFile, cfg.GRPCTLSClientCAFile, cfg.GRPCReflection)
	}

	cfg = LoadConfigArgs([]string{
		"--cache-dir=/tmp/cache",
		"--cache-ttl=2m",
		"--cache-max-entries=8",
		"--cache-max-value-bytes=4096",
		"--grpc-tls-cert-file=/tmp/flag.crt",
		"--grpc-tls-key-file=/tmp/flag.key",
		"--grpc-tls-client-ca-file=/tmp/flag-ca.crt",
		"--grpc-reflection=false",
	})
	if cfg.CacheDir != "/tmp/cache" || cfg.CacheTTL != 2*time.Minute || cfg.CacheMaxEntries != 8 || cfg.CacheMaxValueBytes != 4096 {
		t.Fatalf("flag cache settings = dir %q ttl %s entries %d bytes %d", cfg.CacheDir, cfg.CacheTTL, cfg.CacheMaxEntries, cfg.CacheMaxValueBytes)
	}
	if cfg.CacheEncryptionKey != "cache-secret" {
		t.Fatalf("cache encryption key = %q, want environment-only value", cfg.CacheEncryptionKey)
	}
	if cfg.GRPCTLSCertFile != "/tmp/flag.crt" || cfg.GRPCTLSKeyFile != "/tmp/flag.key" || cfg.GRPCTLSClientCAFile != "/tmp/flag-ca.crt" || cfg.GRPCReflection {
		t.Fatalf("flag gRPC TLS settings = cert %q key %q ca %q reflection %t", cfg.GRPCTLSCertFile, cfg.GRPCTLSKeyFile, cfg.GRPCTLSClientCAFile, cfg.GRPCReflection)
	}
}

func TestLoadConfigReadsPlaybookSettingsWithFlagPrecedence(t *testing.T) {
	t.Setenv("SRE_DATABASE_URL", "postgres://user:secret@db.example.test:5432/sre")
	t.Setenv("SRE_PLAYBOOK_ENABLED", "true")
	t.Setenv("SRE_PLAYBOOK_LEARNING_MODE", "observe_only")
	t.Setenv("SRE_PLAYBOOK_MIN_CONFIDENCE", "0.72")
	t.Setenv("SRE_PLAYBOOK_ALLOWED_ACTIONS", "Manual,GitOpsPR")
	t.Setenv("SRE_PLAYBOOK_ALLOWED_NAMESPACES", "payments,platform")
	t.Setenv("SRE_PLAYBOOK_ALLOWED_KINDS", "Deployment,StatefulSet")
	t.Setenv("SRE_PLAYBOOK_MAX_SOURCE_BYTES", "4096")
	t.Setenv("SRE_PLAYBOOK_MAX_STEP_COUNT", "6")
	t.Setenv("SRE_PLAYBOOK_MAX_TOTAL_TEXT_BYTES", "16384")

	cfg := LoadConfigArgs(nil)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.DatabaseURL != "postgres://user:secret@db.example.test:5432/sre" || !cfg.PlaybookEnabled {
		t.Fatalf("database/playbook enablement = url %q enabled %t", cfg.DatabaseURL, cfg.PlaybookEnabled)
	}
	if cfg.PlaybookLearningMode != "OBSERVE_ONLY" || cfg.PlaybookMinConfidence != 0.72 || cfg.PlaybookMaxSourceBytes != 4096 || cfg.PlaybookMaxStepCount != 6 || cfg.PlaybookMaxTotalTextBytes != 16384 {
		t.Fatalf("playbook scalar settings = mode %q confidence %v source bytes %d step count %d total text bytes %d", cfg.PlaybookLearningMode, cfg.PlaybookMinConfidence, cfg.PlaybookMaxSourceBytes, cfg.PlaybookMaxStepCount, cfg.PlaybookMaxTotalTextBytes)
	}
	if !reflect.DeepEqual(cfg.PlaybookAllowedActions, []string{"Manual", "GitOpsPR"}) {
		t.Fatalf("PlaybookAllowedActions = %#v", cfg.PlaybookAllowedActions)
	}
	if !reflect.DeepEqual(cfg.PlaybookAllowedNamespaces, []string{"payments", "platform"}) {
		t.Fatalf("PlaybookAllowedNamespaces = %#v", cfg.PlaybookAllowedNamespaces)
	}
	if !reflect.DeepEqual(cfg.PlaybookAllowedKinds, []string{"Deployment", "StatefulSet"}) {
		t.Fatalf("PlaybookAllowedKinds = %#v", cfg.PlaybookAllowedKinds)
	}

	cfg = LoadConfigArgs([]string{
		"--database-url=postgres://flag:secret@db.example.test:5432/sre",
		"--playbook-enabled=false",
		"--playbook-learning-mode=DISABLED",
		"--playbook-min-confidence=0.9",
		"--playbook-allowed-actions=Manual",
		"--playbook-allowed-namespaces=prod",
		"--playbook-allowed-kinds=Pod",
		"--playbook-max-source-bytes=2048",
		"--playbook-max-step-count=1",
		"--playbook-max-total-text-bytes=4096",
	})
	if cfg.DatabaseURL != "postgres://flag:secret@db.example.test:5432/sre" || cfg.PlaybookEnabled {
		t.Fatalf("flag database/playbook enablement = url %q enabled %t", cfg.DatabaseURL, cfg.PlaybookEnabled)
	}
	if cfg.PlaybookLearningMode != "DISABLED" || cfg.PlaybookMinConfidence != 0.9 || cfg.PlaybookMaxSourceBytes != 2048 || cfg.PlaybookMaxStepCount != 1 || cfg.PlaybookMaxTotalTextBytes != 4096 {
		t.Fatalf("flag playbook scalar settings = mode %q confidence %v source bytes %d step count %d total text bytes %d", cfg.PlaybookLearningMode, cfg.PlaybookMinConfidence, cfg.PlaybookMaxSourceBytes, cfg.PlaybookMaxStepCount, cfg.PlaybookMaxTotalTextBytes)
	}
	if !reflect.DeepEqual(cfg.PlaybookAllowedActions, []string{"Manual"}) || !reflect.DeepEqual(cfg.PlaybookAllowedNamespaces, []string{"prod"}) || !reflect.DeepEqual(cfg.PlaybookAllowedKinds, []string{"Pod"}) {
		t.Fatalf("flag playbook lists = actions %#v namespaces %#v kinds %#v", cfg.PlaybookAllowedActions, cfg.PlaybookAllowedNamespaces, cfg.PlaybookAllowedKinds)
	}
}

func TestLoadConfigPreservesExplicitInvalidPlaybookLimits(t *testing.T) {
	tests := []struct {
		name           string
		environmentKey string
		flag           string
		value          int
		resolved       func(*Config) int
	}{
		{
			name:           "source bytes",
			environmentKey: "SRE_PLAYBOOK_MAX_SOURCE_BYTES",
			flag:           "--playbook-max-source-bytes",
			value:          -1,
			resolved:       func(cfg *Config) int { return cfg.PlaybookMaxSourceBytes },
		},
		{
			name:           "step count",
			environmentKey: "SRE_PLAYBOOK_MAX_STEP_COUNT",
			flag:           "--playbook-max-step-count",
			value:          0,
			resolved:       func(cfg *Config) int { return cfg.PlaybookMaxStepCount },
		},
		{
			name:           "total text bytes",
			environmentKey: "SRE_PLAYBOOK_MAX_TOTAL_TEXT_BYTES",
			flag:           "--playbook-max-total-text-bytes",
			value:          -3,
			resolved:       func(cfg *Config) int { return cfg.PlaybookMaxTotalTextBytes },
		},
	}

	for _, test := range tests {
		t.Run(test.name+" from environment", func(t *testing.T) {
			t.Setenv(test.environmentKey, strconv.Itoa(test.value))
			cfg := LoadConfigArgs(nil)
			if got := test.resolved(cfg); got != test.value {
				t.Fatalf("resolved limit = %d, want explicit %d", got, test.value)
			}
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() accepted an explicit nonpositive limit")
			}
		})

		t.Run(test.name+" from flag", func(t *testing.T) {
			cfg := LoadConfigArgs([]string{test.flag, strconv.Itoa(test.value)})
			if got := test.resolved(cfg); got != test.value {
				t.Fatalf("resolved limit = %d, want explicit %d", got, test.value)
			}
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() accepted an explicit nonpositive limit")
			}
		})
	}
}

func TestLoadConfigFailsClosedForMalformedPlaybookEnabled(t *testing.T) {
	t.Setenv("SRE_DATABASE_URL", "")
	t.Setenv("SRE_PLAYBOOK_ENABLED", "not-a-bool")

	cfg := LoadConfigArgs(nil)
	if cfg.PlaybookEnabled {
		t.Fatal("malformed SRE_PLAYBOOK_ENABLED enabled playbooks")
	}
}

func TestPlaybookValidationRejectsUnsafeRuntimeSettings(t *testing.T) {
	cfg := LoadConfigArgs([]string{"--playbook-enabled=true"})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "database URL") {
		t.Fatalf("Validate() error = %v, want missing database URL", err)
	}

	cfg = LoadConfigArgs([]string{
		"--database-url=postgres://user:secret@db.example.test:5432/sre",
		"--playbook-learning-mode=AUTO_PROMOTE",
	})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "learning mode") {
		t.Fatalf("Validate() error = %v, want invalid learning mode", err)
	}

	cfg = LoadConfigArgs([]string{
		"--database-url=postgres://user:secret@db.example.test:5432/sre",
		"--playbook-min-confidence=1.01",
	})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "confidence") {
		t.Fatalf("Validate() error = %v, want confidence bounds", err)
	}

	for _, value := range []string{"NaN", "Inf"} {
		t.Setenv("SRE_PLAYBOOK_MIN_CONFIDENCE", value)
		cfg = LoadConfigArgs([]string{"--database-url=postgres://user:secret@db.example.test:5432/sre"})
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "confidence") {
			t.Fatalf("Validate() with SRE_PLAYBOOK_MIN_CONFIDENCE=%q error = %v, want confidence bounds", value, err)
		}
	}
}

func TestLoadConfigDefaultsPlaybookDisabledWithoutDatabase(t *testing.T) {
	for _, key := range []string{"SRE_DATABASE_URL", "SRE_PLAYBOOK_ENABLED", "SRE_PLAYBOOK_LEARNING_MODE"} {
		original, hadOriginal := os.LookupEnv(key)
		t.Cleanup(func() {
			if hadOriginal {
				_ = os.Setenv(key, original)
				return
			}
			_ = os.Unsetenv(key)
		})
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}

	cfg := LoadConfigArgs(nil)
	if cfg.PlaybookEnabled {
		t.Fatal("PlaybookEnabled default = true, want false without database URL")
	}
	if cfg.PlaybookLearningMode != "AUTO_DRAFT" {
		t.Fatalf("PlaybookLearningMode default = %q, want AUTO_DRAFT", cfg.PlaybookLearningMode)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestConfigStringRedactsPlaybookDatabaseURL(t *testing.T) {
	cfg := LoadConfigArgs([]string{
		"--database-url=postgres://user:secret@db.example.test:5432/sre",
		"--api-token=runtime-api-secret",
		"--llm-api-key=runtime-llm-secret",
		"--llm-headers=X-Provider-Token:runtime-header-secret",
	})

	jsonBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal(Config) error = %v", err)
	}
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal(Config) error = %v", err)
	}
	text := cfg.String() + "\n" +
		fmt.Sprintf("%+v", cfg) + "\n" +
		fmt.Sprintf("%#v", cfg) + "\n" +
		fmt.Sprintf("%+v", *cfg) + "\n" +
		fmt.Sprintf("%#v", *cfg) + "\n" +
		string(jsonBytes) + "\n" +
		string(yamlBytes)
	for _, secret := range []string{"postgres://user:secret", "runtime-api-secret", "runtime-llm-secret", "runtime-header-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("Config.String() leaked secret %q in %s", secret, text)
		}
	}
	if !strings.Contains(text, `DatabaseURL:<redacted>`) {
		t.Fatalf("Config.String() did not show redacted database URL: %s", text)
	}
}

func TestLoadConfigFailsClosedForInvalidRequireAPIToken(t *testing.T) {
	t.Setenv("SRE_API_TOKEN", "")
	t.Setenv("SRE_REQUIRE_API_TOKEN", "not-a-boolean")

	originalArgs := os.Args
	originalCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalCommandLine
	})
	os.Args = []string{originalArgs[0]}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	cfg := LoadConfig()
	if !cfg.RequireAPIToken {
		t.Fatal("invalid SRE_REQUIRE_API_TOKEN value disabled required authentication")
	}
}

func TestLoadConfigFailsClosedForBlankRequireAPIToken(t *testing.T) {
	t.Setenv("SRE_API_TOKEN", "")
	t.Setenv("SRE_REQUIRE_API_TOKEN", " \t\n")

	originalArgs := os.Args
	originalCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalCommandLine
	})
	os.Args = []string{originalArgs[0]}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	cfg := LoadConfig()
	if !cfg.RequireAPIToken {
		t.Fatal("blank SRE_REQUIRE_API_TOKEN value disabled required authentication")
	}
}

func TestLoadConfigKeepsLocalSafetyDefaults(t *testing.T) {
	for _, key := range []string{
		"SRE_API_TOKEN",
		"SRE_ALLOWED_ORIGINS",
		"SRE_MAX_BODY_BYTES",
		"SRE_REQUESTS_PER_MINUTE",
		"SRE_REQUEST_BURST",
		"SRE_DATA_DIR",
		"SRE_TRUSTED_CLIENT_IP_HEADER",
		"SRE_TRUSTED_PROXY_CIDRS",
	} {
		t.Setenv(key, "")
	}
	originalRequireAPIToken, hadRequireAPIToken := os.LookupEnv("SRE_REQUIRE_API_TOKEN")
	t.Cleanup(func() {
		if hadRequireAPIToken {
			_ = os.Setenv("SRE_REQUIRE_API_TOKEN", originalRequireAPIToken)
			return
		}
		_ = os.Unsetenv("SRE_REQUIRE_API_TOKEN")
	})
	if err := os.Unsetenv("SRE_REQUIRE_API_TOKEN"); err != nil {
		t.Fatalf("unset SRE_REQUIRE_API_TOKEN: %v", err)
	}

	originalArgs := os.Args
	originalCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalCommandLine
	})
	os.Args = []string{originalArgs[0]}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	cfg := LoadConfig()
	if cfg.APIToken != "" {
		t.Fatalf("APIToken default = %q, want empty for local development", cfg.APIToken)
	}
	if cfg.RequireAPIToken {
		t.Fatal("RequireAPIToken default = true, want false for local development")
	}
	if len(cfg.AllowedOrigins) != 0 {
		t.Fatalf("AllowedOrigins default = %#v, want empty", cfg.AllowedOrigins)
	}
	if cfg.MaxBodyBytes <= 0 || cfg.RequestsPerMinute <= 0 || cfg.RequestBurst <= 0 {
		t.Fatalf("local safety defaults = body %d, rate %d, burst %d; all must be positive", cfg.MaxBodyBytes, cfg.RequestsPerMinute, cfg.RequestBurst)
	}
	if cfg.TrustedClientIPHeader != "" {
		t.Fatalf("TrustedClientIPHeader default = %q, want empty", cfg.TrustedClientIPHeader)
	}
	if len(cfg.TrustedProxyCIDRs) != 0 {
		t.Fatalf("TrustedProxyCIDRs default = %#v, want empty", cfg.TrustedProxyCIDRs)
	}
}

func TestLoadConfigFallsBackForInvalidSafetyEnvironment(t *testing.T) {
	t.Setenv("SRE_MAX_BODY_BYTES", "-1")
	t.Setenv("SRE_REQUESTS_PER_MINUTE", "0")
	t.Setenv("SRE_REQUEST_BURST", "-4")

	originalArgs := os.Args
	originalCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalCommandLine
	})
	os.Args = []string{originalArgs[0]}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	cfg := LoadConfig()
	if cfg.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Fatalf("invalid MaxBodyBytes = %d, want %d", cfg.MaxBodyBytes, DefaultMaxBodyBytes)
	}
	if cfg.RequestsPerMinute != DefaultRequestsPerMinute {
		t.Fatalf("invalid RequestsPerMinute = %d, want %d", cfg.RequestsPerMinute, DefaultRequestsPerMinute)
	}
	if cfg.RequestBurst != DefaultRequestBurst {
		t.Fatalf("invalid RequestBurst = %d, want %d", cfg.RequestBurst, DefaultRequestBurst)
	}
}
