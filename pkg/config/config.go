package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/kubebee-com/sre/pkg/scheduler"
)

const (
	DefaultMaxBodyBytes              int64 = 1 << 20
	DefaultRequestsPerMinute               = 600
	DefaultRequestBurst                    = 20
	DefaultCacheTTL                        = 15 * time.Minute
	DefaultCacheMaxEntries                 = 256
	DefaultCacheMaxValueBytes              = 1 << 20
	DefaultPlaybookLearningMode            = "AUTO_DRAFT"
	DefaultPlaybookMinConfidence           = 0.7
	DefaultPlaybookMaxSourceBytes          = 64 << 10
	DefaultPlaybookMaxStepCount            = 8
	DefaultPlaybookMaxTotalTextBytes       = 256 << 10
	MaxPlaybookPolicyListItems             = 32
	MaxPlaybookPolicyTextBytes             = 128
	MaxPlaybookSourceBytes                 = 1 << 20
	MaxPlaybookStepCount                   = 32
	MaxPlaybookTotalTextBytes              = 4 << 20
)

type Config struct {
	EventDrivenScanning       bool
	EventQueueCapacity        int
	EventDebounce             time.Duration
	LLMEndpointAllowlist      []string
	Kubeconfig                string
	Port                      int
	GRPCPort                  int
	GRPCTLSCertFile           string
	GRPCTLSKeyFile            string
	GRPCTLSClientCAFile       string
	GRPCReflection            bool
	ScanInterval              time.Duration
	ScanJitter                time.Duration
	LeaderElection            bool
	LeaderElectionNamespace   string
	LeaderElectionID          string
	LeaderElectionIdentity    string
	EnableAWSEKS              bool
	AWSRegion                 string
	EKSClusterName            string
	Namespace                 string
	LLMProvider               string
	LLMMode                   string
	LLMWireAPI                string
	LLMAPIKey                 string
	LLMModel                  string
	LLMBaseURL                string
	LLMOrganization           string
	LLMProxyURL               string
	LLMHeaders                []string
	HarnessCommand            string
	WebhookURL                string
	PublicURL                 string
	APIToken                  string
	RequireAPIToken           bool
	AllowedOrigins            []string
	TrustedClientIPHeader     string
	TrustedProxyCIDRs         []string
	MaxBodyBytes              int64
	RequestsPerMinute         int
	RequestBurst              int
	DataDir                   string
	IncludeNamespaces         []string
	ExcludeNamespaces         []string
	LabelSelector             string
	ResourceKinds             []string
	ResourceNames             []string
	Analyzers                 []string
	ScanConcurrency           int
	ScanTimeout               time.Duration
	HistoryDir                string
	CacheDir                  string
	CacheEncryptionKey        string
	CacheTTL                  time.Duration
	CacheMaxEntries           int
	CacheMaxValueBytes        int
	DatabaseURL               string `json:"-" yaml:"-"`
	PlaybookEnabled           bool
	PlaybookLearningMode      string
	PlaybookMinConfidence     float64
	PlaybookAllowedActions    []string
	PlaybookAllowedNamespaces []string
	PlaybookAllowedKinds      []string
	PlaybookMaxSourceBytes    int
	PlaybookMaxStepCount      int
	PlaybookMaxTotalTextBytes int
}

func (c Config) String() string {
	return fmt.Sprintf("%+v", c.redactedForLog())
}

func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.redactedForLog())
}

func (c Config) MarshalYAML() (interface{}, error) {
	return c.redactedForLog(), nil
}

func (c Config) Format(state fmt.State, verb rune) {
	format := "%"
	for _, flag := range []rune{'#', '+', '-', ' ', '0'} {
		if state.Flag(int(flag)) {
			format += string(flag)
		}
	}
	if width, ok := state.Width(); ok {
		format += strconv.Itoa(width)
	}
	if precision, ok := state.Precision(); ok {
		format += "." + strconv.Itoa(precision)
	}
	format += string(verb)
	_, _ = fmt.Fprintf(state, format, c.redactedForLog())
}

func (c Config) redactedForLog() any {
	type printableConfig Config
	redacted := printableConfig(c)
	redactString(&redacted.DatabaseURL)
	redactString(&redacted.LLMAPIKey)
	redactString(&redacted.APIToken)
	redactString(&redacted.WebhookURL)
	redactString(&redacted.CacheEncryptionKey)
	redacted.LLMHeaders = redactHeaderValues(c.LLMHeaders)
	return redacted
}

func LoadConfig() *Config {
	return LoadConfigArgs(os.Args[1:])
}

// LoadConfigArgs parses runtime flags using an invocation-local FlagSet. The
// application has several command surfaces, so package-global flag variables
// would leak state between tests and make subcommand dispatch order-sensitive.
func LoadConfigArgs(args []string) *Config {
	cfg := &Config{}
	allowedOrigins := getEnv("SRE_ALLOWED_ORIGINS", "")
	trustedProxyCIDRs := getEnv("SRE_TRUSTED_PROXY_CIDRS", "")
	includeNamespaces := getEnv("SRE_INCLUDE_NAMESPACES", "")
	excludeNamespaces := getEnv("SRE_EXCLUDE_NAMESPACES", "")
	resourceKinds := getEnv("SRE_RESOURCE_KINDS", "")
	resourceNames := getEnv("SRE_RESOURCE_NAMES", "")
	analyzers := getEnv("SRE_ANALYZERS", "")
	llmEndpointAllowlist := getEnv("LLM_ENDPOINT_ALLOWLIST", "")
	playbookAllowedActions := getEnv("SRE_PLAYBOOK_ALLOWED_ACTIONS", "")
	playbookAllowedNamespaces := getEnv("SRE_PLAYBOOK_ALLOWED_NAMESPACES", "")
	playbookAllowedKinds := getEnv("SRE_PLAYBOOK_ALLOWED_KINDS", "")
	_, playbookEnabledEnvSet := os.LookupEnv("SRE_PLAYBOOK_ENABLED")
	llmHeaders := splitCSV(getEnv("LLM_CUSTOM_HEADERS", getEnv("K8SGPT_CUSTOM_HEADERS", "")))
	headersFlagSet := false

	flags := flag.NewFlagSet("sre-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.Kubeconfig, "kubeconfig", getEnv("KUBECONFIG", ""), "Path to kubeconfig file (empty for in-cluster)")
	flags.IntVar(&cfg.Port, "port", getEnvInt("PORT", 8080), "HTTP server listen port")
	flags.IntVar(&cfg.GRPCPort, "grpc-port", getEnvInt("SRE_GRPC_PORT", 0), "Authenticated gRPC compatibility server port (0 disables)")
	flags.StringVar(&cfg.GRPCTLSCertFile, "grpc-tls-cert-file", getEnv("SRE_GRPC_TLS_CERT_FILE", ""), "PEM certificate file for optional gRPC TLS")
	flags.StringVar(&cfg.GRPCTLSKeyFile, "grpc-tls-key-file", getEnv("SRE_GRPC_TLS_KEY_FILE", ""), "PEM private key file for optional gRPC TLS")
	flags.StringVar(&cfg.GRPCTLSClientCAFile, "grpc-tls-client-ca-file", getEnv("SRE_GRPC_TLS_CLIENT_CA_FILE", ""), "PEM client CA file to require verified gRPC mTLS clients")
	flags.BoolVar(&cfg.GRPCReflection, "grpc-reflection", getEnvBool("SRE_GRPC_REFLECTION", false), "Enable authenticated gRPC server reflection")
	flags.DurationVar(&cfg.ScanInterval, "scan-interval", getEnvDuration("SCAN_INTERVAL", 2*time.Minute), "Interval between automatic cluster scans")
	flags.DurationVar(&cfg.ScanJitter, "scan-jitter", getEnvDuration("SRE_SCAN_JITTER", 0), "Maximum random delay added between automatic scans")
	flags.BoolVar(&cfg.EventDrivenScanning, "event-driven-scanning", getEnvBool("SRE_EVENT_DRIVEN_SCANNING", true), "Trigger targeted scans from Kubernetes Pod and Event changes")
	cfg.EventQueueCapacity = getEnvInt("SRE_EVENT_QUEUE_CAPACITY", scheduler.DefaultTriggerQueueCapacity)
	flags.IntVar(&cfg.EventQueueCapacity, "event-queue-capacity", cfg.EventQueueCapacity, "Maximum distinct Kubernetes event triggers queued in memory")
	cfg.EventDebounce = getEnvDuration("SRE_EVENT_DEBOUNCE", scheduler.DefaultTriggerDebounce)
	flags.DurationVar(&cfg.EventDebounce, "event-debounce", cfg.EventDebounce, "Debounce window for Kubernetes event-triggered scans")
	flags.BoolVar(&cfg.LeaderElection, "leader-election", getEnvBool("SRE_LEADER_ELECTION", false), "Use a Kubernetes Lease so only one replica scans at a time")
	flags.StringVar(&cfg.LeaderElectionNamespace, "leader-election-namespace", getEnv("SRE_LEADER_ELECTION_NAMESPACE", ""), "Namespace for the scan leader-election Lease")
	flags.StringVar(&cfg.LeaderElectionID, "leader-election-id", getEnv("SRE_LEADER_ELECTION_ID", "sre-agent"), "Name of the scan leader-election Lease")
	flags.StringVar(&cfg.LeaderElectionIdentity, "leader-election-identity", getEnv("SRE_LEADER_ELECTION_IDENTITY", ""), "Unique identity used for scan leader election (defaults to hostname)")
	flags.BoolVar(&cfg.EnableAWSEKS, "enable-aws-eks", getEnvBool("SRE_ENABLE_AWS_EKS", false), "Enable the read-only AWS/EKS health integration")
	flags.StringVar(&cfg.AWSRegion, "aws-region", getEnv("AWS_REGION", getEnv("AWS_DEFAULT_REGION", "")), "AWS region for the optional EKS integration")
	flags.StringVar(&cfg.EKSClusterName, "eks-cluster-name", getEnv("SRE_EKS_CLUSTER_NAME", ""), "Explicit EKS cluster name (otherwise derive it from kubeconfig)")
	flags.StringVar(&cfg.Namespace, "namespace", getEnv("NAMESPACE", ""), "Namespace to scan (empty for all namespaces)")
	flags.StringVar(&cfg.LLMProvider, "llm-provider", getEnv("LLM_PROVIDER", "claude"), "Triage provider: claude, codex, deepseek, harness, rule-based")
	flags.StringVar(&cfg.LLMMode, "llm-mode", getEnv("LLM_MODE", ""), "Triage provider mode, such as remote, local, rule, noop, or aws")
	flags.StringVar(&cfg.LLMWireAPI, "llm-wire-api", getEnv("LLM_WIRE_API", ""), "Triage provider wire API: chat or responses")
	flags.StringVar(&cfg.LLMAPIKey, "llm-api-key", getEnv("LLM_API_KEY", ""), "API Key for LLM provider")
	flags.StringVar(&cfg.LLMModel, "llm-model", getEnv("LLM_MODEL", ""), "Model override (e.g. claude-3-7-sonnet, gpt-4o, deepseek-chat)")
	flags.StringVar(&cfg.LLMBaseURL, "llm-base-url", getEnv("LLM_BASE_URL", ""), "Base URL override for LLM provider API")
	flags.StringVar(&llmEndpointAllowlist, "llm-endpoint-allowlist", llmEndpointAllowlist, "Comma-separated provider endpoint origins or paths explicitly allowed for outbound requests")
	flags.StringVar(&cfg.LLMOrganization, "llm-organization", getEnv("LLM_ORGANIZATION", ""), "Optional provider organization or tenant identifier")
	flags.StringVar(&cfg.LLMProxyURL, "llm-proxy-url", getEnv("LLM_PROXY_URL", ""), "Optional provider HTTP proxy URL")
	appendHeaders := func(value string) error {
		if !headersFlagSet {
			llmHeaders = nil
			headersFlagSet = true
		}
		llmHeaders = append(llmHeaders, splitCSV(value)...)
		return nil
	}
	flags.Func("llm-headers", "Custom provider request headers in key:value form; repeat or comma-separate values", appendHeaders)
	flags.Func("custom-headers", "Alias for --llm-headers", appendHeaders)
	flags.StringVar(&cfg.HarnessCommand, "harness-command", getEnv("HARNESS_COMMAND", ""), "Command path for agent harness CLI")
	flags.StringVar(&cfg.WebhookURL, "webhook-url", getEnv("WEBHOOK_URL", ""), "Webhook URL for notifications (Slack/Discord)")
	flags.StringVar(&cfg.PublicURL, "public-url", getEnv("PUBLIC_URL", "https://sre.kubebee.com"), "Public URL for web dashboard")
	cfg.APIToken = getEnv("SRE_API_TOKEN", "")
	flags.StringVar(&cfg.APIToken, "api-token", cfg.APIToken, "API token for authenticated API requests")
	cfg.RequireAPIToken = getEnvBool("SRE_REQUIRE_API_TOKEN", false)
	flags.BoolVar(&cfg.RequireAPIToken, "require-api-token", cfg.RequireAPIToken, "Require a nonblank API token before starting the HTTP server")
	flags.StringVar(&allowedOrigins, "allowed-origins", allowedOrigins, "Comma-separated browser origins allowed to call the HTTP API")
	cfg.TrustedClientIPHeader = getEnv("SRE_TRUSTED_CLIENT_IP_HEADER", "")
	flags.StringVar(&cfg.TrustedClientIPHeader, "trusted-client-ip-header", cfg.TrustedClientIPHeader, "HTTP header overwritten by a trusted ingress with the client address")
	flags.StringVar(&trustedProxyCIDRs, "trusted-proxy-cidrs", trustedProxyCIDRs, "Comma-separated CIDRs for trusted ingress proxy peers")

	cfg.MaxBodyBytes = getEnvInt64("SRE_MAX_BODY_BYTES", DefaultMaxBodyBytes)
	flags.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", cfg.MaxBodyBytes, "Maximum HTTP request body size")
	cfg.RequestsPerMinute = getEnvInt("SRE_REQUESTS_PER_MINUTE", DefaultRequestsPerMinute)
	flags.IntVar(&cfg.RequestsPerMinute, "requests-per-minute", cfg.RequestsPerMinute, "Maximum requests per client per minute")
	cfg.RequestBurst = getEnvInt("SRE_REQUEST_BURST", DefaultRequestBurst)
	flags.IntVar(&cfg.RequestBurst, "request-burst", cfg.RequestBurst, "Maximum immediate request burst per client")
	cfg.DataDir = getEnv("SRE_DATA_DIR", "")
	flags.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "Directory for durable proposal and audit state")
	flags.StringVar(&includeNamespaces, "include-namespaces", includeNamespaces, "Comma-separated namespaces included in scans")
	flags.StringVar(&excludeNamespaces, "exclude-namespaces", excludeNamespaces, "Comma-separated namespaces excluded from scans")
	flags.StringVar(&cfg.LabelSelector, "label-selector", getEnv("SRE_LABEL_SELECTOR", ""), "Kubernetes label selector for scans")
	resourceKindsValue := getEnv("SRE_RESOURCE_KINDS", "")
	flags.StringVar(&resourceKinds, "resource-kinds", resourceKindsValue, "Comma-separated resource kinds included in scans")
	resourceNamesValue := getEnv("SRE_RESOURCE_NAMES", "")
	flags.StringVar(&resourceNames, "resource-names", resourceNamesValue, "Comma-separated resource names included in scans")
	flags.StringVar(&analyzers, "analyzers", analyzers, "Comma-separated analyzer names enabled for scans")
	cfg.ScanConcurrency = getEnvInt("SRE_SCAN_CONCURRENCY", scanplan.DefaultConcurrency)
	flags.IntVar(&cfg.ScanConcurrency, "scan-concurrency", cfg.ScanConcurrency, "Maximum concurrent analyzers")
	cfg.ScanTimeout = getEnvDuration("SRE_SCAN_TIMEOUT", scanplan.DefaultScanTimeout)
	flags.DurationVar(&cfg.ScanTimeout, "scan-timeout", cfg.ScanTimeout, "Maximum duration for one scan")
	cfg.HistoryDir = getEnv("SRE_SCAN_HISTORY_DIR", "")
	flags.StringVar(&cfg.HistoryDir, "scan-history-dir", cfg.HistoryDir, "Directory for sanitized scan history")
	cfg.CacheDir = getEnv("SRE_CACHE_DIR", "")
	flags.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "Directory for the opt-in encrypted provider-result cache")
	cfg.CacheEncryptionKey = getEnv("SRE_CACHE_ENCRYPTION_KEY", "")
	cfg.CacheTTL = getEnvDuration("SRE_CACHE_TTL", DefaultCacheTTL)
	flags.DurationVar(&cfg.CacheTTL, "cache-ttl", cfg.CacheTTL, "TTL for opt-in provider-result cache entries")
	cfg.CacheMaxEntries = getEnvInt("SRE_CACHE_MAX_ENTRIES", DefaultCacheMaxEntries)
	flags.IntVar(&cfg.CacheMaxEntries, "cache-max-entries", cfg.CacheMaxEntries, "Maximum opt-in provider-result cache entries")
	cfg.CacheMaxValueBytes = getEnvInt("SRE_CACHE_MAX_VALUE_BYTES", DefaultCacheMaxValueBytes)
	flags.IntVar(&cfg.CacheMaxValueBytes, "cache-max-value-bytes", cfg.CacheMaxValueBytes, "Maximum opt-in provider-result cache value size")
	cfg.DatabaseURL = getEnv("SRE_DATABASE_URL", "")
	flags.StringVar(&cfg.DatabaseURL, "database-url", cfg.DatabaseURL, "PostgreSQL database URL for the optional playbook catalog")
	cfg.PlaybookEnabled = getEnvBoolFailClosed("SRE_PLAYBOOK_ENABLED", strings.TrimSpace(cfg.DatabaseURL) != "")
	flags.BoolVar(&cfg.PlaybookEnabled, "playbook-enabled", cfg.PlaybookEnabled, "Enable the optional PostgreSQL-backed playbook catalog")
	cfg.PlaybookLearningMode = getEnv("SRE_PLAYBOOK_LEARNING_MODE", DefaultPlaybookLearningMode)
	flags.StringVar(&cfg.PlaybookLearningMode, "playbook-learning-mode", cfg.PlaybookLearningMode, "Playbook learning mode: AUTO_DRAFT, OBSERVE_ONLY, or DISABLED")
	cfg.PlaybookMinConfidence = getEnvFloat("SRE_PLAYBOOK_MIN_CONFIDENCE", DefaultPlaybookMinConfidence)
	flags.Float64Var(&cfg.PlaybookMinConfidence, "playbook-min-confidence", cfg.PlaybookMinConfidence, "Minimum confidence required for playbook policy decisions")
	flags.StringVar(&playbookAllowedActions, "playbook-allowed-actions", playbookAllowedActions, "Comma-separated playbook action allowlist")
	flags.StringVar(&playbookAllowedNamespaces, "playbook-allowed-namespaces", playbookAllowedNamespaces, "Comma-separated playbook namespace allowlist")
	flags.StringVar(&playbookAllowedKinds, "playbook-allowed-kinds", playbookAllowedKinds, "Comma-separated playbook resource-kind allowlist")
	cfg.PlaybookMaxSourceBytes = getEnvInt("SRE_PLAYBOOK_MAX_SOURCE_BYTES", getEnvInt("SRE_PLAYBOOK_MAX_SOURCES", DefaultPlaybookMaxSourceBytes))
	flags.IntVar(&cfg.PlaybookMaxSourceBytes, "playbook-max-source-bytes", cfg.PlaybookMaxSourceBytes, "Maximum bytes per playbook source considered per operation")
	flags.IntVar(&cfg.PlaybookMaxSourceBytes, "playbook-max-sources", cfg.PlaybookMaxSourceBytes, "Deprecated alias for --playbook-max-source-bytes")
	cfg.PlaybookMaxStepCount = getEnvInt("SRE_PLAYBOOK_MAX_STEP_COUNT", getEnvInt("SRE_PLAYBOOK_MAX_STEPS", DefaultPlaybookMaxStepCount))
	flags.IntVar(&cfg.PlaybookMaxStepCount, "playbook-max-step-count", cfg.PlaybookMaxStepCount, "Maximum playbook steps considered per operation")
	flags.IntVar(&cfg.PlaybookMaxStepCount, "playbook-max-steps", cfg.PlaybookMaxStepCount, "Deprecated alias for --playbook-max-step-count")
	cfg.PlaybookMaxTotalTextBytes = getEnvInt("SRE_PLAYBOOK_MAX_TOTAL_TEXT_BYTES", DefaultPlaybookMaxTotalTextBytes)
	flags.IntVar(&cfg.PlaybookMaxTotalTextBytes, "playbook-max-total-text-bytes", cfg.PlaybookMaxTotalTextBytes, "Maximum total playbook text bytes considered per operation")

	_ = flags.Parse(args)
	playbookEnabledFlagSet := false
	flags.Visit(func(flag *flag.Flag) {
		if flag.Name == "playbook-enabled" {
			playbookEnabledFlagSet = true
		}
	})
	if !playbookEnabledEnvSet && !playbookEnabledFlagSet {
		cfg.PlaybookEnabled = strings.TrimSpace(cfg.DatabaseURL) != ""
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.RequestsPerMinute <= 0 {
		cfg.RequestsPerMinute = DefaultRequestsPerMinute
	}
	if cfg.RequestBurst <= 0 {
		cfg.RequestBurst = DefaultRequestBurst
	}
	cfg.AllowedOrigins = splitCSV(allowedOrigins)
	cfg.TrustedProxyCIDRs = splitCSV(trustedProxyCIDRs)
	cfg.IncludeNamespaces = splitCSV(includeNamespaces)
	if len(cfg.IncludeNamespaces) == 0 && strings.TrimSpace(cfg.Namespace) != "" {
		cfg.IncludeNamespaces = []string{strings.TrimSpace(cfg.Namespace)}
	}
	cfg.ExcludeNamespaces = splitCSV(excludeNamespaces)
	cfg.ResourceKinds = splitCSV(resourceKinds)
	cfg.ResourceNames = splitCSV(resourceNames)
	cfg.Analyzers = splitCSV(analyzers)
	cfg.LLMEndpointAllowlist = splitCSV(llmEndpointAllowlist)
	cfg.LLMHeaders = append([]string(nil), llmHeaders...)
	cfg.PlaybookLearningMode = normalizePlaybookLearningMode(cfg.PlaybookLearningMode)
	cfg.PlaybookAllowedActions = splitCSV(playbookAllowedActions)
	cfg.PlaybookAllowedNamespaces = splitCSV(playbookAllowedNamespaces)
	cfg.PlaybookAllowedKinds = splitCSV(playbookAllowedKinds)
	if cfg.ScanConcurrency <= 0 {
		cfg.ScanConcurrency = scanplan.DefaultConcurrency
	}
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = scanplan.DefaultScanTimeout
	}
	if cfg.EventQueueCapacity <= 0 {
		cfg.EventQueueCapacity = scheduler.DefaultTriggerQueueCapacity
	}
	if cfg.EventDebounce < 0 {
		cfg.EventDebounce = scheduler.DefaultTriggerDebounce
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	if cfg.CacheMaxEntries <= 0 {
		cfg.CacheMaxEntries = DefaultCacheMaxEntries
	}
	if cfg.CacheMaxValueBytes <= 0 {
		cfg.CacheMaxValueBytes = DefaultCacheMaxValueBytes
	}
	if cfg.ScanJitter < 0 || cfg.ScanJitter >= cfg.ScanInterval {
		cfg.ScanJitter = 0
	}
	if strings.TrimSpace(cfg.LeaderElectionID) == "" {
		cfg.LeaderElectionID = "sre-agent"
	}
	return cfg
}

func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if c.PlaybookEnabled && strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("playbook database URL is required when playbooks are enabled")
	}
	if !validPlaybookLearningMode(c.PlaybookLearningMode) {
		return fmt.Errorf("invalid playbook learning mode %q", c.PlaybookLearningMode)
	}
	if !finiteConfidence(c.PlaybookMinConfidence) {
		return fmt.Errorf("playbook confidence must be between 0 and 1")
	}
	if err := validatePlaybookPolicyList("playbook allowed actions", c.PlaybookAllowedActions); err != nil {
		return err
	}
	if err := validatePlaybookPolicyList("playbook allowed namespaces", c.PlaybookAllowedNamespaces); err != nil {
		return err
	}
	if err := validatePlaybookPolicyList("playbook allowed kinds", c.PlaybookAllowedKinds); err != nil {
		return err
	}
	if c.PlaybookMaxSourceBytes <= 0 || c.PlaybookMaxSourceBytes > MaxPlaybookSourceBytes {
		return fmt.Errorf("playbook source byte limit must be between 1 and %d", MaxPlaybookSourceBytes)
	}
	if c.PlaybookMaxStepCount <= 0 || c.PlaybookMaxStepCount > MaxPlaybookStepCount {
		return fmt.Errorf("playbook step count must be between 1 and %d", MaxPlaybookStepCount)
	}
	if c.PlaybookMaxTotalTextBytes <= 0 || c.PlaybookMaxTotalTextBytes > MaxPlaybookTotalTextBytes {
		return fmt.Errorf("playbook total text byte limit must be between 1 and %d", MaxPlaybookTotalTextBytes)
	}
	return nil
}

func (c *Config) ScanPlan() scanplan.Plan {
	if c == nil {
		return scanplan.Default()
	}
	return scanplan.Plan{
		SchemaVersion:     scanplan.SchemaVersion,
		IncludeNamespaces: append([]string(nil), c.IncludeNamespaces...),
		ExcludeNamespaces: append([]string(nil), c.ExcludeNamespaces...),
		LabelSelector:     c.LabelSelector,
		Kinds:             append([]string(nil), c.ResourceKinds...),
		Names:             append([]string(nil), c.ResourceNames...),
		Analyzers:         append([]string(nil), c.Analyzers...),
		MaxConcurrency:    c.ScanConcurrency,
		Timeout:           c.ScanTimeout,
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvInt64(key string, fallback int64) int64 {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	if parsed, err := strconv.ParseBool(strings.TrimSpace(val)); err == nil {
		return parsed
	}
	// A malformed security toggle must not silently disable protection.
	return true
}

func getEnvBoolFailClosed(key string, fallback bool) bool {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(val))
	return err == nil && parsed
}

func getEnvFloat(key string, fallback float64) float64 {
	if val := os.Getenv(key); val != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil {
			return f
		}
	}
	return fallback
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return fallback
}

func normalizePlaybookLearningMode(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return DefaultPlaybookLearningMode
	}
	return value
}

func validPlaybookLearningMode(value string) bool {
	switch normalizePlaybookLearningMode(value) {
	case "AUTO_DRAFT", "OBSERVE_ONLY", "DISABLED":
		return true
	default:
		return false
	}
}

func validatePlaybookPolicyList(name string, values []string) error {
	if len(values) > MaxPlaybookPolicyListItems {
		return fmt.Errorf("%s exceeds maximum of %d", name, MaxPlaybookPolicyListItems)
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > MaxPlaybookPolicyTextBytes || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%s contains an invalid value", name)
		}
	}
	return nil
}

func finiteConfidence(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}

func redactString(value *string) {
	if strings.TrimSpace(*value) != "" {
		*value = "<redacted>"
	}
}

func redactHeaderValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	redacted := make([]string, 0, len(values))
	for _, raw := range values {
		key, _, ok := strings.Cut(raw, ":")
		if !ok {
			redacted = append(redacted, "<redacted>")
			continue
		}
		redacted = append(redacted, strings.TrimSpace(key)+":<redacted>")
	}
	return redacted
}
