package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/kubebee-com/sre/pkg/scheduler"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	UserConfigSchemaVersion = "config/v1"
	DefaultConfigDirectory  = "sre-agent"
	DefaultConfigFileName   = "config.yaml"
)

// ProviderProfile contains non-secret provider routing settings. Credentials
// are deliberately not part of the persisted representation; APIKey is only
// a transient input for callers that need to keep one in memory.
type ProviderProfile struct {
	Name         string `json:"name" yaml:"name"`
	Provider     string `json:"provider" yaml:"provider"`
	Mode         string `json:"mode,omitempty" yaml:"mode,omitempty"`
	WireAPI      string `json:"wire_api,omitempty" yaml:"wire_api,omitempty"`
	Model        string `json:"model,omitempty" yaml:"model,omitempty"`
	BaseURL      string `json:"base_url,omitempty" yaml:"base_url,omitempty"`
	Organization string `json:"organization,omitempty" yaml:"organization,omitempty"`
	ProxyURL     string `json:"proxy_url,omitempty" yaml:"proxy_url,omitempty"`
	APIKey       string `json:"-" yaml:"-"`
}

// AnalyzerFilter is a named, reusable scan scope. It contains no credential
// material and maps directly to scanplan.Plan fields.
type AnalyzerFilter struct {
	Name              string   `json:"name" yaml:"name"`
	IncludeNamespaces []string `json:"include_namespaces,omitempty" yaml:"include_namespaces,omitempty"`
	ExcludeNamespaces []string `json:"exclude_namespaces,omitempty" yaml:"exclude_namespaces,omitempty"`
	LabelSelector     string   `json:"label_selector,omitempty" yaml:"label_selector,omitempty"`
	Kinds             []string `json:"kinds,omitempty" yaml:"kinds,omitempty"`
	Names             []string `json:"names,omitempty" yaml:"names,omitempty"`
	Analyzers         []string `json:"analyzers,omitempty" yaml:"analyzers,omitempty"`
}

func (f AnalyzerFilter) Plan() scanplan.Plan {
	return scanplan.Plan{
		SchemaVersion:     scanplan.SchemaVersion,
		IncludeNamespaces: append([]string(nil), f.IncludeNamespaces...),
		ExcludeNamespaces: append([]string(nil), f.ExcludeNamespaces...),
		LabelSelector:     f.LabelSelector,
		Kinds:             append([]string(nil), f.Kinds...),
		Names:             append([]string(nil), f.Names...),
		Analyzers:         append([]string(nil), f.Analyzers...),
		MaxConcurrency:    scanplan.DefaultConcurrency,
		Timeout:           scanplan.DefaultScanTimeout,
	}
}

// UserSettings is the safe subset of runtime configuration that can be
// persisted. API tokens, LLM keys, and webhook URLs are intentionally absent.
type UserSettings struct {
	EventDrivenScanning       *bool    `json:"event_driven_scanning,omitempty" yaml:"event_driven_scanning,omitempty"`
	EventQueueCapacity        int      `json:"event_queue_capacity,omitempty" yaml:"event_queue_capacity,omitempty"`
	EventDebounce             string   `json:"event_debounce,omitempty" yaml:"event_debounce,omitempty"`
	LLMEndpointAllowlist      []string `json:"llm_endpoint_allowlist,omitempty" yaml:"llm_endpoint_allowlist,omitempty"`
	Kubeconfig                string   `json:"kubeconfig,omitempty" yaml:"kubeconfig,omitempty"`
	Port                      int      `json:"port,omitempty" yaml:"port,omitempty"`
	GRPCPort                  int      `json:"grpc_port,omitempty" yaml:"grpc_port,omitempty"`
	GRPCTLSCertFile           string   `json:"grpc_tls_cert_file,omitempty" yaml:"grpc_tls_cert_file,omitempty"`
	GRPCTLSKeyFile            string   `json:"grpc_tls_key_file,omitempty" yaml:"grpc_tls_key_file,omitempty"`
	GRPCTLSClientCAFile       string   `json:"grpc_tls_client_ca_file,omitempty" yaml:"grpc_tls_client_ca_file,omitempty"`
	GRPCReflection            bool     `json:"grpc_reflection,omitempty" yaml:"grpc_reflection,omitempty"`
	ScanInterval              string   `json:"scan_interval,omitempty" yaml:"scan_interval,omitempty"`
	ScanJitter                string   `json:"scan_jitter,omitempty" yaml:"scan_jitter,omitempty"`
	LeaderElection            bool     `json:"leader_election,omitempty" yaml:"leader_election,omitempty"`
	LeaderElectionNamespace   string   `json:"leader_election_namespace,omitempty" yaml:"leader_election_namespace,omitempty"`
	LeaderElectionID          string   `json:"leader_election_id,omitempty" yaml:"leader_election_id,omitempty"`
	LeaderElectionIdentity    string   `json:"leader_election_identity,omitempty" yaml:"leader_election_identity,omitempty"`
	EnableAWSEKS              bool     `json:"enable_aws_eks,omitempty" yaml:"enable_aws_eks,omitempty"`
	AWSRegion                 string   `json:"aws_region,omitempty" yaml:"aws_region,omitempty"`
	EKSClusterName            string   `json:"eks_cluster_name,omitempty" yaml:"eks_cluster_name,omitempty"`
	Namespace                 string   `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	LLMProvider               string   `json:"llm_provider,omitempty" yaml:"llm_provider,omitempty"`
	LLMMode                   string   `json:"llm_mode,omitempty" yaml:"llm_mode,omitempty"`
	LLMWireAPI                string   `json:"llm_wire_api,omitempty" yaml:"llm_wire_api,omitempty"`
	LLMModel                  string   `json:"llm_model,omitempty" yaml:"llm_model,omitempty"`
	LLMBaseURL                string   `json:"llm_base_url,omitempty" yaml:"llm_base_url,omitempty"`
	LLMOrganization           string   `json:"llm_organization,omitempty" yaml:"llm_organization,omitempty"`
	LLMProxyURL               string   `json:"llm_proxy_url,omitempty" yaml:"llm_proxy_url,omitempty"`
	HarnessCommand            string   `json:"harness_command,omitempty" yaml:"harness_command,omitempty"`
	PublicURL                 string   `json:"public_url,omitempty" yaml:"public_url,omitempty"`
	RequireAPIToken           bool     `json:"require_api_token,omitempty" yaml:"require_api_token,omitempty"`
	AllowedOrigins            []string `json:"allowed_origins,omitempty" yaml:"allowed_origins,omitempty"`
	TrustedClientIPHeader     string   `json:"trusted_client_ip_header,omitempty" yaml:"trusted_client_ip_header,omitempty"`
	TrustedProxyCIDRs         []string `json:"trusted_proxy_cidrs,omitempty" yaml:"trusted_proxy_cidrs,omitempty"`
	MaxBodyBytes              int64    `json:"max_body_bytes,omitempty" yaml:"max_body_bytes,omitempty"`
	RequestsPerMinute         int      `json:"requests_per_minute,omitempty" yaml:"requests_per_minute,omitempty"`
	RequestBurst              int      `json:"request_burst,omitempty" yaml:"request_burst,omitempty"`
	DataDir                   string   `json:"data_dir,omitempty" yaml:"data_dir,omitempty"`
	IncludeNamespaces         []string `json:"include_namespaces,omitempty" yaml:"include_namespaces,omitempty"`
	ExcludeNamespaces         []string `json:"exclude_namespaces,omitempty" yaml:"exclude_namespaces,omitempty"`
	LabelSelector             string   `json:"label_selector,omitempty" yaml:"label_selector,omitempty"`
	ResourceKinds             []string `json:"resource_kinds,omitempty" yaml:"resource_kinds,omitempty"`
	ResourceNames             []string `json:"resource_names,omitempty" yaml:"resource_names,omitempty"`
	Analyzers                 []string `json:"analyzers,omitempty" yaml:"analyzers,omitempty"`
	ScanConcurrency           int      `json:"scan_concurrency,omitempty" yaml:"scan_concurrency,omitempty"`
	ScanTimeout               string   `json:"scan_timeout,omitempty" yaml:"scan_timeout,omitempty"`
	HistoryDir                string   `json:"history_dir,omitempty" yaml:"history_dir,omitempty"`
	CacheDir                  string   `json:"cache_dir,omitempty" yaml:"cache_dir,omitempty"`
	CacheTTL                  string   `json:"cache_ttl,omitempty" yaml:"cache_ttl,omitempty"`
	CacheMaxEntries           int      `json:"cache_max_entries,omitempty" yaml:"cache_max_entries,omitempty"`
	CacheMaxValueBytes        int      `json:"cache_max_value_bytes,omitempty" yaml:"cache_max_value_bytes,omitempty"`
	PlaybookEnabled           *bool    `json:"playbook_enabled,omitempty" yaml:"playbook_enabled,omitempty"`
	PlaybookLearningMode      string   `json:"playbook_learning_mode,omitempty" yaml:"playbook_learning_mode,omitempty"`
	PlaybookMinConfidence     *float64 `json:"playbook_min_confidence,omitempty" yaml:"playbook_min_confidence,omitempty"`
	PlaybookAllowedActions    []string `json:"playbook_allowed_actions,omitempty" yaml:"playbook_allowed_actions,omitempty"`
	PlaybookAllowedNamespaces []string `json:"playbook_allowed_namespaces,omitempty" yaml:"playbook_allowed_namespaces,omitempty"`
	PlaybookAllowedKinds      []string `json:"playbook_allowed_kinds,omitempty" yaml:"playbook_allowed_kinds,omitempty"`
	PlaybookMaxSourceBytes    *int     `json:"playbook_max_source_bytes,omitempty" yaml:"playbook_max_source_bytes,omitempty"`
	PlaybookMaxStepCount      *int     `json:"playbook_max_step_count,omitempty" yaml:"playbook_max_step_count,omitempty"`
	PlaybookMaxTotalTextBytes *int     `json:"playbook_max_total_text_bytes,omitempty" yaml:"playbook_max_total_text_bytes,omitempty"`
}

// UserConfig is the versioned on-disk configuration contract.
type UserConfig struct {
	SchemaVersion  string            `json:"schema_version" yaml:"schema_version"`
	DefaultProfile string            `json:"default_profile,omitempty" yaml:"default_profile,omitempty"`
	DefaultFilter  string            `json:"default_filter,omitempty" yaml:"default_filter,omitempty"`
	Profiles       []ProviderProfile `json:"profiles,omitempty" yaml:"profiles,omitempty"`
	Filters        []AnalyzerFilter  `json:"filters,omitempty" yaml:"filters,omitempty"`
	Settings       UserSettings      `json:"settings,omitempty" yaml:"settings,omitempty"`
}

func NewUserConfig() UserConfig {
	return UserConfig{SchemaVersion: UserConfigSchemaVersion}
}

func DefaultPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(directory, DefaultConfigDirectory, DefaultConfigFileName), nil
}

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}
	return &Store{path: filepath.Clean(path)}, nil
}

func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func LoadUserConfig(path string) (UserConfig, error) {
	store, err := NewStore(path)
	if err != nil {
		return UserConfig{}, err
	}
	return store.Load()
}

func SaveUserConfig(path string, cfg UserConfig) error {
	store, err := NewStore(path)
	if err != nil {
		return err
	}
	return store.Save(cfg)
}

func (s *Store) Load() (UserConfig, error) {
	if s == nil {
		return UserConfig{}, errors.New("config store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) Save(cfg UserConfig) error {
	if s == nil {
		return errors.New("config store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(cfg)
}

func (s *Store) loadLocked() (UserConfig, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return NewUserConfig(), nil
	}
	if err != nil {
		return UserConfig{}, fmt.Errorf("read config %q: %w", s.path, err)
	}
	if err := os.Chmod(s.path, 0600); err != nil {
		return UserConfig{}, fmt.Errorf("secure config %q: %w", s.path, err)
	}

	var envelope struct {
		SchemaVersion string `yaml:"schema_version" json:"schema_version"`
	}
	if err := yaml.Unmarshal(data, &envelope); err != nil {
		return UserConfig{}, errors.New("parse user config")
	}
	if envelope.SchemaVersion == UserConfigSchemaVersion {
		var cfg UserConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return UserConfig{}, errors.New("parse versioned user config")
		}
		if err := cfg.normalize(); err != nil {
			return UserConfig{}, err
		}
		return cfg, nil
	}
	if envelope.SchemaVersion != "" && !isMigratableSchema(envelope.SchemaVersion) {
		return UserConfig{}, fmt.Errorf("unsupported user config schema %q", envelope.SchemaVersion)
	}

	cfg, err := migrateLegacyConfig(data)
	if err != nil {
		return UserConfig{}, err
	}
	if err := s.saveLocked(cfg); err != nil {
		return UserConfig{}, fmt.Errorf("persist migrated config: %w", err)
	}
	return cfg, nil
}

func (s *Store) saveLocked(cfg UserConfig) error {
	if err := cfg.normalize(); err != nil {
		return err
	}
	// ProviderProfile.APIKey is intentionally omitted by its serialization
	// tags. Clear it in the copy as a second guard against future encoders.
	cfg = safeConfigCopy(cfg)

	var data []byte
	var err error
	if strings.EqualFold(filepath.Ext(s.path), ".json") {
		data, err = json.MarshalIndent(cfg, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	} else {
		data, err = yaml.Marshal(cfg)
	}
	if err != nil {
		return fmt.Errorf("encode user config: %w", err)
	}

	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(s.path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary config: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	if err := os.Chmod(s.path, 0600); err != nil {
		return fmt.Errorf("secure config: %w", err)
	}
	return nil
}

func (s *Store) CreateProfile(profile ProviderProfile) error {
	if err := profile.normalize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadLocked()
	if err != nil {
		return err
	}
	if findProfile(cfg.Profiles, profile.Name) >= 0 {
		return fmt.Errorf("provider profile %q already exists", profile.Name)
	}
	cfg.Profiles = append(cfg.Profiles, profile)
	return s.saveLocked(cfg)
}

func (s *Store) UpdateProfile(profile ProviderProfile) error {
	if err := profile.normalize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadLocked()
	if err != nil {
		return err
	}
	index := findProfile(cfg.Profiles, profile.Name)
	if index < 0 {
		return fmt.Errorf("provider profile %q not found", profile.Name)
	}
	cfg.Profiles[index] = profile
	return s.saveLocked(cfg)
}

func (s *Store) UpsertProfile(profile ProviderProfile) error {
	if err := profile.normalize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadLocked()
	if err != nil {
		return err
	}
	if index := findProfile(cfg.Profiles, profile.Name); index >= 0 {
		cfg.Profiles[index] = profile
	} else {
		cfg.Profiles = append(cfg.Profiles, profile)
	}
	return s.saveLocked(cfg)
}

func (s *Store) DeleteProfile(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("provider profile name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadLocked()
	if err != nil {
		return err
	}
	index := findProfile(cfg.Profiles, name)
	if index < 0 {
		return fmt.Errorf("provider profile %q not found", name)
	}
	cfg.Profiles = append(cfg.Profiles[:index], cfg.Profiles[index+1:]...)
	if strings.EqualFold(cfg.DefaultProfile, name) {
		cfg.DefaultProfile = ""
	}
	return s.saveLocked(cfg)
}

func (s *Store) ListProfiles() ([]ProviderProfile, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, err
	}
	profiles := append([]ProviderProfile(nil), cfg.Profiles...)
	for index := range profiles {
		profiles[index].APIKey = ""
	}
	return profiles, nil
}

func (s *Store) SetDefaultProfile(name string) error {
	return s.setDefault(name, true)
}

func (s *Store) CreateFilter(filter AnalyzerFilter) error {
	if err := filter.normalize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadLocked()
	if err != nil {
		return err
	}
	if findFilter(cfg.Filters, filter.Name) >= 0 {
		return fmt.Errorf("analyzer filter %q already exists", filter.Name)
	}
	cfg.Filters = append(cfg.Filters, filter)
	return s.saveLocked(cfg)
}

func (s *Store) UpdateFilter(filter AnalyzerFilter) error {
	if err := filter.normalize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadLocked()
	if err != nil {
		return err
	}
	index := findFilter(cfg.Filters, filter.Name)
	if index < 0 {
		return fmt.Errorf("analyzer filter %q not found", filter.Name)
	}
	cfg.Filters[index] = filter
	return s.saveLocked(cfg)
}

func (s *Store) UpsertFilter(filter AnalyzerFilter) error {
	if err := filter.normalize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadLocked()
	if err != nil {
		return err
	}
	if index := findFilter(cfg.Filters, filter.Name); index >= 0 {
		cfg.Filters[index] = filter
	} else {
		cfg.Filters = append(cfg.Filters, filter)
	}
	return s.saveLocked(cfg)
}

func (s *Store) DeleteFilter(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("analyzer filter name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadLocked()
	if err != nil {
		return err
	}
	index := findFilter(cfg.Filters, name)
	if index < 0 {
		return fmt.Errorf("analyzer filter %q not found", name)
	}
	cfg.Filters = append(cfg.Filters[:index], cfg.Filters[index+1:]...)
	if strings.EqualFold(cfg.DefaultFilter, name) {
		cfg.DefaultFilter = ""
	}
	return s.saveLocked(cfg)
}

func (s *Store) ListFilters() ([]AnalyzerFilter, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, err
	}
	return append([]AnalyzerFilter(nil), cfg.Filters...), nil
}

func (s *Store) SetDefaultFilter(name string) error {
	return s.setDefault(name, false)
}

func (s *Store) setDefault(name string, profile bool) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("default name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadLocked()
	if err != nil {
		return err
	}
	if profile {
		if findProfile(cfg.Profiles, name) < 0 {
			return fmt.Errorf("provider profile %q not found", name)
		}
		cfg.DefaultProfile = cfg.Profiles[findProfile(cfg.Profiles, name)].Name
	} else {
		if findFilter(cfg.Filters, name) < 0 {
			return fmt.Errorf("analyzer filter %q not found", name)
		}
		cfg.DefaultFilter = cfg.Filters[findFilter(cfg.Filters, name)].Name
	}
	return s.saveLocked(cfg)
}

type ResolveOptions struct {
	Path        string
	Environment map[string]string
	Flags       map[string]string
	FilterName  string
}

// ResolveConfig applies flags over environment over the safe user config.
// Credentials are read only from flags/environment and are never sourced from
// or written to UserConfig.
func ResolveConfig(options ResolveOptions) (*Config, UserConfig, error) {
	store, err := NewStore(options.Path)
	if err != nil {
		return nil, UserConfig{}, err
	}
	userConfig, err := store.Load()
	if err != nil {
		return nil, UserConfig{}, err
	}
	environment := options.Environment
	if environment == nil {
		environment = currentEnvironment()
	}
	flags := options.Flags

	settings := userConfig.Settings
	if profile := selectedProfile(userConfig, ""); profile != nil {
		if profile.Provider != "" {
			settings.LLMProvider = profile.Provider
		}
		if profile.Mode != "" {
			settings.LLMMode = profile.Mode
		}
		if profile.WireAPI != "" {
			settings.LLMWireAPI = profile.WireAPI
		}
		if profile.Model != "" {
			settings.LLMModel = profile.Model
		}
		if profile.BaseURL != "" {
			settings.LLMBaseURL = profile.BaseURL
		}
		if profile.Organization != "" {
			settings.LLMOrganization = profile.Organization
		}
		if profile.ProxyURL != "" {
			settings.LLMProxyURL = profile.ProxyURL
		}
	}
	filterName := strings.TrimSpace(options.FilterName)
	if filterName == "" {
		filterName = userConfig.DefaultFilter
	}
	if filter := findNamedFilter(userConfig.Filters, filterName); filter != nil {
		if len(settings.IncludeNamespaces) == 0 {
			settings.IncludeNamespaces = append([]string(nil), filter.IncludeNamespaces...)
		}
		if len(settings.ExcludeNamespaces) == 0 {
			settings.ExcludeNamespaces = append([]string(nil), filter.ExcludeNamespaces...)
		}
		if settings.LabelSelector == "" {
			settings.LabelSelector = filter.LabelSelector
		}
		if len(settings.ResourceKinds) == 0 {
			settings.ResourceKinds = append([]string(nil), filter.Kinds...)
		}
		if len(settings.ResourceNames) == 0 {
			settings.ResourceNames = append([]string(nil), filter.Names...)
		}
		if len(settings.Analyzers) == 0 {
			settings.Analyzers = append([]string(nil), filter.Analyzers...)
		}
	}

	cfg := &Config{
		EventDrivenScanning:       true,
		EventQueueCapacity:        scheduler.DefaultTriggerQueueCapacity,
		EventDebounce:             scheduler.DefaultTriggerDebounce,
		Port:                      8080,
		ScanInterval:              defaultScanInterval,
		LLMProvider:               "claude",
		PublicURL:                 "https://sre.kubebee.com",
		MaxBodyBytes:              DefaultMaxBodyBytes,
		RequestsPerMinute:         DefaultRequestsPerMinute,
		RequestBurst:              DefaultRequestBurst,
		ScanConcurrency:           scanplan.DefaultConcurrency,
		ScanTimeout:               scanplan.DefaultScanTimeout,
		CacheTTL:                  DefaultCacheTTL,
		CacheMaxEntries:           DefaultCacheMaxEntries,
		CacheMaxValueBytes:        DefaultCacheMaxValueBytes,
		PlaybookLearningMode:      DefaultPlaybookLearningMode,
		PlaybookMinConfidence:     DefaultPlaybookMinConfidence,
		PlaybookMaxSourceBytes:    DefaultPlaybookMaxSourceBytes,
		PlaybookMaxStepCount:      DefaultPlaybookMaxStepCount,
		PlaybookMaxTotalTextBytes: DefaultPlaybookMaxTotalTextBytes,
	}
	stringValue(&cfg.DatabaseURL, "database-url", "", flags, environment, "SRE_DATABASE_URL")
	if err := boolPointerValue(&cfg.PlaybookEnabled, "playbook-enabled", settings.PlaybookEnabled, strings.TrimSpace(cfg.DatabaseURL) != "", flags, environment, "SRE_PLAYBOOK_ENABLED"); err != nil {
		return nil, UserConfig{}, err
	}
	stringValue(&cfg.Kubeconfig, "kubeconfig", settings.Kubeconfig, flags, environment, "KUBECONFIG")
	if err := intValue(&cfg.Port, "port", settings.Port, flags, environment, "PORT"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := intValue(&cfg.GRPCPort, "grpc-port", settings.GRPCPort, flags, environment, "SRE_GRPC_PORT"); err != nil {
		return nil, UserConfig{}, err
	}
	stringValue(&cfg.GRPCTLSCertFile, "grpc-tls-cert-file", settings.GRPCTLSCertFile, flags, environment, "SRE_GRPC_TLS_CERT_FILE")
	stringValue(&cfg.GRPCTLSKeyFile, "grpc-tls-key-file", settings.GRPCTLSKeyFile, flags, environment, "SRE_GRPC_TLS_KEY_FILE")
	stringValue(&cfg.GRPCTLSClientCAFile, "grpc-tls-client-ca-file", settings.GRPCTLSClientCAFile, flags, environment, "SRE_GRPC_TLS_CLIENT_CA_FILE")
	if err := boolValue(&cfg.GRPCReflection, "grpc-reflection", settings.GRPCReflection, flags, environment, "SRE_GRPC_REFLECTION"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := durationValue(&cfg.ScanInterval, "scan-interval", settings.ScanInterval, flags, environment, "SCAN_INTERVAL"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := durationValue(&cfg.ScanJitter, "scan-jitter", settings.ScanJitter, flags, environment, "SRE_SCAN_JITTER"); err != nil {
		return nil, UserConfig{}, err
	}
	eventDrivenDefault := true
	if settings.EventDrivenScanning != nil {
		eventDrivenDefault = *settings.EventDrivenScanning
	}
	if err := boolValue(&cfg.EventDrivenScanning, "event-driven-scanning", eventDrivenDefault, flags, environment, "SRE_EVENT_DRIVEN_SCANNING"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := intValue(&cfg.EventQueueCapacity, "event-queue-capacity", settings.EventQueueCapacity, flags, environment, "SRE_EVENT_QUEUE_CAPACITY"); err != nil {
		return nil, UserConfig{}, err
	}
	eventDebounceDefault := settings.EventDebounce
	if strings.TrimSpace(eventDebounceDefault) == "" {
		eventDebounceDefault = scheduler.DefaultTriggerDebounce.String()
	}
	if err := durationValue(&cfg.EventDebounce, "event-debounce", eventDebounceDefault, flags, environment, "SRE_EVENT_DEBOUNCE"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := boolValue(&cfg.LeaderElection, "leader-election", settings.LeaderElection, flags, environment, "SRE_LEADER_ELECTION"); err != nil {
		return nil, UserConfig{}, err
	}
	stringValue(&cfg.LeaderElectionNamespace, "leader-election-namespace", settings.LeaderElectionNamespace, flags, environment, "SRE_LEADER_ELECTION_NAMESPACE")
	stringValue(&cfg.LeaderElectionID, "leader-election-id", settings.LeaderElectionID, flags, environment, "SRE_LEADER_ELECTION_ID")
	stringValue(&cfg.LeaderElectionIdentity, "leader-election-identity", settings.LeaderElectionIdentity, flags, environment, "SRE_LEADER_ELECTION_IDENTITY")
	if err := boolValue(&cfg.EnableAWSEKS, "enable-aws-eks", settings.EnableAWSEKS, flags, environment, "SRE_ENABLE_AWS_EKS"); err != nil {
		return nil, UserConfig{}, err
	}
	stringValue(&cfg.AWSRegion, "aws-region", settings.AWSRegion, flags, environment, "AWS_REGION", "AWS_DEFAULT_REGION")
	stringValue(&cfg.EKSClusterName, "eks-cluster-name", settings.EKSClusterName, flags, environment, "SRE_EKS_CLUSTER_NAME")
	stringValue(&cfg.Namespace, "namespace", settings.Namespace, flags, environment, "NAMESPACE")
	stringValue(&cfg.LLMProvider, "llm-provider", settings.LLMProvider, flags, environment, "LLM_PROVIDER")
	stringValue(&cfg.LLMMode, "llm-mode", settings.LLMMode, flags, environment, "LLM_MODE")
	stringValue(&cfg.LLMWireAPI, "llm-wire-api", settings.LLMWireAPI, flags, environment, "LLM_WIRE_API")
	stringValue(&cfg.LLMModel, "llm-model", settings.LLMModel, flags, environment, "LLM_MODEL")
	stringValue(&cfg.LLMBaseURL, "llm-base-url", settings.LLMBaseURL, flags, environment, "LLM_BASE_URL")
	cfg.LLMEndpointAllowlist = listValue(settings.LLMEndpointAllowlist, flags, environment, "llm-endpoint-allowlist", "LLM_ENDPOINT_ALLOWLIST")
	stringValue(&cfg.LLMOrganization, "llm-organization", settings.LLMOrganization, flags, environment, "LLM_ORGANIZATION")
	stringValue(&cfg.LLMProxyURL, "llm-proxy-url", settings.LLMProxyURL, flags, environment, "LLM_PROXY_URL")
	cfg.LLMHeaders = transientHeaderValues(flags, environment)
	stringValue(&cfg.HarnessCommand, "harness-command", settings.HarnessCommand, flags, environment, "HARNESS_COMMAND")
	stringValue(&cfg.PublicURL, "public-url", settings.PublicURL, flags, environment, "PUBLIC_URL")
	stringValue(&cfg.APIToken, "api-token", "", flags, environment, "SRE_API_TOKEN", "API_TOKEN")
	stringValue(&cfg.LLMAPIKey, "llm-api-key", "", flags, environment, "LLM_API_KEY", "SRE_LLM_API_KEY")
	stringValue(&cfg.WebhookURL, "webhook-url", "", flags, environment, "WEBHOOK_URL")
	if err := boolValue(&cfg.RequireAPIToken, "require-api-token", settings.RequireAPIToken, flags, environment, "SRE_REQUIRE_API_TOKEN"); err != nil {
		return nil, UserConfig{}, err
	}
	cfg.AllowedOrigins = listValue(settings.AllowedOrigins, flags, environment, "allowed-origins", "SRE_ALLOWED_ORIGINS")
	stringValue(&cfg.TrustedClientIPHeader, "trusted-client-ip-header", settings.TrustedClientIPHeader, flags, environment, "SRE_TRUSTED_CLIENT_IP_HEADER")
	cfg.TrustedProxyCIDRs = listValue(settings.TrustedProxyCIDRs, flags, environment, "trusted-proxy-cidrs", "SRE_TRUSTED_PROXY_CIDRS")
	if err := int64Value(&cfg.MaxBodyBytes, "max-body-bytes", settings.MaxBodyBytes, flags, environment, "SRE_MAX_BODY_BYTES"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := intValue(&cfg.RequestsPerMinute, "requests-per-minute", settings.RequestsPerMinute, flags, environment, "SRE_REQUESTS_PER_MINUTE"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := intValue(&cfg.RequestBurst, "request-burst", settings.RequestBurst, flags, environment, "SRE_REQUEST_BURST"); err != nil {
		return nil, UserConfig{}, err
	}
	stringValue(&cfg.DataDir, "data-dir", settings.DataDir, flags, environment, "SRE_DATA_DIR")
	cfg.IncludeNamespaces = listValue(settings.IncludeNamespaces, flags, environment, "include-namespaces", "SRE_INCLUDE_NAMESPACES")
	cfg.ExcludeNamespaces = listValue(settings.ExcludeNamespaces, flags, environment, "exclude-namespaces", "SRE_EXCLUDE_NAMESPACES")
	stringValue(&cfg.LabelSelector, "label-selector", settings.LabelSelector, flags, environment, "SRE_LABEL_SELECTOR")
	cfg.ResourceKinds = listValue(settings.ResourceKinds, flags, environment, "resource-kinds", "SRE_RESOURCE_KINDS")
	cfg.ResourceNames = listValue(settings.ResourceNames, flags, environment, "resource-names", "SRE_RESOURCE_NAMES")
	cfg.Analyzers = listValue(settings.Analyzers, flags, environment, "analyzers", "SRE_ANALYZERS")
	if err := intValue(&cfg.ScanConcurrency, "scan-concurrency", settings.ScanConcurrency, flags, environment, "SRE_SCAN_CONCURRENCY"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := durationValue(&cfg.ScanTimeout, "scan-timeout", settings.ScanTimeout, flags, environment, "SRE_SCAN_TIMEOUT"); err != nil {
		return nil, UserConfig{}, err
	}
	stringValue(&cfg.HistoryDir, "scan-history-dir", settings.HistoryDir, flags, environment, "SRE_SCAN_HISTORY_DIR")
	stringValue(&cfg.CacheDir, "cache-dir", settings.CacheDir, flags, environment, "SRE_CACHE_DIR")
	if value, ok := firstMapValue(environment, "SRE_CACHE_ENCRYPTION_KEY"); ok {
		cfg.CacheEncryptionKey = value
	}
	if err := durationValue(&cfg.CacheTTL, "cache-ttl", settings.CacheTTL, flags, environment, "SRE_CACHE_TTL"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := intValue(&cfg.CacheMaxEntries, "cache-max-entries", settings.CacheMaxEntries, flags, environment, "SRE_CACHE_MAX_ENTRIES"); err != nil {
		return nil, UserConfig{}, err
	}
	if err := intValue(&cfg.CacheMaxValueBytes, "cache-max-value-bytes", settings.CacheMaxValueBytes, flags, environment, "SRE_CACHE_MAX_VALUE_BYTES"); err != nil {
		return nil, UserConfig{}, err
	}
	stringValue(&cfg.PlaybookLearningMode, "playbook-learning-mode", settings.PlaybookLearningMode, flags, environment, "SRE_PLAYBOOK_LEARNING_MODE")
	if err := optionalFloatValue(&cfg.PlaybookMinConfidence, "playbook-min-confidence", settings.PlaybookMinConfidence, DefaultPlaybookMinConfidence, flags, environment, "SRE_PLAYBOOK_MIN_CONFIDENCE"); err != nil {
		return nil, UserConfig{}, err
	}
	cfg.PlaybookAllowedActions = normalizeList(listValue(settings.PlaybookAllowedActions, flags, environment, "playbook-allowed-actions", "SRE_PLAYBOOK_ALLOWED_ACTIONS"))
	cfg.PlaybookAllowedNamespaces = normalizeList(listValue(settings.PlaybookAllowedNamespaces, flags, environment, "playbook-allowed-namespaces", "SRE_PLAYBOOK_ALLOWED_NAMESPACES"))
	cfg.PlaybookAllowedKinds = normalizeList(listValue(settings.PlaybookAllowedKinds, flags, environment, "playbook-allowed-kinds", "SRE_PLAYBOOK_ALLOWED_KINDS"))
	if err := optionalIntValue(&cfg.PlaybookMaxSourceBytes, "playbook-max-source-bytes", settings.PlaybookMaxSourceBytes, DefaultPlaybookMaxSourceBytes, flags, environment,
		[]string{"playbook-max-source-bytes", "playbook-max-sources"}, []string{"SRE_PLAYBOOK_MAX_SOURCE_BYTES", "SRE_PLAYBOOK_MAX_SOURCES"}); err != nil {
		return nil, UserConfig{}, err
	}
	if err := optionalIntValue(&cfg.PlaybookMaxStepCount, "playbook-max-step-count", settings.PlaybookMaxStepCount, DefaultPlaybookMaxStepCount, flags, environment,
		[]string{"playbook-max-step-count", "playbook-max-steps"}, []string{"SRE_PLAYBOOK_MAX_STEP_COUNT", "SRE_PLAYBOOK_MAX_STEPS"}); err != nil {
		return nil, UserConfig{}, err
	}
	if err := optionalIntValue(&cfg.PlaybookMaxTotalTextBytes, "playbook-max-total-text-bytes", settings.PlaybookMaxTotalTextBytes, DefaultPlaybookMaxTotalTextBytes, flags, environment,
		[]string{"playbook-max-total-text-bytes"}, []string{"SRE_PLAYBOOK_MAX_TOTAL_TEXT_BYTES"}); err != nil {
		return nil, UserConfig{}, err
	}
	if len(cfg.IncludeNamespaces) == 0 && strings.TrimSpace(cfg.Namespace) != "" {
		cfg.IncludeNamespaces = []string{strings.TrimSpace(cfg.Namespace)}
	}
	if cfg.Port <= 0 {
		cfg.Port = 8080
	}
	if cfg.ScanInterval <= 0 {
		cfg.ScanInterval = defaultScanInterval
	}
	if cfg.ScanJitter < 0 || cfg.ScanJitter >= cfg.ScanInterval {
		cfg.ScanJitter = 0
	}
	if cfg.EventQueueCapacity <= 0 {
		cfg.EventQueueCapacity = scheduler.DefaultTriggerQueueCapacity
	}
	if cfg.EventDebounce < 0 {
		cfg.EventDebounce = scheduler.DefaultTriggerDebounce
	}
	if strings.TrimSpace(cfg.LeaderElectionID) == "" {
		cfg.LeaderElectionID = "sre-agent"
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
	if cfg.ScanConcurrency <= 0 {
		cfg.ScanConcurrency = scanplan.DefaultConcurrency
	}
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = scanplan.DefaultScanTimeout
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
	cfg.PlaybookLearningMode = normalizePlaybookLearningMode(cfg.PlaybookLearningMode)
	if err := cfg.Validate(); err != nil {
		return nil, UserConfig{}, err
	}
	return cfg, userConfig, nil
}

const defaultScanInterval = 2 * 60 * 1000000000

func currentEnvironment() map[string]string {
	values := make(map[string]string)
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			values[key] = value
		}
	}
	return values
}

func stringValue(destination *string, flagKey, fileValue string, flags, environment map[string]string, environmentKeys ...string) {
	if value, ok := firstMapValue(flags, flagKey); ok {
		*destination = value
		return
	}
	if value, ok := firstMapValue(environment, environmentKeys...); ok {
		*destination = value
		return
	}
	*destination = fileValue
}

func listValue(fileValue []string, flags, environment map[string]string, flagKey, environmentKey string) []string {
	if value, ok := firstMapValue(flags, flagKey); ok {
		return splitCSV(value)
	}
	if value, ok := firstMapValue(environment, environmentKey); ok {
		return splitCSV(value)
	}
	return append([]string(nil), fileValue...)
}

func transientHeaderValues(flags, environment map[string]string) []string {
	if value, ok := firstMapValue(flags, "llm-headers"); ok {
		return splitCSV(value)
	}
	if value, ok := firstMapValue(environment, "LLM_CUSTOM_HEADERS", "K8SGPT_CUSTOM_HEADERS"); ok {
		return splitCSV(value)
	}
	return nil
}

func intValue(destination *int, key string, fileValue int, flags, environment map[string]string, environmentKey string) error {
	value, source := precedenceValue(flags, environment, key, environmentKey, strconv.Itoa(fileValue))
	if value == "" {
		*destination = 0
		return nil
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("invalid %s value from %s", key, source)
	}
	*destination = parsed
	return nil
}

func optionalIntValue(destination *int, key string, fileValue *int, fallback int, flags, environment map[string]string, flagKeys, environmentKeys []string) error {
	value, source := "", "user config"
	if raw, ok := firstMapValue(flags, flagKeys...); ok {
		value, source = raw, "flag"
	} else if raw, ok := firstMapValue(environment, environmentKeys...); ok {
		value, source = raw, "environment"
	} else if fileValue != nil {
		value = strconv.Itoa(*fileValue)
	} else {
		value = strconv.Itoa(fallback)
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("invalid %s value from %s", key, source)
	}
	*destination = parsed
	return nil
}

func int64Value(destination *int64, key string, fileValue int64, flags, environment map[string]string, environmentKey string) error {
	value, source := precedenceValue(flags, environment, key, environmentKey, strconv.FormatInt(fileValue, 10))
	if value == "" {
		*destination = 0
		return nil
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid %s value from %s", key, source)
	}
	*destination = parsed
	return nil
}

func durationValue(destination *time.Duration, key, fileValue string, flags, environment map[string]string, environmentKey string) error {
	value, source := precedenceValue(flags, environment, key, environmentKey, fileValue)
	if value == "" {
		*destination = 0
		return nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("invalid %s value from %s", key, source)
	}
	*destination = parsed
	return nil
}

func boolValue(destination *bool, key string, fileValue bool, flags, environment map[string]string, environmentKey string) error {
	value, source := precedenceValue(flags, environment, key, environmentKey, strconv.FormatBool(fileValue))
	if value == "" {
		*destination = false
		return nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		if key == "require-api-token" {
			*destination = true
			return nil
		}
		return fmt.Errorf("invalid %s value from %s", key, source)
	}
	*destination = parsed
	return nil
}

func boolPointerValue(destination *bool, key string, fileValue *bool, fallback bool, flags, environment map[string]string, environmentKey string) error {
	if value, ok := firstMapValue(flags, key); ok {
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("invalid %s value from flag", key)
		}
		*destination = parsed
		return nil
	}
	if value, ok := firstMapValue(environment, environmentKey); ok {
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("invalid %s value from environment", key)
		}
		*destination = parsed
		return nil
	}
	if fileValue != nil {
		*destination = *fileValue
		return nil
	}
	*destination = fallback
	return nil
}

func floatValue(destination *float64, key string, fileValue float64, flags, environment map[string]string, environmentKey string) error {
	value, source := precedenceValue(flags, environment, key, environmentKey, strconv.FormatFloat(fileValue, 'f', -1, 64))
	if value == "" {
		*destination = 0
		return nil
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return fmt.Errorf("invalid %s value from %s", key, source)
	}
	*destination = parsed
	return nil
}

func optionalFloatValue(destination *float64, key string, fileValue *float64, fallback float64, flags, environment map[string]string, environmentKey string) error {
	value, source := "", "user config"
	if raw, ok := firstMapValue(flags, key); ok {
		value, source = raw, "flag"
	} else if raw, ok := firstMapValue(environment, environmentKey); ok {
		value, source = raw, "environment"
	} else if fileValue != nil {
		value = strconv.FormatFloat(*fileValue, 'f', -1, 64)
	} else {
		value = strconv.FormatFloat(fallback, 'f', -1, 64)
	}
	if value == "" {
		*destination = 0
		return nil
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return fmt.Errorf("invalid %s value from %s", key, source)
	}
	*destination = parsed
	return nil
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func precedenceValue(flags, environment map[string]string, flagKey, environmentKey, fileValue string) (string, string) {
	if value, ok := firstMapValue(flags, flagKey); ok {
		return value, "flag"
	}
	if value, ok := firstMapValue(environment, environmentKey); ok {
		return value, "environment"
	}
	return fileValue, "user config"
}

func firstMapValue(values map[string]string, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value, true
		}
	}
	return "", false
}

func (p *ProviderProfile) normalize() error {
	if p == nil {
		return errors.New("provider profile is nil")
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Provider = strings.ToLower(strings.TrimSpace(p.Provider))
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	p.Model = strings.TrimSpace(p.Model)
	p.BaseURL = strings.TrimSpace(p.BaseURL)
	p.Organization = strings.TrimSpace(p.Organization)
	p.ProxyURL = strings.TrimSpace(p.ProxyURL)
	if p.Name == "" {
		return errors.New("provider profile name is required")
	}
	if !safeName(p.Name) {
		return fmt.Errorf("invalid provider profile name %q", p.Name)
	}
	if p.Provider == "" || !safeName(p.Provider) {
		return fmt.Errorf("invalid provider name for profile %q", p.Name)
	}
	switch p.Mode {
	case "", "remote", "local", "rule", "noop", "aws":
	default:
		return fmt.Errorf("invalid provider mode %q for profile %q", p.Mode, p.Name)
	}
	if err := validateEndpoint(p.BaseURL); err != nil {
		return fmt.Errorf("profile %q base URL: %w", p.Name, err)
	}
	if err := validateEndpoint(p.ProxyURL); err != nil {
		return fmt.Errorf("profile %q proxy URL: %w", p.Name, err)
	}
	return nil
}

func (f *AnalyzerFilter) normalize() error {
	if f == nil {
		return errors.New("analyzer filter is nil")
	}
	f.Name = strings.TrimSpace(f.Name)
	if f.Name == "" {
		return errors.New("analyzer filter name is required")
	}
	if !safeName(f.Name) {
		return fmt.Errorf("invalid analyzer filter name %q", f.Name)
	}
	f.IncludeNamespaces = normalizeList(f.IncludeNamespaces)
	f.ExcludeNamespaces = normalizeList(f.ExcludeNamespaces)
	f.Kinds = normalizeList(f.Kinds)
	f.Names = normalizeList(f.Names)
	f.Analyzers = normalizeList(f.Analyzers)
	f.LabelSelector = strings.TrimSpace(f.LabelSelector)
	if _, err := labels.Parse(f.LabelSelector); err != nil {
		return fmt.Errorf("invalid analyzer filter label selector: %w", err)
	}
	for _, namespace := range f.IncludeNamespaces {
		if containsFold(f.ExcludeNamespaces, namespace) {
			return fmt.Errorf("namespace %q is both included and excluded", namespace)
		}
	}
	return nil
}

func (c *UserConfig) normalize() error {
	if c == nil {
		return errors.New("user config is nil")
	}
	if c.SchemaVersion == "" {
		c.SchemaVersion = UserConfigSchemaVersion
	}
	if c.SchemaVersion != UserConfigSchemaVersion {
		return fmt.Errorf("unsupported user config schema %q", c.SchemaVersion)
	}
	c.DefaultProfile = strings.TrimSpace(c.DefaultProfile)
	c.DefaultFilter = strings.TrimSpace(c.DefaultFilter)
	for index := range c.Profiles {
		if err := c.Profiles[index].normalize(); err != nil {
			return err
		}
	}
	for index := range c.Filters {
		if err := c.Filters[index].normalize(); err != nil {
			return err
		}
	}
	sort.Slice(c.Profiles, func(i, j int) bool { return strings.ToLower(c.Profiles[i].Name) < strings.ToLower(c.Profiles[j].Name) })
	sort.Slice(c.Filters, func(i, j int) bool { return strings.ToLower(c.Filters[i].Name) < strings.ToLower(c.Filters[j].Name) })
	for index := 1; index < len(c.Profiles); index++ {
		if strings.EqualFold(c.Profiles[index-1].Name, c.Profiles[index].Name) {
			return fmt.Errorf("duplicate provider profile %q", c.Profiles[index].Name)
		}
	}
	for index := 1; index < len(c.Filters); index++ {
		if strings.EqualFold(c.Filters[index-1].Name, c.Filters[index].Name) {
			return fmt.Errorf("duplicate analyzer filter %q", c.Filters[index].Name)
		}
	}
	if c.DefaultProfile != "" && findProfile(c.Profiles, c.DefaultProfile) < 0 {
		return fmt.Errorf("default provider profile %q not found", c.DefaultProfile)
	}
	if c.DefaultFilter != "" && findFilter(c.Filters, c.DefaultFilter) < 0 {
		return fmt.Errorf("default analyzer filter %q not found", c.DefaultFilter)
	}
	c.Settings = normalizeSettings(c.Settings)
	if err := validatePlaybookSettings(c.Settings); err != nil {
		return err
	}
	return nil
}

func normalizeSettings(settings UserSettings) UserSettings {
	settings.Kubeconfig = strings.TrimSpace(settings.Kubeconfig)
	settings.ScanInterval = strings.TrimSpace(settings.ScanInterval)
	settings.EventDebounce = strings.TrimSpace(settings.EventDebounce)
	settings.Namespace = strings.TrimSpace(settings.Namespace)
	settings.LLMProvider = strings.ToLower(strings.TrimSpace(settings.LLMProvider))
	settings.LLMMode = strings.ToLower(strings.TrimSpace(settings.LLMMode))
	settings.LLMWireAPI = strings.ToLower(strings.TrimSpace(settings.LLMWireAPI))
	settings.LLMModel = strings.TrimSpace(settings.LLMModel)
	settings.LLMBaseURL = strings.TrimSpace(settings.LLMBaseURL)
	settings.LLMEndpointAllowlist = normalizeList(settings.LLMEndpointAllowlist)
	settings.LLMOrganization = strings.TrimSpace(settings.LLMOrganization)
	settings.LLMProxyURL = strings.TrimSpace(settings.LLMProxyURL)
	settings.HarnessCommand = strings.TrimSpace(settings.HarnessCommand)
	settings.PublicURL = strings.TrimSpace(settings.PublicURL)
	settings.LeaderElectionNamespace = strings.TrimSpace(settings.LeaderElectionNamespace)
	settings.LeaderElectionID = strings.TrimSpace(settings.LeaderElectionID)
	settings.LeaderElectionIdentity = strings.TrimSpace(settings.LeaderElectionIdentity)
	settings.GRPCTLSCertFile = strings.TrimSpace(settings.GRPCTLSCertFile)
	settings.GRPCTLSKeyFile = strings.TrimSpace(settings.GRPCTLSKeyFile)
	settings.GRPCTLSClientCAFile = strings.TrimSpace(settings.GRPCTLSClientCAFile)
	settings.AWSRegion = strings.TrimSpace(settings.AWSRegion)
	settings.EKSClusterName = strings.TrimSpace(settings.EKSClusterName)
	settings.AllowedOrigins = normalizeList(settings.AllowedOrigins)
	settings.TrustedClientIPHeader = strings.TrimSpace(settings.TrustedClientIPHeader)
	settings.TrustedProxyCIDRs = normalizeList(settings.TrustedProxyCIDRs)
	settings.DataDir = strings.TrimSpace(settings.DataDir)
	settings.IncludeNamespaces = normalizeList(settings.IncludeNamespaces)
	settings.ExcludeNamespaces = normalizeList(settings.ExcludeNamespaces)
	settings.LabelSelector = strings.TrimSpace(settings.LabelSelector)
	settings.ResourceKinds = normalizeList(settings.ResourceKinds)
	settings.ResourceNames = normalizeList(settings.ResourceNames)
	settings.Analyzers = normalizeList(settings.Analyzers)
	settings.ScanTimeout = strings.TrimSpace(settings.ScanTimeout)
	settings.HistoryDir = strings.TrimSpace(settings.HistoryDir)
	settings.CacheDir = strings.TrimSpace(settings.CacheDir)
	settings.CacheTTL = strings.TrimSpace(settings.CacheTTL)
	settings.PlaybookLearningMode = strings.ToUpper(strings.TrimSpace(settings.PlaybookLearningMode))
	settings.PlaybookAllowedActions = normalizeList(settings.PlaybookAllowedActions)
	settings.PlaybookAllowedNamespaces = normalizeList(settings.PlaybookAllowedNamespaces)
	settings.PlaybookAllowedKinds = normalizeList(settings.PlaybookAllowedKinds)
	return settings
}

func safeConfigCopy(cfg UserConfig) UserConfig {
	copy := cfg
	copy.Profiles = append([]ProviderProfile(nil), cfg.Profiles...)
	for index := range copy.Profiles {
		copy.Profiles[index].APIKey = ""
	}
	copy.Filters = append([]AnalyzerFilter(nil), cfg.Filters...)
	copy.Settings.AllowedOrigins = append([]string(nil), cfg.Settings.AllowedOrigins...)
	copy.Settings.TrustedProxyCIDRs = append([]string(nil), cfg.Settings.TrustedProxyCIDRs...)
	copy.Settings.IncludeNamespaces = append([]string(nil), cfg.Settings.IncludeNamespaces...)
	copy.Settings.ExcludeNamespaces = append([]string(nil), cfg.Settings.ExcludeNamespaces...)
	copy.Settings.LLMEndpointAllowlist = append([]string(nil), cfg.Settings.LLMEndpointAllowlist...)
	copy.Settings.ResourceKinds = append([]string(nil), cfg.Settings.ResourceKinds...)
	copy.Settings.ResourceNames = append([]string(nil), cfg.Settings.ResourceNames...)
	copy.Settings.Analyzers = append([]string(nil), cfg.Settings.Analyzers...)
	if cfg.Settings.PlaybookEnabled != nil {
		enabled := *cfg.Settings.PlaybookEnabled
		copy.Settings.PlaybookEnabled = &enabled
	}
	if cfg.Settings.PlaybookMinConfidence != nil {
		confidence := *cfg.Settings.PlaybookMinConfidence
		copy.Settings.PlaybookMinConfidence = &confidence
	}
	if cfg.Settings.PlaybookMaxSourceBytes != nil {
		value := *cfg.Settings.PlaybookMaxSourceBytes
		copy.Settings.PlaybookMaxSourceBytes = &value
	}
	if cfg.Settings.PlaybookMaxStepCount != nil {
		value := *cfg.Settings.PlaybookMaxStepCount
		copy.Settings.PlaybookMaxStepCount = &value
	}
	if cfg.Settings.PlaybookMaxTotalTextBytes != nil {
		value := *cfg.Settings.PlaybookMaxTotalTextBytes
		copy.Settings.PlaybookMaxTotalTextBytes = &value
	}
	copy.Settings.PlaybookAllowedActions = append([]string(nil), cfg.Settings.PlaybookAllowedActions...)
	copy.Settings.PlaybookAllowedNamespaces = append([]string(nil), cfg.Settings.PlaybookAllowedNamespaces...)
	copy.Settings.PlaybookAllowedKinds = append([]string(nil), cfg.Settings.PlaybookAllowedKinds...)
	return copy
}

func validatePlaybookSettings(settings UserSettings) error {
	if !validPlaybookLearningMode(settings.PlaybookLearningMode) {
		return fmt.Errorf("invalid playbook learning mode %q", settings.PlaybookLearningMode)
	}
	if settings.PlaybookMinConfidence != nil && !finiteConfidence(*settings.PlaybookMinConfidence) {
		return fmt.Errorf("playbook confidence must be between 0 and 1")
	}
	if err := validatePlaybookPolicyList("playbook allowed actions", settings.PlaybookAllowedActions); err != nil {
		return err
	}
	if err := validatePlaybookPolicyList("playbook allowed namespaces", settings.PlaybookAllowedNamespaces); err != nil {
		return err
	}
	if err := validatePlaybookPolicyList("playbook allowed kinds", settings.PlaybookAllowedKinds); err != nil {
		return err
	}
	if settings.PlaybookMaxSourceBytes != nil && (*settings.PlaybookMaxSourceBytes <= 0 || *settings.PlaybookMaxSourceBytes > MaxPlaybookSourceBytes) {
		return fmt.Errorf("playbook source byte limit must be between 1 and %d", MaxPlaybookSourceBytes)
	}
	if settings.PlaybookMaxStepCount != nil && (*settings.PlaybookMaxStepCount <= 0 || *settings.PlaybookMaxStepCount > MaxPlaybookStepCount) {
		return fmt.Errorf("playbook step count must be between 1 and %d", MaxPlaybookStepCount)
	}
	if settings.PlaybookMaxTotalTextBytes != nil && (*settings.PlaybookMaxTotalTextBytes <= 0 || *settings.PlaybookMaxTotalTextBytes > MaxPlaybookTotalTextBytes) {
		return fmt.Errorf("playbook total text byte limit must be between 1 and %d", MaxPlaybookTotalTextBytes)
	}
	return nil
}

func safeName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || (index > 0 && (char == '-' || char == '_' || char == '.')) {
			continue
		}
		return false
	}
	return true
}

func validateEndpoint(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("must be an absolute HTTP(S) URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("must use HTTP or HTTPS")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must not contain credentials, query parameters, or fragments")
	}
	return nil
}

func normalizeList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, "\r\n") {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func findProfile(profiles []ProviderProfile, name string) int {
	for index := range profiles {
		if strings.EqualFold(profiles[index].Name, strings.TrimSpace(name)) {
			return index
		}
	}
	return -1
}

func findFilter(filters []AnalyzerFilter, name string) int {
	for index := range filters {
		if strings.EqualFold(filters[index].Name, strings.TrimSpace(name)) {
			return index
		}
	}
	return -1
}

func selectedProfile(cfg UserConfig, name string) *ProviderProfile {
	name = strings.TrimSpace(name)
	if name == "" {
		name = cfg.DefaultProfile
	}
	if index := findProfile(cfg.Profiles, name); index >= 0 {
		return &cfg.Profiles[index]
	}
	return nil
}

func findNamedFilter(filters []AnalyzerFilter, name string) *AnalyzerFilter {
	if index := findFilter(filters, name); index >= 0 {
		return &filters[index]
	}
	return nil
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func isMigratableSchema(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "config/v0" || value == "config/0" || value == "v0" || value == "0"
}

type legacyDocument struct {
	LLMEndpointAllowlist      interface{}            `yaml:"llm_endpoint_allowlist"`
	EventDrivenScanning       *bool                  `yaml:"event_driven_scanning"`
	EventQueueCapacity        int                    `yaml:"event_queue_capacity"`
	EventDebounce             string                 `yaml:"event_debounce"`
	Provider                  string                 `yaml:"provider"`
	LLMProvider               string                 `yaml:"llm_provider"`
	LLMMode                   string                 `yaml:"llm_mode"`
	Model                     string                 `yaml:"model"`
	LLMModel                  string                 `yaml:"llm_model"`
	BaseURL                   string                 `yaml:"base_url"`
	LLMBaseURL                string                 `yaml:"llm_base_url"`
	Organization              string                 `yaml:"organization"`
	LLMOrganization           string                 `yaml:"llm_organization"`
	ProxyURL                  string                 `yaml:"proxy_url"`
	LLMProxyURL               string                 `yaml:"llm_proxy_url"`
	Kubeconfig                string                 `yaml:"kubeconfig"`
	Port                      int                    `yaml:"port"`
	GRPCPort                  int                    `yaml:"grpc_port"`
	GRPCTLSCertFile           string                 `yaml:"grpc_tls_cert_file"`
	GRPCTLSKeyFile            string                 `yaml:"grpc_tls_key_file"`
	GRPCTLSClientCAFile       string                 `yaml:"grpc_tls_client_ca_file"`
	GRPCReflection            bool                   `yaml:"grpc_reflection"`
	ScanInterval              string                 `yaml:"scan_interval"`
	ScanJitter                string                 `yaml:"scan_jitter"`
	LeaderElection            bool                   `yaml:"leader_election"`
	LeaderElectionNamespace   string                 `yaml:"leader_election_namespace"`
	LeaderElectionID          string                 `yaml:"leader_election_id"`
	LeaderElectionIdentity    string                 `yaml:"leader_election_identity"`
	EnableAWSEKS              bool                   `yaml:"enable_aws_eks"`
	AWSRegion                 string                 `yaml:"aws_region"`
	EKSClusterName            string                 `yaml:"eks_cluster_name"`
	Namespace                 string                 `yaml:"namespace"`
	HarnessCommand            string                 `yaml:"harness_command"`
	PublicURL                 string                 `yaml:"public_url"`
	RequireAPIToken           bool                   `yaml:"require_api_token"`
	AllowedOrigins            interface{}            `yaml:"allowed_origins"`
	TrustedClientHeader       string                 `yaml:"trusted_client_ip_header"`
	TrustedProxyCIDRs         interface{}            `yaml:"trusted_proxy_cidrs"`
	MaxBodyBytes              int64                  `yaml:"max_body_bytes"`
	RequestsPerMinute         int                    `yaml:"requests_per_minute"`
	RequestBurst              int                    `yaml:"request_burst"`
	DataDir                   string                 `yaml:"data_dir"`
	IncludeNamespaces         interface{}            `yaml:"include_namespaces"`
	ExcludeNamespaces         interface{}            `yaml:"exclude_namespaces"`
	LabelSelector             string                 `yaml:"label_selector"`
	ResourceKinds             interface{}            `yaml:"resource_kinds"`
	ResourceNames             interface{}            `yaml:"resource_names"`
	Analyzers                 interface{}            `yaml:"analyzers"`
	ScanConcurrency           int                    `yaml:"scan_concurrency"`
	ScanTimeout               string                 `yaml:"scan_timeout"`
	HistoryDir                string                 `yaml:"history_dir"`
	CacheDir                  string                 `yaml:"cache_dir"`
	CacheTTL                  string                 `yaml:"cache_ttl"`
	CacheMaxEntries           int                    `yaml:"cache_max_entries"`
	CacheMaxValueBytes        int                    `yaml:"cache_max_value_bytes"`
	PlaybookEnabled           bool                   `yaml:"playbook_enabled"`
	PlaybookLearningMode      string                 `yaml:"playbook_learning_mode"`
	PlaybookMinConfidence     float64                `yaml:"playbook_min_confidence"`
	PlaybookAllowedActions    interface{}            `yaml:"playbook_allowed_actions"`
	PlaybookAllowedNamespaces interface{}            `yaml:"playbook_allowed_namespaces"`
	PlaybookAllowedKinds      interface{}            `yaml:"playbook_allowed_kinds"`
	PlaybookMaxSources        int                    `yaml:"playbook_max_sources"`
	PlaybookMaxSourceBytes    int                    `yaml:"playbook_max_source_bytes"`
	PlaybookMaxSteps          int                    `yaml:"playbook_max_steps"`
	PlaybookMaxStepCount      int                    `yaml:"playbook_max_step_count"`
	PlaybookMaxTotalTextBytes int                    `yaml:"playbook_max_total_text_bytes"`
	DefaultProfile            string                 `yaml:"default_profile"`
	DefaultFilter             string                 `yaml:"default_filter"`
	Profile                   interface{}            `yaml:"profile"`
	Profiles                  interface{}            `yaml:"profiles"`
	Filters                   []AnalyzerFilter       `yaml:"filters"`
	Settings                  map[string]interface{} `yaml:"settings"`
}

func migrateLegacyConfig(data []byte) (UserConfig, error) {
	var document legacyDocument
	if err := yaml.Unmarshal(data, &document); err != nil {
		return UserConfig{}, errors.New("parse legacy user config")
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return UserConfig{}, errors.New("parse legacy user config")
	}
	settings := document.Settings
	value := func(keys ...string) interface{} {
		for _, key := range keys {
			if item, ok := raw[key]; ok {
				return item
			}
			if item, ok := settings[key]; ok {
				return item
			}
		}
		return nil
	}
	stringValueFrom := func(fallback string, keys ...string) string {
		if item := value(keys...); item != nil {
			if text, ok := item.(string); ok {
				return strings.TrimSpace(text)
			}
		}
		return strings.TrimSpace(fallback)
	}

	cfg := NewUserConfig()
	cfg.DefaultProfile = stringValueFrom(document.DefaultProfile, "default_profile")
	cfg.DefaultFilter = stringValueFrom(document.DefaultFilter, "default_filter")
	provider := stringValueFrom(firstNonEmpty(document.LLMProvider, document.Provider), "llm_provider", "provider")
	model := stringValueFrom(firstNonEmpty(document.LLMModel, document.Model), "llm_model", "model")
	baseURL := stringValueFrom(firstNonEmpty(document.LLMBaseURL, document.BaseURL), "llm_base_url", "base_url")
	organization := stringValueFrom(firstNonEmpty(document.LLMOrganization, document.Organization), "llm_organization", "organization")
	proxyURL := stringValueFrom(firstNonEmpty(document.LLMProxyURL, document.ProxyURL), "llm_proxy_url", "proxy_url")
	profile := ProviderProfile{Name: "default", Provider: provider, Mode: stringValueFrom(document.LLMMode, "llm_mode"), Model: model, BaseURL: baseURL, Organization: organization, ProxyURL: proxyURL}
	if profileValue := value("profile"); profileValue != nil {
		if profileMap, ok := profileValue.(map[string]interface{}); ok {
			profile = legacyProfileFromMap("default", profileMap)
		}
	}
	if profiles := legacyProfiles(value("profiles")); len(profiles) > 0 {
		cfg.Profiles = profiles
	} else if profile.Provider != "" {
		cfg.Profiles = []ProviderProfile{profile}
	}
	if cfg.DefaultProfile == "" && len(cfg.Profiles) > 0 {
		cfg.DefaultProfile = cfg.Profiles[0].Name
	}

	cfg.Filters = append([]AnalyzerFilter(nil), document.Filters...)
	cfg.Settings = UserSettings{
		EventDrivenScanning:       document.EventDrivenScanning,
		EventQueueCapacity:        document.EventQueueCapacity,
		EventDebounce:             stringValueFrom(document.EventDebounce, "event_debounce"),
		LLMEndpointAllowlist:      legacyStrings(value("llm_endpoint_allowlist", "endpoint_allowlist")),
		Kubeconfig:                stringValueFrom(document.Kubeconfig, "kubeconfig"),
		Port:                      document.Port,
		GRPCPort:                  document.GRPCPort,
		GRPCTLSCertFile:           stringValueFrom(document.GRPCTLSCertFile, "grpc_tls_cert_file"),
		GRPCTLSKeyFile:            stringValueFrom(document.GRPCTLSKeyFile, "grpc_tls_key_file"),
		GRPCTLSClientCAFile:       stringValueFrom(document.GRPCTLSClientCAFile, "grpc_tls_client_ca_file"),
		GRPCReflection:            document.GRPCReflection,
		ScanInterval:              stringValueFrom(document.ScanInterval, "scan_interval"),
		ScanJitter:                stringValueFrom(document.ScanJitter, "scan_jitter"),
		LeaderElection:            document.LeaderElection,
		LeaderElectionNamespace:   stringValueFrom(document.LeaderElectionNamespace, "leader_election_namespace"),
		LeaderElectionID:          stringValueFrom(document.LeaderElectionID, "leader_election_id"),
		LeaderElectionIdentity:    stringValueFrom(document.LeaderElectionIdentity, "leader_election_identity"),
		EnableAWSEKS:              document.EnableAWSEKS,
		AWSRegion:                 stringValueFrom(document.AWSRegion, "aws_region"),
		EKSClusterName:            stringValueFrom(document.EKSClusterName, "eks_cluster_name"),
		Namespace:                 stringValueFrom(document.Namespace, "namespace"),
		LLMProvider:               provider,
		LLMMode:                   stringValueFrom(document.LLMMode, "llm_mode"),
		LLMModel:                  model,
		LLMBaseURL:                baseURL,
		LLMOrganization:           organization,
		LLMProxyURL:               proxyURL,
		HarnessCommand:            stringValueFrom(document.HarnessCommand, "harness_command"),
		PublicURL:                 stringValueFrom(document.PublicURL, "public_url"),
		RequireAPIToken:           document.RequireAPIToken,
		AllowedOrigins:            legacyStrings(value("allowed_origins")),
		TrustedClientIPHeader:     stringValueFrom(document.TrustedClientHeader, "trusted_client_ip_header"),
		TrustedProxyCIDRs:         legacyStrings(value("trusted_proxy_cidrs")),
		MaxBodyBytes:              document.MaxBodyBytes,
		RequestsPerMinute:         document.RequestsPerMinute,
		RequestBurst:              document.RequestBurst,
		DataDir:                   stringValueFrom(document.DataDir, "data_dir"),
		IncludeNamespaces:         legacyStrings(value("include_namespaces")),
		ExcludeNamespaces:         legacyStrings(value("exclude_namespaces")),
		LabelSelector:             stringValueFrom(document.LabelSelector, "label_selector"),
		ResourceKinds:             legacyStrings(value("resource_kinds", "kinds")),
		ResourceNames:             legacyStrings(value("resource_names", "names")),
		Analyzers:                 legacyStrings(value("analyzers")),
		ScanConcurrency:           document.ScanConcurrency,
		ScanTimeout:               stringValueFrom(document.ScanTimeout, "scan_timeout"),
		HistoryDir:                stringValueFrom(document.HistoryDir, "history_dir"),
		CacheDir:                  stringValueFrom(document.CacheDir, "cache_dir"),
		CacheTTL:                  stringValueFrom(document.CacheTTL, "cache_ttl"),
		CacheMaxEntries:           document.CacheMaxEntries,
		CacheMaxValueBytes:        document.CacheMaxValueBytes,
		PlaybookLearningMode:      stringValueFrom(document.PlaybookLearningMode, "playbook_learning_mode"),
		PlaybookAllowedActions:    legacyStrings(value("playbook_allowed_actions")),
		PlaybookAllowedNamespaces: legacyStrings(value("playbook_allowed_namespaces")),
		PlaybookAllowedKinds:      legacyStrings(value("playbook_allowed_kinds")),
		PlaybookMaxSourceBytes:    optionalIntValueFrom(firstNonZero(document.PlaybookMaxSourceBytes, document.PlaybookMaxSources), value("playbook_max_source_bytes", "playbook_max_sources")),
		PlaybookMaxStepCount:      optionalIntValueFrom(firstNonZero(document.PlaybookMaxStepCount, document.PlaybookMaxSteps), value("playbook_max_step_count", "playbook_max_steps")),
		PlaybookMaxTotalTextBytes: optionalIntValueFrom(document.PlaybookMaxTotalTextBytes, value("playbook_max_total_text_bytes")),
	}
	if item := value("playbook_min_confidence"); item != nil {
		confidence := floatValueFrom(document.PlaybookMinConfidence, item)
		cfg.Settings.PlaybookMinConfidence = &confidence
	} else if document.PlaybookMinConfidence != 0 {
		confidence := document.PlaybookMinConfidence
		cfg.Settings.PlaybookMinConfidence = &confidence
	}
	if item := value("playbook_enabled"); item != nil {
		if enabled, ok := boolFromLegacy(item); ok {
			cfg.Settings.PlaybookEnabled = &enabled
		}
	} else if document.PlaybookEnabled {
		enabled := true
		cfg.Settings.PlaybookEnabled = &enabled
	}
	if err := cfg.normalize(); err != nil {
		return UserConfig{}, err
	}
	return cfg, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func boolFromLegacy(value interface{}) (bool, bool) {
	switch value := value.(type) {
	case bool:
		return value, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		return parsed, err == nil
	default:
		return false, false
	}
}

func floatValueFrom(fallback float64, value interface{}) float64 {
	switch value := value.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case string:
		if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
			return parsed
		}
	}
	return fallback
}

func intValueFrom(fallback int, value interface{}) int {
	switch value := value.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return parsed
		}
	}
	return fallback
}

func optionalIntValueFrom(fallback int, value interface{}) *int {
	if value == nil && fallback == 0 {
		return nil
	}
	parsed := intValueFrom(fallback, value)
	return &parsed
}

func legacyStrings(value interface{}) []string {
	switch value := value.(type) {
	case string:
		return splitCSV(value)
	case []string:
		return normalizeList(value)
	case []interface{}:
		values := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
		return normalizeList(values)
	default:
		return nil
	}
}

func legacyProfiles(value interface{}) []ProviderProfile {
	var profiles []ProviderProfile
	switch value := value.(type) {
	case []interface{}:
		for _, item := range value {
			if profileMap, ok := item.(map[string]interface{}); ok {
				name := ""
				if itemName, ok := profileMap["name"].(string); ok {
					name = itemName
				}
				profiles = append(profiles, legacyProfileFromMap(name, profileMap))
			}
		}
	case map[string]interface{}:
		for name, item := range value {
			if profileMap, ok := item.(map[string]interface{}); ok {
				profiles = append(profiles, legacyProfileFromMap(name, profileMap))
			}
		}
	}
	return profiles
}

func legacyProfileFromMap(name string, values map[string]interface{}) ProviderProfile {
	stringFromMap := func(keys ...string) string {
		for _, key := range keys {
			if value, ok := values[key].(string); ok {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}
	return ProviderProfile{
		Name:         strings.TrimSpace(name),
		Provider:     stringFromMap("provider", "llm_provider"),
		Mode:         stringFromMap("mode", "llm_mode"),
		Model:        stringFromMap("model", "llm_model"),
		BaseURL:      stringFromMap("base_url", "llm_base_url"),
		Organization: stringFromMap("organization", "org"),
		ProxyURL:     stringFromMap("proxy_url", "proxy"),
	}
}
