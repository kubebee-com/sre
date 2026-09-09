package legacyagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/buildinfo"

	serverpkg "github.com/kubebee-com/sre/internal/legacyserver"
	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/metrics"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/kubebee-com/sre/pkg/triage"
)

func TestRuntimeGRPCConfigExposesProviderModeWithoutSecrets(t *testing.T) {
	value, err := (runtimeGRPCConfig{config: &config.Config{
		LLMProvider:        "bedrock",
		LLMMode:            "aws",
		LLMModel:           "anthropic.claude-v2",
		LLMAPIKey:          "should-not-be-returned",
		LLMHeaders:         []string{"X-Provider-Token:header-secret"},
		CacheEncryptionKey: "cache-secret",
	}}).GetConfig(context.Background())
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	settings, ok := value.(map[string]interface{})
	if !ok {
		t.Fatalf("GetConfig() type = %T, want map[string]interface{}", value)
	}
	if settings["llm_provider"] != "bedrock" || settings["llm_mode"] != "aws" || settings["llm_model"] != "anthropic.claude-v2" {
		t.Fatalf("provider settings = %#v", settings)
	}
	if settings["llm_wire_api"] != "chat" {
		t.Fatalf("runtime config wire API = %#v, want chat", settings["llm_wire_api"])
	}
	if _, ok := settings["llm_api_key"]; ok {
		t.Fatal("runtime config exposed llm_api_key")
	}
	if _, ok := settings["cache_encryption_key"]; ok {
		t.Fatal("runtime config exposed cache_encryption_key")
	}
	if settings["llm_headers_configured"] != true {
		t.Fatalf("runtime config did not report configured provider headers: %#v", settings)
	}
	if _, ok := settings["llm_headers"]; ok {
		t.Fatal("runtime config exposed provider header values")
	}
}

func TestRuntimeGRPCConfigProjectsSafePlaybookStateWithoutDatabaseCredentials(t *testing.T) {
	databaseURL := "postgres://runtime_user:runtime-password@db.example.test:5432/sre?sslmode=require"
	value, err := (runtimeGRPCConfig{config: &config.Config{
		DatabaseURL:               databaseURL,
		PlaybookEnabled:           true,
		PlaybookLearningMode:      "OBSERVE_ONLY",
		PlaybookMinConfidence:     0.65,
		PlaybookAllowedActions:    []string{"GitOpsPR", "Manual"},
		PlaybookAllowedNamespaces: []string{"payments", "platform"},
		PlaybookAllowedKinds:      []string{"Deployment", "StatefulSet"},
		PlaybookMaxSourceBytes:    2048,
		PlaybookMaxStepCount:      4,
		PlaybookMaxTotalTextBytes: 8192,
		LLMAPIKey:                 "llm-secret",
		LLMHeaders:                []string{"X-Provider-Token:header-secret"},
		WebhookURL:                "https://hooks.example.test/webhook-secret",
		APIToken:                  "api-secret",
		CacheEncryptionKey:        "cache-secret",
	}}).GetConfig(context.Background())
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	settings, ok := value.(map[string]interface{})
	if !ok {
		t.Fatalf("GetConfig() type = %T, want map[string]interface{}", value)
	}

	want := map[string]interface{}{
		"database_url_configured":       true,
		"playbook_enabled":              true,
		"playbook_learning_mode":        "OBSERVE_ONLY",
		"playbook_min_confidence":       0.65,
		"playbook_allowed_actions":      []string{"GitOpsPR", "Manual"},
		"playbook_allowed_namespaces":   []string{"payments", "platform"},
		"playbook_allowed_kinds":        []string{"Deployment", "StatefulSet"},
		"playbook_max_source_bytes":     2048,
		"playbook_max_step_count":       4,
		"playbook_max_total_text_bytes": 8192,
	}
	for key, expected := range want {
		if !reflect.DeepEqual(settings[key], expected) {
			t.Fatalf("runtime config %s = %#v, want %#v", key, settings[key], expected)
		}
	}
	for _, key := range []string{"database_url", "llm_api_key", "llm_headers", "webhook_url", "api_token", "cache_encryption_key"} {
		if _, exists := settings[key]; exists {
			t.Fatalf("runtime config exposed secret field %q", key)
		}
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal projected runtime config: %v", err)
	}
	for _, secret := range []string{databaseURL, "runtime_user", "runtime-password", "llm-secret", "header-secret", "webhook-secret", "api-secret", "cache-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("projected runtime config exposed secret %q: %s", secret, encoded)
		}
	}
}

func TestParseProviderHeadersPreservesRepeatedValuesAndRejectsUnsafeInput(t *testing.T) {
	headers, err := parseProviderHeaders([]string{"X-Request-Tag:one", "X-Request-Tag:two", "X-Empty:"})
	if err != nil {
		t.Fatalf("parseProviderHeaders() error = %v", err)
	}
	if got := headers.Values("X-Request-Tag"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("repeated provider header values = %#v", got)
	}
	if got := headers.Get("X-Empty"); got != "" {
		t.Fatalf("empty provider header value = %q", got)
	}

	for _, input := range [][]string{
		{"missing-separator"},
		{"Host:forbidden"},
		{"X-Bad\nName:value"},
		{"X-Bad:value\r\nInjected:yes"},
	} {
		if _, err := parseProviderHeaders(input); !errors.Is(err, triage.ErrProviderValidation) {
			t.Fatalf("parseProviderHeaders(%q) error = %v, want provider validation", input, err)
		}
	}
}

func TestConfigFlagsCaptureRepeatedProviderHeaders(t *testing.T) {
	flags := configFlagsFromArgs([]string{"explain", "--llm-headers", "X-One:first", "--custom-headers=X-Two:second"})
	if flags["llm-headers"] != "X-One:first,X-Two:second" {
		t.Fatalf("provider header flags = %#v", flags)
	}
}

func TestConfigFlagsCaptureLLMWireAPI(t *testing.T) {
	flags := configFlagsFromArgs([]string{"serve", "--llm-wire-api", "responses"})
	if flags["llm-wire-api"] != "responses" {
		t.Fatalf("wire API flags = %#v", flags)
	}
}

func TestConfigFlagsCaptureLLMEndpointAllowlist(t *testing.T) {
	flags := configFlagsFromArgs([]string{"explain", "--llm-endpoint-allowlist", "https://llm.example.test/backend-api/codex"})
	if flags["llm-endpoint-allowlist"] != "https://llm.example.test/backend-api/codex" {
		t.Fatalf("endpoint allowlist flags = %#v", flags)
	}
}

func TestConfigFlagsCapturePlaybookRuntimeSettings(t *testing.T) {
	flags := configFlagsFromArgs([]string{
		"serve",
		"--database-url", "postgres://user:secret@db.example.test:5432/sre",
		"--playbook-enabled",
		"--playbook-learning-mode", "OBSERVE_ONLY",
		"--playbook-min-confidence", "0",
		"--playbook-allowed-actions", "Manual,GitOpsPR",
		"--playbook-allowed-namespaces", "payments,platform",
		"--playbook-allowed-kinds", "Deployment,StatefulSet",
		"--playbook-max-source-bytes", "2048",
		"--playbook-max-step-count", "3",
		"--playbook-max-total-text-bytes", "8192",
	})
	want := map[string]string{
		"database-url":                  "postgres://user:secret@db.example.test:5432/sre",
		"playbook-enabled":              "true",
		"playbook-learning-mode":        "OBSERVE_ONLY",
		"playbook-min-confidence":       "0",
		"playbook-allowed-actions":      "Manual,GitOpsPR",
		"playbook-allowed-namespaces":   "payments,platform",
		"playbook-allowed-kinds":        "Deployment,StatefulSet",
		"playbook-max-source-bytes":     "2048",
		"playbook-max-step-count":       "3",
		"playbook-max-total-text-bytes": "8192",
	}
	for key, value := range want {
		if flags[key] != value {
			t.Fatalf("config flag %q = %q, want %q in %#v", key, flags[key], value, flags)
		}
	}
}

func TestConfigFlagsMergeRepeatedPlaybookAllowlists(t *testing.T) {
	flags := configFlagsFromArgs([]string{
		"serve",
		"--playbook-allowed-actions", "Manual",
		"--playbook-allowed-actions=GitOpsPR,manual",
		"--playbook-allowed-namespaces", "payments",
		"--playbook-allowed-namespaces=platform,payments",
		"--playbook-allowed-kinds=StatefulSet,Deployment",
		"--playbook-allowed-kinds", "deployment",
	})
	want := map[string]string{
		"playbook-allowed-actions":    "Manual,GitOpsPR,manual",
		"playbook-allowed-namespaces": "payments,platform,payments",
		"playbook-allowed-kinds":      "StatefulSet,Deployment,deployment",
	}
	for key, expected := range want {
		if flags[key] != expected {
			t.Fatalf("config flag %q = %q, want %q", key, flags[key], expected)
		}
	}
}

func TestLoadResolvedConfigMergesAndNormalizesRepeatedPlaybookAllowlists(t *testing.T) {
	cfg, err := loadResolvedConfig([]string{
		"serve",
		"--config", filepath.Join(t.TempDir(), "config.yaml"),
		"--playbook-allowed-actions", "Manual",
		"--playbook-allowed-actions=GitOpsPR,manual",
		"--playbook-allowed-namespaces", "payments",
		"--playbook-allowed-namespaces=platform,payments",
		"--playbook-allowed-kinds=StatefulSet,Deployment",
		"--playbook-allowed-kinds", "deployment",
	})
	if err != nil {
		t.Fatalf("loadResolvedConfig() error = %v", err)
	}
	if !reflect.DeepEqual(cfg.PlaybookAllowedActions, []string{"GitOpsPR", "Manual"}) {
		t.Fatalf("PlaybookAllowedActions = %#v", cfg.PlaybookAllowedActions)
	}
	if !reflect.DeepEqual(cfg.PlaybookAllowedNamespaces, []string{"payments", "platform"}) {
		t.Fatalf("PlaybookAllowedNamespaces = %#v", cfg.PlaybookAllowedNamespaces)
	}
	if !reflect.DeepEqual(cfg.PlaybookAllowedKinds, []string{"Deployment", "StatefulSet"}) {
		t.Fatalf("PlaybookAllowedKinds = %#v", cfg.PlaybookAllowedKinds)
	}
}

func TestConfigFlagsCaptureSeparatedPlaybookEnabledValues(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		flags := configFlagsFromArgs([]string{"serve", "--playbook-enabled", value})
		if flags["playbook-enabled"] != value {
			t.Fatalf("playbook-enabled = %q, want %q in %#v", flags["playbook-enabled"], value, flags)
		}
	}
}

func TestLoadResolvedConfigAppliesPlaybookRuntimeFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := loadResolvedConfig([]string{
		"serve",
		"--config", path,
		"--database-url", "postgres://user:secret@db.example.test:5432/sre",
		"--playbook-enabled",
		"--playbook-learning-mode", "OBSERVE_ONLY",
		"--playbook-min-confidence", "0",
		"--playbook-allowed-actions", "Manual,GitOpsPR",
		"--playbook-allowed-namespaces", "payments,platform",
		"--playbook-allowed-kinds", "Deployment,StatefulSet",
		"--playbook-max-source-bytes", "2048",
		"--playbook-max-step-count", "3",
		"--playbook-max-total-text-bytes", "8192",
	})
	if err != nil {
		t.Fatalf("loadResolvedConfig() error = %v", err)
	}
	if cfg.DatabaseURL != "postgres://user:secret@db.example.test:5432/sre" || !cfg.PlaybookEnabled || cfg.PlaybookLearningMode != "OBSERVE_ONLY" || cfg.PlaybookMinConfidence != 0 {
		t.Fatalf("resolved playbook runtime scalars = %#v", cfg)
	}
	if cfg.PlaybookMaxSourceBytes != 2048 || cfg.PlaybookMaxStepCount != 3 || cfg.PlaybookMaxTotalTextBytes != 8192 {
		t.Fatalf("resolved playbook limits = source bytes %d step count %d total text bytes %d", cfg.PlaybookMaxSourceBytes, cfg.PlaybookMaxStepCount, cfg.PlaybookMaxTotalTextBytes)
	}
	if !reflect.DeepEqual(cfg.PlaybookAllowedActions, []string{"GitOpsPR", "Manual"}) {
		t.Fatalf("resolved PlaybookAllowedActions = %#v", cfg.PlaybookAllowedActions)
	}
}

func TestLoadResolvedConfigRejectsMalformedPlaybookEnabled(t *testing.T) {
	t.Setenv("SRE_PLAYBOOK_ENABLED", "not-a-bool")
	if _, err := loadResolvedConfig([]string{"serve", "--config", filepath.Join(t.TempDir(), "config.yaml")}); err == nil || !strings.Contains(err.Error(), "playbook-enabled") {
		t.Fatalf("loadResolvedConfig() error = %v, want malformed playbook-enabled", err)
	}
}

func TestConfigFlagsPreserveNegativePlaybookValuesForValidation(t *testing.T) {
	flags := configFlagsFromArgs([]string{
		"serve",
		"--config", filepath.Join(t.TempDir(), "config.yaml"),
		"--database-url", "postgres://user:secret@db.example.test:5432/sre",
		"--playbook-enabled",
		"--playbook-min-confidence", "-0.1",
		"--playbook-max-source-bytes", "-1",
		"--playbook-max-step-count", "-2",
		"--playbook-max-total-text-bytes", "-3",
	})
	if flags["playbook-min-confidence"] != "-0.1" || flags["playbook-max-source-bytes"] != "-1" || flags["playbook-max-step-count"] != "-2" || flags["playbook-max-total-text-bytes"] != "-3" {
		t.Fatalf("negative playbook values were not captured: %#v", flags)
	}

	flags = configFlagsFromArgs([]string{
		"serve",
		"--playbook-min-confidence",
		"--database-url", "postgres://user:secret@db.example.test:5432/sre",
	})
	if flags["playbook-min-confidence"] == "--database-url" || flags["database-url"] != "postgres://user:secret@db.example.test:5432/sre" {
		t.Fatalf("parser consumed next flag as value: %#v", flags)
	}

	if _, err := loadResolvedConfig([]string{
		"serve",
		"--config", filepath.Join(t.TempDir(), "config.yaml"),
		"--database-url", "postgres://user:secret@db.example.test:5432/sre",
		"--playbook-enabled",
		"--playbook-min-confidence", "-0.1",
	}); err == nil || !strings.Contains(err.Error(), "confidence") {
		t.Fatalf("loadResolvedConfig() error = %v, want confidence validation failure", err)
	}
}

func TestProviderProfileFromConfigCarriesRuntimeTransportSettings(t *testing.T) {
	profile := providerProfileFromConfig(&config.Config{
		LLMProvider:          "custom",
		LLMWireAPI:           "responses",
		LLMBaseURL:           "https://llm.example.test/backend-api/codex",
		LLMEndpointAllowlist: []string{"https://llm.example.test/backend-api/codex"},
		LLMOrganization:      "org",
		LLMProxyURL:          "https://proxy.example.test",
		LLMAPIKey:            "api-key",
		LLMHeaders:           []string{"X-Header:value"},
	})
	if profile.WireAPI != triage.WireAPIResponses || profile.Endpoint != "https://llm.example.test/backend-api/codex" || len(profile.EndpointAllowlist) != 1 || profile.EndpointAllowlist[0] != "https://llm.example.test/backend-api/codex" || profile.Organization != "org" || profile.ProxyURL != "https://proxy.example.test" {
		t.Fatalf("provider profile transport settings = %#v", profile)
	}
}

func TestBuildTriageProviderRedactsDatabaseDSNFromProviderBoundary(t *testing.T) {
	databaseURL := "postgres://db_user:db-password@db.example.test:5432/sre?sslmode=require"
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read provider request: %v", err)
		}
		requests = append(requests, string(body))
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"provider saw ` + databaseURL + ` db_user:db-password db-password"}}]}`))
	}))
	defer server.Close()

	provider, err := buildTriageProvider(&config.Config{
		LLMProvider: "custom",
		LLMMode:     "local",
		LLMBaseURL:  server.URL,
		LLMModel:    "runtime-model",
		LLMAPIKey:   "runtime-key",
		DatabaseURL: databaseURL,
	})
	if err != nil {
		t.Fatalf("buildTriageProvider() error = %v", err)
	}
	issue := &scanner.Issue{
		ID:          "issue-db",
		Namespace:   "default",
		Kind:        "Pod",
		Name:        "payments",
		Severity:    scanner.SeverityHigh,
		Category:    scanner.CategoryCrashLoop,
		Summary:     "summary " + databaseURL,
		Details:     "credentials db_user:db-password and db-password",
		SpecSnippet: "dsn: " + databaseURL,
	}
	reply, err := provider.Explain(context.Background(), "inspect "+databaseURL+" db-password", issue)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	for _, leaked := range []string{databaseURL, "db_user:db-password", "db-password"} {
		if strings.Contains(reply, leaked) {
			t.Fatalf("provider reply leaked %q: %q", leaked, reply)
		}
		for _, request := range requests {
			if strings.Contains(request, leaked) {
				t.Fatalf("provider request leaked %q: %s", leaked, request)
			}
		}
	}
}

type recordingProvider struct {
	issue *scanner.Issue
}

func (p *recordingProvider) Name() string { return "recording-provider" }

func (p *recordingProvider) Diagnose(_ context.Context, issue *scanner.Issue) (*triage.Diagnosis, error) {
	p.issue = issue
	return &triage.Diagnosis{
		IssueID:         issue.ID,
		ProviderName:    p.Name(),
		Severity:        issue.Severity,
		Summary:         "summary",
		RootCause:       "root cause",
		RemediationPlan: "plan",
		ActionType:      triage.ActionManual,
		ConfidenceScore: 0.8,
	}, nil
}

func (p *recordingProvider) Explain(context.Context, string, *scanner.Issue) (string, error) {
	return "", nil
}

type singleScanService struct {
	report *scanner.ScanReport
}

func (s *singleScanService) Scan(context.Context, string) ([]*scanner.Issue, error) {
	if s.report == nil {
		return nil, nil
	}
	return s.report.Issues, nil
}

func (s *singleScanService) ScanWithPlan(context.Context, scanplan.Plan) (*scanner.ScanReport, error) {
	return s.report, nil
}

func (s *singleScanService) GetAnalyzers() []scanner.AnalyzerInfo {
	return nil
}

func (s *singleScanService) GetPodCleaner() *scanner.PodCleaner {
	return nil
}

func (s *singleScanService) History() scanner.HistoryStore {
	return nil
}

func (s *singleScanService) QueryResource(context.Context, string, string, string) (interface{}, error) {
	return nil, nil
}

func TestRunSingleScanRedactsDatabaseDSNBeforeProviderIssue(t *testing.T) {
	databaseURL := "postgres://db_user:db-password@db.example.test:5432/sre?sslmode=require"
	issue := &scanner.Issue{
		ID:          "issue-db-scan",
		Namespace:   "default",
		Kind:        "Pod",
		Name:        "payments",
		Severity:    scanner.SeverityHigh,
		Category:    scanner.CategoryCrashLoop,
		Summary:     "summary " + databaseURL,
		Details:     "credentials db_user:db-password and db-password",
		LogsSnippet: "logs " + databaseURL,
		SpecSnippet: "dsn: " + databaseURL,
		Events:      []string{"event " + databaseURL},
	}
	service := &singleScanService{report: &scanner.ScanReport{
		SchemaVersion: scanplan.SchemaVersion,
		Scope:         scanplan.Default().EffectiveScope(),
		Issues:        []*scanner.Issue{issue},
	}}
	provider := &recordingProvider{}
	engine := remediation.NewEngine(nil)
	server := serverpkg.NewServer(0, service, provider, engine, nil, serverpkg.ServerOptions{
		RedactionSecrets: providerSecretValues(&config.Config{DatabaseURL: databaseURL}),
	})

	if err := runSingleScan(context.Background(), &config.Config{DatabaseURL: databaseURL}, service, provider, engine, nil, server); err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	if provider.issue == nil {
		t.Fatal("provider did not receive an issue")
	}
	providerText := provider.issue.Summary + "\n" + provider.issue.Details + "\n" + provider.issue.LogsSnippet + "\n" + provider.issue.SpecSnippet + "\n" + strings.Join(provider.issue.Events, "\n")
	for _, leaked := range []string{databaseURL, "db_user:db-password", "db-password"} {
		if strings.Contains(providerText, leaked) {
			t.Fatalf("provider issue leaked %q: %#v", leaked, provider.issue)
		}
	}
}

func TestBuildTriageProviderAppliesRuntimeProviderHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Request-Tag"); got != "first" {
			t.Errorf("X-Request-Tag = %q, want first", got)
		}
		if got := r.Header.Values("X-Request-Tag"); len(got) != 2 || got[1] != "second" {
			t.Errorf("repeated X-Request-Tag values = %#v", got)
		}
		if got := r.Header.Get("OpenAI-Organization"); got != "runtime-org" {
			t.Errorf("OpenAI-Organization = %q, want runtime-org", got)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"runtime reply"}}]}`))
	}))
	defer server.Close()

	provider, err := buildTriageProvider(&config.Config{
		LLMProvider:     "custom",
		LLMMode:         "local",
		LLMBaseURL:      server.URL,
		LLMModel:        "runtime-model",
		LLMAPIKey:       "runtime-key",
		LLMOrganization: "runtime-org",
		LLMHeaders:      []string{"X-Request-Tag:first", "X-Request-Tag:second"},
	})
	if err != nil {
		t.Fatalf("buildTriageProvider() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "hello", nil)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if reply != "runtime reply" {
		t.Fatalf("Explain() reply = %q", reply)
	}
}

// Run the real entrypoint in a subprocess so a dispatch regression cannot start
// a server or terminate the test process through log.Fatal/os.Exit.
func TestMainDispatchesVersionWithPlaybookEnabled(t *testing.T) {
	if os.Getenv("SRE_TEST_MAIN_DISPATCH") == "1" {
		for index, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[index+1:]...)
				legacyMain()
				return
			}
		}
		t.Fatal("missing subprocess argument separator")
	}
	for _, args := range [][]string{
		{"--playbook-enabled", "false", "version"},
		{"--playbook-enabled=false", "version"},
		{"version", "--playbook-enabled", "false"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			commandArgs := append([]string{"-test.run=^TestMainDispatchesVersionWithPlaybookEnabled$", "--", "--config", filepath.Join(t.TempDir(), "config.yaml")}, args...)
			command := exec.CommandContext(ctx, os.Args[0], commandArgs...)
			command.Env = []string{"SRE_TEST_MAIN_DISPATCH=1", "SRE_REQUIRE_API_TOKEN=true"}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("entrypoint failed: %v\n%s", err, output)
			}
			if !strings.HasPrefix(string(output), buildinfo.String()+"\n") {
				t.Fatalf("entrypoint output = %q, want version %q", output, buildinfo.String())
			}
		})
	}
}

func TestObservedTriageProviderPreservesStructuredTaskRunner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("request path = %q, want /chat/completions", r.URL.Path)
		}
		var request map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if _, ok := request["response_format"]; !ok {
			t.Error("structured runtime request omitted response_format")
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"ok\":true}"}}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`)
	}))
	defer server.Close()

	provider, err := buildTriageProvider(&config.Config{
		LLMProvider: "custom",
		LLMMode:     "local",
		LLMBaseURL:  server.URL,
		LLMModel:    "runtime-model",
	})
	if err != nil {
		t.Fatalf("buildTriageProvider() error = %v", err)
	}
	wrapped := observeTriageProvider(provider, providerMetricsObserver{registry: metrics.NewRegistry()})
	runner, ok := wrapped.(triage.StructuredTaskRunner)
	if !ok {
		t.Fatalf("runtime wrapper type %T does not preserve StructuredTaskRunner", wrapped)
	}
	result, err := runner.RunStructured(context.Background(), triage.StructuredTask{
		Operation:    "playbook.digest",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if err != nil {
		t.Fatalf("RunStructured() error = %v", err)
	}
	if result.Text != `{"ok":true}` || result.Usage.TotalTokens != 3 {
		t.Fatalf("RunStructured() = %#v, want delegated structured result", result)
	}
}
