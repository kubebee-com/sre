package legacyagent

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/cache"
	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/kubebee-com/sre/pkg/triage"
)

type fakeCLIService struct {
	report *scanner.ScanReport
	plan   scanplan.Plan
}

func (f *fakeCLIService) ScanWithPlan(_ context.Context, plan scanplan.Plan) (*scanner.ScanReport, error) {
	f.plan = plan
	return f.report, nil
}

func (f *fakeCLIService) GetAnalyzers() []scanner.AnalyzerInfo {
	return []scanner.AnalyzerInfo{{Name: "PodAnalyzer", Resource: "Pod", DocsURL: "https://docs.example.test/pods"}}
}

type fakeCLIProvider struct {
	queries []string
}

func (p *fakeCLIProvider) Name() string { return "test-provider" }

func (p *fakeCLIProvider) Diagnose(context.Context, *scanner.Issue) (*triage.Diagnosis, error) {
	return nil, nil
}

func (p *fakeCLIProvider) Explain(_ context.Context, query string, _ *scanner.Issue) (string, error) {
	p.queries = append(p.queries, query)
	return "reply for " + query, nil
}

type cliCacheOperationObserver struct {
	lookupCalls int
	setCalls    int
}

func (o *cliCacheOperationObserver) ObserveCacheOperation(operation, _ string) {
	switch operation {
	case "lookup":
		o.lookupCalls++
	case "set":
		o.setCalls++
	}
}

func TestNewRootCommandExposesIndependentTask2Commands(t *testing.T) {
	first := NewRootCommand(CLIOptions{Version: "first"})
	second := NewRootCommand(CLIOptions{Version: "second"})

	for _, command := range []string{"version", "serve", "scan", "explain", "analyzers", "config", "filters", "cache"} {
		if first.Find([]string{command}) == nil {
			t.Fatalf("first root is missing %q", command)
		}
		if second.Find([]string{command}) == nil {
			t.Fatalf("second root is missing %q", command)
		}
	}

	var firstOut, secondOut bytes.Buffer
	first.SetOut(&firstOut)
	first.SetErr(&firstOut)
	first.SetArgs([]string{"version"})
	if err := first.Execute(); err != nil {
		t.Fatalf("first version command error = %v", err)
	}
	second.SetOut(&secondOut)
	second.SetErr(&secondOut)
	second.SetArgs([]string{"version"})
	if err := second.Execute(); err != nil {
		t.Fatalf("second version command error = %v", err)
	}
	if firstOut.String() != "first\n" || secondOut.String() != "second\n" {
		t.Fatalf("command state was shared: first %q second %q", firstOut.String(), secondOut.String())
	}
}

func TestMCPCommandUsesExplicitStdioEntrypoint(t *testing.T) {
	called := false
	root := NewRootCommand(CLIOptions{
		MCPStdio: func(context.Context) error {
			called = true
			return nil
		},
	})
	root.SetArgs([]string{"mcp"})
	if err := root.Execute(); err != nil {
		t.Fatalf("mcp command error = %v", err)
	}
	if !called {
		t.Fatal("mcp command did not invoke the configured stdio entrypoint")
	}
}

func TestRootCommandAcceptsTransientProviderHeaders(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCommand(CLIOptions{Version: "test", Out: &out, ErrOut: &out})
	root.SetArgs([]string{"version", "--llm-headers", "X-Test:enabled", "--custom-headers=X-Second:value"})
	if err := root.Execute(); err != nil {
		t.Fatalf("version with provider headers error = %v", err)
	}
	if out.String() != "test\n" {
		t.Fatalf("version output = %q", out.String())
	}
}

func TestRootCommandAcceptsAndResolvesPlaybookRuntimeFlags(t *testing.T) {
	resolved := &config.Config{}
	called := false
	root := NewRootCommand(CLIOptions{
		RuntimeConfig: resolved,
		Serve: func(context.Context) error {
			called = true
			return nil
		},
	})
	root.SetArgs([]string{
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
	if err := root.Execute(); err != nil {
		t.Fatalf("serve with playbook runtime flags error = %v", err)
	}
	if !called {
		t.Fatal("serve callback was not invoked")
	}
	if resolved.DatabaseURL != "postgres://user:secret@db.example.test:5432/sre" || !resolved.PlaybookEnabled || resolved.PlaybookLearningMode != "OBSERVE_ONLY" || resolved.PlaybookMinConfidence != 0 {
		t.Fatalf("resolved playbook scalars = %#v", resolved)
	}
	if !reflect.DeepEqual(resolved.PlaybookAllowedActions, []string{"Manual", "GitOpsPR"}) ||
		!reflect.DeepEqual(resolved.PlaybookAllowedNamespaces, []string{"payments", "platform"}) ||
		!reflect.DeepEqual(resolved.PlaybookAllowedKinds, []string{"Deployment", "StatefulSet"}) {
		t.Fatalf("resolved playbook lists = actions %#v namespaces %#v kinds %#v", resolved.PlaybookAllowedActions, resolved.PlaybookAllowedNamespaces, resolved.PlaybookAllowedKinds)
	}
	if resolved.PlaybookMaxSourceBytes != 2048 || resolved.PlaybookMaxStepCount != 3 || resolved.PlaybookMaxTotalTextBytes != 8192 {
		t.Fatalf("resolved playbook limits = source bytes %d step count %d total text bytes %d", resolved.PlaybookMaxSourceBytes, resolved.PlaybookMaxStepCount, resolved.PlaybookMaxTotalTextBytes)
	}
}

func TestRootCommandPreservesNegativePlaybookLimitsForValidation(t *testing.T) {
	tests := []struct {
		name     string
		flag     string
		resolved func(*config.Config) int
	}{
		{name: "source bytes", flag: "--playbook-max-source-bytes", resolved: func(cfg *config.Config) int { return cfg.PlaybookMaxSourceBytes }},
		{name: "step count", flag: "--playbook-max-step-count", resolved: func(cfg *config.Config) int { return cfg.PlaybookMaxStepCount }},
		{name: "total text bytes", flag: "--playbook-max-total-text-bytes", resolved: func(cfg *config.Config) int { return cfg.PlaybookMaxTotalTextBytes }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := &config.Config{
				PlaybookLearningMode:      config.DefaultPlaybookLearningMode,
				PlaybookMinConfidence:     config.DefaultPlaybookMinConfidence,
				PlaybookMaxSourceBytes:    config.DefaultPlaybookMaxSourceBytes,
				PlaybookMaxStepCount:      config.DefaultPlaybookMaxStepCount,
				PlaybookMaxTotalTextBytes: config.DefaultPlaybookMaxTotalTextBytes,
			}
			root := NewRootCommand(CLIOptions{RuntimeConfig: resolved, Serve: func(context.Context) error { return nil }})
			root.SetArgs([]string{"serve", test.flag, "-1"})
			if err := root.Execute(); err != nil {
				t.Fatalf("Cobra rejected %s -1: %v", test.flag, err)
			}
			if got := test.resolved(resolved); got != -1 {
				t.Fatalf("resolved limit = %d, want -1", got)
			}
			if err := resolved.Validate(); err == nil {
				t.Fatal("Validate() accepted the negative Cobra value")
			}
		})
	}
}

func TestRootCommandAcceptsPlaybookEnabledBooleanForms(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "bare", args: []string{"--playbook-enabled"}, want: true},
		{name: "equals true", args: []string{"--playbook-enabled=true"}, want: true},
		{name: "equals false", args: []string{"--playbook-enabled=false"}, want: false},
		{name: "separated true", args: []string{"--playbook-enabled", "true"}, want: true},
		{name: "separated false", args: []string{"--playbook-enabled", "false"}, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := &config.Config{}
			root := NewRootCommand(CLIOptions{RuntimeConfig: resolved, Serve: func(context.Context) error { return nil }})
			root.SetArgs(append([]string{"serve"}, test.args...))
			if err := root.Execute(); err != nil {
				t.Fatalf("Cobra rejected %q: %v", test.args, err)
			}
			if resolved.PlaybookEnabled != test.want {
				t.Fatalf("PlaybookEnabled = %t, want %t", resolved.PlaybookEnabled, test.want)
			}
		})
	}
}

func TestDocsCommandListsAllowlistedAnalyzerLinks(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCommand(CLIOptions{
		Scanner: &fakeCLIService{},
		Out:     &out,
		ErrOut:  &out,
	})
	root.SetArgs([]string{"docs", "PodAnalyzer"})
	if err := root.Execute(); err != nil {
		t.Fatalf("docs command error = %v", err)
	}
	if !strings.Contains(out.String(), "https://docs.example.test/pods") || !strings.Contains(out.String(), "docs/v1") {
		t.Fatalf("docs command output = %q", out.String())
	}

	root = NewRootCommand(CLIOptions{Scanner: &fakeCLIService{}, Out: &out, ErrOut: &out})
	root.SetArgs([]string{"docs", "UnknownAnalyzer"})
	if err := root.Execute(); err == nil {
		t.Fatal("docs command accepted an unknown analyzer")
	}
}

func TestScanCommandUsesFiltersAndSanitizedJSONOutput(t *testing.T) {
	service := &fakeCLIService{report: &scanner.ScanReport{
		SchemaVersion: scanplan.SchemaVersion,
		Scope:         scanplan.Default().EffectiveScope(),
		Issues: []*scanner.Issue{{
			ID:        "issue-1",
			Namespace: "payments",
			Kind:      "Pod",
			Name:      "checkout-0",
			Severity:  scanner.SeverityHigh,
			Category:  scanner.CategoryCrashLoop,
			Summary:   "summary cli-secret",
			Details:   "details cli-secret",
		}},
	}}
	t.Setenv("LLM_API_KEY", "cli-secret")
	var out bytes.Buffer
	root := NewRootCommand(CLIOptions{Scanner: service, Out: &out, ErrOut: &out, ConfigPath: t.TempDir() + "/config.yaml"})
	root.SetArgs([]string{
		"scan", "--output", "json", "--namespace", "payments", "--kind", "Pod", "--analyzer", "PodAnalyzer",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("scan command error = %v", err)
	}
	if strings.Contains(out.String(), "cli-secret") {
		t.Fatalf("scan output leaked secret: %s", out.String())
	}
	if service.plan.NamespaceArgument() != "payments" || len(service.plan.Kinds) != 1 || len(service.plan.Analyzers) != 1 {
		t.Fatalf("scanner received plan = %#v", service.plan)
	}
	if !strings.Contains(out.String(), `"findings"`) || !strings.Contains(out.String(), `"schema_version"`) {
		t.Fatalf("scan output missing envelope: %s", out.String())
	}
}

func TestExplainInteractiveHonorsHistoryLimitAndCancellation(t *testing.T) {
	provider := &fakeCLIProvider{}
	input := strings.NewReader("one\ntwo\nthree\n:quit\n")
	var out bytes.Buffer
	root := NewRootCommand(CLIOptions{
		Triage:              provider,
		In:                  input,
		Out:                 &out,
		ErrOut:              &out,
		ExplainHistoryLimit: 2,
	})
	root.SetArgs([]string{"explain", "--interactive"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("interactive explain error = %v", err)
	}
	if len(provider.queries) != 3 {
		t.Fatalf("Explain() calls = %d, want 3", len(provider.queries))
	}
	if strings.Count(provider.queries[2], "reply for") > 2 {
		t.Fatalf("history exceeded configured bound: %q", provider.queries[2])
	}
	if !strings.Contains(out.String(), "reply for") {
		t.Fatalf("interactive output missing provider replies: %s", out.String())
	}
}

func TestExplainNoCacheSkipsCacheReadAndWriteForOneShot(t *testing.T) {
	provider := &fakeCLIProvider{}
	fileCache, err := cache.NewFileCache(t.TempDir(), []byte("cli-cache-key"))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	observer := &cliCacheOperationObserver{}
	cached, err := triage.NewCachedProvider(provider, cache.NewObservedCache(fileCache, observer))
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}
	if _, err := cached.Explain(context.Background(), "question", nil); err != nil {
		t.Fatalf("initial Explain() error = %v", err)
	}
	observer.lookupCalls = 0
	observer.setCalls = 0

	var out bytes.Buffer
	root := NewRootCommand(CLIOptions{Triage: cached, Out: &out, ErrOut: &out})
	root.SetArgs([]string{"explain", "--no-cache", "question"})
	if err := root.Execute(); err != nil {
		t.Fatalf("one-shot explain error = %v", err)
	}
	if providerCallCount := len(provider.queries); providerCallCount != 2 {
		t.Fatalf("underlying Explain() calls = %d, want 2", providerCallCount)
	}
	if observer.lookupCalls != 0 || observer.setCalls != 0 {
		t.Fatalf("one-shot --no-cache operations = lookup:%d set:%d, want zero", observer.lookupCalls, observer.setCalls)
	}
}

func TestExplainNoCacheSkipsCacheReadAndWriteForInteractive(t *testing.T) {
	provider := &fakeCLIProvider{}
	fileCache, err := cache.NewFileCache(t.TempDir(), []byte("cli-cache-key"))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	observer := &cliCacheOperationObserver{}
	cached, err := triage.NewCachedProvider(provider, cache.NewObservedCache(fileCache, observer))
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}
	if _, err := cached.Explain(context.Background(), "question", nil); err != nil {
		t.Fatalf("initial Explain() error = %v", err)
	}
	observer.lookupCalls = 0
	observer.setCalls = 0

	var out bytes.Buffer
	root := NewRootCommand(CLIOptions{
		Triage: cached,
		In:     strings.NewReader("question\n:quit\n"),
		Out:    &out,
		ErrOut: &out,
	})
	root.SetArgs([]string{"explain", "--interactive", "--no-cache"})
	if err := root.Execute(); err != nil {
		t.Fatalf("interactive explain error = %v", err)
	}
	if providerCallCount := len(provider.queries); providerCallCount != 2 {
		t.Fatalf("underlying Explain() calls = %d, want 2", providerCallCount)
	}
	if observer.lookupCalls != 0 || observer.setCalls != 0 {
		t.Fatalf("interactive --no-cache operations = lookup:%d set:%d, want zero", observer.lookupCalls, observer.setCalls)
	}
}

func TestConfigCommandDoesNotPrintEnvironmentSecrets(t *testing.T) {
	t.Setenv("LLM_API_KEY", "config-command-secret")
	var out bytes.Buffer
	root := NewRootCommand(CLIOptions{Out: &out, ErrOut: &out, ConfigPath: t.TempDir() + "/config.yaml"})
	root.SetArgs([]string{"config", "show", "--output", "json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("config show error = %v", err)
	}
	if strings.Contains(out.String(), "config-command-secret") || strings.Contains(out.String(), "api_key") {
		t.Fatalf("config output leaked secret fields: %s", out.String())
	}
}

func TestFirstCLICommandSkipsFlagValues(t *testing.T) {
	args := []string{"--config", "/tmp/filters", "filters", "list"}
	if got := firstCLICommand(args); got != "filters" {
		t.Fatalf("firstCLICommand() = %q, want filters", got)
	}
	if !isCLIInvocation(args) {
		t.Fatal("isCLIInvocation() = false, want true")
	}
	if isCLIInvocation([]string{"--kubeconfig", "/tmp/serve", "serve"}) {
		t.Fatal("isCLIInvocation() treated a flag value as a command")
	}
}

func TestProviderProfileFromConfigCarriesNativeAWSMode(t *testing.T) {
	profile := providerProfileFromConfig(&config.Config{
		LLMProvider: "bedrock",
		LLMMode:     "aws",
		LLMModel:    "model",
		AWSRegion:   "us-east-1",
	})
	if profile.Mode != triage.ProviderModeAWS || profile.AWSRegion != "us-east-1" {
		t.Fatalf("provider profile = %#v, want native AWS mode and region", profile)
	}
}

func TestCacheCommandsFailClosedOnPartialEnvironment(t *testing.T) {
	t.Setenv("SRE_CACHE_DIR", t.TempDir())
	t.Setenv("SRE_CACHE_ENCRYPTION_KEY", "")

	var out bytes.Buffer
	root := NewRootCommand(CLIOptions{Out: &out, ErrOut: &out})
	root.SetArgs([]string{"cache", "list"})
	err := root.Execute()
	if err == nil {
		t.Fatal("cache list unexpectedly succeeded with a partial configuration")
	}
	if !strings.Contains(err.Error(), "SRE_CACHE_DIR") || !strings.Contains(err.Error(), "SRE_CACHE_ENCRYPTION_KEY") {
		t.Fatalf("partial cache configuration error = %v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(out.String(), "secret") {
		t.Fatalf("partial cache configuration exposed secret material: error=%q output=%q", err, out.String())
	}
}

func TestCacheListAndStatsAreBoundedAndSecretSafe(t *testing.T) {
	directory := t.TempDir()
	key := "cache-command-secret"
	t.Setenv("SRE_CACHE_DIR", directory)
	t.Setenv("SRE_CACHE_ENCRYPTION_KEY", key)

	resultCache, err := cache.NewFileCache(directory, []byte(key))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	entryKey := cache.NewCacheKey("provider", "model", "https://endpoint.example/v1", "diagnosis-v1", "prompt-secret")
	if err := resultCache.Set(context.Background(), entryKey, []byte("provider-answer-secret")); err != nil {
		t.Fatalf("cache Set() error = %v", err)
	}
	entryPath := resultCache.Path(entryKey)

	var listOut bytes.Buffer
	listRoot := NewRootCommand(CLIOptions{Out: &listOut, ErrOut: &listOut})
	listRoot.SetArgs([]string{"cache", "list", "--output", "json"})
	if err := listRoot.Execute(); err != nil {
		t.Fatalf("cache list error = %v", err)
	}
	listOutput := listOut.String()
	if !strings.Contains(listOutput, entryKey.Digest()) || !strings.Contains(listOutput, `"entry_count": 1`) {
		t.Fatalf("cache list output missing bounded metadata: %s", listOutput)
	}
	for _, secret := range []string{key, "prompt-secret", "provider-answer-secret"} {
		if strings.Contains(listOutput, secret) {
			t.Fatalf("cache list leaked %q: %s", secret, listOutput)
		}
	}
	if _, err := os.Stat(entryPath); err != nil {
		t.Fatalf("cache list removed a valid entry: %v", err)
	}

	var statsOut bytes.Buffer
	statsRoot := NewRootCommand(CLIOptions{Out: &statsOut, ErrOut: &statsOut})
	statsRoot.SetArgs([]string{"cache", "stats", "--output", "json"})
	if err := statsRoot.Execute(); err != nil {
		t.Fatalf("cache stats error = %v", err)
	}
	if !strings.Contains(statsOut.String(), `"schema_version": "cache/v1"`) || strings.Contains(statsOut.String(), key) {
		t.Fatalf("cache stats output was unexpected or leaked the key: %s", statsOut.String())
	}
	if _, err := os.Stat(entryPath); err != nil {
		t.Fatalf("cache stats removed a valid entry: %v", err)
	}
}

func TestCacheRemoveAndPurgeAreExplicitLifecycleOperations(t *testing.T) {
	directory := t.TempDir()
	key := "cache-lifecycle-secret"
	t.Setenv("SRE_CACHE_DIR", directory)
	t.Setenv("SRE_CACHE_ENCRYPTION_KEY", key)

	resultCache, err := cache.NewFileCache(directory, []byte(key))
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	firstKey := cache.NewCacheKey("provider", "model", "endpoint", "schema", "first")
	secondKey := cache.NewCacheKey("provider", "model", "endpoint", "schema", "second")
	for _, entryKey := range []cache.CacheKey{firstKey, secondKey} {
		if err := resultCache.Set(context.Background(), entryKey, []byte("value")); err != nil {
			t.Fatalf("cache Set() error = %v", err)
		}
	}

	var removeOut bytes.Buffer
	removeRoot := NewRootCommand(CLIOptions{Out: &removeOut, ErrOut: &removeOut})
	removeRoot.SetArgs([]string{"cache", "remove", firstKey.Digest()})
	if err := removeRoot.Execute(); err != nil {
		t.Fatalf("cache remove error = %v", err)
	}
	if _, err := os.Stat(resultCache.Path(firstKey)); !os.IsNotExist(err) {
		t.Fatalf("cache remove left the selected entry in place, stat error = %v", err)
	}
	if removeOut.Len() != 0 {
		t.Fatalf("cache remove emitted unexpected output: %q", removeOut.String())
	}
	if _, err := os.Stat(resultCache.Path(secondKey)); err != nil {
		t.Fatalf("cache remove deleted an unselected entry: %v", err)
	}

	var invalidOut bytes.Buffer
	invalidRoot := NewRootCommand(CLIOptions{Out: &invalidOut, ErrOut: &invalidOut})
	invalidRoot.SetArgs([]string{"cache", "remove", "not-a-digest"})
	if err := invalidRoot.Execute(); err == nil {
		t.Fatal("cache remove unexpectedly accepted an invalid digest")
	} else if strings.Contains(err.Error(), key) || strings.Contains(invalidOut.String(), key) {
		t.Fatalf("invalid cache digest path exposed the encryption key: error=%q output=%q", err, invalidOut.String())
	}

	var purgeOut bytes.Buffer
	purgeRoot := NewRootCommand(CLIOptions{Out: &purgeOut, ErrOut: &purgeOut})
	purgeRoot.SetArgs([]string{"cache", "purge"})
	if err := purgeRoot.Execute(); err != nil {
		t.Fatalf("cache purge error = %v", err)
	}
	if _, err := os.Stat(resultCache.Path(secondKey)); !os.IsNotExist(err) {
		t.Fatalf("cache purge left the remaining entry in place, stat error = %v", err)
	}
	if purgeOut.Len() != 0 {
		t.Fatalf("cache purge emitted unexpected output: %q", purgeOut.String())
	}
}

func TestCLIHelpDoesNotExposeDatabaseURLDefault(t *testing.T) {
	cfg := &config.Config{DatabaseURL: "postgres://db-user:db-secret@database.example/sre"}
	var out bytes.Buffer
	root := NewRootCommand(CLIOptions{RuntimeConfig: cfg, Out: &out, ErrOut: &out})
	root.SetArgs([]string{"version", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "db-secret") || strings.Contains(out.String(), cfg.DatabaseURL) {
		t.Fatalf("help exposed database credentials: %s", out.String())
	}
	if cfg.DatabaseURL != "postgres://db-user:db-secret@database.example/sre" {
		t.Fatal("help changed the runtime database URL")
	}
}
