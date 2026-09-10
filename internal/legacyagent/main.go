package legacyagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	server "github.com/kubebee-com/sre/internal/legacyserver"
	"github.com/kubebee-com/sre/pkg/buildinfo"
	"github.com/kubebee-com/sre/pkg/cache"
	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/grpcapi"
	"github.com/kubebee-com/sre/pkg/integration"
	"github.com/kubebee-com/sre/pkg/metrics"
	"github.com/kubebee-com/sre/pkg/notifier"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/kubebee-com/sre/pkg/scheduler"
	"github.com/kubebee-com/sre/pkg/triage"
	"google.golang.org/grpc"
)

type startupReadiness struct {
	initialScanReady atomic.Bool
}

type providerMetricsObserver struct {
	registry *metrics.Registry
}

func (o providerMetricsObserver) ObserveProviderUsage(provider, _ string, usage triage.ProviderTokenUsage) {
	if o.registry == nil {
		return
	}
	o.registry.ObserveProviderRequest(provider, nil)
	o.registry.ObserveProviderUsage(provider, usage.InputTokens, usage.OutputTokens, usage.TotalTokens)
}

func (o providerMetricsObserver) ObserveProviderError(provider, _ string, kind triage.ProviderErrorKind) {
	if o.registry == nil {
		return
	}
	o.registry.ObserveProviderRequest(provider, errors.New(string(kind)))
}

type observedTriageProvider struct {
	provider triage.TriageProvider
	observer triage.ProviderObserver
}

type observedStructuredTriageProvider struct {
	observedTriageProvider
}

func observeTriageProvider(provider triage.TriageProvider, observer triage.ProviderObserver) triage.TriageProvider {
	observed := observedTriageProvider{provider: provider, observer: observer}
	if _, ok := provider.(triage.StructuredTaskRunner); ok {
		return observedStructuredTriageProvider{observedTriageProvider: observed}
	}
	return observed
}

func (p observedTriageProvider) Name() string {
	if p.provider == nil {
		return ""
	}
	return p.provider.Name()
}

func (p observedTriageProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*triage.Diagnosis, error) {
	return p.provider.Diagnose(triage.WithProviderObserver(ctx, p.observer), issue)
}

func (p observedTriageProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	return p.provider.Explain(triage.WithProviderObserver(ctx, p.observer), query, issue)
}

func (p observedStructuredTriageProvider) RunStructured(ctx context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
	runner, ok := p.provider.(triage.StructuredTaskRunner)
	if !ok {
		return triage.StructuredTaskResult{}, triage.ErrStructuredTaskUnsupported
	}
	return runner.RunStructured(triage.WithProviderObserver(ctx, p.observer), task)
}

type runtimeGRPCConfig struct {
	config *config.Config
}

func (c runtimeGRPCConfig) GetConfig(ctx context.Context) (interface{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.config == nil {
		return nil, fmt.Errorf("configuration is unavailable")
	}
	return map[string]interface{}{
		"event_driven_scanning":         c.config.EventDrivenScanning,
		"event_queue_capacity":          c.config.EventQueueCapacity,
		"event_debounce":                c.config.EventDebounce.String(),
		"schema_version":                "config/v1",
		"port":                          c.config.Port,
		"grpc_port":                     c.config.GRPCPort,
		"scan_interval":                 c.config.ScanInterval.String(),
		"scan_jitter":                   c.config.ScanJitter.String(),
		"leader_election":               c.config.LeaderElection,
		"leader_election_namespace":     sanitizer.DefaultRedactor().SanitizeText(c.config.LeaderElectionNamespace),
		"leader_election_id":            sanitizer.DefaultRedactor().SanitizeText(c.config.LeaderElectionID),
		"enable_aws_eks":                c.config.EnableAWSEKS,
		"aws_region":                    sanitizer.DefaultRedactor().SanitizeText(c.config.AWSRegion),
		"eks_cluster_name":              sanitizer.DefaultRedactor().SanitizeText(c.config.EKSClusterName),
		"namespace":                     sanitizer.DefaultRedactor().SanitizeText(c.config.Namespace),
		"llm_provider":                  sanitizer.DefaultRedactor().SanitizeText(c.config.LLMProvider),
		"llm_mode":                      sanitizer.DefaultRedactor().SanitizeText(c.config.LLMMode),
		"llm_wire_api":                  sanitizer.DefaultRedactor().SanitizeText(effectiveWireAPI(c.config)),
		"llm_model":                     sanitizer.DefaultRedactor().SanitizeText(c.config.LLMModel),
		"llm_headers_configured":        len(c.config.LLMHeaders) > 0,
		"public_url":                    sanitizer.DefaultRedactor().SanitizeURL(c.config.PublicURL),
		"require_api_token":             c.config.RequireAPIToken,
		"allowed_origins":               append([]string(nil), c.config.AllowedOrigins...),
		"include_namespaces":            append([]string(nil), c.config.IncludeNamespaces...),
		"exclude_namespaces":            append([]string(nil), c.config.ExcludeNamespaces...),
		"label_selector":                sanitizer.DefaultRedactor().SanitizeText(c.config.LabelSelector),
		"resource_kinds":                append([]string(nil), c.config.ResourceKinds...),
		"resource_names":                append([]string(nil), c.config.ResourceNames...),
		"analyzers":                     append([]string(nil), c.config.Analyzers...),
		"scan_concurrency":              c.config.ScanConcurrency,
		"scan_timeout":                  c.config.ScanTimeout.String(),
		"history_dir_configured":        strings.TrimSpace(c.config.HistoryDir) != "",
		"cache_enabled":                 strings.TrimSpace(c.config.CacheDir) != "" && strings.TrimSpace(c.config.CacheEncryptionKey) != "",
		"cache_dir_configured":          strings.TrimSpace(c.config.CacheDir) != "",
		"cache_ttl":                     c.config.CacheTTL.String(),
		"cache_max_entries":             c.config.CacheMaxEntries,
		"cache_max_value_bytes":         c.config.CacheMaxValueBytes,
		"database_url_configured":       strings.TrimSpace(c.config.DatabaseURL) != "",
		"playbook_enabled":              c.config.PlaybookEnabled,
		"playbook_learning_mode":        c.config.PlaybookLearningMode,
		"playbook_min_confidence":       c.config.PlaybookMinConfidence,
		"playbook_allowed_actions":      append([]string(nil), c.config.PlaybookAllowedActions...),
		"playbook_allowed_namespaces":   append([]string(nil), c.config.PlaybookAllowedNamespaces...),
		"playbook_allowed_kinds":        append([]string(nil), c.config.PlaybookAllowedKinds...),
		"playbook_max_source_bytes":     c.config.PlaybookMaxSourceBytes,
		"playbook_max_step_count":       c.config.PlaybookMaxStepCount,
		"playbook_max_total_text_bytes": c.config.PlaybookMaxTotalTextBytes,
		"grpc_tls_enabled":              strings.TrimSpace(c.config.GRPCTLSCertFile) != "" || strings.TrimSpace(c.config.GRPCTLSKeyFile) != "",
		"grpc_mtls_enabled":             strings.TrimSpace(c.config.GRPCTLSClientCAFile) != "",
		"grpc_reflection":               c.config.GRPCReflection,
	}, nil
}

func effectiveWireAPI(cfg *config.Config) string {
	if cfg == nil {
		return string(triage.WireAPIChat)
	}
	if wireAPI := strings.ToLower(strings.TrimSpace(cfg.LLMWireAPI)); wireAPI != "" {
		return wireAPI
	}
	if strings.EqualFold(strings.TrimSpace(cfg.LLMProvider), "codex") {
		return string(triage.WireAPIResponses)
	}
	return string(triage.WireAPIChat)
}

func runtimeEndpointDisplay(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "Masked"
	}
	return parsed.Scheme + "://" + parsed.Host
}

func (r *startupReadiness) Ready() bool {
	return r != nil && r.initialScanReady.Load()
}

func (r *startupReadiness) MarkScanResult(err error) {
	if r != nil && err == nil {
		r.initialScanReady.Store(true)
	}
}

func LegacyMain() {
	args := normalizePlaybookEnabledArgs(os.Args[1:])
	if hasVersionFlag(args) {
		fmt.Println(buildinfo.String())
		return
	}
	if isCLIInvocation(args) {
		if err := runCLIInvocation(args); err != nil {
			fmt.Fprintln(os.Stderr, sanitizer.DefaultRedactor().SafeLogValue(err.Error()))
			os.Exit(1)
		}
		return
	}
	cfg, err := loadResolvedConfig(removeCommandArg(args, "serve"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %s", sanitizer.DefaultRedactor().SafeLogValue(err.Error()))
	}
	if cfg.RequireAPIToken && strings.TrimSpace(cfg.APIToken) == "" {
		log.Fatal("SRE_API_TOKEN must be nonblank when SRE_REQUIRE_API_TOKEN is enabled")
	}
	if cfg.RequireAPIToken && strings.TrimSpace(cfg.DataDir) == "" {
		log.Fatal("SRE_DATA_DIR must be configured when authenticated production mode is enabled")
	}
	if cfg.GRPCPort != 0 && (cfg.GRPCPort < 1 || cfg.GRPCPort > 65535 || cfg.GRPCPort == cfg.Port) {
		log.Fatal("SRE_GRPC_PORT must be a valid port different from PORT")
	}
	if cfg.GRPCPort != 0 && strings.TrimSpace(cfg.APIToken) == "" {
		log.Fatal("SRE_API_TOKEN must be configured when SRE_GRPC_PORT is enabled")
	}
	sanitizer.ConfigureDefaultRedactor(providerSecretValues(cfg)...)
	log.Println("Initializing Kubebee SRE Agent...")

	// 1. Initialize Kubernetes Client
	k8sClient, kubeRESTConfig, err := buildKubeClients(cfg.Kubeconfig)
	if err != nil {
		log.Fatalf("Failed to initialize Kubernetes client: %v", err)
	}

	// 2. Initialize Triage Provider and the shared private metrics registry.
	// The registry is created before the provider so cache operations are
	// observable through the same authenticated metrics endpoint as scans.
	metricsRegistry := metrics.NewRegistry()
	triageProvider, err := buildTriageProvider(cfg, metricsRegistry)
	if err != nil {
		log.Fatalf("Failed to initialize triage provider: %s", sanitizeLog(cfg, err.Error()))
	}
	triageProvider = observeTriageProvider(triageProvider, providerMetricsObserver{registry: metricsRegistry})
	log.Printf("Selected Triage Provider: %s", sanitizeLog(cfg, triageProvider.Name()))

	// 3. Initialize Scanner, Remediation Engine, and Notifier
	log.Printf("Startup: Initializing typed scanner...")
	redactionSecrets := providerSecretValues(cfg)
	typedScanner := scanner.NewClusterScanner(k8sClient)
	var clusterScanner server.Scanner = typedScanner
	log.Printf("Startup: Initializing dynamic scanner...")
	if dynamicClient, dynamicErr := dynamic.NewForConfig(kubeRESTConfig); dynamicErr != nil {
		log.Printf("Optional dynamic Kubernetes client unavailable; continuing with typed analyzers: %s", sanitizeLog(cfg, dynamicErr.Error()))
	} else {
		clusterScanner = scanner.NewClusterScannerWithDynamicClient(k8sClient, dynamicClient)
	}
	if cfg.EnableAWSEKS {
		registrar, registrarOK := clusterScanner.(integration.AnalyzerRegistrar)
		if !registrarOK {
			log.Printf("AWS/EKS integration unavailable: scanner does not support analyzer registration")
		} else if activateErr := activateConfiguredIntegrations(context.Background(), cfg, registrar, redactionSecrets); activateErr != nil {
			log.Printf("AWS/EKS integration unavailable: %s", sanitizeLog(cfg, activateErr.Error()))
		} else {
			log.Printf("AWS/EKS read-only integration activated")
		}
	}
	var scanHistory scanner.HistoryStore
	historyDir := cfg.HistoryDir
	if historyDir == "" && strings.TrimSpace(cfg.DataDir) != "" {
		historyDir = filepath.Join(cfg.DataDir, "scan-history")
	}
	if historyDir != "" {
		log.Printf("Startup: Initializing scan history store at %s...", historyDir)
		scanHistory, err = scanner.NewFileHistoryStore(historyDir)
		if err != nil {
			log.Fatalf("Failed to initialize scan history store: %s", sanitizeLog(cfg, err.Error()))
		}
		if historyAware, ok := clusterScanner.(interface{ SetHistoryStore(scanner.HistoryStore) }); ok {
			historyAware.SetHistoryStore(scanHistory)
		} else {
			typedScanner.SetHistoryStore(scanHistory)
		}
	}
	var proposalStore remediation.ProposalStore
	if strings.TrimSpace(cfg.DataDir) != "" {
		log.Printf("Startup: Initializing proposal store at %s...", cfg.DataDir)
		proposalStore, err = remediation.NewFileProposalStore(cfg.DataDir)
		if err != nil {
			log.Fatalf("Failed to initialize durable proposal store: %s", sanitizeLog(cfg, err.Error()))
		}
	} else {
		log.Printf("Startup: Initializing memory proposal store...")
		proposalStore = remediation.NewMemoryProposalStore()
	}
	log.Printf("Startup: Initializing playbooks...")
	playbookService, closePlaybooks := startPlaybooks(context.Background(), cfg, triageProvider, metricsRegistry)
	defer closePlaybooks()
	verificationOptions := remediation.EngineVerificationOptions{}
	if playbookService != nil {
		verificationOptions.OutcomeObserver = playbookService
		verificationOptions.TerminalObserver = playbookAuditObserver{service: playbookService}
		verificationOptions.OutcomeObserverTimeout = time.Minute
	}
	log.Printf("Startup: Initializing remediation engine...")
	remediationEngine := remediation.NewEngineWithVerificationOptions(k8sClient, remediation.EngineOptions{Store: proposalStore}, verificationOptions)
	if playbookService != nil {
		playbookService.SetProposalCreator(remediationEngine)
	}
	log.Printf("Startup: Initializing webhook notifier...")
	webhookNotifier := notifier.NewWebhookNotifier(cfg.WebhookURL, cfg.PublicURL, redactionSecrets...)
	readiness := &startupReadiness{}

	// 4. Initialize Web Server & Dashboard
	log.Printf("Startup: Initializing API server on port %d...", cfg.Port)
	apiServer := server.NewServer(cfg.Port, clusterScanner, triageProvider, remediationEngine, webhookNotifier, server.ServerOptions{
		APIToken:              cfg.APIToken,
		RequireAPIToken:       cfg.RequireAPIToken,
		AllowedOrigins:        cfg.AllowedOrigins,
		TrustedClientIPHeader: cfg.TrustedClientIPHeader,
		TrustedProxyCIDRs:     cfg.TrustedProxyCIDRs,
		MaxBodyBytes:          cfg.MaxBodyBytes,
		RequestsPerMinute:     cfg.RequestsPerMinute,
		RequestBurst:          cfg.RequestBurst,
		RedactionSecrets:      redactionSecrets,
		Readiness:             readiness.Ready,
		Metrics:               metricsRegistry,
		Playbooks:             playbookService,
		Runtime: server.RuntimeSettings{
			LLMProvider:         cfg.LLMProvider,
			LLMMode:             cfg.LLMMode,
			LLMWireAPI:          effectiveWireAPI(cfg),
			LLMModel:            cfg.LLMModel,
			LLMBaseURLDisplay:   runtimeEndpointDisplay(cfg.LLMBaseURL),
			ScanInterval:        cfg.ScanInterval.String(),
			ScanJitter:          cfg.ScanJitter.String(),
			EventDrivenScanning: cfg.EventDrivenScanning,
			EventQueueCapacity:  cfg.EventQueueCapacity,
			EventDebounce:       cfg.EventDebounce.String(),
			CacheEnabled:        strings.TrimSpace(cfg.CacheDir) != "" && strings.TrimSpace(cfg.CacheEncryptionKey) != "",
			CacheConfigured:     strings.TrimSpace(cfg.CacheDir) != "",
		},
	})

	var grpcServer *grpc.Server
	var grpcListener net.Listener
	if cfg.GRPCPort > 0 {
		grpcTLS, tlsErr := loadGRPCTLSConfig(cfg)
		if tlsErr != nil {
			log.Fatalf("Failed to initialize gRPC TLS: %s", sanitizeLog(cfg, tlsErr.Error()))
		}
		grpcConfig := runtimeGRPCConfig{config: cfg}
		grpcServer, err = grpcapi.NewServer(clusterScanner, grpcapi.Options{
			APIToken:         cfg.APIToken,
			RequireAPIToken:  true,
			SecretValues:     redactionSecrets,
			Config:           grpcConfig,
			TLSConfig:        grpcTLS,
			EnableReflection: cfg.GRPCReflection,
		})
		if err != nil {
			log.Fatalf("Failed to initialize gRPC server: %s", sanitizeLog(cfg, err.Error()))
		}
		grpcListener, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
		if err != nil {
			log.Fatalf("Failed to bind gRPC server: %s", sanitizeLog(cfg, err.Error()))
		}
		go func() {
			if serveErr := grpcServer.Serve(grpcListener); serveErr != nil {
				log.Printf("gRPC server terminated: %s", sanitizeLog(cfg, serveErr.Error()))
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 5. Start Web UI & API Server
	log.Printf("Startup: Launching API server goroutine...")
	go func() {
		log.Printf("Startup: Calling apiServer.Start...")
		if err := apiServer.Start(ctx); err != nil && err != rest.ErrNotInCluster {
			log.Printf("HTTP server terminated: %s", sanitizeLog(cfg, err.Error()))
		}
	}()

	// 6. Start Background Proactive Scanner Loop
	log.Printf("Startup: Launching scanner loop goroutine...")
	go runScannerLoopWithLeader(ctx, cfg, clusterScanner, triageProvider, remediationEngine, webhookNotifier, apiServer, readiness, k8sClient)

	// Graceful Shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("Startup: SRE Agent initialization complete, waiting for signals...")
	<-sigCh
	log.Println("Received termination signal, shutting down Kubebee SRE Agent...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if grpcServer != nil {
		grpcDone := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(grpcDone)
		}()
		select {
		case <-grpcDone:
		case <-shutdownCtx.Done():
			grpcServer.Stop()
		}
	}
	if grpcListener != nil {
		_ = grpcListener.Close()
	}
	_ = apiServer.Shutdown(shutdownCtx)
	_ = remediationEngine.Close()
	_ = proposalStore.Close()
	if scanHistory != nil {
		_ = scanHistory.Close()
	}
	log.Println("Kubebee SRE Agent stopped cleanly.")
}

func hasVersionFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--version" || arg == "-version" {
			return true
		}
	}
	return false
}

func isCLIInvocation(args []string) bool {
	switch firstCLICommand(args) {
	case "version", "scan", "explain", "analyzers", "docs", "config", "filters", "cache", "mcp", "support-bundle", "dump", "generate":
		return true
	case "serve":
		return false
	}
	return false
}

func removeCommandArg(args []string, command string) []string {
	result := make([]string, 0, len(args))
	removed := false
	for _, arg := range args {
		if !removed && strings.EqualFold(strings.TrimSpace(arg), command) {
			removed = true
			continue
		}
		result = append(result, arg)
	}
	return result
}

func runCLIInvocation(args []string) error {
	args = normalizePlaybookEnabledArgs(args)
	commandName := firstCLICommand(args)
	configPath := cliConfigPath(args)
	options := CLIOptions{
		Version:    buildinfo.String(),
		ConfigPath: configPath,
		SecretValues: []string{
			os.Getenv("LLM_API_KEY"),
			os.Getenv("SRE_API_TOKEN"),
			os.Getenv("WEBHOOK_URL"),
			os.Getenv("SRE_CACHE_ENCRYPTION_KEY"),
			os.Getenv("LLM_CUSTOM_HEADERS"),
			os.Getenv("K8SGPT_CUSTOM_HEADERS"),
		},
	}

	// Configuration and filter commands are deliberately usable without a
	// Kubernetes connection. Scan/analyzer/explain commands initialize only the
	// dependencies needed by that command.
	cfg, err := loadResolvedConfig(args)
	if err != nil {
		return err
	}
	options.RuntimeConfig = cfg
	options.SecretValues = append(options.SecretValues, providerSecretValues(cfg)...)
	var history scanner.HistoryStore
	var client kubernetes.Interface
	var kubeConfig *rest.Config
	if commandName == "scan" || commandName == "analyzers" || commandName == "mcp" || commandName == "support-bundle" || commandName == "dump" {
		client, kubeConfig, err = buildKubeClients(cfg.Kubeconfig)
		if err != nil {
			return fmt.Errorf("initialize Kubernetes client: %w", err)
		}
	}
	if commandName == "explain" {
		options.Triage, err = buildTriageProvider(cfg)
		if err != nil {
			return fmt.Errorf("initialize triage provider: %w", err)
		}
	}
	if commandName == "scan" || commandName == "analyzers" || commandName == "mcp" || commandName == "support-bundle" || commandName == "dump" {
		typed := scanner.NewClusterScanner(client)
		historyDir := cfg.HistoryDir
		if historyDir == "" && strings.TrimSpace(cfg.DataDir) != "" {
			historyDir = filepath.Join(cfg.DataDir, "scan-history")
		}
		if historyDir != "" {
			history, err = scanner.NewFileHistoryStore(historyDir)
			if err != nil {
				return fmt.Errorf("initialize scan history: %w", err)
			}
			typed.SetHistoryStore(history)
			defer history.Close()
		}
		var clusterScanner cliScanner = typed
		if kubeConfig != nil {
			if dynamicClient, dynamicErr := dynamic.NewForConfig(kubeConfig); dynamicErr == nil {
				clusterScanner = scanner.NewClusterScannerWithDynamicClient(client, dynamicClient)
				if history != nil {
					clusterScanner.(interface{ SetHistoryStore(scanner.HistoryStore) }).SetHistoryStore(history)
				}
			}
		}
		if cfg.EnableAWSEKS {
			registrar, registrarOK := clusterScanner.(integration.AnalyzerRegistrar)
			if !registrarOK {
				return errors.New("AWS/EKS integration requires a scanner analyzer registrar")
			}
			if err := activateConfiguredIntegrations(context.Background(), cfg, registrar, options.SecretValues); err != nil {
				return err
			}
		}
		options.Scanner = clusterScanner
		options.BundleScanner = clusterScanner.(cliResourceScanner)
		if commandName == "mcp" {
			mcpScanner, scannerOK := clusterScanner.(server.Scanner)
			if !scannerOK {
				return errors.New("MCP stdio requires a scanner with the server read-only contract")
			}
			mcpServer := server.NewServer(0, mcpScanner, nil, nil, nil, server.ServerOptions{
				APIToken:         cfg.APIToken,
				RedactionSecrets: options.SecretValues,
			})
			options.MCPStdio = mcpServer.ServeStdio
		}
	}
	root := NewRootCommand(options)
	root.SetArgs(args)
	return root.Execute()
}

func firstCLICommand(args []string) string {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if strings.HasPrefix(arg, "-") {
			name := strings.TrimLeft(arg, "-")
			if equals := strings.IndexByte(name, '='); equals >= 0 {
				name = name[:equals]
			}
			if !strings.Contains(arg, "=") && cliFlagTakesValue(name) && index+1 < len(args) {
				index++
			}
			continue
		}
		return strings.ToLower(strings.TrimSpace(arg))
	}
	return ""
}

func cliFlagTakesValue(name string) bool {
	switch name {
	case "config", "api-token", "kubeconfig", "port", "grpc-port", "grpc-tls-cert-file", "grpc-tls-key-file", "grpc-tls-client-ca-file", "scan-interval", "scan-jitter", "leader-election-namespace", "leader-election-id", "leader-election-identity", "aws-region", "eks-cluster-name", "namespace", "llm-provider", "llm-mode", "llm-wire-api", "llm-api-key", "llm-model", "llm-base-url", "llm-organization", "llm-proxy-url", "llm-headers", "custom-headers", "harness-command", "webhook-url", "public-url", "allowed-origins", "trusted-client-ip-header", "trusted-proxy-cidrs", "max-body-bytes", "requests-per-minute", "request-burst", "data-dir", "cache-dir", "cache-ttl", "cache-max-entries", "cache-max-value-bytes", "include-namespaces", "exclude-namespaces", "label-selector", "resource-kinds", "resource-names", "analyzers", "scan-concurrency", "scan-timeout", "scan-history-dir", "database-url", "playbook-learning-mode", "playbook-min-confidence", "playbook-allowed-actions", "playbook-allowed-namespaces", "playbook-allowed-kinds", "playbook-max-source-bytes", "playbook-max-step-count", "playbook-max-total-text-bytes", "playbook-max-sources", "playbook-max-steps", "filter", "include-namespace", "exclude-namespace", "kind", "name", "analyzer", "concurrency", "timeout", "output", "interactive", "include-resource", "event-queue-capacity", "event-debounce", "llm-endpoint-allowlist":
		return true
	default:
		return false
	}
}

func cliConfigPath(args []string) string {
	for index, arg := range args {
		if arg == "--config" && index+1 < len(args) {
			return args[index+1]
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config=")
		}
	}
	return ""
}

func loadResolvedConfig(args []string) (*config.Config, error) {
	cfg, _, err := config.ResolveConfig(config.ResolveOptions{
		Path:  cliConfigPath(args),
		Flags: configFlagsFromArgs(args),
	})
	return cfg, err
}

func configFlagsFromArgs(args []string) map[string]string {
	known := map[string]string{
		"api-token": "api-token", "kubeconfig": "kubeconfig", "port": "port", "grpc-port": "grpc-port", "grpc-tls-cert-file": "grpc-tls-cert-file", "grpc-tls-key-file": "grpc-tls-key-file", "grpc-tls-client-ca-file": "grpc-tls-client-ca-file", "grpc-reflection": "grpc-reflection", "scan-interval": "scan-interval", "scan-jitter": "scan-jitter", "event-driven-scanning": "event-driven-scanning", "event-queue-capacity": "event-queue-capacity", "event-debounce": "event-debounce",
		"leader-election": "leader-election", "leader-election-namespace": "leader-election-namespace", "leader-election-id": "leader-election-id", "leader-election-identity": "leader-election-identity",
		"enable-aws-eks": "enable-aws-eks", "aws-region": "aws-region", "eks-cluster-name": "eks-cluster-name",
		"namespace": "namespace", "llm-provider": "llm-provider", "llm-mode": "llm-mode", "llm-wire-api": "llm-wire-api", "llm-api-key": "llm-api-key", "llm-model": "llm-model",
		"llm-base-url": "llm-base-url", "llm-endpoint-allowlist": "llm-endpoint-allowlist", "llm-organization": "llm-organization", "llm-proxy-url": "llm-proxy-url", "llm-headers": "llm-headers", "custom-headers": "llm-headers",
		"harness-command": "harness-command", "webhook-url": "webhook-url", "public-url": "public-url",
		"require-api-token": "require-api-token", "allowed-origins": "allowed-origins", "trusted-client-ip-header": "trusted-client-ip-header",
		"trusted-proxy-cidrs": "trusted-proxy-cidrs", "max-body-bytes": "max-body-bytes", "requests-per-minute": "requests-per-minute",
		"request-burst": "request-burst", "data-dir": "data-dir", "cache-dir": "cache-dir", "cache-ttl": "cache-ttl", "cache-max-entries": "cache-max-entries", "cache-max-value-bytes": "cache-max-value-bytes", "include-namespaces": "include-namespaces", "exclude-namespaces": "exclude-namespaces",
		"label-selector": "label-selector", "resource-kinds": "resource-kinds", "resource-names": "resource-names", "analyzers": "analyzers",
		"scan-concurrency": "scan-concurrency", "scan-timeout": "scan-timeout", "scan-history-dir": "scan-history-dir",
		"database-url": "database-url", "playbook-enabled": "playbook-enabled", "playbook-learning-mode": "playbook-learning-mode", "playbook-min-confidence": "playbook-min-confidence",
		"playbook-allowed-actions": "playbook-allowed-actions", "playbook-allowed-namespaces": "playbook-allowed-namespaces", "playbook-allowed-kinds": "playbook-allowed-kinds",
		"playbook-max-source-bytes": "playbook-max-source-bytes", "playbook-max-step-count": "playbook-max-step-count", "playbook-max-total-text-bytes": "playbook-max-total-text-bytes",
		"playbook-max-sources": "playbook-max-source-bytes", "playbook-max-steps": "playbook-max-step-count",
	}
	result := make(map[string]string)
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		value := ""
		if equals := strings.IndexByte(name, '='); equals >= 0 {
			value = name[equals+1:]
			name = name[:equals]
		} else if name == "playbook-enabled" && index+1 < len(args) && isBoolLiteral(args[index+1]) {
			value = strings.ToLower(strings.TrimSpace(args[index+1]))
			index++
		} else if index+1 < len(args) && cliFlagTakesValue(name) && cliTokenCanBeValue(args[index+1]) {
			value = args[index+1]
			index++
		} else if name == "require-api-token" || name == "leader-election" || name == "enable-aws-eks" || name == "grpc-reflection" || name == "playbook-enabled" || name == "event-driven-scanning" {
			value = "true"
		} else {
			continue
		}
		if canonical, ok := known[name]; ok {
			if repeatableConfigFlag(canonical) {
				if existing, exists := result[canonical]; exists && existing != "" && value != "" {
					result[canonical] = existing + "," + value
				} else {
					result[canonical] = value
				}
			} else {
				result[canonical] = value
			}
		}
	}
	return result
}

func repeatableConfigFlag(name string) bool {
	switch name {
	case "llm-headers", "playbook-allowed-actions", "playbook-allowed-namespaces", "playbook-allowed-kinds":
		return true
	default:
		return false
	}
}

func cliTokenCanBeValue(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return true
	}
	if !strings.HasPrefix(token, "-") {
		return true
	}
	_, err := strconv.ParseFloat(token, 64)
	return err == nil
}

func normalizePlaybookEnabledArgs(args []string) []string {
	normalized := append([]string(nil), args...)
	for index := 0; index+1 < len(normalized); index++ {
		if normalized[index] != "--playbook-enabled" || !isBoolLiteral(normalized[index+1]) {
			continue
		}
		normalized[index] += "=" + strings.ToLower(strings.TrimSpace(normalized[index+1]))
		normalized = append(normalized[:index+1], normalized[index+2:]...)
	}
	return normalized
}

func isBoolLiteral(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "true") || strings.EqualFold(strings.TrimSpace(value), "false")
}

func activateConfiguredIntegrations(ctx context.Context, cfg *config.Config, registrar integration.AnalyzerRegistrar, secretValues []string) error {
	if cfg == nil || !cfg.EnableAWSEKS {
		return nil
	}
	if registrar == nil {
		return errors.New("scanner analyzer registrar is unavailable")
	}
	awsFactory, err := integration.NewAWSFactory(ctx, integration.AWSOptions{
		Region:         cfg.AWSRegion,
		ClusterName:    cfg.EKSClusterName,
		KubeconfigPath: cfg.Kubeconfig,
		SecretValues:   append([]string(nil), secretValues...),
	})
	if err != nil {
		return fmt.Errorf("initialize AWS/EKS integration: %w", err)
	}
	registry := integration.NewRegistry()
	if err := registry.Register(awsFactory); err != nil {
		return fmt.Errorf("register AWS/EKS integration: %w", err)
	}
	if err := registry.Activate(ctx, "aws-eks", registrar); err != nil {
		return fmt.Errorf("activate AWS/EKS integration: %w", err)
	}
	return nil
}

func loadGRPCTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("gRPC configuration is unavailable")
	}
	certPath := strings.TrimSpace(cfg.GRPCTLSCertFile)
	keyPath := strings.TrimSpace(cfg.GRPCTLSKeyFile)
	caPath := strings.TrimSpace(cfg.GRPCTLSClientCAFile)
	if certPath == "" && keyPath == "" && caPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("both gRPC TLS certificate and key files are required")
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, errors.New("gRPC TLS certificate or key could not be loaded")
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}
	if caPath == "" {
		return config, nil
	}
	data, err := os.ReadFile(caPath)
	if err != nil {
		return nil, errors.New("gRPC client CA could not be loaded")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("gRPC client CA contains no valid certificates")
	}
	config.ClientCAs = pool
	config.ClientAuth = tls.RequireAndVerifyClientCert
	return config, nil
}

func cliRuntimeArgs(args []string) []string {
	known := map[string]bool{
		"kubeconfig": true, "port": true, "grpc-port": true, "grpc-tls-cert-file": true, "grpc-tls-key-file": true, "grpc-tls-client-ca-file": true, "grpc-reflection": true, "scan-interval": true, "scan-jitter": true, "event-driven-scanning": true, "event-queue-capacity": true, "event-debounce": true,
		"leader-election": true, "leader-election-namespace": true, "leader-election-id": true, "leader-election-identity": true, "namespace": true,
		"enable-aws-eks": true, "aws-region": true, "eks-cluster-name": true,
		"llm-provider": true, "llm-mode": true, "llm-wire-api": true, "llm-api-key": true, "llm-model": true, "llm-base-url": true, "llm-endpoint-allowlist": true, "llm-organization": true, "llm-proxy-url": true, "llm-headers": true, "custom-headers": true,
		"harness-command": true, "webhook-url": true, "public-url": true, "require-api-token": true,
		"allowed-origins": true, "trusted-client-ip-header": true, "trusted-proxy-cidrs": true,
		"max-body-bytes": true, "requests-per-minute": true, "request-burst": true,
		"data-dir": true, "cache-dir": true, "cache-ttl": true, "cache-max-entries": true, "cache-max-value-bytes": true, "include-namespaces": true, "exclude-namespaces": true,
		"label-selector": true, "resource-kinds": true, "resource-names": true, "analyzers": true,
		"scan-concurrency": true, "scan-timeout": true, "scan-history-dir": true,
		"database-url": true, "playbook-enabled": true, "playbook-learning-mode": true, "playbook-min-confidence": true,
		"playbook-allowed-actions": true, "playbook-allowed-namespaces": true, "playbook-allowed-kinds": true,
		"playbook-max-source-bytes": true, "playbook-max-step-count": true, "playbook-max-total-text-bytes": true,
		"playbook-max-sources": true, "playbook-max-steps": true,
	}
	result := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if equals := strings.IndexByte(name, '='); equals >= 0 {
			name = name[:equals]
		}
		if !known[name] {
			continue
		}
		result = append(result, arg)
		if !strings.Contains(arg, "=") && index+1 < len(args) && !strings.HasPrefix(args[index+1], "-") {
			result = append(result, args[index+1])
			index++
		}
	}
	return result
}

func runScannerLoop(
	ctx context.Context,
	cfg *config.Config,
	sc server.Scanner,
	tp triage.TriageProvider,
	eng *remediation.Engine,
	notif *notifier.WebhookNotifier,
	srv *server.Server,
	readiness *startupReadiness,
) {
	runScannerLoopWithLeader(ctx, cfg, sc, tp, eng, notif, srv, readiness, nil)
}

func runScannerLoopWithLeader(
	ctx context.Context,
	cfg *config.Config,
	sc server.Scanner,
	tp triage.TriageProvider,
	eng *remediation.Engine,
	notif *notifier.WebhookNotifier,
	srv *server.Server,
	readiness *startupReadiness,
	client kubernetes.Interface,
) {
	if cfg == nil || cfg.ScanInterval <= 0 || sc == nil || tp == nil || eng == nil || srv == nil || readiness == nil {
		return
	}
	runner, err := scheduler.New(scheduler.Options{
		Interval: cfg.ScanInterval,
		Jitter:   cfg.ScanJitter,
		Job: func(scanCtx context.Context) error {
			err := runSingleScan(scanCtx, cfg, sc, tp, eng, notif, srv)
			readiness.MarkScanResult(err)
			if err != nil && scanCtx.Err() == nil {
				log.Printf("Scheduled scan failed: %s", sanitizeLog(cfg, err.Error()))
			}
			return nil
		},
	})
	if err != nil {
		log.Printf("Scheduled scanner disabled: %s", sanitizeLog(cfg, err.Error()))
		return
	}
	if cfg.LeaderElection && client == nil {
		log.Printf("Scheduled scanner disabled: Kubernetes client is required for leader election")
		return
	}
	runScheduledScans := func(scanCtx context.Context) error {
		return runScheduledScansWithTriggers(scanCtx, cfg, client, runner, sc, tp, eng, notif, srv, readiness)
	}
	if !cfg.LeaderElection {
		if err := runScheduledScans(ctx); err != nil && ctx.Err() == nil {
			log.Printf("Scheduled scanner stopped: %s", sanitizeLog(cfg, err.Error()))
		}
		return
	}
	namespace := leaderElectionNamespace(cfg)
	identity := strings.TrimSpace(cfg.LeaderElectionIdentity)
	if identity == "" {
		identity, _ = os.Hostname()
	}
	if identity == "" {
		identity = "sre-agent"
	}
	lease, err := scheduler.NewKubernetesLease(scheduler.LeaseOptions{
		Client:    client,
		Namespace: namespace,
		Name:      cfg.LeaderElectionID,
		Identity:  identity,
	})
	if err != nil {
		log.Printf("Leader election disabled: %s", sanitizeLog(cfg, err.Error()))
		return
	}
	if err := lease.Run(ctx, runScheduledScans); err != nil && ctx.Err() == nil {
		log.Printf("Leader election stopped: %s", sanitizeLog(cfg, err.Error()))
	}
}

func runScheduledScansWithTriggers(
	ctx context.Context,
	cfg *config.Config,
	client kubernetes.Interface,
	runner *scheduler.Runner,
	sc server.Scanner,
	tp triage.TriageProvider,
	eng *remediation.Engine,
	notif *notifier.WebhookNotifier,
	srv *server.Server,
	readiness *startupReadiness,
) error {
	if cfg == nil || runner == nil {
		return scheduler.ErrJobRequired
	}
	if !cfg.EventDrivenScanning || client == nil {
		return runner.Run(ctx)
	}
	queueCapacity := cfg.EventQueueCapacity
	if queueCapacity <= 0 {
		queueCapacity = scheduler.DefaultTriggerQueueCapacity
	}
	debounce := cfg.EventDebounce
	if debounce < 0 {
		debounce = scheduler.DefaultTriggerDebounce
	}
	queue, err := scheduler.NewTriggerQueue(scheduler.TriggerQueueOptions{
		Capacity: queueCapacity,
		Debounce: debounce,
	})
	if err != nil {
		log.Printf("Event-triggered scanner disabled: %s", sanitizeLog(cfg, err.Error()))
		return runner.Run(ctx)
	}
	watchNamespace := ""
	if len(cfg.IncludeNamespaces) == 1 && len(cfg.ExcludeNamespaces) == 0 {
		watchNamespace = cfg.IncludeNamespaces[0]
	}
	source, err := scheduler.NewKubernetesTriggerSource(scheduler.KubernetesTriggerSourceOptions{
		Client: client,
		Sink:   queue,
		Filter: func(trigger scheduler.Trigger) bool {
			_, ok := scheduler.PlanForTrigger(cfg.ScanPlan(), trigger)
			return ok
		},
		Namespace: watchNamespace,
	})
	if err != nil {
		log.Printf("Event-triggered scanner disabled: %s", sanitizeLog(cfg, err.Error()))
		return runner.Run(ctx)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	sourceDone := make(chan error, 1)
	go func() { sourceDone <- source.Run(runCtx) }()

	triggerJob := func(scanCtx context.Context, trigger scheduler.Trigger) error {
		plan, ok := scheduler.PlanForTrigger(cfg.ScanPlan(), trigger)
		if !ok {
			return nil
		}
		err := runSingleScanWithPlan(scanCtx, cfg, sc, tp, eng, notif, srv, plan)
		readiness.MarkScanResult(err)
		if err != nil && scanCtx.Err() == nil {
			log.Printf("Event-triggered scan failed for %s/%s/%s: %s", sanitizeLog(cfg, trigger.Resource), sanitizeLog(cfg, trigger.Namespace), sanitizeLog(cfg, trigger.Name), sanitizeLog(cfg, err.Error()))
		}
		return err
	}
	periodicErr := runner.RunWithTriggers(runCtx, queue, triggerJob)
	cancel()
	<-sourceDone
	return periodicErr
}

func leaderElectionNamespace(cfg *config.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.LeaderElectionNamespace) != "" {
		return strings.TrimSpace(cfg.LeaderElectionNamespace)
	}
	if namespace := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); namespace != "" {
		return namespace
	}
	if namespaceBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if namespace := strings.TrimSpace(string(namespaceBytes)); namespace != "" {
			return namespace
		}
	}
	if cfg != nil {
		return strings.TrimSpace(cfg.Namespace)
	}
	return ""
}

func runSingleScan(
	ctx context.Context,
	cfg *config.Config,
	sc server.Scanner,
	tp triage.TriageProvider,
	eng *remediation.Engine,
	notif *notifier.WebhookNotifier,
	srv *server.Server,
) error {
	if cfg == nil {
		return fmt.Errorf("scan dependencies are unavailable")
	}
	return runSingleScanWithPlan(ctx, cfg, sc, tp, eng, notif, srv, cfg.ScanPlan())
}

func runSingleScanWithPlan(
	ctx context.Context,
	cfg *config.Config,
	sc server.Scanner,
	tp triage.TriageProvider,
	eng *remediation.Engine,
	notif *notifier.WebhookNotifier,
	srv *server.Server,
	plan scanplan.Plan,
) error {
	if cfg == nil || sc == nil || tp == nil || eng == nil || srv == nil {
		return fmt.Errorf("scan dependencies are unavailable")
	}
	namespace := plan.NamespaceArgument()
	if namespace == "" {
		namespace = cfg.Namespace
	}
	log.Printf("Running proactive cluster scan (namespace: '%s')...", sanitizeLog(cfg, namespace))
	timeout := plan.Timeout
	if timeout <= 0 || timeout > scanplan.MaxScanTimeout {
		timeout = scanplan.DefaultScanTimeout
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	report, err := sc.ScanWithPlan(scanCtx, plan)
	if err != nil {
		log.Printf("Scanner encountered error: %s", sanitizeLog(cfg, err.Error()))
		return err
	}
	if report == nil {
		return fmt.Errorf("scanner returned an empty report")
	}
	issues := report.Issues

	srv.UpdateScanResults(issues)
	log.Printf("Scan complete: %d anomalies detected in cluster.", len(issues))

	previous, err := eng.ListProposalsWithError()
	if err != nil {
		return fmt.Errorf("proposal state unavailable")
	}
	known := make(map[string]bool, len(previous))
	for _, proposal := range previous {
		known[proposal.ID] = true
	}

	for _, issue := range issues {
		sanitizedIssue := scanner.SanitizeIssue(issue, providerSecretValues(cfg)...).AsIssue()
		var resolver playbookResolver
		if service := srv.PlaybookService(); service != nil {
			resolver = service
		}
		handled, proposal, resolveErr := resolveScanPlaybook(scanCtx, cfg, resolver, sanitizedIssue)
		if handled {
			if resolveErr != nil {
				log.Printf("Playbook resolution unavailable or blocked for issue %s", sanitizeLog(cfg, issue.ID))
			}
			if proposal == nil {
				continue
			}
		} else {
			diag, err := tp.Diagnose(scanCtx, sanitizedIssue)
			if err != nil {
				log.Printf("Triage failed for issue %s: %s", sanitizeLog(cfg, issue.ID), sanitizeLog(cfg, err.Error()))
				continue
			}
			proposal = eng.CreateProposal(issue, diag)
		}
		if proposal == nil {
			log.Printf("Proposal creation rejected for issue %s", sanitizeLog(cfg, issue.ID))
			continue
		}
		log.Printf("Proposal %s created for %s/%s (Action: %s, Status: %s)",
			sanitizeLog(cfg, proposal.ID), sanitizeLog(cfg, proposal.Kind), sanitizeLog(cfg, proposal.Name), sanitizeLog(cfg, string(proposal.Diagnosis.ActionType)), sanitizeLog(cfg, string(proposal.Status)))

		// Dispatch notification with approval link
		if notif == nil {
			continue
		}
		if err := notifyNewProposal(scanCtx, notif, proposal, known); err != nil {
			log.Printf("Failed to dispatch notification for proposal %s: %s", sanitizeLog(cfg, proposal.ID), sanitizeLog(cfg, err.Error()))
		}
	}
	return nil
}

func providerProfileFromConfig(cfg *config.Config) triage.ProviderProfile {
	if cfg == nil {
		return triage.ProviderProfile{}
	}
	return triage.ProviderProfile{
		EndpointAllowlist: append([]string(nil), cfg.LLMEndpointAllowlist...),
		Provider:          cfg.LLMProvider,
		Mode:              triage.ProviderMode(strings.TrimSpace(cfg.LLMMode)),
		WireAPI:           triage.WireAPI(strings.TrimSpace(cfg.LLMWireAPI)),
		Model:             cfg.LLMModel,
		Endpoint:          cfg.LLMBaseURL,
		Organization:      cfg.LLMOrganization,
		ProxyURL:          cfg.LLMProxyURL,
		APIKey:            cfg.LLMAPIKey,
		AWSRegion:         cfg.AWSRegion,
		Command:           cfg.HarnessCommand,
		SecretValues:      providerSecretValues(cfg),
	}
}

func buildTriageProvider(cfg *config.Config, observers ...cache.OperationObserver) (triage.TriageProvider, error) {
	if cfg == nil {
		return nil, triage.ErrProviderValidation
	}
	profile := providerProfileFromConfig(cfg)
	customHeaders, err := parseProviderHeaders(cfg.LLMHeaders)
	if err != nil {
		return nil, err
	}
	profile.CustomHeaders = customHeaders
	providerName := strings.ToLower(strings.TrimSpace(cfg.LLMProvider))
	if strings.TrimSpace(cfg.LLMAPIKey) == "" {
		switch providerName {
		case "claude", "anthropic", "codex", "openai", "deepseek", "groq":
			log.Printf("Notice: no API key provided for '%s'; using the internal deterministic SRE rule engine.", sanitizeLog(cfg, providerName))
			return configureTriageCache(cfg, triage.NewRuleBasedProvider(providerSecretValues(cfg)...), observers...)
		case "harness":
			if strings.TrimSpace(cfg.HarnessCommand) == "" {
				log.Printf("Notice: no harness command provided; using the internal deterministic SRE rule engine.")
				return configureTriageCache(cfg, triage.NewRuleBasedProvider(providerSecretValues(cfg)...), observers...)
			}
		}
	}
	provider, err := triage.NewProviderFromProfileWithAWS(profile, triage.AWSProviderOptions{Region: cfg.AWSRegion})
	if err != nil {
		return nil, err
	}
	if normalized, normalizeErr := profile.Normalize(); normalizeErr == nil && normalized.Mode == triage.ProviderModeRemote && strings.TrimSpace(normalized.APIKey) == "" {
		log.Printf("Notice: provider '%s' has no API key; using its configured unauthenticated mode or returning provider errors.", sanitizeLog(cfg, normalized.Provider))
	}
	return configureTriageCache(cfg, provider, observers...)
}

const maxProviderHeaderSpecs = 64

func parseProviderHeaders(values []string) (http.Header, error) {
	if len(values) > maxProviderHeaderSpecs {
		return nil, triage.ErrProviderValidation
	}
	headers := make(http.Header)
	for _, raw := range values {
		key, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, triage.ErrProviderValidation
		}
		headers.Add(strings.TrimSpace(key), strings.TrimSpace(value))
	}
	if len(headers) == 0 {
		return nil, nil
	}
	// Reuse the provider's maintained header policy, including forbidden
	// hop-by-hop fields and CRLF/size checks.
	if err := (triage.ProviderProfile{
		Provider:      "noop",
		Mode:          triage.ProviderModeNoOp,
		CustomHeaders: headers,
	}).Validate(); err != nil {
		return nil, triage.ErrProviderValidation
	}
	return headers, nil
}

func configureTriageCache(cfg *config.Config, provider triage.TriageProvider, observers ...cache.OperationObserver) (triage.TriageProvider, error) {
	if cfg == nil || provider == nil {
		return provider, nil
	}
	directory := strings.TrimSpace(cfg.CacheDir)
	key := strings.TrimSpace(cfg.CacheEncryptionKey)
	if directory == "" && key == "" {
		return provider, nil
	}
	if directory == "" || key == "" {
		return nil, errors.New("SRE_CACHE_DIR and SRE_CACHE_ENCRYPTION_KEY must both be configured to enable provider-result caching")
	}
	fileCache, err := cache.NewFileCache(directory, []byte(key),
		cache.WithDefaultTTL(cfg.CacheTTL),
		cache.WithMaxEntries(cfg.CacheMaxEntries),
		cache.WithMaxValueBytes(cfg.CacheMaxValueBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize provider-result cache: %w", err)
	}
	var resultCache cache.Cache = fileCache
	for _, observer := range observers {
		if observer != nil {
			resultCache = cache.NewObservedCache(resultCache, observer)
			break
		}
	}
	return triage.NewCachedProvider(provider, resultCache,
		triage.WithCachedProviderModel(cfg.LLMModel),
		triage.WithCachedProviderEndpoint(cfg.LLMBaseURL),
		triage.WithCachedProviderSecrets(providerSecretValues(cfg)...),
	)
}

func sanitizeLog(cfg *config.Config, message string) string {
	if cfg == nil {
		return sanitizer.DefaultRedactor().SafeLogValue(message)
	}
	return sanitizer.RedactorForSecrets(providerSecretValues(cfg)...).SafeLogValue(message)
}

func providerSecretValues(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	values := []string{cfg.LLMAPIKey, cfg.APIToken, cfg.WebhookURL, cfg.CacheEncryptionKey, cfg.DatabaseURL}
	values = append(values, urlSecretVariants(cfg.WebhookURL)...)
	values = append(values, urlSecretVariants(cfg.DatabaseURL)...)
	for _, raw := range cfg.LLMHeaders {
		if _, value, ok := strings.Cut(raw, ":"); ok {
			values = append(values, strings.TrimSpace(value))
		}
	}
	return values
}

func urlSecretVariants(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var values []string
	if parsed.User != nil {
		userInfo := parsed.User.String()
		if userInfo != "" {
			values = append(values, userInfo)
		}
		username := parsed.User.Username()
		password, hasPassword := parsed.User.Password()
		if username != "" && hasPassword {
			values = append(values, username+":"+password)
		}
		if hasPassword {
			values = append(values, password)
		}
	}
	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		segment = strings.TrimSpace(segment)
		if len(segment) >= 8 {
			values = append(values, segment)
		}
	}
	for _, items := range parsed.Query() {
		for _, item := range items {
			if len(item) >= 8 {
				values = append(values, item)
			}
		}
	}
	return values
}

func buildKubeClient(kubeconfigPath string) (kubernetes.Interface, error) {
	client, _, err := buildKubeClients(kubeconfigPath)
	return client, err
}

func buildKubeClients(kubeconfigPath string) (kubernetes.Interface, *rest.Config, error) {
	k8sCfg, err := buildKubeRESTConfig(kubeconfigPath)
	if err != nil {
		return nil, nil, err
	}
	client, err := kubernetes.NewForConfig(k8sCfg)
	if err != nil {
		return nil, nil, err
	}
	return client, k8sCfg, nil
}

func buildKubeRESTConfig(kubeconfigPath string) (*rest.Config, error) {
	var k8sCfg *rest.Config
	var err error

	if kubeconfigPath != "" {
		k8sCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		k8sCfg, err = rest.InClusterConfig()
		if err != nil {
			// Fallback to default kubeconfig path if outside cluster
			home, _ := os.UserHomeDir()
			defaultKubeconfig := home + "/.kube/config"
			if _, statErr := os.Stat(defaultKubeconfig); statErr == nil {
				k8sCfg, err = clientcmd.BuildConfigFromFlags("", defaultKubeconfig)
			}
		}
	}

	if err != nil {
		return nil, err
	}

	k8sCfg.Timeout = 10 * time.Second
	return k8sCfg, nil
}

// The scan is serialized by the scheduler; the durable proposal IDs survive restarts.
// Transport retries stay within the notifier. Durable delivery is handled by the orchestrator outbox.
type proposalCreationNotifier interface {
	NotifyProposalCreated(context.Context, *remediation.Proposal) error
}

func notifyNewProposal(ctx context.Context, notifier proposalCreationNotifier, proposal *remediation.Proposal, known map[string]bool) error {
	if proposal == nil || known[proposal.ID] {
		return nil
	}
	known[proposal.ID] = true
	return notifier.NotifyProposalCreated(ctx, proposal)
}
