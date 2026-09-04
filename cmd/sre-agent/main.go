package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/notifier"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/server"
	"github.com/kubebee-com/sre/pkg/triage"
)

func main() {
	cfg := config.LoadConfig()
	log.Println("Initializing Kubebee SRE Agent...")

	// 1. Initialize Kubernetes Client
	k8sClient, err := buildKubeClient(cfg.Kubeconfig)
	if err != nil {
		log.Fatalf("Failed to initialize Kubernetes client: %v", err)
	}

	// 2. Initialize Triage Provider
	triageProvider := buildTriageProvider(cfg)
	log.Printf("Selected Triage Provider: %s", triageProvider.Name())

	// 3. Initialize Scanner, Remediation Engine, and Notifier
	clusterScanner := scanner.NewClusterScanner(k8sClient)
	remediationEngine := remediation.NewEngine(k8sClient)
	webhookNotifier := notifier.NewWebhookNotifier(cfg.WebhookURL, cfg.PublicURL)

	// 4. Initialize Web Server & Dashboard
	apiServer := server.NewServer(cfg.Port, clusterScanner, triageProvider, remediationEngine)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 5. Start Background Proactive Scanner Loop
	go runScannerLoop(ctx, cfg, clusterScanner, triageProvider, remediationEngine, webhookNotifier, apiServer)

	// 6. Start Web UI & API Server
	go func() {
		if err := apiServer.Start(ctx); err != nil && err != rest.ErrNotInCluster {
			log.Printf("HTTP server terminated: %v", err)
		}
	}()

	// Graceful Shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Received termination signal, shutting down Kubebee SRE Agent...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = apiServer.Shutdown(shutdownCtx)
	log.Println("Kubebee SRE Agent stopped cleanly.")
}

func runScannerLoop(
	ctx context.Context,
	cfg *config.Config,
	sc *scanner.ClusterScanner,
	tp triage.TriageProvider,
	eng *remediation.Engine,
	notif *notifier.WebhookNotifier,
	srv *server.Server,
) {
	ticker := time.NewTicker(cfg.ScanInterval)
	defer ticker.Stop()

	// Initial scan on startup
	runSingleScan(ctx, cfg, sc, tp, eng, notif, srv)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runSingleScan(ctx, cfg, sc, tp, eng, notif, srv)
		}
	}
}

func runSingleScan(
	ctx context.Context,
	cfg *config.Config,
	sc *scanner.ClusterScanner,
	tp triage.TriageProvider,
	eng *remediation.Engine,
	notif *notifier.WebhookNotifier,
	srv *server.Server,
) {
	log.Printf("Running proactive cluster scan (namespace: '%s')...", cfg.Namespace)
	scanCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	issues, err := sc.Scan(scanCtx, cfg.Namespace)
	if err != nil {
		log.Printf("Scanner encountered error: %v", err)
		return
	}

	srv.SetActiveIssues(issues)
	log.Printf("Scan complete: %d anomalies detected in cluster.", len(issues))

	for _, issue := range issues {
		diag, err := tp.Diagnose(scanCtx, issue)
		if err != nil {
			log.Printf("Triage failed for issue %s: %v", issue.ID, err)
			continue
		}

		proposal := eng.CreateProposal(issue, diag)
		log.Printf("Proposal %s created for %s/%s (Action: %s, Status: %s)",
			proposal.ID, proposal.Kind, proposal.Name, proposal.Diagnosis.ActionType, proposal.Status)

		// Dispatch notification with approval link
		if err := notif.NotifyProposalCreated(scanCtx, proposal); err != nil {
			log.Printf("Failed to dispatch notification for proposal %s: %v", proposal.ID, err)
		}
	}
}

func buildTriageProvider(cfg *config.Config) triage.TriageProvider {
	switch cfg.LLMProvider {
	case "claude":
		if cfg.LLMAPIKey != "" {
			return triage.NewClaudeProvider(cfg.LLMAPIKey, cfg.LLMModel, cfg.LLMBaseURL)
		}
	case "codex", "openai":
		if cfg.LLMAPIKey != "" {
			return triage.NewCodexProvider(cfg.LLMAPIKey, cfg.LLMModel, cfg.LLMBaseURL)
		}
	case "deepseek":
		if cfg.LLMAPIKey != "" {
			return triage.NewDeepSeekProvider(cfg.LLMAPIKey, cfg.LLMModel, cfg.LLMBaseURL)
		}
	case "harness":
		if cfg.HarnessCommand != "" {
			return triage.NewHarnessProvider(cfg.HarnessCommand, nil)
		}
	}

	log.Printf("Notice: No API key provided for '%s', using internal deterministic SRE rule engine.", cfg.LLMProvider)
	return triage.NewRuleBasedProvider()
}

func buildKubeClient(kubeconfigPath string) (kubernetes.Interface, error) {
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
	return kubernetes.NewForConfig(k8sCfg)
}
