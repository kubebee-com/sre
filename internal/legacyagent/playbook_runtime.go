package legacyagent

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/metrics"
	"github.com/kubebee-com/sre/pkg/playbook"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

type playbookResolver interface {
	Resolve(context.Context, *scanner.Issue, string) (playbook.ResolveResult, error)
}

// Enabled catalogs own automatic resolution, including no-match and outage cases.
// Legacy diagnosis must not create an alternative mutation around this policy.
func resolveScanPlaybook(ctx context.Context, cfg *config.Config, service playbookResolver, issue *scanner.Issue) (bool, *remediation.Proposal, error) {
	if cfg == nil || !cfg.PlaybookEnabled {
		return false, nil, nil
	}
	if service == nil {
		return true, nil, playbook.ErrServiceUnavailable
	}
	result, err := service.Resolve(ctx, issue, "scanner")
	return true, result.Proposal, err
}

func playbookSettings(cfg *config.Config) playbook.ServiceSettings {
	return playbook.ServiceSettings{
		Enabled: cfg.PlaybookEnabled, MinConfidence: cfg.PlaybookMinConfidence,
		MaxSteps: cfg.PlaybookMaxStepCount, MaxSourceBytes: cfg.PlaybookMaxSourceBytes, MaxTotalTextBytes: cfg.PlaybookMaxTotalTextBytes,
		LearningMode:      playbook.LearningMode(cfg.PlaybookLearningMode),
		AllowedActions:    append([]string(nil), cfg.PlaybookAllowedActions...),
		AllowedNamespaces: append([]string(nil), cfg.PlaybookAllowedNamespaces...),
		AllowedKinds:      append([]string(nil), cfg.PlaybookAllowedKinds...),
	}
}

func startPlaybooks(ctx context.Context, cfg *config.Config, provider triage.TriageProvider, registry *metrics.Registry) (*playbook.Service, func()) {
	if !cfg.PlaybookEnabled {
		return nil, func() {}
	}
	var catalog playbook.Catalog
	closeCatalog := func() {}
	startup, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	pg, err := playbook.NewPostgresCatalog(startup, cfg.DatabaseURL, playbook.WithCatalogSecrets(providerSecretValues(cfg)...))
	if err != nil {
		// Database errors can contain connection credentials; report only fixed text.
		log.Print("Playbook catalog unavailable; automatic proposals disabled, scanning remains available")
	} else {
		catalog = pg
		closeCatalog = pg.Close
	}
	runner := playbookTaskRunner(provider)
	switch strings.ToLower(strings.TrimSpace(cfg.LLMProvider)) {
	case "claude", "anthropic", "rule", "noop", "bedrock", "aws-bedrock", "sagemaker", "aws-sagemaker", "cohere", "gemini", "huggingface", "ibm", "oci", "vertex":
		runner = nil
	}
	service := playbook.NewService(catalog, runner, playbook.ServiceOptions{Settings: playbookSettings(cfg), Secrets: providerSecretValues(cfg), Observer: registry, ProviderName: cfg.LLMProvider, Timeout: 30 * time.Second})
	return service, closeCatalog
}

// The terminal observer audits all outcomes; the separate verified observer learns.
type playbookAuditObserver struct{ service *playbook.Service }

func (o playbookAuditObserver) ObserveOutcome(ctx context.Context, p *remediation.Proposal) error {
	return o.service.RecordOutcome(ctx, p)
}

func playbookTaskRunner(provider triage.TriageProvider) triage.StructuredTaskRunner {
	if provider == nil {
		return nil
	}
	// Observation/cache wrappers preserve the underlying provider display name.
	switch provider.Name() {
	case "Rule-Based SRE Engine", "NoOp (explicitly disabled)":
		return nil
	}
	runner, _ := provider.(triage.StructuredTaskRunner)
	return runner
}
