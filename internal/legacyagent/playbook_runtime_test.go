package legacyagent

import (
	"context"
	"testing"

	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/playbook"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

type runtimeResolver struct {
	calls  int
	result playbook.ResolveResult
	err    error
}

func (r *runtimeResolver) Resolve(context.Context, *scanner.Issue, string) (playbook.ResolveResult, error) {
	r.calls++
	return r.result, r.err
}
func TestPlaybookScanRoutingFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enabled  bool
		resolver *runtimeResolver
		handled  bool
	}{
		{"disabled", false, &runtimeResolver{}, false},
		{"missing", true, nil, true},
		{"outage", true, &runtimeResolver{err: playbook.ErrCatalogUnavailable}, true},
		{"no match", true, &runtimeResolver{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var resolver playbookResolver
			if tc.resolver != nil {
				resolver = tc.resolver
			}
			handled, proposal, _ := resolveScanPlaybook(context.Background(), &config.Config{PlaybookEnabled: tc.enabled}, resolver, &scanner.Issue{})
			if handled != tc.handled || proposal != nil {
				t.Fatalf("handled=%v proposal=%v", handled, proposal)
			}
			if !tc.enabled && tc.resolver.calls != 0 {
				t.Fatal("disabled feature called catalog")
			}
		})
	}
}
func TestPlaybookRuntimeSettingsPreservePolicy(t *testing.T) {
	cfg := &config.Config{PlaybookEnabled: true, PlaybookMinConfidence: .9, PlaybookMaxStepCount: 3, PlaybookMaxSourceBytes: 1024, PlaybookMaxTotalTextBytes: 4096, PlaybookLearningMode: "OBSERVE_ONLY", PlaybookAllowedNamespaces: []string{"payments"}, PlaybookAllowedActions: []string{string(triage.ActionRestartPod)}}
	settings := playbookSettings(cfg)
	if !settings.Enabled || settings.MinConfidence != .9 || settings.MaxSteps != 3 || settings.AllowClusterScoped || settings.LearningMode != playbook.LearningObserveOnly {
		t.Fatalf("settings=%+v", settings)
	}
	settings.AllowedNamespaces[0] = "other"
	if cfg.PlaybookAllowedNamespaces[0] != "payments" {
		t.Fatal("settings alias configuration")
	}
}

func TestPlaybookRuntimeRejectsWrappedFallbackBeforeFirstTask(t *testing.T) {
	for _, provider := range []triage.TriageProvider{triage.NewRuleBasedProvider(), triage.NewNoOpProvider()} {
		wrapped := observeTriageProvider(provider, nil)
		if playbookTaskRunner(wrapped) != nil {
			t.Fatal("unsupported fallback reported available")
		}
	}
}
