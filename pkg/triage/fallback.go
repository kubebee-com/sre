package triage

import (
	"context"
	"fmt"

	"github.com/kubebee-com/sre/pkg/scanner"
)

type RuleBasedProvider struct{}

func NewRuleBasedProvider() *RuleBasedProvider {
	return &RuleBasedProvider{}
}

func (p *RuleBasedProvider) Name() string {
	return "Rule-Based SRE Engine"
}

func (p *RuleBasedProvider) Diagnose(_ context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	diag := &Diagnosis{
		IssueID:         issue.ID,
		ProviderName:    p.Name(),
		Severity:        issue.Severity,
		ConfidenceScore: 0.90,
	}

	switch issue.Category {
	case scanner.CategoryOOMKilled:
		diag.Summary = fmt.Sprintf("Memory limit exceeded for %s/%s", issue.Kind, issue.Name)
		diag.RootCause = "Container was killed by Linux OOM killer (exit 137). Memory footprint exceeded configured cgroup limit."
		diag.RemediationPlan = "Increase memory requests/limits in deployment manifest and restart workload."
		diag.ActionType = ActionGitOpsPR
		diag.ProposedCommand = fmt.Sprintf("# Propose GitOps PR to bump container memory limits in apps/%s", issue.Namespace)

	case scanner.CategoryCrashLoop:
		diag.Summary = fmt.Sprintf("Repeated application crash in %s/%s", issue.Kind, issue.Name)
		diag.RootCause = fmt.Sprintf("Container failed startup or health probes. Details: %s", issue.Details)
		diag.RemediationPlan = "Safe pod restart to re-initialize container state; if failure persists, inspect logs for startup deadlock."
		diag.ActionType = ActionRestartPod
		diag.ProposedCommand = fmt.Sprintf("kubectl delete pod %s -n %s", issue.Name, issue.Namespace)

	case scanner.CategoryImagePull:
		diag.Summary = fmt.Sprintf("Failed to pull container image for %s/%s", issue.Kind, issue.Name)
		diag.RootCause = "Registry authentication failure, invalid image repository URL, or tag does not exist."
		diag.RemediationPlan = "Verify image repository path, imagePullSecrets, or registry credentials."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl describe pod %s -n %s", issue.Name, issue.Namespace)

	case scanner.CategoryPodFailed:
		diag.Summary = fmt.Sprintf("Pod %s in namespace %s terminated with failure", issue.Name, issue.Namespace)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Delete dead failed pod to allow controller recreation or clean up status."
		diag.ActionType = ActionDeleteFailedPod
		diag.ProposedCommand = fmt.Sprintf("kubectl delete pod %s -n %s", issue.Name, issue.Namespace)

	case scanner.CategoryNodePressure:
		diag.Summary = fmt.Sprintf("Node %s is under degraded condition (%s)", issue.Name, issue.Category)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Cordon node to prevent new pod scheduling while existing workloads are drained or node is inspected."
		diag.ActionType = ActionCordonNode
		diag.ProposedCommand = fmt.Sprintf("kubectl cordon %s", issue.Name)

	default:
		diag.Summary = issue.Summary
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Inspect resource logs, events, and configuration."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl describe %s %s -n %s", issue.Kind, issue.Name, issue.Namespace)
	}

	return diag, nil
}
