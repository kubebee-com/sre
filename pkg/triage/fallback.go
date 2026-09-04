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

	case scanner.CategoryPodEvicted:
		diag.Summary = fmt.Sprintf("Pod %s evicted on node", issue.Name)
		diag.RootCause = fmt.Sprintf("Node reclaimed ephemeral storage or memory. Details: %s", issue.Details)
		diag.RemediationPlan = "Clean up evicted pod resource and check node disk/memory headroom."
		diag.ActionType = ActionDeleteFailedPod
		diag.ProposedCommand = fmt.Sprintf("kubectl delete pod %s -n %s", issue.Name, issue.Namespace)

	case scanner.CategoryPodStuckTerminating:
		diag.Summary = fmt.Sprintf("Pod %s stuck terminating > 5 minutes", issue.Name)
		diag.RootCause = "Container runtime or finalizer deadlock preventing clean termination."
		diag.RemediationPlan = "Force delete pod with grace-period=0 after verifying volume detachment."
		diag.ActionType = ActionDeleteFailedPod
		diag.ProposedCommand = fmt.Sprintf("kubectl delete pod %s -n %s --grace-period=0 --force", issue.Name, issue.Namespace)

	case scanner.CategoryDeploymentMismatch:
		diag.Summary = fmt.Sprintf("Deployment %s replica deficit", issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Inspect underlying ReplicaSet events and trigger rollout restart if stuck."
		diag.ActionType = ActionRolloutRestart
		diag.ProposedCommand = fmt.Sprintf("kubectl rollout restart deployment/%s -n %s", issue.Name, issue.Namespace)

	case scanner.CategoryStatefulSetMismatch, scanner.CategoryDaemonSetMismatch, scanner.CategoryReplicaSetStuck:
		diag.Summary = fmt.Sprintf("Workload %s/%s degraded", issue.Kind, issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Inspect pod scheduling constraints, node selectors, or volume claims."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl describe %s %s -n %s", issue.Kind, issue.Name, issue.Namespace)

	case scanner.CategoryJobFailed:
		diag.Summary = fmt.Sprintf("Batch Job %s exceeded backoff limit or deadline", issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Check job container logs, fix configuration bug, and re-run job."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl logs job/%s -n %s", issue.Name, issue.Namespace)

	case scanner.CategoryServiceNoEndpoint:
		diag.Summary = fmt.Sprintf("Service %s has 0 ready endpoints", issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Verify pod label selectors match running pod labels and readiness probes pass."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl get pods -n %s --show-labels", issue.Namespace)

	case scanner.CategoryIngressBackendNotFound:
		diag.Summary = fmt.Sprintf("Ingress %s references missing backend service", issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Create missing service or correct service name in Ingress manifest via GitOps."
		diag.ActionType = ActionGitOpsPR
		diag.ProposedCommand = fmt.Sprintf("# Fix backend service name in Ingress manifest for %s", issue.Name)

	case scanner.CategoryIngressTLSSecretMissing:
		diag.Summary = fmt.Sprintf("Ingress %s TLS secret not yet provisioned", issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Check cert-manager Certificate and ClusterIssuer challenge status."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl get certificates -n %s", issue.Namespace)

	case scanner.CategoryNetworkPolicyOrphaned:
		diag.Summary = fmt.Sprintf("Orphaned NetworkPolicy %s", issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Remove obsolete NetworkPolicy or update pod selector."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl get netpol %s -n %s -o yaml", issue.Name, issue.Namespace)

	case scanner.CategoryNodePressure, scanner.CategoryNodeNotReady:
		diag.Summary = fmt.Sprintf("Node %s is under degraded condition (%s)", issue.Name, issue.Category)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Cordon node to prevent new pod scheduling while existing workloads are drained or node is inspected."
		diag.ActionType = ActionCordonNode
		diag.ProposedCommand = fmt.Sprintf("kubectl cordon %s", issue.Name)

	case scanner.CategoryPVCPending, scanner.CategoryPVLost:
		diag.Summary = fmt.Sprintf("Persistent volume issue for %s/%s", issue.Kind, issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Verify CSI driver storage provisioner, volume quotas, and underlying disks."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl describe pvc %s -n %s", issue.Name, issue.Namespace)

	case scanner.CategoryHPAScalingLimited, scanner.CategoryHPAMetricsUnavailable:
		diag.Summary = fmt.Sprintf("HPA issue for %s", issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Verify metrics-server availability or adjust maxReplicas limit."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl describe hpa %s -n %s", issue.Name, issue.Namespace)

	case scanner.CategoryPDBDisruptionsBlocked:
		diag.Summary = fmt.Sprintf("PDB %s is blocking node disruptions", issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Allow unhealthy pods to recover before initiating node upgrades or drains."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl get pdb %s -n %s", issue.Name, issue.Namespace)

	default:
		diag.Summary = fmt.Sprintf("Anomaly detected in %s/%s", issue.Kind, issue.Name)
		diag.RootCause = issue.Details
		diag.RemediationPlan = "Inspect resource describe and events to diagnose root cause."
		diag.ActionType = ActionManual
		diag.ProposedCommand = fmt.Sprintf("kubectl describe %s %s -n %s", issue.Kind, issue.Name, issue.Namespace)
	}

	return diag, nil
}

func (p *RuleBasedProvider) Explain(_ context.Context, query string, issue *scanner.Issue) (string, error) {
	if issue == nil {
		return fmt.Sprintf("I am the Kubebee SRE AI Assistant (Rule-Based Engine).\n\nYou asked: %q\n\nI actively monitor all cluster workloads, nodes, and networking components. If an LLM API key (Claude, OpenAI, DeepSeek) is supplied, I can run deep cognitive root-cause analysis on stack traces.", query), nil
	}

	return fmt.Sprintf("### SRE Diagnostic Report: %s/%s\n\n- **Category**: `%s`\n- **Summary**: %s\n- **Technical Diagnosis**: %s\n\n#### Recommended Troubleshooting Commands:\n```bash\nkubectl describe %s %s -n %s\nkubectl logs %s -n %s --tail=50\n```",
		issue.Kind, issue.Name, issue.Category, issue.Summary, issue.Details, issue.Kind, issue.Name, issue.Namespace, issue.Name, issue.Namespace), nil
}
