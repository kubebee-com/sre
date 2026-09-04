package remediation

import (
	"context"
	"fmt"

	"github.com/kubebee-com/sre/pkg/triage"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Executor struct {
	client kubernetes.Interface
}

func NewExecutor(client kubernetes.Interface) *Executor {
	return &Executor{client: client}
}

func (x *Executor) Execute(ctx context.Context, p *Proposal) (string, error) {
	if p.Diagnosis == nil {
		return "", fmt.Errorf("no diagnosis attached to proposal %s", p.ID)
	}

	switch p.Diagnosis.ActionType {
	case triage.ActionRestartPod, triage.ActionDeleteFailedPod:
		// Safe deletion of the pod; controller will reschedule/recreate it
		err := x.client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{})
		if err != nil {
			return "", fmt.Errorf("delete pod %s/%s: %w", p.Namespace, p.Name, err)
		}
		return fmt.Sprintf("Successfully deleted pod %s/%s to trigger clean re-initialization", p.Namespace, p.Name), nil

	case triage.ActionCordonNode:
		node, err := x.client.CoreV1().Nodes().Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("get node %s: %w", p.Name, err)
		}
		node.Spec.Unschedulable = true
		_, err = x.client.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
		if err != nil {
			return "", fmt.Errorf("cordon node %s: %w", p.Name, err)
		}
		return fmt.Sprintf("Successfully cordoned node %s (marked unschedulable)", p.Name), nil

	case triage.ActionGitOpsPR:
		// In GitOps clusters, direct live patching causes drift. Output the declarative change for PR.
		return fmt.Sprintf("GitOps Remediation Proposal generated: %s", p.Diagnosis.ProposedCommand), nil

	case triage.ActionManual:
		return fmt.Sprintf("Manual action acknowledged: %s", p.Diagnosis.ProposedCommand), nil

	default:
		return fmt.Sprintf("Action '%s' acknowledged for execution: %s", p.Diagnosis.ActionType, p.Diagnosis.ProposedCommand), nil
	}
}
