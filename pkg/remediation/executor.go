package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

var (
	ErrStalePrecondition   = errors.New("target is stale and no longer matches the proposal")
	ErrMissingPrecondition = errors.New("mutation requires captured target UID and resourceVersion")
	ErrUnsupportedAction   = errors.New("remediation action is unsupported")
	ErrProtectedTarget     = errors.New("target is protected from remediation")
	ErrForceDeletion       = errors.New("force deletion is not permitted")
)

const (
	verificationInitialBackoff = 10 * time.Millisecond
	verificationMaximumBackoff = 250 * time.Millisecond
)

type Executor struct {
	client kubernetes.Interface
}

func NewExecutor(client kubernetes.Interface) *Executor {
	return &Executor{client: client}
}

// Validate performs the read and eligibility checks without mutating the
// cluster. Execute repeats this immediately before the actual API operation.
func (x *Executor) Validate(ctx context.Context, p *Proposal) error {
	if p == nil || p.Diagnosis == nil {
		return errors.New("proposal diagnosis is required")
	}
	if x == nil || x.client == nil {
		return errors.New("kubernetes client is unavailable")
	}
	if containsForceDeletion(p.Diagnosis.ProposedCommand) {
		return ErrForceDeletion
	}
	if ctx == nil {
		ctx = context.Background()
	}
	switch p.Diagnosis.ActionType {
	case triage.ActionRestartPod, triage.ActionDeleteFailedPod, triage.ActionCleanupPods:
		if strings.TrimSpace(p.TargetUID) == "" || strings.TrimSpace(p.TargetResourceVersion) == "" {
			return ErrMissingPrecondition
		}
		pod, err := x.client.CoreV1().Pods(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("%w: get pod %s/%s", ErrStalePrecondition, p.Namespace, p.Name)
		}
		if err := validateTargetIdentity(p, pod.UID, pod.ResourceVersion); err != nil {
			return err
		}
		if scanner.IsProtectedPod(pod) {
			return fmt.Errorf("%w: pod %s/%s", ErrProtectedTarget, p.Namespace, p.Name)
		}
		if p.Diagnosis.ActionType == triage.ActionCleanupPods {
			if eligible, _, _ := scanner.PodCleanupEligibility(pod, time.Now()); !eligible {
				return fmt.Errorf("%w: pod %s/%s is no longer eligible for cleanup", ErrStalePrecondition, p.Namespace, p.Name)
			}
		}
		return nil
	case triage.ActionRolloutRestart:
		if strings.TrimSpace(p.TargetUID) == "" || strings.TrimSpace(p.TargetResourceVersion) == "" {
			return ErrMissingPrecondition
		}
		deployment, err := x.client.AppsV1().Deployments(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("%w: get deployment %s/%s", ErrStalePrecondition, p.Namespace, p.Name)
		}
		if err := validateTargetIdentity(p, deployment.UID, deployment.ResourceVersion); err != nil {
			return err
		}
		p.rolloutGeneration = deployment.Generation
		p.rolloutBaselineSet = true
		return nil
	case triage.ActionScaleWorkload:
		if p.Diagnosis.TargetReplicas == nil || *p.Diagnosis.TargetReplicas < 0 || *p.Diagnosis.TargetReplicas > 10000 {
			return fmt.Errorf("%w: target replicas are invalid", ErrUnsupportedAction)
		}
		if strings.TrimSpace(p.TargetUID) == "" || strings.TrimSpace(p.TargetResourceVersion) == "" {
			return ErrMissingPrecondition
		}
		object, err := x.scalableWorkload(ctx, p)
		if err != nil {
			return fmt.Errorf("%w: get workload %s/%s", ErrStalePrecondition, p.Namespace, p.Name)
		}
		return validateTargetIdentity(p, object.GetUID(), object.GetResourceVersion())
	case triage.ActionCordonNode:
		if strings.TrimSpace(p.TargetUID) == "" || strings.TrimSpace(p.TargetResourceVersion) == "" {
			return ErrMissingPrecondition
		}
		node, err := x.client.CoreV1().Nodes().Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("%w: get node %s", ErrStalePrecondition, p.Name)
		}
		return validateTargetIdentity(p, node.UID, node.ResourceVersion)
	case triage.ActionGitOpsPR, triage.ActionManual:
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAction, p.Diagnosis.ActionType)
	}
}

func (x *Executor) Execute(ctx context.Context, p *Proposal) (string, error) {
	if p == nil || p.Diagnosis == nil {
		return "", errors.New("proposal diagnosis is required")
	}
	if err := x.Validate(ctx, p); err != nil {
		return "", err
	}

	switch p.Diagnosis.ActionType {
	case triage.ActionRestartPod, triage.ActionDeleteFailedPod, triage.ActionCleanupPods:
		options := metav1.DeleteOptions{}
		uid := types.UID(p.TargetUID)
		resourceVersion := p.TargetResourceVersion
		options.Preconditions = &metav1.Preconditions{
			UID:             &uid,
			ResourceVersion: &resourceVersion,
		}
		if err := x.client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name, options); err != nil {
			if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
				return "", fmt.Errorf("%w: delete pod %s/%s", ErrStalePrecondition, p.Namespace, p.Name)
			}
			return "", fmt.Errorf("delete pod %s/%s failed", p.Namespace, p.Name)
		}
		return fmt.Sprintf("Successfully deleted pod %s/%s to trigger clean re-initialization", p.Namespace, p.Name), nil

	case triage.ActionRolloutRestart:
		patch := map[string]interface{}{
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"metadata": map[string]map[string]string{
						"annotations": {"kubectl.kubernetes.io/restartedAt": time.Now().UTC().Format(time.RFC3339)},
					},
				},
			},
		}
		patch["metadata"] = map[string]string{"resourceVersion": p.TargetResourceVersion}
		patchData, err := json.Marshal(patch)
		if err != nil {
			return "", errors.New("encode rollout restart patch failed")
		}
		_, err = x.client.AppsV1().Deployments(p.Namespace).Patch(ctx, p.Name, types.StrategicMergePatchType, patchData, metav1.PatchOptions{})
		if err != nil {
			if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
				return "", fmt.Errorf("%w: patch deployment %s/%s", ErrStalePrecondition, p.Namespace, p.Name)
			}
			return "", fmt.Errorf("rollout restart deployment %s/%s failed", p.Namespace, p.Name)
		}
		return fmt.Sprintf("Successfully triggered rollout restart for Deployment %s/%s", p.Namespace, p.Name), nil

	case triage.ActionScaleWorkload:
		return x.scaleWorkload(ctx, p)

	case triage.ActionCordonNode:
		node, err := x.client.CoreV1().Nodes().Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("get node %s failed", p.Name)
		}
		if identityErr := validateTargetIdentity(p, node.UID, node.ResourceVersion); identityErr != nil {
			return "", identityErr
		}
		node.Spec.Unschedulable = true
		if _, err = x.client.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
				return "", fmt.Errorf("%w: update node %s", ErrStalePrecondition, p.Name)
			}
			return "", fmt.Errorf("cordon node %s failed", p.Name)
		}
		return fmt.Sprintf("Successfully cordoned node %s (marked unschedulable)", p.Name), nil

	case triage.ActionGitOpsPR:
		return fmt.Sprintf("GitOps Remediation Proposal generated: %s", p.Diagnosis.ProposedCommand), nil

	case triage.ActionManual:
		return fmt.Sprintf("Manual action acknowledged: %s", p.Diagnosis.ProposedCommand), nil

	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedAction, p.Diagnosis.ActionType)
	}
}

func (x *Executor) Verify(ctx context.Context, p *Proposal) (VerificationResult, error) {
	if p == nil || p.Diagnosis == nil {
		return VerificationResult{}, errors.New("proposal diagnosis is required")
	}
	if x == nil || x.client == nil {
		return VerificationResult{}, errors.New("kubernetes client is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	switch p.Diagnosis.ActionType {
	case triage.ActionRestartPod, triage.ActionDeleteFailedPod, triage.ActionCleanupPods:
		return x.verifyPodDeletion(ctx, p), nil

	case triage.ActionScaleWorkload:
		replicas, err := x.currentReplicaCount(ctx, p)
		if err != nil {
			if errors.Is(err, ErrStalePrecondition) || errors.Is(err, ErrUnsupportedAction) {
				return failedResult(err.Error()), nil
			}
			return unavailableResult(err.Error()), nil
		}
		if p.Diagnosis.TargetReplicas == nil {
			return failedResult("target replicas are required"), nil
		}
		if replicas == *p.Diagnosis.TargetReplicas {
			return verifiedResult("replica count matches requested target"), nil
		}
		return failedResult(fmt.Sprintf("replica count is %d, want %d", replicas, *p.Diagnosis.TargetReplicas)), nil

	case triage.ActionCordonNode:
		node, err := x.client.CoreV1().Nodes().Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return failedResult(fmt.Sprintf("node %s no longer exists", p.Name)), nil
			}
			return unavailableResult(fmt.Sprintf("verify node %s failed", p.Name)), nil
		}
		if string(node.UID) != p.TargetUID {
			return failedResult(fmt.Sprintf("node %s UID changed", p.Name)), nil
		}
		if node.Spec.Unschedulable {
			return verifiedResult("node is unschedulable"), nil
		}
		return failedResult(fmt.Sprintf("node %s is still schedulable", p.Name)), nil

	case triage.ActionRolloutRestart:
		deployment, err := x.client.AppsV1().Deployments(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return failedResult(fmt.Sprintf("deployment %s/%s no longer exists", p.Namespace, p.Name)), nil
			}
			return unavailableResult(fmt.Sprintf("verify rollout restart %s/%s failed", p.Namespace, p.Name)), nil
		}
		if string(deployment.UID) != p.TargetUID {
			return failedResult(fmt.Sprintf("deployment %s/%s UID changed", p.Namespace, p.Name)), nil
		}
		if !p.rolloutBaselineSet {
			return unavailableResult("rollout generation baseline is unavailable"), nil
		}
		if deployment.Generation > p.rolloutGeneration {
			return verifiedResult("deployment generation changed"), nil
		}
		return failedResult(fmt.Sprintf("deployment %s/%s generation did not change", p.Namespace, p.Name)), nil

	case triage.ActionGitOpsPR, triage.ActionManual:
		return VerificationResult{Status: VerificationStatusUnverified}, nil

	default:
		return failedResult(fmt.Sprintf("%s cannot be verified", p.Diagnosis.ActionType)), nil
	}
}

func (x *Executor) verifyPodDeletion(ctx context.Context, p *Proposal) VerificationResult {
	backoff := verificationInitialBackoff
	for {
		pod, err := x.client.CoreV1().Pods(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return verifiedResult("pod target is gone")
		}
		if err != nil {
			if ctx.Err() != nil {
				return failedResult(fmt.Sprintf("pod %s/%s still exists after verification timeout", p.Namespace, p.Name))
			}
			return unavailableResult(fmt.Sprintf("verify pod deletion %s/%s failed", p.Namespace, p.Name))
		}
		if string(pod.UID) != p.TargetUID {
			return verifiedResult("pod target was replaced")
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return failedResult(fmt.Sprintf("pod %s/%s still exists after verification timeout", p.Namespace, p.Name))
		case <-timer.C:
		}
		if backoff < verificationMaximumBackoff {
			backoff *= 2
			if backoff > verificationMaximumBackoff {
				backoff = verificationMaximumBackoff
			}
		}
	}
}

func (x *Executor) scalableWorkload(ctx context.Context, p *Proposal) (metav1.Object, error) {
	switch strings.ToLower(strings.TrimSpace(p.Kind)) {
	case "deployment":
		return x.client.AppsV1().Deployments(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
	case "statefulset":
		return x.client.AppsV1().StatefulSets(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
	case "replicaset":
		return x.client.AppsV1().ReplicaSets(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
	default:
		return nil, fmt.Errorf("%w: workload kind %q cannot be scaled", ErrUnsupportedAction, p.Kind)
	}
}

func (x *Executor) currentReplicaCount(ctx context.Context, p *Proposal) (int32, error) {
	switch strings.ToLower(strings.TrimSpace(p.Kind)) {
	case "deployment":
		deployment, err := x.client.AppsV1().Deployments(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return 0, fmt.Errorf("%w: deployment %s/%s no longer exists", ErrStalePrecondition, p.Namespace, p.Name)
			}
			return 0, fmt.Errorf("verify deployment %s/%s scale failed", p.Namespace, p.Name)
		}
		if string(deployment.UID) != p.TargetUID {
			return 0, fmt.Errorf("%w: deployment %s/%s UID changed", ErrStalePrecondition, p.Namespace, p.Name)
		}
		if deployment.Spec.Replicas == nil {
			return 1, nil
		}
		return *deployment.Spec.Replicas, nil
	case "statefulset":
		statefulSet, err := x.client.AppsV1().StatefulSets(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return 0, fmt.Errorf("%w: statefulset %s/%s no longer exists", ErrStalePrecondition, p.Namespace, p.Name)
			}
			return 0, fmt.Errorf("verify statefulset %s/%s scale failed", p.Namespace, p.Name)
		}
		if string(statefulSet.UID) != p.TargetUID {
			return 0, fmt.Errorf("%w: statefulset %s/%s UID changed", ErrStalePrecondition, p.Namespace, p.Name)
		}
		if statefulSet.Spec.Replicas == nil {
			return 1, nil
		}
		return *statefulSet.Spec.Replicas, nil
	case "replicaset":
		replicaSet, err := x.client.AppsV1().ReplicaSets(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return 0, fmt.Errorf("%w: replicaset %s/%s no longer exists", ErrStalePrecondition, p.Namespace, p.Name)
			}
			return 0, fmt.Errorf("verify replicaset %s/%s scale failed", p.Namespace, p.Name)
		}
		if string(replicaSet.UID) != p.TargetUID {
			return 0, fmt.Errorf("%w: replicaset %s/%s UID changed", ErrStalePrecondition, p.Namespace, p.Name)
		}
		if replicaSet.Spec.Replicas == nil {
			return 1, nil
		}
		return *replicaSet.Spec.Replicas, nil
	default:
		return 0, fmt.Errorf("%w: workload kind %q cannot be verified", ErrUnsupportedAction, p.Kind)
	}
}

func (x *Executor) scaleWorkload(ctx context.Context, p *Proposal) (string, error) {
	if p == nil || p.Diagnosis == nil || p.Diagnosis.TargetReplicas == nil {
		return "", fmt.Errorf("%w: target replicas are required", ErrUnsupportedAction)
	}
	if *p.Diagnosis.TargetReplicas < 0 || *p.Diagnosis.TargetReplicas > 10000 {
		return "", fmt.Errorf("%w: target replicas are out of range", ErrUnsupportedAction)
	}
	patch := map[string]interface{}{
		"metadata": map[string]string{"resourceVersion": p.TargetResourceVersion},
		"spec":     map[string]int32{"replicas": *p.Diagnosis.TargetReplicas},
	}
	patchData, err := json.Marshal(patch)
	if err != nil {
		return "", errors.New("encode scale patch failed")
	}
	var patchErr error
	switch strings.ToLower(strings.TrimSpace(p.Kind)) {
	case "deployment":
		_, patchErr = x.client.AppsV1().Deployments(p.Namespace).Patch(ctx, p.Name, types.MergePatchType, patchData, metav1.PatchOptions{})
	case "statefulset":
		_, patchErr = x.client.AppsV1().StatefulSets(p.Namespace).Patch(ctx, p.Name, types.MergePatchType, patchData, metav1.PatchOptions{})
	case "replicaset":
		_, patchErr = x.client.AppsV1().ReplicaSets(p.Namespace).Patch(ctx, p.Name, types.MergePatchType, patchData, metav1.PatchOptions{})
	default:
		return "", fmt.Errorf("%w: workload kind %q cannot be scaled", ErrUnsupportedAction, p.Kind)
	}
	if patchErr != nil {
		if apierrors.IsConflict(patchErr) || apierrors.IsNotFound(patchErr) {
			return "", fmt.Errorf("%w: scale %s/%s", ErrStalePrecondition, p.Namespace, p.Name)
		}
		return "", fmt.Errorf("scale workload %s/%s failed", p.Namespace, p.Name)
	}
	return fmt.Sprintf("Successfully set %s/%s replicas to %d", p.Namespace, p.Name, *p.Diagnosis.TargetReplicas), nil
}

func validateTargetIdentity(proposal *Proposal, uid types.UID, resourceVersion string) error {
	if proposal == nil || strings.TrimSpace(proposal.TargetUID) == "" || strings.TrimSpace(proposal.TargetResourceVersion) == "" {
		return ErrMissingPrecondition
	}
	if proposal.TargetUID != string(uid) || proposal.TargetResourceVersion != resourceVersion {
		return fmt.Errorf("%w: expected %s/%s, got %s/%s", ErrStalePrecondition, proposal.TargetUID, proposal.TargetResourceVersion, uid, resourceVersion)
	}
	return nil
}

func containsForceDeletion(command string) bool {
	fields := strings.Fields(strings.ToLower(command))
	for index, field := range fields {
		if field == "--force" || field == "--grace-period=0" || (field == "--grace-period" && index+1 < len(fields) && fields[index+1] == "0") {
			return true
		}
	}
	return false
}

func verifiedResult(message string) VerificationResult {
	return VerificationResult{Status: VerificationStatusVerified, Message: message}
}

func failedResult(message string) VerificationResult {
	return VerificationResult{Status: VerificationStatusFailed, Message: message}
}

func unavailableResult(message string) VerificationResult {
	return VerificationResult{Status: VerificationStatusUnavailable, Message: message}
}
