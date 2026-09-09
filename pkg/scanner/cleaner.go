package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var ErrCleanupRequiresApproval = errors.New("cleanup requires an approved remediation proposal")

const protectedLabelKey = "sre.kubebee.com/protected"

var protectedNamespaces = map[string]struct{}{
	"kube-system":     {},
	"kube-public":     {},
	"kube-node-lease": {},
}

type PodCleaner struct {
	client kubernetes.Interface
}

func NewPodCleaner(client kubernetes.Interface) *PodCleaner {
	return &PodCleaner{client: client}
}

// ListCleanablePods returns the current set of eligible pods. The returned
// UID and resourceVersion are captured for the later approval precondition.
func (c *PodCleaner) ListCleanablePods(ctx context.Context, namespace string) ([]*CleanablePod, error) {
	pods, err := c.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods for cleanup: %w", err)
	}

	cleanable := make([]*CleanablePod, 0)
	now := time.Now()
	for index := range pods.Items {
		pod := &pods.Items[index]
		candidate, reason, isStuck := PodCleanupEligibility(pod, now)
		if !candidate {
			continue
		}

		age := now.Sub(pod.CreationTimestamp.Time).Round(time.Minute).String()
		var totalRestarts int32
		for _, status := range pod.Status.ContainerStatuses {
			totalRestarts += status.RestartCount
		}

		var deletionTime *time.Time
		if pod.DeletionTimestamp != nil {
			value := pod.DeletionTimestamp.Time
			deletionTime = &value
		}
		cleanable = append(cleanable, &CleanablePod{
			Namespace:             pod.Namespace,
			Name:                  pod.Name,
			TargetUID:             string(pod.UID),
			TargetResourceVersion: pod.ResourceVersion,
			Phase:                 string(pod.Status.Phase),
			Reason:                reason,
			Age:                   age,
			RestartCount:          totalRestarts,
			IsStuck:               isStuck,
			DeletionTime:          deletionTime,
		})
	}
	return cleanable, nil
}

// CleanPods is intentionally limited to dry-run reporting. Mutating cleanup
// must be represented by a proposal and approved through remediation.Engine.
func (c *PodCleaner) CleanPods(ctx context.Context, namespace string, podNames []string, dryRun bool) (*CleanupReport, error) {
	if !dryRun {
		return nil, ErrCleanupRequiresApproval
	}
	candidates, err := c.ListCleanablePods(ctx, namespace)
	if err != nil {
		return nil, err
	}
	requested := make(map[string]struct{}, len(podNames))
	for _, name := range podNames {
		name = strings.TrimSpace(name)
		if name != "" {
			requested[name] = struct{}{}
		}
	}
	report := &CleanupReport{
		TargetPods:    make([]string, 0, len(candidates)),
		CandidatePods: make([]string, 0, len(candidates)),
		DryRun:        true,
	}
	for _, candidate := range candidates {
		if len(requested) > 0 {
			if _, ok := requested[candidate.Name]; !ok {
				continue
			}
		}
		report.CandidatePods = append(report.CandidatePods, candidate.Name)
		report.TargetPods = append(report.TargetPods, candidate.Name)
	}
	return report, nil
}

// PodCleanupEligibility centralizes the policy used during listing and again
// immediately before an approved cleanup mutation.
func PodCleanupEligibility(pod *corev1.Pod, now time.Time) (bool, string, bool) {
	if pod == nil || IsProtectedPod(pod) {
		return false, "", false
	}
	if pod.DeletionTimestamp != nil && now.Sub(pod.DeletionTimestamp.Time) > 5*time.Minute {
		reason := pod.Status.Reason
		if reason == "" {
			reason = "StuckTerminating"
		}
		return true, reason, true
	}
	if pod.Status.Phase == corev1.PodFailed {
		reason := pod.Status.Reason
		if reason == "" {
			reason = "Failed"
		}
		return true, reason, false
	}
	if pod.Status.Reason == "Evicted" {
		return true, "Evicted", false
	}
	if pod.Status.Phase == corev1.PodSucceeded && now.Sub(pod.CreationTimestamp.Time) > time.Hour {
		reason := pod.Status.Reason
		if reason == "" {
			reason = "Completed"
		}
		return true, reason, false
	}
	return false, "", false
}

func IsProtectedPod(pod *corev1.Pod) bool {
	if pod == nil {
		return true
	}
	if _, protected := protectedNamespaces[pod.Namespace]; protected {
		return true
	}
	for key, value := range pod.Labels {
		if (key == protectedLabelKey || strings.HasSuffix(key, "/protected")) && strings.EqualFold(strings.TrimSpace(value), "true") {
			return true
		}
	}
	return false
}
