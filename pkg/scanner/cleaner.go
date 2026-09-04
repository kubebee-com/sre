package scanner

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type PodCleaner struct {
	client kubernetes.Interface
}

func NewPodCleaner(client kubernetes.Interface) *PodCleaner {
	return &PodCleaner{client: client}
}

// ListCleanablePods returns pods eligible for cleanup:
// - Evicted pods (status.reason == "Evicted")
// - Failed pods (status.phase == "Failed")
// - Completed pods (status.phase == "Succeeded" e.g. completed jobs)
// - Stuck Terminating pods (deletionTimestamp > 5 minutes ago)
func (c *PodCleaner) ListCleanablePods(ctx context.Context, namespace string) ([]*CleanablePod, error) {
	pods, err := c.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods for cleanup: %w", err)
	}

	cleanable := make([]*CleanablePod, 0)
	now := time.Now()

	for _, pod := range pods.Items {
		isCandidate := false
		reason := pod.Status.Reason
		isStuck := false

		// 1. Stuck Terminating pods (> 5 minutes past deletion timestamp)
		if pod.DeletionTimestamp != nil {
			if now.Sub(pod.DeletionTimestamp.Time) > 5*time.Minute {
				isCandidate = true
				isStuck = true
				if reason == "" {
					reason = "StuckTerminating"
				}
			}
		} else if pod.Status.Phase == corev1.PodFailed {
			isCandidate = true
			if reason == "" {
				reason = "Failed"
			}
		} else if pod.Status.Reason == "Evicted" {
			isCandidate = true
			reason = "Evicted"
		} else if pod.Status.Phase == corev1.PodSucceeded {
			// Completed job pods older than 1 hour
			if now.Sub(pod.CreationTimestamp.Time) > 1*time.Hour {
				isCandidate = true
				if reason == "" {
					reason = "Completed"
				}
			}
		}

		if isCandidate {
			age := now.Sub(pod.CreationTimestamp.Time).Round(time.Minute).String()
			var totalRestarts int32
			for _, cs := range pod.Status.ContainerStatuses {
				totalRestarts += cs.RestartCount
			}

			var delTime *time.Time
			if pod.DeletionTimestamp != nil {
				delTime = &pod.DeletionTimestamp.Time
			}

			cleanable = append(cleanable, &CleanablePod{
				Namespace:    pod.Namespace,
				Name:         pod.Name,
				Phase:        string(pod.Status.Phase),
				Reason:       reason,
				Age:          age,
				RestartCount: totalRestarts,
				IsStuck:      isStuck,
				DeletionTime: delTime,
			})
		}
	}

	return cleanable, nil
}

// CleanPods removes the specified cleanable pods. If dryRun is true, only simulates deletion.
func (c *PodCleaner) CleanPods(ctx context.Context, namespace string, podNames []string, dryRun bool) (*CleanupReport, error) {
	report := &CleanupReport{
		TargetPods: podNames,
		DryRun:     dryRun,
	}

	if dryRun {
		report.DeletedCount = len(podNames)
		return report, nil
	}

	for _, name := range podNames {
		// Attempt standard delete first
		err := c.client.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil {
			// If standard delete failed or pod is stuck, check if force delete (gracePeriod=0) is needed
			var zero int64 = 0
			forceErr := c.client.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{
				GracePeriodSeconds: &zero,
			})
			if forceErr != nil {
				report.FailedCount++
				report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", name, forceErr))
				continue
			}
		}
		report.DeletedCount++
	}

	return report, nil
}
