package scanner

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// scanDeployments analyzes Deployments for unavailable replicas, replica mismatches, or progress deadline exceeded
func (s *ClusterScanner) scanDeployments(ctx context.Context, namespace string) ([]*Issue, error) {
	depls, err := s.client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, d := range depls.Items {
		specReplicas := int32(1)
		if d.Spec.Replicas != nil {
			specReplicas = *d.Spec.Replicas
		}

		// Check for unavailable or missing ready replicas
		if specReplicas > 0 && d.Status.ReadyReplicas < specReplicas {
			summary := fmt.Sprintf("Deployment has %d/%d ready replicas", d.Status.ReadyReplicas, specReplicas)
			details := fmt.Sprintf("Deployment '%s' in namespace '%s' is degraded. %d replicas unavailable.",
				d.Name, d.Namespace, specReplicas-d.Status.ReadyReplicas)

			// Check condition reasons
			for _, cond := range d.Status.Conditions {
				if cond.Type == "Progressing" && cond.Status == "False" {
					details += fmt.Sprintf(" Condition Progressing is False: %s - %s.", cond.Reason, cond.Message)
				}
			}

			issues = append(issues, &Issue{
				ID:            generateIssueID(d.Namespace, "Deployment", d.Name, string(CategoryDeploymentMismatch)),
				Namespace:     d.Namespace,
				Kind:          "Deployment",
				Name:          d.Name,
				Severity:      SeverityHigh,
				Category:      CategoryDeploymentMismatch,
				Summary:       summary,
				Details:       details,
				FirstObserved: d.CreationTimestamp.Time,
				LastObserved:  d.CreationTimestamp.Time,
			})
		}
	}
	return issues, nil
}

// scanStatefulSets analyzes StatefulSets for unready replicas or partition issues
func (s *ClusterScanner) scanStatefulSets(ctx context.Context, namespace string) ([]*Issue, error) {
	ssList, err := s.client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, ss := range ssList.Items {
		specReplicas := int32(1)
		if ss.Spec.Replicas != nil {
			specReplicas = *ss.Spec.Replicas
		}

		if specReplicas > 0 && ss.Status.ReadyReplicas < specReplicas {
			issues = append(issues, &Issue{
				ID:            generateIssueID(ss.Namespace, "StatefulSet", ss.Name, string(CategoryStatefulSetMismatch)),
				Namespace:     ss.Namespace,
				Kind:          "StatefulSet",
				Name:          ss.Name,
				Severity:      SeverityHigh,
				Category:      CategoryStatefulSetMismatch,
				Summary:       fmt.Sprintf("StatefulSet has %d/%d ready replicas", ss.Status.ReadyReplicas, specReplicas),
				Details:       fmt.Sprintf("StatefulSet '%s' ready replicas mismatch. Replicas: %d, Ready: %d, Current: %d, Updated: %d.",
					ss.Name, specReplicas, ss.Status.ReadyReplicas, ss.Status.CurrentReplicas, ss.Status.UpdatedReplicas),
				FirstObserved: ss.CreationTimestamp.Time,
				LastObserved:  ss.CreationTimestamp.Time,
			})
		}
	}
	return issues, nil
}

// scanDaemonSets analyzes DaemonSets for unscheduled or unready pods across matching nodes
func (s *ClusterScanner) scanDaemonSets(ctx context.Context, namespace string) ([]*Issue, error) {
	dsList, err := s.client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, ds := range dsList.Items {
		if ds.Status.DesiredNumberScheduled > 0 && ds.Status.NumberReady < ds.Status.DesiredNumberScheduled {
			issues = append(issues, &Issue{
				ID:            generateIssueID(ds.Namespace, "DaemonSet", ds.Name, string(CategoryDaemonSetMismatch)),
				Namespace:     ds.Namespace,
				Kind:          "DaemonSet",
				Name:          ds.Name,
				Severity:      SeverityMedium,
				Category:      CategoryDaemonSetMismatch,
				Summary:       fmt.Sprintf("DaemonSet has %d/%d ready pods", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled),
				Details:       fmt.Sprintf("DaemonSet '%s' has %d unready pods across cluster nodes. Desired: %d, Current: %d, Ready: %d, Unavailable: %d.",
					ds.Name, ds.Status.DesiredNumberScheduled-ds.Status.NumberReady, ds.Status.DesiredNumberScheduled, ds.Status.CurrentNumberScheduled, ds.Status.NumberReady, ds.Status.NumberUnavailable),
				FirstObserved: ds.CreationTimestamp.Time,
				LastObserved:  ds.CreationTimestamp.Time,
			})
		}
	}
	return issues, nil
}

// scanReplicaSets analyzes ReplicaSets that are failing to provision pods
func (s *ClusterScanner) scanReplicaSets(ctx context.Context, namespace string) ([]*Issue, error) {
	rsList, err := s.client.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, rs := range rsList.Items {
		specReplicas := int32(1)
		if rs.Spec.Replicas != nil {
			specReplicas = *rs.Spec.Replicas
		}

		// Only check active ReplicaSets with desired replicas
		if specReplicas > 0 && rs.Status.ReadyReplicas < specReplicas {
			for _, cond := range rs.Status.Conditions {
				if cond.Type == "ReplicaFailure" && cond.Status == "True" {
					issues = append(issues, &Issue{
						ID:            generateIssueID(rs.Namespace, "ReplicaSet", rs.Name, string(CategoryReplicaSetStuck)),
						Namespace:     rs.Namespace,
						Kind:          "ReplicaSet",
						Name:          rs.Name,
						Severity:      SeverityHigh,
						Category:      CategoryReplicaSetStuck,
						Summary:       fmt.Sprintf("ReplicaSet failed creating pods: %s", cond.Reason),
						Details:       fmt.Sprintf("ReplicaSet '%s' replica failure: %s", rs.Name, cond.Message),
						FirstObserved: cond.LastTransitionTime.Time,
						LastObserved:  cond.LastTransitionTime.Time,
					})
				}
			}
		}
	}
	return issues, nil
}

// scanJobs analyzes batch Jobs for BackoffLimitExceeded or Deadlines
func (s *ClusterScanner) scanJobs(ctx context.Context, namespace string) ([]*Issue, error) {
	jobs, err := s.client.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, j := range jobs.Items {
		for _, cond := range j.Status.Conditions {
			if cond.Type == "Failed" && cond.Status == "True" {
				issues = append(issues, &Issue{
					ID:            generateIssueID(j.Namespace, "Job", j.Name, string(CategoryJobFailed)),
					Namespace:     j.Namespace,
					Kind:          "Job",
					Name:          j.Name,
					Severity:      SeverityMedium,
					Category:      CategoryJobFailed,
					Summary:       fmt.Sprintf("Batch Job failed: %s", cond.Reason),
					Details:       fmt.Sprintf("Job '%s' failed. Message: %s. Failed pods: %d", j.Name, cond.Message, j.Status.Failed),
					FirstObserved: cond.LastTransitionTime.Time,
					LastObserved:  cond.LastTransitionTime.Time,
				})
			}
		}
	}
	return issues, nil
}

// scanCronJobs analyzes CronJobs for suspended status or failing executions
func (s *ClusterScanner) scanCronJobs(ctx context.Context, namespace string) ([]*Issue, error) {
	cronJobs, err := s.client.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, cj := range cronJobs.Items {
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
			// Informational or skip
			continue
		}
		// If schedule is empty or invalid
		if cj.Spec.Schedule == "" {
			issues = append(issues, &Issue{
				ID:            generateIssueID(cj.Namespace, "CronJob", cj.Name, string(CategoryCronJobFailed)),
				Namespace:     cj.Namespace,
				Kind:          "CronJob",
				Name:          cj.Name,
				Severity:      SeverityMedium,
				Category:      CategoryCronJobFailed,
				Summary:       "CronJob schedule is empty",
				Details:       fmt.Sprintf("CronJob '%s' does not specify a valid cron schedule", cj.Name),
				FirstObserved: cj.CreationTimestamp.Time,
				LastObserved:  cj.CreationTimestamp.Time,
			})
		}
	}
	return issues, nil
}
