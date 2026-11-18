package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// scanDeployments analyzes Deployments for unavailable replicas, replica mismatches, or progress deadline exceeded
func (s *ClusterScanner) scanDeployments(ctx context.Context, namespace string) ([]*Issue, error) {
	depls, err := s.client.AppsV1().Deployments(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, d := range depls.Items {
		specReplicas := int32(1)
		if d.Spec.Replicas != nil {
			specReplicas = *d.Spec.Replicas
		}

		degraded := specReplicas > 0 && d.Status.ReadyReplicas < specReplicas
		details := ""
		if degraded {
			details = fmt.Sprintf("Deployment '%s' in namespace '%s' is degraded. %d replicas unavailable.", d.Name, d.Namespace, specReplicas-d.Status.ReadyReplicas)
		}
		if d.Generation > 0 && d.Status.ObservedGeneration < d.Generation {
			degraded = true
			details = appendWorkloadDetail(details, fmt.Sprintf("Observed generation %d is behind desired generation %d.", d.Status.ObservedGeneration, d.Generation))
		}
		for _, cond := range d.Status.Conditions {
			if (cond.Type == "Progressing" || cond.Type == "Available" || cond.Type == "ReplicaFailure") && cond.Status == "False" {
				degraded = true
				details = appendWorkloadDetail(details, fmt.Sprintf("Condition %s is False: %s - %s.", cond.Type, cond.Reason, cond.Message))
			}
			if cond.Type == "ReplicaFailure" && cond.Status == "True" {
				degraded = true
				details = appendWorkloadDetail(details, fmt.Sprintf("Condition ReplicaFailure is True: %s - %s.", cond.Reason, cond.Message))
			}
		}
		if degraded {
			first := d.CreationTimestamp.Time
			if first.IsZero() {
				first = time.Now().UTC()
			}
			issues = append(issues, &Issue{
				ID: generateIssueID(d.Namespace, "Deployment", d.Name, string(CategoryDeploymentMismatch)), Namespace: d.Namespace,
				Kind: "Deployment", Name: d.Name, TargetUID: string(d.UID), TargetResourceVersion: d.ResourceVersion,
				Severity: SeverityHigh, Category: CategoryDeploymentMismatch,
				Summary: fmt.Sprintf("Deployment has %d/%d ready replicas", d.Status.ReadyReplicas, specReplicas), Details: details,
				FirstObserved: first, LastObserved: time.Now().UTC(), Parent: ownerReferenceForObject(&d),
			})
		}
	}
	return issues, nil
}

// scanStatefulSets analyzes StatefulSets for unready replicas or partition issues
func (s *ClusterScanner) scanStatefulSets(ctx context.Context, namespace string) ([]*Issue, error) {
	ssList, err := s.client.AppsV1().StatefulSets(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, ss := range ssList.Items {
		specReplicas := int32(1)
		if ss.Spec.Replicas != nil {
			specReplicas = *ss.Spec.Replicas
		}

		degraded := specReplicas > 0 && ss.Status.ReadyReplicas < specReplicas
		if ss.Generation > 0 && ss.Status.ObservedGeneration < ss.Generation {
			degraded = true
		}
		if ss.Spec.UpdateStrategy.RollingUpdate != nil && ss.Spec.UpdateStrategy.RollingUpdate.Partition != nil && ss.Status.UpdatedReplicas < specReplicas-*ss.Spec.UpdateStrategy.RollingUpdate.Partition {
			degraded = true
		}
		if degraded {
			first := ss.CreationTimestamp.Time
			if first.IsZero() {
				first = time.Now().UTC()
			}
			issues = append(issues, &Issue{
				ID:        generateIssueID(ss.Namespace, "StatefulSet", ss.Name, string(CategoryStatefulSetMismatch)),
				Namespace: ss.Namespace,
				Kind:      "StatefulSet",
				Name:      ss.Name,
				Severity:  SeverityHigh,
				Category:  CategoryStatefulSetMismatch,
				Summary:   fmt.Sprintf("StatefulSet has %d/%d ready replicas", ss.Status.ReadyReplicas, specReplicas),
				Details: fmt.Sprintf("StatefulSet '%s' ready replicas mismatch. Replicas: %d, Ready: %d, Current: %d, Updated: %d.",
					ss.Name, specReplicas, ss.Status.ReadyReplicas, ss.Status.CurrentReplicas, ss.Status.UpdatedReplicas),
				TargetUID: string(ss.UID), TargetResourceVersion: ss.ResourceVersion,
				FirstObserved: first, LastObserved: time.Now().UTC(), Parent: ownerReferenceForObject(&ss),
			})
		}
	}
	return issues, nil
}

// scanDaemonSets analyzes DaemonSets for unscheduled or unready pods across matching nodes
func (s *ClusterScanner) scanDaemonSets(ctx context.Context, namespace string) ([]*Issue, error) {
	dsList, err := s.client.AppsV1().DaemonSets(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, ds := range dsList.Items {
		degraded := ds.Status.DesiredNumberScheduled > 0 && ds.Status.NumberReady < ds.Status.DesiredNumberScheduled
		if ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled || ds.Status.NumberAvailable < ds.Status.DesiredNumberScheduled {
			degraded = true
		}
		if degraded {
			issues = append(issues, &Issue{
				ID:        generateIssueID(ds.Namespace, "DaemonSet", ds.Name, string(CategoryDaemonSetMismatch)),
				Namespace: ds.Namespace,
				Kind:      "DaemonSet",
				Name:      ds.Name,
				Severity:  SeverityMedium,
				Category:  CategoryDaemonSetMismatch,
				Summary:   fmt.Sprintf("DaemonSet has %d/%d ready pods", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled),
				Details: fmt.Sprintf("DaemonSet '%s' has %d unready pods across cluster nodes. Desired: %d, Current: %d, Ready: %d, Unavailable: %d.",
					ds.Name, ds.Status.DesiredNumberScheduled-ds.Status.NumberReady, ds.Status.DesiredNumberScheduled, ds.Status.CurrentNumberScheduled, ds.Status.NumberReady, ds.Status.NumberUnavailable),
				TargetUID: string(ds.UID), TargetResourceVersion: ds.ResourceVersion,
				FirstObserved: workloadObservedTime(ds.CreationTimestamp), LastObserved: time.Now().UTC(), Parent: ownerReferenceForObject(&ds),
			})
		}
	}
	return issues, nil
}

// scanReplicaSets analyzes ReplicaSets that are failing to provision pods
func (s *ClusterScanner) scanReplicaSets(ctx context.Context, namespace string) ([]*Issue, error) {
	rsList, err := s.client.AppsV1().ReplicaSets(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, rs := range rsList.Items {
		specReplicas := int32(1)
		if rs.Spec.Replicas != nil {
			specReplicas = *rs.Spec.Replicas
		}

		if specReplicas > 0 && rs.Status.ReadyReplicas < specReplicas {
			details := fmt.Sprintf("ReplicaSet '%s' has %d/%d ready replicas.", rs.Name, rs.Status.ReadyReplicas, specReplicas)
			reason := "ReadyReplicasMismatch"
			for _, cond := range rs.Status.Conditions {
				if cond.Type == "ReplicaFailure" && cond.Status == "True" {
					reason = cond.Reason
					details = appendWorkloadDetail(details, cond.Message)
				}
			}
			issues = append(issues, &Issue{
				ID: generateIssueID(rs.Namespace, "ReplicaSet", rs.Name, string(CategoryReplicaSetStuck)), Namespace: rs.Namespace,
				Kind: "ReplicaSet", Name: rs.Name, TargetUID: string(rs.UID), TargetResourceVersion: rs.ResourceVersion,
				Severity: SeverityHigh, Category: CategoryReplicaSetStuck, Summary: fmt.Sprintf("ReplicaSet is not ready: %s", reason), Details: details,
				FirstObserved: workloadObservedTime(rs.CreationTimestamp), LastObserved: time.Now().UTC(), Parent: ownerReferenceForObject(&rs),
			})
		}
	}
	return issues, nil
}

// scanJobs analyzes batch Jobs for BackoffLimitExceeded or Deadlines
func (s *ClusterScanner) scanJobs(ctx context.Context, namespace string) ([]*Issue, error) {
	jobs, err := s.client.BatchV1().Jobs(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	// Only a failing Job owned by a CronJob needs the CronJobs, so they are
	// listed on first use and at most once.
	cronJobs := sync.OnceValues(func() (map[string]*batchv1.CronJob, error) {
		return s.cronJobsByKey(ctx, namespace)
	})
	var cronJobLookupErr error

	now := time.Now().UTC()
	var issues []*Issue
	for index := range jobs.Items {
		job := &jobs.Items[index]
		jobIssues := analyzeJobFailures(job, now)
		if len(jobIssues) == 0 {
			continue
		}
		if owner := controllingCronJobName(job); owner != "" {
			owners, lookupErr := cronJobs()
			if lookupErr != nil {
				// Without the CronJob's status the failure cannot be shown to
				// be superseded, so it is reported.
				cronJobLookupErr = lookupErr
			} else if isSupersededCronJobRun(job, owners[namespaceKey(job.Namespace, owner)], now) {
				continue
			}
		}
		issues = append(issues, jobIssues...)
	}
	return issues, cronJobLookupErr
}

// cronJobsByKey indexes the CronJobs of the scanned namespace. They are a
// dependency of the Jobs under analysis, so the plan selectors do not apply.
func (s *ClusterScanner) cronJobsByKey(ctx context.Context, namespace string) (map[string]*batchv1.CronJob, error) {
	list, err := s.client.BatchV1().CronJobs(namespace).List(ctx, unscopedDependencyListOptions(ctx))
	if err != nil {
		return nil, fmt.Errorf("list CronJobs owning failed Jobs in namespace %q: %w", namespace, err)
	}
	byKey := make(map[string]*batchv1.CronJob, len(list.Items))
	for index := range list.Items {
		cronJob := &list.Items[index]
		byKey[namespaceKey(cronJob.Namespace, cronJob.Name)] = cronJob
	}
	return byKey, nil
}

func analyzeJobFailures(j *batchv1.Job, now time.Time) []*Issue {
	var issues []*Issue
	complete := false
	for _, cond := range j.Status.Conditions {
		if cond.Type == batchv1.JobComplete && cond.Status == corev1.ConditionTrue {
			complete = true
		}
		if cond.Type == batchv1.JobFailed && cond.Status == corev1.ConditionTrue {
			issues = append(issues, &Issue{
				ID:        generateIssueID(j.Namespace, "Job", j.Name, string(CategoryJobFailed)),
				Namespace: j.Namespace,
				Kind:      "Job",
				Name:      j.Name,
				Severity:  SeverityMedium,
				Category:  CategoryJobFailed,
				Summary:   fmt.Sprintf("Batch Job failed: %s", cond.Reason),
				Details:   fmt.Sprintf("Job '%s' failed. Message: %s. Failed pods: %d", j.Name, cond.Message, j.Status.Failed),
				TargetUID: string(j.UID), TargetResourceVersion: j.ResourceVersion,
				FirstObserved: workloadObservedTime(cond.LastTransitionTime),
				LastObserved:  now, Parent: ownerReferenceForObject(j),
			})
		}
	}
	if complete {
		return issues
	}
	if j.Spec.BackoffLimit != nil && j.Status.Failed > *j.Spec.BackoffLimit {
		issues = append(issues, &Issue{
			ID: generateIssueID(j.Namespace, "Job", j.Name, string(CategoryJobBackoffExceeded)), Namespace: j.Namespace,
			Kind: "Job", Name: j.Name, TargetUID: string(j.UID), TargetResourceVersion: j.ResourceVersion,
			Severity: SeverityHigh, Category: CategoryJobBackoffExceeded,
			Summary:       fmt.Sprintf("Job exceeded its backoff limit (%d)", *j.Spec.BackoffLimit),
			Details:       fmt.Sprintf("Job %s has %d failed pod attempts, greater than backoffLimit %d.", j.Name, j.Status.Failed, *j.Spec.BackoffLimit),
			FirstObserved: workloadObservedTime(j.CreationTimestamp), LastObserved: now, Parent: ownerReferenceForObject(j),
		})
	}
	if deadline, ok := jobActiveDeadline(j); ok && now.After(deadline) {
		issues = append(issues, &Issue{
			ID: generateIssueID(j.Namespace, "Job", j.Name, string(CategoryJobDeadlineExceeded)), Namespace: j.Namespace,
			Kind: "Job", Name: j.Name, TargetUID: string(j.UID), TargetResourceVersion: j.ResourceVersion,
			Severity: SeverityHigh, Category: CategoryJobDeadlineExceeded,
			Summary: fmt.Sprintf("Job %s exceeded its active deadline", j.Name), Details: "The Job ran longer than spec.activeDeadlineSeconds without completing.",
			FirstObserved: workloadObservedTime(*j.Status.StartTime), LastObserved: now, Parent: ownerReferenceForObject(j),
		})
	}
	return issues
}

// jobActiveDeadline returns the moment the Job's spec.activeDeadlineSeconds
// runs out, for a Job that has a deadline and has started.
func jobActiveDeadline(job *batchv1.Job) (time.Time, bool) {
	if job.Spec.ActiveDeadlineSeconds == nil || job.Status.StartTime == nil {
		return time.Time{}, false
	}
	return job.Status.StartTime.Add(time.Duration(*job.Spec.ActiveDeadlineSeconds) * time.Second), true
}

// controllingCronJobName returns the name of the CronJob that controls the
// Job, or "" for a Job that no CronJob controls.
func controllingCronJobName(job *batchv1.Job) string {
	for _, owner := range job.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && owner.Kind == "CronJob" {
			return owner.Name
		}
	}
	return ""
}

// isSupersededCronJobRun reports whether the owning CronJob has completed a
// run since the Job failed. Such a failure is history: the schedule has
// recovered, and the old Job leaves nothing to act on. A success at the very
// moment of the failure does not count.
func isSupersededCronJobRun(job *batchv1.Job, cronJob *batchv1.CronJob, now time.Time) bool {
	if cronJob == nil || cronJob.Status.LastSuccessfulTime == nil {
		return false
	}
	failedAt := jobFailureTime(job, now)
	return !failedAt.IsZero() && cronJob.Status.LastSuccessfulTime.After(failedAt)
}

// jobFailureTime returns the latest moment at which the Job is known to have
// been failing: its creation or start, the transition of its Failed condition,
// or, while it has no terminal condition, the expiry of its active deadline.
// A Job that started before its CronJob's last success can still breach its
// deadline after it, and that breach is not superseded.
func jobFailureTime(job *batchv1.Job, now time.Time) time.Time {
	latest := job.CreationTimestamp.Time
	consider := func(candidate time.Time) {
		if candidate.After(latest) {
			latest = candidate
		}
	}
	if job.Status.StartTime != nil {
		consider(job.Status.StartTime.Time)
	}
	terminal := false
	for _, cond := range job.Status.Conditions {
		if cond.Status != corev1.ConditionTrue {
			continue
		}
		switch cond.Type {
		case batchv1.JobComplete:
			terminal = true
		case batchv1.JobFailed:
			terminal = true
			consider(cond.LastTransitionTime.Time)
		}
	}
	if deadline, ok := jobActiveDeadline(job); ok && !terminal && now.After(deadline) {
		consider(deadline)
	}
	return latest
}

// scanCronJobs analyzes CronJobs for suspended status or failing executions
func (s *ClusterScanner) scanCronJobs(ctx context.Context, namespace string) ([]*Issue, error) {
	cronJobs, err := s.client.BatchV1().CronJobs(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, cj := range cronJobs.Items {
		// If schedule is empty or invalid
		if cj.Spec.Schedule == "" {
			issues = append(issues, &Issue{
				ID:        generateIssueID(cj.Namespace, "CronJob", cj.Name, string(CategoryCronJobFailed)),
				Namespace: cj.Namespace,
				Kind:      "CronJob",
				Name:      cj.Name,
				Severity:  SeverityMedium,
				Category:  CategoryCronJobFailed,
				Summary:   "CronJob schedule is empty",
				Details:   fmt.Sprintf("CronJob '%s' does not specify a valid cron schedule", cj.Name),
				TargetUID: string(cj.UID), TargetResourceVersion: cj.ResourceVersion,
				FirstObserved: workloadObservedTime(cj.CreationTimestamp), LastObserved: time.Now().UTC(), Parent: ownerReferenceForObject(&cj),
			})
		}
	}
	return issues, nil
}

func appendWorkloadDetail(current, addition string) string {
	if current == "" {
		return addition
	}
	if addition == "" {
		return current
	}
	return current + " " + addition
}

func workloadObservedTime(value metav1.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.Time
}

func ownerReferenceForObject(object metav1.Object) *ResourceRef {
	if object == nil {
		return nil
	}
	owners := object.GetOwnerReferences()
	if len(owners) == 0 {
		return nil
	}
	owner := owners[0]
	for _, candidate := range owners {
		if candidate.Controller != nil && *candidate.Controller {
			owner = candidate
			break
		}
	}
	return &ResourceRef{Namespace: object.GetNamespace(), Kind: owner.Kind, Name: owner.Name, UID: string(owner.UID)}
}
