package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanplan"
)

type ClusterScanner struct {
	client          kubernetes.Interface
	cleaner         *PodCleaner
	historyRecordMu sync.Mutex
	history         HistoryStore
	metrics         MetricsObserver
	custom          *AnalyzerRegistry
}

// MetricsObserver is intentionally small so scanner callers can provide a
// Prometheus registry or another exporter without coupling scanner to one.
type MetricsObserver interface {
	ObserveScan(error, time.Duration)
	ObserveAnalyzer(string, error, time.Duration)
}

var ErrKubernetesClientUnavailable = errors.New("kubernetes client is unavailable")

func NewClusterScanner(client kubernetes.Interface) *ClusterScanner {
	return &ClusterScanner{
		client:  client,
		cleaner: NewPodCleaner(client),
		custom:  NewAnalyzerRegistry(),
	}
}

func NewClusterScannerWithHistory(client kubernetes.Interface, history HistoryStore) *ClusterScanner {
	scanner := NewClusterScanner(client)
	scanner.history = history
	return scanner
}

func (s *ClusterScanner) SetHistoryStore(history HistoryStore) {
	s.history = history
}

func (s *ClusterScanner) History() HistoryStore {
	return s.history
}

func (s *ClusterScanner) SetMetricsObserver(observer MetricsObserver) {
	s.metrics = observer
}

func (s *ClusterScanner) MetricsObserver() MetricsObserver {
	return s.metrics
}

// RegisterAnalyzer adds an explicit in-process analyzer to future scans.
func (s *ClusterScanner) RegisterAnalyzer(analyzer Analyzer) error {
	if s == nil {
		return ErrAnalyzerInvalid
	}
	if s.custom == nil {
		s.custom = NewAnalyzerRegistry()
	}
	return s.custom.Register(analyzer)
}

func (s *ClusterScanner) UnregisterAnalyzer(name string) error {
	if s == nil || s.custom == nil {
		return ErrAnalyzerNotFound
	}
	return s.custom.Unregister(name)
}

func (s *ClusterScanner) CustomAnalyzers() []Analyzer {
	if s == nil || s.custom == nil {
		return nil
	}
	return s.custom.List()
}

func (s *ClusterScanner) GetPodCleaner() *PodCleaner {
	return s.cleaner
}

// Scan executes all registered analyzers across the target namespace (or all
// namespaces) through the versioned scan-plan contract. Keeping this legacy
// method as a thin adapter ensures REST callers and background scans receive
// the same filters, history, metrics, and error semantics.
func (s *ClusterScanner) Scan(ctx context.Context, namespace string) ([]*Issue, error) {
	plan := scanplan.Default()
	if strings.TrimSpace(namespace) != "" {
		plan.IncludeNamespaces = []string{strings.TrimSpace(namespace)}
	}
	report, err := s.ScanWithPlan(ctx, plan)
	if report == nil {
		return nil, err
	}
	return report.Issues, err
}

func (s *ClusterScanner) enrichIssueTargets(ctx context.Context, issues []*Issue) []*Issue {
	if s == nil || s.client == nil {
		return issues
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, issue := range issues {
		if err := ctx.Err(); err != nil {
			break
		}
		if issue == nil || (issue.TargetUID != "" && issue.TargetResourceVersion != "") {
			continue
		}
		var object metav1.Object
		var err error
		switch issue.Kind {
		case "Pod":
			object, err = s.client.CoreV1().Pods(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "Deployment":
			object, err = s.client.AppsV1().Deployments(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "StatefulSet":
			object, err = s.client.AppsV1().StatefulSets(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "DaemonSet":
			object, err = s.client.AppsV1().DaemonSets(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "ReplicaSet":
			object, err = s.client.AppsV1().ReplicaSets(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "Job":
			object, err = s.client.BatchV1().Jobs(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "CronJob":
			object, err = s.client.BatchV1().CronJobs(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "Service":
			object, err = s.client.CoreV1().Services(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "Ingress":
			object, err = s.client.NetworkingV1().Ingresses(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "NetworkPolicy":
			object, err = s.client.NetworkingV1().NetworkPolicies(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "PersistentVolumeClaim":
			object, err = s.client.CoreV1().PersistentVolumeClaims(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "Node":
			object, err = s.client.CoreV1().Nodes().Get(ctx, issue.Name, metav1.GetOptions{})
		case "HorizontalPodAutoscaler":
			object, err = s.client.AutoscalingV2().HorizontalPodAutoscalers(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		case "PodDisruptionBudget":
			object, err = s.client.PolicyV1().PodDisruptionBudgets(issue.Namespace).Get(ctx, issue.Name, metav1.GetOptions{})
		}
		if err == nil && object != nil {
			issue.TargetUID = string(object.GetUID())
			issue.TargetResourceVersion = object.GetResourceVersion()
		}
	}
	return issues
}

func (s *ClusterScanner) scanPods(ctx context.Context, namespace string) ([]*Issue, error) {
	pods, err := s.client.CoreV1().Pods(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	var enrichmentErrors []error
	for _, pod := range pods.Items {
		// Ignore Succeeded/Completed pods from normal anomaly alert (handled by Cleaner)
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}

		findings := s.analyzePodFindings(&pod)
		if len(findings) == 0 {
			continue
		}
		logs, logErr := s.fetchPodLogsSnippetWithError(ctx, pod.Namespace, pod.Name)
		if logErr != nil && !apierrors.IsNotFound(logErr) {
			enrichmentErrors = append(enrichmentErrors, fmt.Errorf("read logs for Pod %s/%s: %w", pod.Namespace, pod.Name, logErr))
		}
		events, eventErr := s.fetchPodWarningEventsWithError(ctx, pod.Namespace, pod.Name)
		if eventErr != nil && !apierrors.IsNotFound(eventErr) {
			enrichmentErrors = append(enrichmentErrors, fmt.Errorf("list warning Events for Pod %s/%s: %w", pod.Namespace, pod.Name, eventErr))
		}
		for _, issue := range findings {
			// Enrich with tail logs & warning events
			issue.LogsSnippet = logs
			issue.Events = events
			issue.Parent = podOwnerReference(&pod)
			issues = append(issues, issue)
		}
	}
	return issues, errors.Join(enrichmentErrors...)
}

func (s *ClusterScanner) analyzePod(pod *corev1.Pod) (issue *Issue) {
	defer func() {
		if issue != nil && pod != nil {
			issue.TargetUID = string(pod.UID)
			issue.TargetResourceVersion = pod.ResourceVersion
		}
	}()
	now := time.Now()

	// 1. Check if Pod is Evicted
	if pod.Status.Reason == "Evicted" {
		return &Issue{
			ID:            makeID(pod.Namespace, "Pod", pod.Name, "Evicted"),
			Namespace:     pod.Namespace,
			Kind:          "Pod",
			Name:          pod.Name,
			Severity:      SeverityMedium,
			Category:      CategoryPodEvicted,
			Summary:       fmt.Sprintf("Pod was evicted: %s", pod.Status.Message),
			Details:       fmt.Sprintf("Node evicted pod due to resource constraints. Message: %s", pod.Status.Message),
			FirstObserved: now,
			LastObserved:  now,
		}
	}

	// 2. Check if Pod is Stuck in Terminating
	if pod.DeletionTimestamp != nil {
		if now.Sub(pod.DeletionTimestamp.Time) > 5*time.Minute {
			return &Issue{
				ID:            makeID(pod.Namespace, "Pod", pod.Name, "StuckTerminating"),
				Namespace:     pod.Namespace,
				Kind:          "Pod",
				Name:          pod.Name,
				Severity:      SeverityHigh,
				Category:      CategoryPodStuckTerminating,
				Summary:       "Pod is stuck in Terminating status (> 5 minutes)",
				Details:       fmt.Sprintf("Pod deletion was requested at %s but container runtime/finalizers have not terminated.", pod.DeletionTimestamp.Time.Format(time.RFC3339)),
				FirstObserved: pod.DeletionTimestamp.Time,
				LastObserved:  now,
			}
		}
		return nil
	}

	// 3. Check container statuses
	statuses := append([]corev1.ContainerStatus(nil), pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
	for _, cs := range statuses {
		// Waiting state checks
		if cs.State.Waiting != nil {
			reason := cs.State.Waiting.Reason
			switch reason {
			case "CrashLoopBackOff":
				return &Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, reason),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityCritical,
					Category:      CategoryCrashLoop,
					Summary:       fmt.Sprintf("Container '%s' in pod %s is in CrashLoopBackOff", cs.Name, pod.Name),
					Details:       fmt.Sprintf("Container %s is repeatedly crashing with message: %s", cs.Name, cs.State.Waiting.Message),
					FirstObserved: now,
					LastObserved:  now,
				}
			case "ImagePullBackOff", "ErrImagePull":
				return &Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, reason),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityHigh,
					Category:      CategoryImagePull,
					Summary:       fmt.Sprintf("Failed to pull image '%s' for container '%s'", cs.Image, cs.Name),
					Details:       cs.State.Waiting.Message,
					FirstObserved: now,
					LastObserved:  now,
				}
			case "CreateContainerConfigError", "CreateContainerError":
				return &Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, reason),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityHigh,
					Category:      CategoryContainerConfig,
					Summary:       fmt.Sprintf("Container '%s' failed configuration/setup", cs.Name),
					Details:       cs.State.Waiting.Message,
					FirstObserved: now,
					LastObserved:  now,
				}
			}
		}

		// Terminated state checks (OOMKilled, exit 137)
		if cs.State.Terminated != nil {
			if cs.State.Terminated.Reason == "OOMKilled" || cs.State.Terminated.ExitCode == 137 {
				return &Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, "OOMKilled"),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityCritical,
					Category:      CategoryOOMKilled,
					Summary:       fmt.Sprintf("Container '%s' was OOMKilled (Exit 137)", cs.Name),
					Details:       "Container process exceeded memory limits configured in resource spec and was terminated by Linux kernel OOM killer.",
					FirstObserved: cs.State.Terminated.FinishedAt.Time,
					LastObserved:  now,
				}
			}
		}

		// High restart counts (> 5)
		if cs.RestartCount > 5 {
			return &Issue{
				ID:            makeID(pod.Namespace, "Pod", pod.Name, "HighRestarts"),
				Namespace:     pod.Namespace,
				Kind:          "Pod",
				Name:          pod.Name,
				Severity:      SeverityHigh,
				Category:      CategoryHighRestarts,
				Summary:       fmt.Sprintf("Container '%s' has restarted %d times", cs.Name, cs.RestartCount),
				Details:       "High container restart frequency indicates workload instability, memory pressure, or liveness probe failures.",
				FirstObserved: now,
				LastObserved:  now,
			}
		}
	}

	// 4. Pending / Unschedulable
	if pod.Status.Phase == corev1.PodPending {
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
				return &Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, "FailedScheduling"),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityHigh,
					Category:      CategoryFailedScheduling,
					Summary:       fmt.Sprintf("Pod is unschedulable: %s", cond.Reason),
					Details:       cond.Message,
					FirstObserved: cond.LastTransitionTime.Time,
					LastObserved:  now,
				}
			}
		}
	}

	// 5. Phase Failed
	if pod.Status.Phase == corev1.PodFailed {
		return &Issue{
			ID:            makeID(pod.Namespace, "Pod", pod.Name, "PodFailed"),
			Namespace:     pod.Namespace,
			Kind:          "Pod",
			Name:          pod.Name,
			Severity:      SeverityHigh,
			Category:      CategoryPodFailed,
			Summary:       fmt.Sprintf("Pod is in Failed phase: %s", pod.Status.Reason),
			Details:       pod.Status.Message,
			FirstObserved: now,
			LastObserved:  now,
		}
	}

	return nil
}

// analyzePodFindings preserves every independent signal on a pod. The legacy
// analyzePod helper remains for callers that only need the highest-priority
// first finding.
func (s *ClusterScanner) analyzePodFindings(pod *corev1.Pod) []*Issue {
	if pod == nil {
		return nil
	}
	now := time.Now().UTC()
	findings := make([]*Issue, 0, 4)
	appendIssue := func(issue *Issue) {
		if issue == nil {
			return
		}
		issue.TargetUID = string(pod.UID)
		issue.TargetResourceVersion = pod.ResourceVersion
		findings = append(findings, issue)
	}

	if pod.Status.Reason == "Evicted" {
		appendIssue(&Issue{
			ID:            makeID(pod.Namespace, "Pod", pod.Name, "Evicted"),
			Namespace:     pod.Namespace,
			Kind:          "Pod",
			Name:          pod.Name,
			Severity:      SeverityMedium,
			Category:      CategoryPodEvicted,
			Summary:       fmt.Sprintf("Pod was evicted: %s", pod.Status.Message),
			Details:       fmt.Sprintf("Node evicted pod due to resource constraints. Message: %s", pod.Status.Message),
			FirstObserved: now,
			LastObserved:  now,
		})
	}
	if pod.DeletionTimestamp != nil {
		if now.Sub(pod.DeletionTimestamp.Time) > 5*time.Minute {
			appendIssue(&Issue{
				ID:            makeID(pod.Namespace, "Pod", pod.Name, "StuckTerminating"),
				Namespace:     pod.Namespace,
				Kind:          "Pod",
				Name:          pod.Name,
				Severity:      SeverityHigh,
				Category:      CategoryPodStuckTerminating,
				Summary:       "Pod is stuck in Terminating status (> 5 minutes)",
				Details:       fmt.Sprintf("Pod deletion was requested at %s but container runtime/finalizers have not terminated.", pod.DeletionTimestamp.Time.Format(time.RFC3339)),
				FirstObserved: pod.DeletionTimestamp.Time,
				LastObserved:  now,
			})
		}
		return findings
	}

	statuses := append(append([]corev1.ContainerStatus(nil), pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
	for _, status := range statuses {
		containerID := status.Name
		crashLoopReported := false
		if status.State.Waiting != nil {
			switch status.State.Waiting.Reason {
			case "CrashLoopBackOff":
				appendIssue(&Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, "CrashLoop-"+containerID),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityCritical,
					Category:      CategoryCrashLoop,
					Summary:       fmt.Sprintf("Container '%s' in pod %s is in CrashLoopBackOff", containerID, pod.Name),
					Details:       fmt.Sprintf("Container %s is repeatedly crashing with message: %s", containerID, status.State.Waiting.Message),
					FirstObserved: now,
					LastObserved:  now,
				})
				crashLoopReported = true
			case "ImagePullBackOff", "ErrImagePull":
				appendIssue(&Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, "ImagePull-"+containerID),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityHigh,
					Category:      CategoryImagePull,
					Summary:       fmt.Sprintf("Failed to pull image '%s' for container '%s'", status.Image, containerID),
					Details:       status.State.Waiting.Message,
					FirstObserved: now,
					LastObserved:  now,
				})
			case "CreateContainerConfigError", "CreateContainerError":
				appendIssue(&Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, "ContainerConfig-"+containerID),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityHigh,
					Category:      CategoryContainerConfig,
					Summary:       fmt.Sprintf("Container '%s' failed configuration/setup", containerID),
					Details:       status.State.Waiting.Message,
					FirstObserved: now,
					LastObserved:  now,
				})
			}
		}
		if terminated := status.State.Terminated; terminated != nil && (terminated.Reason == "OOMKilled" || terminated.ExitCode == 137) {
			observed := terminated.FinishedAt.Time
			if observed.IsZero() {
				observed = now
			}
			appendIssue(&Issue{
				ID:            makeID(pod.Namespace, "Pod", pod.Name, "OOMKilled-"+containerID),
				Namespace:     pod.Namespace,
				Kind:          "Pod",
				Name:          pod.Name,
				Severity:      SeverityCritical,
				Category:      CategoryOOMKilled,
				Summary:       fmt.Sprintf("Container '%s' was OOMKilled (Exit 137)", containerID),
				Details:       "Container process exceeded memory limits configured in the resource spec and was terminated by the Linux OOM killer.",
				FirstObserved: observed,
				LastObserved:  now,
			})
		}
		if !crashLoopReported && pod.Spec.RestartPolicy == corev1.RestartPolicyAlways && status.RestartCount > 0 {
			if terminated := status.State.Terminated; terminated != nil && terminated.ExitCode != 0 {
				appendIssue(&Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, "CrashLoop-"+containerID),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityCritical,
					Category:      CategoryCrashLoop,
					Summary:       fmt.Sprintf("Container '%s' in pod %s is repeatedly terminating and restarting", containerID, pod.Name),
					Details:       fmt.Sprintf("Container %s exited with code %d and has restarted %d times under restartPolicy Always.", containerID, terminated.ExitCode, status.RestartCount),
					FirstObserved: now,
					LastObserved:  now,
				})
			}
		}
		if status.RestartCount > 5 {
			appendIssue(&Issue{
				ID:            makeID(pod.Namespace, "Pod", pod.Name, "HighRestarts-"+containerID),
				Namespace:     pod.Namespace,
				Kind:          "Pod",
				Name:          pod.Name,
				Severity:      SeverityHigh,
				Category:      CategoryHighRestarts,
				Summary:       fmt.Sprintf("Container '%s' has restarted %d times", containerID, status.RestartCount),
				Details:       "High container restart frequency indicates workload instability, memory pressure, or liveness probe failures.",
				FirstObserved: now,
				LastObserved:  now,
			})
		}
	}

	if pod.Status.Phase == corev1.PodPending {
		for _, condition := range pod.Status.Conditions {
			if condition.Type != corev1.PodScheduled || condition.Status != corev1.ConditionFalse {
				continue
			}
			observed := condition.LastTransitionTime.Time
			if observed.IsZero() {
				observed = now
			}
			appendIssue(&Issue{
				ID:            makeID(pod.Namespace, "Pod", pod.Name, "FailedScheduling"),
				Namespace:     pod.Namespace,
				Kind:          "Pod",
				Name:          pod.Name,
				Severity:      SeverityHigh,
				Category:      CategoryFailedScheduling,
				Summary:       fmt.Sprintf("Pod is unschedulable: %s", condition.Reason),
				Details:       condition.Message,
				FirstObserved: observed,
				LastObserved:  now,
			})
		}
	}
	if pod.Status.Phase == corev1.PodFailed {
		appendIssue(&Issue{
			ID:            makeID(pod.Namespace, "Pod", pod.Name, "PodFailed"),
			Namespace:     pod.Namespace,
			Kind:          "Pod",
			Name:          pod.Name,
			Severity:      SeverityHigh,
			Category:      CategoryPodFailed,
			Summary:       fmt.Sprintf("Pod is in Failed phase: %s", pod.Status.Reason),
			Details:       pod.Status.Message,
			FirstObserved: now,
			LastObserved:  now,
		})
	}
	return findings
}

func podOwnerReference(pod *corev1.Pod) *ResourceRef {
	if pod == nil || len(pod.OwnerReferences) == 0 {
		return nil
	}
	owner := pod.OwnerReferences[0]
	return &ResourceRef{Namespace: pod.Namespace, Kind: owner.Kind, Name: owner.Name, UID: string(owner.UID)}
}

func (s *ClusterScanner) scanNodes(ctx context.Context) ([]*Issue, error) {
	nodes, err := s.client.CoreV1().Nodes().List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	now := time.Now()

	for _, node := range nodes.Items {
		for _, cond := range node.Status.Conditions {
			// Check Ready condition
			if cond.Type == corev1.NodeReady && cond.Status != corev1.ConditionTrue {
				issues = append(issues, &Issue{
					ID:            makeID("", "Node", node.Name, "NodeNotReady"),
					Namespace:     "",
					Kind:          "Node",
					Name:          node.Name,
					Severity:      SeverityCritical,
					Category:      CategoryNodeNotReady,
					Summary:       fmt.Sprintf("Node %s is NotReady (%s)", node.Name, cond.Reason),
					Details:       cond.Message,
					FirstObserved: cond.LastTransitionTime.Time,
					LastObserved:  now,
				})
			}

			// Check Pressure conditions (DiskPressure, MemoryPressure, PIDPressure)
			if (cond.Type == corev1.NodeDiskPressure || cond.Type == corev1.NodeMemoryPressure || cond.Type == corev1.NodePIDPressure) && cond.Status == corev1.ConditionTrue {
				issues = append(issues, &Issue{
					ID:            makeID("", "Node", node.Name, string(cond.Type)),
					Namespace:     "",
					Kind:          "Node",
					Name:          node.Name,
					Severity:      SeverityCritical,
					Category:      CategoryNodePressure,
					Summary:       fmt.Sprintf("Node %s is under %s", node.Name, cond.Type),
					Details:       fmt.Sprintf("Node %s condition %s is True: %s", node.Name, cond.Type, cond.Message),
					FirstObserved: cond.LastTransitionTime.Time,
					LastObserved:  now,
				})
			}

			if cond.Type == corev1.NodeNetworkUnavailable && cond.Status == corev1.ConditionTrue {
				issues = append(issues, &Issue{
					ID:            makeID("", "Node", node.Name, "NetworkUnavailable"),
					Kind:          "Node",
					Name:          node.Name,
					Severity:      SeverityCritical,
					Category:      CategoryNodeNetworkUnavailable,
					Summary:       fmt.Sprintf("Node %s has unavailable network", node.Name),
					Details:       cond.Message,
					FirstObserved: cond.LastTransitionTime.Time,
					LastObserved:  now,
				})
			}
		}
		if node.Spec.Unschedulable {
			issues = append(issues, &Issue{
				ID:            makeID("", "Node", node.Name, "Unschedulable"),
				Kind:          "Node",
				Name:          node.Name,
				Severity:      SeverityMedium,
				Category:      CategoryNodeUnschedulable,
				Summary:       fmt.Sprintf("Node %s is cordoned", node.Name),
				Details:       "The node is marked unschedulable and will not accept new pods until it is uncordoned.",
				FirstObserved: now,
				LastObserved:  now,
			})
		}
		for _, taint := range node.Spec.Taints {
			if taint.Effect != corev1.TaintEffectNoSchedule && taint.Effect != corev1.TaintEffectNoExecute {
				continue
			}
			issues = append(issues, &Issue{
				ID:            makeID("", "Node", node.Name, "Taint-"+taint.Key),
				Kind:          "Node",
				Name:          node.Name,
				Severity:      SeverityLow,
				Category:      CategoryNodeTaint,
				Summary:       fmt.Sprintf("Node %s has a %s taint", node.Name, taint.Effect),
				Details:       fmt.Sprintf("Taint %s=%s:%s may prevent workloads without a matching toleration from scheduling.", taint.Key, taint.Value, taint.Effect),
				FirstObserved: now,
				LastObserved:  now,
			})
		}
	}
	return issues, nil
}

func (s *ClusterScanner) scanPVCs(ctx context.Context, namespace string) ([]*Issue, error) {
	pvcs, err := s.client.CoreV1().PersistentVolumeClaims(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	now := time.Now()

	for _, pvc := range pvcs.Items {
		if pvc.Status.Phase == corev1.ClaimPending {
			issues = append(issues, &Issue{
				ID:            makeID(pvc.Namespace, "PersistentVolumeClaim", pvc.Name, "Pending"),
				Namespace:     pvc.Namespace,
				Kind:          "PersistentVolumeClaim",
				Name:          pvc.Name,
				Severity:      SeverityHigh,
				Category:      CategoryPVCPending,
				Summary:       fmt.Sprintf("PVC %s is stuck in Pending state", pvc.Name),
				Details:       fmt.Sprintf("PVC %s in namespace %s has not bound to any PersistentVolume. Check StorageClass provisioning.", pvc.Name, pvc.Namespace),
				FirstObserved: pvc.CreationTimestamp.Time,
				LastObserved:  now,
			})
		}
		if pvc.Status.Phase == corev1.ClaimLost {
			issues = append(issues, &Issue{
				ID:            makeID(pvc.Namespace, "PersistentVolumeClaim", pvc.Name, "Lost"),
				Namespace:     pvc.Namespace,
				Kind:          "PersistentVolumeClaim",
				Name:          pvc.Name,
				Severity:      SeverityCritical,
				Category:      CategoryPVLost,
				Summary:       fmt.Sprintf("PVC %s is in ClaimLost state", pvc.Name),
				Details:       fmt.Sprintf("PVC %s lost its underlying bound volume.", pvc.Name),
				FirstObserved: pvc.CreationTimestamp.Time,
				LastObserved:  now,
			})
		}
	}
	return issues, nil
}

func (s *ClusterScanner) scanServices(ctx context.Context, namespace string) ([]*Issue, error) {
	svcs, err := s.client.CoreV1().Services(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	var observationErrors []error
	now := time.Now()

	for index := range svcs.Items {
		svc := &svcs.Items[index]
		if svc.Spec.Type == corev1.ServiceTypeExternalName {
			if len(utilvalidation.IsDNS1123Subdomain(svc.Spec.ExternalName)) > 0 {
				issues = append(issues, &Issue{
					ID: makeID(svc.Namespace, "Service", svc.Name, string(CategoryServiceExternalInvalid)), Namespace: svc.Namespace,
					Kind: "Service", Name: svc.Name, TargetUID: string(svc.UID), TargetResourceVersion: svc.ResourceVersion,
					Severity: SeverityHigh, Category: CategoryServiceExternalInvalid,
					Summary:       fmt.Sprintf("Service %s has an invalid ExternalName", svc.Name),
					Details:       fmt.Sprintf("ExternalName %q is not a valid DNS name.", svc.Spec.ExternalName),
					FirstObserved: workloadObservedTime(svc.CreationTimestamp), LastObserved: now,
				})
			}
			continue
		}

		totalEndpoints, endpointObjectFound, endpointComplete, endpointErr := s.serviceReadyEndpoints(ctx, svc)
		if endpointErr != nil {
			observationErrors = append(observationErrors, fmt.Errorf("read Service %s/%s endpoints: %w", svc.Namespace, svc.Name, endpointErr))
			issues = append(issues, &Issue{
				ID:            makeID(svc.Namespace, "Service", svc.Name, "EndpointError"),
				Namespace:     svc.Namespace,
				Kind:          "Service",
				Name:          svc.Name,
				Severity:      SeverityHigh,
				Category:      CategoryServiceEndpointError,
				Summary:       fmt.Sprintf("Service %s endpoint state could not be read", svc.Name),
				Details:       "Endpoint and EndpointSlice lookup failed; verify discovery permissions and the service controller.",
				FirstObserved: svc.CreationTimestamp.Time,
				LastObserved:  now,
			})
			continue
		}

		if !endpointComplete {
			observationErrors = append(observationErrors, fmt.Errorf("incomplete EndpointSlice observation for Service %s/%s", svc.Namespace, svc.Name))
		}
		if !endpointComplete && totalEndpoints == 0 {
			issues = append(issues, &Issue{
				ID:            makeID(svc.Namespace, "Service", svc.Name, "EndpointIncomplete"),
				Namespace:     svc.Namespace,
				Kind:          "Service",
				Name:          svc.Name,
				Severity:      SeverityHigh,
				Category:      CategoryServiceEndpointError,
				Summary:       fmt.Sprintf("Service %s endpoint state is incomplete", svc.Name),
				Details:       "EndpointSlice results exceeded the analyzer bound before a ready endpoint was found; retry the scan for a complete observation.",
				FirstObserved: svc.CreationTimestamp.Time,
				LastObserved:  now,
			})
			continue
		}

		if !endpointObjectFound || totalEndpoints == 0 {
			issues = append(issues, &Issue{
				ID:            makeID(svc.Namespace, "Service", svc.Name, "NoEndpoints"),
				Namespace:     svc.Namespace,
				Kind:          "Service",
				Name:          svc.Name,
				Severity:      SeverityHigh,
				Category:      CategoryServiceNoEndpoint,
				Summary:       fmt.Sprintf("Service %s has 0 ready endpoints", svc.Name),
				Details:       fmt.Sprintf("Service selector %v matches 0 running, ready pods. Client traffic will fail with 502/connection refused.", svc.Spec.Selector),
				FirstObserved: svc.CreationTimestamp.Time,
				LastObserved:  now,
			})
		}

		if mismatch, mismatchErr := s.servicePortMismatchWithError(ctx, svc); mismatchErr != nil {
			return issues, errors.Join(append(observationErrors, mismatchErr)...)
		} else if mismatch != "" {
			issues = append(issues, &Issue{
				ID:            makeID(svc.Namespace, "Service", svc.Name, "PortMismatch-"+mismatch),
				Namespace:     svc.Namespace,
				Kind:          "Service",
				Name:          svc.Name,
				Severity:      SeverityHigh,
				Category:      CategoryServicePortMismatch,
				Summary:       fmt.Sprintf("Service %s target port %s is not declared by matching pods", svc.Name, mismatch),
				Details:       fmt.Sprintf("The Service targetPort %q did not match any declared container port on the selected pods.", mismatch),
				FirstObserved: svc.CreationTimestamp.Time,
				LastObserved:  now,
			})
		}
	}
	return issues, errors.Join(observationErrors...)
}

func (s *ClusterScanner) serviceReadyEndpoints(ctx context.Context, service *corev1.Service) (int, bool, bool, error) {
	slices, err := s.client.DiscoveryV1().EndpointSlices(service.Namespace).List(ctx, endpointSliceListOptions(service))
	if err == nil && slices != nil {
		count := 0
		items := slices.Items
		complete := slices.Continue == ""
		if len(items) > int(maxEndpointSlicesPerService) {
			items = items[:maxEndpointSlicesPerService]
			complete = false
		}
		ownedSliceFound := false
		for _, endpointSlice := range items {
			if endpointSlice.Labels[discoveryv1.LabelServiceName] != service.Name {
				continue
			}
			ownedSliceFound = true
			for _, endpoint := range endpointSlice.Endpoints {
				if endpointSliceEndpointIsReady(endpoint, service.Spec.PublishNotReadyAddresses) {
					count++
				}
			}
		}
		if ownedSliceFound {
			return count, true, complete, nil
		}
		if !complete {
			return 0, true, false, nil
		}
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return 0, false, true, err
	}
	ep, endpointErr := s.client.CoreV1().Endpoints(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if endpointErr != nil {
		if apierrors.IsNotFound(endpointErr) {
			return 0, false, true, nil
		}
		return 0, false, true, endpointErr
	}
	count := 0
	for _, subset := range ep.Subsets {
		count += len(subset.Addresses)
	}
	return count, true, true, nil
}

func (s *ClusterScanner) servicePortMismatch(ctx context.Context, service *corev1.Service) string {
	mismatch, _ := s.servicePortMismatchWithError(ctx, service)
	return mismatch
}

func (s *ClusterScanner) servicePortMismatchWithError(ctx context.Context, service *corev1.Service) (string, error) {
	if len(service.Spec.Ports) == 0 || len(service.Spec.Selector) == 0 {
		return "", nil
	}
	options := listOptionsForScan(ctx)
	options.FieldSelector = ""
	serviceSelector := labels.SelectorFromSet(service.Spec.Selector)
	if options.LabelSelector == "" {
		options.LabelSelector = serviceSelector.String()
	} else {
		globalSelector, err := labels.Parse(options.LabelSelector)
		if err != nil {
			return "", err
		}
		options.LabelSelector = combineLabelSelectors(serviceSelector.String(), globalSelector.String())
	}
	pods, err := s.client.CoreV1().Pods(service.Namespace).List(ctx, options)
	if err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		for _, port := range service.Spec.Ports {
			if port.TargetPort.StrVal != "" && len(utilvalidation.IsDNS1123Label(port.TargetPort.StrVal)) > 0 {
				return port.TargetPort.StrVal, nil
			}
		}
		return "", nil
	}
	for _, port := range service.Spec.Ports {
		target := port.TargetPort
		if target.IntValue() == 0 && target.StrVal == "" {
			target.IntVal = port.Port
		}
		if target.StrVal != "" && len(utilvalidation.IsDNS1123Label(target.StrVal)) > 0 {
			return target.StrVal, nil
		}
		if target.StrVal == "" && (target.IntVal < 1 || target.IntVal > 65535) {
			return fmt.Sprintf("%d", target.IntVal), nil
		}
		declared := false
		matched := false
		for _, pod := range pods.Items {
			for _, container := range append(append([]corev1.Container(nil), pod.Spec.InitContainers...), pod.Spec.Containers...) {
				for _, containerPort := range container.Ports {
					declared = true
					if target.StrVal != "" && containerPort.Name == target.StrVal {
						matched = true
					}
					if target.StrVal == "" && containerPort.ContainerPort == target.IntVal {
						matched = true
					}
				}
			}
		}
		if declared && !matched {
			if target.StrVal != "" {
				return target.StrVal, nil
			}
			return fmt.Sprintf("%d", target.IntVal), nil
		}
	}
	return "", nil
}

func (s *ClusterScanner) fetchPodLogsSnippet(ctx context.Context, namespace, name string) string {
	logs, _ := s.fetchPodLogsSnippetWithError(ctx, namespace, name)
	return logs
}

func (s *ClusterScanner) fetchPodLogsSnippetWithError(ctx context.Context, namespace, name string) (string, error) {
	const maxPodLogBytes = 32 * 1024
	tailLines := int64(30)
	if s == nil || s.client == nil {
		return "", ErrKubernetesClientUnavailable
	}
	var retrievalErrors []error
	for _, previous := range []bool{true, false} {
		stream, err := s.client.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{
			TailLines: &tailLines,
			Previous:  previous,
		}).Stream(ctx)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				retrievalErrors = append(retrievalErrors, err)
			}
			continue
		}
		buf := new(bytes.Buffer)
		_, readErr := io.Copy(buf, io.LimitReader(stream, maxPodLogBytes))
		_ = stream.Close()
		if readErr != nil {
			retrievalErrors = append(retrievalErrors, readErr)
		}
		logs := sanitizer.SanitizeText(buf.String())
		if logs != "" {
			return logs, errors.Join(retrievalErrors...)
		}
	}
	return "", errors.Join(retrievalErrors...)
}

func (s *ClusterScanner) fetchPodWarningEvents(ctx context.Context, namespace, name string) []string {
	events, _ := s.fetchPodWarningEventsWithError(ctx, namespace, name)
	return events
}

func (s *ClusterScanner) fetchPodWarningEventsWithError(ctx context.Context, namespace, name string) ([]string, error) {
	options := listOptionsForScan(ctx)
	options.FieldSelector = fmt.Sprintf("involvedObject.name=%s,type=Warning", name)
	events, err := s.client.CoreV1().Events(namespace).List(ctx, options)
	if err != nil {
		return nil, err
	}

	results := make([]string, 0, len(events.Items))
	for _, e := range events.Items {
		results = append(results, sanitizer.SanitizeText(fmt.Sprintf("[%s] %s: %s", e.Reason, e.Source.Component, e.Message)))
	}
	sort.Strings(results)
	return results, nil
}

func (s *ClusterScanner) scanWarningEvents(ctx context.Context, namespace string) ([]*Issue, error) {
	options := listOptionsForScan(ctx)
	options.FieldSelector = "type=Warning"
	events, err := s.client.CoreV1().Events(namespace).List(ctx, options)
	if err != nil {
		return nil, err
	}
	issues := make([]*Issue, 0, len(events.Items))
	for index := range events.Items {
		event := &events.Items[index]
		if event.Type != corev1.EventTypeWarning {
			continue
		}
		kind := strings.TrimSpace(event.InvolvedObject.Kind)
		if kind == "" {
			kind = "Event"
		}
		name := strings.TrimSpace(event.InvolvedObject.Name)
		if name == "" {
			name = event.Name
		}
		reason := strings.TrimSpace(event.Reason)
		if reason == "" {
			reason = "Warning"
		}
		message := strings.TrimSpace(event.Message)
		if message == "" {
			message = "warning event reported without a message"
		}
		evidence := boundIssueText(fmt.Sprintf("[%s] %s", reason, message), maxIssueDetailsBytes)
		eventKey := string(event.UID)
		if eventKey == "" {
			eventKey = event.Name
		}
		if eventKey == "" {
			eventKey = event.CreationTimestamp.UTC().Format(time.RFC3339Nano)
		}
		observed := warningEventTime(event)
		issues = append(issues, &Issue{
			ID:                    makeID(event.Namespace, kind, name, "WarningEvent-"+reason+"-"+eventKey),
			Namespace:             event.Namespace,
			Kind:                  kind,
			Name:                  name,
			TargetUID:             string(event.InvolvedObject.UID),
			TargetResourceVersion: event.ResourceVersion,
			Severity:              SeverityMedium,
			Category:              CategoryWarningEvent,
			Summary:               fmt.Sprintf("Warning event %s for %s %s", reason, kind, name),
			Details:               evidence,
			Events:                []string{evidence},
			FirstObserved:         observed,
			LastObserved:          observed,
		})
	}
	sort.SliceStable(issues, func(i, j int) bool { return issueLess(issues[i], issues[j]) })
	return issues, nil
}

func warningEventTime(event *corev1.Event) time.Time {
	if event == nil {
		return time.Now().UTC()
	}
	for _, value := range []time.Time{event.EventTime.Time, event.LastTimestamp.Time, event.FirstTimestamp.Time, event.CreationTimestamp.Time} {
		if !value.IsZero() {
			return value
		}
	}
	return time.Now().UTC()
}

func generateIssueID(namespace, kind, name, discriminator string) string {
	return makeID(namespace, kind, name, discriminator)
}

func makeID(namespace, kind, name, reason string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s", namespace, kind, name, reason)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s-%s-%x", strings.ToLower(kind), strings.ToLower(name), hash[:4])
}
