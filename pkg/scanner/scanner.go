package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kubebee-com/sre/pkg/sanitizer"
)

type ClusterScanner struct {
	client  kubernetes.Interface
	cleaner *PodCleaner
}

func NewClusterScanner(client kubernetes.Interface) *ClusterScanner {
	return &ClusterScanner{
		client:  client,
		cleaner: NewPodCleaner(client),
	}
}

func (s *ClusterScanner) GetPodCleaner() *PodCleaner {
	return s.cleaner
}

// GetAnalyzers returns metadata for all supported K8sGPT-compatible analyzers
func (s *ClusterScanner) GetAnalyzers() []AnalyzerInfo {
	return []AnalyzerInfo{
		{Name: "PodAnalyzer", Resource: "Pod", Description: "Checks for CrashLoopBackOff, OOMKilled, ImagePullBackOff, Evicted, and High Restarts", Enabled: true},
		{Name: "DeploymentAnalyzer", Resource: "Deployment", Description: "Checks for replica mismatches, unavailable replicas, and rollout progress failures", Enabled: true},
		{Name: "StatefulSetAnalyzer", Resource: "StatefulSet", Description: "Checks for unready StatefulSet replicas, partitions, and rolling update blocks", Enabled: true},
		{Name: "DaemonSetAnalyzer", Resource: "DaemonSet", Description: "Checks for unscheduled or unready daemon pods across eligible cluster nodes", Enabled: true},
		{Name: "ReplicaSetAnalyzer", Resource: "ReplicaSet", Description: "Detects ReplicaSets failing to satisfy desired replica count", Enabled: true},
		{Name: "JobAnalyzer", Resource: "Job", Description: "Detects failed batch Jobs, deadline exceeded, and backoff limits", Enabled: true},
		{Name: "CronJobAnalyzer", Resource: "CronJob", Description: "Detects invalid schedules and suspended cron executions", Enabled: true},
		{Name: "ServiceAnalyzer", Resource: "Service", Description: "Verifies service selectors and flags services with 0 active endpoints", Enabled: true},
		{Name: "IngressAnalyzer", Resource: "Ingress", Description: "Validates backend target services, paths, and TLS secret availability", Enabled: true},
		{Name: "NetworkPolicyAnalyzer", Resource: "NetworkPolicy", Description: "Detects orphaned network policies matching 0 workloads in namespace", Enabled: true},
		{Name: "PersistentVolumeClaimAnalyzer", Resource: "PersistentVolumeClaim", Description: "Flags PVCs stuck in Pending or Lost status", Enabled: true},
		{Name: "NodeAnalyzer", Resource: "Node", Description: "Checks for NotReady conditions and Disk, Memory, or PID pressure", Enabled: true},
		{Name: "HPAAnalyzer", Resource: "HorizontalPodAutoscaler", Description: "Checks for missing metric sources and scaling limit traps", Enabled: true},
		{Name: "PDBAnalyzer", Resource: "PodDisruptionBudget", Description: "Checks for 0 allowed disruptions blocking node drains", Enabled: true},
	}
}

// Scan executes all registered analyzers across the target namespace (or all namespaces)
func (s *ClusterScanner) Scan(ctx context.Context, namespace string) ([]*Issue, error) {
	var allIssues []*Issue

	// 1. Pods (Core)
	podIssues, err := s.scanPods(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, podIssues...)
	}

	// 2. Deployments
	deplIssues, err := s.scanDeployments(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, deplIssues...)
	}

	// 3. StatefulSets
	ssIssues, err := s.scanStatefulSets(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, ssIssues...)
	}

	// 4. DaemonSets
	dsIssues, err := s.scanDaemonSets(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, dsIssues...)
	}

	// 5. ReplicaSets
	rsIssues, err := s.scanReplicaSets(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, rsIssues...)
	}

	// 6. Batch Jobs
	jobIssues, err := s.scanJobs(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, jobIssues...)
	}

	// 7. CronJobs
	cronIssues, err := s.scanCronJobs(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, cronIssues...)
	}

	// 8. Services
	svcIssues, err := s.scanServices(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, svcIssues...)
	}

	// 9. Ingresses
	ingIssues, err := s.scanIngresses(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, ingIssues...)
	}

	// 10. Network Policies
	netpolIssues, err := s.scanNetworkPolicies(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, netpolIssues...)
	}

	// 11. PVCs
	pvcIssues, err := s.scanPVCs(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, pvcIssues...)
	}

	// 12. Nodes (Cluster-wide)
	nodeIssues, err := s.scanNodes(ctx)
	if err == nil {
		allIssues = append(allIssues, nodeIssues...)
	}

	// 13. HPAs
	hpaIssues, err := s.scanHPAs(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, hpaIssues...)
	}

	// 14. PDBs
	pdbIssues, err := s.scanPDBs(ctx, namespace)
	if err == nil {
		allIssues = append(allIssues, pdbIssues...)
	}

	return allIssues, nil
}

func (s *ClusterScanner) scanPods(ctx context.Context, namespace string) ([]*Issue, error) {
	pods, err := s.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, pod := range pods.Items {
		// Ignore Succeeded/Completed pods from normal anomaly alert (handled by Cleaner)
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}

		issue := s.analyzePod(&pod)
		if issue != nil {
			// Enrich with tail logs & warning events
			issue.LogsSnippet = s.fetchPodLogsSnippet(ctx, pod.Namespace, pod.Name)
			issue.Events = s.fetchPodWarningEvents(ctx, pod.Namespace, pod.Name)
			issues = append(issues, issue)
		}
	}
	return issues, nil
}

func (s *ClusterScanner) analyzePod(pod *corev1.Pod) *Issue {
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
	for _, cs := range append(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses...) {
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

func (s *ClusterScanner) scanNodes(ctx context.Context) ([]*Issue, error) {
	nodes, err := s.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
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
		}
	}
	return issues, nil
}

func (s *ClusterScanner) scanPVCs(ctx context.Context, namespace string) ([]*Issue, error) {
	pvcs, err := s.client.CoreV1().PersistentVolumeClaims(namespace).List(ctx, metav1.ListOptions{})
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
	svcs, err := s.client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	now := time.Now()

	for _, svc := range svcs.Items {
		// Ignore ExternalName or headless without selector
		if svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Selector) == 0 {
			continue
		}

		ep, err := s.client.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if err != nil {
			continue
		}

		totalEndpoints := 0
		for _, subset := range ep.Subsets {
			totalEndpoints += len(subset.Addresses)
		}

		if totalEndpoints == 0 {
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
	}
	return issues, nil
}

func (s *ClusterScanner) fetchPodLogsSnippet(ctx context.Context, namespace, name string) string {
	tailLines := int64(30)
	req := s.client.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{
		TailLines: &tailLines,
		Previous:  true, // Try previous terminated container logs first
	})

	stream, err := req.Stream(ctx)
	if err != nil {
		// Fallback to active container logs
		req = s.client.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{
			TailLines: &tailLines,
		})
		stream, err = req.Stream(ctx)
		if err != nil {
			return ""
		}
	}
	defer stream.Close()

	buf := new(bytes.Buffer)
	_, _ = io.Copy(buf, stream)
	return sanitizer.SanitizeText(buf.String())
}

func (s *ClusterScanner) fetchPodWarningEvents(ctx context.Context, namespace, name string) []string {
	events, err := s.client.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.name=%s,type=Warning", name),
	})
	if err != nil {
		return nil
	}

	var results []string
	for _, e := range events.Items {
		results = append(results, sanitizer.SanitizeText(fmt.Sprintf("[%s] %s: %s", e.Reason, e.Source.Component, e.Message)))
	}
	return results
}

func generateIssueID(namespace, kind, name, discriminator string) string {
	return makeID(namespace, kind, name, discriminator)
}

func makeID(namespace, kind, name, reason string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s", namespace, kind, name, reason)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s-%s-%x", strings.ToLower(kind), strings.ToLower(name), hash[:4])
}
