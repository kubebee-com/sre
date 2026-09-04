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
	client kubernetes.Interface
}

func NewClusterScanner(client kubernetes.Interface) *ClusterScanner {
	return &ClusterScanner{client: client}
}

func (s *ClusterScanner) Scan(ctx context.Context, namespace string) ([]*Issue, error) {
	var allIssues []*Issue

	// 1. Scan Pods
	podIssues, err := s.scanPods(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("scan pods: %w", err)
	}
	allIssues = append(allIssues, podIssues...)

	// 2. Scan Nodes (cluster-wide)
	nodeIssues, err := s.scanNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("scan nodes: %w", err)
	}
	allIssues = append(allIssues, nodeIssues...)

	// 3. Scan PVCs
	pvcIssues, err := s.scanPVCs(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("scan pvcs: %w", err)
	}
	allIssues = append(allIssues, pvcIssues...)

	// 4. Scan Services
	svcIssues, err := s.scanServices(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("scan services: %w", err)
	}
	allIssues = append(allIssues, svcIssues...)

	return allIssues, nil
}

func (s *ClusterScanner) scanPods(ctx context.Context, namespace string) ([]*Issue, error) {
	pods, err := s.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, pod := range pods.Items {
		// Ignore Completed or successfully terminating pods
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}

		issue := s.analyzePod(&pod)
		if issue != nil {
			// Enrich with logs & warning events
			issue.LogsSnippet = s.fetchPodLogsSnippet(ctx, pod.Namespace, pod.Name)
			issue.Events = s.fetchPodWarningEvents(ctx, pod.Namespace, pod.Name)
			issues = append(issues, issue)
		}
	}
	return issues, nil
}

func (s *ClusterScanner) analyzePod(pod *corev1.Pod) *Issue {
	now := time.Now()

	// Check container statuses (CrashLoopBackOff, OOMKilled, ImagePullBackOff, etc.)
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

		// Terminated state checks (OOMKilled, non-zero exit code)
		if cs.State.Terminated != nil {
			if cs.State.Terminated.Reason == "OOMKilled" || cs.State.Terminated.ExitCode == 137 {
				return &Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, "OOMKilled"),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityCritical,
					Category:      CategoryOOMKilled,
					Summary:       fmt.Sprintf("Container '%s' was OOMKilled (ExitCode 137)", cs.Name),
					Details:       fmt.Sprintf("Memory limit exceeded for container %s in pod %s", cs.Name, pod.Name),
					FirstObserved: now,
					LastObserved:  now,
				}
			}
			if cs.State.Terminated.ExitCode != 0 {
				return &Issue{
					ID:            makeID(pod.Namespace, "Pod", pod.Name, fmt.Sprintf("ExitCode%d", cs.State.Terminated.ExitCode)),
					Namespace:     pod.Namespace,
					Kind:          "Pod",
					Name:          pod.Name,
					Severity:      SeverityHigh,
					Category:      CategoryPodFailed,
					Summary:       fmt.Sprintf("Container '%s' exited with code %d", cs.Name, cs.State.Terminated.ExitCode),
					Details:       cs.State.Terminated.Message,
					FirstObserved: now,
					LastObserved:  now,
				}
			}
		}

		// Frequent restart count
		if cs.RestartCount > 10 {
			return &Issue{
				ID:            makeID(pod.Namespace, "Pod", pod.Name, "HighRestarts"),
				Namespace:     pod.Namespace,
				Kind:          "Pod",
				Name:          pod.Name,
				Severity:      SeverityHigh,
				Category:      CategoryHighRestarts,
				Summary:       fmt.Sprintf("Container '%s' has restarted %d times", cs.Name, cs.RestartCount),
				Details:       "High container restart frequency indicates workload instability or memory pressure.",
				FirstObserved: now,
				LastObserved:  now,
			}
		}
	}

	// Pod Pending for > 5 minutes
	if pod.Status.Phase == corev1.PodPending && time.Since(pod.CreationTimestamp.Time) > 5*time.Minute {
		return &Issue{
			ID:            makeID(pod.Namespace, "Pod", pod.Name, "PendingTooLong"),
			Namespace:     pod.Namespace,
			Kind:          "Pod",
			Name:          pod.Name,
			Severity:      SeverityMedium,
			Category:      CategoryFailedScheduling,
			Summary:       fmt.Sprintf("Pod '%s' has been Pending for %v", pod.Name, time.Since(pod.CreationTimestamp.Time).Round(time.Minute)),
			Details:       "Pod unscheduled, possibly due to resource shortage, taint/toleration mismatch, or node affinity constraints.",
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
			if cond.Type == corev1.NodeReady && cond.Status != corev1.ConditionTrue {
				issues = append(issues, &Issue{
					ID:            makeID("", "Node", node.Name, "NotReady"),
					Kind:          "Node",
					Name:          node.Name,
					Severity:      SeverityCritical,
					Category:      CategoryNodePressure,
					Summary:       fmt.Sprintf("Node '%s' is NotReady", node.Name),
					Details:       fmt.Sprintf("Node status condition Ready=%s: %s", cond.Status, cond.Message),
					FirstObserved: now,
					LastObserved:  now,
				})
			}
			if cond.Type == corev1.NodeDiskPressure && cond.Status == corev1.ConditionTrue {
				issues = append(issues, &Issue{
					ID:            makeID("", "Node", node.Name, "DiskPressure"),
					Kind:          "Node",
					Name:          node.Name,
					Severity:      SeverityHigh,
					Category:      CategoryNodePressure,
					Summary:       fmt.Sprintf("Node '%s' is under DiskPressure", node.Name),
					Details:       cond.Message,
					FirstObserved: now,
					LastObserved:  now,
				})
			}
			if cond.Type == corev1.NodeMemoryPressure && cond.Status == corev1.ConditionTrue {
				issues = append(issues, &Issue{
					ID:            makeID("", "Node", node.Name, "MemoryPressure"),
					Kind:          "Node",
					Name:          node.Name,
					Severity:      SeverityHigh,
					Category:      CategoryNodePressure,
					Summary:       fmt.Sprintf("Node '%s' is under MemoryPressure", node.Name),
					Details:       cond.Message,
					FirstObserved: now,
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
		if pvc.Status.Phase == corev1.ClaimLost || (pvc.Status.Phase == corev1.ClaimPending && time.Since(pvc.CreationTimestamp.Time) > 3*time.Minute) {
			issues = append(issues, &Issue{
				ID:            makeID(pvc.Namespace, "PersistentVolumeClaim", pvc.Name, string(pvc.Status.Phase)),
				Namespace:     pvc.Namespace,
				Kind:          "PersistentVolumeClaim",
				Name:          pvc.Name,
				Severity:      SeverityHigh,
				Category:      CategoryPVCPending,
				Summary:       fmt.Sprintf("PVC '%s' is %s", pvc.Name, pvc.Status.Phase),
				Details:       fmt.Sprintf("Storage claim has not bound. StorageClass: %v", pvc.Spec.StorageClassName),
				FirstObserved: now,
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
		// Ignore headless or ExternalName services without selectors
		if len(svc.Spec.Selector) == 0 {
			continue
		}

		eps, err := s.client.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if err != nil {
			continue
		}

		hasEndpoints := false
		for _, subset := range eps.Subsets {
			if len(subset.Addresses) > 0 {
				hasEndpoints = true
				break
			}
		}

		if !hasEndpoints {
			issues = append(issues, &Issue{
				ID:            makeID(svc.Namespace, "Service", svc.Name, "ZeroEndpoints"),
				Namespace:     svc.Namespace,
				Kind:          "Service",
				Name:          svc.Name,
				Severity:      SeverityMedium,
				Category:      CategoryServiceNoEndpoint,
				Summary:       fmt.Sprintf("Service '%s' has 0 endpoints", svc.Name),
				Details:       fmt.Sprintf("Selector %v does not match any healthy, running pods.", svc.Spec.Selector),
				FirstObserved: now,
				LastObserved:  now,
			})
		}
	}
	return issues, nil
}

func (s *ClusterScanner) fetchPodLogsSnippet(ctx context.Context, namespace, name string) string {
	tailLines := int64(50)
	req := s.client.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{
		TailLines: &tailLines,
		Previous:  true, // Fetch previous crashed container if available
	})

	stream, err := req.Stream(ctx)
	if err != nil {
		// Try without previous=true
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

func makeID(namespace, kind, name, reason string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s", namespace, kind, name, reason)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s-%s-%x", strings.ToLower(kind), strings.ToLower(name), hash[:4])
}
