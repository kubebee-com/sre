package scanner

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	cron "github.com/robfig/cron/v3"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanplan"
)

const maxPodLogSnippetBytes = 64 * 1024

func (s *ClusterScanner) scanPodLogs(ctx context.Context, namespace string) ([]*Issue, error) {
	pods, err := s.client.CoreV1().Pods(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	issues := make([]*Issue, 0)
	var logErrors []error
	for index := range pods.Items {
		pod := &pods.Items[index]
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		for _, target := range podLogTargets(pod) {
			if target.restartCount == 0 {
				continue
			}
			for _, previous := range []bool{true, false} {
				logs, logErr := s.fetchBoundedContainerLogsSnippet(ctx, pod.Namespace, pod.Name, target.name, previous)
				if logErr != nil {
					if !apierrors.IsNotFound(logErr) {
						logErrors = append(logErrors, logErr)
					}
				}
				lines := matchingLogLines(logs)
				if len(lines) == 0 {
					continue
				}
				phase := "current"
				if previous {
					phase = "previous"
				}
				evidence := strings.Join(lines, "\n")
				issues = append(issues, &Issue{
					ID:        makeID(pod.Namespace, "Pod", pod.Name, "LogError-"+target.kind+"-"+target.name+"-"+phase),
					Namespace: pod.Namespace, Kind: "Pod", Name: pod.Name,
					TargetUID: string(pod.UID), TargetResourceVersion: pod.ResourceVersion,
					Severity: SeverityMedium, Category: CategoryPodLogError,
					Summary: fmt.Sprintf("Pod %s has %s error patterns in %s container logs", pod.Name, phase, target.kind),
					Details: evidence, LogsSnippet: evidence,
					FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC(), Parent: podOwnerReference(pod),
				})
			}
		}
	}
	return issues, errors.Join(logErrors...)
}

type podLogTarget struct {
	kind         string
	name         string
	restartCount int32
}

func podLogTargets(pod *corev1.Pod) []podLogTarget {
	if pod == nil {
		return nil
	}
	result := make([]podLogTarget, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers)+len(pod.Spec.EphemeralContainers))
	for _, status := range pod.Status.InitContainerStatuses {
		result = append(result, podLogTarget{kind: "init", name: status.Name, restartCount: status.RestartCount})
	}
	for _, status := range pod.Status.ContainerStatuses {
		result = append(result, podLogTarget{kind: "regular", name: status.Name, restartCount: status.RestartCount})
	}
	for _, status := range pod.Status.EphemeralContainerStatuses {
		result = append(result, podLogTarget{kind: "ephemeral", name: status.Name, restartCount: status.RestartCount})
	}
	return result
}

func (s *ClusterScanner) fetchBoundedPodLogsSnippet(ctx context.Context, namespace, name string) string {
	logs, _ := s.fetchBoundedContainerLogsSnippet(ctx, namespace, name, "", true)
	if logs != "" {
		return logs
	}
	logs, _ = s.fetchBoundedContainerLogsSnippet(ctx, namespace, name, "", false)
	return logs
}

func (s *ClusterScanner) fetchBoundedContainerLogsSnippet(ctx context.Context, namespace, name, container string, previous bool) (string, error) {
	if s == nil || s.client == nil {
		return "", ErrKubernetesClientUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tailLines := int64(30)
	options := &corev1.PodLogOptions{TailLines: &tailLines, Container: container, Previous: previous}
	stream, err := s.client.CoreV1().Pods(namespace).GetLogs(name, options).Stream(ctx)
	if err != nil {
		return "", err
	}
	defer stream.Close()
	return readBoundedLogSnippetWithError(stream, maxPodLogSnippetBytes)
}

func readBoundedLogSnippet(reader io.Reader, maxBytes int64) string {
	snippet, _ := readBoundedLogSnippetWithError(reader, maxBytes)
	return snippet
}

func readBoundedLogSnippetWithError(reader io.Reader, maxBytes int64) (string, error) {
	if reader == nil || maxBytes <= 0 {
		return "", nil
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes))
	sanitized := sanitizer.SanitizeText(string(data))
	if int64(len(sanitized)) > maxBytes {
		return sanitized[:maxBytes], err
	}
	return sanitized, err
}

func matchingLogLines(logs string) []string {
	lines := strings.Split(logs, "\n")
	result := make([]string, 0, 5)
	for _, line := range lines {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "error") && !strings.Contains(lower, "fatal") && !strings.Contains(lower, "panic") && !strings.Contains(lower, "exception") && !strings.Contains(lower, "oom") {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, line)
		if len(result) == 5 {
			break
		}
	}
	return result
}

func (s *ClusterScanner) scanWorkloadDrift(ctx context.Context, namespace string) ([]*Issue, error) {
	issues := make([]*Issue, 0)
	deployments, err := s.client.AppsV1().Deployments(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range deployments.Items {
		workload := &deployments.Items[index]
		if workloadSelectorDrifts(workload.Spec.Selector, workload.Spec.Template.Labels) {
			issues = append(issues, workloadDriftIssue("Deployment", workload.Namespace, workload.Name, workload.Spec.Selector, workload.Spec.Template.Labels))
		}
	}
	statefulSets, err := s.client.AppsV1().StatefulSets(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range statefulSets.Items {
		workload := &statefulSets.Items[index]
		if workloadSelectorDrifts(workload.Spec.Selector, workload.Spec.Template.Labels) {
			issues = append(issues, workloadDriftIssue("StatefulSet", workload.Namespace, workload.Name, workload.Spec.Selector, workload.Spec.Template.Labels))
		}
	}
	daemonSets, err := s.client.AppsV1().DaemonSets(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range daemonSets.Items {
		workload := &daemonSets.Items[index]
		if workloadSelectorDrifts(workload.Spec.Selector, workload.Spec.Template.Labels) {
			issues = append(issues, workloadDriftIssue("DaemonSet", workload.Namespace, workload.Name, workload.Spec.Selector, workload.Spec.Template.Labels))
		}
	}
	replicaSets, err := s.client.AppsV1().ReplicaSets(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range replicaSets.Items {
		workload := &replicaSets.Items[index]
		if workloadSelectorDrifts(workload.Spec.Selector, workload.Spec.Template.Labels) {
			issues = append(issues, workloadDriftIssue("ReplicaSet", workload.Namespace, workload.Name, workload.Spec.Selector, workload.Spec.Template.Labels))
		}
	}
	jobs, err := s.client.BatchV1().Jobs(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range jobs.Items {
		workload := &jobs.Items[index]
		if jobSelectorDrifts(workload.Spec.Selector, workload.Spec.ManualSelector, workload.Spec.Template.Labels) {
			issues = append(issues, workloadDriftIssue("Job", workload.Namespace, workload.Name, workload.Spec.Selector, workload.Spec.Template.Labels))
		}
	}
	cronJobs, err := s.client.BatchV1().CronJobs(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range cronJobs.Items {
		workload := &cronJobs.Items[index]
		jobSpec := &workload.Spec.JobTemplate.Spec
		if jobSelectorDrifts(jobSpec.Selector, jobSpec.ManualSelector, jobSpec.Template.Labels) {
			issues = append(issues, workloadDriftIssue("CronJob", workload.Namespace, workload.Name, jobSpec.Selector, jobSpec.Template.Labels))
		}
	}
	return issues, nil
}

func jobSelectorDrifts(selector *metav1.LabelSelector, manualSelector *bool, templateLabels map[string]string) bool {
	if selector == nil && (manualSelector == nil || !*manualSelector) {
		return false
	}
	return workloadSelectorDrifts(selector, templateLabels)
}

func workloadSelectorDrifts(selector *metav1.LabelSelector, templateLabels map[string]string) bool {
	if selector == nil {
		return true
	}
	parsed, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return true
	}
	return !parsed.Matches(labels.Set(templateLabels))
}

func workloadDriftIssue(kind, namespace, name string, selector *metav1.LabelSelector, templateLabels map[string]string) *Issue {
	selectorText := "<nil>"
	if selector != nil {
		selectorText = selector.String()
	}
	return &Issue{
		ID:            makeID(namespace, kind, name, "SelectorDrift"),
		Namespace:     namespace,
		Kind:          kind,
		Name:          name,
		Severity:      SeverityHigh,
		Category:      CategoryWorkloadDrift,
		Summary:       fmt.Sprintf("%s selector does not match its pod template", kind),
		Details:       fmt.Sprintf("Selector %q does not match template labels %v; the controller cannot reliably manage its intended pods.", selectorText, templateLabels),
		FirstObserved: time.Now().UTC(),
		LastObserved:  time.Now().UTC(),
	}
}

func (s *ClusterScanner) scanCronSemantics(ctx context.Context, namespace string) ([]*Issue, error) {
	cronJobs, err := s.client.BatchV1().CronJobs(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	issues := make([]*Issue, 0)
	for index := range cronJobs.Items {
		job := &cronJobs.Items[index]
		var schedule cron.Schedule
		if strings.TrimSpace(job.Spec.Schedule) != "" {
			parsed, parseErr := parser.Parse(job.Spec.Schedule)
			if parseErr != nil {
				issues = append(issues, &Issue{
					ID:            makeID(job.Namespace, "CronJob", job.Name, "InvalidSchedule"),
					Namespace:     job.Namespace,
					Kind:          "CronJob",
					Name:          job.Name,
					Severity:      SeverityHigh,
					Category:      CategoryCronJobInvalid,
					Summary:       fmt.Sprintf("CronJob %s has an invalid schedule", job.Name),
					Details:       "The configured schedule could not be parsed using Kubernetes-compatible five-field cron syntax.",
					FirstObserved: time.Now().UTC(),
					LastObserved:  time.Now().UTC(),
				})
			} else {
				schedule = parsed
			}
		}
		if job.Spec.Suspend != nil && *job.Spec.Suspend {
			issues = append(issues, &Issue{
				ID:            makeID(job.Namespace, "CronJob", job.Name, "Suspended"),
				Namespace:     job.Namespace,
				Kind:          "CronJob",
				Name:          job.Name,
				Severity:      SeverityLow,
				Category:      CategoryCronJobSuspended,
				Summary:       fmt.Sprintf("CronJob %s is suspended", job.Name),
				Details:       "New Jobs will not be scheduled until spec.suspend is set to false.",
				FirstObserved: time.Now().UTC(),
				LastObserved:  time.Now().UTC(),
			})
			continue
		}
		if schedule != nil && job.Status.LastScheduleTime != nil {
			next := schedule.Next(job.Status.LastScheduleTime.Time)
			if time.Now().After(next) {
				overdue := time.Since(next)
				deadline := time.Duration(0)
				if job.Spec.StartingDeadlineSeconds != nil && *job.Spec.StartingDeadlineSeconds > 0 {
					deadline = time.Duration(*job.Spec.StartingDeadlineSeconds) * time.Second
				}
				if deadline == 0 || overdue > deadline {
					issues = append(issues, &Issue{
						ID: makeID(job.Namespace, "CronJob", job.Name, "MissedSchedule"), Namespace: job.Namespace,
						Kind: "CronJob", Name: job.Name, TargetUID: string(job.UID), TargetResourceVersion: job.ResourceVersion,
						Severity: SeverityMedium, Category: CategoryCronJobMissed,
						Summary:       fmt.Sprintf("CronJob %s has missed a scheduled run", job.Name),
						Details:       fmt.Sprintf("The next schedule after %s was due at %s and is overdue by %s.", job.Status.LastScheduleTime.Time.Format(time.RFC3339), next.Format(time.RFC3339), overdue.Round(time.Second)),
						FirstObserved: workloadObservedTime(job.CreationTimestamp), LastObserved: time.Now().UTC(), Parent: ownerReferenceForObject(job),
					})
				}
			}
		}
	}
	return issues, nil
}

func (s *ClusterScanner) scanIngressSemantics(ctx context.Context, namespace string) ([]*Issue, error) {
	ingresses, err := s.client.NetworkingV1().Ingresses(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	services, err := s.client.CoreV1().Services(namespace).List(ctx, ingressDependencyListOptions(ctx))
	if err != nil {
		return nil, err
	}
	needsTLSSecretList := false
	for _, ingress := range ingresses.Items {
		for _, tls := range ingress.Spec.TLS {
			if strings.TrimSpace(tls.SecretName) == "" {
				continue
			}
			needsTLSSecretList = true
			break
		}
	}
	if needsTLSSecretList {
		if _, err := s.client.CoreV1().Secrets(namespace).List(ctx, ingressDependencyListOptions(ctx)); err != nil {
			return nil, fmt.Errorf("list ingress TLS Secrets: %w", err)
		}
	}
	serviceByName := make(map[string]*corev1.Service, len(services.Items))
	for index := range services.Items {
		serviceByName[services.Items[index].Name] = &services.Items[index]
	}
	issues := make([]*Issue, 0)
	for index := range ingresses.Items {
		ingress := &ingresses.Items[index]
		if ingress.Spec.IngressClassName == nil && strings.TrimSpace(ingress.Annotations["kubernetes.io/ingress.class"]) == "" {
			issues = append(issues, &Issue{ID: makeID(ingress.Namespace, "Ingress", ingress.Name, "ClassMissing"), Namespace: ingress.Namespace, Kind: "Ingress", Name: ingress.Name, Severity: SeverityMedium, Category: CategoryIngressClassMissing, Summary: fmt.Sprintf("Ingress %s has no ingress class", ingress.Name), Details: "Set spec.ingressClassName or the legacy ingress.class annotation so a controller can claim this Ingress.", FirstObserved: ingress.CreationTimestamp.Time, LastObserved: time.Now().UTC()})
		}
		if ingressClassName(ingress) != "" && len(ingress.Status.LoadBalancer.Ingress) == 0 && !ingress.CreationTimestamp.Time.IsZero() && time.Since(ingress.CreationTimestamp.Time) > 5*time.Minute {
			issues = append(issues, &Issue{ID: makeID(ingress.Namespace, "Ingress", ingress.Name, "StatusPending"), Namespace: ingress.Namespace, Kind: "Ingress", Name: ingress.Name, Severity: SeverityMedium, Category: CategoryIngressStatusPending, Summary: fmt.Sprintf("Ingress %s has no load balancer address", ingress.Name), Details: "The Ingress controller has not reported an address or hostname; inspect controller events and service exposure.", FirstObserved: ingress.CreationTimestamp.Time, LastObserved: time.Now().UTC()})
		}
		backends := make([]networkingv1.IngressBackend, 0, len(ingress.Spec.Rules)+1)
		if ingress.Spec.DefaultBackend != nil {
			backends = append(backends, *ingress.Spec.DefaultBackend)
		}
		for _, rule := range ingress.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				backends = append(backends, path.Backend)
			}
		}
		for _, backend := range backends {
			if backend.Service == nil {
				if backend.Resource != nil {
					issues = append(issues, &Issue{ID: makeID(ingress.Namespace, "Ingress", ingress.Name, "UnsupportedBackend"), Namespace: ingress.Namespace, Kind: "Ingress", Name: ingress.Name, Severity: SeverityHigh, Category: CategoryIngressPortInvalid, Summary: fmt.Sprintf("Ingress %s uses an unsupported resource backend", ingress.Name), Details: "The analyzer validates Service backends only; verify the referenced resource backend has an active controller.", FirstObserved: ingress.CreationTimestamp.Time, LastObserved: time.Now().UTC()})
				}
				continue
			}
			service := serviceByName[backend.Service.Name]
			if service == nil {
				continue
			}
			if !servicePortMatches(service, backend.Service.Port) {
				issues = append(issues, &Issue{ID: makeID(ingress.Namespace, "Ingress", ingress.Name, "InvalidPort-"+backend.Service.Name), Namespace: ingress.Namespace, Kind: "Ingress", Name: ingress.Name, Severity: SeverityHigh, Category: CategoryIngressPortInvalid, Summary: fmt.Sprintf("Ingress %s references an invalid Service port", ingress.Name), Details: fmt.Sprintf("Service %s does not expose the port selected by this Ingress backend.", backend.Service.Name), FirstObserved: ingress.CreationTimestamp.Time, LastObserved: time.Now().UTC()})
			}
		}
	}
	return issues, nil
}

func ingressClassName(ingress *networkingv1.Ingress) string {
	if ingress == nil {
		return ""
	}
	if ingress.Spec.IngressClassName != nil {
		return strings.TrimSpace(*ingress.Spec.IngressClassName)
	}
	return strings.TrimSpace(ingress.Annotations["kubernetes.io/ingress.class"])
}

func servicePortMatches(service *corev1.Service, port networkingv1.ServiceBackendPort) bool {
	if service == nil {
		return false
	}
	for _, candidate := range service.Spec.Ports {
		if port.Name != "" && candidate.Name == port.Name {
			return true
		}
		if port.Name == "" && candidate.Port == port.Number {
			return true
		}
	}
	return false
}

func (s *ClusterScanner) scanWebhooks(ctx context.Context, _ string) ([]*Issue, error) {
	options := listOptionsForScan(ctx)
	mutating, err := s.client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, options)
	if err != nil {
		return nil, err
	}
	validating, err := s.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, options)
	if err != nil {
		return nil, err
	}
	issues := make([]*Issue, 0)
	for index := range mutating.Items {
		webhookIssues, err := s.webhookIssues(ctx, "MutatingWebhookConfiguration", mutating.Items[index].Name, mutatingWebhookSpecs(mutating.Items[index].Webhooks))
		if err != nil {
			return nil, err
		}
		issues = append(issues, webhookIssues...)
	}
	for index := range validating.Items {
		webhookIssues, err := s.webhookIssues(ctx, "ValidatingWebhookConfiguration", validating.Items[index].Name, validatingWebhookSpecs(validating.Items[index].Webhooks))
		if err != nil {
			return nil, err
		}
		issues = append(issues, webhookIssues...)
	}
	return issues, nil
}

type webhookSpec struct {
	name                    string
	clientConfig            admissionregistrationv1.WebhookClientConfig
	rules                   []admissionregistrationv1.RuleWithOperations
	failurePolicy           *admissionregistrationv1.FailurePolicyType
	matchPolicy             *admissionregistrationv1.MatchPolicyType
	namespaceSelector       *metav1.LabelSelector
	objectSelector          *metav1.LabelSelector
	sideEffects             *admissionregistrationv1.SideEffectClass
	timeoutSeconds          *int32
	admissionReviewVersions []string
	reinvocationPolicy      *admissionregistrationv1.ReinvocationPolicyType
	matchConditions         []admissionregistrationv1.MatchCondition
}

func mutatingWebhookSpecs(webhooks []admissionregistrationv1.MutatingWebhook) []webhookSpec {
	result := make([]webhookSpec, 0, len(webhooks))
	for _, webhook := range webhooks {
		result = append(result, webhookSpec{
			name:                    webhook.Name,
			clientConfig:            webhook.ClientConfig,
			rules:                   webhook.Rules,
			failurePolicy:           webhook.FailurePolicy,
			matchPolicy:             webhook.MatchPolicy,
			namespaceSelector:       webhook.NamespaceSelector,
			objectSelector:          webhook.ObjectSelector,
			sideEffects:             webhook.SideEffects,
			timeoutSeconds:          webhook.TimeoutSeconds,
			admissionReviewVersions: webhook.AdmissionReviewVersions,
			reinvocationPolicy:      webhook.ReinvocationPolicy,
			matchConditions:         webhook.MatchConditions,
		})
	}
	return result
}

func validatingWebhookSpecs(webhooks []admissionregistrationv1.ValidatingWebhook) []webhookSpec {
	result := make([]webhookSpec, 0, len(webhooks))
	for _, webhook := range webhooks {
		result = append(result, webhookSpec{
			name:                    webhook.Name,
			clientConfig:            webhook.ClientConfig,
			rules:                   webhook.Rules,
			failurePolicy:           webhook.FailurePolicy,
			matchPolicy:             webhook.MatchPolicy,
			namespaceSelector:       webhook.NamespaceSelector,
			objectSelector:          webhook.ObjectSelector,
			sideEffects:             webhook.SideEffects,
			timeoutSeconds:          webhook.TimeoutSeconds,
			admissionReviewVersions: webhook.AdmissionReviewVersions,
			matchConditions:         webhook.MatchConditions,
		})
	}
	return result
}

func (s *ClusterScanner) webhookIssues(ctx context.Context, kind, configurationName string, webhooks []webhookSpec) ([]*Issue, error) {
	issues := make([]*Issue, 0)
	for _, webhook := range webhooks {
		base := func(category IssueCategory, severity Severity, reason, summary, details string) *Issue {
			return &Issue{
				ID:            makeID("", kind, configurationName, string(category)+"-"+webhook.name+"-"+reason),
				Kind:          kind,
				Name:          configurationName,
				Severity:      severity,
				Category:      category,
				Summary:       summary,
				Details:       details,
				FirstObserved: time.Now().UTC(),
				LastObserved:  time.Now().UTC(),
			}
		}
		for _, finding := range validateWebhookSpec(webhook) {
			issues = append(issues, base(CategoryWebhookTargetMissing, SeverityHigh, finding.reason, finding.summary, finding.details))
		}
		if webhook.clientConfig.Service == nil {
			if webhook.clientConfig.URL == nil || strings.TrimSpace(*webhook.clientConfig.URL) == "" {
				continue
			}
			if !validWebhookURL(*webhook.clientConfig.URL) {
				continue
			}
			continue
		}
		if webhook.clientConfig.URL != nil {
			continue
		}
		reference := webhook.clientConfig.Service
		if reference == nil || !validWebhookServiceReference(reference) {
			continue
		}
		service, err := s.client.CoreV1().Services(reference.Namespace).Get(ctx, reference.Name, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("read webhook Service %s/%s: %w", reference.Namespace, reference.Name, err)
			}
			issues = append(issues, base(CategoryWebhookServiceMissing, SeverityHigh, "ServiceMissing", fmt.Sprintf("Webhook %s references a missing Service", webhook.name), fmt.Sprintf("Service %s/%s could not be read.", reference.Namespace, reference.Name)))
			continue
		}
		if service.Namespace != reference.Namespace {
			issues = append(issues, base(CategoryWebhookTargetMissing, SeverityHigh, "ServiceNamespaceMismatch", fmt.Sprintf("Webhook %s references a Service in the wrong namespace", webhook.name), fmt.Sprintf("Webhook references Service %s/%s, but the returned Service belongs to namespace %q.", reference.Namespace, reference.Name, service.Namespace)))
			continue
		}
		targetPort := int32(443)
		if reference.Port != nil {
			targetPort = *reference.Port
		}
		if !serviceExposesWebhookPort(service, targetPort) {
			issues = append(issues, base(CategoryWebhookTargetMissing, SeverityHigh, "ServicePortMismatch", fmt.Sprintf("Webhook %s references an unavailable Service port", webhook.name), fmt.Sprintf("Service %s/%s does not expose webhook port %d; exposed ports are %v.", reference.Namespace, reference.Name, targetPort, servicePortNumbers(service))))
		}
		if len(service.Spec.Selector) == 0 {
			issues = append(issues, base(CategoryWebhookNoActivePods, SeverityHigh, "SelectorMissing", fmt.Sprintf("Webhook %s Service has no pod selector", webhook.name), fmt.Sprintf("Service %s/%s cannot identify active webhook pods.", reference.Namespace, reference.Name)))
			continue
		}
		podOptions := listOptionsForScan(ctx)
		podOptions.FieldSelector = ""
		serviceSelector := labels.SelectorFromSet(service.Spec.Selector)
		if podOptions.LabelSelector == "" {
			podOptions.LabelSelector = serviceSelector.String()
		} else {
			globalSelector, parseErr := labels.Parse(podOptions.LabelSelector)
			if parseErr != nil {
				return nil, parseErr
			}
			podOptions.LabelSelector = combineLabelSelectors(serviceSelector.String(), globalSelector.String())
		}
		pods, err := s.client.CoreV1().Pods(reference.Namespace).List(ctx, podOptions)
		if err != nil {
			return nil, fmt.Errorf("list pods backing webhook Service %s/%s: %w", reference.Namespace, reference.Name, err)
		}
		if len(pods.Items) == 0 {
			issues = append(issues, base(CategoryWebhookNoActivePods, SeverityHigh, "NoActivePods", fmt.Sprintf("Webhook %s has no active backing pods", webhook.name), fmt.Sprintf("Service %s/%s has no matching pods.", reference.Namespace, reference.Name)))
		}
	}
	return issues, nil
}

type webhookFinding struct {
	reason  string
	summary string
	details string
}

func validateWebhookSpec(webhook webhookSpec) []webhookFinding {
	findings := make([]webhookFinding, 0, 8)
	add := func(reason, summary, details string) {
		findings = append(findings, webhookFinding{
			reason:  reason,
			summary: fmt.Sprintf("Webhook %s %s", webhook.name, summary),
			details: details,
		})
	}

	if strings.TrimSpace(webhook.name) == "" {
		add("NameMissing", "has no name", "Each admission webhook must have a non-empty name.")
	} else if len(utilvalidation.IsDNS1123Subdomain(webhook.name)) > 0 {
		add("NameInvalid", "has an invalid name", "Admission webhook names must be valid DNS subdomains.")
	}

	if webhook.clientConfig.Service != nil && webhook.clientConfig.URL != nil {
		add("MultipleTargets", "specifies both a Service and a URL target", "Admission webhook clientConfig must specify exactly one of service or url.")
	} else if webhook.clientConfig.Service == nil && webhook.clientConfig.URL == nil {
		add("TargetMissing", "has no service or URL target", "Admission webhook clientConfig must specify a service reference or an absolute URL.")
	}
	if webhook.clientConfig.URL != nil && strings.TrimSpace(*webhook.clientConfig.URL) == "" {
		add("URLMissing", "has an empty URL target", "Admission webhook URL targets must be non-empty absolute HTTPS URLs.")
	} else if webhook.clientConfig.URL != nil && !validWebhookURL(*webhook.clientConfig.URL) {
		add("URLInvalid", "has an invalid URL target", "Admission webhook URL targets must be absolute HTTPS URLs without user info, query parameters, or fragments.")
	}
	if webhook.clientConfig.Service != nil {
		if !validWebhookServiceNamespace(webhook.clientConfig.Service.Namespace) {
			add("ServiceNamespaceInvalid", "has an invalid Service namespace", "Webhook Service references must specify a valid non-empty namespace.")
		}
		if !validWebhookServiceName(webhook.clientConfig.Service.Name) {
			add("ServiceNameInvalid", "has an invalid Service name", "Webhook Service references must specify a valid non-empty Service name.")
		}
		if webhook.clientConfig.Service.Port != nil && !validWebhookPort(*webhook.clientConfig.Service.Port) {
			add("ServicePortInvalid", "has an invalid Service port", "Webhook Service ports must be between 1 and 65535.")
		}
	}
	if len(webhook.clientConfig.CABundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(webhook.clientConfig.CABundle) {
			add("CABundleInvalid", "has an invalid CA bundle", "Webhook clientConfig.caBundle must contain one or more PEM-encoded certificates.")
		}
	}

	if len(webhook.rules) > 0 {
		for index, rule := range webhook.rules {
			missing := make([]string, 0, 4)
			if len(rule.Operations) == 0 {
				missing = append(missing, "operations")
			}
			if len(rule.APIGroups) == 0 {
				missing = append(missing, "apiGroups")
			}
			if len(rule.APIVersions) == 0 {
				missing = append(missing, "apiVersions")
			}
			if len(rule.Resources) == 0 {
				missing = append(missing, "resources")
			}
			if len(missing) > 0 {
				add(fmt.Sprintf("Rule-%d-Missing", index), fmt.Sprintf("has an incomplete rule %d", index), fmt.Sprintf("Admission webhook rule %d must specify %s.", index, strings.Join(missing, ", ")))
			}
			if webhookRuleHasInvalidWildcard(rule.Operations) || webhookRuleHasInvalidWildcard(rule.APIGroups) || webhookRuleHasInvalidWildcard(rule.APIVersions) || webhookRuleHasInvalidWildcard(rule.Resources) {
				add(fmt.Sprintf("Rule-%d-Wildcard", index), fmt.Sprintf("has an invalid wildcard in rule %d", index), fmt.Sprintf("Admission webhook rule %d must use a wildcard as the only value in each wildcard-capable list.", index))
			}
		}
	}

	if webhook.failurePolicy != nil && *webhook.failurePolicy != admissionregistrationv1.Ignore && *webhook.failurePolicy != admissionregistrationv1.Fail {
		add("FailurePolicyInvalid", "has an invalid failure policy", "Admission webhook failurePolicy must be Ignore or Fail.")
	}
	if webhook.matchPolicy != nil && *webhook.matchPolicy != admissionregistrationv1.Exact && *webhook.matchPolicy != admissionregistrationv1.Equivalent {
		add("MatchPolicyInvalid", "has an invalid match policy", "Admission webhook matchPolicy must be Exact or Equivalent.")
	}
	if webhook.sideEffects != nil && *webhook.sideEffects != admissionregistrationv1.SideEffectClassNone && *webhook.sideEffects != admissionregistrationv1.SideEffectClassNoneOnDryRun {
		add("SideEffectsInvalid", "has invalid side effects", "Admission v1 webhooks must declare sideEffects as None or NoneOnDryRun.")
	}
	if webhook.timeoutSeconds != nil && (*webhook.timeoutSeconds < 1 || *webhook.timeoutSeconds > 30) {
		add("TimeoutInvalid", "has an invalid timeout", "Admission webhook timeoutSeconds must be between 1 and 30 seconds.")
	}
	if len(webhook.admissionReviewVersions) > 0 {
		for index, version := range webhook.admissionReviewVersions {
			if strings.TrimSpace(version) == "" {
				add(fmt.Sprintf("AdmissionReviewVersion-%d", index), "has an empty admission review version", "Admission webhook admissionReviewVersions must contain non-empty versions.")
			}
		}
	}
	if webhook.reinvocationPolicy != nil && *webhook.reinvocationPolicy != admissionregistrationv1.NeverReinvocationPolicy && *webhook.reinvocationPolicy != admissionregistrationv1.IfNeededReinvocationPolicy {
		add("ReinvocationPolicyInvalid", "has an invalid reinvocation policy", "Mutating webhook reinvocationPolicy must be Never or IfNeeded.")
	}
	for selectorName, selector := range map[string]*metav1.LabelSelector{"namespace selector": webhook.namespaceSelector, "object selector": webhook.objectSelector} {
		if selector == nil {
			continue
		}
		if _, err := metav1.LabelSelectorAsSelector(selector); err != nil {
			add(strings.ReplaceAll(strings.Title(selectorName), " ", "")+"Invalid", fmt.Sprintf("has an invalid %s", selectorName), fmt.Sprintf("Admission webhook %s could not be converted to a Kubernetes label selector.", selectorName))
		}
	}
	if len(webhook.matchConditions) > 64 {
		add("MatchConditionsLimit", "has too many match conditions", "Admission webhooks may specify at most 64 matchConditions.")
	}
	conditionNames := make(map[string]struct{}, len(webhook.matchConditions))
	for index, condition := range webhook.matchConditions {
		if strings.TrimSpace(condition.Name) == "" || len(utilvalidation.IsQualifiedName(condition.Name)) > 0 {
			add(fmt.Sprintf("MatchCondition-%d-Name", index), fmt.Sprintf("has an invalid match condition name at index %d", index), "Admission webhook match condition names must be valid qualified names.")
		}
		if strings.TrimSpace(condition.Expression) == "" {
			add(fmt.Sprintf("MatchCondition-%d-Expression", index), fmt.Sprintf("has an empty match condition expression at index %d", index), "Admission webhook match condition expressions must be non-empty CEL expressions.")
		}
		if _, exists := conditionNames[condition.Name]; exists {
			add(fmt.Sprintf("MatchCondition-%d-Duplicate", index), fmt.Sprintf("has a duplicate match condition at index %d", index), "Admission webhook match condition names must be unique within a webhook.")
		}
		conditionNames[condition.Name] = struct{}{}
	}

	return findings
}

func validWebhookURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Hostname() != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validWebhookServiceReference(reference *admissionregistrationv1.ServiceReference) bool {
	return reference != nil && validWebhookServiceNamespace(reference.Namespace) && validWebhookServiceName(reference.Name) && (reference.Port == nil || validWebhookPort(*reference.Port))
}

func validWebhookServiceNamespace(namespace string) bool {
	return strings.TrimSpace(namespace) == namespace && len(utilvalidation.IsDNS1123Label(namespace)) == 0
}

func validWebhookServiceName(name string) bool {
	return strings.TrimSpace(name) == name && len(utilvalidation.IsDNS1035Label(name)) == 0
}

func validWebhookPort(port int32) bool {
	return port >= 1 && port <= 65535
}

func serviceExposesWebhookPort(service *corev1.Service, targetPort int32) bool {
	if service == nil {
		return false
	}
	for _, port := range service.Spec.Ports {
		if port.Port == targetPort {
			return true
		}
	}
	return false
}

func servicePortNumbers(service *corev1.Service) []int32 {
	if service == nil {
		return nil
	}
	ports := make([]int32, 0, len(service.Spec.Ports))
	for _, port := range service.Spec.Ports {
		ports = append(ports, port.Port)
	}
	return ports
}

func webhookRuleHasInvalidWildcard[T ~string](values []T) bool {
	if len(values) <= 1 {
		return false
	}
	for _, value := range values {
		if string(value) == "*" {
			return true
		}
	}
	return false
}

func combineLabelSelectors(left, right string) string {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	return left + "," + right
}

func (s *ClusterScanner) scanConfigMaps(ctx context.Context, namespace string) ([]*Issue, error) {
	configMaps, err := s.client.CoreV1().ConfigMaps(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	references, err := s.configMapReferenceRequirements(ctx, namespace)
	if err != nil {
		return nil, err
	}
	used := make(map[string]struct{}, len(references))
	for key := range references {
		used[key] = struct{}{}
	}
	issues := make([]*Issue, 0)
	existing := make(map[string]struct{}, len(configMaps.Items))
	for index := range configMaps.Items {
		configMap := &configMaps.Items[index]
		existing[namespaceKey(configMap.Namespace, configMap.Name)] = struct{}{}
		if configMap.Annotations["sre.kubebee.com/ignore-configmap-check"] == "true" {
			continue
		}
		base := func(category IssueCategory, severity Severity, summary, details string) *Issue {
			return &Issue{ID: makeID(configMap.Namespace, "ConfigMap", configMap.Name, string(category)), Namespace: configMap.Namespace, Kind: "ConfigMap", Name: configMap.Name, Severity: severity, Category: category, Summary: summary, Details: details, FirstObserved: configMap.CreationTimestamp.Time, LastObserved: time.Now().UTC()}
		}
		if len(configMap.Data) == 0 && len(configMap.BinaryData) == 0 {
			issues = append(issues, base(CategoryConfigMapEmpty, SeverityLow, fmt.Sprintf("ConfigMap %s is empty", configMap.Name), "The ConfigMap has no data or binaryData entries."))
		}
		size := 0
		for key, value := range configMap.Data {
			size += len(key) + len(value)
		}
		for key, value := range configMap.BinaryData {
			size += len(key) + len(value)
		}
		if size > 1<<20 {
			issues = append(issues, base(CategoryConfigMapTooLarge, SeverityMedium, fmt.Sprintf("ConfigMap %s exceeds 1 MiB", configMap.Name), "Large ConfigMaps increase API-server/watch payloads; store large content in a dedicated artifact or volume."))
		}
		if _, ok := used[namespaceKey(configMap.Namespace, configMap.Name)]; !ok {
			issues = append(issues, base(CategoryConfigMapUnused, SeverityLow, fmt.Sprintf("ConfigMap %s is not referenced by a workload", configMap.Name), "No pod or workload template in the selected scope references this ConfigMap."))
		}
	}
	for key, reference := range references {
		if reference.optional {
			continue
		}
		if _, ok := existing[key]; ok {
			continue
		}
		referenceNamespace, referenceName := splitNamespaceKey(key)
		issues = append(issues, &Issue{
			ID:        makeID(referenceNamespace, "ConfigMap", referenceName, string(CategoryConfigMapReferenceMissing)),
			Namespace: referenceNamespace, Kind: "ConfigMap", Name: referenceName,
			Severity: SeverityHigh, Category: CategoryConfigMapReferenceMissing,
			Summary:       fmt.Sprintf("ConfigMap %s is referenced but does not exist", referenceName),
			Details:       "A workload references this ConfigMap, but the referenced object was not found in the workload namespace.",
			FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC(),
		})
	}
	return issues, nil
}

func (s *ClusterScanner) configMapUsage(ctx context.Context, namespace string) (map[string]struct{}, error) {
	references, err := s.configMapReferenceRequirements(ctx, namespace)
	if err != nil {
		return nil, err
	}
	used := make(map[string]struct{}, len(references))
	for key := range references {
		used[key] = struct{}{}
	}
	return used, nil
}

type configMapReference struct {
	optional bool
}

func (s *ClusterScanner) configMapReferenceRequirements(ctx context.Context, namespace string) (map[string]configMapReference, error) {
	references := make(map[string]configMapReference)
	addReference := func(ns, name string, optional bool) {
		if strings.TrimSpace(name) == "" {
			return
		}
		key := namespaceKey(ns, name)
		current, ok := references[key]
		if !ok || (!optional && current.optional) {
			references[key] = configMapReference{optional: optional}
		}
	}
	addContainer := func(ns string, env []corev1.EnvVar, envFrom []corev1.EnvFromSource) {
		for _, variable := range env {
			if variable.ValueFrom != nil && variable.ValueFrom.ConfigMapKeyRef != nil {
				optional := variable.ValueFrom.ConfigMapKeyRef.Optional != nil && *variable.ValueFrom.ConfigMapKeyRef.Optional
				addReference(ns, variable.ValueFrom.ConfigMapKeyRef.Name, optional)
			}
		}
		for _, source := range envFrom {
			if source.ConfigMapRef != nil {
				optional := source.ConfigMapRef.Optional != nil && *source.ConfigMapRef.Optional
				addReference(ns, source.ConfigMapRef.Name, optional)
			}
		}
	}
	addPodSpec := func(ns string, spec corev1.PodSpec) {
		for _, container := range spec.InitContainers {
			addContainer(ns, container.Env, container.EnvFrom)
		}
		for _, container := range spec.Containers {
			addContainer(ns, container.Env, container.EnvFrom)
		}
		for _, container := range spec.EphemeralContainers {
			addContainer(ns, container.Env, container.EnvFrom)
		}
		for _, volume := range spec.Volumes {
			if volume.ConfigMap != nil {
				addReference(ns, volume.ConfigMap.Name, false)
			}
			if volume.Projected != nil {
				for _, source := range volume.Projected.Sources {
					if source.ConfigMap != nil {
						addReference(ns, source.ConfigMap.Name, false)
					}
				}
			}
		}
	}
	pods, err := s.client.CoreV1().Pods(namespace).List(ctx, dependentListOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for _, pod := range pods.Items {
		addPodSpec(pod.Namespace, pod.Spec)
	}
	deployments, err := s.client.AppsV1().Deployments(namespace).List(ctx, dependentListOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for _, workload := range deployments.Items {
		addPodSpec(workload.Namespace, workload.Spec.Template.Spec)
	}
	statefulSets, err := s.client.AppsV1().StatefulSets(namespace).List(ctx, dependentListOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for _, workload := range statefulSets.Items {
		addPodSpec(workload.Namespace, workload.Spec.Template.Spec)
	}
	daemonSets, err := s.client.AppsV1().DaemonSets(namespace).List(ctx, dependentListOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for _, workload := range daemonSets.Items {
		addPodSpec(workload.Namespace, workload.Spec.Template.Spec)
	}
	replicaSets, err := s.client.AppsV1().ReplicaSets(namespace).List(ctx, dependentListOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for _, workload := range replicaSets.Items {
		addPodSpec(workload.Namespace, workload.Spec.Template.Spec)
	}
	jobs, err := s.client.BatchV1().Jobs(namespace).List(ctx, dependentListOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for _, workload := range jobs.Items {
		addPodSpec(workload.Namespace, workload.Spec.Template.Spec)
	}
	cronJobs, err := s.client.BatchV1().CronJobs(namespace).List(ctx, dependentListOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for _, workload := range cronJobs.Items {
		addPodSpec(workload.Namespace, workload.Spec.JobTemplate.Spec.Template.Spec)
	}
	return references, nil
}

func namespaceKey(namespace, name string) string { return namespace + "\x00" + name }

func splitNamespaceKey(value string) (string, string) {
	index := strings.IndexByte(value, '\x00')
	if index < 0 {
		return "", value
	}
	return value[:index], value[index+1:]
}

func (s *ClusterScanner) scanStorage(ctx context.Context, namespace string) ([]*Issue, error) {
	issues := make([]*Issue, 0)
	classes, err := s.client.StorageV1().StorageClasses().List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	defaults := make([]*storagev1.StorageClass, 0)
	classNames := make(map[string]struct{}, len(classes.Items))
	for index := range classes.Items {
		storageClass := &classes.Items[index]
		classNames[storageClass.Name] = struct{}{}
		if storageClass.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" || storageClass.Annotations["storageclass.beta.kubernetes.io/is-default-class"] == "true" {
			defaults = append(defaults, storageClass)
		}
		if strings.TrimSpace(storageClass.Provisioner) == "" {
			issues = append(issues, &Issue{ID: makeID("", "StorageClass", storageClass.Name, "NoProvisioner"), Kind: "StorageClass", Name: storageClass.Name, Severity: SeverityHigh, Category: CategoryStorageClassNoProvisioner, Summary: fmt.Sprintf("StorageClass %s has no provisioner", storageClass.Name), Details: "PVCs using this StorageClass cannot be dynamically provisioned.", FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()})
		}
		if deprecatedProvisioner(storageClass.Provisioner) {
			issues = append(issues, &Issue{ID: makeID("", "StorageClass", storageClass.Name, "DeprecatedProvisioner"), Kind: "StorageClass", Name: storageClass.Name, Severity: SeverityMedium, Category: CategoryStorageClassDeprecated, Summary: fmt.Sprintf("StorageClass %s uses a deprecated provisioner", storageClass.Name), Details: fmt.Sprintf("Provisioner %q is deprecated; migrate to the CSI driver equivalent.", storageClass.Provisioner), FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()})
		}
	}
	if len(defaults) > 1 {
		for _, storageClass := range defaults {
			issues = append(issues, &Issue{ID: makeID("", "StorageClass", storageClass.Name, "MultipleDefaults"), Kind: "StorageClass", Name: storageClass.Name, Severity: SeverityMedium, Category: CategoryStorageClassDefault, Summary: fmt.Sprintf("StorageClass %s is one of multiple defaults", storageClass.Name), Details: fmt.Sprintf("The cluster has %d default StorageClasses; PVC default selection is ambiguous.", len(defaults)), FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()})
		}
	}
	persistentVolumes, err := s.client.CoreV1().PersistentVolumes().List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	minimum := resource.MustParse("1Gi")
	for index := range persistentVolumes.Items {
		volume := &persistentVolumes.Items[index]
		base := func(category IssueCategory, severity Severity, suffix, summary, details string) *Issue {
			return &Issue{ID: makeID("", "PersistentVolume", volume.Name, suffix), Kind: "PersistentVolume", Name: volume.Name, TargetUID: string(volume.UID), TargetResourceVersion: volume.ResourceVersion, Severity: severity, Category: category, Summary: summary, Details: details, FirstObserved: volume.CreationTimestamp.Time, LastObserved: time.Now().UTC()}
		}
		switch volume.Status.Phase {
		case corev1.VolumeReleased:
			issues = append(issues, base(CategoryPVReleased, SeverityMedium, "Released", fmt.Sprintf("PersistentVolume %s is Released", volume.Name), "The previous claim was released; reclaim policy and data retention should be reviewed before reuse."))
		case corev1.VolumeFailed:
			issues = append(issues, base(CategoryPVFailed, SeverityHigh, "Failed", fmt.Sprintf("PersistentVolume %s is Failed", volume.Name), "The volume controller reported a failed state; inspect events and the CSI driver."))
		}
		if capacity, ok := volume.Spec.Capacity[corev1.ResourceStorage]; !ok || capacity.Cmp(minimum) < 0 {
			issues = append(issues, base(CategoryPVSmallCapacity, SeverityLow, "SmallCapacity", fmt.Sprintf("PersistentVolume %s has less than 1Gi capacity", volume.Name), "Very small persistent volumes are prone to filling and should be reviewed against workload requirements."))
		}
	}
	pvcs, err := s.client.CoreV1().PersistentVolumeClaims(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range pvcs.Items {
		claim := &pvcs.Items[index]
		if claim.Spec.StorageClassName == nil || strings.TrimSpace(*claim.Spec.StorageClassName) == "" {
			issues = append(issues, &Issue{ID: makeID(claim.Namespace, "PersistentVolumeClaim", claim.Name, "MissingStorageClass"), Namespace: claim.Namespace, Kind: "PersistentVolumeClaim", Name: claim.Name, Severity: SeverityMedium, Category: CategoryPVCStorageClassMissing, Summary: fmt.Sprintf("PVC %s has no StorageClass", claim.Name), Details: "The claim has no explicit or default StorageClass and may remain Pending.", FirstObserved: claim.CreationTimestamp.Time, LastObserved: time.Now().UTC()})
		} else if _, ok := classNames[strings.TrimSpace(*claim.Spec.StorageClassName)]; !ok {
			issues = append(issues, &Issue{ID: makeID(claim.Namespace, "PersistentVolumeClaim", claim.Name, "MissingStorageClass"), Namespace: claim.Namespace, Kind: "PersistentVolumeClaim", Name: claim.Name, Severity: SeverityHigh, Category: CategoryPVCStorageClassMissing, Summary: fmt.Sprintf("PVC %s references a missing StorageClass", claim.Name), Details: fmt.Sprintf("StorageClass %q does not exist, so the claim cannot be dynamically provisioned.", *claim.Spec.StorageClassName), FirstObserved: workloadObservedTime(claim.CreationTimestamp), LastObserved: time.Now().UTC()})
		}
		if capacity, ok := claim.Spec.Resources.Requests[corev1.ResourceStorage]; !ok || capacity.Cmp(minimum) < 0 {
			issues = append(issues, &Issue{ID: makeID(claim.Namespace, "PersistentVolumeClaim", claim.Name, "SmallCapacity"), Namespace: claim.Namespace, Kind: "PersistentVolumeClaim", Name: claim.Name, Severity: SeverityLow, Category: CategoryPVSmallCapacity, Summary: fmt.Sprintf("PVC %s requests less than 1Gi", claim.Name), Details: "Very small persistent volume claims are prone to filling and should be reviewed against workload requirements.", FirstObserved: claim.CreationTimestamp.Time, LastObserved: time.Now().UTC()})
		}
	}
	return filterIssuesByPlan(ctx, issues), nil
}

func deprecatedProvisioner(value string) bool {
	switch value {
	case "kubernetes.io/aws-ebs", "kubernetes.io/gce-pd", "kubernetes.io/azure-disk", "kubernetes.io/azure-file", "kubernetes.io/cinder", "kubernetes.io/vsphere-volume", "kubernetes.io/portworx-volume", "kubernetes.io/rbd":
		return true
	default:
		return false
	}
}

func (s *ClusterScanner) scanSecurity(ctx context.Context, namespace string) ([]*Issue, error) {
	issues := make([]*Issue, 0)
	pods, err := s.client.CoreV1().Pods(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range pods.Items {
		pod := &pods.Items[index]
		findings := podSecurityFindings(pod)
		issues = append(issues, findings...)
	}
	roleBindings, err := s.client.RbacV1().RoleBindings(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range roleBindings.Items {
		binding := &roleBindings.Items[index]
		if strings.EqualFold(strings.TrimSpace(binding.RoleRef.Name), "cluster-admin") {
			issues = append(issues, securityBindingIssue("RoleBinding", binding.Namespace, binding.Name, "RoleBinding grants cluster-admin", "Review whether this binding can be narrowed to the minimum required permissions."))
			continue
		}
		if issue, err := s.roleBindingPrivilegeIssue(ctx, binding); err != nil {
			return nil, err
		} else if issue != nil {
			issues = append(issues, issue)
		}
	}
	clusterBindings, err := s.client.RbacV1().ClusterRoleBindings().List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	for index := range clusterBindings.Items {
		binding := &clusterBindings.Items[index]
		if strings.EqualFold(strings.TrimSpace(binding.RoleRef.Name), "cluster-admin") {
			issues = append(issues, securityBindingIssue("ClusterRoleBinding", "", binding.Name, "ClusterRoleBinding grants cluster-admin", "Cluster-wide administrative access should be limited to a narrowly identified operator identity."))
			continue
		}
		if issue, err := s.clusterRoleBindingPrivilegeIssue(ctx, binding); err != nil {
			return nil, err
		} else if issue != nil {
			issues = append(issues, issue)
		}
	}
	return filterIssuesByPlan(ctx, issues), nil
}

func (s *ClusterScanner) roleBindingPrivilegeIssue(ctx context.Context, binding *rbacv1.RoleBinding) (*Issue, error) {
	if binding == nil || strings.TrimSpace(binding.RoleRef.Name) == "" {
		return nil, nil
	}
	roleKind := strings.TrimSpace(binding.RoleRef.Kind)
	if roleKind == "" {
		roleKind = "Role"
	}
	roleName := binding.RoleRef.Name
	switch strings.ToLower(roleKind) {
	case "role":
		role, err := s.client.RbacV1().Roles(binding.Namespace).Get(ctx, roleName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read Role %s/%s for RoleBinding %s: %w", binding.Namespace, roleName, binding.Name, err)
		}
		if !rbacRulesAreBroad(role.Rules) {
			return nil, nil
		}
		return securityRBACIssue("RoleBinding", binding.Namespace, binding.Name, "Role", roleName, false), nil
	case "clusterrole":
		role, err := s.client.RbacV1().ClusterRoles().Get(ctx, roleName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read ClusterRole %s for RoleBinding %s: %w", roleName, binding.Name, err)
		}
		if !rbacRulesAreBroad(role.Rules) {
			return nil, nil
		}
		return securityRBACIssue("RoleBinding", binding.Namespace, binding.Name, "ClusterRole", roleName, false), nil
	default:
		return nil, nil
	}
}

func (s *ClusterScanner) clusterRoleBindingPrivilegeIssue(ctx context.Context, binding *rbacv1.ClusterRoleBinding) (*Issue, error) {
	if binding == nil || strings.TrimSpace(binding.RoleRef.Name) == "" {
		return nil, nil
	}
	roleKind := strings.TrimSpace(binding.RoleRef.Kind)
	if roleKind != "" && !strings.EqualFold(roleKind, "ClusterRole") {
		return nil, nil
	}
	roleName := binding.RoleRef.Name
	role, err := s.client.RbacV1().ClusterRoles().Get(ctx, roleName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ClusterRole %s for ClusterRoleBinding %s: %w", roleName, binding.Name, err)
	}
	if !rbacRulesAreBroad(role.Rules) {
		return nil, nil
	}
	return securityRBACIssue("ClusterRoleBinding", "", binding.Name, "ClusterRole", roleName, true), nil
}

func rbacRulesAreBroad(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if rbacValuesContainWildcard(rule.Verbs) ||
			rbacValuesContainWildcard(rule.APIGroups) ||
			rbacValuesContainWildcard(rule.Resources) ||
			rbacNonResourceURLsAreBroad(rule.NonResourceURLs) {
			return true
		}
	}
	return false
}

func rbacValuesContainWildcard(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "*" {
			return true
		}
	}
	return false
}

func rbacNonResourceURLsAreBroad(values []string) bool {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "*" || strings.HasSuffix(value, "/*") {
			return true
		}
	}
	return false
}

func podSecurityFindings(pod *corev1.Pod) []*Issue {
	if pod == nil {
		return nil
	}
	findings := make([]*Issue, 0)
	add := func(suffix, summary, details string) {
		findings = append(findings, &Issue{ID: makeID(pod.Namespace, "Pod", pod.Name, suffix), Namespace: pod.Namespace, Kind: "Pod", Name: pod.Name, TargetUID: string(pod.UID), TargetResourceVersion: pod.ResourceVersion, Severity: SeverityHigh, Category: CategorySecurityPrivilege, Summary: summary, Details: details, FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC(), Parent: podOwnerReference(pod)})
	}
	if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
		add("HostNamespace", fmt.Sprintf("Pod %s shares a host namespace", pod.Name), "hostNetwork, hostPID, or hostIPC expands the pod's access to node-level processes and networking.")
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			add("HostPath", fmt.Sprintf("Pod %s mounts a host path", pod.Name), "HostPath volumes expose node filesystem paths and require an explicit security review.")
			break
		}
	}
	checkContainer := func(name string, security *corev1.SecurityContext, ephemeral bool) {
		prefix := ""
		kind := "Container"
		if ephemeral {
			prefix = "ephemeral-"
			kind = "Ephemeral container"
		}
		if security != nil && security.Privileged != nil && *security.Privileged {
			add("Privileged-"+prefix+name, fmt.Sprintf("%s %s/%s is privileged", kind, pod.Name, name), "Privileged containers bypass normal Linux isolation and should be avoided unless explicitly required.")
		}
		if security != nil && security.AllowPrivilegeEscalation != nil && *security.AllowPrivilegeEscalation {
			add("PrivilegeEscalation-"+prefix+name, fmt.Sprintf("%s %s/%s allows privilege escalation", kind, pod.Name, name), "Set allowPrivilegeEscalation=false for workloads that do not require setuid or file capabilities.")
		}
		if runAsUser := effectiveRunAsUser(pod, security); runAsUser != nil && *runAsUser == 0 {
			add("Root-"+prefix+name, fmt.Sprintf("%s %s/%s runs as root", kind, pod.Name, name), "Use a non-root UID and a read-only filesystem where the workload permits it.")
		}
	}
	for _, container := range pod.Spec.InitContainers {
		checkContainer(container.Name, container.SecurityContext, false)
	}
	for _, container := range pod.Spec.Containers {
		checkContainer(container.Name, container.SecurityContext, false)
	}
	for _, container := range pod.Spec.EphemeralContainers {
		checkContainer(container.Name, container.SecurityContext, true)
	}
	return findings
}

func effectiveRunAsUser(pod *corev1.Pod, container *corev1.SecurityContext) *int64 {
	if container != nil && container.RunAsUser != nil {
		return container.RunAsUser
	}
	if pod != nil && pod.Spec.SecurityContext != nil {
		return pod.Spec.SecurityContext.RunAsUser
	}
	return nil
}

func securityBindingIssue(kind, namespace, name, summary, details string) *Issue {
	return &Issue{ID: makeID(namespace, kind, name, "ClusterAdmin"), Namespace: namespace, Kind: kind, Name: name, Severity: SeverityCritical, Category: CategorySecurityClusterBinding, Summary: summary, Details: details, FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()}
}

func securityRBACIssue(kind, namespace, name, roleKind, roleName string, clusterWide bool) *Issue {
	severity := SeverityHigh
	scope := "namespace-scoped"
	if clusterWide {
		severity = SeverityCritical
		scope = "cluster-wide"
	}
	return &Issue{
		ID:            makeID(namespace, kind, name, "BroadPermissions-"+roleKind+"-"+roleName),
		Namespace:     namespace,
		Kind:          kind,
		Name:          name,
		Severity:      severity,
		Category:      CategorySecurityClusterBinding,
		Summary:       fmt.Sprintf("%s grants broad %s permissions through %s %s", kind, scope, roleKind, roleName),
		Details:       fmt.Sprintf("The referenced %s %s contains wildcard RBAC verbs, API groups, resources, or non-resource URLs. Review subjects and narrow the grant to the minimum required permissions.", roleKind, roleName),
		FirstObserved: time.Now().UTC(),
		LastObserved:  time.Now().UTC(),
	}
}

func (s *ClusterScanner) scanHPASemantics(ctx context.Context, namespace string) ([]*Issue, error) {
	hpas, err := s.client.AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	issues := make([]*Issue, 0)
	for index := range hpas.Items {
		hpa := &hpas.Items[index]
		kind := hpa.Spec.ScaleTargetRef.Kind
		if kind == "" {
			kind = "Deployment"
		}
		var targetErr error
		supported := true
		switch strings.ToLower(kind) {
		case "deployment":
			_, targetErr = s.client.AppsV1().Deployments(hpa.Namespace).Get(ctx, hpa.Spec.ScaleTargetRef.Name, metav1.GetOptions{})
		case "statefulset":
			_, targetErr = s.client.AppsV1().StatefulSets(hpa.Namespace).Get(ctx, hpa.Spec.ScaleTargetRef.Name, metav1.GetOptions{})
		case "replicaset":
			_, targetErr = s.client.AppsV1().ReplicaSets(hpa.Namespace).Get(ctx, hpa.Spec.ScaleTargetRef.Name, metav1.GetOptions{})
		default:
			supported = false
			issues = append(issues, &Issue{ID: makeID(hpa.Namespace, "HorizontalPodAutoscaler", hpa.Name, "UnsupportedTarget"), Namespace: hpa.Namespace, Kind: "HorizontalPodAutoscaler", Name: hpa.Name, Severity: SeverityHigh, Category: CategoryHPATargetMissing, Summary: fmt.Sprintf("HPA %s targets unsupported kind %s", hpa.Name, kind), Details: "The HPA target kind is not one of the supported scalable workload kinds.", FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()})
		}
		if supported && apierrors.IsNotFound(targetErr) {
			issues = append(issues, &Issue{ID: makeID(hpa.Namespace, "HorizontalPodAutoscaler", hpa.Name, "TargetMissing"), Namespace: hpa.Namespace, Kind: "HorizontalPodAutoscaler", Name: hpa.Name, Severity: SeverityHigh, Category: CategoryHPATargetMissing, Summary: fmt.Sprintf("HPA %s target %s/%s is missing", hpa.Name, kind, hpa.Spec.ScaleTargetRef.Name), Details: "The scale target could not be found in the HPA namespace.", FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()})
		} else if supported && targetErr != nil {
			return nil, fmt.Errorf("read HPA %s/%s target %s/%s: %w", hpa.Namespace, hpa.Name, kind, hpa.Spec.ScaleTargetRef.Name, targetErr)
		}
		for metricIndex, metric := range hpa.Spec.Metrics {
			invalid := false
			switch metric.Type {
			case "Resource":
				invalid = metric.Resource == nil || strings.TrimSpace(string(metric.Resource.Name)) == ""
			case "Pods":
				invalid = metric.Pods == nil || metric.Pods.Metric.Name == ""
			case "Object":
				invalid = metric.Object == nil || metric.Object.Metric.Name == "" || metric.Object.DescribedObject.Name == ""
			case "External":
				invalid = metric.External == nil || metric.External.Metric.Name == ""
			default:
				invalid = true
			}
			if invalid {
				issues = append(issues, &Issue{ID: makeID(hpa.Namespace, "HorizontalPodAutoscaler", hpa.Name, fmt.Sprintf("Metric-%d", metricIndex)), Namespace: hpa.Namespace, Kind: "HorizontalPodAutoscaler", Name: hpa.Name, Severity: SeverityHigh, Category: CategoryHPAMetricInvalid, Summary: fmt.Sprintf("HPA %s has an invalid metric target", hpa.Name), Details: "Each HPA metric must identify a supported metric source and name.", FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()})
			}
		}
	}
	return issues, nil
}

func (s *ClusterScanner) scanPDBSemantics(ctx context.Context, namespace string) ([]*Issue, error) {
	pdbs, err := s.client.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}
	issues := make([]*Issue, 0)
	for index := range pdbs.Items {
		pdb := &pdbs.Items[index]
		if pdb.Spec.Selector == nil {
			issues = append(issues, &Issue{ID: makeID(pdb.Namespace, "PodDisruptionBudget", pdb.Name, "SelectorMissing"), Namespace: pdb.Namespace, Kind: "PodDisruptionBudget", Name: pdb.Name, Severity: SeverityHigh, Category: CategoryPDBSelectorInvalid, Summary: fmt.Sprintf("PDB %s has no selector", pdb.Name), Details: "A PodDisruptionBudget without a selector cannot express the intended protected workload.", FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()})
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			issues = append(issues, &Issue{ID: makeID(pdb.Namespace, "PodDisruptionBudget", pdb.Name, "SelectorInvalid"), Namespace: pdb.Namespace, Kind: "PodDisruptionBudget", Name: pdb.Name, Severity: SeverityHigh, Category: CategoryPDBSelectorInvalid, Summary: fmt.Sprintf("PDB %s has an invalid selector", pdb.Name), Details: "The PDB selector could not be converted to a Kubernetes label selector.", FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()})
			continue
		}
		options := dependentListOptionsForScan(ctx)
		if options.LabelSelector != "" {
			globalSelector, parseErr := labels.Parse(options.LabelSelector)
			if parseErr == nil {
				options.LabelSelector = combineLabelSelectors(selector.String(), globalSelector.String())
			}
		} else {
			options.LabelSelector = selector.String()
		}
		pods, listErr := s.client.CoreV1().Pods(pdb.Namespace).List(ctx, options)
		if listErr != nil {
			return nil, fmt.Errorf("list pods matching PDB %s/%s: %w", pdb.Namespace, pdb.Name, listErr)
		}
		if len(pods.Items) == 0 {
			issues = append(issues, &Issue{ID: makeID(pdb.Namespace, "PodDisruptionBudget", pdb.Name, "NoMatchingPods"), Namespace: pdb.Namespace, Kind: "PodDisruptionBudget", Name: pdb.Name, Severity: SeverityMedium, Category: CategoryPDBNoMatchingPods, Summary: fmt.Sprintf("PDB %s matches no pods", pdb.Name), Details: "The disruption budget does not currently protect a matching workload; verify selector labels and deployment intent.", FirstObserved: time.Now().UTC(), LastObserved: time.Now().UTC()})
		}
	}
	return issues, nil
}

func filterIssuesByPlan(ctx context.Context, issues []*Issue) []*Issue {
	plan, ok := scanPlanFromContext(ctx)
	if !ok {
		return issues
	}
	filtered := make([]*Issue, 0, len(issues))
	for _, issue := range issues {
		if issueMatchesPlan(plan, issue) {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

func scanPlanFromContext(ctx context.Context) (scanplan.Plan, bool) {
	return scanplan.FromContext(ctx)
}
