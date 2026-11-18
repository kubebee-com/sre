package scanner

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestScanPodLogsDetectsActiveControllerFailuresAndIgnoresBenignLines(t *testing.T) {
	base, _ := url.Parse("http://logs.invalid")
	activePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-sync-controller-0", Namespace: "cluster-config-controller"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         "controller",
				RestartCount: 0,
				State:        corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}},
			}},
		},
	}
	waitingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pending-worker", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         "worker",
				RestartCount: 0,
				State:        corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}},
			}},
		},
	}
	benignPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy-web", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         "web",
				RestartCount: 0,
				State:        corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}},
			}},
		},
	}

	client := logErrorClient{
		Interface: fake.NewSimpleClientset(activePod, waitingPod, benignPod),
		base:      base,
		httpClient: &http.Client{Transport: coverageRoundTripper(func(r *http.Request) (*http.Response, error) {
			path := r.URL.Path
			switch {
			case strings.Contains(path, "/cluster-sync-controller-0/"):
				body := "2026/11/18 05:00:00 OCI NLB discovery: unable to construct NLB client for location \"sjc-1\": bad configuration\n"
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &coverageStringBody{strings.NewReader(body)}}, nil
			case strings.Contains(path, "/healthy-web/"):
				body := "time=... level=info msg=\"completed with 0 errors and err=nil\"\n"
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &coverageStringBody{strings.NewReader(body)}}, nil
			default:
				t.Fatalf("unexpected log fetch for waiting pod or unknown target: %s", path)
				return nil, nil
			}
		})},
	}

	issues, err := NewClusterScanner(client).scanPodLogs(context.Background(), "")
	if err != nil {
		t.Fatalf("scanPodLogs() error = %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("scanPodLogs() returned %d issues, want 1: %#v", len(issues), issues)
	}
	if issues[0].Name != "cluster-sync-controller-0" || issues[0].Severity != SeverityHigh || issues[0].Category != CategoryPodLogError {
		t.Fatalf("unexpected active log issue = %#v", issues[0])
	}
}

type coverageStringBody struct{ *strings.Reader }

func (b *coverageStringBody) Close() error { return nil }

func TestScanPodLogsIgnoresMissingPreviousContainerBadRequestAndHistoryResolvesVanishedPods(t *testing.T) {
	restartedMissingPrev := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "migrator-2", Namespace: "apps", UID: "uid-2"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         "app",
				RestartCount: 1,
				State:        corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
	base, _ := url.Parse("http://logs.invalid")
	k8sClient := fake.NewSimpleClientset(restartedMissingPrev)
	client := logErrorClient{
		Interface: k8sClient,
		base:      base,
		httpClient: &http.Client{Transport: coverageRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.URL.Query().Get("previous") == "true" {
				status := apierrors.NewBadRequest(`previous terminated container "app" in pod "migrator-2" not found`).Status()
				return nil, &apierrors.StatusError{ErrStatus: status}
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &coverageStringBody{strings.NewReader("all good\n")}}, nil
		})},
	}

	history := NewMemoryHistoryStore()
	vanished := &Issue{
		ID:            "apps/Pod/migrator-1/LogError-regular-app-current",
		AnalyzerNames: []string{"LogAnalyzer"},
		Namespace:     "apps",
		Kind:          "Pod",
		Name:          "migrator-1",
		TargetUID:     "uid-1",
		Severity:      SeverityMedium,
		Category:      CategoryPodLogError,
		Summary:       "Pod migrator-1 has current error patterns",
	}
	oldStarted := time.Now().UTC().Add(-10 * time.Minute)
	if err := history.RecordReport(&ScanReport{
		Issues:     []*Issue{vanished},
		Analyzers:  []AnalyzerRun{{Info: AnalyzerInfo{Name: "LogAnalyzer"}}},
		StartedAt:  oldStarted,
		FinishedAt: oldStarted.Add(time.Second),
	}); err != nil {
		t.Fatalf("seed RecordReport() error = %v", err)
	}

	sc := NewClusterScannerWithHistory(client, history)
	report, err := sc.ScanWithPlan(context.Background(), scanPlanForAnalyzer("LogAnalyzer"))
	if err != nil {
		t.Fatalf("ScanWithPlan() error = %v", err)
	}
	if len(report.Analyzers) != 1 || report.Analyzers[0].Error != "" {
		t.Fatalf("LogAnalyzer failed on missing previous container log: %#v", report.Analyzers)
	}
	rows, _ := history.List()
	for _, row := range rows {
		if row.Issue != nil && row.Issue.Name == "migrator-1" && !row.Resolved {
			t.Fatalf("vanished pod issue remained unresolved in history: %#v", row)
		}
	}
}

func TestScanServicesDetectsCiliumHealthCheckNodePortMismatchAndLBPending(t *testing.T) {
	ciliumDisabled := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-config", Namespace: "kube-system"},
		Data: map[string]string{
			"kube-proxy-replacement":       "true",
			"enable-health-check-nodeport": "false",
		},
	}
	lbSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "ingress-nginx-controller",
			Namespace:         "ingress-nginx",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-15 * time.Minute)),
		},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			HealthCheckNodePort:   31543,
			Selector:              map[string]string{"app": "ingress-nginx"},
			Ports:                 []corev1.ServicePort{{Name: "http", Port: 80}},
		},
	}
	epSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx-controller-abc",
			Namespace: "ingress-nginx",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "ingress-nginx-controller"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.42.0.10"}}},
	}

	client := fake.NewSimpleClientset(ciliumDisabled, lbSvc, epSlice)
	issues, err := NewClusterScanner(client).scanServices(context.Background(), "ingress-nginx")
	if err != nil {
		t.Fatalf("scanServices() error = %v", err)
	}

	var foundCiliumCritical, foundLBPending bool
	for _, issue := range issues {
		if issue.Category != CategoryServiceHealthCheck {
			continue
		}
		if issue.Severity == SeverityCritical && strings.Contains(issue.Details, "enable-health-check-nodeport") {
			foundCiliumCritical = true
		}
		if issue.Severity == SeverityHigh && strings.Contains(issue.Summary, "no external ingress address") {
			foundLBPending = true
		}
	}
	if !foundCiliumCritical {
		t.Fatalf("scanServices() did not report critical Cilium healthCheckNodePort mismatch: %#v", issues)
	}
	if !foundLBPending {
		t.Fatalf("scanServices() did not report pending LoadBalancer ingress: %#v", issues)
	}

	// Enabled healthCheckNodePort + assigned LoadBalancer ingress clears both issues.
	ciliumDisabled.Data["enable-health-check-nodeport"] = "true"
	lbSvc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "170.9.4.168"}}
	clientHealthy := fake.NewSimpleClientset(ciliumDisabled, lbSvc, epSlice)
	healthyIssues, err := NewClusterScanner(clientHealthy).scanServices(context.Background(), "ingress-nginx")
	if err != nil {
		t.Fatalf("scanServices(healthy) error = %v", err)
	}
	for _, issue := range healthyIssues {
		if issue.Category == CategoryServiceHealthCheck {
			t.Fatalf("unexpected healthCheck issue when Cilium and LB ingress are healthy: %#v", issue)
		}
	}
}

func TestScanServicesIgnoresForbiddenCiliumConfig(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "cilium-config", nil)
	})
	if _, err := NewClusterScanner(client).scanServices(context.Background(), "default"); err != nil {
		t.Fatalf("scanServices() failed on forbidden cilium-config: %v", err)
	}
}

func TestFoldIssuesAndSummarizeCategoriesReduceNoiseDeterministically(t *testing.T) {
	now := time.Now().UTC()
	var issues []*Issue
	for _, podName := range []string{"db-migrate-c", "db-migrate-a", "db-migrate-b"} {
		issues = append(issues, &Issue{
			ID:        "apps/Pod/" + podName + "/LogError",
			Namespace: "apps", Kind: "Pod", Name: podName,
			Severity: SeverityHigh, Category: CategoryPodLogError,
			Summary:       "Pod " + podName + " has current error patterns in regular container logs",
			Details:       "failed to connect to db",
			LogsSnippet:   "ERROR connection refused",
			FirstObserved: now, LastObserved: now,
			Parent: &ResourceRef{Namespace: "apps", Kind: "Job", Name: "db-migrate"},
		})
	}
	for _, dsPod := range []string{"cilium-1", "cilium-2"} {
		issues = append(issues,
			&Issue{
				ID: "kube-system/Pod/" + dsPod + "/Privileged", Namespace: "kube-system", Kind: "Pod", Name: dsPod,
				Severity: SeverityHigh, Category: CategorySecurityPrivilege,
				Summary: "Container " + dsPod + "/cilium-agent is privileged", Details: "privileged",
				Parent: &ResourceRef{Namespace: "kube-system", Kind: "DaemonSet", Name: "cilium"},
			},
			&Issue{
				ID: "kube-system/Pod/" + dsPod + "/HostNetwork", Namespace: "kube-system", Kind: "Pod", Name: dsPod,
				Severity: SeverityHigh, Category: CategorySecurityPrivilege,
				Summary: "Pod " + dsPod + " shares a host namespace", Details: "hostNetwork",
				Parent: &ResourceRef{Namespace: "kube-system", Kind: "DaemonSet", Name: "cilium"},
			},
		)
	}
	for _, cm := range []string{"cm-1", "cm-2", "cm-3"} {
		issues = append(issues, &Issue{
			ID: "flux-system/ConfigMap/" + cm + "/Unused", Namespace: "flux-system", Kind: "ConfigMap", Name: cm,
			Severity: SeverityLow, Category: CategoryConfigMapUnused,
			Summary: "ConfigMap " + cm + " is unused", Details: "unused",
		})
	}
	for _, cr := range []string{"backup-1", "backup-2"} {
		issues = append(issues, &Issue{
			ID: "apps/Backup/" + cr + "/WarningEvent-FindingCluster", Namespace: "apps", Kind: "Backup", Name: cr,
			Severity: SeverityMedium, Category: CategoryWarningEvent,
			Summary: "Warning event FindingCluster for Backup " + cr, Details: "[FindingCluster] Unknown cluster",
		})
	}
	// Two distinct services must stay unfolded.
	issues = append(issues,
		&Issue{ID: "svc-a", Namespace: "apps", Kind: "Service", Name: "svc-a", Severity: SeverityHigh, Category: CategoryServiceNoEndpoint, Summary: "Service svc-a has 0 ready endpoints"},
		&Issue{ID: "svc-b", Namespace: "apps", Kind: "Service", Name: "svc-b", Severity: SeverityHigh, Category: CategoryServiceNoEndpoint, Summary: "Service svc-b has 0 ready endpoints"},
	)

	folded := FoldIssues(issues)
	if len(folded) != 6 {
		t.Fatalf("FoldIssues() collapsed 14 issues to %d groups, want 6: %#v", len(folded), folded)
	}
	var foundLogGroup, foundPrivGroup, foundCMGroup, foundWarningGroup bool
	for _, item := range folded {
		switch item.Category {
		case CategoryPodLogError:
			foundLogGroup = true
			if item.OccurrenceCount != 3 || item.Name != "db-migrate-a" || len(item.AffectedResources) != 3 {
				t.Fatalf("unexpected folded PodLogError = %#v", item)
			}
		case CategorySecurityPrivilege:
			foundPrivGroup = true
			if item.OccurrenceCount != 4 {
				t.Fatalf("unexpected folded SecurityPrivilege count = %d, want 4", item.OccurrenceCount)
			}
		case CategoryConfigMapUnused:
			foundCMGroup = true
			if item.OccurrenceCount != 3 {
				t.Fatalf("unexpected folded ConfigMapUnused count = %d, want 3", item.OccurrenceCount)
			}
		case CategoryWarningEvent:
			foundWarningGroup = true
			if item.OccurrenceCount != 2 {
				t.Fatalf("unexpected folded WarningEvent count = %d, want 2", item.OccurrenceCount)
			}
		}
	}
	if !foundLogGroup || !foundPrivGroup || !foundCMGroup || !foundWarningGroup {
		t.Fatalf("missing expected folded categories: log=%t priv=%t cm=%t warn=%t", foundLogGroup, foundPrivGroup, foundCMGroup, foundWarningGroup)
	}

	summaries := SummarizeCategories(issues)
	if len(summaries) != 5 {
		t.Fatalf("SummarizeCategories() returned %d categories, want 5: %#v", len(summaries), summaries)
	}
}
