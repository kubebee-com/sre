package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	coretypedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

type parityTestAnalyzer struct {
	name  string
	issue *Issue
}

func (a parityTestAnalyzer) Info() AnalyzerInfo {
	return AnalyzerInfo{
		Name:        a.name,
		Resource:    "Pod",
		Description: "parity test analyzer",
		DocsURL:     "https://example.invalid/parity",
	}
}

func (a parityTestAnalyzer) Analyze(context.Context, string) ([]*Issue, error) {
	return []*Issue{a.issue}, nil
}

type panicParityAnalyzer struct{}

func (panicParityAnalyzer) Info() AnalyzerInfo {
	return AnalyzerInfo{Name: "panic", Resource: "Pod", Description: "panic test analyzer", DocsURL: "https://example.invalid/panic"}
}

func (panicParityAnalyzer) Analyze(context.Context, string) ([]*Issue, error) {
	panic("analyzer secret=should-not-escape")
}

func TestScanWithPlanDeduplicatesFindingsByStableIdentity(t *testing.T) {
	issue := &Issue{
		ID:        "default/Pod/duplicate/CrashLoopBackOff",
		Namespace: "default",
		Kind:      "Pod",
		Name:      "duplicate",
		Category:  CategoryCrashLoop,
		Summary:   "container is restarting",
		Details:   "the same finding was observed by two analyzers",
	}
	scanner := NewClusterScanner(nil)
	for _, name := range []string{"second", "first"} {
		if err := scanner.RegisterAnalyzer(parityTestAnalyzer{name: name, issue: issue}); err != nil {
			t.Fatalf("RegisterAnalyzer(%q): %v", name, err)
		}
	}

	plan := scanplan.Plan{
		SchemaVersion:  scanplan.SchemaVersion,
		Analyzers:      []string{"first", "second"},
		MaxConcurrency: 2,
		Timeout:        scanplan.DefaultScanTimeout,
	}
	report, err := scanner.ScanWithPlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("ScanWithPlan() error = %v", err)
	}
	if got := len(report.Issues); got != 1 {
		t.Fatalf("ScanWithPlan() returned %d duplicate findings, want one: %#v", got, report.Issues)
	}
}

func TestScanWithPlanContainsAnalyzerPanicsAsSanitizedRunErrors(t *testing.T) {
	scanner := NewClusterScanner(nil)
	if err := scanner.RegisterAnalyzer(panicParityAnalyzer{}); err != nil {
		t.Fatalf("RegisterAnalyzer(): %v", err)
	}
	report, err := scanner.ScanWithPlan(context.Background(), scanPlanForAnalyzer("panic"))
	if err != nil {
		t.Fatalf("ScanWithPlan() error = %v", err)
	}
	if len(report.Analyzers) != 1 || !strings.Contains(report.Analyzers[0].Error, "panic") {
		t.Fatalf("panic run = %#v, want a recorded analyzer error", report.Analyzers)
	}
	if strings.Contains(report.Analyzers[0].Error, "should-not-escape") {
		t.Fatalf("panic error leaked sensitive text: %q", report.Analyzers[0].Error)
	}
}

func TestAnalyzePodFindingsIncludesInitRegularAndEphemeralStatuses(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "multi", Namespace: "default"}, Status: corev1.PodStatus{
		InitContainerStatuses:      []corev1.ContainerStatus{{Name: "init", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}},
		ContainerStatuses:          []corev1.ContainerStatus{{Name: "app", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}}},
		EphemeralContainerStatuses: []corev1.ContainerStatus{{Name: "debug", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}}},
	}}
	issues := NewClusterScanner(nil).analyzePodFindings(pod)
	seen := map[IssueCategory]bool{}
	for _, issue := range issues {
		seen[issue.Category] = true
	}
	for _, category := range []IssueCategory{CategoryCrashLoop, CategoryImagePull, CategoryOOMKilled} {
		if !seen[category] {
			t.Errorf("analyzePodFindings() omitted %s: %#v", category, issues)
		}
	}
}

func TestAnalyzePodFindingsInfersCrashLoopFromRestartedTerminatedContainer(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "terminated-restart", Namespace: "default"},
		Spec:       corev1.PodSpec{RestartPolicy: corev1.RestartPolicyAlways},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:         "app",
			RestartCount: 1,
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode: 1,
			}},
		}}},
	}

	if issues := NewClusterScanner(nil).analyzePodFindings(pod); !hasIssueCategory(issues, CategoryCrashLoop) {
		t.Fatalf("analyzePodFindings() omitted inferred crash-loop finding: %#v", issues)
	}
}

func TestScanDeploymentsReportsProgressDeadlineWithoutReplicaDeficit(t *testing.T) {
	ready := int32(1)
	generation := int64(2)
	client := fake.NewSimpleClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", Generation: generation}, Spec: appsv1.DeploymentSpec{Replicas: &ready}, Status: appsv1.DeploymentStatus{
		ObservedGeneration: generation,
		ReadyReplicas:      ready,
		Conditions:         []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", Message: "rollout timed out"}},
	}})
	issues, err := NewClusterScanner(client).scanDeployments(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanDeployments(): %v", err)
	}
	if len(issues) == 0 || !strings.Contains(strings.ToLower(issues[0].Details), "progressdeadlineexceeded") {
		t.Fatalf("scanDeployments() = %#v, want a progress-deadline finding", issues)
	}
}

func TestScanJobsReportsActiveDeadlineAndRetryLimit(t *testing.T) {
	backoff := int32(1)
	deadline := int64(60)
	start := metav1.NewTime(time.Now().Add(-2 * time.Minute))
	client := fake.NewSimpleClientset(&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "batch", Namespace: "default"}, Spec: batchv1.JobSpec{BackoffLimit: &backoff, ActiveDeadlineSeconds: &deadline}, Status: batchv1.JobStatus{StartTime: &start, Failed: 2}})
	issues, err := NewClusterScanner(client).scanJobs(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanJobs(): %v", err)
	}
	if len(issues) < 2 {
		t.Fatalf("scanJobs() = %#v, want deadline and retry findings", issues)
	}
	text := ""
	for _, issue := range issues {
		text += strings.ToLower(issue.Summary + " " + issue.Details)
	}
	for _, want := range []string{"deadline", "backoff"} {
		if !strings.Contains(text, want) {
			t.Errorf("scanJobs() omitted %q: %#v", want, issues)
		}
	}
}

func TestScanServicesReportsInvalidExternalNameAndNamedTargetPort(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "external", Namespace: "default"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: "not a dns name"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromString("https")}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default", Labels: map[string]string{"app": "web"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}}}},
	)
	issues, err := NewClusterScanner(client).scanServices(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanServices(): %v", err)
	}
	text := ""
	for _, issue := range issues {
		text += strings.ToLower(issue.Summary + " " + issue.Details)
	}
	for _, want := range []string{"externalname", "targetport"} {
		if !strings.Contains(text, want) {
			t.Errorf("scanServices() omitted %q: %#v", want, issues)
		}
	}
}

func TestScanConfigMapsReportsMissingReferencedObject(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "present", Namespace: "default"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "consumer", Namespace: "default"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "app",
				EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "missing"},
				}}},
			}}},
		},
	)
	issues, err := NewClusterScanner(client).scanConfigMaps(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanConfigMaps(): %v", err)
	}
	for _, issue := range issues {
		if issue.Category == IssueCategory("ConfigMapReferenceMissing") && issue.Name == "missing" {
			return
		}
	}
	t.Fatalf("scanConfigMaps() = %#v, want a missing-reference finding", issues)
}

func TestScanStorageReportsNamedStorageClassMissing(t *testing.T) {
	className := "missing-class"
	client := fake.NewSimpleClientset(&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "claim", Namespace: "default"}, Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: &className}})
	issues, err := NewClusterScanner(client).scanStorage(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanStorage(): %v", err)
	}
	for _, issue := range issues {
		if issue.Category == IssueCategory("PVCStorageClassMissing") && issue.Name == "claim" {
			return
		}
	}
	t.Fatalf("scanStorage() = %#v, want a named missing StorageClass finding", issues)
}

func TestScanWithPlanContinuesAfterForbiddenAnalyzer(t *testing.T) {
	forbidden := errors.New("forbidden")
	scanner := NewClusterScanner(nil)
	if err := scanner.RegisterAnalyzer(errorParityAnalyzer{name: "forbidden", err: forbidden}); err != nil {
		t.Fatalf("RegisterAnalyzer(): %v", err)
	}
	if err := scanner.RegisterAnalyzer(parityTestAnalyzer{name: "healthy", issue: &Issue{Kind: "Pod", Name: "healthy", Category: CategoryPodFailed}}); err != nil {
		t.Fatalf("RegisterAnalyzer(): %v", err)
	}
	plan := scanplan.Plan{SchemaVersion: scanplan.SchemaVersion, Analyzers: []string{"forbidden", "healthy"}, MaxConcurrency: 2, Timeout: scanplan.DefaultScanTimeout}
	report, err := scanner.ScanWithPlan(context.Background(), plan)
	if err != nil || len(report.Issues) != 1 {
		t.Fatalf("ScanWithPlan() = report=%#v err=%v, want healthy finding and recorded error", report, err)
	}
}

func TestScanWithPlanDoesNotMutateSharedFindingPointers(t *testing.T) {
	issue := &Issue{
		Namespace: "default",
		Kind:      "Pod",
		Name:      "shared",
		Category:  CategoryPodFailed,
		Summary:   strings.Repeat("summary ", maxIssueSummaryBytes),
		Events:    []string{"event"},
	}
	originalSummary := issue.Summary
	scanner := NewClusterScanner(nil)
	for _, name := range []string{"shared-first", "shared-second"} {
		if err := scanner.RegisterAnalyzer(parityTestAnalyzer{name: name, issue: issue}); err != nil {
			t.Fatalf("RegisterAnalyzer(%q): %v", name, err)
		}
	}
	plan := scanplan.Plan{SchemaVersion: scanplan.SchemaVersion, Analyzers: []string{"shared-first", "shared-second"}, MaxConcurrency: 2, Timeout: scanplan.DefaultScanTimeout}
	if _, err := scanner.ScanWithPlan(context.Background(), plan); err != nil {
		t.Fatalf("ScanWithPlan() error = %v", err)
	}
	if issue.Summary != originalSummary || len(issue.Events) != 1 {
		t.Fatalf("ScanWithPlan() mutated analyzer-owned finding: %#v", issue)
	}
}

func TestScanPDBSemanticsClearsParentNameSelectorForPodLookup(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default", Labels: map[string]string{"app": "web"}}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "budget", Namespace: "default"}, Spec: policyv1.PodDisruptionBudgetSpec{Selector: selector}},
	)
	var podFields string
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction := action.(k8stesting.ListAction)
		podFields = listAction.GetListRestrictions().Fields.String()
		if podFields != "" {
			return true, &corev1.PodList{}, nil
		}
		return false, nil, nil
	})
	plan := scanplan.Plan{SchemaVersion: scanplan.SchemaVersion, IncludeNamespaces: []string{"default"}, Names: []string{"budget"}}
	ctx := scanplan.WithContext(context.Background(), plan)
	issues, err := NewClusterScanner(client).scanPDBSemantics(ctx, "default")
	if err != nil {
		t.Fatalf("scanPDBSemantics() error = %v", err)
	}
	if podFields != "" || hasIssueCategory(issues, CategoryPDBNoMatchingPods) {
		t.Fatalf("PDB pod lookup retained parent selector %q: %#v", podFields, issues)
	}
}

func TestScanConfigMapsClearsParentNameSelectorForReferenceLookup(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "consumer", Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "missing"},
		}}}}}},
	})
	var podFields string
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction := action.(k8stesting.ListAction)
		podFields = listAction.GetListRestrictions().Fields.String()
		if podFields != "" {
			return true, &corev1.PodList{}, nil
		}
		return false, nil, nil
	})
	plan := scanplan.Plan{SchemaVersion: scanplan.SchemaVersion, IncludeNamespaces: []string{"default"}, Names: []string{"missing"}}
	ctx := scanplan.WithContext(context.Background(), plan)
	issues, err := NewClusterScanner(client).scanConfigMaps(ctx, "default")
	if err != nil {
		t.Fatalf("scanConfigMaps() error = %v", err)
	}
	if podFields != "" || !hasIssue(issues, "missing", CategoryConfigMapReferenceMissing) {
		t.Fatalf("ConfigMap reference lookup retained parent selector %q: %#v", podFields, issues)
	}
}

func TestScanWithPlanIncludesClusterScopedFindingsWithNamespaceFilter(t *testing.T) {
	client := fake.NewSimpleClientset(&storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "broken"}})
	plan := scanplan.Plan{SchemaVersion: scanplan.SchemaVersion, IncludeNamespaces: []string{"default"}, Analyzers: []string{"StorageAnalyzer"}, MaxConcurrency: 1, Timeout: time.Second}
	report, err := NewClusterScanner(client).ScanWithPlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("ScanWithPlan() error = %v", err)
	}
	if !hasIssue(report.Issues, "broken", CategoryStorageClassNoProvisioner) {
		t.Fatalf("ScanWithPlan() omitted cluster-scoped StorageClass finding: %#v", report.Issues)
	}
}

func TestDynamicScanWithPlanHonorsPlanTimeout(t *testing.T) {
	client := newDynamicTestClient()
	client.PrependReactor("list", "gateways", func(k8stesting.Action) (bool, runtime.Object, error) {
		time.Sleep(25 * time.Millisecond)
		return false, nil, nil
	})
	typed := fake.NewSimpleClientset()
	scanner := NewClusterScannerWithDynamicClient(typed, client)
	plan := scanplan.Plan{SchemaVersion: scanplan.SchemaVersion, Analyzers: []string{"GatewayAnalyzer"}, MaxConcurrency: 1, Timeout: time.Millisecond}
	_, err := scanner.ScanWithPlan(context.Background(), plan)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ScanWithPlan() error = %v, want context deadline exceeded", err)
	}
}

func TestScanPodsPreservesLogPermissionErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse(): %v", err)
	}
	baseClient := fake.NewSimpleClientset(restartedPod("logs"))
	client := logErrorClient{Interface: baseClient, base: base, httpClient: server.Client()}
	_, err = NewClusterScanner(client).scanPods(context.Background(), "default")
	if err == nil {
		t.Fatal("scanPods() discarded pod log permission error")
	}
}

func TestScanPodsPreservesEventPermissionErrors(t *testing.T) {
	client := fake.NewSimpleClientset(restartedPod("events"))
	client.PrependReactor("list", "events", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("events denied"))
	})
	_, err := NewClusterScanner(client).scanPods(context.Background(), "default")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanPods() error = %v, want forbidden event retrieval error", err)
	}
}

func TestScanWarningEventsEmitsStandaloneFindings(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "failed-scheduling.1", Namespace: "default"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "pending", UID: "pod-uid"},
		Reason:         "FailedScheduling",
		Message:        "0/1 nodes are available",
		Type:           corev1.EventTypeWarning,
	})
	scanner := NewClusterScanner(client)
	var eventAnalyzer Analyzer
	for _, analyzer := range scanner.RegisteredAnalyzers() {
		if analyzer.Info().Name == "EventAnalyzer" {
			eventAnalyzer = analyzer
			break
		}
	}
	if eventAnalyzer == nil {
		t.Fatal("EventAnalyzer is not registered")
	}
	issues, err := eventAnalyzer.Analyze(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanWarningEvents() error = %v", err)
	}
	if !hasIssue(issues, "pending", CategoryWarningEvent) {
		t.Fatalf("scanWarningEvents() omitted WarningEvent finding: %#v", issues)
	}
}

func restartedPod(name string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Status: corev1.PodStatus{
		ContainerStatuses: []corev1.ContainerStatus{{Name: "app", RestartCount: 1, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}},
	}}
}

type logErrorClient struct {
	kubernetes.Interface
	base       *url.URL
	httpClient *http.Client
}

func (c logErrorClient) CoreV1() coretypedv1.CoreV1Interface {
	return logErrorCore{CoreV1Interface: c.Interface.CoreV1(), base: c.base, httpClient: c.httpClient}
}

type logErrorCore struct {
	coretypedv1.CoreV1Interface
	base       *url.URL
	httpClient *http.Client
}

func (c logErrorCore) Pods(namespace string) coretypedv1.PodInterface {
	return logErrorPods{PodInterface: c.CoreV1Interface.Pods(namespace), base: c.base, httpClient: c.httpClient}
}

type logErrorPods struct {
	coretypedv1.PodInterface
	base       *url.URL
	httpClient *http.Client
}

func (p logErrorPods) GetLogs(name string, _ *corev1.PodLogOptions) *rest.Request {
	return rest.NewRequestWithClient(p.base, "", rest.ClientContentConfig{}, p.httpClient).Resource("pods").Name(name).SubResource("log")
}

type errorParityAnalyzer struct {
	name string
	err  error
}

func (a errorParityAnalyzer) Info() AnalyzerInfo {
	return AnalyzerInfo{Name: a.name, Resource: "Pod", Description: "error test analyzer", DocsURL: "https://example.invalid/error"}
}

func (a errorParityAnalyzer) Analyze(context.Context, string) ([]*Issue, error) {
	return nil, a.err
}
