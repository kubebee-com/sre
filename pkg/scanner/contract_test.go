package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

func TestScanWithPlanAppliesScopeAndReturnsDeterministicReport(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "prod", UID: "pod-uid", ResourceVersion: "7", Labels: map[string]string{"team": "sre"}},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "restart"}}}}},
	})
	plan := scanplan.Plan{
		IncludeNamespaces: []string{"prod"},
		LabelSelector:     "team=sre",
		Analyzers:         []string{"PodAnalyzer"},
		MaxConcurrency:    1,
		Timeout:           time.Second,
	}
	report, err := NewClusterScanner(client).ScanWithPlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("ScanWithPlan() error = %v", err)
	}
	if report.SchemaVersion != scanplan.SchemaVersion || len(report.Issues) != 1 || len(report.Analyzers) != 1 {
		t.Fatalf("report = %#v", report)
	}
	if report.Issues[0].TargetUID != "pod-uid" || report.Issues[0].TargetResourceVersion != "7" {
		t.Fatalf("target identity = %q/%q", report.Issues[0].TargetUID, report.Issues[0].TargetResourceVersion)
	}
	if report.Analyzers[0].Info.DocsURL == "" || report.Analyzers[0].Duration == "" {
		t.Fatalf("analyzer contract metadata missing: %#v", report.Analyzers[0])
	}
}

func TestScanWithPlanReportsAnalyzerErrorsWithoutLeakingErrorText(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, &secretLookingError{}
	})
	plan := scanplan.Plan{Analyzers: []string{"PodAnalyzer"}, MaxConcurrency: 1, Timeout: time.Second}
	report, err := NewClusterScanner(client).ScanWithPlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("ScanWithPlan() error = %v", err)
	}
	if len(report.Analyzers) != 1 || report.Analyzers[0].Error == "" {
		t.Fatalf("analyzer error not recorded: %#v", report.Analyzers)
	}
	if strings.Contains(report.Analyzers[0].Error, "raw-secret") {
		t.Fatal("analyzer error was not sanitized")
	}
}

type secretLookingError struct{}

func (*secretLookingError) Error() string { return "request failed password=raw-secret" }
