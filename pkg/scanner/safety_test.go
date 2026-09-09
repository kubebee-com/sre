package scanner

import (
	"context"
	"errors"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestScannerAndCleanerPreserveTargetIdentity(t *testing.T) {
	client := fake.NewSimpleClientset()
	sc := NewClusterScanner(client)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "default", UID: types.UID("pod-uid"), ResourceVersion: "11"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed},
	}
	issue := sc.analyzePod(pod)
	if issue == nil || issue.TargetUID != string(pod.UID) || issue.TargetResourceVersion != pod.ResourceVersion {
		t.Fatalf("pod issue identity = %#v, want %q/%q", issue, pod.UID, pod.ResourceVersion)
	}

	cleaner := NewPodCleaner(client)
	if _, err := client.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	candidates, err := cleaner.ListCleanablePods(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListCleanablePods() error = %v", err)
	}
	if len(candidates) != 1 || candidates[0].TargetUID != string(pod.UID) || candidates[0].TargetResourceVersion != pod.ResourceVersion {
		t.Fatalf("cleanable identity = %#v, want %q/%q", candidates, pod.UID, pod.ResourceVersion)
	}
}

func TestCleanerDryRunReportsCurrentCandidatesWithoutDeletion(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "default", UID: types.UID("failed-uid"), ResourceVersion: "1"}, Status: corev1.PodStatus{Phase: corev1.PodFailed}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "running", Namespace: "default", UID: types.UID("running-uid"), ResourceVersion: "1"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	)
	cleaner := NewPodCleaner(client)
	report, err := cleaner.CleanPods(context.Background(), "default", []string{"failed", "running"}, true)
	if err != nil {
		t.Fatalf("dry-run error = %v", err)
	}
	if report.DeletedCount != 0 || len(report.CandidatePods) != 1 || report.CandidatePods[0] != "failed" {
		t.Fatalf("dry-run report = %#v, want only current candidate and zero deletions", report)
	}
	if _, err := client.CoreV1().Pods("default").Get(context.Background(), "failed", metav1.GetOptions{}); err != nil {
		t.Fatalf("dry-run removed candidate: %v", err)
	}
}

func TestCleanerRequiresApprovalAndDoesNotRetryForceDelete(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "default", UID: types.UID("failed-uid"), ResourceVersion: "1"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed},
	})
	deleteCalls := 0
	client.PrependReactor("delete", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteCalls++
		return true, nil, fmt.Errorf("delete should not be called directly")
	})
	_, err := NewPodCleaner(client).CleanPods(context.Background(), "default", []string{"failed"}, false)
	if !errors.Is(err, ErrCleanupRequiresApproval) {
		t.Fatalf("direct cleanup error = %v, want ErrCleanupRequiresApproval", err)
	}
	if deleteCalls != 0 {
		t.Fatalf("direct cleanup issued %d delete calls", deleteCalls)
	}
}

func TestCleanerExcludesProtectedNamespacesAndLabels(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "system-failed", Namespace: "kube-system", UID: types.UID("system"), ResourceVersion: "1"}, Status: corev1.PodStatus{Phase: corev1.PodFailed}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "labeled-failed", Namespace: "default", UID: types.UID("labeled"), ResourceVersion: "1", Labels: map[string]string{"sre.kubebee.com/protected": "true"}}, Status: corev1.PodStatus{Phase: corev1.PodFailed}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "eligible-failed", Namespace: "default", UID: types.UID("eligible"), ResourceVersion: "1"}, Status: corev1.PodStatus{Phase: corev1.PodFailed}},
	)
	candidates, err := NewPodCleaner(client).ListCleanablePods(context.Background(), "")
	if err != nil {
		t.Fatalf("ListCleanablePods() error = %v", err)
	}
	if len(candidates) != 1 || candidates[0].Name != "eligible-failed" {
		t.Fatalf("protected cleanup candidates = %#v", candidates)
	}
}
