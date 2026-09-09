package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPodCleaner(t *testing.T) {
	client := fake.NewSimpleClientset()
	cleaner := NewPodCleaner(client)

	ctx := context.Background()

	// 1. Create test pods:
	// - normal running pod (not cleanable)
	// - evicted pod (cleanable)
	// - failed pod (cleanable)
	// - completed pod (cleanable)
	_, _ = client.CoreV1().Pods("default").Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "running-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}, metav1.CreateOptions{})

	_, _ = client.CoreV1().Pods("default").Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "evicted-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"},
	}, metav1.CreateOptions{})

	_, _ = client.CoreV1().Pods("default").Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "failed-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Error"},
	}, metav1.CreateOptions{})

	past := time.Now().Add(-2 * time.Hour)
	_, _ = client.CoreV1().Pods("default").Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "completed-pod",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: past},
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}, metav1.CreateOptions{})

	// Test ListCleanablePods
	cleanable, err := cleaner.ListCleanablePods(ctx, "default")
	if err != nil {
		t.Fatalf("ListCleanablePods failed: %v", err)
	}

	if len(cleanable) != 3 {
		t.Fatalf("expected 3 cleanable pods, got %d", len(cleanable))
	}

	// Test CleanPods (dry-run)
	report, err := cleaner.CleanPods(ctx, "default", []string{"evicted-pod", "failed-pod"}, true)
	if err != nil {
		t.Fatalf("CleanPods dry-run failed: %v", err)
	}
	if report.DeletedCount != 0 || len(report.CandidatePods) != 2 {
		t.Fatalf("expected 2 dry-run candidates and no deletions, got %#v", report)
	}

	// Mutating cleanup is approval-gated and is not performed by the cleaner.
	if _, err := cleaner.CleanPods(ctx, "default", []string{"evicted-pod"}, false); !errors.Is(err, ErrCleanupRequiresApproval) {
		t.Fatalf("CleanPods mutation error = %v, want approval requirement", err)
	}
}
