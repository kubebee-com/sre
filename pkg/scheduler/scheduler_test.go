package scheduler

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func TestRunnerPreventsOverlap(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	active := 0
	job := func(context.Context) error {
		mu.Lock()
		active++
		if active != 1 {
			mu.Unlock()
			t.Errorf("active jobs = %d, want one", active)
			return nil
		}
		mu.Unlock()
		close(started)
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return nil
	}
	runner, err := New(Options{Interval: time.Second, Jitter: 100 * time.Millisecond, Random: rand.New(rand.NewSource(1)), Job: job})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- func() error { _, err := runner.RunOnce(context.Background()); return err }() }()
	<-started
	if ran, err := runner.RunOnce(context.Background()); ran || !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("overlapping RunOnce() = %v, %v; want false/ErrAlreadyRunning", ran, err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("first RunOnce() error = %v", err)
	}
}

func TestKubernetesLeaseValidation(t *testing.T) {
	if _, err := NewKubernetesLease(LeaseOptions{}); !errors.Is(err, ErrLeaseConfiguration) {
		t.Fatalf("empty lease error = %v, want ErrLeaseConfiguration", err)
	}
	client := fake.NewSimpleClientset()
	lease, err := NewKubernetesLease(LeaseOptions{Client: client, Namespace: "sre", Name: "sre-agent", Identity: "pod-a", LeaseDuration: 30 * time.Second, RenewDeadline: 20 * time.Second, RetryPeriod: 5 * time.Second})
	if err != nil || lease == nil {
		t.Fatalf("NewKubernetesLease() = %#v, %v", lease, err)
	}
}

func TestRunnerReturnsInitialJobError(t *testing.T) {
	want := errors.New("initial failure")
	runner, err := New(Options{Interval: time.Hour, Job: func(context.Context) error { return want }})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := runner.Run(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Run(initial error) = %v, want %v", err, want)
	}
}
