package scheduler

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

func TestTriggerQueueCoalescesLatestStateAndDrainsDeterministically(t *testing.T) {
	queue, err := NewTriggerQueue(TriggerQueueOptions{Capacity: 8, Debounce: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewTriggerQueue() error = %v", err)
	}
	if !queue.Enqueue(Trigger{Resource: "Pod", Namespace: "ops", Name: "worker", EventType: "ADDED"}) {
		t.Fatal("Enqueue(first) = false")
	}
	if !queue.Enqueue(Trigger{Resource: "pod", Namespace: "ops", Name: "worker", EventType: "MODIFIED"}) {
		t.Fatal("Enqueue(update) = false")
	}
	if !queue.Enqueue(Trigger{Resource: "Service", Namespace: "ops", Name: "api", EventType: "MODIFIED"}) {
		t.Fatal("Enqueue(service) = false")
	}
	if got := queue.Pending(); got != 2 {
		t.Fatalf("Pending() = %d, want 2", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	triggers := make(chan Trigger, 2)
	runErr := make(chan error, 1)
	var callbackCount atomic.Int32
	go func() {
		runErr <- queue.Run(ctx, func(_ context.Context, trigger Trigger) error {
			triggers <- trigger
			if callbackCount.Add(1) == 2 {
				cancel()
			}
			return nil
		})
	}()

	var got []Trigger
	for len(got) < 2 {
		select {
		case trigger := <-triggers:
			got = append(got, trigger)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for queued triggers")
		}
	}
	if err := <-runErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	want := []Trigger{
		{Resource: "pod", Namespace: "ops", Name: "worker", EventType: "MODIFIED"},
		{Resource: "Service", Namespace: "ops", Name: "api", EventType: "MODIFIED"},
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Key() < want[j].Key() })
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("drained trigger[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestTriggerKeyCanonicalizesCaseInsensitively(t *testing.T) {
	added := Trigger{Resource: "Pod", Namespace: "Ops", Name: "Worker", EventType: "ADDED"}
	modified := Trigger{Resource: "pod", Namespace: "ops", Name: "worker", EventType: "MODIFIED"}
	if added.Key() != modified.Key() {
		t.Fatalf("case variants have different keys: %q != %q", added.Key(), modified.Key())
	}
	if added.Key() == (Trigger{Resource: "Service", Namespace: "ops", Name: "worker"}).Key() {
		t.Fatal("different resources share a trigger key")
	}
}

func TestTriggerQueueDebouncesBurstBeforeDrainingBatch(t *testing.T) {
	const debounce = 50 * time.Millisecond
	queue, err := NewTriggerQueue(TriggerQueueOptions{Capacity: 4, Debounce: debounce})
	if err != nil {
		t.Fatalf("NewTriggerQueue() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	callbackTimes := make(chan time.Time, 2)
	runErr := make(chan error, 1)
	started := time.Now()
	go func() {
		runErr <- queue.Run(ctx, func(_ context.Context, _ Trigger) error {
			callbackTimes <- time.Now()
			return nil
		})
	}()
	if !queue.Enqueue(Trigger{Resource: "Pod", Namespace: "ops", Name: "worker"}) {
		t.Fatal("Enqueue(first) = false")
	}
	if !queue.Enqueue(Trigger{Resource: "Service", Namespace: "ops", Name: "api"}) {
		t.Fatal("Enqueue(second) = false")
	}

	var callbacks [2]time.Time
	for i := range callbacks {
		select {
		case callbacks[i] = <-callbackTimes:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for debounced batch")
		}
	}
	if elapsed := callbacks[0].Sub(started); elapsed < debounce/2 {
		t.Fatalf("first callback arrived after %s, want at least %s", elapsed, debounce/2)
	}
	if gap := callbacks[1].Sub(callbacks[0]); gap >= debounce/2 {
		t.Fatalf("callbacks separated by %s, want one drained batch", gap)
	}
	cancel()
	if err := <-runErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestTriggerQueueRunReturnsContextCancellation(t *testing.T) {
	queue, err := NewTriggerQueue(TriggerQueueOptions{Capacity: 1})
	if err != nil {
		t.Fatalf("NewTriggerQueue() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- queue.Run(ctx, func(context.Context, Trigger) error { return nil })
	}()
	cancel()
	select {
	case err := <-runErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after cancellation")
	}
}

func TestTriggerQueueBoundsDistinctKeysAndCountsDrops(t *testing.T) {
	queue, err := NewTriggerQueue(TriggerQueueOptions{Capacity: 1, Debounce: time.Hour})
	if err != nil {
		t.Fatalf("NewTriggerQueue() error = %v", err)
	}
	if !queue.Enqueue(Trigger{Resource: "Pod", Namespace: "ops", Name: "worker"}) {
		t.Fatal("Enqueue(first) = false")
	}
	if queue.Enqueue(Trigger{Resource: "Service", Namespace: "ops", Name: "api"}) {
		t.Fatal("Enqueue(overflow) = true, want false")
	}
	if !queue.Enqueue(Trigger{Resource: "pod", Namespace: "ops", Name: "worker", EventType: "DELETED"}) {
		t.Fatal("Enqueue(coalesced) = false")
	}
	if got := queue.DropCount(); got != 1 {
		t.Fatalf("DropCount() = %d, want 1", got)
	}
	if got := queue.Pending(); got != 1 {
		t.Fatalf("Pending() = %d, want 1", got)
	}
}

func TestTriggerQueueRejectsInvalidConfigurationAndTriggers(t *testing.T) {
	if _, err := NewTriggerQueue(TriggerQueueOptions{Capacity: 0}); !errors.Is(err, ErrTriggerQueueConfiguration) {
		t.Fatalf("zero capacity error = %v, want ErrTriggerQueueConfiguration", err)
	}
	if _, err := NewTriggerQueue(TriggerQueueOptions{Capacity: 1, Debounce: -time.Second}); !errors.Is(err, ErrTriggerQueueConfiguration) {
		t.Fatalf("negative debounce error = %v, want ErrTriggerQueueConfiguration", err)
	}
	queue, err := NewTriggerQueue(TriggerQueueOptions{Capacity: 1})
	if err != nil {
		t.Fatalf("NewTriggerQueue() error = %v", err)
	}
	if queue.Enqueue(Trigger{Namespace: "ops", Name: "worker"}) {
		t.Fatal("Enqueue(invalid trigger) = true")
	}
}

func TestPlanForTriggerScopesNamespaceAndPreservesDependencies(t *testing.T) {
	base := scanplan.Default()
	base.LabelSelector = "team=sre"
	plan, ok := PlanForTrigger(base, Trigger{Resource: "Pod", Namespace: "ops", Name: "worker"})
	if !ok {
		t.Fatal("PlanForTrigger() = false, want in-scope trigger")
	}
	if len(plan.IncludeNamespaces) != 1 || plan.IncludeNamespaces[0] != "ops" {
		t.Fatalf("IncludeNamespaces = %#v, want [ops]", plan.IncludeNamespaces)
	}
	if len(plan.Names) != 0 {
		t.Fatalf("Names = %#v, want empty for dependency-safe scan", plan.Names)
	}
	if len(plan.Kinds) != 2 || plan.Kinds[0] != "Event" || plan.Kinds[1] != "Pod" {
		t.Fatalf("Kinds = %#v, want sorted [Event Pod]", plan.Kinds)
	}
	if plan.LabelSelector != base.LabelSelector {
		t.Fatalf("LabelSelector = %q, want %q", plan.LabelSelector, base.LabelSelector)
	}
}

func TestPlanForTriggerUsesEventInvolvedObjectAndHonorsBaseScope(t *testing.T) {
	base := scanplan.Default()
	base.IncludeNamespaces = []string{"ops"}
	plan, ok := PlanForTrigger(base, Trigger{
		Resource:        "Event",
		Namespace:       "ops",
		Name:            "warning.123",
		TargetResource:  "Pod",
		TargetNamespace: "ops",
		TargetName:      "worker",
	})
	if !ok {
		t.Fatal("PlanForTrigger(event) = false, want in-scope trigger")
	}
	if len(plan.Kinds) != 2 || plan.Kinds[0] != "Event" || plan.Kinds[1] != "Pod" {
		t.Fatalf("event Kinds = %#v, want [Event Pod]", plan.Kinds)
	}
	base.ExcludeNamespaces = []string{"ops"}
	if _, ok := PlanForTrigger(base, Trigger{Resource: "Pod", Namespace: "ops", Name: "worker"}); ok {
		t.Fatal("PlanForTrigger(excluded namespace) = true")
	}
	base.ExcludeNamespaces = nil
	base.Kinds = []string{"Deployment"}
	if _, ok := PlanForTrigger(base, Trigger{Resource: "Pod", Namespace: "ops", Name: "worker"}); ok {
		t.Fatal("PlanForTrigger(out-of-scope kind) = true")
	}
}

func TestPlanForTriggerHonorsConfiguredNamesBeforeDroppingDependencyNames(t *testing.T) {
	base := scanplan.Default()
	base.Names = []string{"worker"}
	if _, ok := PlanForTrigger(base, Trigger{Resource: "Pod", Namespace: "ops", Name: "other"}); ok {
		t.Fatal("PlanForTrigger(unselected Pod) = true")
	}
	plan, ok := PlanForTrigger(base, Trigger{Resource: "Pod", Namespace: "ops", Name: "worker"})
	if !ok || len(plan.Names) != 0 {
		t.Fatalf("PlanForTrigger(selected Pod) = %#v, %t; want accepted dependency-safe plan without Names", plan, ok)
	}
	if _, ok := PlanForTrigger(base, Trigger{
		Resource:        "Event",
		Namespace:       "ops",
		Name:            "warning.123",
		TargetResource:  "Pod",
		TargetNamespace: "ops",
		TargetName:      "other",
	}); ok {
		t.Fatal("PlanForTrigger(event for unselected target) = true")
	}
}

func TestRunnerRunWithTriggersSharesOverlapProtection(t *testing.T) {
	periodicStarted := make(chan struct{})
	releasePeriodic := make(chan struct{})
	triggerStarted := make(chan struct{})
	var mu sync.Mutex
	active := 0
	maxActive := 0
	job := func(context.Context) error {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		close(periodicStarted)
		<-releasePeriodic
		mu.Lock()
		active--
		mu.Unlock()
		return nil
	}
	runner, err := New(Options{Interval: time.Hour, Job: job})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	queue, err := NewTriggerQueue(TriggerQueueOptions{Capacity: 2, Debounce: time.Millisecond})
	if err != nil {
		t.Fatalf("NewTriggerQueue() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- runner.RunWithTriggers(ctx, queue, func(_ context.Context, _ Trigger) error {
			close(triggerStarted)
			return nil
		})
	}()
	<-periodicStarted
	if !queue.Enqueue(Trigger{Resource: "Pod", Namespace: "ops", Name: "worker"}) {
		t.Fatal("Enqueue() = false")
	}
	select {
	case <-triggerStarted:
		t.Fatal("trigger job ran while periodic job was active")
	case <-time.After(20 * time.Millisecond):
	}
	close(releasePeriodic)
	select {
	case <-triggerStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for trigger job")
	}
	cancel()
	if err := <-runErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("RunWithTriggers() error = %v, want context.Canceled", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if maxActive != 1 {
		t.Fatalf("max concurrent jobs = %d, want 1", maxActive)
	}
}
