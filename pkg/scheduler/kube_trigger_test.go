package scheduler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
)

type recordingTriggerSink struct {
	mu       sync.Mutex
	triggers []Trigger
	changed  chan struct{}
}

func newRecordingTriggerSink() *recordingTriggerSink {
	return &recordingTriggerSink{changed: make(chan struct{}, 1)}
}

func (s *recordingTriggerSink) Enqueue(trigger Trigger) bool {
	s.mu.Lock()
	s.triggers = append(s.triggers, trigger)
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default:
	}
	return true
}

func (s *recordingTriggerSink) snapshot() []Trigger {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Trigger(nil), s.triggers...)
}

func (s *recordingTriggerSink) waitForAtLeast(t *testing.T, count int) []Trigger {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		if got := s.snapshot(); len(got) >= count {
			return got
		}
		select {
		case <-s.changed:
		case <-timer.C:
			t.Fatalf("timed out waiting for %d triggers; got %d", count, len(s.snapshot()))
		}
	}
}

type runningKubernetesTriggerSource struct {
	cancel context.CancelFunc
	done   chan struct{}
	errCh  chan error
}

func startKubernetesTriggerSource(t *testing.T, client *fake.Clientset, sink *recordingTriggerSink, namespace string) *runningKubernetesTriggerSource {
	t.Helper()
	source, err := NewKubernetesTriggerSource(KubernetesTriggerSourceOptions{
		Client:       client,
		Sink:         sink,
		Namespace:    namespace,
		ResyncPeriod: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewKubernetesTriggerSource() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	running := &runningKubernetesTriggerSource{
		cancel: cancel,
		done:   make(chan struct{}),
		errCh:  make(chan error, 1),
	}
	go func() {
		running.errCh <- source.Run(ctx)
		close(running.done)
	}()
	t.Cleanup(func() {
		running.cancel()
		select {
		case <-running.done:
		case <-time.After(time.Second):
			t.Errorf("KubernetesTriggerSource.Run() did not stop during cleanup")
		}
	})
	waitForKubernetesWatches(t, client)
	return running
}

func waitForKubernetesWatches(t *testing.T, client *fake.Clientset) {
	t.Helper()
	wanted := map[string]bool{"pods": false, "events": false}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, action := range client.Actions() {
			if action.GetVerb() != "watch" {
				continue
			}
			if _, ok := wanted[action.GetResource().Resource]; ok {
				wanted[action.GetResource().Resource] = true
			}
		}
		if wanted["pods"] && wanted["events"] {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("timed out waiting for informer watches: %#v", wanted)
		}
	}
}

func stopKubernetesTriggerSource(t *testing.T, running *runningKubernetesTriggerSource) error {
	t.Helper()
	running.cancel()
	select {
	case err := <-running.errCh:
		return err
	case <-time.After(time.Second):
		t.Fatal("KubernetesTriggerSource.Run() did not return after cancellation")
		return nil
	}
}

func TestKubernetesTriggerSourceEmitsPodAddAndUpdate(t *testing.T) {
	client := fake.NewSimpleClientset()
	sink := newRecordingTriggerSink()
	running := startKubernetesTriggerSource(t, client, sink, "ops")

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "ops"}}
	if _, err := client.CoreV1().Pods("ops").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create(Pod) error = %v", err)
	}
	triggers := sink.waitForAtLeast(t, 1)
	assertKubernetesTrigger(t, triggers[0], "Pod", "ops", "worker", "ADDED")

	pod.Labels = map[string]string{"revision": "2"}
	if _, err := client.CoreV1().Pods("ops").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Update(Pod) error = %v", err)
	}
	triggers = sink.waitForAtLeast(t, 2)
	assertKubernetesTrigger(t, triggers[1], "Pod", "ops", "worker", "MODIFIED")

	if err := client.CoreV1().Pods("ops").Delete(context.Background(), pod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("Delete(Pod) error = %v", err)
	}
	triggers = sink.waitForAtLeast(t, 3)
	assertKubernetesTrigger(t, triggers[2], "Pod", "ops", "worker", "DELETED")

	if err := stopKubernetesTriggerSource(t, running); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestKubernetesTriggerSourceEmitsWarningEventAndInvolvedTarget(t *testing.T) {
	client := fake.NewSimpleClientset()
	sink := newRecordingTriggerSink()
	running := startKubernetesTriggerSource(t, client, sink, "ops")

	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Name: "worker.123", Namespace: "ops"},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Name:      "worker",
			Namespace: "ops",
		},
		Type:   corev1.EventTypeWarning,
		Reason: "Failed",
	}
	if _, err := client.CoreV1().Events("ops").Create(context.Background(), event, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create(Warning Event) error = %v", err)
	}
	triggers := sink.waitForAtLeast(t, 2)

	var eventTrigger, targetTrigger *Trigger
	for index := range triggers {
		trigger := &triggers[index]
		switch {
		case strings.EqualFold(trigger.Resource, "Event") && trigger.Name == event.Name:
			eventTrigger = trigger
		case strings.EqualFold(trigger.Resource, "Pod") && trigger.Namespace == "ops" && trigger.Name == "worker":
			targetTrigger = trigger
		}
	}
	if eventTrigger == nil {
		t.Fatalf("warning event trigger missing from %#v", triggers)
	}
	if targetTrigger == nil {
		t.Fatalf("involved Pod trigger missing from %#v", triggers)
	}
	if eventTrigger.EventType == "" || targetTrigger.EventType == "" {
		t.Fatalf("warning triggers must retain event types: event=%#v target=%#v", *eventTrigger, *targetTrigger)
	}
	if !strings.EqualFold(targetTrigger.EventType, "WARNING") {
		t.Fatalf("involved target event type = %q, want WARNING", targetTrigger.EventType)
	}

	if err := stopKubernetesTriggerSource(t, running); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestKubernetesTriggerSourceFiltersNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset()
	sink := newRecordingTriggerSink()
	running := startKubernetesTriggerSource(t, client, sink, "ops")

	outsidePod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "outside", Namespace: "other"}}
	if _, err := client.CoreV1().Pods("other").Create(context.Background(), outsidePod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create(outside Pod) error = %v", err)
	}
	outsideEvent := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Name: "outside.123", Namespace: "other"},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Name:      outsidePod.Name,
			Namespace: outsidePod.Namespace,
		},
		Type: corev1.EventTypeWarning,
	}
	if _, err := client.CoreV1().Events("other").Create(context.Background(), outsideEvent, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create(outside Event) error = %v", err)
	}

	select {
	case <-sink.changed:
		t.Fatalf("namespace-filtered objects emitted triggers: %#v", sink.snapshot())
	case <-time.After(150 * time.Millisecond):
	}
	if got := sink.snapshot(); len(got) != 0 {
		t.Fatalf("namespace-filtered trigger count = %d, want 0: %#v", len(got), got)
	}
	if err := stopKubernetesTriggerSource(t, running); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestKubernetesTriggerSourceRunReturnsContextCancellation(t *testing.T) {
	client := fake.NewSimpleClientset()
	sink := newRecordingTriggerSink()
	running := startKubernetesTriggerSource(t, client, sink, "ops")
	if err := stopKubernetesTriggerSource(t, running); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestKubernetesTriggerSourceAppliesFilterBeforeEnqueue(t *testing.T) {
	client := fake.NewSimpleClientset()
	sink := newRecordingTriggerSink()
	source, err := NewKubernetesTriggerSource(KubernetesTriggerSourceOptions{
		Client: client,
		Sink:   sink,
		Filter: func(trigger Trigger) bool { return trigger.Name == "selected" },
	})
	if err != nil {
		t.Fatalf("NewKubernetesTriggerSource() error = %v", err)
	}
	source.enqueuePod(watch.Added, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "selected", Namespace: "ops"}})
	source.enqueuePod(watch.Added, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "ignored", Namespace: "ops"}})
	triggers := sink.snapshot()
	if len(triggers) != 1 {
		t.Fatalf("filtered trigger count = %d, want 1: %#v", len(triggers), triggers)
	}
	assertKubernetesTrigger(t, triggers[0], "Pod", "ops", "selected", "ADDED")
}

func TestKubernetesTriggerSourceIgnoresNormalEvents(t *testing.T) {
	client := fake.NewSimpleClientset()
	sink := newRecordingTriggerSink()
	source, err := NewKubernetesTriggerSource(KubernetesTriggerSourceOptions{Client: client, Sink: sink})
	if err != nil {
		t.Fatalf("NewKubernetesTriggerSource() error = %v", err)
	}
	source.enqueueEvent(watch.Added, &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Name: "normal.123", Namespace: "ops"},
		Type:       corev1.EventTypeNormal,
	})
	if got := sink.snapshot(); len(got) != 0 {
		t.Fatalf("normal event emitted triggers: %#v", got)
	}
}

func assertKubernetesTrigger(t *testing.T, got Trigger, resource, namespace, name, eventType string) {
	t.Helper()
	if !strings.EqualFold(got.Resource, resource) || got.Namespace != namespace || got.Name != name {
		t.Fatalf("trigger = %#v, want %s %s/%s", got, resource, namespace, name)
	}
	if !strings.EqualFold(got.EventType, eventType) {
		t.Fatalf("trigger event type = %q, want %q: %#v", got.EventType, eventType, got)
	}
}
