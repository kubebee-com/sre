package scheduler

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

const (
	DefaultTriggerQueueCapacity = 256
	DefaultTriggerDebounce      = 2 * time.Second
	triggerRetryInterval        = 10 * time.Millisecond
)

var (
	ErrTriggerQueueConfiguration = errors.New("trigger queue configuration is invalid")
	ErrTriggerQueueRequired      = errors.New("trigger queue is required")
	ErrTriggerJobRequired        = errors.New("trigger job is required")
)

// Trigger identifies the Kubernetes object whose change should prompt a
// targeted scan. Target fields are populated for Kubernetes Events, whose
// object identity is the event while the useful scan target is involvedObject.
type Trigger struct {
	Resource        string
	Namespace       string
	Name            string
	EventType       string
	TargetResource  string
	TargetNamespace string
	TargetName      string
}

func (t Trigger) normalized() Trigger {
	t.Resource = strings.TrimSpace(t.Resource)
	t.Namespace = strings.TrimSpace(t.Namespace)
	t.Name = strings.TrimSpace(t.Name)
	t.EventType = strings.TrimSpace(t.EventType)
	t.TargetResource = strings.TrimSpace(t.TargetResource)
	t.TargetNamespace = strings.TrimSpace(t.TargetNamespace)
	t.TargetName = strings.TrimSpace(t.TargetName)
	return t
}

// Key is stable across informer callbacks and resource kind casing. Event
// type is intentionally excluded so an update replaces an older state.
func (t Trigger) Key() string {
	t = t.normalized()
	if t.Resource == "" {
		return ""
	}
	return strings.ToLower(strings.Join([]string{t.Resource, t.Namespace, t.Name}, "\x00"))
}

type TriggerJob func(context.Context, Trigger) error

type TriggerQueueOptions struct {
	Capacity int
	Debounce time.Duration
}

// TriggerQueue is a bounded, latest-state queue. It coalesces updates for the
// same object and wakes one consumer after a short global debounce window.
type TriggerQueue struct {
	mu       sync.Mutex
	pending  map[string]Trigger
	capacity int
	debounce time.Duration
	notify   chan struct{}
	dropped  atomic.Uint64
}

func NewTriggerQueue(options TriggerQueueOptions) (*TriggerQueue, error) {
	if options.Capacity <= 0 {
		return nil, ErrTriggerQueueConfiguration
	}
	if options.Debounce < 0 {
		return nil, ErrTriggerQueueConfiguration
	}
	return &TriggerQueue{
		pending:  make(map[string]Trigger, options.Capacity),
		capacity: options.Capacity,
		debounce: options.Debounce,
		notify:   make(chan struct{}, 1),
	}, nil
}

// Enqueue never blocks. A false result means the trigger was invalid or the
// queue was full with distinct object keys; callers should rely on the next
// periodic resync for dropped state.
func (q *TriggerQueue) Enqueue(trigger Trigger) bool {
	if q == nil {
		return false
	}
	trigger = trigger.normalized()
	key := trigger.Key()
	if key == "" {
		return false
	}

	q.mu.Lock()
	if _, exists := q.pending[key]; !exists {
		if len(q.pending) >= q.capacity {
			q.mu.Unlock()
			q.dropped.Add(1)
			return false
		}
	}
	q.pending[key] = trigger
	q.mu.Unlock()

	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

func (q *TriggerQueue) Pending() int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

func (q *TriggerQueue) DropCount() uint64 {
	if q == nil {
		return 0
	}
	return q.dropped.Load()
}

// Run drains debounced batches serially. Job errors are deliberately
// isolated to one trigger so a failed targeted scan cannot stop future event
// processing; the periodic Runner remains the recovery path.
func (q *TriggerQueue) Run(ctx context.Context, job TriggerJob) error {
	if q == nil {
		return ErrTriggerQueueRequired
	}
	if job == nil {
		return ErrTriggerJobRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-q.notify:
		}
		if err := waitTriggerDebounce(ctx, q.debounce); err != nil {
			return err
		}
		for _, trigger := range q.drain() {
			if err := ctx.Err(); err != nil {
				return err
			}
			_ = job(ctx, trigger)
		}
	}
}

func (q *TriggerQueue) drain() []Trigger {
	q.mu.Lock()
	batch := make([]Trigger, 0, len(q.pending))
	for _, trigger := range q.pending {
		batch = append(batch, trigger)
	}
	q.pending = make(map[string]Trigger, q.capacity)
	q.mu.Unlock()
	sort.Slice(batch, func(i, j int) bool { return batch[i].Key() < batch[j].Key() })
	return batch
}

func waitTriggerDebounce(ctx context.Context, debounce time.Duration) error {
	if debounce <= 0 {
		return nil
	}
	timer := time.NewTimer(debounce)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// RunWithTriggers combines periodic and event-triggered jobs under the same
// overlap gate. If a periodic scan is active, an event waits rather than
// being discarded; once the scan finishes, the latest queued state is used.
func (r *Runner) RunWithTriggers(ctx context.Context, queue *TriggerQueue, triggerJob TriggerJob) error {
	if r == nil || r.job == nil {
		return ErrJobRequired
	}
	if queue == nil {
		return ErrTriggerQueueRequired
	}
	if triggerJob == nil {
		return ErrTriggerJobRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	triggerDone := make(chan error, 1)
	go func() {
		triggerDone <- queue.Run(runCtx, func(triggerCtx context.Context, trigger Trigger) error {
			for {
				ran, err := r.runOnceJob(triggerCtx, func(jobCtx context.Context) error {
					return triggerJob(jobCtx, trigger)
				})
				if ran || !errors.Is(err, ErrAlreadyRunning) {
					return err
				}
				timer := time.NewTimer(triggerRetryInterval)
				select {
				case <-triggerCtx.Done():
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return triggerCtx.Err()
				case <-timer.C:
				}
			}
		})
	}()
	periodicErr := r.Run(runCtx)
	cancel()
	<-triggerDone
	return periodicErr
}

// runOnceJob applies the Runner's overlap guard to an arbitrary job while
// retaining the existing RunOnce behavior for the configured periodic job.
func (r *Runner) runOnceJob(ctx context.Context, job Job) (bool, error) {
	if r == nil || job == nil {
		return false, ErrJobRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !r.running.CompareAndSwap(false, true) {
		return false, ErrAlreadyRunning
	}
	defer r.running.Store(false)
	return true, job(ctx)
}

// PlanForTrigger narrows a base scan to the changed namespace and affected
// analyzer resources. Names are intentionally removed because affected
// analyzers commonly inspect related objects (for example Pod -> Event and
// Workload); applying one object name to those dependency lists would hide
// valid findings. A false result means the base scope excludes the trigger.
func PlanForTrigger(base scanplan.Plan, trigger Trigger) (scanplan.Plan, bool) {
	trigger = trigger.normalized()
	if trigger.Resource == "" {
		return scanplan.Plan{}, false
	}
	resource := trigger.Resource
	namespace := trigger.Namespace
	if trigger.TargetResource != "" {
		resource = trigger.TargetResource
		if trigger.TargetNamespace != "" {
			namespace = trigger.TargetNamespace
		}
	}
	if namespace != "" && !base.IncludesNamespace(namespace) {
		return scanplan.Plan{}, false
	}
	if len(base.Kinds) > 0 && !triggerKindAllowed(base.Kinds, resource) && !triggerKindAllowed(base.Kinds, trigger.Resource) {
		return scanplan.Plan{}, false
	}
	if len(base.Names) > 0 && !triggerNameAllowed(base, trigger) {
		return scanplan.Plan{}, false
	}

	kinds := []string{resource}
	if strings.EqualFold(trigger.Resource, "Event") || strings.EqualFold(resource, "Pod") {
		kinds = append(kinds, "Event")
	}
	if len(base.Kinds) > 0 {
		filtered := kinds[:0]
		for _, kind := range kinds {
			if triggerKindAllowed(base.Kinds, kind) {
				filtered = append(filtered, kind)
			}
		}
		kinds = filtered
	}
	if len(kinds) == 0 {
		return scanplan.Plan{}, false
	}
	result := base
	result.Kinds = uniqueCaseInsensitive(kinds)
	result.Names = nil
	if namespace != "" && len(base.IncludeNamespaces) == 0 {
		result.IncludeNamespaces = []string{namespace}
	}
	return result, true
}

func triggerNameAllowed(base scanplan.Plan, trigger Trigger) bool {
	if len(base.Names) == 0 {
		return true
	}
	if containsTriggerName(base.Names, trigger.Name) {
		return true
	}
	return strings.EqualFold(trigger.Resource, "Event") && containsTriggerName(base.Names, trigger.TargetName)
}

func containsTriggerName(names []string, wanted string) bool {
	for _, name := range names {
		if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(wanted)) {
			return true
		}
	}
	return false
}

func triggerKindAllowed(kinds []string, wanted string) bool {
	for _, kind := range kinds {
		if strings.EqualFold(strings.TrimSpace(kind), wanted) {
			return true
		}
	}
	switch strings.ToLower(strings.TrimSpace(wanted)) {
	case "deployment", "statefulset", "daemonset", "replicaset", "job", "cronjob":
		for _, kind := range kinds {
			if strings.EqualFold(strings.TrimSpace(kind), "workload") {
				return true
			}
		}
	case "persistentvolume", "persistentvolumeclaim", "storageclass":
		for _, kind := range kinds {
			if strings.EqualFold(strings.TrimSpace(kind), "storage") {
				return true
			}
		}
	}
	return false
}

func uniqueCaseInsensitive(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, strings.TrimSpace(value))
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i]) < strings.ToLower(result[j]) })
	return result
}
