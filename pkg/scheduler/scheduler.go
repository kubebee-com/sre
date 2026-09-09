// Package scheduler provides bounded, cancellable periodic jobs with
// in-process overlap protection. KubernetesLease adds cross-replica
// coordination using client-go's maintained Lease implementation.
package scheduler

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

var (
	ErrJobRequired        = errors.New("scheduled job is required")
	ErrAlreadyRunning     = errors.New("scheduled job is already running")
	ErrLeaseConfiguration = errors.New("leader lease configuration is invalid")
)

type Job func(context.Context) error

type Options struct {
	Interval time.Duration
	Jitter   time.Duration
	Job      Job
	Random   *rand.Rand
}

type Runner struct {
	interval time.Duration
	jitter   time.Duration
	job      Job
	running  atomic.Bool
	random   *rand.Rand
}

func New(options Options) (*Runner, error) {
	if options.Job == nil {
		return nil, ErrJobRequired
	}
	if options.Interval <= 0 {
		return nil, ErrLeaseConfiguration
	}
	if options.Jitter < 0 || options.Jitter >= options.Interval {
		return nil, ErrLeaseConfiguration
	}
	return &Runner{interval: options.Interval, jitter: options.Jitter, job: options.Job, random: options.Random}, nil
}

// RunOnce executes one job if no prior invocation is still running. It
// returns false and ErrAlreadyRunning when overlap is prevented.
func (r *Runner) RunOnce(ctx context.Context) (bool, error) {
	if r == nil || r.job == nil {
		return false, ErrJobRequired
	}
	return r.runOnceJob(ctx, r.job)
}

func (r *Runner) Running() bool {
	return r != nil && r.running.Load()
}

// Run executes the job immediately, then waits interval plus bounded random
// jitter between later executions. Job errors are returned only for the
// initial execution; periodic errors do not terminate the scheduler.
func (r *Runner) Run(ctx context.Context) error {
	if r == nil || r.job == nil {
		return ErrJobRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := r.RunOnce(ctx); err != nil {
		return err
	}
	for {
		wait := r.interval + r.nextJitter()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
		_, _ = r.RunOnce(ctx)
	}
}

func (r *Runner) nextJitter() time.Duration {
	if r == nil || r.jitter <= 0 {
		return 0
	}
	if r.random != nil {
		return time.Duration(r.random.Int63n(int64(r.jitter) + 1))
	}
	return time.Duration(rand.Int63n(int64(r.jitter) + 1))
}

type LeaseOptions struct {
	Client        kubernetes.Interface
	Namespace     string
	Name          string
	Identity      string
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
}

type KubernetesLease struct {
	lock          resourcelock.Interface
	leaseDuration time.Duration
	renewDeadline time.Duration
	retryPeriod   time.Duration
}

func NewKubernetesLease(options LeaseOptions) (*KubernetesLease, error) {
	if options.Client == nil || strings.TrimSpace(options.Namespace) == "" || strings.TrimSpace(options.Name) == "" || strings.TrimSpace(options.Identity) == "" {
		return nil, ErrLeaseConfiguration
	}
	if options.LeaseDuration <= 0 {
		options.LeaseDuration = 30 * time.Second
	}
	if options.RenewDeadline <= 0 {
		options.RenewDeadline = 20 * time.Second
	}
	if options.RetryPeriod <= 0 {
		options.RetryPeriod = 5 * time.Second
	}
	if options.RenewDeadline >= options.LeaseDuration || options.RetryPeriod >= options.RenewDeadline {
		return nil, ErrLeaseConfiguration
	}
	lock, err := resourcelock.New(resourcelock.LeasesResourceLock, strings.TrimSpace(options.Namespace), strings.TrimSpace(options.Name), options.Client.CoreV1(), options.Client.CoordinationV1(), resourcelock.ResourceLockConfig{Identity: strings.TrimSpace(options.Identity)})
	if err != nil {
		return nil, ErrLeaseConfiguration
	}
	return &KubernetesLease{lock: lock, leaseDuration: options.LeaseDuration, renewDeadline: options.RenewDeadline, retryPeriod: options.RetryPeriod}, nil
}

// Run blocks while participating in leader election. The supplied function
// runs only for the current leader and receives the election cancellation
// context, so scans stop before ReleaseOnCancel releases the Lease.
func (l *KubernetesLease) Run(ctx context.Context, lead Job) error {
	if l == nil || l.lock == nil || lead == nil {
		return ErrLeaseConfiguration
	}
	if ctx == nil {
		ctx = context.Background()
	}
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            l.lock,
		LeaseDuration:   l.leaseDuration,
		RenewDeadline:   l.renewDeadline,
		RetryPeriod:     l.retryPeriod,
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leaderContext context.Context) { _ = lead(leaderContext) },
			OnStoppedLeading: func() {},
			OnNewLeader:      func(string) {},
		},
	})
	if err != nil {
		return ErrLeaseConfiguration
	}
	elector.Run(ctx)
	return ctx.Err()
}
