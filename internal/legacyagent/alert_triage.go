package legacyagent

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/notifier"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

// Pre-alert triage diagnoses the findings that are about to become
// Alertmanager alerts, so that an alert reaches its reader with an analysis
// and a recommended action rather than a bare symptom.
//
// It is bounded and it fails open. Alert dispatch waits at most
// preAlertLimits.wait for diagnoses, and an alert whose diagnosis is late,
// failed, or never started is sent as it is. A diagnosis that was started is
// neither cancelled nor repeated: the proposal loop takes its result, and the
// notifier keeps it, so the next scan annotates the alert without asking the
// provider again.
//
// A diagnosis only ever adds annotations. Whether an alert is sent, and at
// what severity, stays with the scanner, because provider output derives from
// untrusted cluster data and must not be able to silence an alert.

type preAlertOptions struct {
	// wait is how long alert dispatch is held back for diagnoses. No
	// diagnosis is started after it has passed.
	wait time.Duration
	// concurrency is the number of diagnoses that may be in flight.
	concurrency int
}

var preAlertLimits = preAlertOptions{wait: 10 * time.Second, concurrency: 3}

// alertDiagnosis is the diagnosis of one alert candidate. Its diagnosis and
// err are final once done is closed.
type alertDiagnosis struct {
	issue *scanner.Issue
	// taken is set, under alertTriage.mu, when the diagnosis is cached or a
	// worker has taken it on.
	taken     bool
	done      chan struct{}
	diagnosis *triage.Diagnosis
	err       error
}

// alertTriage is the pre-alert triage of one scan.
type alertTriage struct {
	// candidates has every alert candidate of the scan. queue has, in alert
	// order, those whose diagnosis was not cached. Neither changes once the
	// workers have started.
	candidates map[*scanner.Issue]*alertDiagnosis
	queue      []*alertDiagnosis

	mu      sync.Mutex
	cursor  int  // queue[:cursor] has been taken
	closed  bool // nothing more may be taken
	workers sync.WaitGroup
}

// startAlertTriage begins diagnosing the findings of a scan that qualify for
// an alert and have no cached diagnosis. It returns at once; settle waits for
// the results.
func startAlertTriage(ctx context.Context, cfg *config.Config, alertmanager *notifier.AlertmanagerNotifier, provider triage.TriageProvider, folded []*scanner.Issue) *alertTriage {
	run := &alertTriage{candidates: make(map[*scanner.Issue]*alertDiagnosis)}
	// A disabled provider has no analysis to give; asking it only logs errors.
	if provider.Name() == triage.NewNoOpProvider().Name() {
		return run
	}
	for _, issue := range alertmanager.EligibleIssues(folded) {
		candidate := &alertDiagnosis{issue: issue, done: make(chan struct{})}
		run.candidates[issue] = candidate
		if diagnosis, cached := alertmanager.CachedDiagnosis(issue); cached {
			candidate.taken, candidate.diagnosis = true, diagnosis
			close(candidate.done)
			continue
		}
		run.queue = append(run.queue, candidate)
	}
	for worker := 0; worker < min(preAlertLimits.concurrency, len(run.queue)); worker++ {
		run.workers.Add(1)
		go run.diagnose(ctx, cfg, alertmanager, provider)
	}
	return run
}

// diagnose works through the queue until it is empty or closed.
func (t *alertTriage) diagnose(ctx context.Context, cfg *config.Config, alertmanager *notifier.AlertmanagerNotifier, provider triage.TriageProvider) {
	defer t.workers.Done()
	for candidate := t.take(); candidate != nil; candidate = t.take() {
		candidate.diagnosis, candidate.err = provider.Diagnose(ctx, providerIssue(cfg, candidate.issue))
		if candidate.err != nil {
			log.Printf("Pre-alert triage failed for issue %s: %s", sanitizeLog(cfg, candidate.issue.ID), sanitizeLog(cfg, candidate.err.Error()))
		} else {
			alertmanager.RecordDiagnosis(candidate.issue, candidate.diagnosis)
		}
		close(candidate.done)
	}
}

func (t *alertTriage) take() *alertDiagnosis {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.cursor == len(t.queue) {
		return nil
	}
	candidate := t.queue[t.cursor]
	candidate.taken = true
	t.cursor++
	return candidate
}

// settle holds alert dispatch until every queued diagnosis is in, the wait
// runs out, or the scan is cancelled, and then closes the queue. A diagnosis
// in flight runs on; one that has not started is left to the proposal loop.
func (t *alertTriage) settle(ctx context.Context) {
	timer := time.NewTimer(preAlertLimits.wait)
	defer timer.Stop()
	for _, candidate := range t.queue {
		select {
		case <-candidate.done:
			continue
		case <-timer.C:
		case <-ctx.Done():
		}
		break
	}
	t.mu.Lock()
	t.closed = true
	taken := t.queue[:t.cursor]
	t.mu.Unlock()
	if len(t.queue) == 0 {
		return
	}
	finished := 0
	for _, candidate := range taken {
		select {
		case <-candidate.done:
			finished++
		default:
		}
	}
	log.Printf("Pre-alert triage: %d of %d new alert diagnoses finished before dispatch, %d still running, %d not started.",
		finished, len(t.queue), len(taken)-finished, len(t.queue)-len(taken))
}

// result gives the diagnosis that pre-alert triage has, or has under way, for
// a finding, waiting for one that is still running. It reports analyzed as
// false for a finding that triage did not take on, which the caller must then
// diagnose itself. It is meaningful only after settle.
func (t *alertTriage) result(ctx context.Context, issue *scanner.Issue) (diagnosis *triage.Diagnosis, analyzed bool, err error) {
	candidate := t.candidates[issue]
	if candidate == nil {
		return nil, false, nil
	}
	t.mu.Lock()
	taken := candidate.taken
	t.mu.Unlock()
	if !taken {
		return nil, false, nil
	}
	select {
	case <-candidate.done:
		return candidate.diagnosis, true, candidate.err
	case <-ctx.Done():
		return nil, true, ctx.Err()
	}
}

// wait returns once no diagnosis is in flight. A scan waits for it before it
// returns, so that a slow diagnosis still reaches the notifier for the next
// scan.
func (t *alertTriage) wait() {
	t.workers.Wait()
}

// providerIssue is the redacted copy of a finding that a provider may see.
func providerIssue(cfg *config.Config, issue *scanner.Issue) *scanner.Issue {
	return scanner.SanitizeIssue(issue, providerSecretValues(cfg)...).AsIssue()
}
