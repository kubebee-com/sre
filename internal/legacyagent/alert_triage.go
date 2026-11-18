package legacyagent

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/notifier"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

// Pre-alert triage diagnoses the serious findings of a scan, the ones that
// qualify for an alert, before their alerts are dispatched, so that an alert
// reaches its reader with an analysis and a recommended action rather than a
// bare symptom. These are also the only findings the configured provider is
// asked about; see routineProvider.
//
// It is bounded and it fails open. Alert dispatch waits at most
// preAlertLimits.wait for diagnoses, and an alert whose diagnosis is late or
// failed is sent as it is. A late diagnosis is not cancelled: it runs on while
// the scan continues, the proposal loop takes its result, and the provider's
// memory of it (triage.MemoizedProvider) annotates the alert on the next scan
// at no further cost. The provider is not asked later than
// preAlertLimits.budget into a scan, so a slow provider cannot hold a scan,
// and with it the agent's readiness, for longer than that and one more call.
// What is left over is diagnosed by the scans that follow.
//
// A diagnosis only ever adds annotations. Whether an alert is sent, and at
// what severity, stays with the scanner, because provider output derives from
// untrusted cluster data and must not be able to silence an alert.

type preAlertOptions struct {
	// wait is how long alert dispatch is held back for diagnoses.
	wait time.Duration
	// budget is how far into a scan the provider may still be asked.
	budget time.Duration
	// concurrency is the number of diagnoses that may be in flight.
	concurrency int
}

// The wait leaves room for one round of a reasoning model's diagnoses, which
// take about fifteen seconds each, to reach the first dispatch of an alert.
// The budget keeps a scan's triage well inside the default scan interval.
var preAlertLimits = preAlertOptions{wait: 20 * time.Second, budget: 90 * time.Second, concurrency: 3}

// errDiagnosisDeferred marks a finding whose diagnosis did not fit the scan.
var errDiagnosisDeferred = errors.New("diagnosis deferred to a later scan")

// alertDiagnosis is the diagnosis of one serious finding. Its diagnosis and
// err are final once done is closed.
type alertDiagnosis struct {
	issue     *scanner.Issue
	done      chan struct{}
	diagnosis *triage.Diagnosis
	err       error
}

// diagnosisMemory is a provider's memory of the diagnoses it need not be
// asked for again. triage.MemoizedProvider has one.
type diagnosisMemory interface {
	Remembered(*scanner.Issue) (*triage.Diagnosis, bool)
}

// alertTriage is the pre-alert triage of one scan: the diagnosis of every
// serious finding of the scan.
type alertTriage struct {
	candidates map[*scanner.Issue]*alertDiagnosis
	workers    sync.WaitGroup
}

// startAlertTriage begins diagnosing the serious findings of a scan: those
// that the alert policy of alertmanager lets through, whether or not an
// Alertmanager is configured to receive them. It returns at once; settle
// waits for the diagnoses.
func startAlertTriage(ctx context.Context, cfg *config.Config, alertmanager *notifier.AlertmanagerNotifier, provider triage.TriageProvider, folded []*scanner.Issue) *alertTriage {
	run := &alertTriage{candidates: make(map[*scanner.Issue]*alertDiagnosis)}
	// A disabled provider has no analysis to give; asking it only logs errors.
	if provider.Name() == triage.NoOpProviderName {
		return run
	}
	memory, _ := provider.(diagnosisMemory)
	queue := make(chan *alertDiagnosis, len(folded))
	for _, issue := range folded {
		if !alertmanager.IsAlertableIssue(issue) {
			continue
		}
		candidate := &alertDiagnosis{issue: issue, done: make(chan struct{})}
		run.candidates[issue] = candidate
		// What the provider remembers is in at once and costs no budget.
		if memory != nil {
			if diagnosis, ok := memory.Remembered(providerIssue(cfg, issue)); ok {
				candidate.diagnosis = diagnosis
				close(candidate.done)
				continue
			}
		}
		queue <- candidate
	}
	close(queue)
	askBy := time.Now().Add(preAlertLimits.budget)
	for range min(preAlertLimits.concurrency, len(queue)) {
		run.workers.Add(1)
		go func() {
			defer run.workers.Done()
			for candidate := range queue {
				candidate.ask(ctx, cfg, provider, askBy)
			}
		}()
	}
	return run
}

func (d *alertDiagnosis) ask(ctx context.Context, cfg *config.Config, provider triage.TriageProvider, askBy time.Time) {
	defer close(d.done)
	switch {
	case ctx.Err() != nil:
		// A scan that is over asks for nothing more.
		d.err = ctx.Err()
	case time.Now().After(askBy):
		d.err = errDiagnosisDeferred
	default:
		d.diagnosis, d.err = provider.Diagnose(ctx, providerIssue(cfg, d.issue))
		if d.err != nil {
			log.Printf("Pre-alert triage failed for issue %s: %s", sanitizeLog(cfg, d.issue.ID), sanitizeLog(cfg, d.err.Error()))
		}
	}
}

// finished reports whether the diagnosis is final, without waiting for it.
func (d *alertDiagnosis) finished() bool {
	select {
	case <-d.done:
		return true
	default:
		return false
	}
}

// settle holds alert dispatch until every diagnosis is in, the wait runs out,
// or the scan is cancelled. Diagnoses still in flight run on.
func (t *alertTriage) settle(ctx context.Context) {
	timer := time.NewTimer(preAlertLimits.wait)
	defer timer.Stop()
waiting:
	for _, candidate := range t.candidates {
		select {
		case <-candidate.done:
		case <-timer.C:
			break waiting
		case <-ctx.Done():
			break waiting
		}
	}
	late := 0
	for _, candidate := range t.candidates {
		if !candidate.finished() {
			late++
		}
	}
	if late > 0 {
		log.Printf("Pre-alert triage: %d of %d alert diagnoses were not ready at dispatch; those alerts go out without analysis until the next scan.", late, len(t.candidates))
	}
}

// diagnoses returns, by finding, the diagnoses that are in.
func (t *alertTriage) diagnoses() map[*scanner.Issue]*triage.Diagnosis {
	ready := make(map[*scanner.Issue]*triage.Diagnosis, len(t.candidates))
	for issue, candidate := range t.candidates {
		if candidate.finished() && candidate.err == nil && candidate.diagnosis != nil {
			ready[issue] = candidate.diagnosis
		}
	}
	return ready
}

// result gives the diagnosis of a serious finding, waiting for it if it is
// still running; err says why there is none. It reports analyzed as false for
// any other finding, which is left to the routine provider.
func (t *alertTriage) result(ctx context.Context, issue *scanner.Issue) (diagnosis *triage.Diagnosis, analyzed bool, err error) {
	candidate := t.candidates[issue]
	if candidate == nil {
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
// returns, so that a slow diagnosis is remembered for the next scan.
func (t *alertTriage) wait() {
	t.workers.Wait()
	deferred := 0
	for _, candidate := range t.candidates {
		if errors.Is(candidate.err, errDiagnosisDeferred) {
			deferred++
		}
	}
	if deferred > 0 {
		log.Printf("Pre-alert triage: %d of %d diagnoses did not fit this scan and are left to the next.", deferred, len(t.candidates))
	}
}

// asksModel reports whether a provider costs time or quota to ask: every
// provider but the built-in rule engine and the disabled one.
func asksModel(provider triage.TriageProvider) bool {
	name := provider.Name()
	return name != triage.RuleBasedProviderName && name != triage.NoOpProviderName
}

// routineProvider is the provider for the findings that are not serious.
// Those are the many low-severity and posture findings, and a model is not
// asked about them: at seconds per call a scan would never finish them. They
// get the built-in rule engine. A provider that is itself the rule engine, or
// disabled, keeps them.
func routineProvider(cfg *config.Config, provider triage.TriageProvider) triage.TriageProvider {
	if !asksModel(provider) {
		return provider
	}
	return triage.NewRuleBasedProvider(providerSecretValues(cfg)...)
}

// providerIssue is the redacted copy of a finding that a provider may see.
func providerIssue(cfg *config.Config, issue *scanner.Issue) *scanner.Issue {
	return scanner.SanitizeIssue(issue, providerSecretValues(cfg)...).AsIssue()
}
