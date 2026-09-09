package remediation

import (
	"context"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

func TestTerminalObserverAuditsAllDurableFinalStates(t *testing.T) {
	for _, status := range []ProposalStatus{StatusCompleted, StatusFailed, StatusStale, StatusRejected, StatusExpired} {
		t.Run(string(status), func(t *testing.T) {
			calls := make(chan *Proposal, 2)
			e := NewEngineWithVerificationOptions(nil, EngineOptions{}, EngineVerificationOptions{TerminalObserver: outcomeObserverFunc(func(ctx context.Context, p *Proposal) error {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("missing deadline")
				}
				calls <- p
				return nil
			})})
			defer e.Close()
			p := mustCreateVerificationProposal(t, e, &scanner.Issue{ID: "audit", Namespace: "default", Kind: "Pod", Name: "app"}, &triage.Diagnosis{ActionType: triage.ActionManual, ProposedCommand: "# inspect pod"})
			if p == nil {
				t.Fatal("no proposal")
			}
			from := StatusPending
			if status == StatusCompleted || status == StatusFailed {
				if _, err := e.transition(p.ID, StatusPending, StatusApproved, nil, AuditEvent{}); err != nil {
					t.Fatal(err)
				}
				if _, err := e.transition(p.ID, StatusApproved, StatusExecuting, nil, AuditEvent{}); err != nil {
					t.Fatal(err)
				}
				from = StatusExecuting
			}
			if _, err := e.transition(p.ID, from, status, nil, AuditEvent{}); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-calls:
				if got.Status != status {
					t.Fatalf("status=%s", got.Status)
				}
				durable, err := e.store.Get(got.ID)
				if err != nil || durable.Status != status {
					t.Fatal("observer preceded durable transition")
				}
			case <-time.After(time.Second):
				t.Fatal("terminal observer not called")
			}
			if _, err := e.transition(p.ID, from, status, nil, AuditEvent{}); err == nil {
				t.Fatal("duplicate transition accepted")
			}
			select {
			case <-calls:
				t.Fatal("failed transition emitted event")
			case <-time.After(10 * time.Millisecond):
			}
		})
	}
}

func TestTerminalAuditAdmissionBoundedAfterTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{}, 10)
	e := NewEngineWithVerificationOptions(nil, EngineOptions{}, EngineVerificationOptions{OutcomeObserverTimeout: time.Millisecond, TerminalObserver: outcomeObserverFunc(func(context.Context, *Proposal) error { entered <- struct{}{}; <-release; return nil })})
	for i := 0; i < 4; i++ {
		e.scheduleTerminal(&Proposal{Status: StatusFailed})
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("observer did not start")
		}
	}
	time.Sleep(5 * time.Millisecond)
	for i := 0; i < 100; i++ {
		e.scheduleTerminal(&Proposal{Status: StatusFailed})
	}
	select {
	case <-entered:
		t.Fatal("timed-out observers escaped admission bound")
	default:
	}
	closed := make(chan struct{})
	go func() { _ = e.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("audit observer blocked shutdown")
	}
}
