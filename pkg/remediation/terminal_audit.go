package remediation

import (
	"context"
	"errors"
	"log"
)

// transition emits an audit only after the final state is durable. A failed
// compare-and-swap never notifies, so concurrent approvals cannot duplicate it.
func (e *Engine) transition(id string, from, to ProposalStatus, mutate func(*Proposal) error, event AuditEvent) (*Proposal, error) {
	p, err := e.store.Transition(id, from, to, mutate, event)
	if err != nil && !errors.Is(err, ErrInvalidTransition) {
		e.persistenceErrors.Add(1)
		log.Printf("Remediation state persistence failed; reconciliation required")
	}
	if err == nil && e.terminalObserver != nil {
		switch to {
		case StatusCompleted, StatusFailed, StatusStale, StatusRejected, StatusExpired:
			e.scheduleTerminal(p)
		}
	}
	return p, err
}

func (e *Engine) scheduleTerminal(p *Proposal) {
	select {
	case e.terminalSlots <- struct{}{}:
	default:
		return
	}
	snapshot := cloneProposal(p)
	go func() {
		defer func() { <-e.terminalSlots }()
		defer func() { _ = recover() }()
		ctx, cancel := context.WithTimeout(context.Background(), e.outcomeObserverTimeout)
		defer cancel()
		_ = e.terminalObserver.ObserveOutcome(ctx, snapshot)
	}()
}
