package remediation

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

type terminalFailureStore struct{ ProposalStore }

func (s terminalFailureStore) Transition(id string, from, to ProposalStatus, mutate func(*Proposal) error, event AuditEvent) (*Proposal, error) {
	if to == StatusCompleted {
		return nil, errors.New("simulated persistence unavailable")
	}
	return s.ProposalStore.Transition(id, from, to, mutate, event)
}
func TestTerminalPersistenceFailureIsVisibleWithoutActionReplay(t *testing.T) {
	store := NewMemoryProposalStore()
	p := testStoreProposal("persist-failure", "issue")
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	e := NewEngineWithOptions(nil, EngineOptions{Store: terminalFailureStore{store}, Executor: executorFunc(func(context.Context, *Proposal) (string, error) { return "applied", nil })})
	defer e.Close()
	var actions atomic.Uint64
	e.executor = executorFunc(func(context.Context, *Proposal) (string, error) { actions.Add(1); return "applied", nil })
	if _, err := store.Transition(p.ID, StatusPending, StatusApproved, nil, AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	e.executeProposal(p.ID)
	if e.PersistenceErrors() != 1 {
		t.Fatal("terminal persistence failure was not observable")
	}
	e.executeProposal(p.ID)
	if actions.Load() != 1 {
		t.Fatal("ambiguous completed action was replayed")
	}
	got, err := store.Get(p.ID)
	if err != nil || got.Status != StatusExecuting {
		t.Fatalf("must retain reconciliation state: %#v %v", got, err)
	}
}
