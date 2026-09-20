package remediation

import (
	"context"
	"sync"
	"testing"
	"time"
)

type startupSnapshotStore struct {
	ProposalStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *startupSnapshotStore) List() ([]*Proposal, error) {
	s.once.Do(func() { close(s.entered); <-s.release })
	return s.ProposalStore.List()
}

func TestStartupRecoveryCapturesStateBeforeAcceptingNewWork(t *testing.T) {
	store := &startupSnapshotStore{ProposalStore: NewMemoryProposalStore(), entered: make(chan struct{}), release: make(chan struct{})}
	constructed := make(chan *Engine, 1)
	go func() {
		constructed <- NewEngineWithOptions(nil, EngineOptions{Store: store,
			Executor: executorFunc(func(context.Context, *Proposal) (string, error) { return "done", nil })})
	}()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		close(store.release)
		t.Fatal("recovery snapshot was not requested")
	}
	select {
	case engine := <-constructed:
		close(store.release)
		_ = engine.Close()
		t.Fatal("engine accepted new work before capturing startup recovery state")
	case <-time.After(50 * time.Millisecond):
	}
	close(store.release)
	select {
	case engine := <-constructed:
		_ = engine.Close()
	case <-time.After(time.Second):
		t.Fatal("constructor did not complete after snapshot")
	}
}
