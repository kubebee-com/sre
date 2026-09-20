package remediation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRetentionCanceledWorkerDoesNotPrune(t *testing.T) {
	s := &FileProposalStore{dir: t.TempDir(), state: newProposalState()}
	s.path = s.dir + "/proposals.json"
	s.state.Proposals = []*Proposal{{ID: "old", Status: StatusCompleted, UpdatedAt: time.Now().Add(-8 * 24 * time.Hour)}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.RunRetention(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation: %v", err)
	}
	if len(s.state.Proposals) != 1 {
		t.Fatal("canceled worker still mutated the store")
	}
}

func TestRetentionPersistenceFailureDoesNotDiscardInMemoryState(t *testing.T) {
	s := &FileProposalStore{dir: t.TempDir(), state: newProposalState()}
	s.path = s.dir + "/missing/proposals.json"
	s.state.Proposals = []*Proposal{{ID: "old", Status: StatusCompleted, UpdatedAt: time.Now().Add(-8 * 24 * time.Hour)}}
	if _, err := s.PruneRetention(time.Now()); err == nil {
		t.Fatal("persistence error was hidden")
	}
	if len(s.state.Proposals) != 1 {
		t.Fatal("failed persistence discarded in-memory state")
	}
}

func TestRetentionCountBudgetNeverCountsActiveRows(t *testing.T) {
	state := newProposalState()
	now := time.Now().UTC()
	state.Proposals = append(state.Proposals, &Proposal{ID: "active", Status: StatusExecuting, UpdatedAt: now.Add(-30 * 24 * time.Hour)})
	for i := 0; i < maxInactiveProposals+1; i++ {
		state.Proposals = append(state.Proposals, &Proposal{ID: fmt.Sprintf("done-%05d", i), Status: StatusCompleted, UpdatedAt: now.Add(-time.Hour)})
	}
	result, removed, err := retentionState(state, now)
	if err != nil || removed != 1 || len(result.Proposals) != maxInactiveProposals+1 {
		t.Fatalf("budget result removed=%d err=%v", removed, err)
	}
	if result.Proposals[0].ID != "active" || len(state.Proposals) != maxInactiveProposals+2 {
		t.Fatal("active row or input state was altered")
	}
}

func TestRetentionNeverTruncatesActiveProposals(t *testing.T) {
	s := &FileProposalStore{dir: t.TempDir(), state: newProposalState()}
	s.path = s.dir + "/proposals.json"
	for i := 0; i < 650; i++ {
		s.state.Proposals = append(s.state.Proposals, &Proposal{ID: fmt.Sprintf("pending-%d", i), Status: StatusPending, UpdatedAt: time.Now().Add(-30 * 24 * time.Hour)})
	}
	s.pruneOldProposalsLocked()
	if len(s.state.Proposals) != 650 {
		t.Fatalf("lost active approvals: retained %d of 650", len(s.state.Proposals))
	}
}

func TestRetentionExpiresSmallStoresAndKeepsSevenDayWindow(t *testing.T) {
	s := &FileProposalStore{dir: t.TempDir(), state: newProposalState()}
	s.path = s.dir + "/proposals.json"
	now := time.Now().UTC()
	s.state.Proposals = []*Proposal{
		{ID: "expired", Status: StatusCompleted, UpdatedAt: now.Add(-8 * 24 * time.Hour)},
		{ID: "recent", Status: StatusCompleted, UpdatedAt: now.Add(-2 * 24 * time.Hour)},
		{ID: "pending", Status: StatusPending, UpdatedAt: now.Add(-30 * 24 * time.Hour)},
		{ID: "unknown", Status: ProposalStatus("FUTURE_ACTIVE"), UpdatedAt: now.Add(-30 * 24 * time.Hour)},
	}
	s.pruneOldProposalsLocked()
	have := map[string]bool{}
	for _, p := range s.state.Proposals {
		have[p.ID] = true
	}
	if have["expired"] || !have["recent"] || !have["pending"] || !have["unknown"] {
		t.Fatalf("unsafe TTL selection: %v", have)
	}
}

func TestRetentionDoesNotDeleteIndependentAuditRecords(t *testing.T) {
	s := &FileProposalStore{dir: t.TempDir(), state: newProposalState()}
	s.path = s.dir + "/proposals.json"
	for i := 0; i < 201; i++ {
		id := fmt.Sprintf("done-%d", i)
		s.state.Proposals = append(s.state.Proposals, &Proposal{ID: id, Status: StatusCompleted, UpdatedAt: time.Now().Add(-8 * 24 * time.Hour)})
		s.state.Audit = append(s.state.Audit, AuditEvent{ID: id, ProposalID: id, Actor: "operator", At: time.Now().Add(-8 * 24 * time.Hour)})
	}
	s.pruneOldProposalsLocked()
	if len(s.state.Audit) != 201 {
		t.Fatal("operational history TTL must not silently shorten security audit retention")
	}
}
