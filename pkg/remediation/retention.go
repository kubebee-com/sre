package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const completedProposalTTL = 7 * 24 * time.Hour
const maxInactiveProposals = 10000
const maxInactiveProposalBytes = 128 << 20

// Only known terminal states are disposable. Unknown future states fail closed.
func terminalProposal(status ProposalStatus) bool {
	switch status {
	case StatusCompleted, StatusRejected, StatusFailed, StatusStale, StatusExpired:
		return true
	default:
		return false
	}
}

// retentionState never mutates the input or its audit trail. Byte/count budgets
// cover inactive proposal payloads, not active approvals or security audit data.
func retentionState(state proposalState, now time.Time) (proposalState, int, error) {
	type candidate struct {
		proposal *Proposal
		size     int
	}
	inactive := make([]candidate, 0)
	drop := make(map[string]bool)
	bytes := 0
	for _, p := range state.Proposals {
		if !terminalProposal(p.Status) || p.UpdatedAt.IsZero() || p.UpdatedAt.After(now) {
			continue
		}
		if now.Sub(p.UpdatedAt) >= completedProposalTTL {
			drop[p.ID] = true
			continue
		}
		data, err := json.MarshalIndent(p, "    ", "  ")
		if err != nil {
			return state, 0, fmt.Errorf("measure inactive proposal: %w", err)
		}
		size := len(data) + 8
		inactive = append(inactive, candidate{p, size})
		bytes += size
	}
	sort.Slice(inactive, func(i, j int) bool {
		a, b := inactive[i].proposal, inactive[j].proposal
		if a.UpdatedAt.Equal(b.UpdatedAt) {
			return a.ID < b.ID
		}
		return a.UpdatedAt.Before(b.UpdatedAt)
	})
	remaining := len(inactive)
	for _, item := range inactive {
		if remaining <= maxInactiveProposals && bytes <= maxInactiveProposalBytes {
			break
		}
		drop[item.proposal.ID] = true
		remaining--
		bytes -= item.size
	}
	if len(drop) == 0 {
		return state, 0, nil
	}
	result := state
	result.Proposals = make([]*Proposal, 0, len(state.Proposals)-len(drop))
	for _, p := range state.Proposals {
		if !drop[p.ID] {
			result.Proposals = append(result.Proposals, p)
		}
	}
	// Audit is intentionally unchanged. An audit-retention policy must be separate.
	return result, len(drop), nil
}

func (s *FileProposalStore) pruneOldProposalsLocked() error {
	state, count, err := retentionState(s.state, time.Now().UTC())
	if err != nil || count == 0 {
		return err
	}
	if err := s.writeStateLocked(state); err != nil {
		return err
	}
	s.state = state
	return nil
}

// PruneRetention performs an atomic sweep even when no new proposals are written.
func (s *FileProposalStore) PruneRetention(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrStoreClosed
	}
	state, count, err := retentionState(s.state, now)
	if err != nil || count == 0 {
		return count, err
	}
	if err := s.writeStateLocked(state); err != nil {
		return 0, err
	}
	s.state = state
	return count, nil
}

// RunRetention belongs to the application's lifecycle. The caller starts it with
// a cancellation context and must observe errors; no constructor leaks a worker.
func (s *FileProposalStore) RunRetention(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("retention interval must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := s.PruneRetention(time.Now().UTC()); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
