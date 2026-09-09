package playbook

import (
	"context"
	"github.com/kubebee-com/sre/pkg/remediation"
	"strings"
)

// RecordOutcome audits terminal playbook proposals independently of provider
// availability and learning mode. It never invokes a model or creates a draft.
func (s *Service) RecordOutcome(ctx context.Context, proposal *remediation.Proposal) error {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if proposal == nil || proposal.Diagnosis == nil || !strings.HasPrefix(proposal.Diagnosis.ProposedCommand, "# playbook:") {
		return nil
	}
	switch proposal.Status {
	case remediation.StatusCompleted, remediation.StatusFailed, remediation.StatusStale, remediation.StatusRejected, remediation.StatusExpired:
	default:
		return nil
	}
	if nilDependency(s.catalog) {
		return ErrServiceUnavailable
	}
	var p remediation.Proposal
	if err := s.clean(proposal, &p); err != nil {
		return err
	}
	run, err := s.resolutionForProposal(ctx, p.Diagnosis.ProposedCommand)
	if err != nil {
		return err
	}
	if !proposalMatchesRun(p, run) {
		return ErrServiceGuardrail
	}
	record := ResolutionOutcomeRecord{RunID: run.ID, ProposalID: p.ID, Status: string(p.Status), Verification: string(p.VerificationStatus), Message: p.ExecutionResult}
	if p.ExecutionError != "" {
		record.Message = p.ExecutionError
	}
	if err = s.catalog.RecordResolutionOutcome(ctx, record); err != nil {
		return err
	}
	outcome := "failed"
	if p.Status == remediation.StatusCompleted {
		outcome = "unverified"
		if p.VerificationStatus == remediation.VerificationStatusVerified {
			outcome = "verified"
		}
	}
	s.outcome("resolution", outcome)
	return nil
}
