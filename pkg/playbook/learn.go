package playbook

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/kubebee-com/sre/pkg/remediation"
)

// ObserveOutcome uses durable run lineage and the engine's verified execution
// record. Models can describe a candidate but cannot assert execution success.
func (s *Service) ObserveOutcome(ctx context.Context, proposal *remediation.Proposal) error {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	v := s.Settings()
	if v.LearningMode == LearningDisabled {
		s.outcome("learn", "disabled")
		return nil
	}
	if proposal == nil || proposal.Diagnosis == nil {
		return nil
	}
	if proposal.Status != remediation.StatusCompleted && proposal.Status != remediation.StatusFailed && proposal.Status != remediation.StatusStale {
		return nil
	}
	if !strings.HasPrefix(proposal.Diagnosis.ProposedCommand, "# playbook:") {
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
	original, err := s.catalog.GetPlaybook(ctx, run.PlaybookID, run.PlaybookVersion)
	if err != nil {
		return err
	}
	record := ResolutionOutcomeRecord{RunID: run.ID, ProposalID: p.ID, Status: string(p.Status), Verification: string(p.VerificationStatus), Message: p.ExecutionResult}
	if p.ExecutionError != "" {
		record.Message = p.ExecutionError
	}
	if err = s.catalog.RecordResolutionOutcome(ctx, record); err != nil {
		return err
	}
	if p.Status != remediation.StatusCompleted {
		s.outcome("learn", "failed")
		return nil
	}
	if p.VerificationStatus != remediation.VerificationStatusVerified || p.ExecutionError != "" || p.VerificationError != "" || strings.TrimSpace(p.ExecutionResult) == "" {
		s.outcome("learn", "unverified")
		return nil
	}
	s.outcome("learn", "verified")
	if v.LearningMode == LearningObserveOnly {
		return nil
	}
	if err = s.available(v); err != nil {
		return err
	}
	key := "learn-" + SourceChecksum(run.ID+":"+p.ID+":VERIFIED_SUCCESS")
	if candidate, e := s.catalog.GetLearningCandidate(ctx, key); e == nil {
		if candidate.SourceRunID != run.ID {
			return ErrCatalogConflict
		}
		return nil
	} else if !errors.Is(e, ErrCatalogNotFound) {
		return e
	}
	after := EvidenceRef{ID: "outcome-" + SourceChecksum(key+":"+p.ExecutionResult), Kind: p.Kind, Namespace: p.Namespace, Name: p.Name, UID: p.TargetUID, Summary: p.ExecutionResult}
	after.Hash, _ = CanonicalHash(after)
	var digest PlaybookDigest
	if err = s.run(ctx, "learn", map[string]any{"original_playbook": original, "resolution": run, "executed_steps": run.Steps, "verified_outcome": record, "after_evidence": []EvidenceRef{after}, "output_example": digestOutputExample()}, &digest, v); err != nil {
		return err
	}
	if len(original.SourceIDs) == 0 {
		return ErrServiceGuardrail
	}
	digest, err = s.prepareDigest(digest, key, original.SourceIDs[0], "learn", v)
	if err != nil {
		return err
	}
	digest.Lineage = []string{original.ID, run.ID}
	normalized, err := NormalizeDigest(digest)
	if err != nil {
		return ErrServiceInvalid
	}
	s.finishNormalized(&normalized)
	// Candidates retain the executed typed action and exact target. A learned
	// action change is not supported: it would not be backed by this outcome.
	if len(normalized.Steps) != len(run.Steps) {
		return ErrServiceGuardrail
	}
	for i, step := range normalized.Steps {
		actual := run.Steps[i]
		if step.Action != actual.Action || !reflect.DeepEqual(step.TargetReplicas, actual.TargetReplicas) || !reflect.DeepEqual(step.Targets, actual.Targets) {
			return ErrServiceGuardrail
		}
	}
	current := s.Settings()
	if !current.Enabled || current.LearningMode != LearningAutoDraft {
		return nil
	}
	if !s.guardrails(current, normalized).Allowed {
		s.outcome("learn", "guardrail_rejected")
		return ErrServiceGuardrail
	}
	candidate := LearningCandidate{ID: key, SourceRunID: run.ID, Outcome: LearningOutcomeVerifiedSuccess, Playbook: normalized, BeforeEvidence: run.Evidence, AfterEvidence: []EvidenceRef{after}, ExecutedSteps: run.Steps, Model: s.provider, Task: "playbook.learn", IdempotencyKey: key}
	err = s.catalog.RecordLearningCandidate(ctx, candidate)
	if errors.Is(err, ErrCatalogConflict) {
		existing, e := s.catalog.GetLearningCandidate(ctx, key)
		if e == nil && existing.SourceRunID == run.ID && existing.Outcome == LearningOutcomeVerifiedSuccess {
			return nil
		}
	}
	if err != nil {
		return err
	}
	s.outcome("learn", "draft")
	return nil
}
func proposalMatchesRun(p remediation.Proposal, r ResolutionPlan) bool {
	if p.Diagnosis == nil || len(r.Steps) != 1 || p.IssueID != r.FindingID || p.Diagnosis.IssueID != r.FindingID || p.Namespace != r.Target.Namespace || p.Kind != r.Target.Kind || p.Name != r.Target.Name || p.TargetUID != r.TargetUID || p.TargetResourceVersion != r.ResourceVersion || string(p.Diagnosis.ActionType) != r.Steps[0].Action || !reflect.DeepEqual(p.Diagnosis.TargetReplicas, r.Steps[0].TargetReplicas) {
		return false
	}
	a := r.Steps[0].Action
	return a != "Manual" && a != "GitOpsPR" && knownActions[a] != ""
}

var _ remediation.OutcomeObserver = (*Service)(nil)
