package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

// Resolve supports one fully grounded typed action. Multiple steps fail closed
// because remediation proposals are deduplicated by finding and carry one action.
func (s *Service) Resolve(ctx context.Context, issue *scanner.Issue, actor string) (ResolveResult, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	out := ResolveResult{}
	v := s.Settings()
	if err := s.available(v); err != nil {
		return out, err
	}
	if issue == nil || !validActor(actor) {
		return out, ErrServiceInvalid
	}
	var finding scanner.Issue
	if err := s.clean(issue, &finding); err != nil {
		return out, err
	}
	b, _ := json.Marshal(finding)
	if len(b) > v.MaxTotalTextBytes || requireIdentifier("finding", finding.ID) != nil || finding.TargetUID == "" || finding.TargetResourceVersion == "" {
		return out, ErrServiceInvalid
	}
	q := MatchQuery{FindingID: finding.ID, FailureCategory: string(finding.Category), Namespace: finding.Namespace, Kind: finding.Kind, Name: finding.Name, MinConfidence: v.MinConfidence, Limit: MaxCollectionItems}
	active, err := s.catalog.ListActive(ctx, q)
	if err != nil {
		return out, err
	}
	var selected *NormalizedPlaybook
	for _, p := range active {
		if exactBinding(p, q) && s.guardrails(v, p).Allowed {
			p := p
			selected = &p
			break
		}
	}
	if selected == nil {
		return out, nil
	}
	out.Matched = true
	// Observation timestamps are excluded: evidence identity represents content and
	// Kubernetes identity, not the time the same content was scanned again.
	snapshot := finding
	snapshot.FirstObserved = time.Time{}
	snapshot.LastObserved = time.Time{}
	b, _ = json.Marshal(snapshot)
	if len(b) > MaxTextBytes {
		return out, ErrServiceInvalid
	}
	evidence := EvidenceRef{ID: "evidence-" + SourceChecksum(string(b)), Kind: finding.Kind, Namespace: finding.Namespace, Name: finding.Name, UID: finding.TargetUID, ResourceVersion: finding.TargetResourceVersion, Summary: string(b)}
	if err = s.clean(evidence, &evidence); err != nil {
		return out, err
	}
	evidence.Hash, _ = CanonicalHash(evidence)
	if evidence.Validate() != nil {
		return out, ErrServiceInvalid
	}
	if err = s.catalog.RecordFinding(ctx, FindingRecord{ID: finding.ID, Query: q, Evidence: []EvidenceRef{evidence}, Summary: finding.Summary}); err != nil {
		return out, err
	}
	if err = s.catalog.RecordEvidence(ctx, evidence); err != nil {
		return out, err
	}
	example := ResolutionPlan{ID: "service-assigned", FindingID: finding.ID, PlaybookID: selected.ID, PlaybookVersion: selected.Version, Target: ResourceSelector{Namespace: finding.Namespace, Kind: finding.Kind, Name: finding.Name}, TargetUID: finding.TargetUID, ResourceVersion: finding.TargetResourceVersion, Evidence: []EvidenceRef{evidence}, Steps: selected.Steps, Rationale: "Evidence-grounded rationale", RequiresApproval: true, Confidence: .8, Preconditions: []string{"required condition"}, Postconditions: []string{"expected condition"}, Verification: []string{"verify expected condition"}}
	var plan ResolutionPlan
	if err = s.run(ctx, "resolve", map[string]any{"finding": finding, "playbook": selected, "evidence": []EvidenceRef{evidence}, "output_example": example}, &plan, v); err != nil {
		return out, err
	}
	plan.ID = "pending"
	plan.CreatedAt = time.Time{}
	if !validResolution(plan, finding, *selected, evidence, v) {
		s.outcome("resolve", "guardrail_rejected")
		return out, ErrServiceGuardrail
	}
	b, _ = json.Marshal(plan)
	plan.ID = "run-" + SourceChecksum(string(b))
	// Re-read both policy and immutable version lifecycle immediately before the
	// proposal boundary. Never hold the settings lock across a provider call.
	current := s.Settings()
	if err = s.available(current); err != nil {
		return out, err
	}
	p, err := s.catalog.GetPlaybook(ctx, selected.ID, selected.Version)
	if err != nil {
		return out, err
	}
	if p.Lifecycle != LifecycleActive || !s.guardrails(current, p).Allowed || !validResolution(plan, finding, p, evidence, current) {
		return out, ErrServiceGuardrail
	}
	s.mu.RLock()
	creator := s.creator
	s.mu.RUnlock()
	if nilDependency(creator) {
		return out, ErrServiceUnavailable
	}
	if err = s.catalog.RecordResolution(ctx, plan); err != nil {
		return out, err
	}
	diag := &triage.Diagnosis{IssueID: finding.ID, Summary: plan.Rationale, RootCause: plan.Rationale, Severity: finding.Severity, RemediationPlan: plan.Steps[0].Description, ActionType: triage.ActionType(plan.Steps[0].Action), ProposedCommand: fmt.Sprintf("# playbook:%s:%d run:%s", plan.PlaybookID, plan.PlaybookVersion, plan.ID), TargetReplicas: cloneTargetReplicas(plan.Steps[0].TargetReplicas), ConfidenceScore: plan.Confidence, ProviderName: "playbook"}
	if diag.RemediationPlan == "" {
		diag.RemediationPlan = plan.Rationale
	}
	proposal, err := creator.CreateProposalForActor(&finding, diag, s.safeActor(actor))
	if err != nil {
		return out, ErrServiceInvalid
	}
	if proposal == nil || proposal.Diagnosis == nil || proposal.IssueID != finding.ID || proposal.TargetUID != finding.TargetUID || proposal.TargetResourceVersion != finding.TargetResourceVersion || proposal.Diagnosis.ProposedCommand != diag.ProposedCommand {
		return out, ErrCatalogConflict
	}
	out.Plan = &plan
	out.Proposal = proposal
	s.outcome("resolve", "resolved")
	return out, nil
}
func exactBinding(p NormalizedPlaybook, q MatchQuery) bool {
	if p.Lifecycle != LifecycleActive || !contains(p.FailureCategories, q.FailureCategory) {
		return false
	}
	for _, b := range p.Applicability {
		if b.Namespace == q.Namespace && b.Kind == q.Kind && b.Name == q.Name && b.LabelSelector == "" {
			return true
		}
	}
	return false
}
func validResolution(p ResolutionPlan, i scanner.Issue, book NormalizedPlaybook, e EvidenceRef, v ServiceSettings) bool {
	if p.Validate() != nil || p.FindingID != i.ID || p.PlaybookID != book.ID || p.PlaybookVersion != book.Version || p.Target != (ResourceSelector{Namespace: i.Namespace, Kind: i.Kind, Name: i.Name}) || p.TargetUID != i.TargetUID || p.ResourceVersion != i.TargetResourceVersion || len(p.Uncertainties) > 0 || p.Confidence < v.MinConfidence || len(p.Steps) != 1 || len(book.Steps) != 1 || !p.RequiresApproval || len(p.Evidence) != 1 || !reflect.DeepEqual(p.Evidence[0], e) {
		return false
	}
	step := p.Steps[0]
	allowed := book.Steps[0]
	if step.ID != allowed.ID || step.Action != allowed.Action || step.Command != "" || step.ObserveOnly || step.RequiresReview || step.Confidence < v.MinConfidence || step.Action == "Manual" || step.Action == "GitOpsPR" || len(v.AllowedActions) > 0 && !contains(v.AllowedActions, step.Action) || !reflect.DeepEqual(step.TargetReplicas, allowed.TargetReplicas) {
		return false
	}
	if len(step.Targets) != 1 || step.Targets[0] != p.Target || len(step.EvidenceRefs) != 1 || step.EvidenceRefs[0] != e.ID {
		return false
	}
	return true
}

// resolutionForProposal validates durable lineage instead of trusting a model
// or deriving a new finding snapshot from changed live data.
func (s *Service) resolutionForProposal(ctx context.Context, command string) (ResolutionPlan, error) {
	parts := strings.Fields(command)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "run:") {
		return ResolutionPlan{}, ErrServiceInvalid
	}
	run := strings.TrimPrefix(parts[2], "run:")
	p, err := s.catalog.GetResolution(ctx, run)
	if err != nil {
		return p, err
	}
	expected := fmt.Sprintf("# playbook:%s:%d run:%s", p.PlaybookID, p.PlaybookVersion, p.ID)
	if command != expected {
		return p, ErrServiceInvalid
	}
	return p, nil
}
