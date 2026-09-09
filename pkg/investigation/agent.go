package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/interaction"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"reflect"
	"slices"
	"time"
)

// AgentInput is a bounded, projected snapshot. No credentials enter this payload.
type AgentInput struct {
	Scope          identity.Scope        `json:"scope"`
	JobID          string                `json:"job_id"`
	IncidentID     string                `json:"incident_id"`
	ProfileID      string                `json:"profile_id"`
	ProfileVersion string                `json:"profile_version"`
	Provider       ProviderMetadata      `json:"provider"`
	Snapshot       Snapshot              `json:"snapshot"`
	Guidance       []incident.GoldenCase `json:"guidance"`
}
type AgentClaim struct {
	Input      AgentInput `json:"input"`
	AttemptID  string     `json:"attempt_id"`
	LeaseUntil time.Time  `json:"lease_until"`
}
type AgentAuthenticator func(*postgres.Tx) (incident.Agent, error)

func (q *Queue) ClaimAgent(ctx context.Context, scope identity.Scope, auth AgentAuthenticator, profiles []string) (*AgentClaim, error) {
	s := q.Service
	var lease postgres.DiagnosticLease
	var p identity.Principal
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		a, err := auth(tx)
		if err != nil {
			return err
		}
		lease, err = tx.ClaimAgentDiagnostic(a, profiles)
		return err
	})
	if errors.Is(err, postgres.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	profile, ok := s.profiles[lease.Job.ProfileID]
	if !ok || !profileAllows(profile, scope) {
		return nil, postgres.ErrConflict
	}
	p, err = s.Policy.OpenPrincipal(lease.Authority, scope, authorization.Investigate)
	if err != nil {
		return nil, err
	}
	state, err := s.readSnapshot(ctx, scope, lease.Job.IncidentID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	guidance := []incident.GoldenCase{}
	if s.Guidance != nil {
		guidance, err = s.Guidance(ctx, p, scope)
		if err != nil {
			return nil, err
		}
		guidance = applicableGuidance(guidance, state.Evidence, time.Now())
	}
	in := AgentInput{Scope: scope, JobID: lease.Job.ID, IncidentID: lease.Job.IncidentID, ProfileID: profile.ID, ProfileVersion: profile.Version, Provider: profile.Metadata, Snapshot: state, Guidance: guidance}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > 60000 {
		return nil, postgres.ErrInvalid
	}
	err = s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		a, err := auth(tx)
		if err != nil {
			return err
		}
		current, err := tx.AgentDiagnostic(lease.Job.ID, lease.AttemptID, a, false)
		if err != nil {
			return err
		}
		if _, err = s.Policy.OpenPrincipal(current.Authority, scope, authorization.Investigate); err != nil {
			return err
		}
		if err = s.validateAgentSnapshot(tx, in, time.Now()); err != nil {
			return err
		}
		if err = tx.StartAgentDiagnostic(lease.Job.ID, profile.Version, PromptVersion, RubricVersion); err != nil {
			return err
		}
		return tx.SetDiagnosticInput(lease.Job.ID, lease.AttemptID, raw, false)
	})
	if err != nil {
		return nil, err
	}
	return &AgentClaim{Input: in, AttemptID: lease.AttemptID, LeaseUntil: lease.LeaseUntil}, nil
}

func (q *Queue) HeartbeatAgent(ctx context.Context, scope identity.Scope, auth AgentAuthenticator, id, attempt string) (time.Time, error) {
	var until time.Time
	err := q.Service.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		a, err := auth(tx)
		if err != nil {
			return err
		}
		l, err := tx.AgentDiagnostic(id, attempt, a, true)
		if err != nil {
			return err
		}
		if _, err = q.Service.Policy.OpenPrincipal(l.Authority, scope, authorization.Investigate); err != nil {
			return err
		}
		until = l.LeaseUntil
		return nil
	})
	return until, err
}

// validateAgentSnapshot checks source generation/revocation and current evidence
// versions under the same scope lock as result persistence. No agent claims can
// override the evidence authority or turn a model hypothesis into approval.
func (s *Service) validateAgentSnapshot(tx *postgres.Tx, in AgentInput, at time.Time) error {
	profile, ok := s.profiles[in.ProfileID]
	if !ok || profile.Version != in.ProfileVersion || !profileAllows(profile, in.Scope) {
		return postgres.ErrConflict
	}
	if !in.Snapshot.ValidUntil.After(at) {
		return postgres.ErrConflict
	}
	current, err := tx.CurrentEvidence(in.IncidentID, at, 100)
	if err != nil {
		return err
	}
	byRef := map[incident.ItemRef]bool{}
	for _, item := range current {
		ref := incident.ItemRef{ID: item.ID, Version: item.Version}
		eligible, err := tx.Eligible(ref, at)
		if err != nil {
			return err
		}
		if !eligible {
			continue
		}
		var observation privacy.Observation
		if strictDecode(item.Body, &observation) != nil || observation.Validate() != nil {
			return postgres.ErrInvalid
		}
		if observation.ObservedAt.After(at) || !observation.ValidUntil.After(at) {
			continue
		}
		byRef[ref] = true
	}
	// Newly arrived contradictions must be assessed in a fresh attempt, too.
	if len(byRef) != len(in.Snapshot.Evidence) {
		return postgres.ErrConflict
	}
	for _, e := range in.Snapshot.Evidence {
		if !byRef[e.Ref] {
			return postgres.ErrConflict
		}
		eligible, err := tx.Eligible(e.Ref, at)
		if err != nil {
			return err
		}
		if !eligible {
			return postgres.ErrConflict
		}
		source := e.Observation.Source
		if source != nil {
			a, err := tx.AgentByID(source.AgentID)
			if err != nil {
				return err
			}
			if a.Role != "COLLECTOR" || a.Revoked || a.Generation != source.Generation || a.Epoch != source.Epoch || !a.ExpiresAt.After(at) || (s.AuthorityEpoch != "" && a.Epoch != s.AuthorityEpoch) {
				return postgres.ErrConflict
			}
		} else if s.AuthorityEpoch != "" {
			return postgres.ErrConflict
		}
	}
	clarifications, err := tx.InteractionContext(in.IncidentID)
	if err != nil {
		return err
	}
	if !slices.Equal(clarifications, in.Snapshot.Clarifications) {
		return postgres.ErrConflict
	}
	env, err := tx.EnvironmentContext()
	if in.Snapshot.Environment == nil {
		if err == nil {
			return postgres.ErrConflict
		}
		if !errors.Is(err, postgres.ErrNotFound) {
			return err
		}
	} else {
		if err != nil {
			return err
		}
		if env.Version != in.Snapshot.Environment.Version {
			return postgres.ErrConflict
		}
	}
	for _, g := range in.Guidance {
		if s.ValidateGuidance == nil {
			return postgres.ErrConflict
		}
		ok, err := s.ValidateGuidance(tx, g)
		if err != nil {
			return err
		}
		if !ok {
			return postgres.ErrConflict
		}
	}
	return nil
}

// ValidateAgentResult ignores asserted certainty and re-runs the deterministic
// citation rubric using the orchestrator's stored input, never agent-supplied facts.
func ValidateAgentResult(result RunResult, state Snapshot, at time.Time) (Assessment, error) {
	if len(result.Rounds) > 3 {
		return Assessment{}, postgres.ErrInvalid
	}
	if !reflect.DeepEqual(result.Assessment.Conclusion, Conclusion{}) {
		return AssessCandidate(result.Assessment.Conclusion, state.Evidence, at)
	}
	switch result.Assessment.ReasonCode {
	case "NO_CURRENT_ELIGIBLE_EVIDENCE", "DISCRIMINATING_EVIDENCE_REQUIRED", "COLLECTION_BUDGET_EXHAUSTED", "REPEATED_CHECK_WITHOUT_PROGRESS", "FRESH_COLLECTION_UNAVAILABLE":
		return Assessment{Status: NeedsEvidence, ReasonCode: result.Assessment.ReasonCode}, nil
	case "PROVIDER_UNAVAILABLE", "INVALID_PROVIDER_OUTPUT", "INVALID_PROVIDER_EVIDENCE":
		return Assessment{Status: Inconclusive, ReasonCode: result.Assessment.ReasonCode}, nil
	}
	return Assessment{}, postgres.ErrInvalid
}

func (q *Queue) CompleteAgent(ctx context.Context, scope identity.Scope, auth AgentAuthenticator, id, attempt string, submitted RunResult) (incident.Item, error) {
	s := q.Service
	var claim incident.Item
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		a, err := auth(tx)
		if err != nil {
			return err
		}
		l, err := tx.AgentDiagnostic(id, attempt, a, false)
		if err != nil {
			return err
		}
		if _, err = s.Policy.OpenPrincipal(l.Authority, scope, authorization.Investigate); err != nil {
			return err
		}
		var in AgentInput
		if strictDecode(l.Input, &in) != nil {
			return postgres.ErrConflict
		}
		if in.JobID != id || in.Scope != scope || submitted.RunID != id || submitted.ProfileID != in.ProfileID || submitted.ProfileVersion != in.ProfileVersion || submitted.PrivacyVersion != privacy.Version || submitted.PromptVersion != PromptVersion || submitted.RubricVersion != RubricVersion {
			return postgres.ErrInvalid
		}
		now := time.Now().UTC()
		if err = s.validateAgentSnapshot(tx, in, now); err != nil {
			return err
		}
		assessment, err := ValidateAgentResult(submitted, in.Snapshot, now)
		if err != nil {
			return err
		}
		result := RunResult{RunID: id, ProfileID: in.ProfileID, ProfileVersion: in.ProfileVersion, PrivacyVersion: privacy.Version, PromptVersion: PromptVersion, RubricVersion: RubricVersion, Assessment: assessment}
		// Counts are bounded telemetry; free text and endpoint details are not persisted.
		for i, round := range submitted.Rounds {
			if round.ProviderLatencyMS < 0 || round.ProviderLatencyMS > 90000 || round.EvidenceCount < 0 || round.EvidenceCount > 64 || round.ChecksRequested < 0 || round.ChecksRequested > 2 {
				return postgres.ErrInvalid
			}
			round.Number = i + 1
			round.Status = assessment.Status
			round.Reason = assessment.ReasonCode
			if round.Usage != nil {
				u := round.Usage
				if u.InputTokens < 0 || u.OutputTokens < 0 || u.TotalTokens < 0 || u.InputTokens > 1000000000 || u.OutputTokens > 1000000000 || u.TotalTokens > 1000000000 {
					return postgres.ErrInvalid
				}
			}
			result.Rounds = append(result.Rounds, round)
		}
		if in.Snapshot.Environment != nil {
			result.EnvironmentVersion = in.Snapshot.Environment.Version
		}
		for _, g := range in.Guidance {
			result.KnowledgeVersions = append(result.KnowledgeVersions, incident.ItemRef{ID: g.ID, Version: g.Version})
		}
		body, _ := json.Marshal(result)
		claim = incident.Item{Scope: scope, IncidentID: in.IncidentID, ID: identity.NewID(), Version: 1, Kind: incident.Claim, Body: body, ObservedAt: now, ValidUntil: in.Snapshot.ValidUntil, Parents: in.Snapshot.Parents}
		if err = claim.Seal(); err != nil {
			return err
		}
		if err = tx.PutItem(claim); err != nil {
			return err
		}
		ref := &incident.ItemRef{ID: claim.ID, Version: claim.Version}
		if err = tx.FinishRun(id, string(assessment.Status), assessment.ReasonCode, ref); err != nil {
			return err
		}
		if err = tx.FinishDiagnosticJob(id, "COMPLETED", ref); err != nil {
			return err
		}
		if assessment.Status == NeedsEvidence {
			request := interaction.Request{Scope: scope, ID: identity.NewID(), IncidentID: in.IncidentID, JobID: id, Kind: interaction.Clarification, Question: "CHANGE_CONTEXT", Version: 1, Status: "PENDING", ExpiresAt: now.Add(time.Hour)}
			if err = tx.CreateInteraction(request, l.Job.ActorID); err != nil {
				return err
			}
		}
		payload, _ := json.Marshal(map[string]string{"incident_id": in.IncidentID, "item_id": claim.ID})
		return tx.Enqueue(id, "INVESTIGATION_RECORDED", payload)
	})
	return claim, err
}

// RefreshAgent asks the existing collector for a bounded read-only rescan. The
// orchestrator supplies the resulting projection; the model never receives raw
// Kubernetes objects and cannot introduce its own observations.
func (q *Queue) RefreshAgent(ctx context.Context, scope identity.Scope, auth AgentAuthenticator, id, attempt string, checks []Check) (*Snapshot, error) {
	s := q.Service
	var in AgentInput
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		a, err := auth(tx)
		if err != nil {
			return err
		}
		l, err := tx.AgentDiagnostic(id, attempt, a, false)
		if err != nil {
			return err
		}
		if _, err = s.Policy.OpenPrincipal(l.Authority, scope, authorization.Investigate); err != nil {
			return err
		}
		if l.RefreshCount >= 2 || len(checks) == 0 || len(checks) > 2 || strictDecode(l.Input, &in) != nil {
			return postgres.ErrInvalid
		}
		for _, check := range checks {
			if (check.Kind != "REFRESH_RESOURCE_STATE" && check.Kind != "REFRESH_DEPENDENCIES") || !privacy.ValidHandle(check.ResourceHandle) {
				return postgres.ErrInvalid
			}
			found := false
			for _, e := range in.Snapshot.Evidence {
				if e.Observation.ResourceHandle == check.ResourceHandle && e.Observation.Source != nil && e.Observation.Source.AgentID == a.ID && e.Observation.Source.Generation == a.Generation {
					found = true
				}
			}
			if !found {
				return postgres.ErrInvalid
			}
		}
		if err = s.validateAgentSnapshot(tx, in, time.Now()); err != nil {
			return err
		}
		// Reserve refresh budget before waiting so concurrent requests cannot exceed it.
		return tx.SetDiagnosticInput(id, attempt, l.Input, true)
	})
	if err != nil {
		return nil, err
	}
	ready, err := s.collectChecks(ctx, scope, in.IncidentID, checks, in.Snapshot.Evidence)
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, nil
	}
	next, err := s.readSnapshot(ctx, scope, in.IncidentID, time.Now())
	if err != nil {
		return nil, err
	}
	if (in.Snapshot.Environment == nil) != (next.Environment == nil) || (in.Snapshot.Environment != nil && in.Snapshot.Environment.Version != next.Environment.Version) {
		return nil, postgres.ErrConflict
	}
	in.Snapshot = next
	raw, _ := json.Marshal(in)
	err = s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		a, err := auth(tx)
		if err != nil {
			return err
		}
		l, err := tx.AgentDiagnostic(id, attempt, a, false)
		if err != nil {
			return err
		}
		if _, err = s.Policy.OpenPrincipal(l.Authority, scope, authorization.Investigate); err != nil {
			return err
		}
		if err = s.validateAgentSnapshot(tx, in, time.Now()); err != nil {
			return err
		}
		return tx.SetDiagnosticInput(id, attempt, raw, false)
	})
	if err != nil {
		return nil, err
	}
	return &next, nil
}
