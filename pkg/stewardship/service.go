package stewardship

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"time"
)

type Service struct {
	DB     *postgres.Store
	Policy *authorization.Policy
}
type AdjudicateRequest struct {
	Item               incident.ItemRef   `json:"item"`
	ItemHash           string             `json:"item_hash"`
	FeedbackID         string             `json:"feedback_id,omitempty"`
	Reason             string             `json:"reason"`
	CorrectionEvidence []incident.ItemRef `json:"correction_evidence"`
	IdempotencyKey     string             `json:"idempotency_key"`
}

func (s *Service) Adjudicate(ctx context.Context, p identity.Principal, scope identity.Scope, r AdjudicateRequest) (incident.Adjudication, error) {
	if err := s.Policy.Authorize(p, scope, authorization.Adjudicate); err != nil {
		return incident.Adjudication{}, err
	}
	switch r.Reason {
	case "CONFIRMED", "FACTUAL_ERROR", "NOT_APPLICABLE", "STALE", "UNRESOLVED":
	default:
		return incident.Adjudication{}, postgres.ErrInvalid
	}
	if !identity.ValidID(r.IdempotencyKey) || len(r.CorrectionEvidence) > 32 {
		return incident.Adjudication{}, postgres.ErrInvalid
	}
	r.IdempotencyKey = fleet.TokenHash(r.IdempotencyKey)
	raw, _ := json.Marshal(r)
	digest := fleet.TokenHash(string(raw))
	var a incident.Adjudication
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		old, err := tx.AdjudicationForKey(p.ID, r.IdempotencyKey)
		if err == nil {
			if old.RequestHash != digest {
				return postgres.ErrConflict
			}
			a = old
			return nil
		}
		if !errors.Is(err, postgres.ErrNotFound) {
			return err
		}
		item, err := tx.Item(r.Item)
		if err != nil {
			return err
		}
		if item.Hash != r.ItemHash {
			return postgres.ErrConflict
		}
		if r.FeedbackID != "" {
			event, err := tx.FeedbackByID(r.FeedbackID)
			if err != nil {
				return err
			}
			if event.Item != r.Item || event.ItemHash != r.ItemHash {
				return postgres.ErrConflict
			}
		}
		seen := map[incident.ItemRef]bool{}
		for _, ref := range r.CorrectionEvidence {
			if seen[ref] {
				return postgres.ErrInvalid
			}
			seen[ref] = true
			e, err := tx.Item(ref)
			if err != nil {
				return err
			}
			if e.IncidentID != item.IncidentID || e.Kind != incident.Evidence {
				return postgres.ErrInvalid
			}
			ok, err := tx.Eligible(ref, time.Now())
			if err != nil {
				return err
			}
			if !ok {
				return postgres.ErrConflict
			}
		}
		a = incident.Adjudication{Scope: scope, ID: identity.NewID(), IncidentID: item.IncidentID, Item: r.Item, ItemHash: item.Hash, FeedbackID: r.FeedbackID, ActorID: p.ID, Reason: r.Reason, CorrectionEvidence: r.CorrectionEvidence, RequestHash: digest, IdempotencyKey: r.IdempotencyKey, At: time.Now().UTC()}
		if err := tx.PutAdjudication(a); err != nil {
			return err
		}
		if r.Reason == "FACTUAL_ERROR" {
			if err := tx.Quarantine(r.Item); err != nil {
				return err
			}
		}
		// Confirmation is an attributed judgment. It never clears an existing dispute.
		payload, _ := json.Marshal(map[string]string{"adjudication_id": a.ID, "incident_id": a.IncidentID})
		return tx.Enqueue(a.ID, "ADJUDICATION_RECORDED", payload)
	})
	return a, err
}

type CorroborateRequest struct {
	Claim                incident.ItemRef   `json:"claim"`
	ClaimHash            string             `json:"claim_hash"`
	Evidence             []incident.ItemRef `json:"evidence"`
	UpstreamChecked      bool               `json:"upstream_checked"`
	TemporalOrderChecked bool               `json:"temporal_order_checked"`
	AlternativesTested   bool               `json:"alternatives_tested"`
}
type CorroboratedBody struct {
	investigation.RunResult
	StewardID            string           `json:"steward_id"`
	OriginalClaim        incident.ItemRef `json:"original_claim"`
	UpstreamChecked      bool             `json:"upstream_checked"`
	TemporalOrderChecked bool             `json:"temporal_order_checked"`
	AlternativesTested   bool             `json:"alternatives_tested"`
}

func (s *Service) Corroborate(ctx context.Context, p identity.Principal, scope identity.Scope, r CorroborateRequest) (incident.Item, error) {
	if err := s.Policy.Authorize(p, scope, authorization.Adjudicate); err != nil {
		return incident.Item{}, err
	}
	if !r.UpstreamChecked || !r.TemporalOrderChecked || !r.AlternativesTested || len(r.Evidence) < 2 || len(r.Evidence) > 32 {
		return incident.Item{}, postgres.ErrInvalid
	}
	var result incident.Item
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		claim, err := tx.Item(r.Claim)
		if err != nil {
			return err
		}
		if claim.Kind != incident.Claim || claim.Hash != r.ClaimHash {
			return postgres.ErrConflict
		}
		ok, err := tx.Eligible(r.Claim, time.Now())
		if err != nil {
			return err
		}
		if !ok {
			return postgres.ErrConflict
		}
		var run investigation.RunResult
		if json.Unmarshal(claim.Body, &run) != nil || run.Assessment.Status != investigation.Hypothesis {
			return postgres.ErrInvalid
		}
		switch run.Assessment.Conclusion.CauseCode {
		case privacy.NetworkBlocked, privacy.ConfigurationDrift, privacy.ResourcePressure:
		default:
			return postgres.ErrInvalid
		}
		evidence := []investigation.EvidenceSnapshot{}
		parents := []incident.ItemRef{r.Claim}
		seen := map[incident.ItemRef]bool{r.Claim: true}
		until := claim.ValidUntil
		for _, ref := range r.Evidence {
			if seen[ref] {
				return postgres.ErrInvalid
			}
			seen[ref] = true
			e, err := tx.Item(ref)
			if err != nil {
				return err
			}
			if e.Kind != incident.Evidence || e.IncidentID != claim.IncidentID {
				return postgres.ErrInvalid
			}
			ok, err := tx.Eligible(ref, time.Now())
			if err != nil {
				return err
			}
			if !ok {
				return postgres.ErrConflict
			}
			var o privacy.Observation
			if json.Unmarshal(e.Body, &o) != nil || o.Validate() != nil {
				return postgres.ErrInvalid
			}
			evidence = append(evidence, investigation.EvidenceSnapshot{Ref: ref, Observation: o})
			parents = append(parents, ref)
			if e.ValidUntil.Before(until) {
				until = e.ValidUntil
			}
		}
		candidate := run.Assessment.Conclusion
		directAt := time.Time{}
		for _, e := range evidence {
			if e.Observation.ResourceHandle == candidate.ResourceHandle && e.Observation.Code == candidate.CauseCode {
				if directAt.IsZero() || e.Observation.ObservedAt.Before(directAt) {
					directAt = e.Observation.ObservedAt
				}
			}
		}
		discriminated := false
		for _, e := range evidence {
			if e.Observation.Code == candidate.CauseCode || e.Observation.Code == privacy.Healthy || e.Observation.Code == privacy.ReadUnavailable || e.Observation.ObservedAt.Before(directAt) {
				continue
			}
			linked := e.Observation.ResourceHandle == candidate.ResourceHandle
			for _, h := range e.Observation.DependencyHandles {
				if h == candidate.ResourceHandle {
					linked = true
				}
			}
			if linked {
				discriminated = true
			}
		}
		if directAt.IsZero() || !discriminated {
			return postgres.ErrConflict
		}
		candidate.SupportingEvidence = r.Evidence
		assessed, err := investigation.AssessCandidate(candidate, evidence, time.Now())
		if err != nil || assessed.Status != investigation.Hypothesis {
			return postgres.ErrConflict
		}
		// Include every current evidence item in deterministic contradiction checks,
		// so the reviewer cannot omit an observed healthy contradiction.
		current, err := tx.CurrentEvidence(claim.IncidentID, time.Now(), 100)
		if err != nil {
			return err
		}
		if len(current) == 100 {
			return postgres.ErrConflict
		}
		for _, e := range current {
			eligible, err := tx.Eligible(incident.ItemRef{ID: e.ID, Version: e.Version}, time.Now())
			if err != nil {
				return err
			}
			if !eligible {
				continue
			}
			var o privacy.Observation
			if json.Unmarshal(e.Body, &o) == nil && o.ResourceHandle == candidate.ResourceHandle && o.Code == privacy.Healthy {
				return postgres.ErrConflict
			}
		}
		run.Assessment = assessed
		run.Assessment.Status = investigation.Corroborated
		run.Assessment.ReasonCode = "INDEPENDENT_STEWARD_CAUSAL_REVIEW"
		body, _ := json.Marshal(CorroboratedBody{RunResult: run, StewardID: p.ID, OriginalClaim: r.Claim, UpstreamChecked: true, TemporalOrderChecked: true, AlternativesTested: true})
		result = incident.Item{Scope: scope, IncidentID: claim.IncidentID, ID: identity.NewID(), Version: 1, Kind: incident.Claim, Body: body, ObservedAt: time.Now().UTC(), ValidUntil: until, Parents: parents}
		if err := result.Seal(); err != nil {
			return err
		}
		if err := tx.PutItem(result); err != nil {
			return err
		}
		event := incident.Adjudication{Scope: scope, ID: identity.NewID(), IncidentID: claim.IncidentID, Item: incident.ItemRef{ID: result.ID, Version: result.Version}, ItemHash: result.Hash, ActorID: p.ID, Reason: "CONFIRMED", At: time.Now().UTC(), IdempotencyKey: identity.NewID(), RequestHash: result.Hash}
		if err := tx.PutAdjudication(event); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]string{"incident_id": claim.IncidentID, "item_id": result.ID})
		return tx.Enqueue(result.ID, "CLAIM_CORROBORATED", payload)
	})
	return result, err
}
