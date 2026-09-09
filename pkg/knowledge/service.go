package knowledge

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"time"
)

type Service struct {
	DB     *postgres.Store
	Policy *authorization.Policy
}
type CandidateRequest struct {
	Claim      incident.ItemRef `json:"claim"`
	ClaimHash  string           `json:"claim_hash"`
	RecoveryID string           `json:"recovery_id"`
}

func (s *Service) Candidate(ctx context.Context, p identity.Principal, scope identity.Scope, r CandidateRequest) (incident.GoldenCase, error) {
	if err := s.Policy.Authorize(p, scope, authorization.ReviewKnowledge); err != nil {
		return incident.GoldenCase{}, err
	}
	var g incident.GoldenCase
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		claim, err := tx.Item(r.Claim)
		if err != nil {
			return err
		}
		if claim.Kind != incident.Claim || claim.Hash != r.ClaimHash {
			return postgres.ErrConflict
		}
		var body struct {
			investigation.RunResult
			StewardID string `json:"steward_id"`
		}
		if json.Unmarshal(claim.Body, &body) != nil || body.StewardID == "" || body.Assessment.Status != investigation.Corroborated {
			return postgres.ErrInvalid
		}
		assessment, err := tx.RecoveryAssessment(r.RecoveryID)
		if err != nil {
			return err
		}
		if assessment.IncidentID != claim.IncidentID || assessment.Status != "RECOVERED" || len(assessment.Evidence) < 3 {
			return postgres.ErrConflict
		}
		g = incident.GoldenCase{Scope: scope, ID: identity.NewID(), Version: 1, State: "CANDIDATE", IncidentID: claim.IncidentID, Claim: r.Claim, ClaimHash: claim.Hash, RecoveryID: r.RecoveryID, CauseCode: string(body.Assessment.Conclusion.CauseCode), CreatedBy: p.ID, CreatedAt: time.Now().UTC()}
		if ok, err := EligibleTx(tx, g); err != nil {
			return err
		} else if !ok {
			return postgres.ErrConflict
		}
		return tx.PutGoldenCase(g)
	})
	return g, err
}
func EligibleTx(tx *postgres.Tx, g incident.GoldenCase) (bool, error) {
	ok, err := tx.HistoricalEligible(g.Claim)
	if err != nil || !ok {
		return false, err
	}
	claim, err := tx.Item(g.Claim)
	if err != nil {
		return false, err
	}
	if claim.Hash != g.ClaimHash {
		return false, nil
	}
	a, err := tx.RecoveryAssessment(g.RecoveryID)
	if err != nil {
		return false, err
	}
	if a.IncidentID != g.IncidentID || a.Status != "RECOVERED" || len(a.Evidence) < 3 {
		return false, nil
	}
	for _, ref := range a.Evidence {
		ok, err := tx.HistoricalEligible(ref)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}
func (s *Service) Publish(ctx context.Context, p identity.Principal, scope identity.Scope, id string, version int64) (incident.GoldenCase, error) {
	if err := s.Policy.Authorize(p, scope, authorization.ReviewKnowledge); err != nil {
		return incident.GoldenCase{}, err
	}
	var g incident.GoldenCase
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		var err error
		g, err = tx.GoldenCase(id)
		if err != nil {
			return err
		}
		if g.Version != version || g.State != "CANDIDATE" || g.CreatedBy == p.ID {
			return postgres.ErrConflict
		}
		if ok, err := EligibleTx(tx, g); err != nil {
			return err
		} else if !ok {
			return postgres.ErrConflict
		}
		g.Evaluation = Evaluate(g)
		if !g.Evaluation.Approved {
			return postgres.ErrConflict
		}
		g.Version++
		g.State = "ACTIVE"
		g.ReviewedBy = p.ID
		g.PublishedAt = time.Now().UTC()
		if err := tx.PutGoldenCase(g); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]string{"case_id": g.ID, "incident_id": g.IncidentID})
		return tx.Enqueue(identity.NewID(), "KNOWLEDGE_PUBLISHED", payload)
	})
	return g, err
}
func (s *Service) Retire(ctx context.Context, p identity.Principal, scope identity.Scope, id string, version int64) (incident.GoldenCase, error) {
	if err := s.Policy.Authorize(p, scope, authorization.ReviewKnowledge); err != nil {
		return incident.GoldenCase{}, err
	}
	var g incident.GoldenCase
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		var err error
		g, err = tx.GoldenCase(id)
		if err != nil {
			return err
		}
		if g.Version != version || g.State == "RETIRED" {
			return postgres.ErrConflict
		}
		g.Version++
		g.State = "RETIRED"
		g.ReviewedBy = p.ID
		return tx.PutGoldenCase(g)
	})
	return g, err
}

// Retrieve is scoped, checks lineage synchronously, and returns bounded guidance.
func (s *Service) Retrieve(ctx context.Context, p identity.Principal, scope identity.Scope) ([]incident.GoldenCase, error) {
	if err := s.Policy.Authorize(p, scope, authorization.Read); err != nil {
		return nil, err
	}
	result := []incident.GoldenCase{}
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		after := ""
		for page := 0; page < 100; page++ {
			cases, err := tx.GoldenCases(after, 100)
			if err != nil {
				return err
			}
			for _, g := range cases {
				after = g.ID
				if g.State != "ACTIVE" {
					continue
				}
				ok, err := EligibleTx(tx, g)
				if err != nil {
					return err
				}
				if ok {
					result = append(result, g)
					if len(result) == 16 {
						return nil
					}
				}
			}
			if len(cases) < 100 {
				return nil
			}
		}
		return postgres.ErrUnavailable
	})
	return result, err
}

func PublishedEligibleTx(tx *postgres.Tx, g incident.GoldenCase) (bool, error) {
	current, err := tx.GoldenCase(g.ID)
	if err != nil {
		return false, err
	}
	if current.Version != g.Version || current.State != "ACTIVE" {
		return false, nil
	}
	return EligibleTx(tx, current)
}
