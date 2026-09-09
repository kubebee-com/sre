// Package execution authorizes a single typed mutation at an explicit database boundary.
package execution

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"time"
)

type Service struct {
	Fleet   *fleet.Service
	Enabled bool
}
type ProposeRequest struct {
	IncidentID   string           `json:"incident_id"`
	Kind         string           `json:"kind"`
	Evidence     incident.ItemRef `json:"evidence"`
	EvidenceHash string           `json:"evidence_hash"`
	ExecutorID   string           `json:"executor_id"`
}
type Claim struct {
	Action       incident.Action `json:"action"`
	ReceiptToken string          `json:"receipt_token"`
}

func (s *Service) available() error {
	if s == nil || !s.Enabled || s.Fleet == nil {
		return authorization.ErrForbidden
	}
	return nil
}
func (s *Service) Propose(ctx context.Context, p identity.Principal, scope identity.Scope, r ProposeRequest) (incident.Action, error) {
	if err := s.available(); err != nil {
		return incident.Action{}, err
	}
	if err := s.Fleet.Policy.Authorize(p, scope, authorization.Investigate); err != nil {
		return incident.Action{}, err
	}
	if r.Kind != "REPLACE_POD" || !identity.ValidID(r.ExecutorID) {
		return incident.Action{}, postgres.ErrInvalid
	}
	var a incident.Action
	err := s.Fleet.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		item, err := tx.Item(r.Evidence)
		if err != nil {
			return err
		}
		if item.Kind != incident.Evidence || item.IncidentID != r.IncidentID || item.Hash != r.EvidenceHash {
			return postgres.ErrConflict
		}
		eligible, err := tx.Eligible(r.Evidence, time.Now())
		if err != nil {
			return err
		}
		if !eligible {
			return postgres.ErrConflict
		}
		current, err := tx.CurrentItem(item.ID)
		if err != nil {
			return err
		}
		if current.Version != item.Version {
			return postgres.ErrConflict
		}
		var o privacy.Observation
		if json.Unmarshal(item.Body, &o) != nil || o.Validate() != nil || o.Target == nil || o.Source == nil || o.Target.Kind != "Pod" || o.Target.UID == "" || o.Target.ResourceVersion == "" || (o.Code != privacy.CrashLoop && o.Code != privacy.PodFailed) {
			return postgres.ErrInvalid
		}
		executor, err := tx.AgentByID(r.ExecutorID)
		if err != nil {
			return err
		}
		source, err := tx.AgentByID(o.Source.AgentID)
		if err != nil {
			return err
		}
		if executor.Role != fleet.Executor || executor.Revoked || executor.Epoch != s.Fleet.Epoch || !executor.ExpiresAt.After(time.Now()) || executor.ClusterUID != source.ClusterUID {
			return postgres.ErrConflict
		}
		expiry := time.Now().Add(5 * time.Minute)
		for _, until := range []time.Time{item.ValidUntil, o.ValidUntil, source.ExpiresAt, executor.ExpiresAt} {
			if until.Before(expiry) {
				expiry = until
			}
		}
		plan := incident.ActionPlan{Scope: scope, ID: identity.NewID(), IncidentID: r.IncidentID, Kind: r.Kind, Evidence: r.Evidence, EvidenceHash: item.Hash, ResourceHandle: o.ResourceHandle, TargetCommitment: o.Target.Commitment, SourceAgentID: o.Source.AgentID, SourceGeneration: o.Source.Generation, ExecutorID: executor.ID, ExecutorGeneration: executor.Generation, Epoch: s.Fleet.Epoch, PolicyVersion: s.Fleet.Policy.Version(), ExpiresAt: expiry.UTC()}
		a = incident.Action{Plan: plan, Hash: plan.Hash(), Version: 1, State: "PROPOSED", ProposedBy: p.ID, CreatedAt: time.Now().UTC()}
		if err := tx.SaveAction(a, 0, ""); err != nil {
			return err
		}
		return enqueue(tx, a)
	})
	return a, err
}
func (s *Service) current(tx *postgres.Tx, a incident.Action) error {
	if a.Hash != a.Plan.Hash() || a.Plan.Epoch != s.Fleet.Epoch || a.Plan.PolicyVersion != s.Fleet.Policy.Version() || !a.Plan.ExpiresAt.After(time.Now()) {
		return postgres.ErrConflict
	}
	eligible, err := tx.Eligible(a.Plan.Evidence, time.Now())
	if err != nil {
		return err
	}
	if !eligible {
		return postgres.ErrConflict
	}
	item, err := tx.CurrentItem(a.Plan.Evidence.ID)
	if err != nil {
		return err
	}
	if item.Version != a.Plan.Evidence.Version || item.Hash != a.Plan.EvidenceHash {
		return postgres.ErrConflict
	}
	executor, err := tx.AgentByID(a.Plan.ExecutorID)
	if err != nil {
		return err
	}
	if executor.Revoked || executor.Role != fleet.Executor || executor.Epoch != a.Plan.Epoch || executor.Generation != a.Plan.ExecutorGeneration || !executor.ExpiresAt.After(time.Now()) {
		return postgres.ErrConflict
	}
	return nil
}
func (s *Service) Approve(ctx context.Context, p identity.Principal, scope identity.Scope, id, hash string) (incident.Action, error) {
	if err := s.available(); err != nil {
		return incident.Action{}, err
	}
	if err := s.Fleet.Policy.Authorize(p, scope, authorization.Approve); err != nil {
		return incident.Action{}, err
	}
	var a incident.Action
	err := s.Fleet.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		var err error
		a, _, err = tx.Action(id)
		if err != nil {
			return err
		}
		if a.State != "PROPOSED" || subtle.ConstantTimeCompare([]byte(hash), []byte(a.Hash)) != 1 {
			return postgres.ErrConflict
		}
		if err := s.current(tx, a); err != nil {
			return err
		}
		a.State = "APPROVED"
		a.ApprovedBy = p.ID
		a.ApprovalExpiresAt = p.ExpiresAt.UTC()
		a.Version++
		if err := tx.SaveAction(a, a.Version-1, ""); err != nil {
			return err
		}
		return enqueue(tx, a)
	})
	return a, err
}
func (s *Service) Claim(ctx context.Context, scope identity.Scope, token, id string) (Claim, error) {
	if err := s.available(); err != nil {
		return Claim{}, err
	}
	var result Claim
	err := s.Fleet.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		agent, err := s.Fleet.AuthenticateTx(tx, token, fleet.Executor)
		if err != nil {
			return err
		}
		a, _, err := tx.Action(id)
		if err != nil {
			return err
		}
		if a.State != "APPROVED" || a.ApprovedBy == "" || !a.ApprovalExpiresAt.After(time.Now()) || a.Plan.ExecutorID != agent.ID || a.Plan.ExecutorGeneration != agent.Generation {
			return postgres.ErrConflict
		}
		if err := s.current(tx, a); err != nil {
			return err
		}
		a.State = "SUBMITTED"
		a.SubmittedAt = time.Now().UTC()
		a.Version++
		result = Claim{Action: a, ReceiptToken: identity.NewID() + identity.NewID()}
		if err := tx.SaveAction(a, a.Version-1, fleet.TokenHash(result.ReceiptToken)); err != nil {
			return err
		}
		return enqueue(tx, a)
	})
	if err != nil {
		return Claim{}, err
	}
	return result, nil
}
func (s *Service) Receipt(ctx context.Context, scope identity.Scope, token, id, receipt, outcome string) (incident.Action, error) {
	if err := s.available(); err != nil {
		return incident.Action{}, err
	}
	if outcome != "APPLIED" && outcome != "PRECONDITION_FAILED" && outcome != "DENIED" && outcome != "AMBIGUOUS" {
		return incident.Action{}, postgres.ErrInvalid
	}
	var a incident.Action
	err := s.Fleet.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		agent, err := s.Fleet.AuthenticateTx(tx, token, fleet.Executor)
		if err != nil {
			return err
		}
		var stored string
		a, stored, err = tx.Action(id)
		if err != nil {
			return err
		}
		if a.Plan.ExecutorID != agent.ID || a.Plan.ExecutorGeneration != agent.Generation || len(receipt) != 64 || subtle.ConstantTimeCompare([]byte(stored), []byte(fleet.TokenHash(receipt))) != 1 {
			return postgres.ErrConflict
		}
		if a.State != "SUBMITTED" {
			// An authenticated late receipt may acknowledge an owner reconciliation,
			// but cannot replace its uncertain outcome or create another transition.
			if a.OutcomeCode == outcome || (a.State == "AMBIGUOUS" && a.OutcomeCode == "AMBIGUOUS" && a.ReconciledBy != "") {
				return nil
			}
			return postgres.ErrConflict
		}
		a.State = "FAILED"
		if outcome == "APPLIED" || outcome == "AMBIGUOUS" {
			a.State = outcome
		}
		a.OutcomeCode = outcome
		a.CompletedAt = time.Now().UTC()
		a.Version++
		if err := tx.SaveAction(a, a.Version-1, stored); err != nil {
			return err
		}
		return enqueue(tx, a)
	})
	return a, err
}
func (s *Service) Cancel(ctx context.Context, p identity.Principal, scope identity.Scope, id string) (incident.Action, error) {
	if err := s.available(); err != nil {
		return incident.Action{}, err
	}
	if err := s.Fleet.Policy.Authorize(p, scope, authorization.Approve); err != nil {
		return incident.Action{}, err
	}
	var a incident.Action
	err := s.Fleet.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		var err error
		a, _, err = tx.Action(id)
		if err != nil {
			return err
		}
		if a.State != "PROPOSED" && a.State != "APPROVED" {
			return postgres.ErrConflict
		}
		a.State = "CANCELLED"
		a.CompletedAt = time.Now().UTC()
		a.Version++
		if err := tx.SaveAction(a, a.Version-1, ""); err != nil {
			return err
		}
		return enqueue(tx, a)
	})
	return a, err
}
func enqueue(tx *postgres.Tx, a incident.Action) error {
	raw, _ := json.Marshal(map[string]string{"action_id": a.Plan.ID, "incident_id": a.Plan.IncidentID, "state": a.State})
	return tx.Enqueue(identity.NewID(), "ACTION_UPDATED", raw)
}
