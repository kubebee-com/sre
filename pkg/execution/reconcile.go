package execution

import (
	"context"
	"crypto/subtle"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"time"
)

// Reconcile records uncertainty when a submitted action has no terminal receipt
// after two minutes. It never authorizes a retry or asserts an operation effect.
// SaveAction's version compare-and-swap also arbitrates a concurrent receipt.
func (s *Service) Reconcile(ctx context.Context, p identity.Principal, scope identity.Scope, id, hash string) (incident.Action, error) {
	if err := s.available(); err != nil {
		return incident.Action{}, err
	}
	if err := s.Fleet.Policy.Authorize(p, scope, authorization.Approve); err != nil {
		return incident.Action{}, err
	}
	if !identity.ValidID(id) || len(hash) != 64 {
		return incident.Action{}, postgres.ErrInvalid
	}
	var a incident.Action
	err := s.Fleet.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		var stored string
		var err error
		a, stored, err = tx.Action(id)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if a.State != "SUBMITTED" || a.SubmittedAt.IsZero() || a.SubmittedAt.Add(120*time.Second).After(now) || subtle.ConstantTimeCompare([]byte(hash), []byte(a.Hash)) != 1 {
			return postgres.ErrConflict
		}
		a.State = "AMBIGUOUS"
		a.OutcomeCode = "AMBIGUOUS"
		a.ReconciledBy = p.ID
		a.CompletedAt = now
		a.Version++
		if err := tx.SaveAction(a, a.Version-1, stored); err != nil {
			return err
		}
		return enqueue(tx, a)
	})
	if err != nil {
		return incident.Action{}, err
	}
	return a, nil
}
