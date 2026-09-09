package investigation

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/interaction"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"time"
)

// Snapshot contains only projected, scoped evidence authorized by the orchestrator.
type Snapshot struct {
	Evidence       []EvidenceSnapshot
	Parents        []incident.ItemRef
	ValidUntil     time.Time
	Environment    *incident.EnvironmentContext
	Clarifications []interaction.Context `json:"clarifications,omitempty"`
}

type snapshotState = Snapshot

func (s *Service) readSnapshot(ctx context.Context, scope identity.Scope, incidentID string, now time.Time) (snapshotState, error) {
	validUntil := now.Add(5 * time.Minute)
	snapshot := []EvidenceSnapshot{}
	parents := []incident.ItemRef{}
	var environment *incident.EnvironmentContext
	var clarifications []interaction.Context
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if _, err := tx.Incident(incidentID); err != nil {
			return err
		}
		if c, err := tx.EnvironmentContext(); err == nil {
			environment = &c
		} else if !errors.Is(err, postgres.ErrNotFound) {
			return err
		}
		answers, err := tx.InteractionContext(incidentID)
		clarifications = answers
		if err != nil {
			return err
		}
		items, err := tx.CurrentEvidence(incidentID, now, 100)
		if err != nil {
			return err
		}
		if len(items) == 100 {
			return ErrBusy
		}
		for _, item := range items {
			if item.Kind != incident.Evidence {
				continue
			}
			ref := incident.ItemRef{ID: item.ID, Version: item.Version}
			eligible, err := tx.Eligible(ref, now)
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
			if s.AuthorityEpoch != "" {
				if observation.Source == nil || observation.Source.Epoch != s.AuthorityEpoch {
					continue
				}
				agent, err := tx.AgentByID(observation.Source.AgentID)
				if err != nil {
					return err
				}
				if agent.Revoked || agent.Epoch != s.AuthorityEpoch || agent.Generation != observation.Source.Generation || !agent.ExpiresAt.After(now) {
					continue
				}
			}
			if observation.ObservedAt.After(now) || !observation.ValidUntil.After(now) {
				continue
			}
			if len(snapshot) >= 64 {
				return ErrBusy
			}
			snapshot = append(snapshot, EvidenceSnapshot{Ref: ref, Observation: observation})
			parents = append(parents, ref)
			if item.ValidUntil.Before(validUntil) {
				validUntil = item.ValidUntil
			}
			if observation.ValidUntil.Before(validUntil) {
				validUntil = observation.ValidUntil
			}
		}
		return nil
	})
	if err != nil {
		return snapshotState{}, err
	}
	return snapshotState{Evidence: snapshot, Parents: parents, ValidUntil: validUntil, Environment: environment, Clarifications: clarifications}, nil
}
