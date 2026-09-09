package investigation

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"time"
)

type queuedRunKey struct{}
type Queue struct {
	Service *Service
	Scopes  []identity.Scope
}

func (q *Queue) Enqueue(ctx context.Context, p identity.Principal, scope identity.Scope, incidentID, profileID string) (incident.DiagnosticJob, error) {
	s := q.Service
	if s.Policy.Authorize(p, scope, authorization.Investigate) != nil {
		return incident.DiagnosticJob{}, authorization.ErrForbidden
	}
	profile, ok := s.profiles[profileID]
	if !ok || !profileAllows(profile, scope) {
		return incident.DiagnosticJob{}, postgres.ErrInvalid
	}
	authority, err := s.Policy.SealPrincipal(p, scope, authorization.Investigate)
	if err != nil {
		return incident.DiagnosticJob{}, err
	}
	job := incident.DiagnosticJob{Scope: scope, ID: identity.NewID(), IncidentID: incidentID, ProfileID: profileID, ActorID: p.ID, State: "QUEUED", CreatedAt: time.Now().UTC(), ExpiresAt: p.ExpiresAt.UTC()}
	if deadline := job.CreatedAt.Add(10 * time.Minute); job.ExpiresAt.After(deadline) {
		job.ExpiresAt = deadline
	}
	err = s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		old, err := tx.ActiveDiagnosticJob(incidentID)
		if err == nil {
			if old.ProfileID != profileID {
				return postgres.ErrConflict
			}
			job = old
			return nil
		}
		if !errors.Is(err, postgres.ErrNotFound) {
			return err
		}
		if err := tx.PutDiagnosticJob(job, authority); err != nil {
			return err
		}
		if err := tx.StartRun(job.ID, incidentID, profileID, profile.Version, PromptVersion, RubricVersion, job.CreatedAt); err != nil {
			return err
		}
		return tx.QueueRun(job.ID)
	})
	return job, err
}
func (q *Queue) Cancel(ctx context.Context, p identity.Principal, scope identity.Scope, id string) error {
	if q.Service.Policy.Authorize(p, scope, authorization.Investigate) != nil {
		return authorization.ErrForbidden
	}
	err := q.Service.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		j, err := tx.DiagnosticJob(id)
		if err != nil {
			return err
		}
		if j.State != "QUEUED" && j.State != "RUNNING" {
			return postgres.ErrConflict
		}
		if err := tx.FinishDiagnosticJob(id, "CANCELLED", nil); err != nil {
			return err
		}
		return tx.FinishRun(id, "CANCELLED", "ENGINEER_CANCELLED", nil)
	})
	return err
}

// Run remains a compatibility lifecycle hook. Jobs are claimed only by enrolled
// agents; no orchestrator worker executes provider inference or owns cancellation.
func (q *Queue) Run(ctx context.Context) { <-ctx.Done() }
