package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"time"
)

const DiagnosticLeaseDuration = 30 * time.Second

type DiagnosticLease struct {
	Job          incident.DiagnosticJob `json:"job"`
	AttemptID    string                 `json:"attempt_id"`
	LeaseUntil   time.Time              `json:"lease_until"`
	Authority    string                 `json:"-"`
	Input        json.RawMessage        `json:"-"`
	RefreshCount int                    `json:"-"`
}

// ClaimAgentDiagnostic serializes application capacity through the scope transaction
// lock. Only read-only work is recovered; execution retains its separate journal.
func (t *Tx) ClaimAgentDiagnostic(a incident.Agent, profiles []string) (DiagnosticLease, error) {
	l := DiagnosticLease{Job: incident.DiagnosticJob{Scope: t.scope}}
	if a.Scope != t.scope || a.Role != "COLLECTOR" || len(profiles) == 0 || len(profiles) > 32 {
		return l, ErrInvalid
	}
	for _, p := range profiles {
		if !identity.ValidID(p) {
			return l, ErrInvalid
		}
	}
	// Expired authority is terminal. An expired worker lease with live authority is
	// reclaimable, with a fresh attempt identity and a fresh authoritative snapshot.
	_, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.investigation_runs SET status='CANCELLED',reason='AUTHORITY_EXPIRED',finished_at=clock_timestamp() WHERE `+scopeWhere+` AND id IN (SELECT id FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND state IN ('QUEUED','RUNNING') AND expires_at<=clock_timestamp()) AND status IN ('QUEUED','RUNNING')`, t.args()...)
	if err != nil {
		return l, safeError(err)
	}
	_, err = t.db.Exec(t.ctx, `UPDATE enterprise_core.diagnostic_jobs SET state='CANCELLED',authority='',input=NULL WHERE `+scopeWhere+` AND state IN ('QUEUED','RUNNING') AND expires_at<=clock_timestamp()`, t.args()...)
	if err != nil {
		return l, safeError(err)
	}
	_, err = t.db.Exec(t.ctx, `UPDATE enterprise_core.diagnostic_jobs SET state='QUEUED',input=NULL WHERE `+scopeWhere+` AND state='RUNNING' AND (lease_until IS NULL OR lease_until<=clock_timestamp())`, t.args()...)
	if err != nil {
		return l, safeError(err)
	}
	l.AttemptID = identity.NewID()
	err = t.db.QueryRow(t.ctx, `UPDATE enterprise_core.diagnostic_jobs SET state='RUNNING',agent_id=$4,agent_generation=$5,agent_epoch=$6,attempt_id=$7,lease_until=LEAST(expires_at,clock_timestamp()+interval '30 seconds'),input=NULL,refresh_count=0 WHERE `+scopeWhere+` AND id=(SELECT id FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND state='QUEUED' AND profile_id=ANY($8) AND expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND state='RUNNING') ORDER BY created_at,id LIMIT 1) RETURNING id,incident_id,profile_id,actor_id,state,created_at,expires_at,authority,lease_until`, t.args(a.ID, a.Generation, a.Epoch, l.AttemptID, profiles)...).Scan(&l.Job.ID, &l.Job.IncidentID, &l.Job.ProfileID, &l.Job.ActorID, &l.Job.State, &l.Job.CreatedAt, &l.Job.ExpiresAt, &l.Authority, &l.LeaseUntil)
	return l, safeError(err)
}

func (t *Tx) AgentDiagnostic(id, attempt string, a incident.Agent, renew bool) (DiagnosticLease, error) {
	l := DiagnosticLease{Job: incident.DiagnosticJob{Scope: t.scope}, AttemptID: attempt}
	if !identity.ValidID(id) || !identity.ValidID(attempt) || a.Scope != t.scope || a.Role != "COLLECTOR" {
		return l, ErrInvalid
	}
	where := scopeWhere + ` AND id=$4 AND attempt_id=$5 AND agent_id=$6 AND agent_generation=$7 AND agent_epoch=$8 AND state='RUNNING' AND expires_at>clock_timestamp() AND lease_until>clock_timestamp()`
	args := t.args(id, attempt, a.ID, a.Generation, a.Epoch)
	if renew {
		tag, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.diagnostic_jobs SET lease_until=LEAST(expires_at,clock_timestamp()+interval '30 seconds') WHERE `+where, args...)
		if err != nil {
			return l, safeError(err)
		}
		if tag.RowsAffected() != 1 {
			return l, ErrNotFound
		}
	}
	err := t.db.QueryRow(t.ctx, `SELECT id,incident_id,profile_id,actor_id,state,created_at,expires_at,authority,lease_until,input,refresh_count FROM enterprise_core.diagnostic_jobs WHERE `+where, args...).Scan(&l.Job.ID, &l.Job.IncidentID, &l.Job.ProfileID, &l.Job.ActorID, &l.Job.State, &l.Job.CreatedAt, &l.Job.ExpiresAt, &l.Authority, &l.LeaseUntil, &l.Input, &l.RefreshCount)
	return l, safeError(err)
}

func (t *Tx) SetDiagnosticInput(id, attempt string, input []byte, refresh bool) error {
	if len(input) > 65536 || !json.Valid(input) {
		return ErrInvalid
	}
	delta := 0
	if refresh {
		delta = 1
	}
	tag, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.diagnostic_jobs SET input=$6,refresh_count=refresh_count+$7 WHERE `+scopeWhere+` AND id=$4 AND attempt_id=$5 AND state='RUNNING' AND lease_until>clock_timestamp() AND expires_at>clock_timestamp() AND refresh_count+$7<=2`, t.args(id, attempt, input, delta)...)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// StartAgentDiagnostic verifies the pinned profile version recorded at enqueue.
func (t *Tx) StartAgentDiagnostic(id, profileVersion, promptVersion, rubricVersion string) error {
	tag, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.investigation_runs SET status='RUNNING' WHERE `+scopeWhere+` AND id=$4 AND profile_version=$5 AND prompt_version=$6 AND rubric_version=$7 AND status IN ('QUEUED','RUNNING')`, t.args(id, profileVersion, promptVersion, rubricVersion)...)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
