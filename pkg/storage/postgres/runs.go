package postgres

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"time"
)

func (t *Tx) StartRun(id, incidentID, profile, profileVersion, prompt, rubric string, at time.Time) error {
	if !identity.ValidID(id) || !identity.ValidID(incidentID) || at.IsZero() {
		return ErrInvalid
	}
	tag, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.investigation_runs(organization_id,cluster_id,application_id,id,incident_id,profile_id,profile_version,prompt_version,rubric_version,status,reason,started_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'RUNNING','', $10) ON CONFLICT(organization_id,cluster_id,application_id,id) DO UPDATE SET status='RUNNING' WHERE enterprise_core.investigation_runs.status='QUEUED' AND enterprise_core.investigation_runs.incident_id=EXCLUDED.incident_id AND enterprise_core.investigation_runs.profile_id=EXCLUDED.profile_id`, t.args(id, incidentID, profile, profileVersion, prompt, rubric, at)...)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
func (t *Tx) FinishRun(id, status, reason string, ref *incident.ItemRef) error {
	if !identity.ValidID(id) {
		return ErrInvalid
	}
	var claimID any
	var version any
	if ref != nil {
		claimID = ref.ID
		version = ref.Version
	}
	_, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.investigation_runs SET status=$5,reason=$6,finished_at=now(),claim_id=$7,claim_version=$8 WHERE `+scopeWhere+` AND id=$4 AND status IN ('RUNNING','QUEUED')`, t.args(id, status, reason, claimID, version)...)
	return safeError(err)
}
func (t *Tx) InterruptRuns() error {
	_, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.investigation_runs SET status='INTERRUPTED',reason='CONTROL_PLANE_RESTART',finished_at=now() WHERE `+scopeWhere+` AND status IN ('RUNNING','QUEUED')`, t.args()...)
	return safeError(err)
}

func (t *Tx) QueueRun(id string) error {
	_, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.investigation_runs SET status='QUEUED' WHERE `+scopeWhere+` AND id=$4 AND status='RUNNING'`, t.args(id)...)
	return safeError(err)
}
