package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

func (t *Tx) PutDiagnosticJob(j incident.DiagnosticJob, authority string) error {
	if j.Scope != t.scope || !identity.ValidID(j.ID) || len(authority) > 65536 || j.State != "QUEUED" {
		return ErrInvalid
	}
	var count int
	if err := t.db.QueryRow(t.ctx, `SELECT count(*) FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND state IN ('QUEUED','RUNNING')`, t.args()...).Scan(&count); err != nil {
		return safeError(err)
	}
	if count >= 8 {
		return ErrConflict
	}
	_, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.diagnostic_jobs(organization_id,cluster_id,application_id,id,incident_id,profile_id,actor_id,state,created_at,expires_at,authority) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.args(j.ID, j.IncidentID, j.ProfileID, j.ActorID, j.State, j.CreatedAt, j.ExpiresAt, authority)...)
	return safeError(err)
}
func (t *Tx) ActiveDiagnosticJob(incidentID string) (incident.DiagnosticJob, error) {
	j := incident.DiagnosticJob{Scope: t.scope}
	err := t.db.QueryRow(t.ctx, `SELECT id,incident_id,profile_id,actor_id,state,created_at,expires_at FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND incident_id=$4 AND state IN ('QUEUED','RUNNING') LIMIT 1`, t.args(incidentID)...).Scan(&j.ID, &j.IncidentID, &j.ProfileID, &j.ActorID, &j.State, &j.CreatedAt, &j.ExpiresAt)
	return j, safeError(err)
}
func (t *Tx) ClaimDiagnosticJob() (incident.DiagnosticJob, string, error) {
	j := incident.DiagnosticJob{Scope: t.scope}
	var authority string
	err := t.db.QueryRow(t.ctx, `UPDATE enterprise_core.diagnostic_jobs SET state='RUNNING' WHERE `+scopeWhere+` AND id=(SELECT id FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND state='QUEUED' AND NOT EXISTS(SELECT 1 FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND state='RUNNING') ORDER BY created_at,id LIMIT 1) RETURNING id,incident_id,profile_id,actor_id,state,created_at,expires_at,authority`, t.args()...).Scan(&j.ID, &j.IncidentID, &j.ProfileID, &j.ActorID, &j.State, &j.CreatedAt, &j.ExpiresAt, &authority)
	return j, authority, safeError(err)
}
func (t *Tx) DiagnosticJob(id string) (incident.DiagnosticJob, error) {
	j := incident.DiagnosticJob{Scope: t.scope}
	if !identity.ValidID(id) {
		return j, ErrInvalid
	}
	var raw []byte
	err := t.db.QueryRow(t.ctx, `SELECT id,incident_id,profile_id,actor_id,state,created_at,expires_at,result FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND id=$4`, t.args(id)...).Scan(&j.ID, &j.IncidentID, &j.ProfileID, &j.ActorID, &j.State, &j.CreatedAt, &j.ExpiresAt, &raw)
	if err != nil {
		return j, safeError(err)
	}
	if len(raw) > 0 && json.Unmarshal(raw, &j.Result) != nil {
		return j, ErrUnavailable
	}
	return j, nil
}
func (t *Tx) FinishDiagnosticJob(id, state string, result *incident.ItemRef) error {
	if !identity.ValidID(id) || (state != "COMPLETED" && state != "CANCELLED" && state != "FAILED") {
		return ErrInvalid
	}
	var raw any
	if result != nil {
		raw, _ = json.Marshal(result)
	}
	_, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.diagnostic_jobs SET state=$5,result=$6,authority='',input=NULL,lease_until=NULL WHERE `+scopeWhere+` AND id=$4 AND state IN ('QUEUED','RUNNING')`, t.args(id, state, raw)...)
	return safeError(err)
}
func (t *Tx) DiagnosticJobs(incidentID string) ([]incident.DiagnosticJob, error) {
	if !identity.ValidID(incidentID) {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT id,incident_id,profile_id,actor_id,state,created_at,expires_at,result FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND incident_id=$4 ORDER BY created_at DESC,id DESC LIMIT 50`, t.args(incidentID)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.DiagnosticJob{}
	for rows.Next() {
		j := incident.DiagnosticJob{Scope: t.scope}
		var raw []byte
		if err := rows.Scan(&j.ID, &j.IncidentID, &j.ProfileID, &j.ActorID, &j.State, &j.CreatedAt, &j.ExpiresAt, &raw); err != nil {
			return nil, safeError(err)
		}
		if len(raw) > 0 && json.Unmarshal(raw, &j.Result) != nil {
			return nil, ErrUnavailable
		}
		result = append(result, j)
	}
	return result, safeError(rows.Err())
}
func (t *Tx) InterruptDiagnosticJobs() error {
	_, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.diagnostic_jobs SET state='CANCELLED',authority='' WHERE `+scopeWhere+` AND state IN ('QUEUED','RUNNING')`, t.args()...)
	return safeError(err)
}
