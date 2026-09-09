package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/interaction"
	"time"
)

func (t *Tx) CreateInteraction(r interaction.Request, actor string) error {
	if r.Scope != t.scope || r.Validate(time.Now()) != nil || !identity.ValidID(actor) {
		return ErrInvalid
	}
	if _, err := t.Incident(r.IncidentID); err != nil {
		return err
	}
	// Only link a job after independently establishing scoped incident ownership.
	if r.JobID != "" {
		var found bool
		err := t.db.QueryRow(t.ctx, `SELECT EXISTS(SELECT 1 FROM enterprise_core.diagnostic_jobs WHERE `+scopeWhere+` AND id=$4 AND incident_id=$5)`, t.args(r.JobID, r.IncidentID)...).Scan(&found)
		if err != nil {
			return safeError(err)
		}
		if !found {
			return ErrInvalid
		}
	}
	_, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.interactions(organization_id,cluster_id,application_id,id,incident_id,job_id,kind,question,version,status,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,'PENDING',$9,$10)`, t.args(r.ID, r.IncidentID, r.JobID, r.Kind, r.Question, r.ExpiresAt, actor)...)
	if err != nil {
		return safeError(err)
	}
	payload, _ := json.Marshal(map[string]string{"incident_id": r.IncidentID, "request_id": r.ID, "actor_id": actor})
	return t.Enqueue("interaction_"+r.ID, "CLARIFICATION_REQUESTED", payload)
}

const interactionColumns = `id,incident_id,job_id,kind,question,version,CASE WHEN status='PENDING' AND expires_at<=clock_timestamp() THEN 'EXPIRED' ELSE status END,expires_at,created_by,answer,actor_id,answered_at`

func (t *Tx) Interactions(after string, limit int) ([]interaction.Request, error) {
	if (after != "" && !identity.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT `+interactionColumns+` FROM enterprise_core.interactions WHERE `+scopeWhere+` AND id>$4 ORDER BY id LIMIT $5`, t.args(after, limit)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []interaction.Request{}
	for rows.Next() {
		r := interaction.Request{Scope: t.scope}
		if err := rows.Scan(&r.ID, &r.IncidentID, &r.JobID, &r.Kind, &r.Question, &r.Version, &r.Status, &r.ExpiresAt, &r.CreatedBy, &r.Answer, &r.ActorID, &r.AnsweredAt); err != nil {
			return nil, safeError(err)
		}
		result = append(result, r)
	}
	return result, safeError(rows.Err())
}
func (t *Tx) AnswerInteraction(id string, version int64, answer, actor string) error {
	if !identity.ValidID(id) || !identity.ValidID(actor) || version < 1 {
		return ErrInvalid
	}
	var question string
	err := t.db.QueryRow(t.ctx, `SELECT question FROM enterprise_core.interactions WHERE `+scopeWhere+` AND id=$4`, t.args(id)...).Scan(&question)
	if err != nil {
		return safeError(err)
	}
	if !(interaction.Request{Question: question}).Accepts(answer) {
		return ErrInvalid
	}
	tag, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.interactions SET status='ANSWERED',version=version+1,answer=$6,actor_id=$7,answered_at=clock_timestamp() WHERE `+scopeWhere+` AND id=$4 AND version=$5 AND status='PENDING' AND expires_at>clock_timestamp()`, t.args(id, version, answer, actor)...)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	payload, _ := json.Marshal(map[string]any{"request_id": id, "version": version, "answer": answer, "actor_id": actor})
	return t.Enqueue("answer_"+id, "CLARIFICATION_ANSWERED", payload)
}

// InteractionContext returns the latest unexpired answer for each closed question
// type in this incident. Answers supply context and cannot establish evidence or
// grant permission to execute actions.
func (t *Tx) InteractionContext(incidentID string) ([]interaction.Context, error) {
	if !identity.ValidID(incidentID) {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT DISTINCT ON (question) question,answer FROM enterprise_core.interactions WHERE `+scopeWhere+` AND incident_id=$4 AND status='ANSWERED' AND expires_at>clock_timestamp() ORDER BY question,answered_at DESC,id DESC LIMIT 8`, t.args(incidentID)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []interaction.Context{}
	for rows.Next() {
		var c interaction.Context
		if err := rows.Scan(&c.Question, &c.Answer); err != nil {
			return nil, safeError(err)
		}
		if !(interaction.Request{Question: c.Question}).Accepts(c.Answer) {
			return nil, ErrInvalid
		}
		result = append(result, c)
	}
	return result, safeError(rows.Err())
}
