package postgres

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"time"
)

func (t *Tx) PutCollectionCheck(c incident.CollectionCheck) error {
	if c.Scope != t.scope || !identity.ValidID(c.ID) || !identity.ValidID(c.AgentID) || c.Generation < 1 {
		return ErrInvalid
	}
	_, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.collection_checks VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL)`, t.args(c.ID, c.IncidentID, c.AgentID, c.Generation, c.Handle, c.Kind, c.CreatedAt, c.ExpiresAt)...)
	return safeError(err)
}
func (t *Tx) CollectionRequested(agent incident.Agent) (bool, error) {
	if agent.Scope != t.scope {
		return false, ErrInvalid
	}
	var requested bool
	err := t.db.QueryRow(t.ctx, `SELECT EXISTS(SELECT 1 FROM enterprise_core.collection_checks WHERE `+scopeWhere+` AND agent_id=$4 AND generation=$5 AND expires_at>now() AND fulfilled_at IS NULL)`, t.args(agent.ID, agent.Generation)...).Scan(&requested)
	return requested, safeError(err)
}
func (t *Tx) FulfillCollectionChecks(agent incident.Agent, handle string, at time.Time) error {
	if agent.Scope != t.scope {
		return ErrInvalid
	}
	_, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.collection_checks SET fulfilled_at=$7 WHERE `+scopeWhere+` AND agent_id=$4 AND generation=$5 AND handle=$6 AND created_at<=$7 AND expires_at>=$7 AND fulfilled_at IS NULL`, t.args(agent.ID, agent.Generation, handle, at)...)
	return safeError(err)
}
func (t *Tx) CollectionCheckReady(id string) (bool, error) {
	if !identity.ValidID(id) {
		return false, ErrInvalid
	}
	var ready bool
	err := t.db.QueryRow(t.ctx, `SELECT fulfilled_at IS NOT NULL FROM enterprise_core.collection_checks WHERE `+scopeWhere+` AND id=$4`, t.args(id)...).Scan(&ready)
	return ready, safeError(err)
}
