package postgres

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"time"
)

func (t *Tx) CreateBootstrap(b incident.AgentBootstrap) error {
	a := b.Agent
	if a.Scope != t.scope || !identity.ValidID(a.ID) || !identity.ValidID(a.ClusterUID) || len(b.TokenHash) != 64 || !identity.ValidID(a.Epoch) || (a.Role != "COLLECTOR" && a.Role != "EXECUTOR") {
		return ErrInvalid
	}
	if _, err := t.db.Exec(t.ctx, "INSERT INTO enterprise_core.scopes VALUES($1,$2,$3) ON CONFLICT DO NOTHING", t.args()...); err != nil {
		return safeError(err)
	}
	_, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.agent_bootstraps(organization_id,cluster_id,application_id,token_hash,agent_id,role,audience,epoch,cluster_uid,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, t.args(b.TokenHash, a.ID, a.Role, a.Audience, a.Epoch, a.ClusterUID, b.ExpiresAt)...)
	return safeError(err)
}
func (t *Tx) ConsumeBootstrap(hash, uid, role, audience, epoch, credentialHash string, expires time.Time) (incident.Agent, error) {
	var id string
	err := t.db.QueryRow(t.ctx, "UPDATE enterprise_core.agent_bootstraps SET consumed_at=now() WHERE "+scopeWhere+" AND token_hash=$4 AND cluster_uid=$5 AND role=$6 AND audience=$7 AND epoch=$8 AND consumed_at IS NULL AND expires_at>now() RETURNING agent_id", t.args(hash, uid, role, audience, epoch)...).Scan(&id)
	if err != nil {
		return incident.Agent{}, safeError(err)
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.agents(organization_id,cluster_id,application_id,id,role,audience,epoch,generation,cluster_uid,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10) ON CONFLICT(organization_id,cluster_id,application_id,id) DO UPDATE SET role=EXCLUDED.role,audience=EXCLUDED.audience,epoch=EXCLUDED.epoch,generation=enterprise_core.agents.generation+1,cluster_uid=EXCLUDED.cluster_uid,token_hash=EXCLUDED.token_hash,expires_at=EXCLUDED.expires_at,revoked=false`, t.args(id, role, audience, epoch, uid, credentialHash, expires)...)
	if err != nil {
		return incident.Agent{}, safeError(err)
	}
	return t.AgentByToken(credentialHash)
}
func (t *Tx) AgentByToken(hash string) (incident.Agent, error) {
	if len(hash) != 64 {
		return incident.Agent{}, ErrInvalid
	}
	a := incident.Agent{Scope: t.scope}
	err := t.db.QueryRow(t.ctx, "SELECT id,role,audience,epoch,generation,cluster_uid,expires_at,revoked FROM enterprise_core.agents WHERE "+scopeWhere+" AND token_hash=$4", t.args(hash)...).Scan(&a.ID, &a.Role, &a.Audience, &a.Epoch, &a.Generation, &a.ClusterUID, &a.ExpiresAt, &a.Revoked)
	return a, safeError(err)
}
func (t *Tx) AgentByID(id string) (incident.Agent, error) {
	a := incident.Agent{Scope: t.scope}
	err := t.db.QueryRow(t.ctx, "SELECT id,role,audience,epoch,generation,cluster_uid,expires_at,revoked FROM enterprise_core.agents WHERE "+scopeWhere+" AND id=$4", t.args(id)...).Scan(&a.ID, &a.Role, &a.Audience, &a.Epoch, &a.Generation, &a.ClusterUID, &a.ExpiresAt, &a.Revoked)
	return a, safeError(err)
}
func (t *Tx) RevokeAgent(id string) error {
	if !identity.ValidID(id) {
		return ErrInvalid
	}
	if _, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.agent_revocations SELECT organization_id,cluster_id,application_id,id,epoch,generation FROM enterprise_core.agents WHERE `+scopeWhere+` AND id=$4 ON CONFLICT DO NOTHING`, t.args(id)...); err != nil {
		return safeError(err)
	}
	tag, err := t.db.Exec(t.ctx, "UPDATE enterprise_core.agents SET revoked=true,generation=generation+1 WHERE "+scopeWhere+" AND id=$4", t.args(id)...)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}
func (t *Tx) RotateAgent(id string, generation int64, hash string, expires time.Time) (incident.Agent, error) {
	if !identity.ValidID(id) || generation < 1 || len(hash) != 64 {
		return incident.Agent{}, ErrInvalid
	}
	tag, err := t.db.Exec(t.ctx, "UPDATE enterprise_core.agents SET token_hash=$6,expires_at=$7,generation=generation+1 WHERE "+scopeWhere+" AND id=$4 AND generation=$5 AND revoked=false", t.args(id, generation, hash, expires)...)
	if err != nil {
		return incident.Agent{}, safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return incident.Agent{}, ErrConflict
	}
	return t.AgentByToken(hash)
}

func (t *Tx) Agents() ([]incident.Agent, error) {
	rows, err := t.db.Query(t.ctx, `SELECT id,role,audience,epoch,generation,cluster_uid,expires_at,revoked FROM enterprise_core.agents WHERE `+scopeWhere+` ORDER BY id LIMIT 100`, t.args()...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.Agent{}
	for rows.Next() {
		a := incident.Agent{Scope: t.scope}
		if err := rows.Scan(&a.ID, &a.Role, &a.Audience, &a.Epoch, &a.Generation, &a.ClusterUID, &a.ExpiresAt, &a.Revoked); err != nil {
			return nil, safeError(err)
		}
		result = append(result, a)
	}
	return result, safeError(rows.Err())
}
