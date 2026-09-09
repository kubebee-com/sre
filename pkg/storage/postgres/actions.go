package postgres

import (
	"encoding/json"
	"fmt"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

func (t *Tx) Action(id string) (incident.Action, string, error) {
	if !identity.ValidID(id) {
		return incident.Action{}, "", ErrInvalid
	}
	var raw []byte
	var receipt string
	err := t.db.QueryRow(t.ctx, "SELECT envelope,receipt_hash FROM enterprise_core.actions WHERE "+scopeWhere+" AND id=$4", t.args(id)...).Scan(&raw, &receipt)
	if err != nil {
		return incident.Action{}, "", safeError(err)
	}
	var a incident.Action
	if json.Unmarshal(raw, &a) != nil || a.Plan.Scope != t.scope || a.Hash != a.Plan.Hash() {
		return incident.Action{}, "", ErrUnavailable
	}
	return a, receipt, nil
}
func (t *Tx) SaveAction(a incident.Action, expectedVersion int64, receiptHash string) error {
	if a.Plan.Scope != t.scope || !identity.ValidID(a.Plan.ID) || a.Hash != a.Plan.Hash() || a.Version != expectedVersion+1 {
		return ErrInvalid
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return ErrInvalid
	}
	if expectedVersion == 0 {
		_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.actions VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, t.args(a.Plan.ID, a.Plan.IncidentID, a.Version, a.State, raw, receiptHash)...)
	} else {
		var count int64
		tag, e := t.db.Exec(t.ctx, `UPDATE enterprise_core.actions SET version=$6,state=$7,envelope=$8,receipt_hash=$9 WHERE `+scopeWhere+` AND id=$4 AND version=$5`, t.args(a.Plan.ID, expectedVersion, a.Version, a.State, raw, receiptHash)...)
		err = e
		count = tag.RowsAffected()
		if err == nil && count != 1 {
			return ErrConflict
		}
	}
	if err != nil {
		return safeError(err)
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.action_events VALUES($1,$2,$3,$4,$5,$6)`, t.args(a.Plan.ID, a.Version, raw)...)
	return safeError(err)
}
func (t *Tx) Actions(after string, limit int) ([]incident.Action, error) {
	if (after != "" && !identity.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT envelope FROM enterprise_core.actions WHERE `+scopeWhere+` AND id>$4 ORDER BY id LIMIT $5`, t.args(after, limit)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.Action{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, safeError(err)
		}
		var a incident.Action
		if json.Unmarshal(raw, &a) != nil || a.Plan.Scope != t.scope || a.Hash != a.Plan.Hash() {
			return nil, ErrUnavailable
		}
		result = append(result, a)
	}
	return result, safeError(rows.Err())
}

// ExecutorActions filters authorized work before pagination, avoiding starvation
// behind unrelated or terminal historical actions.
func (t *Tx) ExecutorActions(agent incident.Agent, after string, limit int) ([]incident.Action, error) {
	if agent.Scope != t.scope || !identity.ValidID(agent.ID) || agent.Generation < 1 || (after != "" && !identity.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT envelope FROM enterprise_core.actions WHERE `+scopeWhere+` AND state='APPROVED' AND id>$4 AND envelope#>>'{plan,executor_id}'=$5 AND envelope#>>'{plan,executor_generation}'=$6 AND (envelope#>>'{plan,expires_at}')::timestamptz>now() AND (envelope->>'approval_expires_at')::timestamptz>now() AND envelope#>>'{plan,epoch}'=$8 ORDER BY id LIMIT $7`, t.args(after, agent.ID, fmt.Sprint(agent.Generation), limit, agent.Epoch)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.Action{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, safeError(err)
		}
		var a incident.Action
		if json.Unmarshal(raw, &a) != nil || a.Plan.Scope != t.scope || a.Hash != a.Plan.Hash() {
			return nil, ErrUnavailable
		}
		result = append(result, a)
	}
	return result, safeError(rows.Err())
}
