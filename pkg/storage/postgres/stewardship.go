package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

func (t *Tx) PutAdjudication(a incident.Adjudication) error {
	if a.Scope != t.scope || !identity.ValidID(a.ID) || !validRef(a.Item) {
		return ErrInvalid
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return ErrInvalid
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.adjudications VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.args(a.ID, a.IncidentID, a.Item.ID, a.Item.Version, a.ActorID, a.IdempotencyKey, raw, a.At)...)
	return safeError(err)
}
func (t *Tx) AdjudicationForKey(actor, key string) (incident.Adjudication, error) {
	var raw []byte
	err := t.db.QueryRow(t.ctx, `SELECT envelope FROM enterprise_core.adjudications WHERE `+scopeWhere+` AND actor_id=$4 AND idempotency_key=$5`, t.args(actor, key)...).Scan(&raw)
	if err != nil {
		return incident.Adjudication{}, safeError(err)
	}
	var a incident.Adjudication
	if json.Unmarshal(raw, &a) != nil || a.Scope != t.scope {
		return a, ErrUnavailable
	}
	return a, nil
}
func (t *Tx) Adjudications(ref incident.ItemRef, limit int) ([]incident.Adjudication, error) {
	if !validRef(ref) || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT envelope FROM enterprise_core.adjudications WHERE `+scopeWhere+` AND item_id=$4 AND item_version=$5 ORDER BY created_at DESC,id DESC LIMIT $6`, t.args(ref.ID, ref.Version, limit)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.Adjudication{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, safeError(err)
		}
		var a incident.Adjudication
		if json.Unmarshal(raw, &a) != nil || a.Scope != t.scope {
			return nil, ErrUnavailable
		}
		result = append(result, a)
	}
	return result, safeError(rows.Err())
}
