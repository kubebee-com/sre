package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

func (t *Tx) CurrentItem(id string) (incident.Item, error) {
	if !identity.ValidID(id) {
		return incident.Item{}, ErrInvalid
	}
	var raw []byte
	err := t.db.QueryRow(t.ctx, "SELECT envelope FROM enterprise_core.items WHERE "+scopeWhere+" AND id=$4 ORDER BY version DESC LIMIT 1", t.args(id)...).Scan(&raw)
	if err != nil {
		return incident.Item{}, safeError(err)
	}
	return decodeItem(raw)
}
func (t *Tx) FeedbackForKey(actor, key string) (incident.FeedbackEvent, error) {
	if !identity.ValidID(actor) || !identity.ValidID(key) {
		return incident.FeedbackEvent{}, ErrInvalid
	}
	var raw []byte
	err := t.db.QueryRow(t.ctx, "SELECT event FROM enterprise_core.feedback WHERE "+scopeWhere+" AND actor_id=$4 AND idempotency_key=$5", t.args(actor, key)...).Scan(&raw)
	if err != nil {
		return incident.FeedbackEvent{}, safeError(err)
	}
	var event incident.FeedbackEvent
	if json.Unmarshal(raw, &event) != nil {
		return event, ErrUnavailable
	}
	return event, nil
}
func (t *Tx) FeedbackByID(id string) (incident.FeedbackEvent, error) {
	if !identity.ValidID(id) {
		return incident.FeedbackEvent{}, ErrInvalid
	}
	var raw []byte
	err := t.db.QueryRow(t.ctx, "SELECT event FROM enterprise_core.feedback WHERE "+scopeWhere+" AND id=$4", t.args(id)...).Scan(&raw)
	if err != nil {
		return incident.FeedbackEvent{}, safeError(err)
	}
	var event incident.FeedbackEvent
	if json.Unmarshal(raw, &event) != nil {
		return event, ErrUnavailable
	}
	return event, nil
}
func (t *Tx) AddFeedback(event incident.FeedbackEvent) error {
	if event.Scope != t.scope || !identity.ValidID(event.ID) || !identity.ValidID(event.ActorID) || !identity.ValidID(event.IdempotencyKey) || event.At.IsZero() || !validRef(event.Item) {
		return ErrInvalid
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return ErrInvalid
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.feedback VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, t.args(event.IncidentID, event.ID, event.ActorID, event.IdempotencyKey, event.Item.ID, event.Item.Version, event.RequestHash, raw, event.At)...)
	return safeError(err)
}
func (t *Tx) FeedbackHistory(ref incident.ItemRef, limit int) ([]incident.FeedbackEvent, error) {
	if !validRef(ref) || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, "SELECT event FROM enterprise_core.feedback WHERE "+scopeWhere+" AND item_id=$4 AND item_version=$5 ORDER BY created_at DESC,id DESC LIMIT $6", t.args(ref.ID, ref.Version, limit)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	events := []incident.FeedbackEvent{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, safeError(err)
		}
		var event incident.FeedbackEvent
		if json.Unmarshal(raw, &event) != nil {
			return nil, ErrUnavailable
		}
		events = append(events, event)
	}
	return events, safeError(rows.Err())
}
