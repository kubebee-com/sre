package postgres

import (
	"bytes"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

func (t *Tx) EnqueueOnce(key, kind string, payload json.RawMessage) (bool, error) {
	if !identity.ValidID(key) || !identity.ValidID(kind) {
		return false, ErrInvalid
	}
	canonical, err := incident.CanonicalObject(payload)
	if err != nil {
		return false, ErrInvalid
	}
	tag, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.outbox(organization_id,cluster_id,application_id,id,event_key,kind,payload) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(organization_id,cluster_id,application_id,event_key) DO NOTHING`, t.args(identity.NewID(), key, kind, canonical)...)
	if err != nil {
		return false, safeError(err)
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	var previousKind string
	var previous []byte
	err = t.db.QueryRow(t.ctx, "SELECT kind,payload FROM enterprise_core.outbox WHERE "+scopeWhere+" AND event_key=$4", t.args(key)...).Scan(&previousKind, &previous)
	if err != nil {
		return false, safeError(err)
	}
	previous, err = incident.CanonicalObject(previous)
	if err != nil {
		return false, ErrUnavailable
	}
	if kind != previousKind || !bytes.Equal(canonical, previous) {
		return false, ErrConflict
	}
	return false, nil
}

func (t *Tx) Enqueue(key, kind string, payload json.RawMessage) error {
	_, err := t.EnqueueOnce(key, kind, payload)
	return err
}
