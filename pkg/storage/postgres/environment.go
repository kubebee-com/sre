package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/incident"
)

func (t *Tx) EnvironmentContext() (incident.EnvironmentContext, error) {
	var raw []byte
	err := t.db.QueryRow(t.ctx, `SELECT envelope FROM enterprise_core.environment_contexts WHERE `+scopeWhere+` ORDER BY version DESC LIMIT 1`, t.args()...).Scan(&raw)
	if err != nil {
		return incident.EnvironmentContext{}, safeError(err)
	}
	var c incident.EnvironmentContext
	if json.Unmarshal(raw, &c) != nil || c.Scope != t.scope {
		return c, ErrUnavailable
	}
	return c, nil
}
func (t *Tx) PutEnvironmentContext(c incident.EnvironmentContext) error {
	if c.Scope != t.scope || c.Version < 1 {
		return ErrInvalid
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return ErrInvalid
	}
	if _, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.scopes VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, t.args()...); err != nil {
		return safeError(err)
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.environment_contexts VALUES($1,$2,$3,$4,$5)`, t.args(c.Version, raw)...)
	return safeError(err)
}
