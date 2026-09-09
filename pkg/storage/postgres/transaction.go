package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

// Tx is scoped and callback-local; do not use it concurrently or retain it.
type Tx struct {
	authorityEpoch string
	db             pgx.Tx
	ctx            context.Context
	scope          identity.Scope
}

func (s *Store) Transact(ctx context.Context, scope identity.Scope, fn func(*Tx) error) error {
	if scope.Validate() != nil || fn == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SET LOCAL statement_timeout = '10s'"); err != nil {
		return safeError(err)
	}
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", scope.Key()); err != nil {
		return safeError(err)
	}
	bound := &Tx{db: tx, ctx: ctx, scope: scope, authorityEpoch: s.authorityEpoch()}
	if err = fn(bound); err != nil {
		return err
	}
	return safeError(tx.Commit(ctx))
}

const scopeWhere = "organization_id=$1 AND cluster_id=$2 AND application_id=$3"

func (t *Tx) args(rest ...any) []any {
	return append([]any{t.scope.OrganizationID, t.scope.ClusterID, t.scope.ApplicationID}, rest...)
}
func validState(state string) bool {
	switch state {
	case "OPEN", "INVESTIGATING", "NEEDS_EVIDENCE", "INCONCLUSIVE", "CORROBORATED", "MITIGATED", "RECOVERED", "RESOLVED", "CLOSED":
		return true
	}
	return false
}
func (t *Tx) CreateIncident(i incident.Incident) error {
	if i.Scope != t.scope || !identity.ValidID(i.ID) || i.Version != 1 || !validState(i.State) || i.OpenedAt.IsZero() {
		return ErrInvalid
	}
	if _, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.scopes VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, t.args()...); err != nil {
		return safeError(err)
	}
	_, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.incidents VALUES($1,$2,$3,$4,$5,$6,$7)`, t.args(i.ID, i.Version, i.State, i.OpenedAt)...)
	return safeError(err)
}
func (t *Tx) Incident(id string) (incident.Incident, error) {
	if !identity.ValidID(id) {
		return incident.Incident{}, ErrInvalid
	}
	i := incident.Incident{Scope: t.scope, ID: id}
	err := t.db.QueryRow(t.ctx, "SELECT version,state,opened_at FROM enterprise_core.incidents WHERE "+scopeWhere+" AND id=$4", t.args(id)...).Scan(&i.Version, &i.State, &i.OpenedAt)
	return i, safeError(err)
}
func (t *Tx) UpdateIncident(id string, expectedVersion int64, state string) error {
	if !identity.ValidID(id) || expectedVersion < 1 || !validState(state) {
		return ErrInvalid
	}
	tag, err := t.db.Exec(t.ctx, "UPDATE enterprise_core.incidents SET version=version+1,state=$6 WHERE "+scopeWhere+" AND id=$4 AND version=$5", t.args(id, expectedVersion, state)...)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (t *Tx) Incidents(afterID string, limit int) ([]incident.Incident, error) {
	if (afterID != "" && !identity.ValidID(afterID)) || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, "SELECT id,version,state,opened_at FROM enterprise_core.incidents WHERE "+scopeWhere+" AND id>$4 ORDER BY id LIMIT $5", t.args(afterID, limit)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	items := []incident.Incident{}
	for rows.Next() {
		i := incident.Incident{Scope: t.scope}
		if err := rows.Scan(&i.ID, &i.Version, &i.State, &i.OpenedAt); err != nil {
			return nil, safeError(err)
		}
		items = append(items, i)
	}
	return items, safeError(rows.Err())
}

// ActiveIncident returns the current application episode, retaining recovered
// episodes until explicit closure so recurrence can be recorded separately.
func (t *Tx) ActiveIncident() (incident.Incident, error) {
	i := incident.Incident{Scope: t.scope}
	err := t.db.QueryRow(t.ctx, `SELECT id,version,state,opened_at FROM enterprise_core.incidents WHERE `+scopeWhere+` AND state NOT IN ('CLOSED','RESOLVED') ORDER BY opened_at DESC,id DESC LIMIT 1`, t.args()...).Scan(&i.ID, &i.Version, &i.State, &i.OpenedAt)
	return i, safeError(err)
}
