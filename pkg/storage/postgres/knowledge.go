package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

func (t *Tx) HistoricalEligible(ref incident.ItemRef) (bool, error) {
	if !validRef(ref) {
		return false, ErrInvalid
	}
	ok, err := t.Uncontested(ref)
	if err != nil || !ok {
		return false, err
	}
	var allowed bool
	err = t.db.QueryRow(t.ctx, ``+lineageSQL+` SELECT COALESCE(bool_and(i.kind<>'EVIDENCE' OR EXISTS(
 SELECT 1 FROM enterprise_core.agents a WHERE a.organization_id=$1 AND a.cluster_id=$2 AND a.application_id=$3 AND a.id=i.envelope#>>'{body,source,agent_id}' AND a.role='COLLECTOR' AND NOT a.revoked AND a.epoch=i.envelope#>>'{body,source,epoch}' AND ($6='' OR a.epoch=$6)
 AND NOT EXISTS(SELECT 1 FROM enterprise_core.agent_revocations r WHERE r.organization_id=$1 AND r.cluster_id=$2 AND r.application_id=$3 AND r.agent_id=a.id AND r.epoch=a.epoch AND r.through_generation >= (i.envelope#>>'{body,source,generation}')::bigint)
 )),false) FROM lineage l JOIN enterprise_core.items i ON i.organization_id=$1 AND i.cluster_id=$2 AND i.application_id=$3 AND i.id=l.id AND i.version=l.version`, t.args(ref.ID, ref.Version, t.authorityEpoch)...).Scan(&allowed)
	return allowed, safeError(err)
}
func (t *Tx) PutGoldenCase(g incident.GoldenCase) error {
	if g.Scope != t.scope || !identity.ValidID(g.ID) || g.Version < 1 {
		return ErrInvalid
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return ErrInvalid
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.golden_cases VALUES($1,$2,$3,$4,$5,$6,$7)`, t.args(g.ID, g.Version, g.State, raw)...)
	return safeError(err)
}
func (t *Tx) GoldenCase(id string) (incident.GoldenCase, error) {
	if !identity.ValidID(id) {
		return incident.GoldenCase{}, ErrInvalid
	}
	var raw []byte
	err := t.db.QueryRow(t.ctx, `SELECT envelope FROM enterprise_core.golden_cases WHERE `+scopeWhere+` AND id=$4 ORDER BY version DESC LIMIT 1`, t.args(id)...).Scan(&raw)
	if err != nil {
		return incident.GoldenCase{}, safeError(err)
	}
	var g incident.GoldenCase
	if json.Unmarshal(raw, &g) != nil || g.Scope != t.scope {
		return g, ErrUnavailable
	}
	return g, nil
}
func (t *Tx) GoldenCases(after string, limit int) ([]incident.GoldenCase, error) {
	if (after != "" && !identity.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT DISTINCT ON(id) envelope FROM enterprise_core.golden_cases WHERE `+scopeWhere+` AND id>$4 ORDER BY id,version DESC LIMIT $5`, t.args(after, limit)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.GoldenCase{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, safeError(err)
		}
		var g incident.GoldenCase
		if json.Unmarshal(raw, &g) != nil || g.Scope != t.scope {
			return nil, ErrUnavailable
		}
		result = append(result, g)
	}
	return result, safeError(rows.Err())
}
