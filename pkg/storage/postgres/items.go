package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"time"
)

func validRef(ref incident.ItemRef) bool { return identity.ValidID(ref.ID) && ref.Version > 0 }
func (t *Tx) PutItem(item incident.Item) error {
	if item.Scope != t.scope || item.Seal() != nil {
		return ErrInvalid
	}
	// Parents must already exist in this incident. This also prevents dependency cycles.
	for _, ref := range item.Parents {
		parent, err := t.Item(ref)
		if err != nil {
			if err == ErrNotFound {
				return ErrInvalid
			}
			return err
		}
		if parent.IncidentID != item.IncidentID {
			return ErrInvalid
		}
	}
	envelope, err := json.Marshal(item)
	if err != nil {
		return ErrInvalid
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.items(organization_id,cluster_id,application_id,incident_id,id,version,kind,envelope,hash,observed_at,valid_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.args(item.IncidentID, item.ID, item.Version, string(item.Kind), envelope, item.Hash, item.ObservedAt, item.ValidUntil)...)
	if err != nil {
		return safeError(err)
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.item_eligibility(organization_id,cluster_id,application_id,item_id,item_version) VALUES($1,$2,$3,$4,$5)`, t.args(item.ID, item.Version)...)
	if err != nil {
		return safeError(err)
	}
	for _, ref := range item.Parents {
		_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.item_parents VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.args(item.IncidentID, item.ID, item.Version, ref.ID, ref.Version)...)
		if err != nil {
			return safeError(err)
		}
	}
	return t.linkGuidance(item)
}
func decodeItem(raw []byte) (incident.Item, error) {
	var item incident.Item
	if json.Unmarshal(raw, &item) != nil {
		return item, ErrUnavailable
	}
	stored := item.Hash
	if item.Seal() != nil || item.Hash != stored {
		return incident.Item{}, ErrUnavailable
	}
	return item, nil
}
func (t *Tx) Item(ref incident.ItemRef) (incident.Item, error) {
	if !validRef(ref) {
		return incident.Item{}, ErrInvalid
	}
	var raw []byte
	if err := t.db.QueryRow(t.ctx, "SELECT envelope FROM enterprise_core.items WHERE "+scopeWhere+" AND id=$4 AND version=$5", t.args(ref.ID, ref.Version)...).Scan(&raw); err != nil {
		return incident.Item{}, safeError(err)
	}
	item, err := decodeItem(raw)
	if err == nil && item.Scope != t.scope {
		return incident.Item{}, ErrUnavailable
	}
	return item, err
}

// Items returns the latest immutable version of each item, ordered by ID.
func (t *Tx) Items(incidentID, afterID string, limit int) ([]incident.Item, error) {
	if !identity.ValidID(incidentID) || (afterID != "" && !identity.ValidID(afterID)) || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, "SELECT DISTINCT ON(id) envelope FROM enterprise_core.items WHERE "+scopeWhere+" AND incident_id=$4 AND id>$5 ORDER BY id,version DESC LIMIT $6", t.args(incidentID, afterID, limit)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.Item{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, safeError(err)
		}
		item, err := decodeItem(raw)
		if err != nil || item.Scope != t.scope {
			return nil, ErrUnavailable
		}
		result = append(result, item)
	}
	return result, safeError(rows.Err())
}
func (t *Tx) Quarantine(ref incident.ItemRef) error {
	if !validRef(ref) {
		return ErrInvalid
	}
	tag, err := t.db.Exec(t.ctx, "UPDATE enterprise_core.item_eligibility SET quarantined=true WHERE "+scopeWhere+" AND item_id=$4 AND item_version=$5", t.args(ref.ID, ref.Version)...)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}
func (t *Tx) Eligible(ref incident.ItemRef, at time.Time) (bool, error) {
	if !validRef(ref) || at.IsZero() {
		return false, ErrInvalid
	}
	var eligible bool
	err := t.db.QueryRow(t.ctx, ``+lineageSQL+` SELECT COALESCE(bool_and(COALESCE(NOT e.quarantined,false) AND (l.historic OR (i.observed_at<=$6 AND i.valid_until>$6)) AND (i.kind<>'EVIDENCE' OR
 ($7='' AND i.envelope#>>'{body,source,epoch}' IS NULL) OR EXISTS (
 SELECT 1 FROM enterprise_core.agents a WHERE a.organization_id=$1 AND a.cluster_id=$2 AND a.application_id=$3
 AND a.id=i.envelope#>>'{body,source,agent_id}' AND (l.historic OR a.generation::text=i.envelope#>>'{body,source,generation}')
 AND a.epoch=i.envelope#>>'{body,source,epoch}' AND ($7='' OR a.epoch=$7) AND a.role='COLLECTOR' AND NOT a.revoked AND (l.historic OR a.expires_at>$6)
 AND NOT EXISTS(SELECT 1 FROM enterprise_core.agent_revocations r WHERE r.organization_id=$1 AND r.cluster_id=$2 AND r.application_id=$3 AND r.agent_id=a.id AND r.epoch=a.epoch AND r.through_generation >= (i.envelope#>>'{body,source,generation}')::bigint)
 ))),false)
 FROM lineage l
 LEFT JOIN enterprise_core.items i ON i.organization_id=$1 AND i.cluster_id=$2 AND i.application_id=$3 AND i.id=l.id AND i.version=l.version
 LEFT JOIN enterprise_core.item_eligibility e ON e.organization_id=$1 AND e.cluster_id=$2 AND e.application_id=$3 AND e.item_id=l.id AND e.item_version=l.version`, t.args(ref.ID, ref.Version, at, t.authorityEpoch)...).Scan(&eligible)
	return eligible, safeError(err)
}

// CurrentEvidence selects latest versions before freshness filtering so expired
// replacements never resurrect older evidence. Claims do not consume the budget.
func (t *Tx) CurrentEvidence(incidentID string, at time.Time, limit int) ([]incident.Item, error) {
	if !identity.ValidID(incidentID) || at.IsZero() || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT envelope FROM (
 SELECT DISTINCT ON(id) id,kind,envelope,observed_at,valid_until FROM enterprise_core.items
 WHERE `+scopeWhere+` AND incident_id=$4 ORDER BY id,version DESC
 ) latest WHERE kind='EVIDENCE' AND observed_at<=$5 AND valid_until>$5 ORDER BY id LIMIT $6`, t.args(incidentID, at, limit)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.Item{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, safeError(err)
		}
		item, err := decodeItem(raw)
		if err != nil || item.Scope != t.scope {
			return nil, ErrUnavailable
		}
		result = append(result, item)
	}
	return result, safeError(rows.Err())
}

// Uncontested checks immutable historic lineage without pretending old evidence
// is fresh. Callers must separately enforce current observations and authority.
func (t *Tx) Uncontested(ref incident.ItemRef) (bool, error) {
	if !validRef(ref) {
		return false, ErrInvalid
	}
	var ok bool
	err := t.db.QueryRow(t.ctx, ``+lineageSQL+` SELECT COALESCE(bool_and(COALESCE(NOT e.quarantined,false)),false) FROM lineage l LEFT JOIN enterprise_core.item_eligibility e ON e.organization_id=$1 AND e.cluster_id=$2 AND e.application_id=$3 AND e.item_id=l.id AND e.item_version=l.version`, t.args(ref.ID, ref.Version)...).Scan(&ok)
	return ok, safeError(err)
}
