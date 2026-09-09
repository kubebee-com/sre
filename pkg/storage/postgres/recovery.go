package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"time"
)

func (t *Tx) PutRecoveryProfile(p incident.RecoveryProfile) error {
	if p.Scope != t.scope || !identity.ValidID(p.ID) || p.Version < 1 {
		return ErrInvalid
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return ErrInvalid
	}
	if _, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.scopes VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, t.args()...); err != nil {
		return safeError(err)
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.recovery_profiles VALUES($1,$2,$3,$4,$5,$6)`, t.args(p.ID, p.Version, raw)...)
	return safeError(err)
}
func (t *Tx) RecoveryProfile(id string) (incident.RecoveryProfile, error) {
	if !identity.ValidID(id) {
		return incident.RecoveryProfile{}, ErrInvalid
	}
	var raw []byte
	err := t.db.QueryRow(t.ctx, `SELECT envelope FROM enterprise_core.recovery_profiles WHERE `+scopeWhere+` AND id=$4 ORDER BY version DESC LIMIT 1`, t.args(id)...).Scan(&raw)
	if err != nil {
		return incident.RecoveryProfile{}, safeError(err)
	}
	var p incident.RecoveryProfile
	if json.Unmarshal(raw, &p) != nil || p.Scope != t.scope {
		return p, ErrUnavailable
	}
	return p, nil
}
func (t *Tx) PutHealthSample(s incident.HealthSample) error {
	if s.Scope != t.scope || !validRef(s.Evidence) || s.At.IsZero() {
		return ErrInvalid
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return ErrInvalid
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.health_samples VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, t.args(s.IncidentID, s.Handle, s.At, s.Evidence.ID, s.Evidence.Version, raw)...)
	return safeError(err)
}
func (t *Tx) HealthSamples(incidentID, handle string, since time.Time) ([]incident.HealthSample, error) {
	if !identity.ValidID(incidentID) || !identity.ValidID(handle) || since.IsZero() {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT envelope FROM enterprise_core.health_samples WHERE `+scopeWhere+` AND incident_id=$4 AND handle=$5 AND observed_at>=$6 ORDER BY observed_at DESC LIMIT 512`, t.args(incidentID, handle, since)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.HealthSample{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, safeError(err)
		}
		var s incident.HealthSample
		if json.Unmarshal(raw, &s) != nil || s.Scope != t.scope {
			return nil, ErrUnavailable
		}
		result = append(result, s)
	}
	return result, safeError(rows.Err())
}
func (t *Tx) PutRecoveryAssessment(a incident.RecoveryAssessment) error {
	if a.Scope != t.scope || !identity.ValidID(a.ID) {
		return ErrInvalid
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return ErrInvalid
	}
	_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.recovery_assessments(organization_id,cluster_id,application_id,id,incident_id,envelope) VALUES($1,$2,$3,$4,$5,$6)`, t.args(a.ID, a.IncidentID, raw)...)
	return safeError(err)
}
func (t *Tx) RecoveryAssessment(id string) (incident.RecoveryAssessment, error) {
	if !identity.ValidID(id) {
		return incident.RecoveryAssessment{}, ErrInvalid
	}
	var raw []byte
	err := t.db.QueryRow(t.ctx, `SELECT envelope FROM enterprise_core.recovery_assessments WHERE `+scopeWhere+` AND id=$4`, t.args(id)...).Scan(&raw)
	if err != nil {
		return incident.RecoveryAssessment{}, safeError(err)
	}
	var a incident.RecoveryAssessment
	if json.Unmarshal(raw, &a) != nil || a.Scope != t.scope {
		return a, ErrUnavailable
	}
	return a, nil
}
