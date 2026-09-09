package postgres

import (
	"time"
)

// OperationalSnapshot contains counts only; scope authorization precedes reads.
type OperationalSnapshot struct {
	Coverage             map[string]int64 `json:"coverage"`
	Agents               map[string]int64 `json:"agents"`
	Jobs                 map[string]int64 `json:"jobs"`
	Actions              map[string]int64 `json:"actions"`
	Notifications        map[string]int64 `json:"notifications"`
	FreshEvidence        int64            `json:"fresh_evidence"`
	QuarantinedItems     int64            `json:"quarantined_items"`
	OldestPendingSeconds *float64         `json:"oldest_pending_seconds"`
	At                   time.Time        `json:"at"`
}

func (t *Tx) OperationalSnapshot(at time.Time) (OperationalSnapshot, error) {
	result := OperationalSnapshot{At: at, Agents: map[string]int64{}, Jobs: map[string]int64{}, Actions: map[string]int64{}, Notifications: map[string]int64{}}
	queries := []struct {
		sql    string
		target map[string]int64
	}{
		{`SELECT CASE WHEN revoked THEN 'REVOKED' WHEN expires_at<=now() OR epoch<>$4 THEN 'EXPIRED' ELSE 'CURRENT' END,count(*) FROM enterprise_core.agents WHERE ` + scopeWhere + ` GROUP BY 1`, result.Agents},
		{`SELECT state,count(*) FROM enterprise_core.diagnostic_jobs WHERE ` + scopeWhere + ` GROUP BY state`, result.Jobs},
		{`SELECT state,count(*) FROM enterprise_core.actions WHERE ` + scopeWhere + ` GROUP BY state`, result.Actions},
		{`SELECT state,count(*) FROM enterprise_core.notifications WHERE ` + scopeWhere + ` GROUP BY state`, result.Notifications},
	}
	for n, q := range queries {
		args := t.args()
		if n == 0 {
			args = t.args(t.authorityEpoch)
		}
		rows, err := t.db.Query(t.ctx, q.sql, args...)
		if err != nil {
			return result, safeError(err)
		}
		for rows.Next() {
			var state string
			var count int64
			if err := rows.Scan(&state, &count); err != nil {
				rows.Close()
				return result, safeError(err)
			}
			q.target[state] = count
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return result, safeError(err)
		}
	}
	if err := t.db.QueryRow(t.ctx, `SELECT count(*) FROM enterprise_core.items WHERE `+scopeWhere+` AND kind='EVIDENCE' AND observed_at<=now() AND valid_until>now()`, t.args()...).Scan(&result.FreshEvidence); err != nil {
		return result, safeError(err)
	}
	if err := t.db.QueryRow(t.ctx, `SELECT count(*) FROM enterprise_core.item_eligibility WHERE `+scopeWhere+` AND quarantined`, t.args()...).Scan(&result.QuarantinedItems); err != nil {
		return result, safeError(err)
	}
	err := t.db.QueryRow(t.ctx, `SELECT EXTRACT(EPOCH FROM now()-min(created_at))::float8 FROM enterprise_core.notifications WHERE `+scopeWhere+` AND acknowledged_by='' AND state IN ('PENDING','SENDING')`, t.args()...).Scan(&result.OldestPendingSeconds)
	if err != nil {
		return result, safeError(err)
	}
	result.Coverage, err = t.CoverageCounts()
	return result, err
}

// Retain removes expendable transient data only. Evidence, review/audit records,
// approvals, revocations and recovery/knowledge provenance are never erased here.
func (t *Tx) Retain(days int) error {
	if days < 7 || days > 3650 {
		return ErrInvalid
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	queries := []string{
		`DELETE FROM enterprise_core.outbox WHERE ` + scopeWhere + ` AND id IN (SELECT id FROM enterprise_core.outbox WHERE ` + scopeWhere + ` AND kind='COLLECTOR_REPORT' AND created_at<$4 LIMIT 500)`,
		`DELETE FROM enterprise_core.agent_bootstraps WHERE ` + scopeWhere + ` AND token_hash IN (SELECT token_hash FROM enterprise_core.agent_bootstraps WHERE ` + scopeWhere + ` AND expires_at<$4 LIMIT 500)`,
		`UPDATE enterprise_core.diagnostic_jobs SET authority='' WHERE ` + scopeWhere + ` AND state IN ('COMPLETED','CANCELLED','FAILED') AND authority<>'' AND expires_at<$4`,
	}
	for _, q := range queries {
		if _, err := t.db.Exec(t.ctx, q, t.args(cutoff)...); err != nil {
			return safeError(err)
		}
	}
	return nil
}
