package postgres

import (
	"github.com/kubebee-com/sre/pkg/incident"
	"time"
)

func (t *Tx) PutCoverage(a incident.Agent, coverage string, at time.Time) error {
	if a.Scope != t.scope || at.IsZero() || (coverage != "COMPLETE" && coverage != "PARTIAL" && coverage != "UNAVAILABLE") {
		return ErrInvalid
	}
	_, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.collection_coverage VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(organization_id,cluster_id,application_id,agent_id) DO UPDATE SET generation=EXCLUDED.generation,epoch=EXCLUDED.epoch,observed_at=EXCLUDED.observed_at,coverage=EXCLUDED.coverage WHERE enterprise_core.collection_coverage.observed_at<EXCLUDED.observed_at`, t.args(a.ID, a.Generation, a.Epoch, at, coverage)...)
	return safeError(err)
}
func (t *Tx) CoverageCounts() (map[string]int64, error) {
	rows, err := t.db.Query(t.ctx, `SELECT CASE WHEN c.agent_id IS NULL THEN 'UNKNOWN' WHEN a.revoked OR a.epoch<>$4 OR c.epoch<>a.epoch OR c.generation<>a.generation OR a.expires_at<=now() OR c.observed_at<now()-interval '90 seconds' THEN 'STALE' ELSE c.coverage END,count(*) FROM enterprise_core.agents a LEFT JOIN enterprise_core.collection_coverage c ON c.organization_id=a.organization_id AND c.cluster_id=a.cluster_id AND c.application_id=a.application_id AND c.agent_id=a.id WHERE a.organization_id=$1 AND a.cluster_id=$2 AND a.application_id=$3 AND a.role='COLLECTOR' GROUP BY 1`, t.args(t.authorityEpoch)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := map[string]int64{}
	for rows.Next() {
		var state string
		var n int64
		if err := rows.Scan(&state, &n); err != nil {
			return nil, safeError(err)
		}
		result[state] = n
	}
	return result, safeError(rows.Err())
}
