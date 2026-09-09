package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/incident"
	"time"
)

type QualityRun struct {
	IncidentID                                                                   string
	Corroborated                                                                 bool
	Day, ProfileID, ProfileVersion, PromptVersion, RubricVersion, Status, Reason string
	Invalidated                                                                  bool
	Reviews                                                                      []incident.Adjudication
}

func (t *Tx) QualityRuns(since time.Time) ([]QualityRun, error) {
	if since.IsZero() {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT r.incident_id,EXISTS(SELECT 1 FROM enterprise_core.items c WHERE c.organization_id=$1 AND c.cluster_id=$2 AND c.application_id=$3 AND c.kind='CLAIM' AND c.envelope#>>'{body,run_id}'=r.id AND c.envelope#>>'{body,assessment,status}'='CORROBORATED'),to_char(r.started_at AT TIME ZONE 'UTC','YYYY-MM-DD'),r.profile_id,r.profile_version,r.prompt_version,r.rubric_version,r.status,r.reason,NOT COALESCE((WITH RECURSIVE edges AS (
 SELECT child_id,child_version,parent_id,parent_version FROM enterprise_core.item_parents WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3
 UNION ALL SELECT child_id,child_version,parent_id,parent_version FROM enterprise_core.historical_dependencies WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3
 ), lineage(id,version) AS (
 SELECT id,version FROM enterprise_core.items WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3 AND kind='CLAIM' AND envelope#>>'{body,run_id}'=r.id
 UNION SELECT e.parent_id,e.parent_version FROM edges e JOIN lineage l ON e.child_id=l.id AND e.child_version=l.version
 ) SELECT bool_and(NOT q.quarantined AND (i.kind<>'EVIDENCE' OR ($5='' AND i.envelope#>>'{body,source,epoch}' IS NULL) OR EXISTS(
 SELECT 1 FROM enterprise_core.agents a WHERE a.organization_id=$1 AND a.cluster_id=$2 AND a.application_id=$3 AND a.id=i.envelope#>>'{body,source,agent_id}' AND a.role='COLLECTOR' AND NOT a.revoked AND a.epoch=i.envelope#>>'{body,source,epoch}' AND ($5='' OR a.epoch=$5)
 AND NOT EXISTS(SELECT 1 FROM enterprise_core.agent_revocations v WHERE v.organization_id=$1 AND v.cluster_id=$2 AND v.application_id=$3 AND v.agent_id=a.id AND v.epoch=a.epoch AND v.through_generation>=(i.envelope#>>'{body,source,generation}')::bigint)
 ))) FROM lineage l JOIN enterprise_core.items i ON i.organization_id=$1 AND i.cluster_id=$2 AND i.application_id=$3 AND i.id=l.id AND i.version=l.version JOIN enterprise_core.item_eligibility q ON q.organization_id=$1 AND q.cluster_id=$2 AND q.application_id=$3 AND q.item_id=l.id AND q.item_version=l.version),true),COALESCE((SELECT jsonb_agg(a.envelope ORDER BY a.created_at DESC,a.id DESC) FROM enterprise_core.adjudications a JOIN enterprise_core.items i ON i.organization_id=a.organization_id AND i.cluster_id=a.cluster_id AND i.application_id=a.application_id AND i.id=a.item_id AND i.version=a.item_version WHERE a.organization_id=$1 AND a.cluster_id=$2 AND a.application_id=$3 AND i.kind='CLAIM' AND i.envelope#>>'{body,run_id}'=r.id),'[]'::jsonb) FROM enterprise_core.investigation_runs r WHERE r.organization_id=$1 AND r.cluster_id=$2 AND r.application_id=$3 AND r.started_at>=$4 ORDER BY r.started_at LIMIT 100001`, t.args(since, t.authorityEpoch)...)

	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []QualityRun{}
	for rows.Next() {
		var r QualityRun
		var raw []byte
		if err := rows.Scan(&r.IncidentID, &r.Corroborated, &r.Day, &r.ProfileID, &r.ProfileVersion, &r.PromptVersion, &r.RubricVersion, &r.Status, &r.Reason, &r.Invalidated, &raw); err != nil {
			return nil, safeError(err)
		}
		if json.Unmarshal(raw, &r.Reviews) != nil {
			return nil, ErrUnavailable
		}
		result = append(result, r)
		if len(result) > 100000 {
			return nil, ErrUnavailable
		}
	}
	return result, safeError(rows.Err())
}
func (t *Tx) RecoveryCounts(since time.Time) (map[string]int, error) {
	rows, err := t.db.Query(t.ctx, `SELECT envelope->>'status',count(DISTINCT incident_id) FROM enterprise_core.recovery_assessments WHERE `+scopeWhere+` AND created_at>=$4 GROUP BY envelope->>'status'`, t.args(since)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, safeError(err)
		}
		result[status] = n
	}
	return result, safeError(rows.Err())
}
