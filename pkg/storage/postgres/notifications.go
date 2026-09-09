package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"time"
)

func (t *Tx) MaterializeNotifications(route string) error {
	if !identity.ValidID(route) {
		return ErrInvalid
	}
	// Collector reports and other internal events cannot crowd out operator events.
	_, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.notifications(organization_id,cluster_id,application_id,id,event_id,route_id,kind,incident_id)
 SELECT o.organization_id,o.cluster_id,o.application_id,md5(o.id||'/'||$4),o.id,$4,o.kind,COALESCE(o.payload->>'incident_id','') FROM enterprise_core.outbox o
 WHERE o.organization_id=$1 AND o.cluster_id=$2 AND o.application_id=$3 AND o.kind IN ('INCIDENT_CREATED','INVESTIGATION_RECORDED','ACTION_UPDATED','CLAIM_CORROBORATED','ADJUDICATION_RECORDED','KNOWLEDGE_PUBLISHED','RECOVERY_CHANGED','CLARIFICATION_REQUESTED')
 AND o.created_at >= COALESCE((SELECT registered_at FROM enterprise_core.notification_routes WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3 AND id=$4),'-infinity'::timestamptz)
 AND NOT EXISTS(SELECT 1 FROM enterprise_core.notifications n WHERE n.organization_id=$1 AND n.cluster_id=$2 AND n.application_id=$3 AND n.event_id=o.id AND n.route_id=$4)
 ORDER BY o.created_at,o.id LIMIT 50 ON CONFLICT DO NOTHING`, t.args(route)...)
	return safeError(err)
}
func (t *Tx) LeaseNotification(route string) (incident.Notification, error) {
	if !identity.ValidID(route) {
		return incident.Notification{}, ErrInvalid
	}
	if _, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.notifications SET state='FAILED',lease='',lease_until=NULL WHERE `+scopeWhere+` AND route_id=$4 AND state='SENDING' AND lease_until<now() AND attempts>=8`, t.args(route)...); err != nil {
		return incident.Notification{}, safeError(err)
	}
	n := incident.Notification{Scope: t.scope, Lease: identity.NewID()}
	err := t.db.QueryRow(t.ctx, `UPDATE enterprise_core.notifications SET state='SENDING',lease=$5,lease_until=now()+interval '30 seconds',attempts=attempts+1 WHERE `+scopeWhere+` AND id=(SELECT id FROM enterprise_core.notifications WHERE `+scopeWhere+` AND route_id=$4 AND acknowledged_by='' AND ((state='PENDING' AND next_attempt_at<=now()) OR (state='SENDING' AND lease_until<now())) AND attempts<8 ORDER BY next_attempt_at,id LIMIT 1) RETURNING id,event_id,route_id,kind,incident_id,state,attempts,created_at,delivered_at,acknowledged_by`, t.args(route, n.Lease)...).Scan(&n.ID, &n.EventID, &n.RouteID, &n.Kind, &n.IncidentID, &n.State, &n.Attempts, &n.CreatedAt, &n.DeliveredAt, &n.AcknowledgedBy)
	return n, safeError(err)
}
func (t *Tx) FinishNotification(n incident.Notification, delivered bool) error {
	if n.Scope != t.scope || !identity.ValidID(n.ID) || !identity.ValidID(n.Lease) {
		return ErrInvalid
	}
	state := "PENDING"
	var deliveredAt any
	if delivered {
		state = "DELIVERED"
		deliveredAt = time.Now()
	} else if n.Attempts >= 8 {
		state = "FAILED"
	}
	delay := time.Duration(1<<min(n.Attempts, 8)) * time.Second
	tag, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.notifications SET state=$6,delivered_at=$7,lease='',lease_until=NULL,next_attempt_at=$8 WHERE `+scopeWhere+` AND id=$4 AND lease=$5 AND state='SENDING'`, t.args(n.ID, n.Lease, state, deliveredAt, time.Now().Add(delay))...)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
func (t *Tx) Notifications(after string, limit int) ([]incident.Notification, error) {
	if (after != "" && !identity.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := t.db.Query(t.ctx, `SELECT id,event_id,route_id,kind,incident_id,state,attempts,created_at,delivered_at,acknowledged_by FROM enterprise_core.notifications WHERE `+scopeWhere+` AND id>$4 ORDER BY id LIMIT $5`, t.args(after, limit)...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := []incident.Notification{}
	for rows.Next() {
		n := incident.Notification{Scope: t.scope}
		if err := rows.Scan(&n.ID, &n.EventID, &n.RouteID, &n.Kind, &n.IncidentID, &n.State, &n.Attempts, &n.CreatedAt, &n.DeliveredAt, &n.AcknowledgedBy); err != nil {
			return nil, safeError(err)
		}
		result = append(result, n)
	}
	return result, safeError(rows.Err())
}
func (t *Tx) AcknowledgeNotification(id, actor string) error {
	if !identity.ValidID(id) || !identity.ValidID(actor) {
		return ErrInvalid
	}
	tag, err := t.db.Exec(t.ctx, `UPDATE enterprise_core.notifications SET acknowledged_by=$5 WHERE `+scopeWhere+` AND id=$4 AND acknowledged_by=''`, t.args(id, actor)...)
	if err != nil {
		return safeError(err)
	}
	if tag.RowsAffected() == 0 {
		var found bool
		err = t.db.QueryRow(t.ctx, `SELECT acknowledged_by<>'' FROM enterprise_core.notifications WHERE `+scopeWhere+` AND id=$4`, t.args(id)...).Scan(&found)
		return safeError(err)
	}
	payload, _ := json.Marshal(map[string]string{"notification_id": id, "actor_id": actor})
	return t.Enqueue("ack_"+id, "NOTIFICATION_ACKNOWLEDGED", payload)
}
func (t *Tx) EscalateNotifications(route, to string, after time.Duration) error {
	if !identity.ValidID(route) || !identity.ValidID(to) || route == to || after < time.Minute {
		return ErrInvalid
	}
	_, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.notifications(organization_id,cluster_id,application_id,id,event_id,route_id,kind,incident_id)
 SELECT organization_id,cluster_id,application_id,md5(event_id||'/'||$5),event_id,$5,kind,incident_id FROM enterprise_core.notifications source WHERE `+scopeWhere+` AND route_id=$4 AND acknowledged_by='' AND created_at<=$6 AND state IN ('DELIVERED','FAILED')
 AND EXISTS (SELECT 1 FROM enterprise_core.outbox original WHERE original.organization_id=$1 AND original.cluster_id=$2 AND original.application_id=$3 AND original.id=source.event_id AND original.created_at >= COALESCE((SELECT registered_at FROM enterprise_core.notification_routes WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3 AND id=$5),'-infinity'::timestamptz))
 AND NOT EXISTS (SELECT 1 FROM enterprise_core.notifications destination WHERE destination.organization_id=$1 AND destination.cluster_id=$2 AND destination.application_id=$3 AND destination.event_id=source.event_id AND destination.route_id=$5) ORDER BY created_at LIMIT 50 ON CONFLICT DO NOTHING`, t.args(route, to, time.Now().Add(-after))...)
	return safeError(err)
}

// RegisterNotificationRoute establishes the first activation boundary. Reusing an
// existing route retains its backlog; a new route never sends old incident history.
func (t *Tx) RegisterNotificationRoute(id string) error {
	if !identity.ValidID(id) {
		return ErrInvalid
	}
	if _, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.scopes VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, t.args()...); err != nil {
		return safeError(err)
	}
	_, err := t.db.Exec(t.ctx, `INSERT INTO enterprise_core.notification_routes(organization_id,cluster_id,application_id,id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, t.args(id)...)
	return safeError(err)
}
