CREATE TABLE enterprise_core.notifications (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 id text NOT NULL,event_id text NOT NULL,route_id text NOT NULL,kind text NOT NULL,incident_id text NOT NULL,
 state text NOT NULL DEFAULT 'PENDING',attempts integer NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now(),delivered_at timestamptz,acknowledged_by text NOT NULL DEFAULT '',
 lease text NOT NULL DEFAULT '',lease_until timestamptz,next_attempt_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 UNIQUE(organization_id,cluster_id,application_id,event_id,route_id),
 FOREIGN KEY(organization_id,cluster_id,application_id,event_id) REFERENCES enterprise_core.outbox(organization_id,cluster_id,application_id,id)
);
