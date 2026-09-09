CREATE TABLE enterprise_core.adjudications (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 id text NOT NULL,incident_id text NOT NULL,item_id text NOT NULL,item_version bigint NOT NULL,
 actor_id text NOT NULL,idempotency_key text NOT NULL,envelope jsonb NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 UNIQUE(organization_id,cluster_id,application_id,actor_id,idempotency_key),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id,item_id,item_version) REFERENCES enterprise_core.items(organization_id,cluster_id,application_id,incident_id,id,version)
);
CREATE INDEX adjudications_item ON enterprise_core.adjudications(organization_id,cluster_id,application_id,item_id,item_version,created_at DESC);
