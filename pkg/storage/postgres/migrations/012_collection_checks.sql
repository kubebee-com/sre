CREATE TABLE enterprise_core.collection_checks (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 id text NOT NULL,incident_id text NOT NULL,agent_id text NOT NULL,generation bigint NOT NULL,
 handle text NOT NULL,kind text NOT NULL CHECK(kind IN ('REFRESH_RESOURCE_STATE','REFRESH_DEPENDENCIES')),
 created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,fulfilled_at timestamptz,
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id) REFERENCES enterprise_core.incidents(organization_id,cluster_id,application_id,id)
);
