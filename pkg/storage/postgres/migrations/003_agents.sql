CREATE TABLE enterprise_core.agent_bootstraps (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 token_hash text NOT NULL, agent_id text NOT NULL, role text NOT NULL CHECK(role IN ('COLLECTOR','EXECUTOR')),
 audience text NOT NULL, epoch text NOT NULL, cluster_uid text NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz,
 PRIMARY KEY(organization_id,cluster_id,application_id,token_hash),
 FOREIGN KEY(organization_id,cluster_id,application_id) REFERENCES enterprise_core.scopes
);
CREATE TABLE enterprise_core.agents (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 id text NOT NULL, role text NOT NULL CHECK(role IN ('COLLECTOR','EXECUTOR')), audience text NOT NULL,
 epoch text NOT NULL, generation bigint NOT NULL CHECK(generation>0), cluster_uid text NOT NULL,
 token_hash text NOT NULL, expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 UNIQUE(organization_id,cluster_id,application_id,token_hash),
 FOREIGN KEY(organization_id,cluster_id,application_id) REFERENCES enterprise_core.scopes
);
