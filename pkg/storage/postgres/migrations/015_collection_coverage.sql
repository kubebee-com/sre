CREATE TABLE enterprise_core.collection_coverage (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 agent_id text NOT NULL,generation bigint NOT NULL,epoch text NOT NULL,observed_at timestamptz NOT NULL,
 coverage text NOT NULL CHECK(coverage IN ('COMPLETE','PARTIAL','UNAVAILABLE')),
 PRIMARY KEY(organization_id,cluster_id,application_id,agent_id),
 FOREIGN KEY(organization_id,cluster_id,application_id,agent_id) REFERENCES enterprise_core.agents(organization_id,cluster_id,application_id,id)
);
