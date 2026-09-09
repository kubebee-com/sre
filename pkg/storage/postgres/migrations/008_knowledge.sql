CREATE TABLE enterprise_core.agent_revocations (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 agent_id text NOT NULL,epoch text NOT NULL,through_generation bigint NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,agent_id,epoch,through_generation)
);
CREATE TABLE enterprise_core.golden_cases (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 id text NOT NULL,version bigint NOT NULL CHECK(version>0),state text NOT NULL CHECK(state IN ('CANDIDATE','ACTIVE','RETIRED')),
 envelope jsonb NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,id,version),
 FOREIGN KEY(organization_id,cluster_id,application_id) REFERENCES enterprise_core.scopes
);
