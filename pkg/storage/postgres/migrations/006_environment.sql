CREATE TABLE enterprise_core.environment_contexts (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 version bigint NOT NULL CHECK(version>0),envelope jsonb NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,version),
 FOREIGN KEY(organization_id,cluster_id,application_id) REFERENCES enterprise_core.scopes
);
