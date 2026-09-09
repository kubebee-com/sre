CREATE TABLE enterprise_core.actions (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 id text NOT NULL, incident_id text NOT NULL, version bigint NOT NULL CHECK(version>0),
 state text NOT NULL CHECK(state IN ('PROPOSED','APPROVED','SUBMITTED','APPLIED','FAILED','AMBIGUOUS','CANCELLED')),
 envelope jsonb NOT NULL, receipt_hash text NOT NULL DEFAULT '',
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id) REFERENCES enterprise_core.incidents(organization_id,cluster_id,application_id,id)
);
CREATE INDEX actions_state ON enterprise_core.actions(organization_id,cluster_id,application_id,state,id);
CREATE TABLE enterprise_core.action_events (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 action_id text NOT NULL, version bigint NOT NULL, envelope jsonb NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,action_id,version),
 FOREIGN KEY(organization_id,cluster_id,application_id,action_id) REFERENCES enterprise_core.actions(organization_id,cluster_id,application_id,id)
);
