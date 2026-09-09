CREATE TABLE enterprise_core.investigation_runs (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 id text NOT NULL,incident_id text NOT NULL,profile_id text NOT NULL,profile_version text NOT NULL,
 prompt_version text NOT NULL,rubric_version text NOT NULL,status text NOT NULL,reason text NOT NULL,
 started_at timestamptz NOT NULL,finished_at timestamptz,claim_id text,claim_version bigint,
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id) REFERENCES enterprise_core.incidents(organization_id,cluster_id,application_id,id)
);
CREATE INDEX investigation_runs_time ON enterprise_core.investigation_runs(organization_id,cluster_id,application_id,started_at);
