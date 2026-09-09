CREATE TABLE enterprise_core.diagnostic_jobs (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 id text NOT NULL,incident_id text NOT NULL,profile_id text NOT NULL,actor_id text NOT NULL,
 state text NOT NULL CHECK(state IN ('QUEUED','RUNNING','COMPLETED','CANCELLED','FAILED')),
 created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,authority text NOT NULL,result jsonb,
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id) REFERENCES enterprise_core.incidents(organization_id,cluster_id,application_id,id)
);
CREATE UNIQUE INDEX one_active_diagnosis_per_incident ON enterprise_core.diagnostic_jobs(organization_id,cluster_id,application_id,incident_id) WHERE state IN ('QUEUED','RUNNING');
CREATE UNIQUE INDEX one_running_diagnosis_per_application ON enterprise_core.diagnostic_jobs(organization_id,cluster_id,application_id) WHERE state='RUNNING';
