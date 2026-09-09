CREATE TABLE enterprise_core.interactions (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 id text NOT NULL, incident_id text NOT NULL, job_id text NOT NULL DEFAULT '',
 kind text NOT NULL CHECK(kind='CLARIFICATION'),
 question text NOT NULL CHECK(question IN ('CHANGE_CONTEXT','IMPACT','CONTINUE_DIAGNOSIS')),
 version bigint NOT NULL CHECK(version>0), status text NOT NULL CHECK(status IN ('PENDING','ANSWERED')),
 expires_at timestamptz NOT NULL, created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 answer text NOT NULL DEFAULT '', actor_id text NOT NULL DEFAULT '', answered_at timestamptz,
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id) REFERENCES enterprise_core.incidents(organization_id,cluster_id,application_id,id),
 CHECK((status='PENDING' AND answer='' AND actor_id='' AND answered_at IS NULL) OR (status='ANSWERED' AND answer<>'' AND actor_id<>'' AND answered_at IS NOT NULL))
);
