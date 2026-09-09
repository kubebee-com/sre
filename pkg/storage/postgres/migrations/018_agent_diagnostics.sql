-- Read-only diagnostic attempts are durable and fenced independently of replicas.
ALTER TABLE enterprise_core.diagnostic_jobs
 ADD COLUMN agent_id text,
 ADD COLUMN agent_generation bigint,
 ADD COLUMN agent_epoch text,
 ADD COLUMN attempt_id text,
 ADD COLUMN lease_until timestamptz,
 ADD COLUMN input jsonb,
 ADD COLUMN refresh_count integer NOT NULL DEFAULT 0;
CREATE INDEX diagnostic_lease_expiry ON enterprise_core.diagnostic_jobs(lease_until) WHERE state='RUNNING';
