CREATE TABLE enterprise_core.recovery_profiles (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 id text NOT NULL,version bigint NOT NULL CHECK(version>0),envelope jsonb NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,id,version),
 FOREIGN KEY(organization_id,cluster_id,application_id) REFERENCES enterprise_core.scopes
);
CREATE TABLE enterprise_core.health_samples (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 incident_id text NOT NULL,handle text NOT NULL,observed_at timestamptz NOT NULL,
 item_id text NOT NULL,item_version bigint NOT NULL,envelope jsonb NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,incident_id,handle,observed_at),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id,item_id,item_version) REFERENCES enterprise_core.items(organization_id,cluster_id,application_id,incident_id,id,version)
);
CREATE TABLE enterprise_core.recovery_assessments (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 id text NOT NULL,incident_id text NOT NULL,envelope jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id) REFERENCES enterprise_core.incidents(organization_id,cluster_id,application_id,id)
);
