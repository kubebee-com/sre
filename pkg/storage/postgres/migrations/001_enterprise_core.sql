CREATE TABLE enterprise_core.scopes (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 PRIMARY KEY (organization_id,cluster_id,application_id)
);
CREATE TABLE enterprise_core.incidents (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 id text NOT NULL, version bigint NOT NULL CHECK(version>0), state text NOT NULL, opened_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 FOREIGN KEY(organization_id,cluster_id,application_id) REFERENCES enterprise_core.scopes
);
CREATE TABLE enterprise_core.items (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 incident_id text NOT NULL, id text NOT NULL, version bigint NOT NULL CHECK(version>0),
 kind text NOT NULL CHECK(kind IN ('EVIDENCE','CLAIM')), envelope jsonb NOT NULL,
 hash text NOT NULL, observed_at timestamptz NOT NULL, valid_until timestamptz NOT NULL CHECK(valid_until>observed_at),
 PRIMARY KEY(organization_id,cluster_id,application_id,id,version),
 UNIQUE(organization_id,cluster_id,application_id,incident_id,id,version),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id) REFERENCES enterprise_core.incidents(organization_id,cluster_id,application_id,id)
);
CREATE TABLE enterprise_core.item_parents (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 incident_id text NOT NULL, child_id text NOT NULL, child_version bigint NOT NULL, parent_id text NOT NULL, parent_version bigint NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,child_id,child_version,parent_id,parent_version),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id,child_id,child_version) REFERENCES enterprise_core.items(organization_id,cluster_id,application_id,incident_id,id,version),
 FOREIGN KEY(organization_id,cluster_id,application_id,incident_id,parent_id,parent_version) REFERENCES enterprise_core.items(organization_id,cluster_id,application_id,incident_id,id,version)
);
CREATE TABLE enterprise_core.item_eligibility (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 item_id text NOT NULL, item_version bigint NOT NULL, quarantined boolean NOT NULL DEFAULT false,
 PRIMARY KEY(organization_id,cluster_id,application_id,item_id,item_version),
 FOREIGN KEY(organization_id,cluster_id,application_id,item_id,item_version) REFERENCES enterprise_core.items(organization_id,cluster_id,application_id,id,version)
);
CREATE TABLE enterprise_core.outbox (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 id text NOT NULL, event_key text NOT NULL, kind text NOT NULL, payload jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), delivered_at timestamptz,
 attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 UNIQUE(organization_id,cluster_id,application_id,event_key),
 FOREIGN KEY(organization_id,cluster_id,application_id) REFERENCES enterprise_core.scopes
);
