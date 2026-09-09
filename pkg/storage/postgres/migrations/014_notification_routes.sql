CREATE TABLE enterprise_core.notification_routes (
 organization_id text NOT NULL,cluster_id text NOT NULL,application_id text NOT NULL,
 id text NOT NULL,registered_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,cluster_id,application_id,id),
 FOREIGN KEY(organization_id,cluster_id,application_id) REFERENCES enterprise_core.scopes
);
