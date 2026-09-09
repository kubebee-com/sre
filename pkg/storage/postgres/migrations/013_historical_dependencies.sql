-- Historical guidance is provenance, not a fresh observation in the new incident.
CREATE TABLE enterprise_core.historical_dependencies (
 organization_id text NOT NULL, cluster_id text NOT NULL, application_id text NOT NULL,
 child_id text NOT NULL, child_version bigint NOT NULL, parent_id text NOT NULL, parent_version bigint NOT NULL,
 PRIMARY KEY(organization_id,cluster_id,application_id,child_id,child_version,parent_id,parent_version),
 FOREIGN KEY(organization_id,cluster_id,application_id,child_id,child_version) REFERENCES enterprise_core.items(organization_id,cluster_id,application_id,id,version),
 FOREIGN KEY(organization_id,cluster_id,application_id,parent_id,parent_version) REFERENCES enterprise_core.items(organization_id,cluster_id,application_id,id,version)
);
