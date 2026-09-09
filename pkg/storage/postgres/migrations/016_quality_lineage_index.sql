CREATE INDEX items_claim_run ON enterprise_core.items(organization_id,cluster_id,application_id,(envelope#>>'{body,run_id}')) WHERE kind='CLAIM';
