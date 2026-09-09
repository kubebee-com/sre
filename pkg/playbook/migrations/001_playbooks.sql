CREATE SCHEMA IF NOT EXISTS playbook_catalog;
CREATE TABLE IF NOT EXISTS playbook_catalog.sources (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS sources_hash_idx ON playbook_catalog.sources(content_hash);
CREATE UNIQUE INDEX IF NOT EXISTS sources_lookup_idx ON playbook_catalog.sources(lookup_key);
CREATE TABLE IF NOT EXISTS playbook_catalog.digests (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS digests_hash_idx ON playbook_catalog.digests(content_hash);
CREATE TABLE IF NOT EXISTS playbook_catalog.playbooks (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '' CHECK (state IN ('NORMALIZED','REVIEW','ACTIVE','REJECTED','RETIRED')),
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS playbooks_hash_idx ON playbook_catalog.playbooks(content_hash);
CREATE TABLE IF NOT EXISTS playbook_catalog.steps (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS steps_hash_idx ON playbook_catalog.steps(content_hash);
CREATE INDEX IF NOT EXISTS steps_lookup_idx ON playbook_catalog.steps(lookup_key);
CREATE TABLE IF NOT EXISTS playbook_catalog.bindings (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS bindings_hash_idx ON playbook_catalog.bindings(content_hash);
CREATE INDEX IF NOT EXISTS bindings_lookup_idx ON playbook_catalog.bindings(lookup_key);
CREATE TABLE IF NOT EXISTS playbook_catalog.findings (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS findings_hash_idx ON playbook_catalog.findings(content_hash);
CREATE TABLE IF NOT EXISTS playbook_catalog.evidence_snapshots (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS evidence_snapshots_hash_idx ON playbook_catalog.evidence_snapshots(content_hash);
CREATE TABLE IF NOT EXISTS playbook_catalog.resolution_runs (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS resolution_runs_hash_idx ON playbook_catalog.resolution_runs(content_hash);
CREATE TABLE IF NOT EXISTS playbook_catalog.resolution_steps (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS resolution_steps_hash_idx ON playbook_catalog.resolution_steps(content_hash);
CREATE INDEX IF NOT EXISTS resolution_steps_lookup_idx ON playbook_catalog.resolution_steps(lookup_key);
CREATE TABLE IF NOT EXISTS playbook_catalog.approvals (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS approvals_hash_idx ON playbook_catalog.approvals(content_hash);
CREATE INDEX IF NOT EXISTS approvals_lookup_idx ON playbook_catalog.approvals(lookup_key);
CREATE TABLE IF NOT EXISTS playbook_catalog.feedback (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS feedback_hash_idx ON playbook_catalog.feedback(content_hash);
CREATE INDEX IF NOT EXISTS feedback_lookup_idx ON playbook_catalog.feedback(lookup_key);
CREATE TABLE IF NOT EXISTS playbook_catalog.relations (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS relations_hash_idx ON playbook_catalog.relations(content_hash);
CREATE TABLE IF NOT EXISTS playbook_catalog.learning_candidates (
 id text NOT NULL,
 version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
 lookup_key text NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT '',
 content_hash text NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (id, version)
);
CREATE INDEX IF NOT EXISTS learning_candidates_hash_idx ON playbook_catalog.learning_candidates(content_hash);
CREATE UNIQUE INDEX IF NOT EXISTS learning_candidates_lookup_idx ON playbook_catalog.learning_candidates(lookup_key);
CREATE INDEX IF NOT EXISTS playbooks_state_idx ON playbook_catalog.playbooks(state,id,version);
CREATE INDEX IF NOT EXISTS playbooks_search_idx ON playbook_catalog.playbooks USING gin ((payload -> 'failure_categories'));
CREATE INDEX IF NOT EXISTS bindings_resource_idx ON playbook_catalog.bindings ((payload ->> 'namespace'), (payload ->> 'kind'), (payload ->> 'name'));
CREATE INDEX IF NOT EXISTS bindings_selector_idx ON playbook_catalog.bindings USING gin(payload jsonb_path_ops);
CREATE INDEX IF NOT EXISTS digests_source_idx ON playbook_catalog.digests ((payload ->> 'source_id'));
CREATE UNIQUE INDEX IF NOT EXISTS feedback_run_proposal_idx ON playbook_catalog.feedback ((payload ->> 'run_id'), (payload ->> 'proposal_id'));
CREATE INDEX IF NOT EXISTS evidence_resource_idx ON playbook_catalog.evidence_snapshots ((payload ->> 'uid'), (payload ->> 'resource_version'));
CREATE INDEX IF NOT EXISTS relations_from_idx ON playbook_catalog.relations ((payload ->> 'from_id'));
CREATE INDEX IF NOT EXISTS relations_to_idx ON playbook_catalog.relations ((payload ->> 'to_id'));

-- Schema-qualified sources/digests/steps/bindings correspond to the design's
-- playbook_sources/playbook_digests/playbook_steps/playbook_bindings tables.
ALTER TABLE playbook_catalog.bindings ADD COLUMN IF NOT EXISTS namespace text GENERATED ALWAYS AS (payload ->> 'namespace') STORED;
ALTER TABLE playbook_catalog.bindings ADD COLUMN IF NOT EXISTS kind text GENERATED ALWAYS AS (payload ->> 'kind') STORED;
ALTER TABLE playbook_catalog.bindings ADD COLUMN IF NOT EXISTS resource_name text GENERATED ALWAYS AS (payload ->> 'name') STORED;
ALTER TABLE playbook_catalog.playbooks ADD COLUMN IF NOT EXISTS canonical_hash text GENERATED ALWAYS AS (payload ->> 'canonical_hash') STORED;
CREATE INDEX IF NOT EXISTS bindings_typed_resource_idx ON playbook_catalog.bindings(namespace,kind,resource_name);
CREATE INDEX IF NOT EXISTS playbooks_canonical_hash_idx ON playbook_catalog.playbooks(canonical_hash);
CREATE INDEX IF NOT EXISTS sources_text_search_idx ON playbook_catalog.sources USING gin(to_tsvector('english',coalesce(payload ->> 'sanitized_content','')));
CREATE INDEX IF NOT EXISTS digests_text_search_idx ON playbook_catalog.digests USING gin(to_tsvector('english',coalesce(payload ->> 'title','') || ' ' || coalesce(payload ->> 'summary','')));
CREATE INDEX IF NOT EXISTS playbooks_text_search_idx ON playbook_catalog.playbooks USING gin(to_tsvector('english',coalesce(payload ->> 'title','') || ' ' || coalesce(payload ->> 'summary','')));

CREATE UNIQUE INDEX IF NOT EXISTS playbooks_canonical_lookup_idx ON playbook_catalog.playbooks(lookup_key);
