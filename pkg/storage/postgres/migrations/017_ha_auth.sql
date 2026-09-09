CREATE TABLE enterprise_core.login_challenges (
 key_hash text PRIMARY KEY,
 verifier text NOT NULL,
 nonce text NOT NULL,
 expires_at timestamptz NOT NULL
);
CREATE INDEX login_challenges_expiry ON enterprise_core.login_challenges(expires_at);
CREATE TABLE enterprise_core.browser_sessions (
 key_hash text PRIMARY KEY,
 principal_id text NOT NULL,
 issuer text NOT NULL,
 groups text[] NOT NULL,
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 csrf text NOT NULL
);
CREATE INDEX browser_sessions_expiry ON enterprise_core.browser_sessions(expires_at);
