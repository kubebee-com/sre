# Unified SRE chart

Install the orchestrator centrally and an agent-only release in each scoped cluster.
Use your published images built from `deploy/Dockerfile.unified`.

The orchestrator requires an existing ConfigMap with key `config.json`, using the
deployment configuration schema in `deploy/examples/enterprise/config.json` (the
schema is preserved during migration). Its existing Secret supplies:

- `SRE_DATABASE_URL`: PostgreSQL DSN with verified TLS.
- `SRE_PUBLIC_URL`: exact external HTTPS origin; register `/auth/callback` with OIDC.
- `SRE_OIDC_ISSUER`, `SRE_OIDC_CLIENT_ID`, `SRE_OIDC_CLIENT_SECRET`.
- `SRE_AUTHORITY_GENERATION`: same operator-managed generation on every replica.
- `SRE_AUTHORITY_KEY`: base64-encoded random 32-byte shared key for queued authority.

```bash
helm upgrade --install sre ./deploy/helm/sre --namespace sre --create-namespace \
  --set orchestrator.existingConfigMap=sre-config \
  --set orchestrator.existingSecret=sre-orchestrator \
  -f reviewed-values.yaml
```

Configure TLS ingress and PostgreSQL network CIDRs in reviewed values. The chart
does not install PostgreSQL or an identity provider. Two replicas provide application
redundancy; spread constraints, PDB and rolling updates do not make the database HA.
Rotate the authority generation/key consistently across all replicas. A coordinated
security reset must remove old-config replicas before declaring old authority revoked.

Agent-only values:

```yaml
orchestrator:
  enabled: false
agent:
  enabled: true
  orchestratorURL: https://sre.example.com
  organizationID: my-org
  clusterID: prod
  applicationID: payments
  expectedClusterUID: verified-kube-system-uid
  namespaces: [payments]
  profiles: [approved-profile]
  identityKeySecret: sre-agent-identity
  collectorBootstrapSecret: sre-collector-bootstrap
  providerSecret: sre-provider-credentials
```

Create the identity Secret with a 32-byte raw `key`. Create the role-specific
bootstrap Secret with `token` from the orchestrator enrollment API/UI. The agent
image initializes these into private persistent files. Provider Secret environment
keys must match the approved profile's `api_key_env`; provider keys are not sent in
job payloads. `profiles` explicitly advertises which profiles this agent can run.

To allow execution, also provision an executor bootstrap Secret, set
`agent.executionEnabled=true`, and enable execution centrally. One agent process
then holds both capability credentials; this differs from the old separate-process
collector/executor isolation. Namespace-scoped RBAC and approval checks remain.

Agents use a single-writer PVC and Recreate strategy to protect their execution
journal and identity registry. They do not expose a browser UI or inbound Service.

For IM routes and verified human commands, see the [messaging guide](../../../docs/messaging.md). Store IM credentials in `orchestrator.existingSecret`; agents do not need them.
