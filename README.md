# KubeBee SRE

One system with two runtimes:

- **sre-orchestrator** serves the UI/API, coordinates scoped work, owns approvals,
  sends notifications, and records evidence, recovery, and reviewed learning.
- **sre-agent** collects evidence, runs diagnosis/debugging, and optionally executes
  approved actions. Run the same binary in Kubernetes or on a host with kubeconfig.

The orchestrator has no Kubernetes credentials. Agents connect outbound over HTTPS.
Provider credentials stay on agents. There is one authorization and approval flow
across interactive CLI, messaging notifications, and the owned UI.

## Build

```bash
make build
./bin/sre-agent --help
```

Build container images with `deploy/Dockerfile.unified`, targets `orchestrator` and
`agent`. Image repository names in the chart are examples; publish your reviewed
builds to your registry.

## Deploy

Use [the unified Helm chart](deploy/helm/sre/README.md). It supports an orchestrator
release and agent-only releases in workload clusters. The orchestrator defaults to
two replicas with shared PostgreSQL state and OIDC authentication. PostgreSQL HA
and ingress/TLS are deployment dependencies.

Local agent example, after administrator enrollment and private file provisioning:

```bash
KUBECONFIG=$HOME/.kube/config ./bin/sre-agent \
  --orchestrator=https://sre.example.com \
  --organization-id=my-org --cluster-id=prod --application-id=payments \
  --cluster-uid=VERIFIED_KUBE_SYSTEM_UID --namespaces=payments \
  --state-dir=$HOME/.local/state/sre-agent \
  --identity-key-file=/private/identity.key \
  --collector-bootstrap-file=/private/collector-bootstrap \
  --profiles=approved-profile \
  --interactive --human-token-file=/private/human-oidc-token
```

Use `--in-cluster` instead of kubeconfig for ServiceAccount credentials. Use standard
`KUBECONFIG` or `--kubeconfig`; `KUBE_CONFIG` is an accepted alias. Unattended agents
omit `--interactive` and never read terminal input. Human responses use the same
orchestrator APIs in every channel; terminal disconnection leaves requests pending.

## Approval and notifications

Observe-only is the default. Both orchestrator and agent must enable execution,
and Kubernetes RBAC must permit the action. An authorized human approves the exact
plan hash before execution. The current governed action is replacement of one
unhealthy controller-managed Pod. Agent/model output never grants mutation authority.

Interactive CLI supports `investigate INCIDENT PROFILE`, clarification, approve/reject, and notification
acknowledgement. Slack notifications link to authenticated UI review; native Slack
approval callbacks are not enabled without a verified human identity mapping.
Notification retries, deduplication, escalation and audit remain centrally persisted.

See [migration and configuration](docs/unified-sre-migration.md) for credential,
package, chart, and historical-state changes. The [approved design](docs/superpowers/specs/2026-09-08-unified-sre-design.md)
describes the architecture and acceptance requirements.

Configure Slack, Teams, Discord, Telegram, Google Chat, WhatsApp and Matrix using the [messaging channel guide](docs/messaging.md). Slack, Discord and Telegram support verified approval and clarification commands.

The [Kind acceptance guide](docs/kind-acceptance.md) describes the comprehensive two-cluster suite and its resource requirements. Run it later on a suitable host with `make unified-kind-test`.
