# Deployment

The production manifest expects an externally managed `sre-agent-secrets` Secret
containing a non-empty `SRE_API_TOKEN`. `LLM_API_KEY` and `WEBHOOK_URL` are
optional keys and are read explicitly; the application never imports every
Secret key into its environment.

The base deployment uses a fixed release tag, a durable `ReadWriteOnce` data
volume at `/var/lib/sre-agent`, non-root/read-only runtime settings, probes, a
PodDisruptionBudget, and a NetworkPolicy. Replace the release image with the
published digest through the release overlay or your deployment system before
applying it in production.

```bash
kubectl create namespace sre --dry-run=client -o yaml | kubectl apply -f -
kubectl -n sre create secret generic sre-agent-secrets \
  --from-literal=SRE_API_TOKEN="$SRE_API_TOKEN" \
  --from-literal=LLM_API_KEY="${LLM_API_KEY:-}" \
  --from-literal=LLM_CUSTOM_HEADERS="${LLM_CUSTOM_HEADERS:-}" \
  --from-literal=WEBHOOK_URL="${WEBHOOK_URL:-}" \
  --from-literal=SRE_CACHE_ENCRYPTION_KEY="${SRE_CACHE_ENCRYPTION_KEY:-}"
kubectl apply -k deploy/k8s
```

The base Kustomize package is observation-only. It does not grant pod, node, or
workload mutation verbs. To intentionally enable the already approval-gated
remediation actions, apply the explicit overlay instead:

```bash
kubectl apply -k deploy/overlays/remediation
```

The AWS/EKS integration is disabled by default. Enable it with
`SRE_ENABLE_AWS_EKS=true` and provide AWS SDK credentials plus `AWS_REGION` or
`SRE_EKS_CLUSTER_NAME` when context discovery is not suitable. Provider-result
caching is also opt-in: set `SRE_CACHE_DIR` and provide
`SRE_CACHE_ENCRYPTION_KEY` in the Secret. The cache stores only encrypted,
bounded provider results.

For native AWS model inference, set `LLM_MODE=aws` with `LLM_PROVIDER=bedrock`
or `sagemaker`, and set `AWS_REGION`. SageMaker uses `LLM_BASE_URL` as its
endpoint name. The AWS SDK credential chain supplies credentials; no AWS
credentials are stored in the ConfigMap.

Set `LLM_ORGANIZATION` and `LLM_PROXY_URL` in the ConfigMap for non-secret
provider routing settings. For a non-default remote `LLM_BASE_URL`, also set
`LLM_ENDPOINT_ALLOWLIST` to the approved endpoint origin or path. Put custom
`key:value` request headers in the
`LLM_CUSTOM_HEADERS` Secret key; the application validates and redacts their
values and does not persist them.

The optional gRPC listener accepts `SRE_GRPC_PORT`. Configure
`SRE_GRPC_TLS_CERT_FILE`, `SRE_GRPC_TLS_KEY_FILE`, and optionally
`SRE_GRPC_TLS_CLIENT_CA_FILE` from the `sre-agent-grpc-tls` Secret mounted at
`/etc/sre-agent/grpc-tls` for TLS/mTLS. The Secret should contain `tls.crt`,
`tls.key`, and optionally `ca.crt`; the static manifest fails closed if gRPC is
enabled without the certificate pair. Reflection is disabled unless
`SRE_GRPC_REFLECTION=true`.

## Kind acceptance

The disposable integration path uses a pinned `kindest/node` image and the
`deploy/overlays/kind` Kustomize overlay. It builds `sre-agent:kind` locally,
loads it into a uniquely named cluster, creates a temporary non-empty API
token, checks rollout/readiness, and exercises the public health endpoints plus
authenticated and unauthenticated status behavior.

```bash
make kind-test
```

The script skips only when the `kind` executable is unavailable. It does not
log in to a registry and its cleanup trap deletes only the cluster it created.

## Optional playbook catalog

Follow [Guarded playbook operations](playbooks.md) to configure PostgreSQL,
import runbooks, review immutable versions, and enable verified-outcome learning.
Supply `SRE_DATABASE_URL` through your secret manager and set
`SRE_PLAYBOOK_ENABLED` explicitly. No database credential belongs in a ConfigMap
or persisted user profile. Database unavailability preserves observation and
blocks automatic playbook proposals.
