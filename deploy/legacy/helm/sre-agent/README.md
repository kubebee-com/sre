# sre-agent Helm chart

This chart packages the authenticated SRE Agent deployment with release-scoped
names and selectors. The default installation uses a non-root, read-only
container, a durable `ReadWriteOnce` data claim, a read-only ClusterRole, a
PodDisruptionBudget, and a NetworkPolicy.

The chart does not create a Secret by default. Create the external Secret before
installing, or explicitly opt in to chart-managed `stringData`:

```bash
kubectl create namespace sre --dry-run=client -o yaml | kubectl apply -f -
kubectl -n sre create secret generic sre-agent-secrets \
  --from-literal=SRE_API_TOKEN="$SRE_API_TOKEN" \
  --from-literal=LLM_API_KEY="${LLM_API_KEY:-}" \
  --from-literal=WEBHOOK_URL="${WEBHOOK_URL:-}" \
  --from-literal=SRE_CACHE_ENCRYPTION_KEY="${SRE_CACHE_ENCRYPTION_KEY:-}"

helm upgrade --install sre-agent ./deploy/helm/sre-agent \
  --namespace sre --create-namespace \
  --set secret.name=sre-agent-secrets \
  --set image.digest=sha256:<64 lowercase hexadecimal characters>
```

Image tags must be fixed release tags; `latest` and malformed tags/digests are
rejected during rendering. A digest is preferred for production and takes
precedence over the tag.

Ingress, ServiceMonitor, PDB, and NetworkPolicy are independently configurable.
Ingress is disabled by default and requires TLS values when enabled.
ServiceMonitor scrapes `/metrics` through the HTTP Service port and is disabled
by default because its CRD is not present in every cluster.

The default ClusterRole grants observation only. Secret reads and remediation
verbs require explicit values and should be reviewed against the operator's
threat model before enabling them.

The optional AWS/EKS analyzer is enabled with `config.enableAWSEKS=true` and
uses the AWS SDK default credential chain. Set `config.awsRegion` and
`config.eksClusterName` when kubeconfig context discovery is not available.

Provider-result caching is disabled by default. To enable encrypted local
caching, set `config.cacheDir` under the mounted data path and provide
`SRE_CACHE_ENCRYPTION_KEY` in the external Secret. The cache TTL and bounds are
`config.cacheTTL`, `config.cacheMaxEntries`, and `config.cacheMaxValueBytes`.

Provider organization and proxy settings are configured with
`config.llmOrganization` and `config.llmProxyURL`. Custom request headers are
transient and should be supplied as `LLM_CUSTOM_HEADERS` in the external Secret
or through `secret.llmCustomHeaders` when chart-managed secrets are explicitly
enabled. Values use comma-separated `key:value` entries and are never written
to the user profile.

For a non-default remote endpoint, set `config.llmBaseURL` together with
`config.llmEndpointAllowlist` containing the approved endpoint origin or path.
The allowlist is required by the provider endpoint policy.

To use native AWS model clients, set `config.llmMode=aws`, choose
`config.llmProvider=bedrock` or `sagemaker`, and set `config.awsRegion`.
SageMaker uses `config.llmBaseURL` for the endpoint name; credentials come from
the AWS SDK credential chain.

Set `grpc.enabled=true` to expose the authenticated gRPC Service. For TLS,
also set `grpc.tls.enabled=true` and provide an external Secret containing
`tls.crt` and `tls.key`; set `grpc.tls.clientCAFile` to require verified
mTLS clients. Reflection is disabled unless `grpc.reflection=true`. The static
Kustomize manifest uses the separate `sre-agent-grpc-tls` Secret at
`/etc/sre-agent/grpc-tls`; the Helm chart uses `grpc.tls.secretName`.

### File-backed state and monitoring

This chart currently permits one replica and uses `Recreate` deployments. The
proposal directory is exclusively locked for the process lifetime; rolling
replacement would overlap writers or leave a replacement waiting for the volume.
Upgrades therefore have a brief availability gap. Multiple replicas require the
enterprise shared-storage runtime, not simply a higher replica count.

When API authentication and ServiceMonitor are enabled, Prometheus uses a Bearer
credential from `serviceMonitor.authorization.secretName` (defaults to the app
Secret) and `secretKey` (defaults to `SRE_API_TOKEN`). The referenced Secret must
be accessible to the Prometheus Operator according to its namespace policies.
Only Secret references appear in the monitor manifest.
