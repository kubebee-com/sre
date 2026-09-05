# KubeBee SRE / K8sGPT Evidence Index

This index makes the comparison auditable. The upstream side is frozen to the shallow clone `k8sgpt/` at commit `731a6c90749e8e62b9325e41712c39c0d72510c4`; the KubeBee side is the current working tree at `/home/kevin/sre` on 2026-09-05. The detailed normalized records are in [the K8sGPT inventory](feature-gap-k8sgpt-inventory.md) and [the KubeBee SRE inventory](feature-gap-kubebee-sre-inventory.md). The [feature-gap table](kubebee-sre-k8sgpt-feature-gap.md) is the decision layer.

Evidence uses compact brace notation such as `pkg/analyzer/{pod,log}.go`; it means each comma-separated path (`pkg/analyzer/pod.go` and `pkg/analyzer/log.go`) and was checked after expansion. A source path followed by a symbol is an implementation anchor, not a claim that the line number is an API contract.

In the evidence map, the first implementation column is relative to the `k8sgpt/` clone unless the path already begins with `k8sgpt/`; the KubeBee implementation column is relative to this repository. This keeps repeated upstream paths readable while preserving an unambiguous root.

## Evidence Baseline

| Item | Evidence |
|---|---|
| Upstream identity | `k8sgpt/.git/shallow`, `git rev-parse HEAD`, `git show -s --format='%H %cI %s'` -> `731a6c90749e8e62b9325e41712c39c0d72510c4`, 2026-09-01 commit. |
| Upstream file audit | `docs/k8sgpt-analysis/REPORT.md` and four appendices cover all 266 tracked files one by one; `tracked-files.txt` and `reviewed-files.txt` match. |
| KubeBee executable entrypoint | `cmd/sre-agent/main.go` constructs config, Kubernetes client, scanner, triage providers, remediation, notifier, HTTP server, and periodic scan loop. |
| KubeBee analyzer entrypoint | `pkg/scanner/scanner.go` and `pkg/scanner/analyzers_{workloads,networking,policy}.go`; metadata is returned by `GetAnalyzers`. |
| KubeBee external sinks | `pkg/triage`, `pkg/notifier/webhook.go`, `pkg/server/handlers.go`, `pkg/server/static`, `deploy/k8s`. |
| README verification rule | README claims are accepted only when source/reachability evidence supports them; overclaims are recorded in `docs/feature-gap-kubebee-sre-inventory.md` under README Claim Audit. |

## Capability Evidence Map

Each row below is one upstream slice. `Limit` identifies the evidence boundary or the missing behavior that prevents an unconditional `Covered` status.

| ID | K8sGPT implementation and proof | KubeBee SRE implementation and proof | Limit / unresolved evidence |
|---|---|---|---|
| KG-CLI-01 | `k8sgpt/cmd/root.go` rootCmd/initConfig/migration; `k8sgpt/cmd/root_test.go`. | `cmd/sre-agent/main.go`; `pkg/config/config.go`. | No Cobra tree, migration, or persisted command config. |
| KG-CLI-02 | `k8sgpt/cmd/analyze/analyze.go`; `k8sgpt/pkg/analysis/analysis.go`; `k8sgpt/cmd/analyze/analyze_test.go`. | `cmd/sre-agent/main.go:70-157`; `pkg/server/handlers.go:259-303`; `pkg/triage/provider.go`. | Scan/chat exist, but no compatible CLI flags, docs output, custom headers, or CLI interactive session. |
| KG-CLI-03 | `k8sgpt/cmd/analyze/analyze.go:resolveResourceSelection`; `k8sgpt/pkg/analysis/analysis.go`; `k8sgpt/pkg/analyzer/resource_selector_test.go`. | `pkg/config/config.go:15-20`; `pkg/scanner/scanner.go:56-143`. | Namespace only; no labels/name/filters or explicit concurrency plan. |
| KG-CLI-04 | `k8sgpt/pkg/analysis/output.go`; `k8sgpt/pkg/common/types.go`; `k8sgpt/pkg/analysis/output_test.go`. | `pkg/scanner/types.go:Issue`; `pkg/server/handlers.go:24-86`; `pkg/server/static/app.js`. | JSON API exists, but no versioned multi-format schema, docs/parents/stats, or complete redaction. |
| KG-CLI-05 | `k8sgpt/cmd/dump/dump.go`; `k8sgpt/cmd/generate/generate.go`; root registration. | No dump/generate implementation; only runtime config flags. | Requires bounded, redacted support bundle and safe provider URL helper. |
| KG-CLI-06 | `k8sgpt/cmd/auth/{auth,add,update,remove,list,default,provider_helpers}.go`; helper tests. | `pkg/config/config.go:22-59`; provider construction in `cmd/sre-agent/main.go:135-157`. | One startup profile; no multi-provider CRUD/rotation/default management. |
| KG-CLI-07 | `k8sgpt/cmd/filters/{filters,add,list,remove}.go`; `k8sgpt/pkg/analysis/analysis.go` active_filters. | `pkg/scanner/scanner.go:GetAnalyzers`; no filter persistence. | Requires declarative analyzer filter catalog and effective-scope output. |
| KG-ANL-01 | `k8sgpt/pkg/analyzer/{pod,log}.go`; `k8sgpt/pkg/analyzer/{pod,log}_test.go`; core map in `k8sgpt/pkg/analyzer/analyzer.go`. | `pkg/scanner/scanner.go:146-327,462-500`; `pkg/sanitizer/sanitizer.go`. | KubeBee detects common pod states but emits first match only; no independent log analyzer or all container classes. |
| KG-ANL-02 | `k8sgpt/pkg/analyzer/{deployment,rs,statefulset,daemonset,job,cronjob}.go` and matching tests. | `pkg/scanner/analyzers_workloads.go:11-210`. | Status checks omit workload graph, selector/template drift, child-pod evidence, and Cron syntax/missed runs. |
| KG-ANL-03 | `k8sgpt/pkg/analyzer/{service,ingress}.go`; `k8sgpt/pkg/analyzer/{service,ingress}_test.go`. | `pkg/scanner/scanner.go:377-459`; `pkg/scanner/analyzers_networking.go:221-295`. | Endpoints and object existence only; no EndpointSlice, ports, class/status, or cross-namespace semantics. |
| KG-ANL-04 | `k8sgpt/pkg/analyzer/{mutating_webhook,validating_webhook}.go`; matching tests. | No webhook analyzer in `pkg/scanner`. | Entire admission webhook resource/failure family is absent. |
| KG-ANL-05 | `k8sgpt/pkg/analyzer/configmap.go`; `k8sgpt/pkg/analyzer/{configmap,configmap_initcontainer,configmap_projected}_test.go`. | No ConfigMap logic in `pkg/scanner`. | Entire ConfigMap hygiene/reference family is absent. |
| KG-ANL-06 | `k8sgpt/pkg/analyzer/{node,storage,pvc}.go`; `k8sgpt/pkg/analyzer/{node,storage,pvc}_test.go`. | `pkg/scanner/scanner.go:330-417`; `pkg/scanner/types.go`. | Node/PVC subset only; upstream StorageClass/PV phase/capacity checks and node network condition are absent. |
| KG-ANL-07 | `k8sgpt/pkg/analyzer/{hpa,pdb,netpol}.go`; `k8sgpt/pkg/analyzer/{hpa,pdb,netpol}_test.go`. | `pkg/scanner/analyzers_policy.go:11-92`; `analyzers_networking.go:297-331`. | HPA/PDB status subset and matchLabels-only NetworkPolicy logic; upstream empty-selector behavior and richer semantics need explicit tests. |
| KG-ANL-08 | `k8sgpt/pkg/analyzer/{gatewayclass,gateway,httproute}.go`; tests; controller-runtime client. | No Gateway API dependency or analyzer in `pkg/scanner`; `go.mod`. | Entire Gateway API family is absent. |
| KG-ANL-09 | `k8sgpt/pkg/analyzer/security.go`; `k8sgpt/pkg/analyzer/security_test.go`. | No workload security analyzer; `pkg/sanitizer` is data redaction only. | Entire privilege/effective-binding analysis is absent. |
| KG-ANL-10 | OLM files `k8sgpt/pkg/analyzer/{clustercatalog,clusterextension,clusterserviceversion,subscription,instalplan,catalogsource,operatorgroup}.go` plus matching tests. | No dynamic client/OLM code in `pkg/scanner`; `go.mod`. | Entire OLM analyzer family is absent. |
| KG-ANL-11 | `k8sgpt/pkg/analyzer/analyzer.go:GetAnalyzerMap,ListFilters`; `k8sgpt/pkg/integration/integration.go` and plugins. | No `pkg/integration` or activation registry; `pkg/scanner/scanner.go:GetAnalyzers`. | Prometheus/KEDA/Kyverno/AWS analyzer integration is absent. |
| KG-ANL-12 | `k8sgpt/pkg/common/types.go`; `k8sgpt/pkg/common/listoptions_test.go`; analyzer metrics in `k8sgpt/pkg/analyzer/analyzer.go`. | `pkg/scanner/types.go:Issue,AnalyzerInfo`; `pkg/scanner/scanner.go`; analyzer endpoint in `pkg/server/handlers.go:185-210`. | No common SDK contract, parent/docs/pre-analysis, metrics, or execution health. |
| KG-AI-01 | `k8sgpt/pkg/ai/openai.go`; `k8sgpt/pkg/ai/iai.go`; `k8sgpt/pkg/ai/openai_header_transport_test.go`. | `pkg/triage/codex.go`; `pkg/triage/provider.go`; `pkg/config/config.go`. | Basic OpenAI-compatible path only; options, strict validation, and provider contract tests absent. |
| KG-AI-02 | `k8sgpt/pkg/ai/azureopenai.go`; `azureopenai_test.go`. | No Azure adapter in `pkg/triage`. | Entire Azure backend is absent. |
| KG-AI-03 | `k8sgpt/pkg/ai/anthropic.go`; `k8sgpt/pkg/ai/anthropic_test.go`. | `pkg/triage/claude.go`; provider selection in `cmd/sre-agent/main.go`. | Claude analogue exists but lacks provider-specific contract/error/session tests and controls. |
| KG-AI-04 | `k8sgpt/pkg/ai/{localai,ollama,customrest,litellm,groq}.go`; LiteLLM tests. | `pkg/triage/{codex,deepseek,harness}.go`. | No named local/REST/LiteLLM/Groq backends or endpoint policy. |
| KG-AI-05 | `k8sgpt/pkg/ai/{amazonbedrock,amazonbedrockconverse,amazonsagemaker,bedrockmantle}.go`; AWS mock tests. | No AWS AI adapter in `pkg/triage`; no AWS AI dependency in `go.mod`. | Entire AWS provider family is absent. |
| KG-AI-06 | `k8sgpt/pkg/ai/{googlegenai,googlevertexai}.go`; tests. | No Google AI adapter in `pkg/triage`. | Entire Gemini/Vertex family is absent. |
| KG-AI-07 | `k8sgpt/pkg/ai/{ocigenai,watsonxai,cohere,huggingface,noopai}.go`; backend registry. | `pkg/triage/fallback.go`; provider selection in `main.go`. | Rule fallback is not these providers; cloud adapters and explicit NoOp are absent. |
| KG-AI-08 | `k8sgpt/pkg/ai/prompts.go`; `k8sgpt/pkg/analysis/analysis.go:GetAIResults`; `k8sgpt/pkg/util/util.go`. | `pkg/triage/provider.go:12-68`; `pkg/sanitizer/sanitizer.go`; scanner log/event enrichment. | Sanitizer covers common patterns, but no mapping restoration, language/docs prompt registry, or all-sink guarantee. |
| KG-AI-09 | `k8sgpt/pkg/ai/interactive/interactive.go`; analyze interactive branch. | `pkg/server/handlers.go:259-303`; `pkg/server/static/app.js:334-375`. | Chat is a single Explain request; no bounded authenticated multi-turn session. |
| KG-CACHE-01 | `k8sgpt/pkg/cache/{file_based,cache}.go`; `k8sgpt/pkg/cache/{file_based,cache}_test.go`; `k8sgpt/cmd/cache`. | No `pkg/cache`; provider called directly from `cmd/sre-agent/main.go`. | No local cache, disable/list/remove/purge, encryption, or retention. |
| KG-CACHE-02 | `k8sgpt/pkg/cache/{s3_based,gcs_based,azuresa_based,interplex_based}.go`; cache lifecycle commands. | No remote cache or cache API in `pkg/config`/`pkg/server`. | Entire remote cache family is absent. |
| KG-CACHE-03 | `k8sgpt/pkg/util/util.go:GetCacheKey`; `k8sgpt/pkg/analysis/analysis.go:580-627`. | No cache key/store implementation. | Requires semantic model/prompt/schema/redaction identity and encryption. |
| KG-PRIV-01 | `k8sgpt/pkg/common/types.go:Sensitive`; `k8sgpt/pkg/analysis/analysis.go:GetAIResults`; `k8sgpt/pkg/util/util.go`. | `pkg/sanitizer/sanitizer.go`; `pkg/notifier/webhook.go`; scanner issue fields. | Regex sanitizer is not a mapping contract; raw specs/events/notifications/JSON may escape. |
| KG-API-01 | `k8sgpt/pkg/server/server.go`; `k8sgpt/cmd/serve/serve.go`; `k8sgpt/pkg/server/server_test.go`. | `pkg/server/server.go`; handlers and wildcard CORS middleware. | REST exists but no gRPC/gateway/reflection compatibility, identity, or authz. |
| KG-API-02 | `k8sgpt/pkg/server/{analyze,config,query}/*.go`; server tests. | `pkg/server/handlers.go:24-373`; `pkg/server/server.go:50-89`. | No free-form query/custom-analyzer RPC, schema version, structured transport errors, or authz. |
| KG-API-03 | `k8sgpt/pkg/server/server.go:ServeMetrics`; analyzer metrics/stats. | `pkg/server/handlers.go:24-48` status endpoint. | No Prometheus metrics or dependency-aware health/readiness endpoint. |
| KG-API-04 | `k8sgpt/pkg/server/{mcp,mcp_handlers,mcp_prompts}.go`; MCP chart values. | No MCP package, route, or deployment value. | Entire MCP transport/tool/prompt family is absent. |
| KG-EXT-01 | `k8sgpt/pkg/custom_analyzer/customAnalyzer.go`; `k8sgpt/pkg/custom/client.go`; `k8sgpt/cmd/customAnalyzer`; `k8sgpt/pkg/custom/client_test.go`. | No external analyzer client/registration in `pkg/scanner` or server. | Entire custom gRPC extension family is absent. |
| KG-EXT-02 | `k8sgpt/pkg/integration/integration.go`; AWS/KEDA/Kyverno/Prometheus plugins. | No integration contract or lifecycle package. | Entire plugin deployment/activation lifecycle is absent. |
| KG-INT-01 | `k8sgpt/pkg/integration/aws/{aws,eks}.go`; `eks_test.go`. | No AWS/EKS integration. | Requires opt-in cloud discovery, identity, and analyzer registration. |
| KG-INT-02 | `k8sgpt/pkg/integration/prometheus/{prometheus,config_analyzer,relabel_analyzer}.go`; tests. | No Prometheus integration. | Requires parser, activation, endpoint policy, and credential redaction. |
| KG-INT-03 | `k8sgpt/pkg/integration/{kyverno,keda}`; tests. | No Kyverno/KEDA integration. | Requires CRD discovery, analyzer family, and ownership-safe lifecycle. |
| KG-OPS-01 | `k8sgpt/charts/k8sgpt/{Chart.yaml,values.yaml,templates}`; Helm checks. | `deploy/k8s/{deployment,configmap,secret.example,rbac,service,ingress,kustomization}.yaml`. | Kustomize exists but Helm/ServiceMonitor/MCP packaging and release-safe selectors are absent. |
| KG-OPS-02 | `k8sgpt/.github/workflows/{build_container,golangci_lint,release,semantic_pr,test}.yaml`; `k8sgpt/.goreleaser.yaml`; `k8sgpt/container/Dockerfile`; `k8sgpt/Makefile`; release SBOM files. | `.github/workflows/ci.yaml`; `deploy/Dockerfile`; `go.mod`; `Makefile`. | CI/build exists but lacks SBOM/signing/provenance/vulnerability gates, digest pinning, and aligned toolchain. |
| KG-OPS-03 | `k8sgpt/cmd/serve/serve.go`; `k8sgpt/pkg/server/server.go`; `k8sgpt/pkg/kubernetes/kubernetes.go`; `k8sgpt/cmd/serve/serve_test.go`, `k8sgpt/pkg/kubernetes/kubernetes_test.go`. | `cmd/sre-agent/main.go:70-182`; `pkg/config/config.go`; scanner. | Proactive loop exists, but no leader election/history/overlap control, server auth, or graceful job lifecycle. |
| KG-OPS-04 | `k8sgpt/README.md`; `k8sgpt/pkg/server/README.md`; `k8sgpt/pkg/server/client_example/README.md`; `k8sgpt/RELEASE.md`, `k8sgpt/CONTRIBUTING.md`, and governance docs. | `README.md`; `deploy/k8s`; `.github/workflows/ci.yaml`. | Product docs exist but no compatible CLI/MCP/server examples, generated inventories, or upgrade contract. |

## KubeBee SRE Verification Commands

Commands below were run against the current working tree; they prove local compilation/unit behavior only and do not prove a live cluster or external provider.

| Command | Result | Interpretation |
|---|---|---|
| `go test ./... -count=1` | Passed: `cmd/sre-agent` and `pkg/config` have no tests; notifier, remediation, sanitizer, scanner, and triage passed. | Source compiles and focused package tests pass. |
| `go vet ./...` | Passed. | No vet diagnostics in the current tree. |
| `go test ./... -count=1 -coverprofile=/tmp/kubebee-sre-cover-final.out` | Passed; total statement coverage `16.9%` (`go tool cover -func ... | tail -1`). | Source compiles and focused tests pass, but server/config/entrypoint coverage is 0% and scanner coverage is 11.0%; coverage is not feature parity. |
| `go test -race ./...` | Passed for all packages. | Race coverage now exercises the ticker-adjacent packages and in-memory state, but it still does not prove live-cluster or multi-replica behavior. |
| `go vet ./...` | Passed with no diagnostics. | Static Go checks are clean for the current tree. |
| `make -n all` | Passed dry-run; expands to `go test -v -race ./...` and a static `go build` into `bin/sre-agent`. | The Makefile has no missing-target failure in the current tree; an actual build smoke test and linker metadata check remain needed. |
| `kubectl kustomize deploy/k8s` | Passed; rendered 191 lines. | Kustomize syntax and resource composition are valid; cluster admission, image availability, ingress identity, and RBAC behavior remain environment-dependent. |
| `helm lint k8sgpt/charts/k8sgpt` and `helm template k8sgpt k8sgpt/charts/k8sgpt` | Passed; lint reports only the upstream icon recommendation and default render produced 136 lines. | This validates the frozen upstream chart for comparison, not KubeBee deployment compatibility. |

## Unresolved External Evidence

- Kubernetes API semantics that depend on discovery, CRD versions, EndpointSlice, Gateway API, OLM, or admission webhooks require envtest or a disposable cluster.
- Claude, OpenAI/Codex, DeepSeek, harness, Slack, Discord, and Teams behavior requires contract fixtures or controlled endpoints; no production credentials were used.
- RBAC, ingress TLS, NetworkPolicy, image provenance, and rollout behavior require rendered-manifest checks plus a cluster admission/deployment test.
- KubeBee currently stores proposals and runtime webhook/configuration state in process memory; restart durability and multi-replica behavior therefore cannot be inferred from unit tests.
- Any row marked `Covered` in a future revision must attach the acceptance artifact named in the gap table and link it here; source similarity alone is insufficient.
