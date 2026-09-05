# K8sGPT Project, CLI, Delivery, and Asset Review

## Scope Summary

Status: **DONE_WITH_CONCERNS**. This review covers all 97 tracked paths outside `pkg/` at immutable commit `731a6c90749e8e62b9325e41712c39c0d72510c4`: governance and user documentation; GitHub CI, dependency automation, and release packaging; the in-repository Helm chart; Cobra CLI composition and flows; the production container and Grafana dashboard; dependency/history artifacts; and all visual assets. The project has broad operational documentation, pinned GitHub Action digests, focused tests for recent CLI changes, a non-root distroless runtime, and valid default/MCP Helm rendering. Material concerns include unsafe secret exposure to same-repository PR builds, branch protection that requires only DCO rather than tests/lint, overbroad chart RBAC and cross-release Service selection, release metadata/build drift, unauthenticated HTTP MCP guidance, sparse test coverage across stateful CLI commands, and governance/security documents that claim controls not present in this scope.

## File Inventory

### `.github/CODEOWNERS`
- **Role:** Defines automatic reviewers for all repository changes and special ownership of repository settings.
- **Implementation:** `/.github/settings.yml` is assigned to the maintainers team, while `*` requests maintainers, k8sgpt maintainers, and approvers; the leading slash in the settings rule correctly scopes it to the repository root.
- **Dependencies:** Relies on GitHub teams existing and branch protection requiring code-owner approval, as configured in `.github/settings.yml`.
- **Quality/Risk:** Broad default ownership is clear, but it does not create component-specific accountability and includes approvers for every path even though the documented role boundaries differ.

### `.github/ISSUE_TEMPLATE/bug_report.md`
- **Role:** Collects reproducible bug reports with environment and backend context.
- **Implementation:** Prelabels reports as `bug` and asks for expected/current behavior, four reproduction steps, K8sGPT and Kubernetes versions, AI provider, platform, and additional evidence.
- **Dependencies:** Links users to `docs.k8sgpt.ai` and assumes the `bug` label exists.
- **Quality/Risk:** The template captures useful triage fields but omits explicit redaction guidance even though logs, configuration snippets, cluster names, and provider data can be sensitive.

### `.github/ISSUE_TEMPLATE/config.yml`
- **Role:** Configures GitHub's issue chooser and support/security routes.
- **Implementation:** Disables blank issues and links documentation, a Slack invite, and `SECURITY.md`.
- **Dependencies:** Depends on external documentation and Slack URLs remaining valid and on the public security policy describing a private reporting path.
- **Quality/Risk:** Routing is concise, but directing vulnerability reporters to a policy that also suggests public/community Slack is weaker than a dedicated private advisory route.

### `.github/ISSUE_TEMPLATE/feature_request.md`
- **Role:** Structures enhancement proposals.
- **Implementation:** Prelabels issues as `enhancement` and requests problem, desired solution, alternatives, context, and willingness to implement.
- **Dependencies:** Assumes the enhancement label and issue-based design process described in governance.
- **Quality/Risk:** It supports lightweight discovery but does not ask for security, operational, compatibility, or acceptance-test impact for cluster-facing features.

### `.github/pull_request_template.md`
- **Role:** Standardizes PR descriptions and contributor self-checks.
- **Implementation:** Requests an issue link, description, code style, documentation assessment, test status, and additional breaking/dependency context.
- **Dependencies:** Complements `CONTRIBUTING.md`, semantic-title validation, DCO, CODEOWNERS, and CI.
- **Quality/Risk:** The checks are voluntary Markdown boxes and omit explicit security/supply-chain and user-visible compatibility review; emoji-heavy headings are cosmetic only.

### `.github/settings.yml`
- **Role:** Declares repository metadata, team permissions, merge policy, and `main` protection for a settings-management app.
- **Implementation:** Grants admin/maintain/push permissions to four teams, enables all three merge styles, requires one code-owner review, resolved conversations, linear history, admin enforcement, and a single required `DCO` status.
- **Dependencies:** Requires a repository-settings application and matching GitHub team/status names; CODEOWNERS supplies the review groups.
- **Quality/Risk:** Tests and lint are not required checks despite documentation claiming passing CI is mandatory, contributors receive push permission, and enabling merge commits conflicts operationally with required linear history.

### `.github/workflows/build_container.yaml`
- **Role:** Builds and publishes development multi-architecture images for pushes and eligible PRs.
- **Implementation:** Derives branch/time metadata, logs into GHCR with `K8SGPT_BOT_SECRET`, builds `linux/amd64,linux/arm64`, and publishes only a timestamp tag; Action dependencies are digest-pinned.
- **Dependencies:** Uses checkout, keptn branch extraction, Docker metadata/login/QEMU/Buildx/build-push actions, GHCR, and `container/Dockerfile`.
- **Quality/Risk:** Same-repository non-bot PR code is built with a BuildKit secret and registry credentials available, which is dangerous given contributor push access; metadata-generated tags are ignored, and build args `GIT_HASH`, `RELEASE_VERSION`, and `BUILD_TIME` do not match Dockerfile args `COMMIT`, `VERSION`, and `DATE`.

### `.github/workflows/golangci_lint.yaml`
- **Role:** Runs static analysis on pull requests to `main`.
- **Implementation:** Uses digest-pinned checkout and golangci-lint action v9 with golangci-lint `v2.12.2` and `only-new-issues: true`.
- **Dependencies:** Relies on GitHub-hosted runners and the linter action's Go/tool setup.
- **Quality/Risk:** Pinning is strong, but only-new-issues intentionally permits existing findings and the check is not required by `.github/settings.yml`.

### `.github/workflows/release.yaml`
- **Role:** Creates release-please releases, publishes GoReleaser artifacts, builds the release container, and attaches its SBOM.
- **Implementation:** Runs on `main`, maintenance branches, or dispatch; release creation gates parallel GoReleaser and multi-arch GHCR jobs, with digest-pinned actions, write-scoped permissions, Syft, and a release-attached SPDX file.
- **Dependencies:** Uses release-please, GoReleaser, Docker Buildx, GHCR, Syft, softprops release upload, bot/Slack secrets, `.goreleaser.yaml`, and the Dockerfile.
- **Quality/Risk:** The GoReleaser binary is selected as mutable `latest`, container builds pass no version args, no image signature is configured, and no explicit provenance configuration or policy is declared (although docker/build-push-action may emit default provenance); the Krew update is commented out, and these gaps contradict parts of `RELEASE.md` and the security assessment.

### `.github/workflows/semantic_pr.yaml`
- **Role:** Enforces conventional PR titles and single-commit messages.
- **Implementation:** On `pull_request_target`, a digest-pinned action accepts 12 types, optional `deps` scope, lowercase subjects, and read-only contents/PR permissions.
- **Dependencies:** Feeds release-please changelog categorization and conventional-commit guidance.
- **Quality/Risk:** The privileged event is used with minimal permissions and no PR checkout, which limits exposure; however, docs prescribe `chores` while this workflow accepts `chore`.

### `.github/workflows/test.yaml`
- **Role:** Runs the complete Go test suite and uploads coverage on pushes and PRs.
- **Implementation:** Sets up Go `~1.26`, executes `go test ./... -coverprofile=coverage.txt`, and calls digest-pinned Codecov with a token.
- **Dependencies:** Uses checkout/setup-go/Codecov and the module/toolchain declarations.
- **Quality/Risk:** There is one OS/toolchain lane, no race/vet/integration/Kubernetes-version matrix, and this workflow is not a required status in repository settings despite broader claims in technical-review documents.

### `.gitignore`
- **Role:** Excludes IDE, debug, platform, build, and example-server artifacts.
- **Implementation:** Ignores `.idea`, `.DS_Store`, debug files, VS Code patterns, `dist/`, `bin/`, and a server example while re-including `charts/k8sgpt` from the broad `k8sgpt*` pattern.
- **Dependencies:** Aligns with Makefile output under `bin/` and GoReleaser output under `dist/`.
- **Quality/Risk:** The unanchored `k8sgpt*` glob can silently hide new files/directories beginning with that name beyond the intended local binary.

### `.goreleaser.yaml`
- **Role:** Defines cross-platform binaries, archives, SBOMs, Linux packages, Homebrew publishing, checksums, snapshots, and Slack announcements.
- **Implementation:** Builds static Linux/Windows/macOS binaries, packages deb/rpm/apk, creates tar/zip archives, emits archive SBOMs, updates `homebrew-k8sgpt`, and injects version/commit/date linker values.
- **Dependencies:** Requires GoReleaser v2, Syft, repository/Slack credentials, LICENSE, and Git history/tags.
- **Quality/Risk:** Pre-release `go mod tidy` mutates the checkout, and `-X main.Date` targets a nonexistent exported variable; direct execution confirmed releases retain `built at: unknown` because the program defines lowercase `main.date`.

### `.krew.yaml`
- **Role:** Templates Krew plugin manifests for seven Darwin/Linux/Windows architecture combinations.
- **Implementation:** Uses release URLs and generated SHA256 values, renames the archive binary to `kubectl-gpt`, includes LICENSE, and exposes the plugin as `kubectl gpt`.
- **Dependencies:** Artifact names must exactly match `.goreleaser.yaml`, and publishing needs a separate Krew index update step.
- **Quality/Risk:** Coverage is broad, but the release workflow's Krew bot is disabled; Windows file/bin names omit `.exe`, which should be verified against generated archives and Krew conventions.

### `.release-please-manifest.json`
- **Role:** Stores release-please's current version for the root package.
- **Implementation:** A minimal JSON mapping records `.` at `0.4.38`.
- **Dependencies:** Must remain synchronized with release tags, README download snippets, and chart `appVersion` through `release-please-config.json`.
- **Quality/Risk:** It is machine-managed and internally consistent at this commit; manual edits could desynchronize downstream version substitutions.

### `ADOPTERS.md`
- **Role:** Provides an adopter registry and CNCF incubation evidence template.
- **Implementation:** Defines production, development/trial, and TOC-verified tables plus contribution instructions and support links.
- **Dependencies:** Relies on organizations volunteering data and maintainers/TOC verifying adoption.
- **Quality/Risk:** Every table is empty, so it currently provides no evidence for the stated requirement of three independent adopters.

### `CHANGELOG.md`
- **Role:** Machine-maintained release history for user-visible changes.
- **Implementation:** Contains 121 linked release sections from `0.0.3` (2023-03-23) through `0.4.38` (2026-09-01), categorized mainly into Features, Other, Bug Fixes, Docs, and dependency/refactoring sections.
- **Dependencies:** Generated from conventional commits by release-please and referenced by release notes/configuration.
- **Quality/Risk:** The long artifact is navigable and traceable to PRs, but its quality inherits inconsistent commit categorization; it should remain generated rather than manually curated line by line.

### `CODE_OF_CONDUCT.md`
- **Role:** Establishes community behavior expectations and enforcement.
- **Implementation:** Uses Contributor Covenant 2.0 with scope, four enforcement levels, privacy commitments, contact email, attribution, and related references.
- **Dependencies:** Requires community leaders to operate the documented process and secure reports sent to `contact@k8sgpt.ai`.
- **Quality/Risk:** Substantive and standard; it does not identify a named response group, alternate private channel, or expected response timeline.

### `CONTRIBUTING.md`
- **Role:** Guides contributors through prerequisites, issue/PR workflow, DCO, commits, builds, and releases.
- **Implementation:** Documents fork/branch/review practices, a shell helper for signoff, conventional types, local Go/container builds, and release-please behavior.
- **Dependencies:** Should match Cobra commands, `go.mod`, semantic PR validation, and the actual release workflow.
- **Quality/Risk:** It says Go 1.24+ while the module requires 1.26.3/toolchain 1.26.5, recommends nonexistent `auth key`, lists `chores` instead of accepted `chore`, and contains an unterminated `Release-As` example.

### `GENERAL_TECHNICAL_REVIEW.md`
- **Role:** Answers a CNCF-style Day 0/1/2 general technical review for incubation.
- **Implementation:** Describes personas, design, installation, security, rollout, reliability, observability, dependencies, troubleshooting, and governance at project version 0.4.32.
- **Dependencies:** Draws assertions from roadmap/governance/security/release docs and also conflates this CLI repository with the separate operator and related repositories.
- **Quality/Risk:** Numerous claims are not evidenced here: anonymization is not default, tests lack a Kubernetes-version matrix, FOSSA is absent, Helm has no probes/configurable replicas, there is a built-in dashboard, AI fallback is not implemented, and `serve --mcp` still requires provider configuration.

### `GOVERNANCE.md`
- **Role:** Defines decision-making, maintainer lifecycle, vendor neutrality, subprojects, participation, and amendments.
- **Implementation:** Prefers 48-hour consensus, then majority voting with 50% quorum; significant decisions need votes, governance amendments and revocation use two-thirds thresholds, and inactivity is six months.
- **Dependencies:** References `MAINTAINERS.md`, CNCF policy, GitHub/Slack channels, and separately governed organization repositories.
- **Quality/Risk:** It is materially clearer than informal governance, but "active maintainer" is undefined and tie-breaking power is concentrated in a named project lead.

### `INTEGRATIONS.md`
- **Role:** Catalogs ecosystem, AI provider, tool, and remote-cache integrations.
- **Implementation:** Uses tables for CNCF projects, LLM backends, adjacent tools, and S3/Azure/GCS caching, with links to MCP and custom-analyzer guidance.
- **Dependencies:** Must track backend names in code, separate operator/charts behavior, external projects, and `SUPPORTED_MODELS.md`.
- **Quality/Risk:** Several statements describe other repositories as if implemented here, the Custom REST link is invalid (`https://`), provider naming is inconsistent, and the repository's own dashboard is underrepresented.

### `LICENSE`
- **Role:** Supplies the project's legal terms.
- **Implementation:** Contains the complete Apache License 2.0 text and an application appendix naming the 2023 K8sGPT authors.
- **Dependencies:** Included in GoReleaser packages/archives and Krew installations and referenced by source headers.
- **Quality/Risk:** Canonical and complete; CRLF line endings are harmless but can create avoidable formatting churn.

### `MAINTAINERS.md`
- **Role:** Publishes current maintainer/approver definitions, responsibilities, affiliations, onboarding, and contacts.
- **Implementation:** Lists seven maintainers with domains and an empty emeritus table, then describes majority-based promotion and communication channels.
- **Dependencies:** Should align with GitHub team membership, CODEOWNERS, governance, and security response ownership.
- **Quality/Risk:** It provides accountability, but no approvers are actually listed despite defining the role, and the technical review names an additional DaoCloud maintainer absent here.

### `MCP.md`
- **Role:** Documents MCP server modes, 12 tools, three resources, three prompts, JSON-RPC examples, and client integration.
- **Implementation:** Presents stdio and stateless HTTP startup, curl payloads for discovery/invocation, Kubernetes log/resource operations, and Claude Desktop configuration.
- **Dependencies:** Must remain synchronized with `cmd/serve`, `pkg/server`, MCP Go library behavior, and Kubernetes RBAC.
- **Quality/Risk:** HTTP examples expose cluster data and operations on `0.0.0.0`-style network service usage without authentication, authorization, TLS, or network-policy guidance; documentation also uses string booleans and promises tool behavior without contract tests in this scope.

### `Makefile`
- **Role:** Provides local build, test, lint, Helm deploy, container, cleanup, and help targets.
- **Implementation:** Derives Git metadata, builds a static binary with correct lowercase `main.date`, downloads Helm 3.11.3 on demand, and supports multi-arch push/local images.
- **Dependencies:** Requires Go, Git, Docker/Buildx, curl/tar, golangci-lint, and network access for Helm.
- **Quality/Risk:** `make all` was directly verified to fail because it requires nonexistent `add-copyright` (the defined target is `copyright.add`); `clean` recursively deletes overridable `OUTPUT_DIR`, and downloaded Helm is not checksum-verified.

### `README.md`
- **Role:** Primary project overview, installation guide, CLI quick start/reference, feature/security explanation, and community entry point.
- **Implementation:** Covers package managers, operator links, analyzers, providers, filters, serve/MCP, caching, custom analyzers, plaintext config storage, and partial anonymization, with badges and three referenced local images.
- **Dependencies:** Release-please updates version snippets; behavior should match CLI flags, external docs, release assets, and image paths.
- **Quality/Risk:** It candidly warns that keys are plaintext and events are not anonymized, but also says all filters run by default, uses `k8sgpt auth` where `auth add` is required, contains stale command examples, and gives a misleading banner alt text unrelated to the logo.

### `RELEASE.md`
- **Role:** Describes release automation, cadence, versioning, artifacts, configuration, and manual triggering.
- **Implementation:** Attributes release PR/tagging to release-please and cross-platform packaging to GoReleaser, with monthly semantic-versioned releases and a `gh workflow run` example.
- **Dependencies:** Should match `release.yaml`, `.goreleaser.yaml`, `.krew.yaml`, chart publication, and Homebrew repositories.
- **Quality/Risk:** It inaccurately says GoReleaser builds containers and that the workflow updates Helm/Krew; the actual workflow builds containers separately, does not publish this chart, and has the Krew update disabled.

### `ROADMAP.md`
- **Role:** States strategic focus areas and near/medium/long-term initiatives.
- **Implementation:** Prioritizes providers, analyzers, observability, scalability, security, multi-cluster use, anomaly detection, plugins, and eventual automated remediation.
- **Dependencies:** Community issues/Slack and governance are named as prioritization inputs; dates and completion should align with releases.
- **Quality/Risk:** It is readable but has no owners, milestones, issue links, success metrics, or completed-item history, making delivery accountability difficult.

### `SECURITY.md`
- **Role:** Defines supported versions and vulnerability reporting.
- **Implementation:** Supports only the latest release and suggests email or contacting maintainers in Slack, with a simple forward-fix example.
- **Dependencies:** Relies on `contact@k8sgpt.ai`, maintainers, and release capability.
- **Quality/Risk:** Eleven lines are insufficient for a mature response policy: there is no private advisory link, encryption option, severity taxonomy, response timeline, embargo/coordinated-disclosure process, or explicit warning not to post secrets in Slack.

### `SECURITY_SELF_ASSESSMENT.md`
- **Role:** Provides an explicitly incomplete internal CNCF security self-assessment.
- **Implementation:** Describes actors/data flow, goals, controls, development pipeline, response process, known data/config/custom-analyzer risks, ecosystem, and case studies.
- **Dependencies:** Claims must be substantiated by workflows, CLI defaults, Helm RBAC, release artifacts, and separate operator behavior.
- **Quality/Risk:** It calls anonymization default when the CLI flag defaults false, labels SBOM generation as image signing, claims every PR has required CI/DCO and strict reviews when settings require only DCO, and says all backend communication uses TLS despite configurable HTTP endpoints.

### `SUPPORTED_MODELS.md`
- **Role:** Documents provider-specific model flexibility, required fields, and fixed model lists.
- **Implementation:** Covers OpenAI/Azure/local/cloud backends, Bedrock inference profiles, Vertex/Watson models, and Bedrock Mantle endpoint/model details.
- **Dependencies:** Must track fast-moving provider APIs and backend validation implemented under `pkg/ai` plus auth flags in `cmd/auth`.
- **Quality/Risk:** Hard-coded model catalogs age quickly and no generation/verification mechanism is cited; naming differs from `INTEGRATIONS.md`, and model availability links should be treated as authoritative over this snapshot.

### `charts/k8sgpt/Chart.yaml`
- **Role:** Defines the Helm application chart and default application release.
- **Implementation:** Helm API v2 chart `k8sgpt` is version `1.0.0` with appVersion `v0.4.38`, marked for generic release-please substitution.
- **Dependencies:** App version is synchronized by release-please and defaults the deployment image tag.
- **Quality/Risk:** Helm lint passes, with only a recommended icon warning; chart version is static and therefore cannot communicate template changes independently from app releases.

### `charts/k8sgpt/templates/_helpers.tpl`
- **Role:** Centralizes chart naming and standard labels.
- **Implementation:** Produces DNS-length name/fullname/chart values and managed-by, name, instance, chart, and optional app-version labels.
- **Dependencies:** Included by every workload/RBAC/service template and driven by name/fullname overrides.
- **Quality/Risk:** Standard Helm patterns are used correctly, though selectors later fail to consume the complete instance label consistently.

### `charts/k8sgpt/templates/deployment.yaml`
- **Role:** Deploys one K8sGPT serve-mode pod with optional MCP, provider environment, and ephemeral config.
- **Implementation:** Uses one replica, service account, image/tag values, ports 8080/8081/optional MCP, `serve` args, optional pod security context/resources, env-backed provider settings, and `emptyDir` mounted as XDG config/cache.
- **Dependencies:** Requires chart values, optional generated Secret, container entrypoint, Kubernetes API RBAC, and the CLI's environment bootstrap.
- **Quality/Risk:** There are no readiness/liveness probes, pod/container security defaults, affinity/PDB, configurable replicas, or persistent configuration; MCP `http` value is ignored because `--mcp-http` is always supplied when enabled.

### `charts/k8sgpt/templates/role.yaml`
- **Role:** Grants the chart's service account cluster-wide analyzer access.
- **Implementation:** Creates a ClusterRole allowing `get`, `list`, and `watch` on `*` resources in `*` API groups.
- **Dependencies:** Bound by `rolebinding.yaml` and required by broad analyzer discovery.
- **Quality/Risk:** Verbs are read-only but the resource/API scope is maximally broad, including Secrets; the namespaced metadata field is ineffective for ClusterRole and least-privilege claims are overstated.

### `charts/k8sgpt/templates/rolebinding.yaml`
- **Role:** Binds the release service account to its ClusterRole.
- **Implementation:** Creates a cluster-scoped binding with a namespaced ServiceAccount subject and matching generated role name.
- **Dependencies:** Requires `sa.yaml`, `role.yaml`, and stable helper-generated names.
- **Quality/Risk:** The binding is structurally valid, but its own namespace metadata is ignored and it propagates the overbroad all-resource ClusterRole cluster-wide.

### `charts/k8sgpt/templates/sa.yaml`
- **Role:** Creates the workload identity used by the deployment.
- **Implementation:** Emits a namespaced ServiceAccount with helper-generated name and standard chart labels.
- **Dependencies:** Referenced by the Deployment and ClusterRoleBinding.
- **Quality/Risk:** Minimal and valid; there is no value to disable creation/use an existing account or configure annotations for workload identity.

### `charts/k8sgpt/templates/secret.yaml`
- **Role:** Optionally stores the AI backend credential.
- **Implementation:** Creates Opaque Secret `ai-backend-secret` with caller-supplied `data.secret-key`, expecting users to provide base64 themselves.
- **Dependencies:** Deployment references the fixed name/key when `.Values.secret.secretKey` is nonempty.
- **Quality/Risk:** The fixed name collides across releases in one namespace, user-supplied base64 is error-prone, and embedding credentials in values increases Git/Helm release-secret exposure; `stringData` or external-secret integration would be safer ergonomically.

### `charts/k8sgpt/templates/service.yaml`
- **Role:** Exposes gRPC/HTTP, metrics, and optional MCP ports.
- **Implementation:** Creates a configurable Service with ports 8080, 8081, and MCP, plus optional annotations.
- **Dependencies:** Selects deployment pods and supplies the named `metrics` port consumed by ServiceMonitor.
- **Quality/Risk:** Its selector includes only app name, not release instance, so multiple same-chart releases in a namespace can route to each other's pods; network-exposed MCP has no chart-level access control.

### `charts/k8sgpt/templates/serviceMonitor.yaml`
- **Role:** Optionally registers the metrics endpoint with Prometheus Operator.
- **Implementation:** Emits a ServiceMonitor selecting both app name and release instance, scraping `/metrics` via the `metrics` Service port with honorLabels.
- **Dependencies:** Requires the Prometheus Operator CRD and matching Service labels/port.
- **Quality/Risk:** Template logic is sound and optional labels support operator discovery, but no interval, timeout, TLS, authorization, or namespace-selector values are available.

### `charts/k8sgpt/values-mcp-example.yaml`
- **Role:** Demonstrates enabling networked MCP through Helm.
- **Implementation:** Enables MCP on string port `8089`, repeats image/provider/resources/service/secret/monitor defaults, and describes the API key as base64 encoded.
- **Dependencies:** Merges with chart defaults and is consumed by deployment/service templates.
- **Quality/Risk:** It exposes MCP without authentication/TLS guidance and defines `mcp.http`, but the template never reads that field; duplication invites drift from `values.yaml`.

### `charts/k8sgpt/values.yaml`
- **Role:** Supplies chart defaults for image, provider, MCP, resources, security context, secret, Service, and ServiceMonitor.
- **Implementation:** Defaults to GHCR and Chart appVersion, Always pull, OpenAI/gpt-3.5-turbo, MCP disabled, constrained resources, empty security context, ClusterIP, and monitoring disabled.
- **Dependencies:** All chart templates consume these values; runtime image itself enforces UID/GID 65532.
- **Quality/Risk:** Defaults omit pod/container hardening, probes, replica control, network policy, and secret-provider alternatives; the backend comment lists only OpenAI/llama despite much broader support.

### `cmd/analyze/analyze.go`
- **Role:** Implements the primary cluster scan, optional AI explanation, output/stats, custom analysis, and interactive follow-up flow.
- **Implementation:** Resolves `Kind/Name` into a filter/name selector, constructs `analysis.NewAnalysis`, runs analyzers, optionally calls AI/anonymization, prints text/JSON and stats, and runs an interrupt-aware interactive client.
- **Dependencies:** Uses Cobra/Viper/color and `pkg/analysis`/interactive AI; persistent Kubernetes flags are set in root.
- **Quality/Risk:** Extensive flags are useful, but `os.Exit` throughout bypasses deferred cleanup and hinders testing, global mutable flag state complicates repeated execution, and resource parsing accepts extra slashes in the name.

### `cmd/analyze/analyze_test.go`
- **Role:** Tests reconciliation of `--resource` and `--filter`.
- **Implementation:** Table tests no-resource, implicit/matching/case-insensitive filters, conflicting filters, and missing kind/name halves.
- **Dependencies:** Directly exercises the pure `resolveResourceSelection` helper.
- **Quality/Risk:** Focused coverage is good; missing cases include whitespace kind normalization, `Kind/name/extra`, repeated matching filters, and end-to-end propagation to analyzers.

### `cmd/auth/add.go`
- **Role:** Adds an AI provider and persists its credential/model/provider-specific settings.
- **Implementation:** Validates backend/Azure type and sampling ranges, conditionally requires cloud fields, prompts invisibly for required passwords, applies provider-specific model defaults, rejects duplicate names, and writes Viper config.
- **Dependencies:** Uses the backend registry and password policy in `pkg/ai`, terminal input, go-openai API types, and shared package globals.
- **Quality/Risk:** `--password` exposes secrets to process history, configuration remains plaintext, required-field logic is string-name based, and command-level `os.Exit` makes atomic/error-path testing difficult.

### `cmd/auth/auth.go`
- **Role:** Defines shared auth state and groups add/list/remove/default/update subcommands.
- **Implementation:** Declares all provider flag variables plus `ai.AIConfiguration`; bare `auth` prints help.
- **Dependencies:** Every auth source file shares these globals and Cobra command instances.
- **Quality/Risk:** Centralization is simple but creates cross-test/cross-execution state leakage and prevents independent concurrent command construction.

### `cmd/auth/default.go`
- **Role:** Reads or changes the default configured AI provider.
- **Implementation:** Without `--provider` it reports configured/default OpenAI and exits; otherwise lowercases the name, validates existence, updates configuration, and writes it.
- **Dependencies:** Uses Viper's `ai` configuration and providers created by `auth add`.
- **Quality/Risk:** Calling `os.Exit(0)` for a normal query is hostile to embedding/tests, and forcing lowercase may fail for previously stored non-normalized provider names.

### `cmd/auth/list.go`
- **Role:** Lists default, active, and unused backends with optional non-secret details.
- **Implementation:** Cross-compares configured providers with `ai.Backends`, colorizes groups, and shows model, engine, and base URL under `--details`.
- **Dependencies:** Depends on backend registry ordering and Viper configuration schema.
- **Quality/Risk:** It intentionally omits passwords and custom headers, which is good; nested loops are minor and duplicate/unknown configured providers are silently hidden.

### `cmd/auth/provider_helpers.go`
- **Role:** Maps auth flags into provider structures and applies selected updates.
- **Implementation:** Add mapping includes all shared fields, while update changes name/model/password/base URL/engine/org/Azure fields and always assigns temperature.
- **Dependencies:** Couples directly to package-global flags and `ai.AIProvider` fields.
- **Quality/Risk:** Update cannot preserve "unspecified" temperature because Cobra defaults it to 0.7, and it omits endpoint, region, provider/compartment IDs, top-p/top-k/max-token/stop-sequence fields supported by add.

### `cmd/auth/provider_helpers_test.go`
- **Role:** Verifies Azure API version persistence, flag-to-provider mapping, updates, and backend-specific model defaults.
- **Implementation:** Uses temporary 0600 config files, Viper resets, direct command `Run` invocation, shared-state reset helpers, and field assertions.
- **Dependencies:** Requires the singleton Cobra commands/Viper and provider schema.
- **Quality/Risk:** Tests cover recent regressions well but bypass `PreRun`, so they do not reveal that real Azure updates require engine/base URL even for an API-version-only change; flag values on singleton commands are not fully reset.

### `cmd/auth/remove.go`
- **Role:** Removes one or more comma-separated provider configurations.
- **Implementation:** Requires `--backends`, splices matched providers, resets a removed default to OpenAI, errors on missing names, then persists.
- **Dependencies:** Uses shared auth configuration and Viper write semantics.
- **Quality/Risk:** No whitespace/case normalization is performed, a stale error recommends nonexistent `auth new`, and all errors terminate the process rather than return command errors.

### `cmd/auth/update.go`
- **Role:** Updates selected fields of an existing backend.
- **Implementation:** Requires backend, imposes Azure engine/base URL requirements and API-type validation, restricts organization ID to OpenAI/Azure, validates temperature, mutates matching providers, and writes config.
- **Dependencies:** Uses go-openai types, shared flags/helper, and Viper.
- **Quality/Risk:** Actual Cobra execution cannot perform a narrow Azure credential/version update without resupplying endpoint fields; supported add-time sampling/cloud fields cannot be updated, while default temperature overwrites prior values.

### `cmd/cache/add.go`
- **Role:** Configures one remote cache provider.
- **Implementation:** Accepts Azure, GCS, S3, or Interplex type and cloud-specific region/bucket/project/storage/endpoint/insecure flags, with required-together and mutual-exclusion constraints.
- **Dependencies:** Delegates construction and persistence to `pkg/cache` and external cloud credentials.
- **Quality/Risk:** `--insecure` permits TLS verification bypass, provider requirements are not fully expressed in Cobra validation, and there are no tests in this package for destructive or cloud-specific flag combinations.

### `cmd/cache/cache.go`
- **Role:** Defines the cache command group.
- **Implementation:** Bare execution renders help; subcommands self-register from their own `init` functions.
- **Dependencies:** Root command registration and Cobra initialization order.
- **Quality/Risk:** The help failure panics rather than returning an error, unlike most other command groups; no tests cover registration/help behavior.

### `cmd/cache/get.go`
- **Role:** Reports the currently configured remote cache.
- **Implementation:** Loads cache configuration and prints the provider name.
- **Dependencies:** Uses `pkg/cache.GetCacheConfiguration` and provider `GetName`.
- **Quality/Risk:** Simple flow, but output lacks a trailing newline and uses `os.Exit` on load failures; no test covers missing/corrupt configuration.

### `cmd/cache/list.go`
- **Role:** Displays remote-cache objects and timestamps in a table.
- **Implementation:** Loads the active provider, calls `List`, reflects `CacheObjectDetails` fields for headers, appends name/update rows, and renders with tablewriter.
- **Dependencies:** Assumes exactly the cache detail schema/order returned by `pkg/cache` and tablewriter's API.
- **Quality/Risk:** Reflection dynamically tracks headers but row construction is fixed to two fields, so adding a struct field can break rendering; remote error/empty cases are untested.

### `cmd/cache/purge.go`
- **Role:** Deletes one named cached object or every object.
- **Implementation:** `--all` lists then removes entries sequentially and reports aggregate failed names; otherwise the first positional argument is deleted.
- **Dependencies:** Uses the configured remote provider's List/Remove operations.
- **Quality/Risk:** `--all` performs irreversible remote deletion without confirmation or exact-argument validation, and partial failure leaves an unknown subset removed; no tests protect this path.

### `cmd/cache/remove.go`
- **Role:** Removes remote-cache configuration and returns to file cache.
- **Implementation:** Delegates to `pkg/cache.RemoveRemoteCache` and prints success.
- **Dependencies:** Depends on cache configuration persistence; deliberately does not delete upstream storage.
- **Quality/Risk:** Scope is appropriately narrow, but behavior and recovery from corrupt/missing config are untested.

### `cmd/customAnalyzer/add.go`
- **Role:** Adds a remote custom analyzer endpoint to local configuration.
- **Implementation:** Reads configured analyzers, validates name/URL/port via `Check`, appends connection data, writes config, and uses localhost:8085 defaults.
- **Dependencies:** Uses `pkg/custom_analyzer`, Viper, and a separately running analyzer service.
- **Quality/Risk:** Defaults allow an accidental bare `add` to persist a placeholder analyzer, transport security/authentication are absent from the CLI surface, and no tests cover duplicates or validation.

### `cmd/customAnalyzer/customAnalyzer.go`
- **Role:** Defines the custom-analyzer command group and shared configuration slice.
- **Implementation:** Registers add/remove/list and shows help on bare invocation.
- **Dependencies:** Uses the custom analyzer schema and root Cobra command.
- **Quality/Risk:** Functional grouping is clear, but singleton global configuration shares the same testability/reentrancy issues as auth.

### `cmd/customAnalyzer/list.go`
- **Role:** Lists configured custom analyzers and optional connection details.
- **Implementation:** Unmarshals `custom_analyzers`, prints names, and under `--details` prints URL and port.
- **Dependencies:** Relies on Viper and the custom analyzer connection schema.
- **Quality/Risk:** Details may disclose internal network topology in logs/support output; there is no connectivity/status check or test coverage.

### `cmd/customAnalyzer/remove.go`
- **Role:** Removes comma-separated custom analyzer entries.
- **Implementation:** Requires `--names`, validates nonempty input, splices exact-name matches, fails on missing names, and writes the resulting slice.
- **Dependencies:** Uses shared Viper configuration state.
- **Quality/Risk:** Exact untrimmed matching is brittle, process exits impede composition, and multi-name/error behavior has no tests.

### `cmd/dump/dump.go`
- **Role:** Produces a timestamped JSON support bundle containing AI configuration, filters, cluster version, and K8sGPT build info.
- **Implementation:** Removes custom headers, replaces passwords with their first four characters plus `***`, queries Kubernetes discovery, marshals indented JSON, and writes mode 0644 in the current directory.
- **Dependencies:** Uses Viper, AI schema, Kubernetes client/discovery, local filesystem, and version values set by root.
- **Quality/Risk:** Retaining credential prefixes and other endpoint/org/provider fields conflicts with "non-sensitive" wording, and world-readable 0644 output can leak configuration; redaction and failure paths are untested.

### `cmd/filters/add.go`
- **Role:** Enables one or more analyzer filters.
- **Implementation:** Validates exact names against core/additional/integration filters, warns for Log data exposure, defaults active state to core filters, rejects duplicates, and writes config.
- **Dependencies:** Uses analyzer registry and duplicate-removal utility under `pkg/`, plus Viper.
- **Quality/Risk:** The explicit Log warning is valuable, but case/whitespace-sensitive comma parsing is unforgiving and only Log gets sensitivity messaging even though events can also expose data.

### `cmd/filters/filters.go`
- **Role:** Groups filter management commands and provides aliases/help.
- **Implementation:** Registers list/add/remove and shows help when invoked without arguments.
- **Dependencies:** Root Cobra composition and sibling subcommands.
- **Quality/Risk:** Clear and small; behavior has no direct command registration/help tests.

### `cmd/filters/list.go`
- **Role:** Displays active and unused core, optional, and integration filters.
- **Implementation:** Defaults empty config to core filters, computes set difference, color-codes integration filters, and asks integration ownership logic before printing active non-integrations.
- **Dependencies:** Uses analyzer/integration registries, slices, utility diff, and Viper.
- **Quality/Risk:** Repeated integration ownership calls may be costly or side-effectful, and errors are used as normal classification signals; output consistency is untested.

### `cmd/filters/remove.go`
- **Role:** Disables one or more active filters.
- **Implementation:** Parses one comma-separated argument, defaults to core filters, rejects empty/duplicate inputs, splices exact matches, rejects unknown active entries, and persists.
- **Dependencies:** Uses analyzer core defaults, duplicate utility, and Viper.
- **Quality/Risk:** Validation is sensible but case/space brittle; the Long description incorrectly says "add command," and state transitions lack tests.

### `cmd/generate/generate.go`
- **Role:** Opens a browser to obtain an API key.
- **Implementation:** Reads/overrides a backend label, launches the platform opener, and always opens `https://platform.openai.com/api-keys` while printing follow-up `auth add` instructions.
- **Dependencies:** Uses OS-specific `xdg-open`, `rundll32`, or `open`, plus a GUI/session.
- **Quality/Risk:** The backend option is misleading because every backend opens the OpenAI page; errors are merely printed and the command can report backend-specific success text for the wrong provider.

### `cmd/integration/activate.go`
- **Role:** Activates and optionally installs a named integration.
- **Implementation:** Defaults active filters to core filters and delegates activation with namespace and `--no-install` to `pkg/integration`.
- **Dependencies:** Analyzer registry, Viper state, integration implementation, and potentially cluster installation permissions.
- **Quality/Risk:** Integration errors are printed then returned with a successful process status, which breaks automation; spelling/help quality and absence of tests compound ambiguity.

### `cmd/integration/deactivate.go`
- **Role:** Deactivates a named integration in a namespace.
- **Implementation:** Requires exactly one argument, delegates to the integration provider, and prints confirmation.
- **Dependencies:** `pkg/integration` owns uninstallation/config effects.
- **Quality/Risk:** Like activation, failures return without a nonzero Cobra error/exit code, so scripts may treat a failed deactivation as successful.

### `cmd/integration/integration.go`
- **Role:** Groups integration commands and defines a shared namespace.
- **Implementation:** Supports singular/plural aliases, prints help by default, and defaults namespace to `default`.
- **Dependencies:** Sibling activate/deactivate/list commands and root Cobra registration.
- **Quality/Risk:** The examples are helpful, but a cluster-scoped or installation-specific default namespace may be surprising and there is no config-driven default validation.

### `cmd/integration/list.go`
- **Role:** Separates built-in integrations into active and unused lists.
- **Implementation:** Calls `IsActivate` once per integration in each of two loops and prints both groups.
- **Dependencies:** Relies on integration provider discovery/state checks.
- **Quality/Risk:** State checks are duplicated, unused entries are colored green like active ones, and errors terminate immediately; no output/error tests exist.

### `cmd/root.go`
- **Role:** Composes the CLI, manages build metadata, global Kubernetes/config/verbosity flags, Viper environment loading, and legacy config migration.
- **Implementation:** Migrates `~/.k8sgpt.yaml` to XDG config during package initialization, registers nine command groups, writes/reads YAML config, sets K8SGPT env handling, and exits on Cobra errors.
- **Dependencies:** Cobra, Viper, XDG paths, filesystem utilities, and all command packages.
- **Quality/Risk:** Filesystem migration at `init` time affects even help/import/tests, `viper.Set` gives empty CLI flag values precedence over config-file kube settings, and SafeWrite/Write config handling silently ignores many errors.

### `cmd/root_test.go`
- **Role:** Verifies propagation of the verbose global into Viper.
- **Implementation:** Mutates package-global `verbose`, resets Viper, invokes `initConfig`, and asserts the boolean.
- **Dependencies:** Uses real root globals/XDG behavior rather than an isolated command/config object.
- **Quality/Risk:** It does not restore `verbose` or set a temporary config path, can interact with developer config discovery, and misses migration, precedence, environment, and execution cases.

### `cmd/serve/serve.go`
- **Role:** Runs API and metrics servers and optionally an MCP server, sourcing an AI provider from config or environment.
- **Implementation:** Parses sampling/custom-header env values, may persist an env-built provider, validates the selected backend, starts Zap logging, MCP, metrics, and main servers in goroutines, then blocks forever.
- **Dependencies:** `pkg/server`, `pkg/ai`, Cobra/Viper, HTTP headers, environment variables, and local config writeability.
- **Quality/Risk:** Partial env presence is treated as a provider and written before name validation, potentially persisting invalid/plaintext secrets; MCP startup still launches other listeners, goroutine `os.Exit` is abrupt, and top-k validates 10-100 while claiming 1-100.

### `cmd/serve/serve_test.go`
- **Role:** Tests environment-to-provider mapping for Azure API version/custom fields and the all-unset path.
- **Implementation:** Uses `t.Setenv` and injected closures for headers/sampling values, then asserts selected provider fields.
- **Dependencies:** Directly exercises `providerFromEnv` without starting servers or touching Viper.
- **Quality/Risk:** The helper seam is useful, but no tests cover partial envs, range parsing, provider selection, config persistence, listener failures, MCP mode, or graceful shutdown.

### `cmd/version.go`
- **Role:** Prints version, commit, and build time.
- **Implementation:** Uses injected linker globals, and for development builds falls back to Go build information and VCS settings before formatting one line.
- **Dependencies:** `main.go`, Makefile/GoReleaser/Docker linker flags, and Go module build metadata.
- **Quality/Risk:** Fallback behavior is reasonable, but package globals are mutated; release configuration's case-mismatched date target was directly shown to leave `unknown`.

### `container/Dockerfile`
- **Role:** Builds a static K8sGPT binary and packages it in a minimal non-root runtime image.
- **Implementation:** Uses `golang:1.27-alpine3.23`, downloads modules before copying source, injects version fields, then copies only the binary into `gcr.io/distroless/static` and runs UID/GID 65532.
- **Dependencies:** Requires network module downloads, full build context, mutable upstream image tags, and matching CI build args.
- **Quality/Risk:** Multi-stage/distroless/non-root are strong; base images are not digest-pinned, no build-cache mounts or healthcheck exist, and CI/release argument mismatches leave production metadata blank/unknown.

### `container/dashboards/k8sgpt-dashboard.json`
- **Role:** Importable Grafana dashboard for K8sGPT analyzer error metrics.
- **Implementation:** Grafana schema 38/plugin 9.4.7 dashboard with six panels, a Prometheus datasource UID fixed to `prometheus`, namespace multi-select, total/per-analyzer gauges and time series over five minutes, and external logo/help links.
- **Dependencies:** Requires metric `analyzer_errors` with `namespace`/`analyzer_name` labels, Grafana, Prometheus, and a matching datasource UID.
- **Quality/Risk:** Useful baseline observability, but no refresh is configured, threshold 80 is unexplained, fixed datasource/dashboard IDs hinder provisioning portability, and technical-review docs incorrectly claim no built-in dashboard.

### `go.mod`
- **Role:** Declares module identity, Go/toolchain requirements, direct and transitive dependencies, and compatibility replacements.
- **Implementation:** Requires Go 1.26.3/toolchain 1.26.5 and a large cloud/AI/Kubernetes/Helm/Prometheus stack; replaces Docker with 28.0.4 and `dario.cat/mergo` with the legacy module path.
- **Dependencies:** Drives all builds, tests, dependency automation, and `go.sum`; several heavyweight libraries are linked to provider/integration features.
- **Quality/Risk:** Versions are explicit, but the broad dependency/supply-chain footprint is substantial, Kubernetes modules mix 0.32.2/0.32.3, contributor guidance understates the minimum (Go 1.24 versus 1.26.3), and Docker's Go 1.27 satisfies the module minimum while creating build-toolchain/version drift across development, CI, and container paths.

### `go.sum`
- **Role:** Integrity-lock artifact for the complete Go module build list and historical module graph.
- **Implementation:** Contains 2,351 checksum lines across GitHub, Google/Go/Kubernetes/cloud and other hosts; SHA256 of this tracked artifact is `11f2f165c32d8482b1f51ef58330a611fcacdc0d9f25ad5294f7ddb21e1d4e58`.
- **Dependencies:** Generated by Go module resolution/tidy from `go.mod` and verified through the public checksum ecosystem where available.
- **Quality/Risk:** Checksums support reproducibility but do not attest maintainer trust or vulnerability status; GoReleaser's pre-hook can rewrite this file during release if module metadata drifts.

### `images/banner-black.png`
- **Role:** README banner variant intended for light backgrounds.
- **Implementation:** 78,345-byte 1576x710 RGBA PNG showing the blue concentric K8sGPT mark with black wordmark/tagline; README references it as the fallback image.
- **Dependencies:** Paired with `banner-white.png` through README `<picture>` media selection.
- **Quality/Risk:** Correctly optimized enough for documentation, but the README alt text describes unrelated light/dark sample text instead of the K8sGPT identity.

### `images/banner-white.png`
- **Role:** README banner variant intended for dark backgrounds.
- **Implementation:** 79,995-byte 1576x710 RGBA PNG showing the blue mark with white `K8SGPT KUBERNETES SUPERPOWERS` wordmark; referenced by README dark-mode source.
- **Dependencies:** Raster counterpart to the unreferenced white SVG.
- **Quality/Risk:** Visually appropriate and modest size; duplicated raster/vector sources can drift without an asset-generation source of truth.

### `images/banner-white.svg`
- **Role:** Scalable source/variant of the white K8sGPT banner.
- **Implementation:** 22,770-byte 788x355 SVG with viewBox `0 0 788 355` and eight path elements; it contains vector outlines rather than external resources.
- **Dependencies:** Corresponds visually and at 2x scale to `banner-white.png` but has no tracked reference.
- **Quality/Risk:** Compact, self-contained vector content is reusable, yet being orphaned makes its maintenance purpose unclear and outlined text reduces accessibility/editability.

### `images/demo.gif`
- **Role:** Legacy animated terminal demonstration.
- **Implementation:** 335,106-byte GIF89a at 1073x739; visual inspection shows a K8sGPT repository prompt and the animation is not referenced by any tracked non-image file.
- **Dependencies:** Captures historical CLI behavior/tooling rather than being generated in the current build.
- **Quality/Risk:** Orphaned animation adds repository weight and can become behaviorally stale; terminal recordings may expose environment names and should be reviewed before reuse.

### `images/demo1.gif`
- **Role:** Legacy smaller terminal demonstration.
- **Implementation:** 235,209-byte GIF89a at 683x470 beginning at a K8sGPT repository prompt; no tracked reference exists.
- **Dependencies:** Standalone documentation media with no current consumer.
- **Quality/Risk:** Orphaned and likely redundant with other demos, so its user value no longer offsets maintenance/clone cost unless intentionally archived.

### `images/demo2.gif`
- **Role:** Legacy terminal workflow animation.
- **Implementation:** 263,501-byte GIF89a at 1020x608 using a dark terminal capture; it is unreferenced in tracked text.
- **Dependencies:** Encodes a point-in-time CLI flow and visual theme.
- **Quality/Risk:** Unreferenced demos are difficult to validate for current commands, output, privacy, and accessibility; a caption/transcript is absent.

### `images/demo3.png`
- **Role:** Static example of JSON analysis output.
- **Implementation:** 360,972-byte 2628x1780 RGBA screenshot showing `analyze --filter svc,pod,pvc --explain -o json | jq` with Argo CD/default namespace findings and generated explanations.
- **Dependencies:** Represents CLI output and cluster-derived sample data but is not referenced by tracked documentation.
- **Quality/Risk:** Orphaned, large, and contains concrete resource identifiers/UUID-like values; screenshots are inaccessible and stale more quickly than text fixtures.

### `images/demo4.gif`
- **Role:** Primary animated README demonstration.
- **Implementation:** 220,550-byte GIF89a at 1020x627, referenced at README line 30 and beginning with the terminal prompt before demonstrating CLI use.
- **Dependencies:** This is the only demo animation currently linked from README.
- **Quality/Risk:** It provides immediate product context, but lacks alt text/transcript and should be regenerated when commands/output materially change.

### `images/demo5.gif`
- **Role:** Additional terminal demonstration.
- **Implementation:** 1,450,453-byte GIF89a at 657x470, by far the largest visual asset, beginning with a K8sGPT prompt on Kubernetes v1.20.3; no tracked reference exists.
- **Dependencies:** Historical recorded CLI/Kubernetes environment.
- **Quality/Risk:** Large, orphaned, and visibly tied to an old Kubernetes version, making it a strong cleanup/archive candidate.

### `images/image.png`
- **Role:** Static promotional CLI output screenshot.
- **Implementation:** 315,604-byte 1872x1216 RGBA image showing the obsolete `./k8sgpt find problems --explain` syntax and example image-pull/OOM diagnoses.
- **Dependencies:** Historical CLI behavior; no tracked file references it.
- **Quality/Risk:** The obsolete command makes the unreferenced screenshot actively misleading, and text embedded in imagery is inaccessible/search-invisible.

### `images/landing.png`
- **Role:** Static terminal capture of `k8sgpt analyze --explain` results.
- **Implementation:** 412,236-byte 2630x1870 RGBA screenshot with progress/output for Argo CD and demo workloads; it is unreferenced.
- **Dependencies:** Captures point-in-time analyzer and AI output.
- **Quality/Risk:** Large and orphaned, with concrete namespace/workload identifiers and no accessible transcript; generated advice can age independently of code.

### `images/nodes.gif`
- **Role:** Legacy animation likely demonstrating node analysis.
- **Implementation:** 122,414-byte GIF89a at 615x412 beginning at a K8sGPT prompt on Kubernetes v1.20.3; no tracked text references it.
- **Dependencies:** Historical terminal recording only.
- **Quality/Risk:** Its old environment and orphaned state make correctness unverifiable for current releases; retain only with explicit documentation ownership.

### `main.go`
- **Role:** Minimal executable entrypoint and linker metadata owner.
- **Implementation:** Defines lowercase `version`, `commit`, and `date` defaults and passes them to `cmd.Execute`.
- **Dependencies:** Build pipelines must target exact symbol casing; `cmd/version.go` reads the resulting values.
- **Quality/Risk:** Deliberately small and clear; inconsistent linker flags elsewhere demonstrate the need for a build-time version test.

### `release-please-config.json`
- **Role:** Configures root Go release versioning, changelog sections, and extra-file substitutions.
- **Implementation:** Uses manifest mode, pre-1.0 minor/patch rules, updates README and Chart appVersion, exposes selected commit categories, and hides build/CI/revert/style/test sections.
- **Dependencies:** Works with the manifest, semantic PR titles, changelog, README markers, and Chart generic version marker.
- **Quality/Risk:** Schema-backed structure is clear, but hiding CI/build changes can obscure operationally significant release changes and chart package version is not incremented.

### `renovate.json`
- **Role:** Automates dependency update grouping, labels, Go tidying, digest pinning, and merging.
- **Implementation:** Extends base/digest/signoff/all-nonmajor presets, schedules anytime, enables platform automerge, groups Azure/Prometheus/Kubernetes/Go, labels managers, and scans version variables with regex.
- **Dependencies:** Requires Renovate, branch protection, supported managers, and matching `_VERSION` comments.
- **Quality/Risk:** Top-level automerge is broad and should be audited for major-update behavior, regex scanning covers many files, and automated tidy can create wide module churn in a very large dependency graph.

## Scope Findings

**Strengths**

- All reviewed GitHub Actions references are digest-pinned, release images get an attached Syft SPDX SBOM, and the runtime is a static non-root binary in distroless (`.github/workflows/*.yaml`, `container/Dockerfile`).
- CLI structure is discoverable and the focused resource-selection/Azure-version/provider-env regression tests pass (`cmd/analyze/analyze_test.go`, `cmd/auth/provider_helpers_test.go`, `cmd/serve/serve_test.go`). Direct verification: `go test ./cmd/...` passed for every command package.
- The chart is small and renderable in both modes. Direct verification: `helm lint charts/k8sgpt`, default `helm template`, and MCP-example `helm template` all succeeded (`charts/k8sgpt/**`).
- User documentation openly acknowledges plaintext API-key storage, incomplete event anonymization, destructive cache purging, and local-model alternatives (`README.md`), which is more useful than an unconditional privacy claim.

**Risks**

- **High - PR secret boundary:** same-repository PR Docker builds receive a bot BuildKit secret and registry login while repository settings give contributors push permission; PR-controlled Dockerfile/build context could exfiltrate credentials (`.github/workflows/build_container.yaml`, `.github/settings.yml`). Restrict publishing to trusted push workflows or approval-gated environments and never pass release secrets to untrusted code builds.
- **High - network/cluster exposure:** MCP HTTP documentation and Helm exposure include no authentication, authorization, TLS, or network policy, while the ServiceAccount can read every resource including Secrets (`MCP.md`, `charts/k8sgpt/templates/role.yaml`, `charts/k8sgpt/templates/service.yaml`). Define an authenticated threat model and reduce RBAC to analyzer-required resources.
- **High - inaccurate security posture:** assessment/review documents claim default anonymization, TLS-only backends, image signing, required CI, FOSSA, multi-version tests, probes, fallback, and other controls not evidenced by implementation (`SECURITY_SELF_ASSESSMENT.md`, `GENERAL_TECHNICAL_REVIEW.md`, `cmd/analyze/analyze.go`, `.github/**`, `charts/**`). Treat these as governance defects, not wording polish.
- **Medium - release correctness:** container workflows do not supply the Dockerfile's expected build args, GoReleaser writes nonexistent `main.Date`, and `make all` references nonexistent `add-copyright` (`build_container.yaml`, `release.yaml`, `.goreleaser.yaml`, `Makefile`, `main.go`). Direct checks produced `built at: unknown` and `No rule to make target 'add-copyright'`.
- **Medium - Helm multi-release isolation:** the Service omits the instance selector and the Secret has a fixed name, allowing routing/credential collisions between releases in one namespace (`charts/k8sgpt/templates/service.yaml`, `secret.yaml`).
- **Medium - support bundle leakage:** dump files are 0644 and retain the first four credential characters plus sensitive provider metadata (`cmd/dump/dump.go`). Fully redact and create with 0600.
- **Medium - weak merge gates:** branch protection requires only DCO, not tests, lint, semantic validation, or container build (`.github/settings.yml`). This conflicts with contributor/security documentation and permits merging known failing code after one review.
- **Medium - stateful CLI reliability:** most commands use package globals and `os.Exit`, and cache/custom-analyzer/filter/integration/dump/generate paths have no tests. Integration failures can even return success status (`cmd/**`).

**Improvement Opportunities**

- Add release smoke tests that build through each official path, run `k8sgpt version`, verify expected tags/metadata, and reconcile `RELEASE.md` with actual Homebrew/Krew/chart/container publishers.
- Build fresh Cobra command trees with returned errors and injected config/filesystem/server interfaces; prioritize destructive cache operations, config precedence/migration, provider partial-env validation, and integration exit codes.
- Publish a narrowly scoped RBAC matrix per analyzer, chart configurable existing-ServiceAccount/external-secret/network-policy/probes/security contexts, and include release instance in every selector/name.
- Replace orphaned/stale media with an owned, reproducible current demo plus alt text/transcript; 8 of 11 visual assets have no tracked reference, and `images/demo5.gif` alone is 1.45 MB.
- Upgrade `SECURITY.md` to a private coordinated-disclosure process and mechanically audit CNCF review assertions against repository evidence before publishing future assessments.

## Coverage Verification

- Expected scope: 97 paths from `git ls-files | awk '$0 !~ /^pkg\//'`.
- Documented records: 97 unique H3 backtick paths.
- Missing paths: 0.
- Extra paths: 0.
- Duplicate paths: 0.
- Source repository mutation: none; commit remained `731a6c90749e8e62b9325e41712c39c0d72510c4` with a clean worktree after review commands.
