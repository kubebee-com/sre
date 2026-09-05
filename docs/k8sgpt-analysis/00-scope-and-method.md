# K8sGPT Analysis Scope And Method

## Repository Identity

- Upstream: `https://github.com/k8sgpt-ai/k8sgpt.git`
- Clone mode: `--depth 1 --single-branch`
- Branch: `main`
- Commit: `731a6c90749e8e62b9325e41712c39c0d72510c4`
- Commit date: `2026-09-01`
- Commit subject: `chore(deps): update golang docker tag to v1.27 (#1745)`
- Tracked files: 266
- Review date: 2026-09-04

## Scope

The audit covers every path returned by `git ls-files` at the commit above. It includes source code, tests, project and governance documents, CI/release configuration, Helm resources, container and dashboard definitions, dependency manifests, and image assets. Git internals and untracked files are outside scope.

## Per-File Method

Each file receives one path-exact record with:

- **Role:** the file's responsibility.
- **Implementation:** significant behavior, content, or artifact properties.
- **Dependencies:** callers, callees, deployment relationships, or documentation references.
- **Quality/Risk:** correctness, security, maintainability, operational, and test observations.

Text files are read directly. Binary assets are inspected through file metadata and their references from tracked text. Lock/checksum data is reviewed as a reproducibility and supply-chain artifact rather than line-by-line dependency prose.

## Evidence Discipline

Statements should distinguish direct source evidence from architectural inference. Cross-cutting findings in the aggregate report must point to exact repository paths. A mechanical manifest comparison verifies that every tracked path has exactly one per-file record.

