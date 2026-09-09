# Unified SRE Kind acceptance expansion

User authorized implementation and explicitly prohibited execution on this resource-constrained host. Do not create clusters, run containers, build images/binaries, or execute acceptance tests during development.

Extend the existing two-cluster suite rather than discard its collection, privacy, RBAC, exact-target remediation, recovery and volume checks.

- Add unified agent acceptance using the product binary, real kubeconfig and in-cluster ServiceAccount access; exercise enrollment, diagnostics, persistent state/restart and failure boundaries.
- Expand existing cluster remediation acceptance to drive human approval and notification through the orchestrator HTTP/messaging boundary and durable state.
- Repair browser coverage references and require browser dependencies in the comprehensive runner.
- Add a clearly named unified Kind runner, preserve old entrypoint compatibility, build/load artifacts only when invoked, require fixture inputs, retain failure diagnostics and clean only disposable resources.
- Document scenarios, boundaries, prerequisites, resource cost, artifact handling and future execution command.
- Validate edits only with formatting, parsing and static inspection here. All cluster behavior remains unexecuted until run on a suitable host.

Implemented the scenarios and runner above. Validation is intentionally limited to gofmt, shell/JavaScript/Python/YAML syntax parsing and static review. No compilation, image build, test execution or cluster creation was performed. See docs/kind-acceptance.md for the exact coverage boundary and future run instructions.
