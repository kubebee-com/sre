# KubeBee SRE K8sGPT Feature-Gap Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Build a complete, evidence-backed feature-gap table and dependency-ordered roadmap comparing KubeBee SRE with K8sGPT commit 731a6c90749e8e62b9325e41712c39c0d72510c4.

**Architecture:** Two fresh reviewers independently inventory K8sGPT and KubeBee SRE into disjoint evidence files. The coordinator normalizes capabilities into stable IDs, writes the table and roadmap, then runs mechanical coverage/link/quality checks and obtains an independent final review.

**Tech Stack:** Go source/tests, Kubernetes client-go/manifests, Markdown, Git, shell validation.

---

### Task 1: Inventory K8sGPT Capabilities

**Files:**
- Read: docs/k8sgpt-analysis/REPORT.md
- Read: docs/k8sgpt-analysis/01-project-cli-delivery-assets.md
- Read: docs/k8sgpt-analysis/02-ai-analysis-cache-extensions.md
- Read: docs/k8sgpt-analysis/03-kubernetes-analyzers.md
- Read: docs/k8sgpt-analysis/04-integrations-server-utilities.md
- Read: k8sgpt/**
- Create: docs/feature-gap-k8sgpt-inventory.md

- [x] **Step 1: Enumerate K8sGPT capability candidates by taxonomy family**

Use the existing per-file appendices as an index, then verify each candidate against implementation, tests, CLI flags, and manifests. Include every user-visible or extension-facing capability, not merely package names.

- [x] **Step 2: Record one evidence entry per normalized capability**

Each entry must contain: stable candidate key, capability name, behavior at the frozen commit, exact K8sGPT paths/symbols, tests/configuration proving reachability, known limitations/security notes, and the proposed parity acceptance test.

- [x] **Step 3: Separate distinct missing slices**

Split analyzer resource coverage, AI provider families, transports, cache backends, and operational controls when their parity status could differ. Do not use a broad row that hides a missing resource/provider/transport.

- [x] **Step 4: Validate the inventory**

Check every cited K8sGPT path exists, every candidate has evidence and acceptance criteria, and every capability family from the approved design appears.

### Task 2: Inventory KubeBee SRE Capabilities

**Files:**
- Read: README.md
- Read: cmd/sre-agent/main.go
- Read: pkg/config/**
- Read: pkg/scanner/**
- Read: pkg/sanitizer/**
- Read: pkg/triage/**
- Read: pkg/remediation/**
- Read: pkg/notifier/**
- Read: pkg/server/**
- Read: deploy/**
- Read: .github/**
- Create: docs/feature-gap-kubebee-sre-inventory.md

- [x] **Step 1: Enumerate implemented KubeBee SRE capabilities**

Trace the executable path from main through scanner, sanitizer, triage, remediation, notifier, HTTP handlers, and Kubernetes manifests. Treat README-only claims as unverified until source-backed.

- [x] **Step 2: Record one evidence entry per KubeBee capability**

Each entry must contain: stable candidate key, capability name, actual behavior, exact SRE paths/symbols, tests/configuration proving reachability, safety/operational limits, and whether it is a K8sGPT parity candidate or an SRE differentiator.

- [x] **Step 3: Identify stronger equivalents explicitly**

Document approval-gated mutation, deterministic rule-based fallback, multi-channel notifications, proactive scanning, cleanup, and dashboard/chat behavior separately from K8sGPT parity rows.

- [x] **Step 4: Validate the inventory**

Check every cited SRE path exists, distinguish implemented from README-promised behavior, and record evidence limitations for live-cluster/provider-only behavior.

### Task 3: Normalize And Build The Feature-Gap Table

**Files:**
- Read: docs/feature-gap-k8sgpt-inventory.md
- Read: docs/feature-gap-kubebee-sre-inventory.md
- Read: docs/k8sgpt-analysis/**
- Create: docs/kubebee-sre-k8sgpt-feature-gap.md

- [x] **Step 1: Assign stable IDs and map every K8sGPT capability**

Use family prefixes (DISC, ANL, AI, PRIV, CACHE, API, INT, OPS) and numeric suffixes. Split rows until each status is unambiguous.

- [x] **Step 2: Fill all required columns**

Every row must include K8sGPT behavior/evidence, KubeBee SRE behavior/evidence, status, explicit missing slices, better solution, priority, and acceptance evidence. Covered rows must explain the equivalence; Partial rows must list concrete missing capabilities.

- [x] **Step 3: Add summary sections**

Include parity totals by status/family, KubeBee SRE stronger capabilities, top safety blockers, assumptions/limitations, and links to both inventories and the prior 266-file K8sGPT review.

- [x] **Step 4: Mechanically validate table integrity**

Check stable IDs are unique, required columns are nonempty, every Partial/Missing row has a nontrivial missing-slice explanation, all cited paths exist, and every K8sGPT inventory key maps to one or more table IDs.

### Task 4: Write The Evidence Index And Roadmap

**Files:**
- Read: docs/kubebee-sre-k8sgpt-feature-gap.md
- Read: docs/feature-gap-k8sgpt-inventory.md
- Read: docs/feature-gap-kubebee-sre-inventory.md
- Create: docs/kubebee-sre-k8sgpt-evidence.md
- Create: docs/kubebee-sre-k8sgpt-roadmap.md

- [x] **Step 1: Build the evidence index**

Cross-reference each stable gap ID to source paths, tests, manifests, and evidence limitations. Include the frozen K8sGPT commit and current KubeBee SRE working-tree basis.

- [x] **Step 2: Build dependency-ordered work packages**

Group table gaps into P0 safety, P1 parity-critical, P2 important, and P3 polish packages. Each package must name affected files/modules, prerequisites, exact behavior to add, tests, and closure evidence. Preserve KubeBee SRE's stronger security/approval properties.

- [x] **Step 3: Define the 100% closure gate**

State that parity is complete only when all K8sGPT capability IDs are Covered or explicitly superseded by a safer, end-to-end equivalent, and all acceptance evidence passes.

### Task 5: Independent Review And Final Verification

**Files:**
- Review: all files under docs/*feature-gap*.md
- Review: docs/kubebee-sre-k8sgpt-feature-gap.md
- Review: docs/kubebee-sre-k8sgpt-roadmap.md
- Review: docs/kubebee-sre-k8sgpt-evidence.md

- [x] **Step 1: Run source/path and table-schema checks**

Fail on missing paths, duplicate IDs, blank statuses, missing Partial explanations, unresolved links, or inventory keys absent from the table.

- [x] **Step 2: Run repository verification**

Run go test ./..., go vet ./..., and relevant manifest/configuration checks without claiming live-cluster behavior. Record exact outcomes and environmental limitations.

- [x] **Step 3: Obtain independent quality review**

Have a fresh reviewer inspect representative rows from every family, all P0/P1 rows, all Covered claims, and the 100% closure gate. Correct all Critical/Important findings before completion.

- [x] **Step 4: Confirm final handoff**

Report the table path, roadmap path, evidence path, parity totals, stronger-equivalent inventory, and residual verification limitations.
