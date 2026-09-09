# Enterprise Offline Evaluation Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans with test-first implementation and independent review.

**Goal:** Compare two immutable profile outputs on the same frozen synthetic cases without contacting providers or granting production authority.

**Architecture:** A versioned JSON corpus feeds the real diagnostic rubric. Deterministic reference runners and hash-bound recorded outputs produce paired case results. Reports contain dataset/profile/prompt/rubric identities, call budgets, latency provenance, nullable token accounting and no automatic promotion.

**Tech Stack:** Go, existing investigation rubric, JSON CLI.

## Constraints

Offline only; no credentials, Kubernetes access, customer text, training writes or provider requests. A benchmark pass is not production diagnostic success.

## Tasks

- [x] Add failing tests in `pkg/evaluation/evaluation_test.go` for paired budget enforcement, changed dataset hash, missing replay cases and abstention versus unsupported symptoms.
- [x] Implement `pkg/evaluation` using immutable corpus hashing and a closed runner selection (`conservative/v1`, `abstain/v1`, recorded profile file). Score exact positive hypotheses and negative abstentions separately.
- [x] Add frozen `testdata/evaluation/causal-v1.json` with direct cause, side effect, contradiction, stale, future, insufficient and upstream-selection cases. Keep held-out membership explicit; published fixtures cannot be claimed secret holdouts.
- [x] Add `cmd/sre-evaluate` with bounded input, JSON report output and nonzero invalid-input failures. Record all failures rather than dropping denominator cases.
- [x] Run `go test -race ./pkg/evaluation ./cmd/sre-evaluate` and an actual CLI comparison. Document report meaning, replay format, governance and limitations in `docs/evaluation-rubric.md`.

Validation: tests first failed for absent implementation, replay cross-dataset reuse and report mutation of private measurements. Each was corrected and the focused suite passed. Independent review is handled by the root enterprise implementation workflow; no production provider requests or rollout occurred.
