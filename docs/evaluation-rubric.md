# Offline paired diagnostic evaluation

`sre-evaluate` compares two profiles on exactly the same immutable evidence snapshots. It runs locally, constructs no AI provider, reads no cluster credentials, changes no knowledge or cluster state, and sends no requests. Use it as a review artifact before changing an approved profile or golden guidance rule.

```sh
go run ./cmd/sre-evaluate \
  --dataset testdata/evaluation/causal-v1.json \
  --baseline abstain/v1 --candidate conservative/v1 --max-calls 26 \
  > paired-report.json
```

The shipped `causal-v1` corpus has thirteen synthetic cases: six positives and seven negatives. Cases cover resource pressure, network restrictions, configuration drift, symptoms, dependency side effects, healthy contradictions, expired and future evidence, missing evidence, incomplete collection and selection of an upstream resource. The normalized dataset SHA-256 is `afcec27c6072bab3edcd70281eb676c27e6df491348c0cbc43755271996df267`. A regression test pins this hash. Changes to the frozen corpus require a new version and review, retaining the old file for historical comparisons.

`baseline` and `heldout` split labels distinguish original examples from perturbations. All shipped cases are public. They are not secret holdouts, and their pass rate does not estimate real incident accuracy. Maintain a separately reviewed, access-controlled synthetic corpus for a stronger release gate; it must contain both positive and negative cases. Never include customer names, logs, source provenance, target identifiers or raw customer data. The loader accepts only the typed evidence contract and rejects source and target metadata.

## What is scored

Every output passes through the same `investigation.AssessCandidate` rubric as production. Positive cases require a valid `HYPOTHESIS` for the exact expected cause and resource. Negative cases require `NEEDS_EVIDENCE` or `INCONCLUSIVE`. Invalid citations and provider failures are errors and receive no credit, including on negative cases. Nothing in this evaluation grants `CORROBORATED`, publishes a golden case, changes an approved provider or establishes recovery.

`conservative/v1` is a deterministic reference implementation using the production guidance-applicability predicate. `abstain/v1` always declines to identify a cause. Their expected result on the shipped corpus is 13/13 versus 7/13. This demonstrates the test mechanics and the difference between abstention and supported hypotheses; it is not evidence that an AI model improved. Scores describe the output **after the production safety rubric**, rather than the raw model's unaided reasoning.

The report retains one pair for every case, profile and prompt versions, current rubric version, dataset hash, positive and negative counts, error counts, false positives, candidate-only wins, baseline-only wins and ties. Error cases stay in the denominator. Inspect individual pairs and split membership before deciding whether an aggregate improvement is meaningful. Six wins against an always-abstaining reference do not justify an automatic production rollout.

## Comparing recorded AI profiles without provider access

Capture outputs in a separately authorized evaluation environment, with tools disabled and only the synthetic evidence for each case supplied to the provider. Do not send `expected_cause`, `expected_handle` or other answer labels. Record the immutable configured profile version and the prompt version used. There is deliberately no arbitrary provider endpoint, shell command or credential flag in this CLI.

Pass each recording's local filename through `--baseline` or `--candidate`. A recording is a JSON object with this shape:

```json
{
  "dataset_hash": "afcec27c6072bab3edcd70281eb676c27e6df491348c0cbc43755271996df267",
  "profile": {"id": "approved-profile", "version": "v3", "prompt_version": "investigation/v1"},
  "results": {
    "resource_pressure": {
      "conclusion": {
        "cause_code": "RESOURCE_PRESSURE",
        "resource_handle": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "supporting_evidence": [{"id": "resource_pressure-0", "version": 1}],
        "contradicting_evidence": [],
        "alternatives": []
      },
      "latency_ms": 250,
      "usage": {"input_tokens": 100, "output_tokens": 40, "total_tokens": 140}
    }
  }
}
```

The example shows one result; a valid recording must include **every** dataset case exactly once, with no extra cases. A failed case has `error_code` equal to `PROVIDER_FAILED`, `TIMEOUT`, `INVALID_OUTPUT` or `BUDGET_EXCEEDED`, and no conclusion. Unknown or absent measurements use `null`. Both success and failure may carry measured usage. Duplicate keys, unknown fields, invalid token accounting and a different dataset hash are rejected. Input files are bounded to 64 KiB, datasets to 256 cases and evidence to 64 observations per case.

The report includes a normalized SHA-256 of each recording, preserving the identity of the precise replayed artifact even when a producer reuses a profile version. Recording metadata is operator-supplied: `RECORDED_UNVERIFIED` clearly distinguishes it from measured local reference latency. Store the recording, report, configuration and independent review together in your controlled release artifacts. A hash establishes artifact identity, not trusted provenance or authenticity.

## Budgets and missing measurements

`--max-calls` counts case evaluations across both profiles, including replayed failures; it is checked before evaluation and capped at 512. The evaluator rejects a budget smaller than twice the case count, so truncation cannot improve a score. These are evaluation calls, not live AI requests. There is no remote execution path.

Reference latency measures the local deterministic calculation only. Replay latency is the recorded provider latency, when supplied. `latency_samples` states its coverage; do not compare local and provider latency as equivalent performance. `known_usage` sums reported tokens, `usage_samples` records coverage, and total `usage` is null unless every result supplies valid accounting. Zero known tokens with zero samples means unknown, not free. Monetary cost remains null because the evaluator has no trusted versioned pricing source. The report makes no production success-rate, causal recovery, cost-saving or statistical-significance claim.

An authorized reviewer should examine regressions, negative cases, lineage eligibility, measurement coverage and representative production feedback before changing a profile. Publication and owner-approved execution remain separate enterprise workflows.
