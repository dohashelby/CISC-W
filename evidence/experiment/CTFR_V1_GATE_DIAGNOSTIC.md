# CTFR v1 gate diagnostic and v2 fork decision

## Status

The version 1 non-confirmatory Stage D gate completed all five arms on
2026-09-20, but the frozen analyzer classified the gate as `INVALID`. The
version 1 gate is not reused as confirmation and does not authorize Stage D,
Stage E, or overhead execution.

The failure archive is `avep-ctfr-full-study-v1-partial.tgz` with SHA-256:

```text
00779d3c313f0fd5133587af9429f1f6c2fcfabbe2f2668c34bffee4c5bc01cf
```

The archive preserves the original declaration, analyzer, assessment, five
complete raw arm directories, baseline pilot, generated manifests, and
environment evidence.

## Observed validation defects

The original assessment contained 221,878 errors. Of those, 221,160 were
`unexpected request id`, 30 were evaluation-counter mismatches, five reported
no valid mixed-principal batch, and the remaining messages were consequences
of those failed joins.

The request-ID errors were caused by comparing a gateway completion base
(`cmpl-<trusted-upstream-id>`) with the worker's actual vLLM child ID
(`cmpl-<trusted-upstream-id>-<output-index>-<8-lowercase-hex>`). A read-only
diagnostic normalized only that strict suffix. Across every arm, all 2,592
expected authenticated request bases were present; there were zero unknown
IDs, principal mismatches, missing expected IDs, or base collisions. Each arm
also contained 134 reserved `_warmup_<n>_` telemetry items with principal
`-1`; no malformed negative-principal identity was observed.

The counter mismatch was separate. The v1 analyzer attempted to reconstruct
the GPU evaluator's per-position counts from response-level speculative
summaries. Those summaries are not the estimator-call transcript and did not
equal the GPU counters in any arm. The v1 telemetry did not record the aligned
`num_sampled` and `num_rejected` vectors, so the exact kernel inputs cannot be
reconstructed post hoc from the preserved evidence.

## Decision

The version 1 result remains invalid; no threshold or frozen outcome is
retroactively relaxed. Version 2 adds strict worker-ID normalization and direct
estimator-input telemetry, assigns fresh versioned manifests, baseline, result
root, credentials, declaration, and archive, then reruns the complete five-arm
gate prospectively. All scientific workloads, budgets, thresholds, arm order,
and models remain unchanged.
