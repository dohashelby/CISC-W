# PCFR mitigation experiment protocol

## Objective

Test whether policy-consistent feedback routing prevents the confirmed
post-intervention victim degradation while preserving adaptation for legitimate
transformed requests.

## Fixed implementation scope

- pinned vLLM commit and model revisions are identical to the independent v2
  factorial confirmation;
- one worker and the existing localhost two-principal gateway are retained;
- the first policy fingerprint is binary: presence of `allowed_token_ids`;
- every run starts a fresh server and a reset estimator bank;
- the selected attack token remains 279 and is not re-screened.

## Stage A: mechanism gate

Run detailed telemetry for these arms:

1. attack + `shared`;
2. attack + `drop`;
3. attack + `route`;
4. placebo + `shared`;
5. placebo + `route`.

All arms use the same warm-up, four victim pre windows, 4,096-request
intervention, and eight victim post windows as the confirmatory v2 experiment.
The gate verifies routing, domain-specific state transitions, acceptance
matching, authentication, and complete request accounting before performance
replication begins.

## Stage B: security performance

Use eight fresh temporal blocks.  Within each block, run four fresh-process
arms in a balanced order:

- attack + `shared`;
- attack + `route`;
- placebo + `shared`;
- placebo + `route`.

The primary block interaction is:

```text
[(attack, route) - (attack, shared)]
  - [(placebo, route) - (placebo, shared)]
```

Outcomes are normalized to each process's four pre windows.  The primary
outcome is mean throughput over all eight fixed post windows; positive means
that routing specifically removes attack harm.

## Stage C: retained-adaptation utility

This stage distinguishes PCFR from disabling learning.  Use a legitimate
transformed workload whose acceptance regime changes within long-lived
requests, and compare `drop` with `route`.  The endpoint is recovery of
calibration and useful draft budget in the transformed domain, together with
throughput and latency.  The exact workload and threshold must be declared only
after a GPU pilot confirms that the shift is observable; pilot observations
must never be counted as confirmatory replicates.

## Stop and cost controls

The instance remains localhost-only.  A shutdown deadline is required for every
AWS run.  Stage B begins only after Stage A passes.  Stage C begins only after a
separate declared pilot and decision rule.  Failures preserve a partial archive
and stop further billable work.
