# AVEP preregistered 2x2 confirmatory experiment, version 2

## Protocol revision and separation from v1

This is protocol `avep-factorial-confirmatory-v2`. It is declared before any
v2 request is sent and uses only fresh server processes and fresh v2 result
directories. The selected token (`279`), workloads, endpoints, arm schedule,
and thresholds are fixed before v2 collection.

The independent v1 gate remains an invalid confirmatory cohort under its own
rules because its prespecified `post_01` budget interaction did not pass. v1
revealed a delayed, oscillatory response: the attack-shared estimator first
overshot and the harmful budget and throughput effects appeared after the
first post window. v2 uses that cohort only as pilot evidence to choose a fixed
eight-window estimand. It does not amend, reclassify, or count v1 observations
as v2 replicates.

## Research question

Does an attack-specific, post-request performance effect across a fixed
recovery horizon require the attacker's verification feedback to update the
shared online acceptance estimator?

The design crosses two factors:

- workload: `placebo` or `attack`;
- estimator updates during the intervention: `shared` or `blocked`.

This produces four arms:

| Arm | Intervention workload | Estimator update |
| --- | --- | --- |
| `placebo_shared` (`P-S`) | unconstrained placebo | enabled |
| `placebo_blocked` (`P-B`) | unconstrained placebo | disabled |
| `attack_shared` (`A-S`) | `allowed_token_ids=[279]` | enabled |
| `attack_blocked` (`A-B`) | `allowed_token_ids=[279]` | disabled |

For every block and outcome, the interaction is:

```text
[(A-S) - (A-B)] - [(P-S) - (P-B)]
```

Each post window is normalized to that fresh process's mean across four
pre-intervention victim windows. The primary outcome is the arithmetic mean of
the eight normalized post-window throughput values. A negative interaction
supports an attack-specific effect mediated by estimator updates.

## Fixed implementation and topology

- vLLM commit: `4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c`
- target model: `Qwen/Qwen3-4B`, revision
  `1cfa9a7208912126459214e8b04321603b3df60c`
- draft model: `z-lab/Qwen3-4B-DFlash-b16`, revision
  `b74e3a329c4d963783143b1e970d95b002be72bd`
- selected token: `279`, frozen from earlier exploratory screening
- one vLLM worker and one localhost authentication gateway
- distinct randomly generated attacker, victim, and upstream bearer keys
- deterministic prompts, temperature zero, and seed `20260918 + request index`

The v2 wrapper reuses the audited v1 lifecycle implementation through a
deterministic source transformation. Its own declared, hashed source embeds
and verifies the exact v1 driver SHA-256 before loading any function, so the
transitive execution input is fixed before requests begin.

The gateway must reject missing, unknown, and cross-principal credentials. It
records a key-free audit event for every request. Every workload response must
join one-to-one to the expected authenticated principal, gateway instance, and
worker marker.

## Workload

Every arm starts a new server process and receives:

1. 1,024 victim warm-up requests, concurrency 32, `max_tokens=32`;
2. four victim pre windows of 128 requests, concurrency 32,
   `max_tokens=32`;
3. 4,096 attacker intervention requests, concurrency 8, `max_tokens=2`;
4. eight victim post windows of 128 requests, concurrency 32,
   `max_tokens=32`.

Only attack arms set `allowed_token_ids=[279]`. Placebo arms send the same
number of otherwise identical requests without an allowlist. The update gate
is changed immediately before intervention and restored before the first post
request. Blocking suppresses only `OnlineAcceptanceEstimator.step()`; it does
not suppress request execution, drafting, target verification, or adaptive
policy use.

## Gate and performance cohort

A separate detailed telemetry gate runs in this fixed order:

1. `placebo_blocked`
2. `placebo_shared`
3. `attack_blocked`
4. `attack_shared`

Performance collection begins only if all structural and mechanism rules in
`FACTORIAL_CONFIRMATORY_V2_DECISION_RULES.md` pass.

Eight independent temporal blocks then follow. Every arm is a fresh process.
The four-order Williams design is repeated twice:

| Block | Fixed arm order |
| --- | --- |
| 01 | `A-S`, `A-B`, `P-B`, `P-S` |
| 02 | `A-B`, `P-S`, `A-S`, `P-B` |
| 03 | `P-S`, `P-B`, `A-B`, `A-S` |
| 04 | `P-B`, `A-S`, `P-S`, `A-B` |
| 05 | `A-S`, `A-B`, `P-B`, `P-S` |
| 06 | `A-B`, `P-S`, `A-S`, `P-B` |
| 07 | `P-S`, `P-B`, `A-B`, `A-S` |
| 08 | `P-B`, `A-S`, `P-S`, `A-B` |

Requests are not independent replicates. Statistical resampling is over the
eight complete process blocks.

## Endpoints and interpretation

The primary endpoint is the block-level attack-by-update interaction in mean
normalized throughput across `post_01` through `post_08`. Latency p50/p95
interactions use the same fixed horizon. Per-window trajectories, estimator
deltas, budget interactions, intervention duration, cumulative victim wall
time, and victim-harm-to-attacker-work ratios are secondary.

Passing supports an attack-specific estimator-mediated effect for two
gateway-authenticated principals on the pinned vLLM configuration. It does not
establish native vLLM tenancy, every affected version, another model pair,
another serving engine, or a production-grade mitigation.

## Cost and stop conditions

The gate plus 32 performance processes are expected to take roughly 77--95
minutes on the Seoul `g6e.2xlarge`. At USD 2.75652/hour, expected EC2 compute
cost is about USD 3.54--4.36, plus VAT and small storage/public-IPv4 charges.
This is an estimate, not a billing cap.

An independent shutdown deadline remains mandatory. Any structural failure,
mechanism-gate failure, server failure, timeout, request failure,
authentication/audit mismatch, or inability to restore updates stops the
cohort and preserves a partial archive. No v2 threshold may be relaxed after
v2 data exist.
