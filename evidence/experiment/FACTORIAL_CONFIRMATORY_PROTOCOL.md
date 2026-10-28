# AVEP preregistered 2x2 confirmatory experiment

## Protocol revision

This is protocol version `avep-factorial-confirmatory-v1`. It is an
independent fresh-process cohort. The selected token (`279`), workload,
endpoints, arm schedule, and decision thresholds are fixed before any v1 data
are generated. No token screen is permitted in this study.

## Research question

Does an attack-specific post-request performance effect require the attacker's
verification feedback to update the shared online acceptance estimator?

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

The primary estimand is the block-level difference in differences:

```text
[(A-S) - (A-B)] - [(P-S) - (P-B)]
```

Outcomes are normalized to each fresh process's four pre-intervention victim
windows. A negative throughput interaction supports an attack-specific effect
mediated by estimator updates.

## Fixed implementation and topology

- vLLM commit: `4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c`
- target: `Qwen/Qwen3-4B`, revision
  `1cfa9a7208912126459214e8b04321603b3df60c`
- draft: `z-lab/Qwen3-4B-DFlash-b16`, revision
  `b74e3a329c4d963783143b1e970d95b002be72bd`
- selected token: `279`, frozen from the earlier exploratory screen
- one vLLM worker and one localhost authentication gateway
- distinct randomly generated attacker, victim, and upstream bearer keys
- deterministic prompts, temperature zero, and seed `20260918 + request index`

The gateway must reject missing, unknown, and cross-principal credentials. It
records a key-free audit event for every accepted and rejected request. Every
workload response must join one-to-one to the expected authenticated principal,
gateway instance, and worker marker.

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
is changed immediately before the intervention and restored to enabled before
the first post request. Blocking suppresses only
`OnlineAcceptanceEstimator.step()`; it does not suppress request execution,
drafting, target verification, or adaptive policy use.

## Gate and performance cohort

A separate detailed telemetry gate runs in this fixed order:

1. `placebo_blocked`
2. `placebo_shared`
3. `attack_blocked`
4. `attack_shared`

Performance collection begins only if the gate satisfies all structural and
mechanism rules in `FACTORIAL_CONFIRMATORY_DECISION_RULES.md`.

Eight independent temporal blocks follow. Every arm is a fresh process. The
following four-order Williams design is repeated twice, balancing each arm's
position and every first-order predecessor relationship:

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

The primary endpoint is the post-window-1 normalized throughput interaction.
Latency p50/p95 interactions, estimator deltas, normalized budget interaction,
all eight post-window trajectories, intervention duration, and cumulative
victim token/time effects are secondary endpoints.

Passing this experiment supports an attack-specific estimator-mediated effect
for two gateway-authenticated principals on the pinned vLLM configuration. It
does not establish native vLLM tenancy, every affected version, another model
pair, another serving engine, or a production-grade mitigation.

## Cost and stop conditions

The four-arm gate plus 32 performance processes are expected to take roughly
77--95 minutes on the previously used Seoul `g6e.2xlarge` instance. At the
previously observed USD 2.75652/hour rate, expected EC2 cost is approximately
USD 3.54--4.36, plus VAT and small storage/public-IPv4 charges. This is an
estimate, not a billing cap.

The instance must receive an independent four-hour shutdown deadline before
collection starts. Any structural failure, mechanism-gate failure, server
failure, timeout, nonzero request failure count, authentication/audit mismatch,
or inability to restore updates stops the cohort and preserves a partial
archive. No failed threshold may be relaxed after data exist.
