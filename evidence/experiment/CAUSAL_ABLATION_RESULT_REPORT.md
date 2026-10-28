# AVEP estimator-update causal-ablation result

## Status

The confirmatory v2 cohort is structurally valid and satisfies the
predeclared primary decision rule.

- Analyzer classification: `TARGETED_CAUSAL_SIGNAL`
- Overall validity: `true`
- Analyzer errors: none
- Mechanism gate: passed all five checks
- Performance cohort: six of six paired effects were negative
- Primary paired-bootstrap 95% interval: entirely below zero

The defensible conclusion is narrow but strong: in the tested vLLM
configuration, the victim-side degradation produced by the fixed attacker
workload requires the attacker's verification feedback to update the shared
online acceptance estimator. This is evidence for the causal path

`attacker feedback -> shared estimator update -> later victim policy -> outcome`.

It is not evidence that every adaptive LLM serving engine is vulnerable.

## Experimental question and manipulation

Both arms executed the same 4,096-request attacker intervention with identical
token constraint, concurrency, request order, models, and hardware. The only
manipulated mediator was estimator accumulation/refitting during the attacker
phase:

- `shared`: attacker verification outcomes updated the estimator normally.
- `blocked`: the estimator's `step()` operation was suppressed only during the
  attacker intervention.

Updates were re-enabled before the first victim post request. The blocked arm
therefore still executed speculative decoding and target verification; it was
not a no-traffic or adaptive-decoding-disabled control.

Two distinct gateway-authenticated principals represented attacker and victim,
and both were routed to one pinned vLLM worker. These principals are an
experimental trust-boundary construction, not a claim that vLLM itself exposes
native tenant identities.

## Fixed environment

- vLLM commit: `4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c`
- vLLM build: `0.29.1rc1.dev190+g4fe9e6f6e.d20260918.precompiled`
- Target: `Qwen/Qwen3-4B`
  (`1cfa9a7208912126459214e8b04321603b3df60c`)
- Draft: `z-lab/Qwen3-4B-DFlash-b16`
  (`b74e3a329c4d963783143b1e970d95b002be72bd`)
- Speculation: DFlash, four speculative tokens, adaptive verification enabled
- GPU: NVIDIA L40S, 46,068 MiB, driver `580.126.09`
- AWS: Seoul `g6e.2xlarge`, one worker
- Selected token: `279`, frozen from the earlier exploratory screen
- Protocol: `avep-causal-ablation-v2`

Every fresh process used 1,024 victim warm-up requests, four 128-request victim
pre windows, one 4,096-request attacker intervention, and eight 128-request
victim post windows. Each arm was a new server process. Six performance pairs
used a fixed balanced arm order, so requests within one process were not
miscounted as independent replicates.

## Validity checks

All 14 planned runs completed: two mechanism-gate arms and twelve performance
arms. In every performance intervention:

- 4,096 of 4,096 requests succeeded;
- zero requests failed;
- returned token IDs were recorded;
- the observed control-token fraction was exactly `1.0`;
- intervention wall time was approximately 33.33 seconds.

The declared protocol, decision rules, driver, analyzer, tests, gateway, probe,
and causal patch hashes in the artifact match the local source files. The
analyzer's declaration check, topology checks, request/audit joins, phase-order
checks, update-gate checks, and state checks all passed.

## Mechanism gate

| Check | Blocked | Shared | Relevant contrast |
|---|---:|---:|---:|
| Attacker draft acceptance rate | 0.0000 | 0.0000 | absolute difference 0.0000 |
| Estimator state invariant | yes | no, as intended | only shared state moved |
| `intercept[0]` change | unchanged | -13.9037 | threshold was <= -0.50 |
| Normalized first-post draft budget | 1.0031 | 0.5606 | shared - blocked = -0.4425 |

The arms therefore delivered the same low-acceptance verification stimulus,
while only the shared arm changed the proposed mediator. Suppressing that
update preserved the estimator and the next victim policy; allowing it changed
both.

## Primary performance endpoint

For each fresh-process pair, the predeclared endpoint was

`shared(post_01 / pre_mean) - blocked(post_01 / pre_mean)`.

| Pair | Normalized-throughput effect |
|---:|---:|
| 1 | -0.2674 |
| 2 | -0.1902 |
| 3 | -0.1600 |
| 4 | -0.1498 |
| 5 | -0.2073 |
| 6 | -0.2289 |

- Negative pairs: `6/6` (predeclared requirement: at least `5/6`)
- Mean paired effect: `-0.2006`
- Paired-bootstrap 95% CI: `[-0.2331, -0.1695]`

This is a 20.06 percentage-point difference between the two baseline-normalized
arms, not a claim of a universal 20.06% raw-throughput loss.

## Secondary endpoints

| Endpoint | Mean shared-minus-blocked normalized effect | 95% CI |
|---|---:|---:|
| Latency p50 | +0.1662 | [+0.1156, +0.2133] |
| Latency p95 | +0.5662 | [+0.4110, +0.7262] |

The normalized-throughput contrast remained negative for all eight post
windows:

| Victim window | Shared-minus-blocked normalized throughput |
|---:|---:|
| post 1 | -0.2006 |
| post 2 | -0.2441 |
| post 3 | -0.3593 |
| post 4 | -0.3642 |
| post 5 | -0.3723 |
| post 6 | -0.3871 |
| post 7 | -0.3061 |
| post 8 | -0.3299 |

Thus the shared-versus-blocked after-effect remained observable through the
full 1,024 post-intervention victim requests per performance arm when
aggregated across the six pairs. The experiment establishes this short-horizon
observation; it does not establish an unbounded persistence duration.

## Causal interpretation

The result rejects the most important alternative explanation tested here:
that the later victim degradation is merely a direct consequence of running
the attacker's workload, target verification, GPU work, or speculative decoding.
Those operations occurred in both arms. When the estimator update alone was
blocked, the state and policy effect disappeared; when it was enabled, state,
policy, throughput, and latency moved in the predicted directions.

This is targeted mediation evidence within the pinned implementation. It is
stronger than a simple before/after observation and stronger than merely
showing two principals share a worker.

## Claim boundary for the paper

The experiment supports the following claim:

> A request-controlled verification stream can alter mutable adaptive control
> state shared across later requests in the tested vLLM implementation, and
> suppressing only that estimator update prevents the observed post-attack
> victim degradation.

It does not yet support these broader claims:

- all online-adaptive LLM serving controllers are vulnerable;
- native vLLM tenant isolation was bypassed;
- the effect generalizes to other models, GPUs, workers, or serving engines;
- the attack is cheap under arbitrary real-world traffic distributions;
- the state remains poisoned indefinitely;
- the observed normalized effect equals the same percentage loss in every
  production deployment.

For a paper, cross-engine generality should therefore be presented as a design
framework or hypothesis until another engine is tested, while vLLM remains the
validated case study.

## Invalid v1 cohort

The completed v1 cohort is retained for audit but must not be used as
confirmatory evidence. Its overall classification is `INVALID`.

V1 sent `allowed_token_ids=[279]` but did not request returned token IDs. The
prewritten validator required an observed control-token fraction of exactly
1.0, so all twelve performance interventions failed the evidence check and the
performance summaries were invalid. The v1 mechanism gate happened to pass,
and all six raw throughput contrasts were negative, but those observations do
not override the structural invalidity.

V2 changed only evidence capture by recording returned token IDs. It did not
change the workload, arm order, mediator intervention, endpoints, or decision
thresholds.

## Artifacts and integrity

Confirmatory v2 archive:

- File: `/Users/doha/Downloads/avep-causal-ablation-v2-results.tgz`
- SHA-256:
  `e14e7544ec0dda2814de5da253100ae997da6481364b7e30fe98149b8b733a45`

Invalid v1 audit archive:

- File: `/Users/doha/Downloads/avep-causal-ablation-partial.tgz`
- SHA-256:
  `eda371c57d57d0be4d51dc93a1369cdc2367086d1bd9dc41b3e5921214a4e6d3`

Both local hashes match the copies verified on the EC2 host and in AWS
CloudShell. The raw v2 archive contains the predeclarations, environment and
source hashes, per-request records, gateway audit logs, estimator snapshots,
all phase summaries, gate assessment, and final causal assessment.

## Operational cleanup

After artifact retrieval, AWS reported instance
`i-020836daed664114b` as `stopped`. EC2 compute billing for the instance is
therefore no longer running, although the retained EBS volume can continue to
incur its small storage charge until it is deleted.
