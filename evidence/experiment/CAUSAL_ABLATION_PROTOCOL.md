# AVEP estimator-update causal ablation

## Protocol revision

This is protocol version `avep-causal-ablation-v2`. The completed v1 cohort
was retained but classified `INVALID` because performance interventions sent
`allowed_token_ids=[279]` without recording returned token IDs, while the
prewritten validator required an observed control-token fraction. V2 changes
only evidence capture: every intervention records returned token IDs. The
workload, arm order, causal manipulation, endpoints, and decision thresholds
are unchanged.

## Research question

Does the short-horizon victim degradation observed after the crafted attacker
phase require the attacker's verification feedback to update the shared online
acceptance estimator?

This experiment holds the attacker workload fixed and intervenes only on the
proposed mediator. In the `shared` arm, the estimator observes the attacker's
verification outcomes normally. In the `blocked` arm, the same requests are
executed and verified, but estimator accumulation and refitting are disabled
only for the attacker intervention. Updates are re-enabled before the first
victim post request.

```text
shared:  attacker feedback -> estimator update -> victim policy -> outcome
blocked: attacker feedback -X estimator update -> victim policy -> outcome
```

The ablation does not disable speculative decoding, request execution, target
verification, or adaptive policy use during the attacker phase. It suppresses
only the estimator's `step()` operation. This makes `blocked` an
update-suppression control rather than a no-traffic or adaptive-off control.

## Fixed inputs

- vLLM commit: `4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c`
- target model: `Qwen/Qwen3-4B`, revision
  `1cfa9a7208912126459214e8b04321603b3df60c`
- draft model: `z-lab/Qwen3-4B-DFlash-b16`, revision
  `b74e3a329c4d963783143b1e970d95b002be72bd`
- selected token: `279`, frozen from the completed exploratory screen
- two distinct gateway-authenticated principals on one worker
- deterministic prompts, temperature zero, and seed `20260918 + request index`

Every fresh process receives 1,024 victim warm-up requests, four victim pre
windows of 128 requests, the 4,096-request attacker intervention, and eight
victim post windows of 128 requests. The intervention has concurrency 8 and
`max_tokens=2`; every other phase has concurrency 32 and `max_tokens=32`.
All intervention requests apply `allowed_token_ids=[279]` in both arms.
Returned token IDs are recorded for every intervention and must all equal 279.

Before the intervention, both arms invoke the same localhost-only RPC. The
`shared` arm sets updates to true and the `blocked` arm sets them to false.
Both arms invoke the RPC again to set updates to true after the intervention.
The driver snapshots estimator state before gating, immediately after gating,
after intervention, immediately after re-enabling, and after every workload
window.

## Cohorts and order

A telemetry-enabled gate pair runs `blocked`, then `shared`. Performance data
are collected only if the gate proves that the blocked estimator state was
invariant and the shared estimator moved in the expected direction.

Six performance pairs use this fixed balanced order:

1. `shared`, `blocked`
2. `blocked`, `shared`
3. `shared`, `blocked`
4. `blocked`, `shared`
5. `shared`, `blocked`
6. `blocked`, `shared`

Each arm is a new server process. Requests within a process are correlated and
are never treated as independent experimental replicates.

## Interpretation

If both arms receive the same potent attack workload, the blocked arm keeps
its pre-intervention estimator state unchanged, and the shared arm alone shows
state movement followed by lower victim budget and performance, the result
supports this causal path:

`attacker verification feedback -> estimator update -> later victim policy`.

The result remains scoped to this pinned vLLM implementation, one model pair,
one worker, one selected token, and two gateway-authenticated principals. It
does not by itself establish native vLLM tenant isolation, cross-engine
generality, low attacker resource cost, or long-term persistence.

## Cost guard

The gate pair plus twelve performance processes should take approximately
35--50 minutes on the previously observed Seoul `g6e.2xlarge` setup. At the
previously observed USD 2.75652/hour rate, expected EC2 cost is approximately
USD 1.61--2.30, plus VAT and small storage/public-IPv4 charges. This estimate
is not a billing cap. The instance must be stopped after artifact retrieval,
including on failure.
