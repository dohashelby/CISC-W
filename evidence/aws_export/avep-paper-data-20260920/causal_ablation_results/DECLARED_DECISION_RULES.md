# AVEP causal-ablation decision rules

These rules were fixed before collecting the causal-ablation cohort. The
selected token is intentionally reused from the prior exploratory screen; this
study tests mediation, not independent attack discovery.

## Structural validity

Every arm must use the declared commit, model revisions, topology, credentials,
request schedule, and fixed token 279. All requests must succeed and join the
gateway audit to the expected principal, gateway instance, and worker marker.
The intervention must end before the first post request begins.

The update-gate RPC must succeed on exactly one worker. Immediately before the
intervention, `shared` must report updates enabled and `blocked` disabled.
Immediately after the intervention, both must be restored to enabled before any
post request.

For `blocked`, these state fields must be exactly unchanged from the pre-gate
snapshot through the intervention snapshot:

- `steps_since_refit`
- `refits`
- `slope`
- `intercepts`
- `counts`
- `info`
- `grad`

`updates_enabled` is excluded because it is the manipulated field. For
`shared`, updates must remain enabled.

## Mechanism gate

The separate telemetry pair passes only if all conditions hold:

1. both intervention acceptance rates are at most 0.05;
2. their absolute acceptance-rate difference is at most 0.02;
3. blocked estimator state is invariant across the intervention;
4. shared `intercept[0]` intervention-minus-pre change is at most -0.50;
5. shared-minus-blocked normalized post-1 draft budget is at most -0.05.

Failure stops the experiment before performance runs. Thresholds are not
changed after gate artifacts exist.

## Primary endpoint

For each fresh-process pair:

`E_tput = shared(post_01 / pre_mean) - blocked(post_01 / pre_mean)`.

Negative values support the proposed causal path. The targeted causal signal
criterion requires at least five of six pair effects to be negative and the
paired bootstrap 95% interval for their mean to have an upper bound below zero.

Latency p50 and p95, all eight post-window trajectories, estimator deltas, and
intervention wall times are secondary endpoints. They do not replace the
primary rule. Bootstrap resampling is over six process pairs, not requests.

The analyzer emits one of:

- `TARGETED_CAUSAL_SIGNAL`
- `TARGETED_CAUSAL_INCONCLUSIVE`
- `INVALID`

Even `TARGETED_CAUSAL_SIGNAL` is a scoped ablation result, not proof of
cross-engine generality or a resource-amplification claim.

