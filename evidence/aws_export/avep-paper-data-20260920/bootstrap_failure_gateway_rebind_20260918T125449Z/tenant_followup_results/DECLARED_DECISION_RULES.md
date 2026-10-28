# AVEP authenticated two-tenant follow-up decision rules

## Status and scope

These rules define a new, explicitly exploratory follow-up. They were written
after inspecting the 2026-09-18 primary experiment and must not be described as
the preregistration for that experiment. The follow-up tests whether an
ordinary-token, at-most-one-speculative-round intervention can produce the
intended low draft-acceptance stimulus and whether any resulting effect is
visible in the first small, non-overlapping victim window.

The experimental unit is a fresh vLLM server process. Requests within a process
are correlated observations and are not independent replicates.

## Fixed authenticated topology and identity mapping

Every server process has exactly one localhost gateway and exactly one vLLM
worker. The gateway listens on `127.0.0.1:8001`; the worker listens on
`127.0.0.1:8000`. Two distinct bearer-key fingerprints, named `attacker` and
`victim`, and a third distinct upstream-key fingerprint are declared and
hashed before screen or gate data are collected. Secret key material is never
archived.

The screen warm-up is authenticated as victim and every token candidate as
attacker. In every adaptive run, warm-up, all pre windows, and all post windows
are authenticated as victim; only the intervention is authenticated as
attacker. Placebo uses the attacker credential too, but omits
`allowed_token_ids`. Both principals must be routed by the same gateway
instance to the same worker marker within a run.

Before workload collection in each process, correct attacker and victim keys
must each return 200, missing and unknown keys must each return 401, and
attacker-as-victim and victim-as-attacker claims must each return 403. Rejected
checks must not be forwarded upstream.

Every successful completion record must join one-to-one to a unique gateway
audit event with the expected key fingerprint, authenticated tenant, claimed
principal, request ID, gateway instance, and upstream worker marker. The audit
may contain exactly those workload events and the six authentication-check
events. Any key reuse, tenant mismatch, cross-worker route, missing, duplicate,
or extra event, or failed negative check is a structural failure.

## Fixed screen

The adaptive-off screen uses these 12 ordinary, non-special token IDs in this
fixed order:

`279, 323, 6303, 8251, 23811, 3015, 8094, 12095, 13, 11, 0, 30`.

Each candidate receives 256 requests at concurrency 8 and `max_tokens=2`, with
detailed speculative metrics and returned token IDs. The first token is sampled
by the target model during prefill; the second permits at most one initial
speculative verification round. Every candidate artifact must have zero failed
requests, exactly 512 completion tokens, `control_token_fraction == 1.0`, and
genuine positive aggregate drafted/speculative evidence. The selected token is
the valid candidate with the lowest aggregate acceptance (`sum(accepted) /
sum(drafted)`); ties are
resolved by the earlier position in the fixed list. The screen is a
stimulus-selection procedure, not a security outcome.

## Fixed process order

The gate pair runs in this order: `placebo`, then `attack`.

If and only if the potency gate passes, the four performance pairs run in the
following fixed order:

1. `placebo`, then `attack`
2. `attack`, then `placebo`
3. `attack`, then `placebo`
4. `placebo`, then `attack`

The harness writes and hashes a machine-readable schedule and a copy of this
file before collecting screen or gate data.

## Fixed gate and performance workload

Every adaptive-on process is reset to constructor estimator state immediately
after server readiness and before any workload. It then runs:

1. 1,024 warm-up requests at concurrency 32 and `max_tokens=32`;
2. four pre-intervention windows of 128 victim requests at concurrency 32 and
   `max_tokens=32`;
3. 4,096 matched intervention requests at concurrency 8 and `max_tokens=2`
   (exactly 8,192 completion tokens);
4. eight post-intervention windows of 128 victim requests at concurrency 32 and
   `max_tokens=32`.

The attack intervention alone applies the selected ordinary token through
`allowed_token_ids`. The placebo has the same prompts, request count,
concurrency, output limit, and process lifecycle without that constraint.
Traffic phases do not overlap.

The attacker intervention must finish before the first victim post request
starts. Authentication changes identity evidence only; it does not change any
request count, concurrency, token limit, prompt, model, gate threshold, pair
order, or endpoint definition from the v1 follow-up.

## Potency gate

All four conditions must hold in the separate telemetry-enabled gate pair:

1. `attack_acceptance_rate <= 0.05`;
2. `placebo_acceptance_rate - attack_acceptance_rate >= 0.10`;
3. `attack_delta_intercept0 - placebo_delta_intercept0 <= -0.50`, where each
   delta is intervention minus pre-intervention estimator intercept 0;
4. `(attack_post_01_budget / attack_pre_budget_mean) -
   (placebo_post_01_budget / placebo_pre_budget_mean) <= -0.05`.

Machine-checked spellings of the same four thresholds are fixed as follows:

- `attack acceptance <= 0.05`
- `placebo - attack >= 0.10`
- `delta-delta intercept[0] <= -0.50`
- `normalized post-1 budget attack - placebo <= -0.05`

The gate also requires exact configurations, zero request failures, finite
metrics, successful startup resets, no workload between server readiness and
reset, and complete artifacts. Individual intervention requests may have a
well-formed zero-draft record, but each intervention phase must contain positive
aggregate drafted and speculative-step evidence; acceptance is always computed
as aggregate accepted tokens divided by aggregate drafted tokens. Other
detailed gate phases may have a well-formed all-zero aggregate, in which case
their aggregate acceptance is null rather than zero. If any condition fails,
the harness does not run performance pairs and records a stopped-at-gate
result. Thresholds must not be changed after gate data exist.

## Exploratory performance endpoint

For each of four fresh-process pairs, the short-horizon throughput effect is:

`(attack post_01 / attack pre-window mean) -
 (placebo post_01 / placebo pre-window mean)`.

A negative value is adverse. Latency p50 and p95 use the same normalization,
with positive values adverse. The analyzer reports every pair, their mean, a
server-run bootstrap 95% interval, all eight normalized post-window
trajectories for every pair and in aggregate, and recovery summaries.

With only four pairs, even a same-direction result is labeled an
`EXPLORATORY_SHORT_HORIZON_SIGNAL`, never a reproduced vulnerability. That
label additionally requires at least three of four throughput effects to be
negative and the bootstrap interval's upper bound to be below zero. Any other
valid outcome is `EXPLORATORY_INCONCLUSIVE`. A later confirmatory study must
freeze the selected token and design in advance and use at least 6--10 new
independent pairs.

The analyzer must emit only `EXPLORATORY_SHORT_HORIZON_SIGNAL` or
`EXPLORATORY_INCONCLUSIVE`. It fails closed on any mismatch in the declared
schedule or hash, declared-input manifest or file hashes, fixed cross-process
order or timestamps, environment manifests, run configuration, or required
artifact structure. No exploratory outcome may be worded as confirmation.

The analyzer's gate-only mode is limited to the pre-performance potency check.
It fully validates declarations, screen, gate runs, and their provenance while
ignoring performance directories solely so an interrupted passing cohort can
resume. The final analysis does not use that mode and requires all eight valid
performance runs. Any performance artifact paired with a failed gate is an
error, not a result.

Passing tenant evidence supports only a claim about two gateway-authenticated
principals sharing one vLLM worker. It must not be described as native vLLM
tenant isolation, a cross-engine result, or proof of harm. The original potency
and performance criteria remain independently necessary.
