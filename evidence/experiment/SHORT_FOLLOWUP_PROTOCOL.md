# AVEP ordinary-token short-horizon follow-up

## Motivation

The 2026-09-18 primary study was valid but inconclusive. Its constrained
ordinary-token intervention did not create the intended acceptance collapse:
the attack arm's aggregate draft acceptance was 0.41835, versus 0.31426 for the
placebo. Detailed records explain the reversal. For token 23811 (`" hello"`),
acceptance was 0 in speculative steps 0 and 1, then increased as the forced
output repeated, reaching 0.633 at step 8, 0.808 at step 9, and at least 0.989
from step 10 onward. The intervention therefore mixed an initially adverse
stimulus with a later, highly predictable repeated-token stimulus.

The original 1,024-request post windows could also average over a short effect
and subsequent online recovery. A post-hoc split of the first 128 requests in
the first victim window was adverse for throughput and p50 latency in five of
six pairs, but that split was not predeclared and concurrent requests overlap
chunk boundaries. It motivates, but does not prove, a short-horizon effect.

## Design

This follow-up changes only what is needed to answer those two questions:

- An adaptive-off, detailed-metrics screen selects an ordinary token that the
  drafter rarely proposes in the first speculative verification round.
- The matched intervention uses `max_tokens=2`: the first token is sampled by
  the target model during prefill, followed by at most one initial speculative
  verification round. This actually exercises the speculative path while
  preventing the many repeated forced-token rounds that reversed the primary
  intervention's intended stimulus.
- Concurrency 8 and 4,096 requests provide enough scheduler steps for the
  estimator's 100-step refit cadence while keeping the intervention bounded.
- Four 128-request windows before and eight after the intervention make the
  immediate effect and recovery visible without treating requests as
  independent replicates.
- A telemetry gate pair must demonstrate stimulus, state movement, and policy
  movement before any performance repetitions are spent.
- Performance runs disable detailed metrics and steady-state telemetry and use
  four balanced, fixed-order fresh-process pairs.

The complete constants and stop/go criteria are in
`SHORT_FOLLOWUP_DECISION_RULES.md` and are copied and hashed by the harness
before data collection.

## Interpretation limits

This is an outcome-informed exploratory follow-up, not a retroactive repair of
the primary experiment and not independent confirmation. Passing the gate means
only that the revised workload is a potent mechanistic stimulus. Four
performance pairs can justify a short-horizon signal worth confirming, but
cannot establish a vulnerability, affected-version range, severity, or
cross-engine generality. Failure at any stage is retained and reported rather
than prompting another token or threshold search.

The server remains bound to `127.0.0.1` on an isolated user-controlled instance.
`VLLM_SERVER_DEV_MODE=1` is used only for the local estimator snapshot/reset
RPCs and must not be used in production.

## Expected runtime and cost

On the observed Seoul `g6e.2xlarge` L40S setup, a fresh process took roughly
2.5--3 minutes including startup. The screen should take about 3--4 minutes,
the gate pair about 6--7 minutes, and four performance pairs about 22--26
minutes. Allow 32--42 minutes total. At USD 2.75652/hour, that is approximately
USD 1.47--1.93 of EC2 time, with roughly USD 0.15--0.19 VAT before small storage
and public-IPv4 charges. Gate failure stops after about 10 minutes.

## Remote invocation

After copying the new files to `/home/ubuntu/avep`, run:

```bash
cd /home/ubuntu/avep
chmod 0755 run_short_followup.sh
setsid ./run_short_followup.sh core \
  > short-followup-driver.log 2>&1
```

The final archive is `/home/ubuntu/avep/avep-short-followup-results.tgz`; its
SHA-256 sidecar is written next to it. `gate` runs only the screen and gate pair,
`performance` requires an already-passing gate and runs the fixed four pairs,
and `analyze` only reanalyzes and archives existing artifacts. The
pre-performance gate check validates only the declared screen and gate cohort,
so an interrupted performance cohort can resume: completed run directories are
kept, while each incomplete run directory is moved under `_incomplete` before
that run is repeated. Final analysis still requires all eight valid performance
runs and fails closed on a partial cohort. A failed gate is never accepted when
any performance directory exists.
