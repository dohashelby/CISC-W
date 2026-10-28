# CTFR experiment protocol

## Objective

Evaluate whether context-tagged feedback retirement removes the confirmed
post-request victim effect, whether its protection is stronger than policy-only
routing, and whether validated retirement preserves useful benign adaptation.

All confirmatory thresholds, source hashes, model revisions, orders, and
workloads are frozen before the first confirmatory request.  Pilot data may
select an observable same-policy and benign-drift workload but is never reused
as confirmation.

## Prospective v2 amendment

Version 1 stopped at its non-confirmatory Stage D gate. Its immutable partial
archive has SHA-256
`00779d3c313f0fd5133587af9429f1f6c2fcfabbe2f2668c34bffee4c5bc01cf`.
The gate exposed two evidence-contract defects: worker completion IDs include a
vLLM-generated output-index/nonce suffix, and response-level speculative
metrics do not constitute an exact transcript of the GPU estimator inputs.
No version 1 gate arm is reused or counted in version 2.

Version 2 is declared prospectively with fresh manifests, baseline pilot,
result root, credentials, and complete five-arm gate. The worker telemetry now
records the aligned `num_sampled` and `num_rejected` vectors plus the configured
speculative depth at every estimator call. The analyzer accepts only the
documented vLLM completion suffix, treats only the reserved startup
`_warmup_<n>_` namespace as unauthenticated warmup, and reconstructs the
estimator's per-position observation counts from those direct inputs. The
frozen corpus, workload budgets, arm order, retirement thresholds, models, and
scientific decision rules are otherwise unchanged.

## Fixed environment

- vLLM commit `4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c`;
- the model and draft revisions from factorial-confirmatory v2;
- one NVIDIA L40S worker behind the localhost authenticated gateway;
- `TRITON_ALLOW_NON_CONSTEXPR_GLOBALS=1` for the frozen PCFR/CTFR kernel
  dispatch constants, recorded in the environment manifest;
- fresh process and reset controller for every arm;
- requests, gateway audit events, trusted internal request IDs, worker markers,
  and phase labels joined one-to-one;
- model revisions, feature contract, canonical effective policy, and
  verification configuration fixed process-wide;
- attacker work fully drained before post-attack victim measurement.

## Stage 0: implementation invariants

Before performance trials, use deterministic unit and integration tests to
show:

1. the gateway, not the client, binds principal identity;
2. client-supplied request IDs and identity-like headers cannot select another
   principal's bank;
3. attacker and victim observations remain correctly attributed even when
   their requests share a GPU batch;
4. every read-only evaluation counter equals the count reconstructed from the
   authenticated worker ID, persistent slot, principal, `num_sampled`, and
   `num_rejected` vectors supplied to the GPU estimator call;
5. committed coefficients, refit metadata, version, and influence credits
   remain exactly invariant under unretired feedback while only the selected
   shadow statistics change;
6. retirement is invoked only after the harness has drained every admitted
   request at the declared single-worker quiescent barrier; and
7. one eligible retirement attempt produces the declared final coefficients,
   version, credits, refit metadata, and cleared shadows.

The integration gate verifies authenticated request-to-slot attribution in
observed mixed-principal batches.  The implementation maps an unrecognized
direct-upstream request to `-1`, uses the canonical prediction bank, and drops
that feedback from principal shadows, but the study does not separately force
slot reuse or a direct-upstream unknown-ID case.  Those paths remain
source-audited behavior rather than empirical paper claims; normal tenants do
not possess the upstream credential.  A read-only evaluation accumulator must
continue to record log-loss and Brier score while estimator updates are
disabled, without changing any coefficient, statistic, version, clock, or
influence credit. Its per-position counts must match the direct worker
verification-input transcript exactly; response-level speculative summaries
remain auxiliary evidence and are not substituted for that transcript.

A deterministic victim replay additionally compares the complete verification-
budget sequence element-by-element with and without an attacker shadow.  Until
that optional stronger test passes, the claim is limited to serialized
committed-state invariance rather than end-to-end decision noninterference.

Version pinning, stale-candidate squash under concurrent promotion, crash
atomicity, and dynamic eviction are explicitly out of scope for this prototype.

Any invariant failure stops GPU performance experiments.

## Stage A: cross-policy mechanism and mitigation gate

Reuse the frozen `allowed_token_ids=[279]` intervention and the existing phase
shape:

```text
1,024 victim warm-up
4 x 128 victim pre windows
4,096 attacker or placebo intervention requests
queue drain
8 x 128 victim post windows
```

Detailed telemetry arms:

1. `placebo_shared`;
2. `attack_shared`;
3. `attack_route` (the PCFR routing mechanism check);
4. `placebo_ctfr-shadow`;
5. `attack_ctfr-shadow`.

This stage verifies that the known effect is still reachable, checks the PCFR
state-routing mechanism, and tests CTFR committed-state invariance.  Because
the gate has no placebo-route arm, it makes no PCFR performance-mitigation
claim.  Any PCFR or CTFR performance statement requires paired placebo arms and
the eight-block schedule below; the initial gate runs alone are not performance
replicates.

## Stage B: same-policy discrimination

This stage prevents CTFR from collapsing into PCFR under a new name.  A pilot
selects a low-acceptance prompt/workload corpus without changing the canonical
effective policy.  Confirmation logs must establish equality of:

- target and draft model revisions;
- canonical sampling-policy fingerprint;
- estimator feature-contract version;
- temperature, verification configuration, and output constraints; and
- all controller context except authenticated principal and payload.

Confirmatory arms are `placebo_shared`, `attack_shared`, `placebo_route`,
`attack_route`, `placebo_ctfr-shadow`, `attack_ctfr-shadow`, and matched
`ctfr-full` arms.  PCFR is expected to share state because the policy
fingerprint is identical; CTFR-shadow is expected to isolate unretired attacker
feedback.  CTFR-full separately records whether the candidate is ineligible,
squashed, or retired within the predeclared influence bounds.

If a reproducible API-level same-policy attack cannot be found before the
predeclared pilot budget expires, this stage is reported as unavailable.  It
must not be simulated by relabeling a cross-policy attack as same-policy.

## Stage C: slow-drip attack

Using the same-policy attack fixed in Stage B, insert one poison request after
each declared batch of benign updates across multiple retirement attempts.  The
final attack request must finish and the queue must drain before victim
measurement.  Compare `shared`, `ctfr-shadow`, and `ctfr-full` against matched
placebo sequences.  CTFR-full is the primary treatment because it tests whether
many small candidates can pass retirement and accumulate drift.

The primary mechanism endpoint remains committed-state invariance.  The
performance endpoint is secondary because a sufficiently weak slow drip may
not create a measurable shared-mode effect within the fixed cost horizon.

## Stage D: benign adaptation retirement

Two distinct authenticated principals, both assigned frozen benign workloads
by the experiment, encounter the same workload shift.  The validator observes
identity and update geometry, not benignness or independence.  Compare:

- `shared` as the adaptive ceiling for this configuration;
- `frozen` (`shared` with estimator updates disabled) as the non-adaptive
  floor;
- `tenant-local` as the strongest simple adaptive-isolation baseline;
- `ctfr-shadow` as a no-promotion control; and
- `ctfr-full` with the predeclared retirement rule.

Every arm loads the same serialized baseline controller learned in a separate
pilot cohort.  Its coefficient digest is frozen before confirmation.  The
sequence is:

```text
updates on -> mode-specific compile warm-up -> reset -> load frozen baseline
-> read-only baseline evaluation
-> simultaneous declared workload shift for benign principals A and B
-> independent shadow accumulation
-> exactly one validator decision at a quiescent retirement barrier
-> updates off -> post-retirement evaluation on held-out requests
```

Warm-up executes each arm's accumulation and read-only evaluation paths.  The
non-confirmatory gate also invokes the shared, tenant-local, and CTFR refit or
retirement paths before any confirmatory block, populating their Triton cache.
Gate latency is never a timing replicate and must not be reported as promotion
or retirement performance.  The following reset and baseline load must clear
all warm-up statistics, refits, versions, credits, and coefficients; the
analyzer verifies the resulting pre-adaptation state against the serialized
baseline.

Run eight fresh-process blocks per arm, with exactly one retirement attempt per
CTFR-full block.  The tenant-local primary baseline is **epoch-matched**: it
accumulates the same principal-scoped observations and applies exactly one
independent native refit to each bank at the same quiescent barrier.  It does
not auto-refit during accumulation.  A native online-refit tenant-local arm may
be reported only as a sensitivity analysis.  The fixed 161-point validation
grid and held-out evaluation requests are distinct.  Retirement success,
delay, squash rate, read-only calibration loss, verification budget,
throughput, and latency are recorded.  This stage is required before claiming
that CTFR preserves adaptation.  A paper-level benefit claim additionally
requires a declared advantage over tenant-local, such as higher held-out
utility from corroborating benign principals.

Before those confirmatory blocks, the non-confirmatory gate must show all of:
directionally higher baseline-normalized held-out throughput for `shared` than
for `frozen`, a successful eligible `ctfr-full` retirement with compatible
candidates, a successful tenant-local refit, mixed-principal worker
attribution, and unchanged policy state during read-only evaluation.  A gate
failure stops the study; any resulting design or corpus change requires a new
version and declaration.

The tenant-local and CTFR arms receive identical request manifests and report
actual graded-observation counts per principal.  The predeclared tolerance is
zero: each tenant-local count must exactly equal the corresponding CTFR-full
count within a block, or the block and advantage claim are invalid.  Held-out
outcomes are reported separately for principals A and B before aggregation.
This makes the intended comparison explicit:
whether corroborated cross-principal evidence adds useful adaptation beyond
two isolated adaptive estimators, not whether CTFR merely saw more traffic.
Because sampling is deterministic and speculative decoding is intended to be
lossless, every held-out ordinal must also have identical output-token IDs and
output hash across all five arms within a block.  Any mismatch invalidates that
block's performance interpretation rather than being treated as a quality/
latency tradeoff.

Read-only log-loss and Brier scores are secondary descriptive diagnostics.
Each arm observes predictions only at draft positions admitted by its current
policy, so the support and per-position counts can differ across arms.  The
study reports those exposure counts and does not make a causal calibration
improvement claim without a separate fixed-depth common-support replay.

## Stage E: assumption and overhead tests

### Sybil boundary

With the fixed two-principal validator, compare one attacker identity with two
attacker-controlled identities.  One identity must fail quorum.  The two-
credential case is a negative control that may retire and therefore documents,
rather than hides, the quorum-capture limitation.  Also test attacker plus
benign principal with directionally disagreeing candidates; it must squash.

Dynamic-cardinality, TTL, and eviction experiments are deferred because the
prototype hard-codes two banks.  They remain explicit production limitations.

### No-attack overhead

Compare a shared-mode control with estimator updates disabled against
`ctfr-full` shadow accumulation without retirement.  Both arms load the same
committed baseline and must retain exactly the same committed policy throughout
the adaptation window.  This isolates shadow observation bookkeeping from
policy adaptation.  Read-only calibration instrumentation is disabled in both
overhead arms, so the shared control does not pay CTFR principal-attribution or
evaluation-kernel costs while CTFR retains the complete request-origin and
shadow path.  Report throughput and p50/p95 latency from that adaptation
window.  Sample GPU memory, host memory, and whole-process CPU only from the
same window.  CPU utilization is computed from consecutive Linux `/proc`
process tick deltas divided by the matching wall-clock interval, so startup
and JIT time before the adaptation sampler starts are excluded.  The
prototype analytically bounds only persistent fixed
shadow-state tensors; transient candidate clones and validation-grid workspace
are excluded from that bound.  Sampled process CPU and allocator-level
GPU/host memory are coarse measurements, not isolated shadow-manager costs.

The per-step construction and scatter of authenticated principal labels is
part of CTFR prototype overhead and is not subtracted from the measurement.
All probe phases request token IDs, matching the frozen sampling policy and
preserving evidence for constrained-token workloads.

### Origin-binding robustness

Attempt victim-prefix request IDs, conflicting identity-like headers, and
missing credentials.  Confirm that the gateway overwrites external IDs and
that every accepted request joins one-to-one with the intended worker bank.

## Replication and estimands

Security-performance comparisons use eight fresh temporal blocks.  Arm order
is frozen in `DECLARED_SCHEDULE.json` as an explicit ordered array for every
block, and the analyzer verifies order from phase timestamps.  A partially
recorded block is invalid and must be rerun in a newly declared result root;
only a wholly complete block may be skipped after a restart.  The independent
unit is the complete block,
not individual requests.

For outcome `Y`, the primary mitigation interaction is:

```text
I_b = [Y(attack, CTFR) - Y(placebo, CTFR)]
      - [Y(attack, shared) - Y(placebo, shared)]
```

Positive throughput `I_b` means CTFR specifically removes attack harm.  Each
post window is normalized by that process's four pre windows, then the fixed
eight-window mean is used.  Confidence intervals resample complete blocks with
a fixed seed.

## Scope-preserving stop rules

- Stage B starts only after Stage A invariants pass.
- Stage C starts only if the same-policy pilot yields a frozen workload.
- Stage D uses a separate pilot and confirmatory cohort.
- Stage E may use cheap CPU tests where GPU behavior is irrelevant.
- Every AWS run has a shutdown deadline and partial-archive trap.
- Failed structural validation invalidates the arm; it is not retried silently.
- A drain barrier is evidenced by two consecutive samples with zero running
  and waiting requests before any retirement or local-refit RPC.
