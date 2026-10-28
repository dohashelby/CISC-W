# CTFR predeclared decision rules

These rules define the structure of the CTFR study.  Numeric retirement
hyperparameters that require a pilot (`beta`, directional agreement,
coefficient and feature-grid trust regions, minimum observations, and initial
per-process influence credit) must be filled, frozen, and hashed before
confirmatory data collection.  A placeholder is not an executable
preregistration.

## Structural validity

Every planned request must complete successfully and join one-to-one with the
expected authenticated principal, gateway instance, trusted internal request
ID, worker marker, phase, and run.  Each arm starts a fresh process.  Model
revisions, process-wide policy context, source hashes, workload counts, phase
order, and treatment must match the declaration.  Gate or pilot runs are never
counted as confirmatory blocks. Worker completion IDs are joined only after
strict validation of the vLLM-generated output-index/nonce suffix. Reserved
startup warmups cannot satisfy authenticated-request coverage. For every
measured phase and principal, the read-only evaluator's per-position counts
must equal the counts reconstructed from the aligned `num_sampled` and
`num_rejected` vectors recorded immediately before the estimator call.

## Exact pre-retirement committed-state gate

For every `ctfr-shadow` attack run, all of the following must hold:

1. committed version is unchanged during intervention;
2. committed coefficients, committed refit metadata, version, and influence
   credits are value-equal before and after intervention;
3. the attacker's shadow statistics and observation count change;
4. no victim or placebo shadow receives the attack observations;
5. every feedback observation is attributable to exactly one accepted gateway
   request; and
6. retirement is not called until every admitted request has completed.

One mismatch fails the property.  No confidence interval or tolerance replaces
this structural test.

The stronger phrase `controller-decision noninterference` is allowed only if a
separate deterministic replay fixes victim inputs, seeds, and batching trace
and the complete verification-budget sequence matches element-by-element.  It
is not implied by the committed-state gate.

## Cross-policy performance signal

Using eight complete blocks, mitigation requires:

- the known shared-mode attack effect is adverse in at least seven blocks;
- the CTFR-minus-shared attack-specific throughput interaction is positive in
  at least seven blocks;
- the one-sided exact sign-test probability is at most 0.05; and
- the paired block-bootstrap 95% interval for mean interaction is above zero.

In addition, the mean CTFR attack post/pre throughput must be at least 0.95.
This practical threshold is not a proof of equivalence to placebo.

## Same-policy superiority over PCFR

This claim is allowed only if:

1. all policy/context equality checks pass;
2. shared and PCFR both show an adverse attack effect in at least seven of eight
   blocks;
3. CTFR passes the exact pre-retirement committed-state gate; and
4. CTFR's paired interaction against PCFR has a 95% block-bootstrap interval
   strictly above zero for throughput.

Failure to find an API-level same-policy attack yields `NOT_TESTED`, not support
for the claim.

## Benign adaptation retention

The paper may say CTFR preserves useful adaptation only if:

1. two distinct principal shadows, supplied benign workloads by the
   experiment, independently meet eligibility rules;
2. exactly one declared candidate retires at the quiescent barrier;
3. the post-barrier snapshot has the declared coefficients, advanced version,
   debited credits, refit metadata, and cleared shadows;
4. all evaluation requests are admitted only after that barrier;
5. CTFR-full outperforms `frozen` after retirement with a paired 95% interval
   above zero; and
6. CTFR-full recovers at least 80% of the `shared`-over-`frozen` throughput
   gain.

CTFR may be described as preferable to simple adaptive isolation only if the
predeclared held-out endpoint also improves over `tenant-local` with a paired
95% interval above zero.  Otherwise the result is reported as a security/
adaptation characterization, not as evidence that retirement is the better
deployment design.

The primary tenant-local baseline is epoch-matched: both principal banks start
from the identical frozen baseline, consume the same manifest as CTFR, and are
independently refit exactly once at the quiescent barrier.  Comparing CTFR to a
tenant-local controller that updated earlier is not accepted as the primary
causal comparison.  In every block, each principal's actual graded-observation
count must match exactly between tenant-local and CTFR-full; no tolerance is
allowed.  Before any benefit test, the shared-versus-frozen paired interval
must establish that the frozen workload actually contains an adaptation
opportunity.

Within each block, all five arms must produce identical held-out token IDs and
output hashes for every ordinal.  A semantic-output mismatch invalidates the
block and prevents mitigation utility or overhead claims.

Grid-validation pass/fail, promotion delay, calibration, verification budget,
squashes, and overhead are reported even when the endpoint fails.  The rate of
benign squashes is estimated across eight fresh-process blocks with exactly one
retirement attempt per block.

Calibration loss and Brier score are descriptive only because each policy may
admit a different set of draft positions.  Their per-position exposure counts
must be reported, and they cannot support a causal calibration claim without a
separate common-support replay.

The non-confirmatory gate passes only when `shared` has strictly higher
baseline-normalized held-out throughput than `frozen`, CTFR-full retires one
eligible compatible pair, tenant-local completes its single epoch-matched
refit, mixed-principal attribution is observed, and read-only evaluation leaves
policy state unchanged.  The one-run directional check is only a cost gate,
not confirmatory evidence.

## Overhead guardrails

Under stationary no-attack traffic:

- the shared-mode control must keep updates disabled and both arms must retain
  the identical committed baseline during the measured adaptation window;
- read-only calibration metrics must be disabled in both overhead arms, so the
  control does not execute CTFR-only principal or evaluation kernels;
- paired adaptation outputs must have identical token IDs and output hashes;
- mean adaptation-window throughput loss relative to that fixed-policy shared
  control must be no more than 5%;
- mean p95 latency increase must be no more than 5%; and
- the analytically accounted persistent fixed shadow-state tensors must stay
  within the predeclared 1,024-byte bound for `max_num_seqs=64` and draft depth
  four.

Whole-process RSS, CPU, and allocator-level GPU memory are supporting
measurements.  They do not isolate shadow-manager CPU time and therefore
cannot support an isolated-component overhead claim.  The 1,024-byte bound
does not include transient retirement candidate clones, validation-grid
workspace, framework allocator overhead, or model/runtime memory; those costs
must not be described as covered by the analytical bound.

These are practical guardrails.  They are statistical equivalence only if the
entire corresponding confidence interval lies within the declared equivalence
region.

## Sybil interpretation

With one eligible attacker identity, no attacker-only candidate may retire.
The two-attacker-credential negative control is expected to expose the limit of
the two-principal quorum assumption.  Passing the one-identity case supports
only a claim under authenticated-principal and bounded-collusion assumptions;
it does not support the phrase `Sybil-resistant`.

## Allowed paper conclusions

If the mechanism, security, utility, and overhead rules pass, the paper may
claim exact pre-retirement committed-estimator-state invariance and empirically
useful, conditional retirement for the pinned single-worker vLLM
configuration.  It may claim controller-decision noninterference only if the
separate deterministic replay gate passes.  It may not claim a benignness
oracle, arbitrary poisoning resistance, concurrent/crash-safe publication,
cross-engine validation, or security after an attacker captures the declared
quorum.
