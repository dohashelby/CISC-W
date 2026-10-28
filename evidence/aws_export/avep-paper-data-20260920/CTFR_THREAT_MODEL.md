# CTFR threat model and assumptions

## Protected asset

The protected asset is mutable online controller state that changes future
serving decisions, not model weights or generated-text correctness.  In the
vLLM case study the relevant asset is the adaptive-verification acceptance
estimator and the verification budget derived from it.

## Principals and trust boundary

- The attacker and victim have different gateway-authenticated identities.
- Both legitimately submit inference requests to one worker.
- The gateway and worker are trusted; the inference payload is untrusted.
- The worker is reachable only through the gateway in the experiment.
- The gateway strips client identity claims and attaches an internal context.
- Model/draft revisions and effective policy fingerprints are derived
  server-side.

The prototype identity is an experimental gateway principal, not a claim that
vLLM currently offers native tenant isolation.

## Attacker capabilities

The attacker may choose prompts, seeds, supported sampling parameters, request
timing, and request count within service limits.  The attacker may deliberately
produce low-acceptance feedback and may spread it slowly across retirement
epochs.  In the Sybil boundary experiment, the attacker may control a declared
number of authenticated principals.

The attacker cannot access the host, GPU memory, estimator telemetry or reset
RPCs; alter model weights; forge the trusted gateway context; change the frozen
validator; or overlap the measured victim phase with queued attack work.

## Security objective

Before retirement, one principal's feedback must not alter the serialized
committed controller state.  Exact equality of another principal's
serving-policy trace is a stronger target that is claimed only if a
deterministic replay fixes the victim inputs, seeds, and batch trace and passes
element-by-element.  After retirement, the objective is narrower: empirically
bound admitted influence under the declared validator, identity, and collusion
assumptions.

The objective does not cover ordinary shared-GPU contention, output integrity,
confidentiality, model training poisoning, KV-cache contamination, or malicious
operators.

## Prototype trust assumptions that must be visible in the paper

1. Authenticated identities are scarce enough for the declared quorum and
   influence budget to mean something.
2. The gateway-to-worker principal binding cannot be spoofed or dropped
   silently; model, policy, and feature context remain fixed process-wide in
   the first prototype.
3. The controller's full mutable adaptation state and refit timing are known
   and shadowed.
4. The harness drains all requests and invokes retirement at a single-worker
   quiescent barrier.
5. The fixed 161-point validation grid covers only its declared feature
   domain; it is not a benignness oracle.
6. Per-principal influence credits are non-refilling and reset when the process
   restarts.

The prototype does not implement admission-time version pinning, stale
feedback rejection during concurrent promotion, crash atomicity, dynamic
principal allocation or eviction, or multi-worker publication.  These are
requirements for a production architecture, not evaluated assumptions.

## Explicit failure boundaries

- **Quorum capture:** an attacker controlling the required quorum may cause a
  malicious candidate to be considered.
- **Validator blind spots:** a candidate can behave safely on the fixed feature
  grid and badly elsewhere.
- **Slow cumulative drift:** per-commit bounds compound until the prototype's
  non-refilling per-process influence credit is exhausted; a restart resets it.
- **Identity churn:** weak admission turns principal isolation into a naming
  exercise.
- **Implementation incompleteness:** an unshadowed counter, timer, or cache
  invalidates the committed-state invariant; concurrent version races remain
  unevaluated.
- **Fixed cardinality:** the prototype recognizes exactly two principals and
  provides no evidence about dynamic allocation, TTL, or eviction.
- **Other workers/engines:** no empirical claim transfers without separate
  implementation evidence.
