# PCFR mitigation decision rules

These rules apply to the first `allowed_token_ids` policy-domain prototype.
They must be frozen and hashed before the mechanism gate sends any request.

## Structural validity

Every request must succeed and join one-to-one to the expected authenticated
principal, gateway instance, worker marker, phase, and run.  Commit, model
revisions, token, workload counts, phase order, and treatment mode must match
the declaration.  Each arm starts a fresh process.  No gate run is a
performance replicate.

## Mechanism gate

The gate passes only if all of the following hold:

1. attack acceptance is at most 0.05 in all three attack arms;
2. the maximum pairwise attack-acceptance difference is at most 0.02;
3. the attack-shared canonical estimator changes during intervention;
4. the canonical estimator and its refit clock are exactly invariant during
   the attack-route intervention;
5. the routed estimator changes during the attack-route intervention;
6. canonical traffic changes the canonical estimator in the placebo-route arm;
7. the mean normalized post-window draft-budget effect in attack-route is at
   least 0.05 better than attack-shared after subtracting the corresponding
   placebo difference;
8. every coefficient and endpoint is finite and all audit checks pass.

An invariant state comparison includes coefficients, accumulators, counts,
refit count, and steps since refit.  Request-local feature and prediction
buffers are excluded because they are not consumed by unrelated future slots.

## Security performance endpoint

For each block, normalize every post-window throughput by that run's mean
throughput across `pre_01` through `pre_04`, then average `post_01` through
`post_08` for each arm.  Let the block interaction be:

```text
I_b = [M(attack, route) - M(attack, shared)]
      - [M(placebo, route) - M(placebo, shared)]
```

A security-mitigation signal requires:

- all eight blocks structurally valid;
- at least seven of eight `I_b` values positive;
- one-sided exact sign-test probability at most 0.05;
- paired block-bootstrap 95% interval for mean `I_b` strictly above zero.

The bootstrap uses 20,000 fixed-seed resamples of complete blocks.  Requests
are not independent replicates.  p50 and p95 latency, estimator trajectories,
budgets, and overhead are secondary endpoints.

## Benign overhead guardrail

Across the placebo arms, report the route-minus-shared effect and its paired
bootstrap interval.  The preregistered practical guardrail is an absolute mean
throughput change of at most 5%.  Passing this guardrail is not statistical
equivalence unless the entire confidence interval also lies in [-0.05, 0.05].

## Interpretation

Passing Stages A and B establishes mitigation of this attack for the pinned
configuration and policy fingerprint.  It does not yet establish retained
adaptation; that requires Stage C.  It also does not establish tenant isolation
for tenants sharing the same feedback domain or support a claim covering other
serving engines without separate implementation evidence.
