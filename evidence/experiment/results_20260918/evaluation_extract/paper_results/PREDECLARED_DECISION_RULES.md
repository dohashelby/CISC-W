# AVEP decision rules

These rules were fixed before observing any completed attack/placebo pair.

## Integrity gate

The result is inconclusive unless the analyzer reports a valid, complete
20-run cohort, six complete attack/placebo pairs, no excluded runs, no request
failures, finite positive performance metrics, and valid archive hashes.

## Primary endpoint

Let each pair's throughput effect be:

`attack post/baseline - placebo post/baseline`.

The primary availability effect is reproduced only when all six pair effects
are analyzed, their mean is negative, and the server-run bootstrap 95%
confidence interval has an upper bound below zero. A confidence interval that
crosses zero is inconclusive. With no equivalence margin predeclared, a
complete cohort is called negative only when the interval is wholly
non-adverse.

Positive attack-minus-placebo p50 and p95 latency effects are corroborating
outcomes. Estimator movement must be stronger after attack than placebo, and
the telemetry mechanism runs must show a consistent post-intervention
verification-budget change. Coefficient movement without matched victim harm
is estimator instability, not a confirmed vulnerability.

## Control attenuation

For throughput, let `P` be the placebo mean ratio, `A` the attack mean ratio,
`X` a control mean ratio, and `H = P - A`. When `H > 0`, define residual harm
as `H_X = max(0, P - X)` and attenuation as `1 - H_X / H`. Reset and
adaptive-off controls each must attenuate at least 50% and move in the expected
direction (`X > A`). Apply the analogous rule to latency with `H = A - P` and
`H_X = max(0, X - P)`.

The reset arm is interpreted as a cold-state mitigation control, not as exact
restoration of the pre-intervention estimator. Adaptive-off is a descriptive
ablation, not a formal attack-by-adaptation interaction because it has no
matched adaptive-off placebo arm.
