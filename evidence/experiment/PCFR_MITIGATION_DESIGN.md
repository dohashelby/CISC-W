# Policy-Consistent Feedback Routing (PCFR)

## Status and claim boundary

PCFR is a research mitigation for cross-request contamination in online adaptive
serving control.  It is not presented as a generic solution to data poisoning.
The narrower claim is that feedback used to update a shared serving controller
must not cross a policy boundary that changes the meaning of that feedback.

The vLLM prototype initially recognizes one target-side policy transform:
`allowed_token_ids`.  The architecture is intended to extend to logit bias,
penalties, structured-output constraints, top-k/top-p filtering, watermarking,
and other transforms after their compatibility with the estimator feature is
specified explicitly.

## Problem

The adaptive-verification estimator predicts draft acceptance from a feature
derived from draft logits.  The observed accept/reject label can instead be
generated after target-side sampling transforms.  A label produced under such
a transform is not necessarily an observation of the relationship modeled by
the canonical estimator.  Pooling it into canonical shared state creates both
a statistical mismatch and a cross-request information-flow path.

## Mechanism

PCFR assigns every feedback observation a trusted policy-domain label.  In the
prototype:

- domain 0 is canonical inference without `allowed_token_ids`;
- domain 1 is inference with `allowed_token_ids`.

Each domain has independent sufficient statistics, refit clocks, and learned
coefficients.  A request reads and updates only its own domain.  In particular,
domain-1 traffic must neither contribute observations to domain 0 nor advance
domain 0's refit clock.  The latter rule closes a timing-mediated state path in
which an unrelated request could otherwise cause pending canonical statistics
to be committed early.

The prototype exposes three modes from the same implementation:

| Mode | Read path | Update path | Purpose |
| --- | --- | --- | --- |
| `shared` | canonical estimator | all feedback to canonical | vulnerable control |
| `drop` | canonical estimator | transformed feedback discarded | filtering baseline |
| `route` | matching domain | matching domain only | PCFR treatment |

`drop` demonstrates that excluding the attack observation is sufficient.
`route` additionally tests whether transformed traffic can retain useful online
adaptation without changing canonical victim state.

## Security property

Before an explicit promotion mechanism is introduced, PCFR targets policy-domain
noninterference.  For domains `a != v`, an observation generated in `a` must not
change the controller state read by `v`:

```text
state_v(after observations_a) = state_v(before observations_a)
```

This property concerns controller state, not shared GPU contention or ordinary
queueing interference.  It also does not isolate two mutually hostile tenants
that deliberately use the same policy domain.  Strong tenant noninterference
requires a trusted principal label in the domain key.

## Novelty position

PCFR borrows established ideas—provenance labels, state partitioning, and robust
online learning—but applies them at a different boundary: mutable runtime state
inside an LLM serving controller.  The proposed research contribution is the
combination of (1) a policy-compatibility contract for feedback, (2) routing of
online controller observations by that contract, and (3) domain-specific refit
clocks that provide an explicit noninterference invariant.

The paper must not claim that state partitioning or poisoning defense itself is
new.  It may claim that, within the documented literature search, no prior LLM
serving work was found that enforces provenance-aware feedback isolation for an
online adaptive speculative-decoding controller.

This boundary matters because GRIEF (2026) already treats cross-request
contamination and performance interference in LLM serving engines as a broad
security surface.  Aurora (2026) and SpecServe (2025) also establish that live
feedback can drive speculative-serving adaptation.  PCFR's candidate novelty
is therefore neither cross-request interference nor online adaptation alone;
it is the explicit policy-compatibility contract and noninterfering feedback
route between them.

Relevant primary sources checked through 2026-09-20:

- GRIEF: <https://arxiv.org/abs/2605.11202>
- Aurora: <https://arxiv.org/abs/2602.06932>
- SpecServe: <https://arxiv.org/abs/2503.05096>
- online learning with off-policy feedback:
  <https://proceedings.mlr.press/v201/gabbianelli23a.html>
- adversarial online learning with temporal feedback graphs:
  <https://proceedings.mlr.press/v247/gatmiry24b.html>

## Production extensions

A complete design should use a trusted domain key such as:

```text
(authenticated principal, model pair, estimator feature contract,
 target-policy transform fingerprint)
```

It also needs bounded state cardinality, eviction behavior that cannot cause
cross-domain reuse, and a safe promotion protocol if observations are ever to
be merged into a global estimator.  Those are outside the first prototype and
must be identified as limitations.
