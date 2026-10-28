# CTFR related-work and novelty boundary

## Ideas that are not new

- Spectre-era work established cross-context mistraining of shared predictors.
- SafeSpec proposed holding speculative microarchitectural side effects in
  shadow structures and committing or squashing them later.
- Optimistic concurrency control and MVCC validate before commit and expose
  stable versions to readers.
- Biba-style and decentralized information-flow systems attach integrity or
  principal labels to state transitions.
- Token buckets, robust aggregation, trust regions, provenance, and safe
  fallback controllers are established techniques.
- Online-learning poisoning, federated-learning shadow models, and safe policy
  updates already study related validate-before-adopt patterns.
- Partial predictor isolation and delayed attribution have failed in adjacent
  microarchitectural settings; those results motivate complete shadowing and
  origin-bound asynchronous feedback rather than a coefficient-only patch.

The paper must cite these as design lineage, not imply invention.

## Candidate research gap

Online-adaptive LLM serving work uses live runtime feedback to change
speculative-decoding or scheduling policy.  Existing serving-security work also
establishes cross-request performance interference.  The narrower candidate
gap is a retirement boundary for controller feedback itself:

```text
authenticated request origin
-> principal-scoped speculative feedback
-> complete shadow controller state
-> validation
-> quiescent retire or squash
```

The paper's novelty is defensible only if it contributes all three of the
following:

1. a precise committed/unretired state model and pre-retirement committed-state
   invariance property;
2. a vLLM implementation that binds authenticated origin and shadows every
   adaptation-relevant variable; and
3. evidence separating security from disabled learning through same-policy,
   slow-drip, and benign-retirement experiments.

Simply naming state partitioning `retirement`, or showing the already known
attack disappears when learning is disabled, is insufficient.

## Recommended novelty sentence

> We introduce and evaluate a retirement-inspired feedback boundary for an
> online-adaptive LLM serving controller, separating committed estimator state
> from principal-scoped unretired feedback in a single-worker vLLM case study.

This deliberately avoids a `first` claim.  A documented literature search
through the submission date is still required, but the technical contribution
does not depend on proving that no adjacent system used similar vocabulary.

## Likely reviewer objections and required answers

| Objection | Evidence required |
| --- | --- |
| "This is just per-tenant state." | global committed state plus shadow/validate/quiescent-retirement implementation; PCFR baseline |
| "This is just SafeSpec renamed." | explain missing branch-resolution oracle; define serving-specific validator and limits |
| "Dropping updates already solves it." | benign-drift experiment showing useful adaptation after retirement |
| "Policy fingerprinting already blocks the PoC." | real same-policy attack where PCFR fails and CTFR protects |
| "The identity header is attacker-controlled." | gateway overwrites context; localhost-only upstream; audit join |
| "A hidden counter still leaks influence." | exact serialized committed-state invariant including refit metadata |
| "Quorum equals Sybil security." | one versus two attacker-controlled identities and explicit assumption |
| "The validator proves safety." | call it empirical/domain-limited; state fixed-grid blind spots |
| "Requests race with promotion." | acknowledge quiescent-only prototype; do not claim concurrent safety |
| "It cannot scale." | disclose fixed two-bank prototype; leave dynamic cardinality as future work |

## Primary design lineage

- Spectre: <https://arxiv.org/abs/1801.01203>
- SafeSpec: <https://arxiv.org/abs/1806.05179>
- Optimistic concurrency control:
  <https://db.cs.cmu.edu/papers/1981/kung-tods1981.pdf>
- Decentralized information-flow control:
  <https://www.cs.cornell.edu/andru/papers/sp98/paper.html>
- Simplex-style safe fallback: <https://arxiv.org/abs/2102.12981>

## Nearest serving and learning context

- GRIEF: <https://arxiv.org/abs/2605.11202>
- Aurora: <https://arxiv.org/abs/2602.06932>
- SpecServe: <https://arxiv.org/abs/2503.05096>
- Online Speculative Decoding: <https://arxiv.org/abs/2310.07177>
- adversarial risks of test-time adaptation:
  <https://proceedings.mlr.press/v202/wu23h.html>
- realistic test-time data poisoning:
  <https://proceedings.iclr.cc/paper_files/paper/2025/hash/bb309cc1fbdb88ea755bd7cee4b310ec-Abstract-Conference.html>
- shadow learning in continual federated learning:
  <https://arxiv.org/abs/2205.11736>
- authentication/provenance against poisoning:
  <https://arxiv.org/abs/2105.10051>
- adaptive online-poisoning certificates:
  <https://proceedings.mlr.press/v258/bose25b.html>
- robust test-time adaptation with MedBN:
  <https://openaccess.thecvf.com/content/CVPR2024/papers/Park_MedBN_Robust_Test-Time_Adaptation_against_Malicious_Test_Samples_CVPR_2024_paper.pdf>
- online learning with off-policy feedback:
  <https://proceedings.mlr.press/v201/gabbianelli23a.html>
- adversarial online learning with temporal feedback graphs:
  <https://proceedings.mlr.press/v247/gatmiry24b.html>
- Branch History Injection:
  <https://www.usenix.org/system/files/sec22-barberis.pdf>
- Branch Privilege Injection:
  <https://www.usenix.org/system/files/usenixsecurity25-ruegge.pdf>

The learning papers establish that inference-time or online adaptation can be
poisoned, while Online Speculative Decoding and Aurora establish that live LLM
serving traces can drive adaptation.  GRIEF establishes a broader class of
cross-request serving failures.  CTFR must therefore be distinguished by its
asset and property: shared serving-controller state, authenticated-principal
impact, and exact committed-state invariance before retirement.  A preliminary
keyword search did not identify an identical serving-feedback retirement
mechanism, but absence from a search is not proof of priority; the paper avoids
a `first` claim.
