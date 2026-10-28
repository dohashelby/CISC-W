# Final experiment review

Date: 2026-09-18

## Verdict

The predeclared experiment is **INCONCLUSIVE** for a post-attack availability
vulnerability. It provides strong evidence that the selected attack workload
moves vLLM's process-shared online acceptance-estimator state, but it does not
show that this state movement causes adverse performance for subsequent victim
requests under the tested configuration.

This is neither a successful vulnerability reproduction nor a negative result
that establishes equivalence. No equivalence margin was predeclared, and the
primary confidence interval crosses zero.

## Primary and corroborating outcomes

All effects below are paired `attack post/baseline - placebo post/baseline`
differences across six complete pairs.

| Endpoint | Mean effect | Bootstrap 95% CI | Interpretation |
|---|---:|---:|---|
| Throughput | +0.372% | [-0.080%, +0.795%] | Crosses zero and points slightly toward better attack-arm throughput; primary adverse rule fails. |
| p50 latency | -0.784% | [-3.302%, +1.590%] | Crosses zero and does not corroborate harm. |
| p95 latency | -0.412% | [-0.798%, -0.023%] | Entirely in the direction of lower latency after attack, not harm. |

The attack-arm mean post/baseline throughput ratio was `0.988295`; placebo was
`0.984575`. The preregistered adverse direction required attack to be lower
than placebo with the upper confidence bound below zero.

## State and mechanism evidence

- Estimator coefficient movement was substantially larger after attack than
  placebo: mean L2 norm `3.2963` versus `0.1267`, approximately 26 times larger.
- This establishes workload-sensitive shared-state movement in the tested
  implementation, but coefficient movement alone was explicitly insufficient
  under the predeclared rules.
- The telemetry mechanism check failed. From baseline to the first victim
  window, the attack budget ratio increased rather than decreased:
  - mean-of-ratios change: attack `+0.004779`, placebo `+0.003590`;
  - weighted-ratio change: attack `+0.002311`, placebo `+0.001157`.
- The attack and placebo mechanism runs reproduced only about 99.4% and 99.5%
  exact baseline-to-post-1 victim token matches, respectively, so the strict
  token-match sanity check also failed.
- Reset and adaptive-off controls did not satisfy attenuation or expected-
  direction requirements because the measured primary harm was negative: the
  attack arm was not worse than placebo.

## Failure analysis

The chosen intervention was not a sustained low-acceptance stimulus. With token
23811 (`" hello"`) forced for 32 generated tokens, aggregated per-generation
telemetry shows 0% acceptance at generation indices 0 and 1, followed by a
steady increase: 63.3% at index 8, 80.8% at index 9, and approximately
98.9–100% from index 10 onward. The repeated forced-token sequence rapidly
became predictable to the draft model. Consequently, whole-intervention draft
acceptance was `0.41835` for attack versus `0.31426` for placebo—the opposite
of the intended acceptance-collapse stimulus.

A post-hoc cut of the first 128 requests in each original `post_01` artifact
shows a potentially short-lived signal: attack-minus-placebo throughput was
negative in five of six pairs, with an unweighted mean near -1.15%. This is not
confirmatory evidence because the cut was chosen after observing the full
result and request intervals can overlap at the chunk boundary. It motivates a
new, prospectively fixed experiment using one-token interventions and explicit
128-request post windows.

## What can and cannot be claimed

Supported by this run:

> In pinned vLLM adaptive verification, an attacker-influenced request stream
> can produce much larger changes in a process-shared online acceptance
> estimator than a matched placebo stream.

Not supported by this run:

> The resulting state change causes persistent throughput or latency
> degradation for unrelated later requests.

Accordingly, a paper should present this run as evidence of a cross-request
state channel or estimator manipulability, not as confirmation of an
availability vulnerability. A vulnerability claim requires a revised,
independently predeclared confirmatory experiment that links state movement to
a measurable policy change and adverse victim impact.

## Integrity summary

- 20/20 planned runs completed; 0 excluded; 0 request failures.
- Six attack/placebo pairs were analyzed.
- The primary archive SHA-256 matches its sidecar.
- All 730 extracted result files match the archive byte for byte.
- All environments match the pinned manifest.
- All 17 adaptive-on processes began from the same valid server-ready startup
  state.
- The corrected evaluator reports zero integrity errors and was covered by 14
  fail-closed unit tests.

## Limitations and protocol disclosure

- The primary estimate has only six paired observations and tests one vLLM
  commit, GPU type, target/draft model pair, selected token, workload, and
  intervention dose.
- Each post window aggregates 1,024 victim requests, so a brief early transient
  could be averaged away.
- Reset and adaptive-off arms have three unpaired runs each; adaptive-off has
  no matched placebo arm. There is only one telemetry mechanism run per arm.
- The rules were timestamped at `2026-09-18T09:24:06Z`, after pair-01 placebo
  completed (`09:21:42Z`) and after pair-01 attack post window 4 completed
  (`09:24:02Z`), but before the attack run and therefore the first complete
  pair finished (`09:24:24Z`). This satisfies the rules document's literal
  "before any completed pair" statement, but it is not preregistration before
  data collection and should not be represented as such.
- The archive cannot prove whether partial pair-01 numerical results were
  inspected before the decision-rule freeze.

See `POSTFLIGHT_EVALUATOR_AMENDMENT.md` for the transparent postflight
integrity-validator corrections and provenance hashes.
