# Postflight evaluator amendment

Date: 2026-09-18

## Scope

This amendment changes only postflight integrity validation. It does not
change collected data, endpoint definitions, cohort inclusion, statistical
thresholds, the bootstrap procedure, or the predeclared decision rules.

The original evaluation is preserved as `paper_claim_evaluation.json`. The
corrected evaluation is `paper_claim_evaluation_corrected.json`. The original
evaluator and its tests are preserved in `avep-evaluator-bundle.tar.xz`.

The amendments were made after the initial evaluator had exposed the effect
estimates. They are therefore disclosed as postflight changes and are limited
to independently explainable integrity-check defects. The paired estimates and
all decision-rule inputs are byte-for-byte unchanged between the original and
corrected evaluation outputs.

## Amendments

1. Nanosecond timestamps are now accepted only when the JSON value is a native,
   non-boolean, nonnegative integer. Differences are computed as integers before
   conversion to seconds. The original validator converted timestamps through
   binary floating point and consequently rounded valid nanosecond values.
2. The initial-state gate now checks the source-derived server-ready startup
   signature rather than requiring a pristine constructor state. Before serving
   traffic, the pinned vLLM revision executes scheduler-realistic kernel warm-up
   through the normal sampling path. This produces six estimator steps and 66
   position-0 observations while leaving `refits == 0` and all learned
   coefficients at their constructor defaults. The complete captured initial
   state is also required to be semantically and byte identical across all 17
   adaptive-on fresh processes. No observed row-0 statistic or observed hash is
   hard-coded as an acceptance criterion.
3. Reset validation still requires `reset.before == state_intervention`,
   `reset.after == state_reset`, and a constructor-default clean reset state.
   It no longer requires `reset.after == state_initial`, because the predeclared
   protocol defines reset as a cold-state mitigation rather than exact
   restoration of the post-profiling server-ready state.

For a future confirmatory run, reset the estimator immediately after
`server_ready` and before capturing `state_initial`; that removes the startup
profiling distinction altogether.

## Validation and outcome

- Corrected evaluator unit tests: 14/14 passed.
- Primary archive integrity: valid; 730 live files and 730 archived files, with
  no missing, extra, or content-mismatched result files.
- Cohort integrity: valid; 20/20 planned runs, six complete attack/placebo
  pairs, no exclusions, and no request failures.
- Initial-state integrity: valid; all 17 adaptive-on initial states are
  semantically and byte identical and satisfy the source-derived startup
  signature.
- Final classification: `INCONCLUSIVE`.

The correction changes the integrity gate from invalid to valid. It does not
change the classification because the predeclared primary adverse-effect rule
is still not satisfied.

## Decision-rule timing disclosure

`PREDECLARED_AT_UTC.txt` records `2026-09-18T09:24:06Z`. Filesystem timestamps
in the immutable result archive show that `pair_01_placebo` completed at
`09:21:42Z`, `pair_01_attack/post_04.summary.json` was written at `09:24:02Z`,
and the attack run completed at `09:24:24Z`. Thus the rules were fixed before
the first complete attack/placebo pair, as the rules document states, but not
before data collection began: the placebo run and four of six attack post
windows were already complete. The archive alone cannot establish whether
their numerical results were inspected before the freeze. This should be
described as a prospective decision-rule freeze before the first complete pair,
not as preregistration before data collection.

## SHA-256 provenance

- Primary archive: `cbbc6e33e4645898eace76e0ba6c97082dc0d22ffa83521fecd0674c2307af8c`
- Original evaluator bundle: `5df3ace178ddf642f4523ca8197204cfd373467eb94cde3abc3e3024fb19e0c5`
- Original evaluator: `a7d364548867da3fdbb015e371330a93d1ae80e98679a5f280ce8f975edbd40a`
- Original evaluator tests: `cf4cf4927bcd90d77e2971c6e24a2004406d970e7d66cb41be5142db057a5b7c`
- Corrected evaluator: `f368277a67296dc9bb3843a1722d00259f67f3ce3a2f9af14fe0cc4772cda7bc`
- Corrected evaluator tests: `77b701fde204c84e3b6568bf0915858823a1f6a773c152ab5b846818f8b48df0`
- Original evaluation: `fdcc777966ec9e8a07be912345ed80ba76b5a48d163acaad4759e6f18661875b`
- Corrected evaluation: `d9bf016e6ee42a7bf5283f8a9fd5106e30f6faf5abb97b05345b8e4311cadbfc`
- Predeclared rules: `72e8a9f3f76ff548d3fdc3ff881d254f9c65a7d03164b466126ea951de33b637`
- Analyzer assessment: `84242600b27c12c4d3f2eb78d8c5d5c52e8e7f2f3102304638351de94fa9715b`
- Common initial state: `b6a11c48ced23cadaaeba72b4dce71aaf45be5d33649c28828b21ba48be24aaf`
