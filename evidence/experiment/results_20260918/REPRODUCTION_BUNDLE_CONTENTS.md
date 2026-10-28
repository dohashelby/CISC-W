# AVEP reproduction bundle contents

This bundle preserves the immutable AWS experiment archive, the original and
corrected postflight evaluations, both evaluator versions, and the experiment
protocol. Paths below are relative to `security_avep_experiment` in the bundle.

| File | SHA-256 | Purpose |
|---|---|---|
| `results_20260918/avep-paper-results.tgz` | `cbbc6e33e4645898eace76e0ba6c97082dc0d22ffa83521fecd0674c2307af8c` | Immutable primary data and run artifacts |
| `results_20260918/avep-paper-results.tgz.sha256` | `18e5a9b9eb57f49d00192c24cc332c6e5d3dd284bb7997289c2f93183eb23617` | AWS-generated archive sidecar |
| `results_20260918/paper_claim_evaluation.json` | `fdcc777966ec9e8a07be912345ed80ba76b5a48d163acaad4759e6f18661875b` | Preserved original postflight evaluation |
| `results_20260918/paper_claim_evaluation_corrected.json` | `d9bf016e6ee42a7bf5283f8a9fd5106e30f6faf5abb97b05345b8e4311cadbfc` | Corrected postflight evaluation |
| `results_20260918/POSTFLIGHT_EVALUATOR_AMENDMENT.md` | `db4654f1f9d2c7c79414c58547bfb3c11e5b454a9ab109fc52f37ba0801d27c9` | Transparent amendment and provenance record |
| `results_20260918/FINAL_EXPERIMENT_REVIEW.md` | `3dba83d76b2e04d18f72900b7bee1700fe1989d5ab4d33d08eddf3d5c3d6155f` | Scientific interpretation and limitations |
| `evaluate_paper_results.py` | `f368277a67296dc9bb3843a1722d00259f67f3ce3a2f9af14fe0cc4772cda7bc` | Corrected fail-closed evaluator |
| `test_evaluate_paper_results.py` | `77b701fde204c84e3b6568bf0915858823a1f6a773c152ab5b846818f8b48df0` | Corrected evaluator's 14 regression tests |
| `avep-evaluator-bundle.tar.xz` | `5df3ace178ddf642f4523ca8197204cfd373467eb94cde3abc3e3024fb19e0c5` | Original evaluator and tests, unmodified |
| `PAPER_EXPERIMENTS.md` | `26d01e6e17629191327d3a625ff74824904445336a380a3b4c641a4779debd81` | Experiment design |
| `PREDECLARED_DECISION_RULES.md` | `72e8a9f3f76ff548d3fdc3ff881d254f9c65a7d03164b466126ea951de33b637` | Decision rules frozen before the first complete pair |
| `avep-paper-experiment-20260918-v2.tgz` | `916c415cb98479e1a9c16b30622f0fd04c8eb5ebed6ca656abc2662c3cb8e9b1` | Input harness deployed to AWS |

## Re-evaluate

Extract `results_20260918/avep-paper-results.tgz` so that its `paper_results`
directory is available, then run:

```bash
python evaluate_paper_results.py \
  --result-root paper_results \
  --assessment paper_results/paper_assessment.json \
  --archive results_20260918/avep-paper-results.tgz \
  --archive-sha256 results_20260918/avep-paper-results.tgz.sha256 \
  --output paper_claim_evaluation_reproduced.json
```

Use Python 3.12 or later. In the vLLM development repository, follow its
`uv`-managed environment policy rather than invoking a system Python.
