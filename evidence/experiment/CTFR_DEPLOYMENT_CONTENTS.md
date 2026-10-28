# CTFR deployment bundle contents

The preparation produces two layers.  The smaller mechanism archive contains
the frozen inputs for the first CTFR-shadow gate.  The full-study archive adds
the Stage D/E and overhead machinery.  Neither archive contains credentials.
The local full-study artifact is
`avep-ctfr-full-study-v2-deploy-20260920.tar.xz`; its exact members are frozen in
`CTFR_DEPLOYMENT_FILELIST.txt` and its detached SHA-256 is distributed beside
it.  Generated manifests, the learned baseline, raw baseline-pilot directory,
environment inventory, and all result files are intentionally created on the
pinned GPU host and are not present in this pre-execution bundle.  Successful
and failure-result archives include the complete pilot directory plus an exact
all-file provenance manifest; analysis independently re-extracts its learned
bank and binds it to the frozen baseline digest.

The mechanism layer exercises shared, PCFR-route, and CTFR-shadow behavior.
The full-study layer in this bundle additionally provides `tenant-local` and
`ctfr-full` retirement arms, including the Stage D harness needed to test
whether validated retirement preserves benign adaptation.  The initial gate
uses all five arms and adds mixed-batch worker attribution.  Deterministic
decision replay remains separate and is still required for the stronger
end-to-end noninterference claim.

- design and claim-boundary documents: `CTFR_*.md`;
- cumulative source patches: paper instrumentation, causal ablation, PCFR,
  CTFR, the full-study experiment-support layer, and a frozen Triton
  `static_range` compatibility patch, plus a v1-to-v2 direct-verification
  telemetry migration patch for already prepared hosts;
- `prepare_ctfr_source.sh`, which applies those patches idempotently to the
  pinned commit and runs remote syntax/unit checks through the pinned venv;
- `run_ctfr_mechanism.sh`, which reuses the audited server lifecycle and runs
  the predeclared gate/performance schedule;
- the fail-closed CTFR analyzer and its unit tests;
- the authenticated CTFR gateway, bounded probe, base analyzer, and frozen base
  driver required transitively by the harness.

The full-study layer additionally includes:

- `tenant-local` epoch-matched refit, baseline-state loading, exact retirement
  outputs, and read-only log-loss/Brier counters;
- `ctfr_frozen_corpus.json`, its deterministic manifest generator, schema, and
  unit tests;
- `ctfr_dual_probe.py` for wave-interleaved principal traffic and origin-ID
  spoof checks;
- `run_ctfr_full_study.sh`, which separates manifest generation, baseline,
  non-confirmatory gate, Stage D, Stage E, overhead, and analysis;
- queue-drain and resource evidence; and
- the strict full-study analyzer and tests.

The full-study bundle also freezes the authenticated gateway, sampling policy,
probe return-token behavior, persistent-only memory-bound scope, and portable
Linux process-group sampler.  Its overhead comparison keeps both arms on the
same committed policy, disables read-only evaluation instrumentation, and
measures the adaptation request window so policy improvement is not mistaken
for mechanism cost.  CPU samples use interval `/proc` tick deltas rather than
process-lifetime averages.  Unconditional retirement/refit call markers,
queue-gauge
presence counts, exact baseline reload checks, cross-arm output equivalence,
and exact tenant-local/CTFR observation-count matching are analyzed
fail-closed.

The bundle must be hashed locally, copied to the retained EBS volume, hashed
again remotely, and extracted only if both values match.  Credentials remain
generated on the instance with mode `0600` and are excluded from archives meant
for publication.
