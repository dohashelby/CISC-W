# CTFR staged execution runbook

## Safety and cost boundary

Preparation is local and does not start AWS resources.  Before each GPU phase,
re-check the current instance rate and remaining promotional credit.  The last
verified rate for the retained Seoul `g6e.2xlarge` was USD 2.75652/hour; at that
rate the driver's default six-hour wall-time cutoff corresponds to about USD
16.54 of instance time before tax.  An outer `timeout` covers the complete
driver invocation, sends `TERM` at the deadline, and allows at most 120 seconds
for cleanup before `KILL`.  It does **not** stop the EC2 instance, so the
operator must stop the instance after every invocation or failure.  The limit
is per invocation, not a cumulative AWS spending cap; record the duration and
estimated charge after every phase before starting the next one.

Use USD 90 of gross eligible usage as the operational hard ceiling.  This
leaves a USD 10 buffer below the user's USD 100 credit/tax boundary.  EBS and
other retained resources must be checked separately because they can continue
accruing charges while the instance is stopped.

## Phase order

Run each phase separately and copy out its partial archive before proceeding.

1. `preflight`: apply the frozen patch stack and run syntax/unit checks.
2. `manifests`: generate and byte-check the nine workload manifests from the
   hash-frozen corpus.
3. `baseline`: exercise the mode-specific update path for compilation, reset
   all warm-up state, learn the baseline regime, and serialize `C*` once.  The
   driver freezes an all-file SHA-256 provenance manifest for the raw pilot;
   declaration and analysis fail if the pilot or extracted baseline changes.
4. `declare`: hash the source, baseline, corpus, manifests, schedule, and
   decision rules before any confirmatory request.
5. `gate`: run one non-confirmatory fresh-process arm for each Stage D mode.
   Stop here unless the shared-versus-frozen adaptation opportunity exists,
   both benign CTFR candidates are eligible and compatible, tenant-local refit
   succeeds, origin binding passes, and read-only evaluation leaves policy
   state unchanged.
6. `stage-d`: run eight balanced fresh-process blocks of `shared`, `frozen`,
   `tenant-local`, `ctfr-shadow`, and `ctfr-full`.
7. `stage-e`: run the one-identity gate plus eight-block disagreement and
   quorum-capture controls.
8. `overhead`: run eight alternating paired blocks of fixed-policy shared and
   CTFR-full without retirement under stationary traffic.  Only the adaptation
   window is sampled, so both arms serve with the same committed coefficients
   while CTFR alone performs shadow bookkeeping.
9. `analyze` and `archive`: perform strict structural/statistical analysis and
   create the result archive plus SHA-256 sidecar.

The gate is not a confirmatory replicate.  If it motivates any change to the
corpus, retirement thresholds, source, or analysis, assign a new version,
regenerate every hash, relearn the baseline, and redeclare before Stage D.
The driver re-analyzes the raw gate evidence and requires every frozen gate
predicate before it will launch Stage D, Stage E, or overhead arms.

The v1 gate stopped under this rule and is preserved as described in
`CTFR_V1_GATE_DIAGNOSTIC.md`. The v2 driver uses fresh `*_v2` manifests,
baseline, credentials, result root, declaration, and archives. Do not copy a
v1 gate directory or declaration into the v2 root.

Arm order is part of the declaration.  A fully complete temporal block may be
skipped on restart, but the driver refuses a partially recorded gate or block.
Do not fill in the remaining arms later: quarantine that result root, start a
new version, and rerun the whole block so elapsed-time drift cannot silently
change the declared ordering.

## Remote commands

From `/home/ubuntu/avep` in the pinned environment:

```bash
./run_ctfr_full_study.sh preflight
./run_ctfr_full_study.sh manifests
./run_ctfr_full_study.sh baseline
./run_ctfr_full_study.sh declare
./run_ctfr_full_study.sh gate
```

Only after gate review:

```bash
./run_ctfr_full_study.sh stage-d
./run_ctfr_full_study.sh stage-e
./run_ctfr_full_study.sh overhead
./run_ctfr_full_study.sh analyze
```

Every arm records a fresh process UUID, authenticated gateway evidence,
request manifest hashes, queue-drain samples, estimator snapshots, exactly one
declared barrier decision where applicable, read-only calibration metrics,
coarse resource samples, and a `COMPLETE` marker.
