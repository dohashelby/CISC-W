# AVEP paper-grade vLLM experiment protocol

> Historical protocol note: this document records the earlier paired study.
> The paper's primary confirmatory evidence is now the independent
> `avep-factorial-confirmatory-v2` cohort described in
> `FACTORIAL_CONFIRMATORY_V2_PROTOCOL.md` and
> `FACTORIAL_CONFIRMATORY_V2_RESULT_REPORT.md`. Do not substitute the earlier
> paired endpoint below for the final 2x2 factorial estimand.

## Scope

The experiment uses only an isolated, user-controlled AWS instance and a vLLM
API bound to `127.0.0.1`. It does not send traffic to any third-party serving
deployment. The tested source is pinned to commit
`4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c`.

The experimental unit is a fresh vLLM server process. Individual inference
requests within a process are correlated observations and are not counted as
independent replicates.

## Primary hypothesis

Compared with an equal-sized placebo workload, an intervention using a legal
target-only token constraint changes the worker-shared online acceptance
estimator and degrades the throughput of later, non-overlapping victim requests.

## Primary outcome

For every fresh-process run, compute the mean throughput of six post-intervention
victim windows relative to that run's baseline. The primary effect is the paired
difference:

`attack post/baseline - placebo post/baseline`.

A negative value indicates greater residual throughput loss after the attack.
Report the mean paired effect and a server-run bootstrap 95% confidence interval.

## Secondary outcomes

- paired differences in p50 and p95 latency ratios;
- estimator coefficient changes measured only between workload phases;
- verification-budget changes in separate telemetry-enabled mechanism runs;
- recovery trajectory over six victim windows;
- request failures;
- exact token identity in deterministic mechanism runs;
- behavior after an in-process estimator-only reset;
- behavior with adaptive verification disabled.

## Arms

1. `attack`: 1,024 requests with one ordinary, non-special allowed token;
2. `placebo`: 1,024 otherwise identical requests without the constraint;
3. `reset`: the attack followed by an estimator-only reset before victim traffic;
4. `adaptive_off`: the attack with adaptive verification disabled;
5. telemetry-enabled attack and placebo mechanism runs.

Attack and placebo use the same prompts, output length, concurrency, and request
count. Performance runs disable detailed per-request metrics and steady-state
telemetry. Mechanism runs are analyzed separately and are not pooled into the
performance estimates.

## Per-run phases

1. fresh server process;
2. 1,024-request warmup;
3. 2,048-request baseline;
4. 1,024-request intervention;
5. six non-overlapping 1,024-request victim windows;
6. clean server shutdown.

The probe waits for every response before advancing to the next phase. An
on-demand worker RPC snapshots estimator state only after a phase completes.

## Ordinary-token preflight

Candidate strings must tokenize to exactly one ID and must not be tokenizer
special tokens. Six ordinary candidates are tested before the main study. The
candidate with the lowest observed draft acceptance is selected, and its source
text, tokenizer token, decoded form, and token ID are preserved.

## Precommitted run order

The first ten pair orders are fixed in `run_paper_trials.sh` before observing new
results. The default run uses the first six pairs. This prevents changing arm
order in response to interim outcomes.

## Interpretation rules

The analyzer inventories every run directory with metadata, including runs that
do not have a `COMPLETE` marker. It reports missing or malformed artifacts and
request failures by phase (including warmup and intervention), and excludes
those runs from inferential summaries with an explicit attrition reason. Only
complete, readable runs with no failed requests enter paired or arm-level
performance estimates.

Evidence for estimator-mediated cross-request impact requires all of the
following:

- attack and victim traffic do not overlap;
- the ordinary-token attack changes estimator state more than placebo;
- later victim policy or SLA differs from the matched placebo arm;
- estimator-only reset substantially attenuates the effect;
- disabling adaptive verification substantially attenuates the effect;
- a fresh process begins near the clean state.

If only numerically unstable estimator coefficients change, without a matched
victim impact, the result is reported as estimator instability rather than a
confirmed cross-request availability vulnerability.
