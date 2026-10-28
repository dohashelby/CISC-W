# CTFR v2 five-arm gate: preserved negative result

Date: 2026-09-20 (Asia/Seoul)

## Outcome

The predeclared CTFR v2 five-arm cost gate did **not** pass. The run is
preserved as a valid negative gate result and must not be repaired by rerunning
only the `ctfr-full` arm or by changing a threshold in place.

All five fresh-process arms (`shared`, `frozen`, `tenant-local`,
`ctfr-shadow`, and `ctfr-full`) were present. Each arm's evaluation phase
completed 256/256 requests with zero failed requests and zero missing audit
event IDs. The gate nevertheless failed closed because the declared benign
pair did not retire in `ctfr-full`.

Across the four measured phases, every arm completed 2,592/2,592 requests
(12,960 total) with `evidence_ok = true`. Every quiescent barrier recorded all
2,048 admitted adaptation requests as completed and zero active requests.

## Exact failure

The retirement response was:

```json
{
  "retired": false,
  "reason": "aggregate exceeds decision trust region",
  "max_probability_shift": 0.1522071361541748
}
```

The frozen maximum probability-shift bound was `0.15`. The candidate exceeded
it by `0.0022071361541748`, or approximately `1.47142410%` relative to the
bound. This is a genuine mechanism-level gate rejection, not an analyzer or
request-transport failure.

The recorded retirement hyperparameters were:

```json
{
  "min_observations": 1024,
  "delta_clip": 2.0,
  "min_cosine": 0.8,
  "max_commit_norm": 1.0,
  "max_probability_shift": 0.15,
  "bucket_capacity": 2.0
}
```

## Gate evidence

The frozen gate assessment records:

- `arm_count = 5`
- `mixed_principal_binding_verified = true`
- `pre_retirement_committed_state_invariance = true`
- `shared_over_frozen_adaptation_opportunity = true`
- `tenant_local_refit_valid = true`
- `ctfr_retirement_geometry_valid = false`
- overall `valid = false`

The first four checks are useful diagnostic evidence, but the fail-closed
overall result means they do not license the planned paper claims by
themselves. Stage D's eight confirmatory blocks, Stage E, and the overhead
study were not run after the gate failed.

The `ctfr-full` rejection made no partial state change: committed version,
influence credits, and refit count remained `0`, `[2.0, 2.0]`, and `0`,
respectively. The tenant-local control did complete its declared epoch-matched
refits, advancing both principal-local versions from 0 to 1.

## Additional blocker found during archive audit

Held-out semantic equivalence is not established across the five gate arms.
Only 145/256 baseline-evaluation ordinals and 143/256 post-evaluation ordinals
had identical output hashes across all five arms. The predeclared confirmatory
rules require every ordinal's token IDs and output hash to match within a
block. Therefore v3 must diagnose and remove this source of output divergence
before an eight-block confirmatory Stage D run; merely fixing retirement would
still leave the confirmatory design invalid.

## Preserved evidence

Archive:

`avep-ctfr-full-study-v2-partial.tgz`

SHA-256:

`3557356220ce8831732171439fbec448a308b7cf0179c9f6243a4130e95a3691`

The hash was verified on the EC2 host, after transfer into AWS CloudShell, and
again after copying into this local result directory. The archive contains the
five arm directories, declarations and sidecar hashes, the frozen baseline,
the gate assessment, the exact barrier response, server/gateway logs, audit
joins, estimator snapshots, and resource samples.

A local safety and integrity audit found 334 members and 6,558,329 bytes, with
only regular files and directories: no absolute paths, parent traversal,
links, or special entries. All 44 frozen-input digest entries, all 25 baseline
pilot provenance entries, and all declaration sidecars verified successfully.

## Scientific handling

Do not:

- relabel v2 as a successful CTFR result;
- rerun only `ctfr-full` under the v2 root;
- relax the `0.15` trust-region bound after observing this result; or
- merge a patched arm with the other four v2 arms.

Any mechanism, source, threshold, workload, analyzer, or corpus change requires
a fresh v3 protocol root, new hashes and declaration, a new baseline pilot,
and a complete five-arm gate.

## Recommended v3 mechanism change

Keep the frozen safety bound and make retirement feasibility deterministic:

1. form the compatible candidates' consensus update;
2. project it into the parameter-norm bound;
3. search a predeclared fixed scale grid for the largest scale whose measured
   probability shift is at most `0.15`;
4. commit only that scaled update; and
5. record the selected scale and pre/post trust-region geometry.

This changes CTFR from all-or-nothing rejection to bounded fractional
retirement without weakening the decision trust region. It must be introduced
and evaluated as v3, not retrofitted into v2.

## AWS disposition

The evidence-only restart did not launch vLLM or rerun any experimental arm.
The temporary loopback HTTP server and SSM forwarding process were stopped,
and EC2 instance `i-020836daed664114b` reached `stopped` with waiter return code
zero. Based on the observed 2026-09-20 09:41:45--09:54:11 UTC interval and the
working estimate of USD 2.75652/hour, this retrieval used approximately USD
0.57 of compute before tax (approximately USD 0.06 at 10% VAT). The attached
200 GiB gp3 EBS volume remains allocated and therefore remains billable while
the instance is stopped. The AWS Pricing API returned `0.0912 USD/GB-month`
for gp3 provisioned storage in Asia Pacific (Seoul), so its full-month rack
rate is approximately USD 18.24 before tax (USD 1.824 at 10% VAT). It uses the
included gp3 baseline of 3,000 IOPS and 125 MB/s, so no extra provisioned-IOPS
or throughput charge was identified.
