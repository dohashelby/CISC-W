# AVEP bounded Gate 1 experiment

## Current paper-grade result

The latest independent experiment is protocol
`avep-factorial-confirmatory-v2`, a preregistered 2x2 attack/placebo by
estimator-update shared/blocked design with eight complete fresh-process
blocks. Its analyzer classification is `CONFIRMATORY_FACTORIAL_SIGNAL`.

- Protocol: `FACTORIAL_CONFIRMATORY_V2_PROTOCOL.md`
- Fixed rules: `FACTORIAL_CONFIRMATORY_V2_DECISION_RULES.md`
- Result report: `FACTORIAL_CONFIRMATORY_V2_RESULT_REPORT.md`
- Compact result transcription:
  `factorial_confirmatory_v2_result_summary.json`

The original Gate 1 material described below is retained as discovery history;
it is not the final confirmatory evidence.

This directory contains a localhost-only, single-worker experiment for the
inconclusive AVEP hypothesis. It is not a public exploit or a vulnerability
claim.

The run is pinned to vLLM commit
`4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c`, Qwen3-4B revision
`1cfa9a7208912126459214e8b04321603b3df60c`, and DFlash revision
`b74e3a329c4d963783143b1e970d95b002be72bd`.

The AWS instance must have no inbound security-group rules. The API binds to
`127.0.0.1`; access is through SSM only. The launch configuration uses
instance-initiated shutdown behavior `terminate`, an encrypted gp3 root volume
with `DeleteOnTermination=true`, IMDSv2-only metadata, and a four-hour hard
shutdown timer.

Each strong run executes a neutral baseline, a bounded 1,024-request poison
phase, a post-poison victim phase, two recovery phases, and a fresh-process
control. Two independent strong runs are preserved under
`evidence_20260917/`. The assessment deliberately labels a result as a Gate 1
signal, never as a verified vulnerability.
