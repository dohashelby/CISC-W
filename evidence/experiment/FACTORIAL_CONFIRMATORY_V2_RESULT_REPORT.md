# AVEP 2x2 factorial-confirmatory v2 result

## Status

The independent v2 cohort is structurally valid and satisfies every
predeclared mechanism and primary-outcome rule.

- Analyzer classification: `CONFIRMATORY_FACTORIAL_SIGNAL`
- Overall validity: `true`
- Analyzer errors: none
- Mechanism gate: all six checks passed
- Performance cohort: all 32 planned arms completed in all eight blocks
- Adverse throughput interactions: `8/8`
- One-sided exact sign-test probability: `0.00390625`
- Primary paired-block bootstrap interval: entirely below zero

The defensible conclusion is:

> In the pinned vLLM configuration, the post-request victim-performance
> effect was attack-specific and required the attacker's verification
> feedback to update the worker-shared online acceptance estimator.

This is a vLLM case-study result for the declared configuration. It is not
evidence that every online-adaptive serving engine is vulnerable.

## Design

The experiment crossed two factors in a fixed 2x2 design:

| Arm | Intervention workload | Estimator update |
| --- | --- | --- |
| `placebo_shared` (`P-S`) | unconstrained placebo | enabled |
| `placebo_blocked` (`P-B`) | unconstrained placebo | disabled |
| `attack_shared` (`A-S`) | `allowed_token_ids=[279]` | enabled |
| `attack_blocked` (`A-B`) | `allowed_token_ids=[279]` | disabled |

The block-level estimand was

```text
[(A-S) - (A-B)] - [(P-S) - (P-B)].
```

Every arm used a fresh vLLM process. The performance cohort comprised eight
complete temporal blocks, with the four-arm Williams order repeated twice.
Requests within a process were treated as correlated measurements, not as
independent replicates. Statistical inference resampled complete blocks.

Each arm executed:

- 1,024 victim warm-up requests;
- four 128-request victim pre windows;
- 4,096 attacker intervention requests;
- eight 128-request, non-overlapping victim post windows.

Attacker and victim were distinct gateway-authenticated principals routed to
one worker. The gateway identities are an experimental trust boundary and not
a claim that vLLM exposes native tenant identities.

## Fixed environment

- vLLM commit: `4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c`
- Target: `Qwen/Qwen3-4B`, revision
  `1cfa9a7208912126459214e8b04321603b3df60c`
- Draft: `z-lab/Qwen3-4B-DFlash-b16`, revision
  `b74e3a329c4d963783143b1e970d95b002be72bd`
- Selected token: `279`, frozen from earlier exploratory screening
- GPU: NVIDIA L40S on AWS Seoul `g6e.2xlarge`
- Topology: one localhost-only vLLM worker and one authentication gateway
- Protocol: `avep-factorial-confirmatory-v2`

The v2 protocol, rules, schedule, source inputs, and transitive v1 driver hash
were committed before the first v2 request. The first deployment attempt was
aborted before any workload request when the missing transitive source-hash
check was detected; that pre-run attempt was preserved separately and is not
part of this cohort.

## Mechanism gate

All six predeclared checks passed.

| Observation | Result |
| --- | ---: |
| Attack acceptance, blocked/shared | `0.0000 / 0.0000` |
| Placebo acceptance, blocked/shared | `0.1875 / 0.1875` |
| Both blocked estimator states | exactly invariant |
| `intercept[0]` attack-by-update interaction | `-13.850842` |
| Mean eight-window normalized budget interaction | `-0.516309` |

Thus both attack arms received the same zero-acceptance verification stimulus.
Only the shared arms allowed that feedback to change the proposed mediator,
and the downstream verification-budget interaction moved in the adverse
direction.

## Primary performance endpoint

The predeclared endpoint was the block-level attack-by-update interaction in
the arithmetic mean of pre-normalized throughput across `post_01` through
`post_08`.

Mean normalized arm outcomes were:

| Arm | Mean post/pre throughput |
| --- | ---: |
| `A-S` | `0.684679` |
| `A-B` | `1.001843` |
| `P-S` | `0.926882` |
| `P-B` | `0.996215` |

The corresponding simple update effects were:

- attack: `A-S - A-B = -0.317165`;
- placebo: `P-S - P-B = -0.069334`.

Subtracting the placebo update effect produced the primary interaction:

- mean: `-0.247831`;
- paired-block bootstrap 95% CI: `[-0.258618, -0.238009]`;
- adverse blocks: `8/8`;
- one-sided exact sign-test: `p = 0.00390625`.

The eight block interactions were:

| Block | Throughput interaction |
| ---: | ---: |
| 01 | `-0.277154` |
| 02 | `-0.244125` |
| 03 | `-0.262462` |
| 04 | `-0.245273` |
| 05 | `-0.250082` |
| 06 | `-0.241501` |
| 07 | `-0.237717` |
| 08 | `-0.224336` |

The value `-0.247831` is a 24.78 percentage-point interaction between
baseline-normalized arms. It must not be presented as a universal 24.78% raw
throughput loss for arbitrary deployments.

## Secondary endpoints

Both fixed-horizon latency interactions were adverse and their bootstrap
intervals excluded zero.

| Endpoint | Mean interaction | 95% bootstrap CI |
| --- | ---: | ---: |
| Normalized p50 latency | `+0.505264` | `[+0.485950, +0.526696]` |
| Normalized p95 latency | `+0.478777` | `[+0.455672, +0.493538]` |

The throughput interaction was negative in every post window, without
selecting a post-hoc onset point:

| Window | Mean throughput interaction |
| --- | ---: |
| `post_01` | `-0.095496` |
| `post_02` | `-0.187892` |
| `post_03` | `-0.325674` |
| `post_04` | `-0.295651` |
| `post_05` | `-0.291483` |
| `post_06` | `-0.287162` |
| `post_07` | `-0.240802` |
| `post_08` | `-0.258489` |

The trajectory supports a delayed, non-monotone controller response rather
than a claim that the first post window is always the maximum-impact window.
The mean measured victim-harm-to-attacker-intervention-wall-time ratio was
`0.143185`. Because it is below one and covers only the fixed victim horizon,
this experiment does not establish economic amplification.

## Causal interpretation

The factorial design rules out the two most important tested alternatives:

1. **Attack workload alone.** Both attack arms executed the same 4,096
   low-acceptance requests, target verification, and GPU work, but their later
   outcomes diverged when estimator updates were enabled versus blocked.
2. **Shared-update mode alone.** The placebo shared-versus-blocked contrast was
   measured in every block and subtracted from the attack contrast.

Together with exact blocked-state invariance, the estimator coefficient
interaction, and the verification-budget interaction, the result supports the
measured path:

```text
attacker-controlled verification feedback
  -> worker-shared estimator update
  -> later victim verification-policy change
  -> throughput and latency degradation
```

The experiment tests whether the estimator update is required for the effect;
it does not prove that the current sampling-support handling is the only
possible root cause.

## Claim boundary

The result supports an attack-specific, estimator-mediated, cross-principal
post-request effect for two gateway-authenticated principals on one pinned
vLLM worker.

It does not establish:

- native vLLM tenant isolation bypass;
- every affected vLLM version;
- generality to other models, GPUs, workers, or serving engines;
- an unbounded persistence duration beyond the eight post windows;
- economic amplification under arbitrary traffic distributions;
- that any proposed mitigation is production-ready.

The paper can generalize the *risk structure* to online-adaptive serving, but
must identify vLLM as the only experimentally validated case study until a
second independent engine is tested.

## Artifact integrity and AWS state

The complete remote archive was generated and verified before the instance was
stopped:

- EC2/EBS path:
  `/home/ubuntu/avep/avep-factorial-confirmatory-v2-results.tgz`
- Size: approximately 36 MiB
- SHA-256:
  `24d66078399e3a8a9a7a9c78c2dc26f8cfefa8a71a25f26a45dd91d82738a032`
- Assessment inside the result root:
  `/home/ubuntu/avep/factorial_confirmatory_results_v2/factorial_assessment.json`
- Assessment size: approximately 163 KiB
- Archive verification: `sha256sum -c` returned `OK`

The archive remains on the retained EBS volume. EC2 compute was stopped after
collection; only the small retained-volume cost continues until the instance
or volume is explicitly deleted.

Treat the raw archive as a private audit artifact. Before any public release,
inspect it for ephemeral bearer keys, host identifiers, private advisory
details, and other environment metadata, then produce a separately hashed
sanitized reproduction bundle.

The observed start-to-confirmed-stop interval was approximately 2.565 hours
(`2026-09-19 19:19:29` to about `21:53:22` KST). At the experiment's quoted
rate of USD 2.75652/hour, the conservative compute estimate is about USD 7.07;
10% VAT on that amount is about USD 0.71 before any credit treatment. Small
public-IPv4 charges are not included in that estimate. This is an engineering
estimate, not an AWS invoice.

The stopped instance retains one encrypted 200-GiB gp3 volume
(`vol-0d7566df92038fe73`). The AWS Pricing API returned
`$0.0912/GiB-month` for gp3 storage in Seoul, so continued retention is about
USD 18.24 per month (about USD 0.61 per 30-day-equivalent day), with
approximately USD 1.82 monthly VAT before credit treatment. The volume was not
deleted because it contains the authoritative raw archive.
