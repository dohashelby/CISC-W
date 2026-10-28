# AVEP factorial-confirmatory v2 decision rules

These rules are fixed before collecting protocol
`avep-factorial-confirmatory-v2`. Token 279 is reused without a new screen.
The invalid v1 gate is treated only as pilot evidence and is not a v2
replicate.

## Structural validity

Every arm must use the declared commit, model revisions, topology,
credentials, workload, token, and order. All requests must succeed and join
one-to-one to the gateway audit under the expected principal, gateway
instance, and worker marker. The intervention must end before post window 1.

Attack interventions must record returned token IDs and have control-token
fraction exactly 1.0. Placebo interventions must not carry an allowed-token
constraint. All four arms execute exactly 4,096 attacker requests.

Immediately before intervention, `shared` arms must report updates enabled and
`blocked` arms disabled. All arms must report updates enabled after the
intervention and before victim post traffic. In blocked arms, these fields
must be exactly unchanged from pre-intervention through intervention:

- `steps_since_refit`
- `refits`
- `slope`
- `intercepts`
- `counts`
- `info`
- `grad`

The eight complete blocks and every timestamp must match the declared Williams
order. Requests are never counted as independent samples.

## Mechanism gate

The detailed four-arm gate passes only if all conditions hold:

1. both attack-arm intervention acceptance rates are at most 0.05;
2. their absolute acceptance-rate difference is at most 0.02;
3. in each update mode, placebo acceptance minus attack acceptance is at least
   0.10;
4. both blocked estimator states are exactly invariant during intervention;
5. the `intercept[0]` difference-in-differences is at most -0.50;
6. the arithmetic mean of the eight normalized post-window draft-budget
   interactions is at most -0.05.

For rule 6, each arm's window budget is divided by its mean budget across
`pre_01` through `pre_04`. The interaction is calculated separately for each
of `post_01` through `post_08`, then the eight interactions are averaged. The
fixed full horizon includes `post_01`; no onset window is selected after data
collection.

Gate failure stops performance collection. Gate results are not performance
replicates.

## Primary endpoint

For arm `w_u` in block `b`, first define each normalized post window:

```text
Y(b,w,u,p) = throughput(b,w,u,p) / mean(pre_01..pre_04 throughput)
```

Then define the fixed-horizon arm outcome:

```text
M(b,w,u) = mean(Y(b,w,u,post_01)..Y(b,w,u,post_08))
```

The block interaction is:

```text
I_b = [M(b,attack,shared) - M(b,attack,blocked)]
      - [M(b,placebo,shared) - M(b,placebo,blocked)]
```

A confirmatory signal requires all of the following:

- all eight blocks are structurally valid;
- at least seven of eight `I_b` values are negative;
- the one-sided exact sign-test probability is at most 0.05;
- the paired block-bootstrap 95% interval for mean `I_b` has an upper bound
  below zero.

The bootstrap uses 20,000 fixed-seed resamples of complete blocks. The exact
sign test uses a 0.5 null probability and counts zero as nonnegative.

## Secondary endpoints

- fixed-horizon p50 and p95 latency interactions, where positive is adverse;
- all eight per-window throughput interactions, reported without selecting a
  new primary onset point;
- normalized draft-budget interactions;
- `intercept[0]`, slope, refit, and finite-coefficient trajectories;
- cumulative victim wall-time interaction;
- intervention wall time and victim-harm/attacker-work ratio;
- recovery or continued degradation within the fixed horizon.

Secondary endpoints do not replace a failed primary endpoint. No subgroup,
alternative horizon, token, threshold, or model configuration may be promoted
after v2 collection.

## Classification

The analyzer emits exactly one classification:

- `CONFIRMATORY_FACTORIAL_SIGNAL`
- `CONFIRMATORY_FACTORIAL_INCONCLUSIVE`
- `INVALID`

Even a signal is scoped to the pinned single-worker vLLM configuration and the
declared gateway-authenticated principals.
