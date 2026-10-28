# AVEP factorial-confirmatory decision rules

These rules are fixed before collecting protocol
`avep-factorial-confirmatory-v1`. Token 279 is reused without a new screen.

## Structural validity

Every arm must use the declared commit, model revisions, topology, credentials,
workload, token, and order. All requests must succeed and join one-to-one to the
gateway audit under the expected principal, gateway instance, and worker
marker. The intervention must end before post window 1 starts.

Attack interventions must record returned token IDs and have control-token
fraction exactly 1.0. Placebo interventions must not carry an allowed-token
constraint. All four arms execute exactly 4,096 attacker requests.

Immediately before intervention, `shared` arms must report updates enabled and
`blocked` arms disabled. All arms must report updates enabled after the
intervention and before victim post traffic. In blocked arms, the following
fields must be exactly unchanged from the pre-intervention snapshot through
the intervention snapshot:

- `steps_since_refit`
- `refits`
- `slope`
- `intercepts`
- `counts`
- `info`
- `grad`

The eight complete blocks and every run timestamp must match the declared
Williams order. Requests are never counted as independent samples.

## Mechanism gate

The detailed four-arm gate passes only if all conditions hold:

1. both attack-arm intervention acceptance rates are at most 0.05;
2. the absolute difference between attack-arm acceptance rates is at most 0.02;
3. in each update mode, placebo acceptance minus attack acceptance is at least
   0.10;
4. both blocked estimator states are exactly invariant during intervention;
5. the `intercept[0]` difference-in-differences is at most -0.50;
6. the normalized post-window-1 draft-budget interaction is at most -0.05.

Gate failure stops performance collection. Gate results are not included as
performance replicates.

## Primary endpoint

For arm `w_u` in block `b`, define:

```text
Y(b,w,u) = post_01_output_tokens_per_second / mean(pre_01..pre_04)
```

The block interaction is:

```text
I_b = [Y(b,attack,shared) - Y(b,attack,blocked)]
      - [Y(b,placebo,shared) - Y(b,placebo,blocked)]
```

Negative values support the proposed causal path. A confirmatory signal
requires all of the following:

- all eight blocks are structurally valid;
- at least seven of eight `I_b` values are negative;
- the one-sided exact sign-test probability for the observed negative count is
  at most 0.05;
- the paired block-bootstrap 95% interval for the mean interaction has an
  upper bound below zero.

The bootstrap uses 20,000 fixed-seed resamples of complete blocks. The exact
sign test is computed under a 0.5 null probability, without dropping zero
interactions.

## Secondary endpoints

- p50 and p95 latency interactions, where positive is adverse;
- normalized draft-budget interaction;
- `intercept[0]`, slope, and refit deltas;
- throughput interaction for all eight post windows;
- cumulative victim completion-time increase and degraded-token exposure;
- intervention wall time and victim-harm/attacker-work ratios;
- observed recovery within the fixed eight-window horizon.

Secondary endpoints do not replace a failed primary endpoint. No subgroup,
alternative post-window boundary, token, or threshold may be promoted after
data collection.

## Classification

The analyzer emits exactly one classification:

- `CONFIRMATORY_FACTORIAL_SIGNAL`
- `CONFIRMATORY_FACTORIAL_INCONCLUSIVE`
- `INVALID`

Even a confirmatory signal is scoped to the pinned single-worker vLLM
configuration and the declared gateway-authenticated principals.
