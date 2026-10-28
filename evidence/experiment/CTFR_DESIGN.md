# Context-Tagged Feedback Retirement (CTFR)

## Research status and claim boundary

CTFR is a research architecture for online-adaptive serving controllers.  It
adapts speculative-state retirement from CPU microarchitecture to runtime
feedback: feedback produced by an untrusted request is treated as speculative
until a separate retirement rule either commits it to the controller state or
squashes it.

The cross-domain analogy is an inspiration, not the novelty claim.  Shadow
state, commit/abort, provenance labels, and bounded influence all have prior
art.  The candidate contribution is their use as one serving-control boundary:

1. distinguish committed controller state from unretired request feedback;
2. bind feedback to a trusted request origin and explicit policy context;
3. shadow every mutable input to adaptation, including sufficient statistics
   and refit timing;
4. define pre-retirement committed-state invariance and a stronger target
   noninterference property; and
5. evaluate the security/adaptation trade-off in a real LLM serving engine.

The strong property stops at retirement.  Unlike a CPU branch, arbitrary
serving feedback has no resolution oracle that proves it benign.  Post-retirement
safety is conditional on authentication, validator coverage, influence bounds,
and the assumed number of colluding principals.

## Cross-field construction

The primary transfer is one concrete CPU state-visibility lifecycle:

```text
untrusted result -> shadow side effects -> explicit retire or squash
```

CTFR translates it as:

```text
request feedback -> principal-scoped shadow controller state
                 -> validate -> quiescent publish or squash
```

This creates four testable design obligations: committed versus unretired
state, invisibility of unretired feedback to unrelated requests, complete
shadowing of every adaptation-relevant variable, and an explicit publish-or-
squash point.  Branch-predictor isolation additionally motivates binding the
shadow to authenticated origin rather than only to a policy fingerprint.

OCC/MVCC and integrity information flow are supporting formalisms, not co-equal
novelty claims: the former clarifies validation and version consistency for a
future concurrent implementation, while the latter describes the rule that a
low-integrity request cannot directly write high-integrity committed state.
Cumulative influence accounting constrains accepted updates.  Version pinning,
distributed atomic publication, time-refilling rate limits, and a Simplex-style
fallback are not implemented in the first prototype.

## State model

Let `C^v` be committed controller version `v`.  Separate policy context `tau`
from authenticated principal `p`, then define the full origin key
`kappa = (p, tau)`.  Same-policy principals have equal `tau` but different
`p`.  The target architecture indexes an unretired shadow by `U[kappa, v]`:

```text
C^v = (coefficients, commit_version, committed_refit_metadata,
       per_principal_remaining_influence_credits)

U[kappa,v] = (
    sufficient_statistics,
    gradient,
    observation_counts,
    steps_since_refit
)
```

The server derives the context tag rather than accepting one from the client:

```text
tau = H(target_and_draft_model_revisions,
        estimator_feature_contract_version,
        canonical_effective_sampling_policy,
        verification_configuration)
kappa = (authenticated_principal, tau)
```

The authenticated principal must come from a trusted admission layer.  A
client-supplied header is not a security label.  Missing or invalid labels are
fail-closed: their feedback is dropped or placed in an anonymous shadow that
is never eligible for global retirement.

## Request lifecycle

1. **Admission.** The trusted gateway authenticates the principal.  The target
   architecture derives `tau`, reads current committed version `v`, and binds
   `(kappa,v)` to the request.
2. **Serving.** The request reads only `C^v`.  It remains pinned to that version
   until completion so an atomic promotion cannot produce a mixed-version
   request.
3. **Feedback.** Acceptance observations, sufficient statistics, observation
   counts, and the refit clock update only `U[kappa,v]`.  They do not modify `C^v`
   or any other shadow.
4. **Candidate construction.** At a fixed epoch, each eligible shadow proposes
   a clipped update relative to its base version.  A complete implementation
   squashes or explicitly rebases stale candidates.
5. **Validation.** A candidate set is checked against the declared quorum,
   per-principal weight, influence-credit, and trust-region rules.  A trusted
   sentinel is a future strengthening, not part of the first prototype.
6. **Retirement.** If every rule passes, the first prototype publishes
   coefficients and metadata at a harness-enforced single-worker quiescent
   barrier.  Otherwise `C^v` remains unchanged.
7. **Reclamation.** Expired shadows are deleted, never merged into another
   principal's state.  Capacity exhaustion fails closed for learning, not for
   inference.

Coefficients alone are not enough.  Sharing a refit clock or pending sufficient
statistics would let an unretired request change when a victim observes a new
policy.  CTFR therefore shadows all adaptation-relevant state.

## Security properties

### P1: pre-retirement committed-state invariance

For unrelated victim `q != p`, hold the exogenous batch, load, request inputs,
and committed version fixed.  Feedback `F_p` that has not retired must not
change the serialized committed estimator state:

```text
C(after F_p unretired) = C(before F_p)
```

This is an exact value invariant, not a statistical equivalence claim.  The
first mechanism gate compares the committed coefficient bank, version, refit
metadata, and influence credits.  The stronger target property
`D_q(C^v,F_p)=D_q(C^v,empty)` requires a deterministic replay of the same victim
inputs, seeds, and batch trace and is not claimed until that replay passes.

P1 excludes normal queueing, GPU contention, and nondeterministic kernel timing.
Experiments drain the attack queue before measuring the victim and compare the
controller outputs rather than wall-clock equality.

### P2: bounded promotion influence

Retirement cannot prove feedback benign.  CTFR instead constrains a successful
promotion:

- each principal update is norm-clipped to `beta`;
- no principal receives aggregate weight above `rho`;
- a non-refilling per-process credit bounds cumulative admitted influence in
  the first prototype;
- each commit stays within parameter and fixed feature-grid acceptance-
  probability trust regions; and
- a quorum of distinct authenticated principals must support a compatible
  direction.

These are conditional bounds, not universal poisoning resistance.  They rely
on the identity system and do not survive an attacker controlling the declared
quorum.  The credit resets on process restart and is not a lifetime or
wall-clock bound.

### P3: target architecture requirement for version-consistent publication

A complete implementation must pin a request to one committed version, reject
or rebase stale feedback, and publish all workers consistently.  The first
prototype does not implement or evaluate concurrent version pinning, crash
atomicity, or distributed publication; it evaluates only a single-worker
quiescent barrier enforced by the harness.

## Prototype configurations

The vLLM prototype should expose the following modes from a common code path:

| Mode | Update behavior | Experimental role |
| --- | --- | --- |
| `shared` | immediate worker-shared update | vulnerable control |
| `frozen` | `shared` serving with estimator updates disabled | safe non-adaptive floor |
| `route` | route by policy fingerprint | PCFR provenance-routing baseline |
| `tenant-local` | principal-scoped banks, each refit once at the declared barrier | epoch-matched simple adaptive-isolation baseline |
| `ctfr-shadow` | shadow per principal; never promote | exact committed-state gate |
| `ctfr-full` | shadow, validate, then quiescently promote | utility treatment |

The older internal `drop` mode drops only transformed-policy feedback and is
therefore not a general non-adaptive baseline; paper experiments use the
explicit `frozen` arm instead.  The primary tenant-local arm is epoch-matched
to CTFR-full so that update timing cannot explain their difference.  A native
online-refit tenant-local configuration is optional sensitivity analysis.

`ctfr-shadow` deliberately sacrifices global adaptation.  It isolates whether
the retirement boundary itself enforces P1.  `ctfr-full` must separately show
that controlled retirement recovers useful benign adaptation.  CTFR-full must
also be compared with `tenant-local`: without a measured advantage from
cross-principal benign evidence, retirement may be unjustified complexity over
per-principal isolation.

The experiment-support prototype now implements the two fixed principal banks,
explicit epoch-matched tenant-local refit, frozen baseline loading, and
read-only principal-scoped calibration counters.  Retirement still occurs only
at a quiescent
barrier after all admitted requests have completed.  This makes version
publication unambiguous without claiming concurrent or distributed atomic
commit.  Admission-time version pinning and cross-worker compare-and-swap
remain architecture requirements and separate future implementation work.

Within one prototype process, model revisions and the estimator feature
contract are fixed globally.  The trusted gateway overwrites the external
request ID with an authenticated-principal origin prefix; the worker maps only
that internal prefix to a shadow.  A production implementation should carry a
typed, signed context object rather than encode the label in an identifier.

## Fixed first-prototype retirement rule

The first GPU prototype uses a deliberately small rule that can be audited:

- two distinct authenticated principals are required (`k = 2`); the utility
  experiment supplies benign workloads, but the validator cannot know they are
  benign or independent;
- each must contribute at least the declared observation count;
- each principal's candidate delta is L2-clipped to the declared `beta`;
- neither principal may supply more than one half of aggregate candidate
  weight;
- the two deltas must pass a declared directional-agreement threshold;
- the aggregate must stay inside the declared coefficient and fixed
  feature-grid probability trust regions;
- a non-refilling per-process influence credit must remain; and
- coefficients, version, credits, refit metadata, and shadow clearing are
  updated at a harness-enforced quiescent barrier.

This rule is intentionally not called Sybil-resistant.  A separate negative
control gives the attacker `k` principals and demonstrates the boundary of the
quorum assumption.

## Future fail-closed resource policy

The current prototype hard-codes two principal banks and implements neither TTL
nor dynamic eviction.  A production shadow manager must bound cardinality and
fail closed for learning without merging or promoting evicted state.  This is
an architecture requirement and explicit limitation, not an evaluated result.

For the frozen `max_num_seqs=64`, four-step experiment configuration, the
additional fixed research tensors occupy 956 bytes relative to the original
one-bank estimator: 348 bytes for three extra coefficient/statistic banks, 256
bytes each for policy-domain and authenticated-principal slot labels, and 96
bytes for the read-only two-principal evaluation counters.  The declaration
rounds this to a conservative 1,024-byte **persistent shadow-state** bound.
Transient retirement clones and validation-grid workspace are excluded, as are
framework allocator overhead.  Whole-process resource samples are reported
separately.

## Paper-level claim

The strongest defensible claim, if all declared experiments pass, is:

> We transfer speculative-state retirement to online LLM serving feedback and
> implement a two-principal, single-worker vLLM prototype.  Under a
> harness-enforced quiescent protocol, unretired cross-principal feedback leaves
> the serialized committed estimator state exactly invariant.  We separately
> evaluate whether a bounded two-principal retirement rule can recover benign
> adaptation.

The paper must not claim that CTFR proves feedback benign, solves arbitrary
poisoning, resists unrestricted Sybils, or has been validated across serving
engines.
