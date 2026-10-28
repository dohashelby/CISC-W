# CTFR Stage D/E frozen-corpus and manifest schema

## Purpose

`generate_ctfr_manifests.py` turns one reviewed and hash-frozen corpus into the
nine request manifests used by the dual-principal Stage D/E harness.  Counts,
prompt order, sampling settings, principal assignment, seeds, and wave order
come only from the frozen corpus or the versioned generator.  They are not
selected after observing a confirmatory result.

The transport names remain `attacker` and `victim` because those are the two
authenticated gateway identities.  The manifest's `principal_roles` records
their scientific role in each experiment.  In Stage D both are experiment-
assigned benign principals; in E3 both credentials are attacker-controlled.

## Frozen corpus: `ctfr-frozen-corpus-v1`

The top-level object has these fields:

| Field | Requirement |
|---|---|
| `schema` | Exactly `ctfr-frozen-corpus-v1`. |
| `corpus_id` | Stable identifier matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. |
| `frozen_sha256` | Lowercase SHA-256 of the canonical corpus after removing this field. Required for generation. |
| `request_defaults` | Exactly `base_seed`, `max_tokens`, and `temperature`. |
| `repetitions` | Exactly one positive count for each output manifest stem. |
| `prompt_sets` | Exactly the seven prompt sets below. |
| `metadata` | Optional JSON object; included in the corpus hash but not copied into requests. |

`base_seed` is a non-negative 63-bit integer.  `max_tokens` is in `[1, 64]`,
and `temperature` is finite and in `[0, 2]`.  A repetition count is in
`[1, 4096]`; generation also rejects any individual manifest over 8,192
requests.  Baseline/shifted evaluation repetition counts must match, as must
the E1/E2/E3 counts.  These checks preserve paired evaluation and an equal
per-identity adversarial observation budget across the assumption tests.

The required repetition keys, which are also the manifest names, are:

```text
compile_warmup
baseline_adaptation
baseline_evaluation
shifted_adaptation
shifted_evaluation
stationary_adaptation
e1_one_identity
e2_disagreement
e3_two_credentials
```

### Prompt objects

Every prompt object contains:

```json
{
  "prompt_id": "eval-001",
  "prompt": "A frozen prompt"
}
```

It may override `max_tokens`, `temperature`, or `allowed_token_ids`.
`allowed_token_ids` is either omitted/null or a non-empty list of distinct,
non-negative token IDs.  Unknown keys, duplicate JSON keys, non-finite numbers,
empty prompts, NUL bytes, and prompts larger than 32 KiB are rejected.

Prompt IDs and exact prompt text are globally unique across source sets.  This
prevents an evaluation example from being hidden under a new ID in a training
set.  The generator also checks the declared training/evaluation partitions
directly.

### Required prompt sets

| Prompt set | Role |
|---|---|
| `compile_warmup` | Request shapes used only before a process/controller reset. |
| `baseline_benign_train` | Benign observations used to learn and serialize baseline state `C*`. |
| `adaptation_eval` | Held-out cohort used by both baseline and post-shift evaluation. |
| `shifted_benign_train` | Corroborating benign post-shift observations for Stage D. |
| `stationary_benign_train` | No-attack stationary traffic for the overhead study. |
| `adversarial_train` | Fixed attacker workload reused across E1, E2, and E3. |
| `disagreement_benign_train` | Fixed benign workload paired against the attacker in E2. |

`adversarial_train` and `disagreement_benign_train` must have the same number
of prompts so E2 can pair one request from each principal in every wave.

The baseline and shifted evaluation manifests deliberately reuse the one
`adaptation_eval` set.  Thus they are paired on prompt IDs and deterministic
seeds while remaining held out from every adaptation set.  Evaluation prompts
must not be used to update the controller before their declared evaluation
point; the harness is responsible for restoring the serialized state around
measurement when an arm's mode would otherwise learn from evaluation traffic.

## Generated manifests

The generator writes these exact files:

| File | Identities and source sets |
|---|---|
| `compile_warmup.json` | Both identities; `compile_warmup`. |
| `baseline_adaptation.json` | Both benign identities; `baseline_benign_train`. |
| `baseline_evaluation.json` | Both benign identities; `adaptation_eval`. |
| `shifted_adaptation.json` | Both benign identities; `shifted_benign_train`. |
| `shifted_evaluation.json` | Both benign identities; `adaptation_eval`. |
| `stationary_adaptation.json` | Both benign identities; `stationary_benign_train`. |
| `e1_one_identity.json` | Only the `attacker` identity; `adversarial_train`. |
| `e2_disagreement.json` | `attacker` uses adversarial; `victim` uses disagreement-benign. |
| `e3_two_credentials.json` | Both attacker-controlled credentials use the same adversarial prompt in each wave. |

The names E2 and E3 encode predeclared experimental intent, not their result.
The pilot must establish and freeze candidate geometry.  The confirmatory
analyzer must still verify that E2 candidates disagree and squash, and report
whether E3 candidates actually satisfy the retirement rule.  Manifest
assignment alone is not evidence for either conclusion.

Every generated file has `schema: ctfr-workload-manifest-v1`, so it can be
consumed directly by `ctfr_dual_probe.py`.  Extra evidence fields include
`prompt_id`, `prompt_set`, `repetition`, and `workload_role`.

For dual-principal manifests, every wave contains exactly one request for each
principal.  Submission order alternates between waves.  E1 has one attacker
request per wave.  Ordinals are contiguous from zero, and waves are contiguous
from zero.

Seeds are derived deterministically from the frozen base seed, a fixed seed
scope, the repetition, and the prompt ID.  Principal identity is intentionally
excluded: two principals receiving the same prompt in a wave receive the same
seed.  Baseline/shifted evaluation share a seed scope, and the adversarial
requests in E1/E2/E3 share a seed scope, making the intended comparisons
paired.

## Canonical hashes

Canonical JSON uses UTF-8, sorted object keys, no insignificant whitespace, and
no NaN or infinity.  `manifest_index.json` contains the canonical SHA-256,
request count, and wave count of every manifest in fixed order.

The index also contains `bundle_sha256`, computed over the corpus identity,
generator schema, and the complete ordered manifest-descriptor list.  The
bundle hash is not a hash of its own containing index file.  It is a compact
commitment to the corpus and all nine canonical manifest hashes.

Generation refuses to overwrite an existing file whose bytes differ.  Use a
fresh directory for a new frozen cohort.  Check mode regenerates the expected
content in memory and requires byte-for-byte equality for all nine manifests
and the index.

## Freeze and generation workflow

Start with a complete corpus object but omit `frozen_sha256`.  A minimal shape
is:

```json
{
  "schema": "ctfr-frozen-corpus-v1",
  "corpus_id": "ctfr-stage-de-pilot-locked-v1",
  "request_defaults": {
    "base_seed": 20260920,
    "max_tokens": 16,
    "temperature": 0.0
  },
  "repetitions": {
    "compile_warmup": 1,
    "baseline_adaptation": 1,
    "baseline_evaluation": 1,
    "shifted_adaptation": 1,
    "shifted_evaluation": 1,
    "stationary_adaptation": 1,
    "e1_one_identity": 1,
    "e2_disagreement": 1,
    "e3_two_credentials": 1
  },
  "prompt_sets": {
    "compile_warmup": [{"prompt_id": "warm-001", "prompt": "warm"}],
    "baseline_benign_train": [{"prompt_id": "base-001", "prompt": "base"}],
    "adaptation_eval": [{"prompt_id": "eval-001", "prompt": "eval"}],
    "shifted_benign_train": [{"prompt_id": "shift-001", "prompt": "shift"}],
    "stationary_benign_train": [{"prompt_id": "stat-001", "prompt": "stat"}],
    "adversarial_train": [{"prompt_id": "adv-001", "prompt": "adv"}],
    "disagreement_benign_train": [{"prompt_id": "dis-001", "prompt": "dis"}]
  }
}
```

From `security_avep_experiment`, use the pinned vLLM environment:

```bash
../.venv/bin/python generate_ctfr_manifests.py \
  --corpus ctfr_frozen_corpus.json \
  --print-corpus-sha256
```

Review the corpus, insert the printed value as `frozen_sha256`, and do not
change any other byte-level JSON value without recomputing and reviewing the
hash.  Generate and independently check the bundle:

```bash
../.venv/bin/python generate_ctfr_manifests.py \
  --corpus ctfr_frozen_corpus.json \
  --output-dir manifests

../.venv/bin/python generate_ctfr_manifests.py \
  --corpus ctfr_frozen_corpus.json \
  --output-dir manifests \
  --check
```

Archive the frozen corpus, generator, `manifest_index.json`, source/patch
hashes, and generated manifests before the first confirmatory request.  The
compile-warmup manifest must be followed by the declared process/controller
reset; it must not seed a measured arm.
