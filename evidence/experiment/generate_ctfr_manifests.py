#!/usr/bin/env python
"""Generate frozen dual-principal CTFR Stage D/E workload manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CORPUS_SCHEMA = "ctfr-frozen-corpus-v1"
MANIFEST_SCHEMA = "ctfr-workload-manifest-v1"
INDEX_SCHEMA = "ctfr-manifest-index-v1"
GENERATOR_SCHEMA = "ctfr-manifest-generator-v1"
PRINCIPALS = ("attacker", "victim")
MAX_ENTRIES = 8192

PROMPT_SET_NAMES = (
    "compile_warmup",
    "baseline_benign_train",
    "adaptation_eval",
    "shifted_benign_train",
    "stationary_benign_train",
    "adversarial_train",
    "disagreement_benign_train",
)
TRAIN_PROMPT_SETS = frozenset(
    {
        "baseline_benign_train",
        "shifted_benign_train",
        "stationary_benign_train",
        "adversarial_train",
        "disagreement_benign_train",
    }
)
EVAL_PROMPT_SETS = frozenset({"adaptation_eval"})


@dataclass(frozen=True)
class Assignment:
    principal: str
    prompt_set: str
    role: str


@dataclass(frozen=True)
class ManifestSpec:
    name: str
    file_name: str
    stage: str
    purpose: str
    seed_scope: str
    assignments: tuple[Assignment, ...]


DUAL_BENIGN_ROLES = (
    Assignment("attacker", "baseline_benign_train", "benign-a"),
    Assignment("victim", "baseline_benign_train", "benign-b"),
)

MANIFEST_SPECS = (
    ManifestSpec(
        "compile_warmup",
        "compile_warmup.json",
        "D0",
        "compile request shapes before a controller reset",
        "compile-warmup",
        (
            Assignment("attacker", "compile_warmup", "benign-a"),
            Assignment("victim", "compile_warmup", "benign-b"),
        ),
    ),
    ManifestSpec(
        "baseline_adaptation",
        "baseline_adaptation.json",
        "D",
        "learn the frozen baseline regime before C* serialization",
        "baseline-adaptation",
        DUAL_BENIGN_ROLES,
    ),
    ManifestSpec(
        "baseline_evaluation",
        "baseline_evaluation.json",
        "D",
        "evaluate the frozen pre-shift baseline on held-out prompts",
        "adaptation-evaluation",
        (
            Assignment("attacker", "adaptation_eval", "benign-a"),
            Assignment("victim", "adaptation_eval", "benign-b"),
        ),
    ),
    ManifestSpec(
        "shifted_adaptation",
        "shifted_adaptation.json",
        "D",
        "accumulate corroborating post-shift benign feedback",
        "shifted-adaptation",
        (
            Assignment("attacker", "shifted_benign_train", "benign-a"),
            Assignment("victim", "shifted_benign_train", "benign-b"),
        ),
    ),
    ManifestSpec(
        "shifted_evaluation",
        "shifted_evaluation.json",
        "D",
        "evaluate post-shift utility on the same held-out cohort",
        "adaptation-evaluation",
        (
            Assignment("attacker", "adaptation_eval", "benign-a"),
            Assignment("victim", "adaptation_eval", "benign-b"),
        ),
    ),
    ManifestSpec(
        "stationary_adaptation",
        "stationary_adaptation.json",
        "E-overhead",
        "measure no-attack stationary adaptation and overhead",
        "stationary-adaptation",
        (
            Assignment(
                "attacker", "stationary_benign_train", "benign-a"
            ),
            Assignment("victim", "stationary_benign_train", "benign-b"),
        ),
    ),
    ManifestSpec(
        "e1_one_identity",
        "e1_one_identity.json",
        "E1",
        "exercise one attacker identity below the two-principal quorum",
        "sybil-assumption",
        (
            Assignment("attacker", "adversarial_train", "attacker-a"),
        ),
    ),
    ManifestSpec(
        "e2_disagreement",
        "e2_disagreement.json",
        "E2",
        "exercise directionally disagreeing attacker and benign candidates",
        "sybil-assumption",
        (
            Assignment("attacker", "adversarial_train", "attacker-a"),
            Assignment(
                "victim", "disagreement_benign_train", "benign-b"
            ),
        ),
    ),
    ManifestSpec(
        "e3_two_credentials",
        "e3_two_credentials.json",
        "E3",
        "document quorum capture by two attacker-controlled credentials",
        "sybil-assumption",
        (
            Assignment("attacker", "adversarial_train", "attacker-a"),
            Assignment("victim", "adversarial_train", "attacker-b"),
        ),
    ),
)

MANIFEST_NAMES = tuple(spec.name for spec in MANIFEST_SPECS)
_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def read_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject_constant,
    )


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def corpus_content_sha256(payload: dict[str, Any]) -> str:
    material = dict(payload)
    material.pop("frozen_sha256", None)
    return canonical_sha256(material)


def _is_int(value: Any) -> bool:
    return type(value) is int


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _validate_request_profile(
    profile: dict[str, Any],
    *,
    location: str,
    require_prompt: bool,
) -> None:
    allowed = {
        "prompt_id",
        "prompt",
        "max_tokens",
        "temperature",
        "allowed_token_ids",
    }
    if not isinstance(profile, dict):
        raise ValueError(f"{location} must be an object")
    unexpected = set(profile) - allowed
    if unexpected:
        raise ValueError(f"{location} has unknown keys: {sorted(unexpected)}")
    if require_prompt:
        prompt_id = profile.get("prompt_id")
        prompt = profile.get("prompt")
        if not isinstance(prompt_id, str) or not _ID_PATTERN.fullmatch(
            prompt_id
        ):
            raise ValueError(f"{location}.prompt_id is invalid")
        if not isinstance(prompt, str) or not prompt or "\x00" in prompt:
            raise ValueError(f"{location}.prompt must be non-empty text")
        if len(prompt.encode()) > 32768:
            raise ValueError(f"{location}.prompt exceeds 32 KiB")
    max_tokens = profile.get("max_tokens")
    if max_tokens is not None and (
        not _is_int(max_tokens) or not 1 <= max_tokens <= 64
    ):
        raise ValueError(f"{location}.max_tokens must be in [1, 64]")
    temperature = profile.get("temperature")
    if temperature is not None and (
        not _is_number(temperature) or not 0 <= temperature <= 2
    ):
        raise ValueError(f"{location}.temperature must be in [0, 2]")
    token_ids = profile.get("allowed_token_ids")
    if token_ids is not None:
        if (
            not isinstance(token_ids, list)
            or not token_ids
            or any(not _is_int(token) or token < 0 for token in token_ids)
            or len(set(token_ids)) != len(token_ids)
        ):
            raise ValueError(
                f"{location}.allowed_token_ids must contain distinct "
                "non-negative integers"
            )


def validate_corpus(
    payload: Any,
    *,
    verify_frozen_hash: bool = True,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("corpus must be a JSON object")
    required = {
        "schema",
        "corpus_id",
        "request_defaults",
        "repetitions",
        "prompt_sets",
    }
    allowed = required | {"frozen_sha256", "metadata"}
    missing = required - set(payload)
    unexpected = set(payload) - allowed
    if missing:
        raise ValueError(f"corpus is missing keys: {sorted(missing)}")
    if unexpected:
        raise ValueError(f"corpus has unknown keys: {sorted(unexpected)}")
    if payload["schema"] != CORPUS_SCHEMA:
        raise ValueError(f"corpus schema must be {CORPUS_SCHEMA}")
    corpus_id = payload["corpus_id"]
    if not isinstance(corpus_id, str) or not _ID_PATTERN.fullmatch(corpus_id):
        raise ValueError("corpus_id is invalid")
    if "metadata" in payload and not isinstance(payload["metadata"], dict):
        raise ValueError("metadata must be an object")

    defaults = payload["request_defaults"]
    if not isinstance(defaults, dict):
        raise ValueError("request_defaults must be an object")
    if set(defaults) != {"base_seed", "max_tokens", "temperature"}:
        raise ValueError(
            "request_defaults must contain exactly base_seed, max_tokens, "
            "and temperature"
        )
    if not _is_int(defaults["base_seed"]) or not (
        0 <= defaults["base_seed"] <= 2**63 - 1
    ):
        raise ValueError("request_defaults.base_seed must be a 63-bit integer")
    _validate_request_profile(
        {
            "max_tokens": defaults["max_tokens"],
            "temperature": defaults["temperature"],
        },
        location="request_defaults",
        require_prompt=False,
    )

    repetitions = payload["repetitions"]
    if not isinstance(repetitions, dict) or set(repetitions) != set(
        MANIFEST_NAMES
    ):
        raise ValueError(
            "repetitions must contain exactly the nine manifest names"
        )
    for name, count in repetitions.items():
        if not _is_int(count) or not 1 <= count <= 4096:
            raise ValueError(f"repetitions.{name} must be in [1, 4096]")
    if repetitions["baseline_evaluation"] != repetitions[
        "shifted_evaluation"
    ]:
        raise ValueError(
            "baseline_evaluation and shifted_evaluation repetitions must "
            "match"
        )
    sybil_repetitions = {
        repetitions["e1_one_identity"],
        repetitions["e2_disagreement"],
        repetitions["e3_two_credentials"],
    }
    if len(sybil_repetitions) != 1:
        raise ValueError("E1, E2, and E3 repetitions must match")

    prompt_sets = payload["prompt_sets"]
    if not isinstance(prompt_sets, dict) or set(prompt_sets) != set(
        PROMPT_SET_NAMES
    ):
        raise ValueError(
            "prompt_sets must contain exactly the seven declared sets"
        )
    prompt_id_owner: dict[str, str] = {}
    prompt_text_owner: dict[str, str] = {}
    for set_name in PROMPT_SET_NAMES:
        prompts = prompt_sets[set_name]
        if not isinstance(prompts, list) or not prompts:
            raise ValueError(f"prompt_sets.{set_name} must be non-empty")
        for index, prompt in enumerate(prompts):
            location = f"prompt_sets.{set_name}[{index}]"
            _validate_request_profile(
                prompt,
                location=location,
                require_prompt=True,
            )
            prompt_id = prompt["prompt_id"]
            prior_set = prompt_id_owner.get(prompt_id)
            if prior_set is not None:
                raise ValueError(
                    f"prompt_id {prompt_id!r} appears in {prior_set} and "
                    f"{set_name}"
                )
            prompt_id_owner[prompt_id] = set_name
            prompt_text = prompt["prompt"]
            prior_text_set = prompt_text_owner.get(prompt_text)
            if prior_text_set is not None:
                raise ValueError(
                    "identical prompt text appears under multiple IDs in "
                    f"{prior_text_set} and {set_name}"
                )
            prompt_text_owner[prompt_text] = set_name

    train_ids = {
        prompt["prompt_id"]
        for set_name in TRAIN_PROMPT_SETS
        for prompt in prompt_sets[set_name]
    }
    eval_ids = {
        prompt["prompt_id"]
        for set_name in EVAL_PROMPT_SETS
        for prompt in prompt_sets[set_name]
    }
    if train_ids & eval_ids:
        raise ValueError("training and evaluation prompt IDs overlap")
    warmup_ids = {
        prompt["prompt_id"] for prompt in prompt_sets["compile_warmup"]
    }
    if warmup_ids & (train_ids | eval_ids):
        raise ValueError("compile-warmup prompt IDs must be disjoint")

    e2_lengths = {
        len(prompt_sets["adversarial_train"]),
        len(prompt_sets["disagreement_benign_train"]),
    }
    if len(e2_lengths) != 1:
        raise ValueError(
            "adversarial_train and disagreement_benign_train must have "
            "equal length for E2 wave pairing"
        )

    if verify_frozen_hash:
        frozen_hash = payload.get("frozen_sha256")
        expected_hash = corpus_content_sha256(payload)
        if not isinstance(frozen_hash, str) or not _SHA256_PATTERN.fullmatch(
            frozen_hash
        ):
            raise ValueError("frozen_sha256 must be a lowercase SHA-256")
        if frozen_hash != expected_hash:
            raise ValueError(
                "frozen_sha256 mismatch: expected " + expected_hash
            )
    return payload


def _request_seed(
    base_seed: int,
    seed_scope: str,
    repetition: int,
    prompt_id: str,
) -> int:
    material = [base_seed, seed_scope, repetition, prompt_id]
    return int(canonical_sha256(material)[:16], 16) % (2**31)


def _entry_for(
    *,
    assignment: Assignment,
    prompt: dict[str, Any],
    defaults: dict[str, Any],
    ordinal: int,
    wave: int,
    repetition: int,
    seed_scope: str,
) -> dict[str, Any]:
    return {
        "allowed_token_ids": prompt.get("allowed_token_ids"),
        "max_tokens": prompt.get("max_tokens", defaults["max_tokens"]),
        "ordinal": ordinal,
        "principal": assignment.principal,
        "prompt": prompt["prompt"],
        "prompt_id": prompt["prompt_id"],
        "prompt_set": assignment.prompt_set,
        "repetition": repetition,
        "seed": _request_seed(
            defaults["base_seed"],
            seed_scope,
            repetition,
            prompt["prompt_id"],
        ),
        "temperature": prompt.get(
            "temperature", defaults["temperature"]
        ),
        "wave": wave,
        "workload_role": assignment.role,
    }


def _build_manifest(
    corpus: dict[str, Any], spec: ManifestSpec
) -> dict[str, Any]:
    prompt_sets = corpus["prompt_sets"]
    lengths = {
        len(prompt_sets[assignment.prompt_set])
        for assignment in spec.assignments
    }
    if len(lengths) != 1:
        raise ValueError(f"{spec.name} assignments have unequal set lengths")
    prompts_per_principal = lengths.pop()
    repetitions = corpus["repetitions"][spec.name]
    entries: list[dict[str, Any]] = []
    wave = 0
    for repetition in range(repetitions):
        for prompt_index in range(prompts_per_principal):
            assignments = list(spec.assignments)
            if wave % 2:
                assignments.reverse()
            for assignment in assignments:
                prompt = prompt_sets[assignment.prompt_set][prompt_index]
                entries.append(
                    _entry_for(
                        assignment=assignment,
                        prompt=prompt,
                        defaults=corpus["request_defaults"],
                        ordinal=len(entries),
                        wave=wave,
                        repetition=repetition,
                        seed_scope=spec.seed_scope,
                    )
                )
            wave += 1
    if len(entries) > MAX_ENTRIES:
        raise ValueError(
            f"{spec.name} has {len(entries)} entries; maximum is "
            f"{MAX_ENTRIES}"
        )
    return {
        "corpus_id": corpus["corpus_id"],
        "corpus_sha256": corpus["frozen_sha256"],
        "entry_count": len(entries),
        "entries": entries,
        "generator_schema": GENERATOR_SCHEMA,
        "manifest_name": spec.name,
        "principal_roles": {
            assignment.principal: assignment.role
            for assignment in spec.assignments
        },
        "purpose": spec.purpose,
        "repetitions": repetitions,
        "schema": MANIFEST_SCHEMA,
        "seed_scope": spec.seed_scope,
        "source_prompt_sets": sorted(
            {assignment.prompt_set for assignment in spec.assignments}
        ),
        "stage": spec.stage,
        "wave_count": wave,
    }


def build_bundle(corpus: dict[str, Any]) -> dict[str, Any]:
    validate_corpus(corpus)
    manifests = {
        spec.file_name: _build_manifest(corpus, spec)
        for spec in MANIFEST_SPECS
    }
    descriptors = [
        {
            "canonical_sha256": canonical_sha256(
                manifests[spec.file_name]
            ),
            "entry_count": manifests[spec.file_name]["entry_count"],
            "file": spec.file_name,
            "manifest_name": spec.name,
            "wave_count": manifests[spec.file_name]["wave_count"],
        }
        for spec in MANIFEST_SPECS
    ]
    bundle_material = {
        "corpus_id": corpus["corpus_id"],
        "corpus_sha256": corpus["frozen_sha256"],
        "generator_schema": GENERATOR_SCHEMA,
        "manifests": descriptors,
    }
    index = {
        **bundle_material,
        "bundle_sha256": canonical_sha256(bundle_material),
        "schema": INDEX_SCHEMA,
    }
    return {"index": index, "manifests": manifests}


def _pretty_json(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _expected_files(bundle: dict[str, Any]) -> dict[str, str]:
    files = {
        name: _pretty_json(payload)
        for name, payload in bundle["manifests"].items()
    }
    files["manifest_index.json"] = _pretty_json(bundle["index"])
    return files


def write_bundle(bundle: dict[str, Any], output_dir: Path) -> None:
    expected = _expected_files(bundle)
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"output path is not a directory: {output_dir}")
    for name, content in expected.items():
        path = output_dir / name
        if path.exists() and path.read_text(encoding="utf-8") != content:
            raise FileExistsError(
                f"refusing to overwrite divergent manifest: {path}"
            )
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in expected.items():
        path = output_dir / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")


def check_bundle(bundle: dict[str, Any], output_dir: Path) -> None:
    expected = _expected_files(bundle)
    for name, content in expected.items():
        path = output_dir / name
        if not path.is_file():
            raise ValueError(f"missing generated file: {path}")
        if path.read_text(encoding="utf-8") != content:
            raise ValueError(f"generated file differs from frozen input: {path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--print-corpus-sha256", action="store_true")
    args = parser.parse_args()
    if args.print_corpus_sha256:
        if args.check or args.output_dir is not None:
            parser.error(
                "--print-corpus-sha256 cannot be combined with output options"
            )
    elif args.output_dir is None:
        parser.error("--output-dir is required unless printing the corpus hash")
    return args


def main() -> None:
    args = parse_args()
    corpus = read_json(args.corpus)
    if args.print_corpus_sha256:
        validate_corpus(corpus, verify_frozen_hash=False)
        print(corpus_content_sha256(corpus))
        return
    validate_corpus(corpus)
    bundle = build_bundle(corpus)
    if args.check:
        check_bundle(bundle, args.output_dir)
        action = "checked"
    else:
        write_bundle(bundle, args.output_dir)
        action = "generated"
    print(
        json.dumps(
            {
                "action": action,
                "bundle_sha256": bundle["index"]["bundle_sha256"],
                "corpus_sha256": corpus["frozen_sha256"],
                "output_dir": str(args.output_dir),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
