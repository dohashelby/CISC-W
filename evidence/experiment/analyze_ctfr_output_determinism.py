#!/usr/bin/env python
"""Diagnose exact-output instability in CTFR fresh-process controls."""

from __future__ import annotations

import argparse
import itertools
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from generate_ctfr_manifests import build_bundle, read_json

PHASE_MANIFESTS = {
    "baseline_evaluation": "baseline_evaluation.json",
    "evaluation": "shifted_evaluation.json",
}
IDENTICAL_POLICY_CONTROL_PAIRS = {
    "baseline_evaluation": None,
    "evaluation": (("frozen", "ctfr-shadow"),),
}


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value is not an object")
    return value


def arm_from_directory(path: Path) -> str:
    prefix = "gate_stage_d_"
    if not path.name.startswith(prefix):
        raise ValueError(f"unexpected gate directory: {path}")
    return path.name[len(prefix) :]


def token_sequence(record: dict[str, Any]) -> tuple[int, ...]:
    tokens = record.get("token_ids")
    if not isinstance(tokens, list) or any(
        isinstance(token, bool) or not isinstance(token, int)
        for token in tokens
    ):
        raise ValueError("successful record has invalid token_ids")
    return tuple(tokens)


def first_divergence(
    left: tuple[int, ...],
    right: tuple[int, ...],
) -> int | None:
    for index, (left_token, right_token) in enumerate(zip(left, right)):
        if left_token != right_token:
            return index
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def load_arm_records(
    root: Path,
    phase: str,
) -> dict[str, dict[int, dict[str, Any]]]:
    result: dict[str, dict[int, dict[str, Any]]] = {}
    for run_directory in sorted(root.glob("gate_stage_d_*")):
        path = run_directory / f"{phase}.json"
        if not path.is_file():
            continue
        arm = arm_from_directory(run_directory)
        artifact = load_object(path)
        records = artifact.get("records")
        if not isinstance(records, list):
            raise ValueError(f"{path}: records is not a list")
        by_ordinal: dict[int, dict[str, Any]] = {}
        for record in records:
            if not isinstance(record, dict) or record.get("ok") is not True:
                continue
            ordinal = record.get("ordinal")
            if (
                isinstance(ordinal, bool)
                or not isinstance(ordinal, int)
                or ordinal < 0
                or ordinal in by_ordinal
            ):
                raise ValueError(f"{path}: invalid or duplicate ordinal")
            token_sequence(record)
            by_ordinal[ordinal] = record
        result[arm] = by_ordinal
    if len(result) < 2:
        raise ValueError(f"{phase}: fewer than two gate arms are available")
    return result


def manifest_entries(manifest: dict[str, Any]) -> dict[int, dict[str, Any]]:
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("manifest entries are absent")
    result: dict[int, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("manifest entry is not an object")
        ordinal = entry.get("ordinal")
        if isinstance(ordinal, bool) or not isinstance(ordinal, int):
            raise ValueError("manifest ordinal is invalid")
        result[ordinal] = entry
    return result


def compare_pair(
    left: dict[int, dict[str, Any]],
    right: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    common = sorted(set(left) & set(right))
    equal = 0
    divergences: list[dict[str, int]] = []
    for ordinal in common:
        position = first_divergence(
            token_sequence(left[ordinal]),
            token_sequence(right[ordinal]),
        )
        if position is None:
            equal += 1
        elif len(divergences) < 16:
            divergences.append(
                {"ordinal": ordinal, "first_divergence_position": position}
            )
    return {
        "common_ordinals": len(common),
        "exact_equal": equal,
        "exact_equal_rate": equal / len(common) if common else None,
        "first_divergence_examples": divergences,
    }


def within_arm_variants(
    records: dict[int, dict[str, Any]],
    manifest: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    by_prompt: dict[str, set[tuple[int, ...]]] = defaultdict(set)
    by_exact_input: dict[tuple[str, int], set[tuple[int, ...]]] = defaultdict(
        set
    )
    for ordinal, record in records.items():
        entry = manifest.get(ordinal)
        if entry is None:
            continue
        prompt_id = entry.get("prompt_id")
        seed = entry.get("seed")
        if not isinstance(prompt_id, str) or not isinstance(seed, int):
            raise ValueError("manifest prompt identity is invalid")
        tokens = token_sequence(record)
        by_prompt[prompt_id].add(tokens)
        by_exact_input[(prompt_id, seed)].add(tokens)
    prompt_counts = {
        prompt_id: len(outputs)
        for prompt_id, outputs in sorted(by_prompt.items())
    }
    exact_counts = {
        f"{prompt_id}:{seed}": len(outputs)
        for (prompt_id, seed), outputs in sorted(by_exact_input.items())
    }
    return {
        "prompt_distinct_output_counts": prompt_counts,
        "prompts_with_multiple_outputs": sum(
            count > 1 for count in prompt_counts.values()
        ),
        "max_outputs_for_one_prompt": max(prompt_counts.values(), default=0),
        "identical_prompt_seed_groups_with_multiple_outputs": sum(
            count > 1 for count in exact_counts.values()
        ),
        "identical_prompt_seed_distinct_output_counts": exact_counts,
    }


def analyze_phase(
    root: Path,
    phase: str,
    manifest_payload: dict[str, Any],
) -> dict[str, Any]:
    arms = load_arm_records(root, phase)
    manifest = manifest_entries(manifest_payload)
    arm_names = sorted(arms)
    pairwise: dict[str, Any] = {}
    for left_name, right_name in itertools.combinations(arm_names, 2):
        key = f"{left_name}__{right_name}"
        pairwise[key] = compare_pair(arms[left_name], arms[right_name])

    common = sorted(set.intersection(*(set(arms[name]) for name in arm_names)))
    all_arm_equal = 0
    for ordinal in common:
        outputs = {
            token_sequence(arms[name][ordinal]) for name in arm_names
        }
        all_arm_equal += len(outputs) == 1

    configured_pairs = IDENTICAL_POLICY_CONTROL_PAIRS[phase]
    if configured_pairs is None:
        configured_pairs = tuple(itertools.combinations(arm_names, 2))
    control_results: dict[str, Any] = {}
    for left_name, right_name in configured_pairs:
        if left_name not in arms or right_name not in arms:
            continue
        key = f"{left_name}__{right_name}"
        control_results[key] = compare_pair(
            arms[left_name],
            arms[right_name],
        )

    return {
        "arms": {
            name: {
                "successful_records": len(records),
                "within_arm": within_arm_variants(records, manifest),
            }
            for name, records in arms.items()
        },
        "all_arm_common_ordinals": len(common),
        "all_arm_exact_equal": all_arm_equal,
        "all_arm_exact_equal_rate": (
            all_arm_equal / len(common) if common else None
        ),
        "pairwise": pairwise,
        "identical_policy_controls": control_results,
    }


def analyze(
    root: Path,
    manifests: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    phases = {
        phase: analyze_phase(root, phase, manifests[manifest_name])
        for phase, manifest_name in PHASE_MANIFESTS.items()
    }
    divergent_controls: list[str] = []
    for phase, result in phases.items():
        for pair, comparison in result["identical_policy_controls"].items():
            if comparison["exact_equal"] != comparison["common_ordinals"]:
                divergent_controls.append(f"{phase}:{pair}")
    frozen_exact_input_instability = 0
    for result in phases.values():
        frozen = result["arms"].get("frozen")
        if frozen is not None:
            frozen_exact_input_instability += frozen["within_arm"][
                "identical_prompt_seed_groups_with_multiple_outputs"
            ]
    nondeterminism = bool(
        divergent_controls or frozen_exact_input_instability
    )
    return {
        "schema": "ctfr-output-determinism-diagnostic-v1",
        "classification": (
            "execution_nondeterminism_detected"
            if nondeterminism
            else "exact_output_reproducible_in_observed_controls"
        ),
        "divergent_identical_policy_controls": divergent_controls,
        "frozen_identical_input_instability_groups": (
            frozen_exact_input_instability
        ),
        "phases": phases,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bundle = build_bundle(read_json(args.corpus))
    result = analyze(args.root, bundle["manifests"])
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
        summary = {
            "classification": result["classification"],
            "divergent_identical_policy_controls": result[
                "divergent_identical_policy_controls"
            ],
            "frozen_identical_input_instability_groups": result[
                "frozen_identical_input_instability_groups"
            ],
            "all_arm_exact_equal": {
                phase: {
                    "equal": value["all_arm_exact_equal"],
                    "common": value["all_arm_common_ordinals"],
                }
                for phase, value in result["phases"].items()
            },
            "output": str(args.output),
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
