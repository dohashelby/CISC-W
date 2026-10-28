#!/usr/bin/env python
"""Analyze the preregistered CTFR exact-output determinism gate."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RunSpec:
    name: str
    concurrency: int
    waves_per_batch: int
    execution_mode: str
    repetitions: int


RUN_SPECS = (
    RunSpec("graph_c32_a", 32, 16, "cuda-graph", 2),
    RunSpec("graph_c32_b", 32, 16, "cuda-graph", 1),
    RunSpec("graph_c2_a", 2, 1, "cuda-graph", 2),
    RunSpec("graph_c2_b", 2, 1, "cuda-graph", 1),
    RunSpec("eager_c2_a", 2, 1, "eager", 2),
    RunSpec("eager_c2_b", 2, 1, "eager", 1),
)

COMPARISONS = (
    (
        "same_process_graph_c32",
        ("graph_c32_a", 1),
        ("graph_c32_a", 2),
    ),
    (
        "fresh_process_graph_c32",
        ("graph_c32_a", 1),
        ("graph_c32_b", 1),
    ),
    (
        "same_process_graph_c2",
        ("graph_c2_a", 1),
        ("graph_c2_a", 2),
    ),
    (
        "fresh_process_graph_c2",
        ("graph_c2_a", 1),
        ("graph_c2_b", 1),
    ),
    (
        "same_process_eager_c2",
        ("eager_c2_a", 1),
        ("eager_c2_a", 2),
    ),
    (
        "fresh_process_eager_c2",
        ("eager_c2_a", 1),
        ("eager_c2_b", 1),
    ),
)


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level value is not an object")
    return value


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
    for position, (left_token, right_token) in enumerate(zip(left, right)):
        if left_token != right_token:
            return position
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def load_probe(
    path: Path,
    spec: RunSpec,
    expected_requests: int,
) -> dict[int, tuple[int, ...]]:
    artifact = load_object(path)
    config = artifact.get("config")
    summary = artifact.get("summary")
    records = artifact.get("records")
    if not isinstance(config, dict):
        raise ValueError(f"{path}: config is absent")
    if not isinstance(summary, dict) or summary.get("evidence_ok") is not True:
        raise ValueError(f"{path}: authenticated probe evidence is incomplete")
    expected_config = {
        "concurrency": spec.concurrency,
        "waves_per_batch": spec.waves_per_batch,
        "return_token_ids": True,
    }
    for field, expected in expected_config.items():
        if config.get(field) != expected:
            raise ValueError(
                f"{path}: {field}={config.get(field)!r}, expected {expected!r}"
            )
    if not isinstance(records, list) or len(records) != expected_requests:
        found = len(records) if isinstance(records, list) else "invalid"
        raise ValueError(
            f"{path}: expected {expected_requests} records, found {found}"
        )
    result: dict[int, tuple[int, ...]] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("ok") is not True:
            raise ValueError(f"{path}: failed or invalid record")
        ordinal = record.get("ordinal")
        if (
            isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal < 0
            or ordinal in result
        ):
            raise ValueError(f"{path}: invalid or duplicate ordinal")
        result[ordinal] = token_sequence(record)
    if set(result) != set(range(expected_requests)):
        raise ValueError(f"{path}: ordinal coverage is incomplete")
    return result


def compare_outputs(
    left: dict[int, tuple[int, ...]],
    right: dict[int, tuple[int, ...]],
) -> dict[str, Any]:
    if set(left) != set(right):
        raise ValueError("comparison operands have different ordinals")
    equal = 0
    examples: list[dict[str, int]] = []
    divergence_histogram: dict[int, int] = {}
    for ordinal in sorted(left):
        position = first_divergence(left[ordinal], right[ordinal])
        if position is None:
            equal += 1
            continue
        divergence_histogram[position] = (
            divergence_histogram.get(position, 0) + 1
        )
        if len(examples) < 16:
            examples.append(
                {
                    "ordinal": ordinal,
                    "first_divergence_position": position,
                }
            )
    total = len(left)
    return {
        "compared": total,
        "exact_equal": equal,
        "exact_equal_rate": equal / total if total else None,
        "all_exact": equal == total,
        "first_divergence_histogram": {
            str(position): count
            for position, count in sorted(divergence_histogram.items())
        },
        "first_divergence_examples": examples,
    }


def select_gate(comparisons: dict[str, dict[str, Any]]) -> tuple[str, str]:
    graph_c32 = (
        comparisons["same_process_graph_c32"]["all_exact"]
        and comparisons["fresh_process_graph_c32"]["all_exact"]
    )
    graph_c2 = (
        comparisons["same_process_graph_c2"]["all_exact"]
        and comparisons["fresh_process_graph_c2"]["all_exact"]
    )
    eager_c2 = (
        comparisons["same_process_eager_c2"]["all_exact"]
        and comparisons["fresh_process_eager_c2"]["all_exact"]
    )
    if graph_c32:
        return (
            "realistic_fresh_process_exact_replay_supported",
            "retain exact-token equality in the realistic concurrency-32 gate",
        )
    if graph_c2:
        return (
            "small_batch_graph_exact_replay_supported",
            "measure performance at realistic load, but evaluate exact-token "
            "equality in a separate concurrency-2 CUDA-graph replay",
        )
    if eager_c2:
        return (
            "eager_small_batch_exact_replay_supported",
            "measure performance at realistic load, but evaluate exact-token "
            "equality in a separate concurrency-2 eager replay",
        )
    return (
        "cross_process_exact_replay_not_supported",
        "do not attribute cross-process token hashes to CTFR; use "
        "teacher-forced common-support metrics and task-level noninferiority",
    )


def analyze(root: Path) -> dict[str, Any]:
    schedule = load_object(root / "DECLARED_SCHEDULE.json")
    if schedule.get("schema") != "ctfr-determinism-gate-v1":
        raise ValueError("unexpected or absent determinism-gate schedule")
    expected_requests = schedule.get("evaluation_requests")
    if (
        isinstance(expected_requests, bool)
        or not isinstance(expected_requests, int)
        or expected_requests < 1
    ):
        raise ValueError("schedule has an invalid evaluation request count")

    runs: dict[tuple[str, int], dict[int, tuple[int, ...]]] = {}
    manifest_hashes: set[str] = set()
    for spec in RUN_SPECS:
        condition = root / spec.name
        metadata = load_object(condition / "metadata.json")
        if metadata.get("execution_mode") != spec.execution_mode:
            raise ValueError(f"{condition}: execution mode does not match")
        if metadata.get("process_uuid") in (None, ""):
            raise ValueError(f"{condition}: process UUID is absent")
        for repetition in range(1, spec.repetitions + 1):
            path = condition / f"evaluation_{repetition:02d}.json"
            artifact = load_object(path)
            config = artifact.get("config")
            if not isinstance(config, dict):
                raise ValueError(f"{path}: config is absent")
            manifest_hash = config.get("manifest_sha256")
            if not isinstance(manifest_hash, str) or len(manifest_hash) != 64:
                raise ValueError(f"{path}: manifest hash is invalid")
            manifest_hashes.add(manifest_hash)
            runs[(spec.name, repetition)] = load_probe(
                path,
                spec,
                expected_requests,
            )
    if len(manifest_hashes) != 1:
        raise ValueError("probe runs did not use one frozen evaluation manifest")

    comparison_results = {
        name: compare_outputs(runs[left], runs[right])
        for name, left, right in COMPARISONS
    }
    classification, recommendation = select_gate(comparison_results)
    return {
        "schema": "ctfr-determinism-gate-assessment-v1",
        "classification": classification,
        "recommended_output_gate": recommendation,
        "evaluation_requests": expected_requests,
        "manifest_sha256": next(iter(manifest_hashes)),
        "comparisons": comparison_results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = analyze(args.root)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(encoded, end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded, encoding="utf-8")
    print(
        json.dumps(
            {
                "classification": result["classification"],
                "recommended_output_gate": result[
                    "recommended_output_gate"
                ],
                "output": str(args.output),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
