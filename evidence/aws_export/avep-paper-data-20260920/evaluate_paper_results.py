#!/usr/bin/env python
"""Apply the predeclared AVEP postflight decision rules."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
import tarfile
from datetime import datetime
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


METRICS = {
    "throughput": "aggregate_output_tokens_per_second",
    "latency_p50": "latency_ms_p50",
    "latency_p95": "latency_ms_p95",
}
TARGET_MODEL = "Qwen/Qwen3-4B"
TARGET_REVISION = "1cfa9a7208912126459214e8b04321603b3df60c"
TARGET_VLLM_SHA = "4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c"
TRUSTED_ARTIFACT_SHA256 = {
    "avep_paper_instrumentation.patch": (
        "4cbc2736357f47fd5305e125854d4eb2a681d0834599046888dada8bb4b78450"
    ),
    "paper_probe.py": (
        "3db98a3e0868f18aea097ee2f32856580f9243c4cf9c430922265c1d771a435f"
    ),
    "analyze_paper_trials.py": (
        "c3a14bced5fd27b3720719d68967cf2a164fc2e689749544364a37bca60ce160"
    ),
    "run_paper_trials.sh": (
        "dab299053044a5ca11f607997c708a86ca7aaadf4ee75977954df784e2cb807d"
    ),
    "paper_results/PREDECLARED_DECISION_RULES.md": (
        "72e8a9f3f76ff548d3fdc3ff881d254f9c65a7d03164b466126ea951de33b637"
    ),
}
BASE_URL = "http://127.0.0.1:8000/v1"
PROBE_SEED = 20260918
MAX_TOKENS = 32
SPECULATIVE_STEPS = 4
PHASE_PATTERN = re.compile(r"===== AVEP_PHASE (\S+)")
BUDGET_PATTERN = re.compile(r"AVEP_BUDGET\s+(\{.*\})")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
PHASES = (
    "warmup",
    "baseline",
    "intervention",
    *(f"post_{index:02d}" for index in range(1, 7)),
)
EXPECTED_REQUESTS = {
    "warmup": 1024,
    "baseline": 2048,
    "intervention": 1024,
    **{f"post_{index:02d}": 1024 for index in range(1, 7)},
}
RUN_PATTERN = re.compile(
    r"(?:pair_[0-9][0-9]_(?:attack|placebo)"
    r"|reset_[0-9][0-9]"
    r"|adaptive_off_[0-9][0-9]"
    r"|mechanism_(?:attack|placebo))"
)
EXPECTED_METADATA: dict[str, dict[str, Any]] = {
    **{
        f"pair_{pair_id}_{arm}": {
            "pair_id": pair_id,
            "arm": arm,
            "adaptive": True,
            "telemetry": False,
        }
        for pair_id in (f"{index:02d}" for index in range(1, 7))
        for arm in ("attack", "placebo")
    },
    **{
        f"reset_{index:02d}": {
            "pair_id": None,
            "arm": "reset",
            "adaptive": True,
            "telemetry": False,
        }
        for index in range(1, 4)
    },
    **{
        f"adaptive_off_{index:02d}": {
            "pair_id": None,
            "arm": "adaptive_off",
            "adaptive": False,
            "telemetry": False,
        }
        for index in range(1, 4)
    },
    "mechanism_attack": {
        "pair_id": None,
        "arm": "attack",
        "adaptive": True,
        "telemetry": True,
    },
    "mechanism_placebo": {
        "pair_id": None,
        "arm": "placebo",
        "adaptive": True,
        "telemetry": True,
    },
}


def finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def nonnegative_integer(value: Any) -> int | None:
    number = finite_number(value)
    if number is None or number < 0 or not number.is_integer():
        return None
    return int(number)


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value is not an object")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def all_finite_numbers(value: Any) -> bool:
    if isinstance(value, list):
        return all(all_finite_numbers(item) for item in value)
    return finite_number(value) is not None


def all_zero_numbers(value: Any) -> bool:
    if isinstance(value, list):
        return all(all_zero_numbers(item) for item in value)
    number = finite_number(value)
    return number is not None and math.isclose(number, 0.0, abs_tol=1e-7)


def structures_close(left: Any, right: Any) -> bool:
    left_number = finite_number(left)
    right_number = finite_number(right)
    if left_number is not None or right_number is not None:
        return (
            left_number is not None
            and right_number is not None
            and math.isclose(
                left_number,
                right_number,
                rel_tol=1e-7,
                abs_tol=1e-7,
            )
        )
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(
                structures_close(left_item, right_item)
                for left_item, right_item in zip(left, right, strict=True)
            )
        )
    if isinstance(left, dict) or isinstance(right, dict):
        return (
            isinstance(left, dict)
            and isinstance(right, dict)
            and set(left) == set(right)
            and all(structures_close(left[key], right[key]) for key in left)
        )
    return left == right


def bootstrap_mean_ci(
    values: list[float], *, samples: int = 20_000, seed: int = 20260918
) -> dict[str, float | int | None]:
    if not values:
        return {"n": 0, "mean": None, "ci95_low": None, "ci95_high": None}
    rng = random.Random(seed)
    means = []
    for _ in range(samples):
        draw = [values[rng.randrange(len(values))] for _ in values]
        means.append(statistics.fmean(draw))
    means.sort()
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "ci95_low": means[int(samples * 0.025)],
        "ci95_high": means[min(int(samples * 0.975), samples - 1)],
    }


def expected_phase_config(
    run_name: str,
    phase: str,
    poison_token_id: int | None,
) -> dict[str, Any]:
    metadata = EXPECTED_METADATA[run_name]
    intervention = phase == "intervention"
    constrained = intervention and metadata["arm"] != "placebo"
    return {
        "phase": phase,
        "principal": "attacker" if intervention else "victim",
        "model": TARGET_MODEL,
        "base_url": BASE_URL,
        "requests": EXPECTED_REQUESTS[phase],
        "concurrency": 64 if intervention else 32,
        "max_tokens": MAX_TOKENS,
        "allowed_token_id": poison_token_id if constrained else None,
        "seed": PROBE_SEED,
        "return_token_ids": metadata["telemetry"],
    }


def inspect_phase(
    path: Path,
    phase: str,
    expected_config: dict[str, Any],
) -> tuple[dict[str, float], list[str], dict[str, int] | None]:
    errors: list[str] = []
    values: dict[str, float] = {}
    timing: dict[str, int] | None = None
    try:
        payload = load_object(path)
        config = payload.get("config")
        if not isinstance(config, dict):
            raise ValueError("config is missing or is not an object")
        for field, expected_value in expected_config.items():
            actual = config.get(field)
            if actual != expected_value:
                errors.append(
                    f"config.{field} is {actual!r}, expected "
                    f"{expected_value!r}"
                )

        started_ns = nonnegative_integer(payload.get("started_ns"))
        finished_ns = nonnegative_integer(payload.get("finished_ns"))
        if started_ns is None or finished_ns is None:
            errors.append("top-level timestamps are not non-negative integers")
        elif finished_ns <= started_ns:
            errors.append("top-level finished_ns is not after started_ns")
        else:
            timing = {"started_ns": started_ns, "finished_ns": finished_ns}

        summary = payload.get("summary")
        if not isinstance(summary, dict):
            raise ValueError("summary is missing or is not an object")
        requests = nonnegative_integer(summary.get("requests"))
        successful = nonnegative_integer(summary.get("successful"))
        failed = nonnegative_integer(summary.get("failed"))
        if requests is None:
            errors.append("summary.requests is not a non-negative integer")
        elif requests != EXPECTED_REQUESTS[phase]:
            errors.append(
                f"summary.requests is {requests}, expected "
                f"{EXPECTED_REQUESTS[phase]}"
            )
        if successful is None:
            errors.append("summary.successful is not a non-negative integer")
        elif successful != EXPECTED_REQUESTS[phase]:
            errors.append(
                f"summary.successful is {successful}, expected "
                f"{EXPECTED_REQUESTS[phase]}"
            )
        if failed is None:
            errors.append("summary.failed is not a non-negative integer")
        elif failed != 0:
            errors.append(f"summary.failed is {failed}, expected zero")
        if requests is not None and failed is not None and failed > requests:
            errors.append("summary.failed exceeds summary.requests")

        completion_tokens = nonnegative_integer(
            summary.get("completion_tokens")
        )
        expected_tokens = EXPECTED_REQUESTS[phase] * MAX_TOKENS
        if completion_tokens != expected_tokens:
            errors.append(
                f"summary.completion_tokens is {completion_tokens}, expected "
                f"{expected_tokens}"
            )

        records = payload.get("records")
        if not isinstance(records, list):
            errors.append("records is not a list")
            records = []
        elif len(records) != EXPECTED_REQUESTS[phase]:
            errors.append(
                f"records has {len(records)} entries, expected "
                f"{EXPECTED_REQUESTS[phase]}"
            )

        bad_indices = 0
        non_objects = 0
        unsuccessful = 0
        bad_record_times = 0
        bad_completion_counts = 0
        bad_token_id_records = 0
        latencies: list[float] = []
        record_starts: list[int] = []
        record_finishes: list[int] = []
        expected_return_ids = expected_config["return_token_ids"]
        expected_allowed_id = expected_config["allowed_token_id"]
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                non_objects += 1
                continue
            if nonnegative_integer(record.get("index")) != index:
                bad_indices += 1
            if record.get("ok") is not True:
                unsuccessful += 1
            record_start = nonnegative_integer(record.get("started_ns"))
            record_finish = nonnegative_integer(record.get("finished_ns"))
            if (
                record_start is None
                or record_finish is None
                or record_finish <= record_start
            ):
                bad_record_times += 1
            else:
                record_starts.append(record_start)
                record_finishes.append(record_finish)
            latency = finite_number(record.get("latency_ms"))
            if latency is None or latency <= 0:
                bad_record_times += 1
            else:
                latencies.append(latency)
            usage = record.get("usage")
            record_tokens = (
                nonnegative_integer(usage.get("completion_tokens"))
                if isinstance(usage, dict)
                else None
            )
            if record_tokens != MAX_TOKENS:
                bad_completion_counts += 1
            token_ids = record.get("token_ids")
            token_ids_valid = isinstance(token_ids, list) and all(
                nonnegative_integer(token_id) is not None
                for token_id in token_ids
            )
            if expected_return_ids:
                if not token_ids_valid or len(token_ids) != MAX_TOKENS:
                    bad_token_id_records += 1
                elif expected_allowed_id is not None and any(
                    token_id != expected_allowed_id for token_id in token_ids
                ):
                    bad_token_id_records += 1
            elif token_ids not in (None, []):
                bad_token_id_records += 1
        for count, message in (
            (non_objects, "records are not objects"),
            (bad_indices, "records have non-canonical indices"),
            (unsuccessful, "records are not successful"),
            (bad_record_times, "records have invalid timing data"),
            (bad_completion_counts, "records have unexpected completion counts"),
            (bad_token_id_records, "records have invalid token-ID evidence"),
        ):
            if count:
                errors.append(f"{count} {message}")

        if timing is not None and record_starts and record_finishes:
            if min(record_starts) < timing["started_ns"]:
                errors.append("a record starts before the phase timestamp")
            if max(record_finishes) > timing["finished_ns"]:
                errors.append("a record finishes after the phase timestamp")

        if len(latencies) == EXPECTED_REQUESTS[phase]:
            for key, quantile in (
                ("latency_ms_p50", 0.50),
                ("latency_ms_p95", 0.95),
            ):
                observed = finite_number(summary.get(key))
                recomputed = percentile(latencies, quantile)
                if (
                    observed is None
                    or recomputed is None
                    or not math.isclose(
                        observed,
                        recomputed,
                        rel_tol=1e-12,
                        abs_tol=1e-9,
                    )
                ):
                    errors.append(f"summary.{key} does not match records")

        wall_seconds = finite_number(summary.get("wall_seconds"))
        aggregate = finite_number(
            summary.get("aggregate_output_tokens_per_second")
        )
        if wall_seconds is None or wall_seconds <= 0:
            errors.append("summary.wall_seconds is not finite and positive")
        elif completion_tokens is not None:
            if record_starts and record_finishes:
                raw_wall_seconds = (
                    max(record_finishes) - min(record_starts)
                ) / 1_000_000_000
                if not math.isclose(
                    wall_seconds,
                    raw_wall_seconds,
                    rel_tol=1e-12,
                    abs_tol=1e-9,
                ):
                    errors.append("summary.wall_seconds does not match records")
            recomputed_aggregate = completion_tokens / wall_seconds
            if aggregate is None or not math.isclose(
                aggregate,
                recomputed_aggregate,
                rel_tol=1e-12,
                abs_tol=1e-9,
            ):
                errors.append(
                    "summary aggregate throughput is internally inconsistent"
                )
        for metric, key in METRICS.items():
            value = finite_number(summary.get(key))
            if value is None or value <= 0:
                errors.append(f"summary.{key} is not finite and positive")
            else:
                values[metric] = value
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    return values, errors, timing


def estimator_result(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = load_object(path)
        results = payload.get("results")
        if not isinstance(results, list) or len(results) != 1:
            raise ValueError("results must contain exactly one worker state")
        state = results[0]
        if not isinstance(state, dict):
            raise ValueError("worker state is not an object")
        if not isinstance(state.get("available"), bool):
            raise ValueError("worker state lacks a boolean available field")
        return state, None
    except (OSError, ValueError, TypeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def available_state_errors(state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if state.get("available") is not True:
        return ["estimator state is unavailable"]
    for field in ("steps_since_refit", "refits"):
        if nonnegative_integer(state.get(field)) is None:
            errors.append(f"{field} is not a non-negative integer")
    slope = finite_number(state.get("slope"))
    intercepts = state.get("intercepts")
    if slope is None:
        errors.append("slope is not finite")
    if not isinstance(intercepts, list) or len(intercepts) != SPECULATIVE_STEPS:
        errors.append(
            f"intercepts does not contain {SPECULATIVE_STEPS} values"
        )
    elif not all_finite_numbers(intercepts):
        errors.append("intercepts contains a non-finite value")
    shapes = {
        "counts": (SPECULATIVE_STEPS,),
        "info": (SPECULATIVE_STEPS, 3),
        "grad": (SPECULATIVE_STEPS, 2),
    }
    for field, shape in shapes.items():
        value = state.get(field)
        shape_valid = isinstance(value, list) and len(value) == shape[0]
        if shape_valid and len(shape) == 2:
            shape_valid = all(
                isinstance(row, list) and len(row) == shape[1] for row in value
            )
        if not shape_valid or not all_finite_numbers(value):
            errors.append(
                f"{field} is missing, non-finite, or has the wrong shape"
            )
    return errors


def clean_state_errors(state: dict[str, Any]) -> list[str]:
    errors = available_state_errors(state)
    if errors:
        return errors
    slope = finite_number(state.get("slope"))
    intercepts = state["intercepts"]
    if slope is None or not math.isclose(slope, 0.5, abs_tol=1e-6):
        errors.append("clean-state slope is not 0.5")
    if any(
        not math.isclose(float(value), -0.2, abs_tol=1e-6)
        for value in intercepts
    ):
        errors.append("clean-state intercepts are not all -0.2")
    if state.get("steps_since_refit") != 0 or state.get("refits") != 0:
        errors.append("clean-state refit counters are not zero")
    for field in ("counts", "info", "grad"):
        if not all_zero_numbers(state.get(field)):
            errors.append(f"clean-state {field} is not all zero")
    return errors


def estimator_vector(path: Path) -> tuple[list[float] | None, str | None]:
    state, state_error = estimator_result(path)
    if state_error is not None:
        return None, state_error
    assert state is not None
    try:
        state_errors = available_state_errors(state)
        if state_errors:
            raise ValueError("; ".join(state_errors))
        slope = finite_number(state.get("slope"))
        intercepts = state.get("intercepts")
        assert slope is not None
        assert isinstance(intercepts, list)
        vector = [slope]
        for index, value in enumerate(intercepts):
            number = finite_number(value)
            if number is None:
                raise ValueError(f"intercepts[{index}] is not finite")
            vector.append(number)
        return vector, None
    except (OSError, ValueError, TypeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def inspect_reset_state(
    run_dir: Path,
    initial_state: dict[str, Any] | None,
    intervention_state: dict[str, Any] | None,
    reset_state: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    try:
        payload = load_object(run_dir / "estimator_reset.json")
        results = payload.get("results")
        if not isinstance(results, list) or len(results) != 1:
            raise ValueError("results must contain exactly one worker response")
        response = results[0]
        if not isinstance(response, dict) or response.get("available") is not True:
            raise ValueError("reset response is unavailable")
        reset = response.get("reset")
        if not isinstance(reset, dict):
            raise ValueError("reset response lacks the reset object")
        before = reset.get("before")
        after = reset.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ValueError("reset response lacks before/after states")
        errors.extend(
            f"reset.before: {error}" for error in available_state_errors(before)
        )
        errors.extend(
            f"reset.after: {error}" for error in clean_state_errors(after)
        )
        if intervention_state is None or not structures_close(
            before, intervention_state
        ):
            errors.append("reset.before does not match state_intervention.json")
        if reset_state is None or not structures_close(after, reset_state):
            errors.append("reset.after does not match state_reset.json")
        if initial_state is None or not structures_close(after, initial_state):
            errors.append("reset.after does not match state_initial.json")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"estimator_reset.json: {type(exc).__name__}: {exc}")
    return errors


def inspect_run(run_dir: Path) -> dict[str, Any]:
    errors: list[str] = []
    metadata: dict[str, Any] = {}
    try:
        metadata = load_object(run_dir / "metadata.json")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"metadata.json: {type(exc).__name__}: {exc}")

    expected = EXPECTED_METADATA.get(run_dir.name)
    mismatches: dict[str, dict[str, Any]] = {}
    if expected is not None:
        if metadata.get("run_name") != run_dir.name:
            mismatches["run_name"] = {
                "expected": run_dir.name,
                "actual": metadata.get("run_name"),
            }
            errors.append(
                f"metadata.run_name is {metadata.get('run_name')!r}, "
                f"expected {run_dir.name!r}"
            )
        for field, expected_value in expected.items():
            actual = metadata.get(field)
            if actual != expected_value:
                mismatches[field] = {
                    "expected": expected_value,
                    "actual": actual,
                }
                errors.append(
                    f"metadata.{field} is {actual!r}, expected "
                    f"{expected_value!r}"
                )
    token_id = metadata.get("poison_token_id")
    validated_token_id = nonnegative_integer(token_id)
    if validated_token_id is None:
        errors.append("metadata.poison_token_id is not a non-negative integer")
    if not (run_dir / "COMPLETE").is_file():
        errors.append("COMPLETE marker is absent")
    expected_post_files = {
        f"post_{index:02d}{suffix}.json"
        for index in range(1, 7)
        for suffix in ("", ".summary")
    } | {f"state_post_{index:02d}.json" for index in range(1, 7)}
    try:
        unexpected_post_files = sorted(
            path.name
            for path in run_dir.iterdir()
            if path.is_file()
            and (
                re.fullmatch(r"post_[0-9]+(?:\.summary)?\.json", path.name)
                or re.fullmatch(r"state_post_[0-9]+\.json", path.name)
            )
            and path.name not in expected_post_files
        )
    except OSError as exc:
        unexpected_post_files = []
        errors.append(f"run inventory: {type(exc).__name__}: {exc}")
    if unexpected_post_files:
        errors.append(
            "unexpected post-window artifacts: "
            + ", ".join(unexpected_post_files)
        )

    phases: dict[str, dict[str, float]] = {}
    phase_errors: dict[str, list[str]] = {}
    phase_timings: dict[str, dict[str, int]] = {}
    for phase in PHASES:
        path = run_dir / f"{phase}.json"
        if not path.is_file():
            phase_errors[phase] = ["artifact is absent"]
            errors.append(f"{phase}.json is absent")
            continue
        phase_config = (
            expected_phase_config(run_dir.name, phase, validated_token_id)
            if expected is not None
            else {}
        )
        values, current_errors, timing = inspect_phase(
            path,
            phase,
            phase_config,
        )
        summary_path = run_dir / f"{phase}.summary.json"
        try:
            embedded_summary = load_object(path).get("summary")
            printed_summary = load_object(summary_path)
            if not isinstance(embedded_summary, dict) or not structures_close(
                embedded_summary, printed_summary
            ):
                current_errors.append(
                    "standalone summary does not match embedded summary"
                )
        except (OSError, ValueError, TypeError) as exc:
            current_errors.append(
                f"standalone summary: {type(exc).__name__}: {exc}"
            )
        phases[phase] = values
        if timing is not None:
            phase_timings[phase] = timing
        if current_errors:
            phase_errors[phase] = current_errors
            errors.extend(f"{phase}.json: {error}" for error in current_errors)

    for left_name, right_name in zip(PHASES[:-1], PHASES[1:], strict=True):
        left = phase_timings.get(left_name)
        right = phase_timings.get(right_name)
        if (
            left is not None
            and right is not None
            and left["finished_ns"] > right["started_ns"]
        ):
            errors.append(f"{left_name} overlaps or follows {right_name}")

    vectors: dict[str, list[float] | None] = {}
    requires_estimator = bool(expected and expected["adaptive"])
    for state_name in ("baseline", "intervention"):
        vector, state_error = estimator_vector(
            run_dir / f"state_{state_name}.json"
        )
        vectors[state_name] = vector
        if state_error is not None and requires_estimator:
            errors.append(f"state_{state_name}.json: {state_error}")
    before = vectors["baseline"]
    after = vectors["intervention"]

    state_names = [
        "initial",
        "warmup",
        "baseline",
        "intervention",
        *(f"post_{index:02d}" for index in range(1, 7)),
    ]
    if expected and expected["arm"] == "reset":
        state_names.append("reset")
    states: dict[str, dict[str, Any] | None] = {}
    for state_name in state_names:
        state, state_error = estimator_result(
            run_dir / f"state_{state_name}.json"
        )
        states[state_name] = state
        if state_error is not None:
            errors.append(f"state_{state_name}.json: {state_error}")
            continue
        assert state is not None
        if requires_estimator:
            errors.extend(
                f"state_{state_name}.json: {error}"
                for error in available_state_errors(state)
            )
        elif state.get("available") is not False:
            errors.append(
                f"state_{state_name}.json: adaptive-off run exposes an "
                "active estimator"
            )
        elif state != {
            "available": False,
            "reason": "No online acceptance estimator is active",
        }:
            errors.append(
                f"state_{state_name}.json: unexpected adaptive-off state schema"
            )
    if requires_estimator and states.get("initial") is not None:
        errors.extend(
            f"state_initial.json: {error}"
            for error in clean_state_errors(states["initial"])
        )
    if expected and expected["arm"] == "reset":
        reset_state = states.get("reset")
        if reset_state is not None:
            errors.extend(
                f"state_reset.json: {error}"
                for error in clean_state_errors(reset_state)
            )
        errors.extend(
            inspect_reset_state(
                run_dir,
                states.get("initial"),
                states.get("intervention"),
                reset_state,
            )
        )
    elif (run_dir / "estimator_reset.json").exists() or (
        run_dir / "state_reset.json"
    ).exists():
        errors.append("non-reset run contains reset-only artifacts")
    if expected and not expected["telemetry"]:
        try:
            server_log = (run_dir / "server.log").read_text(errors="replace")
            if "AVEP_BUDGET " in server_log or "AVEP_ESTIMATOR " in server_log:
                errors.append("steady-state telemetry appears in a performance run")
        except OSError as exc:
            errors.append(f"server.log: {type(exc).__name__}: {exc}")

    movement: dict[str, Any] | None = None
    if before is not None and after is not None:
        if len(before) != len(after):
            errors.append("estimator coefficient-vector lengths differ")
        else:
            delta = [right - left for left, right in zip(before, after)]
            movement = {
                "baseline": before,
                "intervention": after,
                "delta": delta,
                "l2_norm": math.sqrt(sum(value * value for value in delta)),
            }

    ratios: dict[str, float] = {}
    baseline = phases.get("baseline", {})
    for metric in METRICS:
        denominator = baseline.get(metric)
        posts = [
            phases.get(f"post_{index:02d}", {}).get(metric)
            for index in range(1, 7)
        ]
        if denominator is None or any(value is None for value in posts):
            continue
        ratios[metric] = statistics.fmean(
            float(value) / denominator for value in posts if value is not None
        )
    return {
        "run": run_dir.name,
        "metadata": metadata,
        "metadata_mismatches": mismatches,
        "phase_errors": phase_errors,
        "phase_timings": phase_timings,
        "post_mean_ratios": ratios,
        "estimator_movement": movement,
        "errors": errors,
    }


def raw_paired_effects(
    runs: dict[str, dict[str, Any]], errors: list[str]
) -> dict[str, Any]:
    pairs = []
    effects = {metric: [] for metric in METRICS}
    for pair_id in (f"{index:02d}" for index in range(1, 7)):
        attack = runs.get(f"pair_{pair_id}_attack")
        placebo = runs.get(f"pair_{pair_id}_placebo")
        row: dict[str, Any] = {"pair_id": pair_id, "metrics": {}}
        if attack is None or placebo is None:
            errors.append(f"pair {pair_id} is incomplete")
            pairs.append(row)
            continue
        for metric in METRICS:
            attack_ratio = attack["post_mean_ratios"].get(metric)
            placebo_ratio = placebo["post_mean_ratios"].get(metric)
            effect = None
            if attack_ratio is None or placebo_ratio is None:
                errors.append(f"pair {pair_id} lacks the {metric} ratio")
            else:
                effect = attack_ratio - placebo_ratio
                effects[metric].append(effect)
            row["metrics"][metric] = {
                "attack_ratio": attack_ratio,
                "placebo_ratio": placebo_ratio,
                "attack_minus_placebo": effect,
            }
        pairs.append(row)
    return {
        "pair_count": sum(
            all(
                row["metrics"].get(metric, {}).get(
                    "attack_minus_placebo"
                )
                is not None
                for metric in METRICS
            )
            for row in pairs
        ),
        "pairs": pairs,
        "summary": {
            metric: bootstrap_mean_ci(values)
            for metric, values in effects.items()
        },
    }


def estimator_analysis(
    runs: dict[str, dict[str, Any]], errors: list[str]
) -> dict[str, Any]:
    paired = []
    attack_values = []
    placebo_values = []
    all_movements: dict[str, Any] = {}
    for name in sorted(EXPECTED_METADATA):
        run = runs.get(name)
        movement = run.get("estimator_movement") if run else None
        all_movements[name] = movement
    for pair_id in (f"{index:02d}" for index in range(1, 7)):
        attack = all_movements.get(f"pair_{pair_id}_attack")
        placebo = all_movements.get(f"pair_{pair_id}_placebo")
        attack_norm = attack.get("l2_norm") if attack else None
        placebo_norm = placebo.get("l2_norm") if placebo else None
        difference = None
        if attack_norm is None or placebo_norm is None:
            errors.append(f"pair {pair_id} lacks estimator movement")
        else:
            difference = attack_norm - placebo_norm
            attack_values.append(attack_norm)
            placebo_values.append(placebo_norm)
        paired.append(
            {
                "pair_id": pair_id,
                "attack_l2_norm": attack_norm,
                "placebo_l2_norm": placebo_norm,
                "attack_minus_placebo": difference,
            }
        )
    attack_mean = (
        statistics.fmean(attack_values) if len(attack_values) == 6 else None
    )
    placebo_mean = (
        statistics.fmean(placebo_values) if len(placebo_values) == 6 else None
    )
    stronger = (
        attack_mean is not None
        and placebo_mean is not None
        and attack_mean > placebo_mean
    )
    return {
        "movement_definition": (
            "Euclidean norm of [slope, *intercepts] intervention-minus-baseline"
        ),
        "runs": all_movements,
        "paired": paired,
        "attack_mean_l2_norm": attack_mean,
        "placebo_mean_l2_norm": placebo_mean,
        "stronger_after_attack": stronger,
    }


def arm_mean(
    runs: dict[str, dict[str, Any]], names: list[str], metric: str
) -> float | None:
    values = [
        runs[name]["post_mean_ratios"].get(metric)
        for name in names
        if name in runs
    ]
    if len(values) != len(names) or any(value is None for value in values):
        return None
    return statistics.fmean(float(value) for value in values if value is not None)


def attenuation(
    placebo: float | None,
    attack: float | None,
    control: float | None,
    *,
    adverse_high: bool,
) -> dict[str, Any]:
    if placebo is None or attack is None or control is None:
        return {
            "harm": None,
            "residual_harm": None,
            "attenuation": None,
            "expected_direction": False,
            "passes_50_percent_rule": False,
        }
    if adverse_high:
        harm = attack - placebo
        residual = max(0.0, control - placebo)
        expected_direction = control < attack
    else:
        harm = placebo - attack
        residual = max(0.0, placebo - control)
        expected_direction = control > attack
    value = 1.0 - residual / harm if harm > 0 else None
    passes = value is not None and value >= 0.5 and expected_direction
    return {
        "harm": harm,
        "residual_harm": residual if harm > 0 else None,
        "attenuation": value,
        "expected_direction": expected_direction,
        "passes_50_percent_rule": passes,
    }


def control_analysis(
    runs: dict[str, dict[str, Any]], errors: list[str]
) -> dict[str, Any]:
    attack_names = [f"pair_{index:02d}_attack" for index in range(1, 7)]
    placebo_names = [f"pair_{index:02d}_placebo" for index in range(1, 7)]
    control_names = {
        "reset": [f"reset_{index:02d}" for index in range(1, 4)],
        "adaptive_off": [
            f"adaptive_off_{index:02d}" for index in range(1, 4)
        ],
    }
    result: dict[str, Any] = {
        "adaptive_off_interpretation": (
            "Descriptive ablation only; no matched adaptive-off placebo arm "
            "exists, so this is not a factorial interaction estimate."
        ),
        "metrics": {},
    }
    for metric in METRICS:
        placebo = arm_mean(runs, placebo_names, metric)
        attack = arm_mean(runs, attack_names, metric)
        if placebo is None or attack is None:
            errors.append(f"control analysis lacks {metric} attack/placebo data")
        controls: dict[str, Any] = {}
        for arm, names in control_names.items():
            control = arm_mean(runs, names, metric)
            if control is None:
                errors.append(f"control analysis lacks {metric} {arm} data")
            controls[arm] = {
                "mean_ratio": control,
                **attenuation(
                    placebo,
                    attack,
                    control,
                    adverse_high=metric != "throughput",
                ),
            }
        result["metrics"][metric] = {
            "placebo_mean_ratio": placebo,
            "attack_mean_ratio": attack,
            "controls": controls,
        }
    result["all_controls_pass"] = all(
        control["passes_50_percent_rule"]
        for metric in result["metrics"].values()
        for control in metric["controls"].values()
    )
    return result


def assessment_run_map(
    assessment: dict[str, Any], errors: list[str]
) -> dict[str, dict[str, Any]]:
    rows = assessment.get("runs")
    if not isinstance(rows, list):
        errors.append("assessment.runs is not a list")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("run"), str):
            errors.append(f"assessment.runs[{index}] is not a named object")
            continue
        name = row["run"]
        if name in result:
            errors.append(f"assessment contains duplicate run {name}")
        result[name] = row
    return result


def validate_assessment(
    assessment: dict[str, Any], errors: list[str]
) -> dict[str, dict[str, Any]]:
    checks = {
        "run_count_is_20": assessment.get("run_count") == 20,
        "discovered_run_count_is_20": (
            assessment.get("discovered_run_count") == 20
        ),
        "excluded_run_count_is_zero": assessment.get("excluded_run_count") == 0,
        "cohort_validation_is_valid": (
            isinstance(assessment.get("cohort_validation"), dict)
            and assessment["cohort_validation"].get("valid") is True
        ),
        "complete_pair_count_is_six": (
            isinstance(assessment.get("paired_analysis"), dict)
            and assessment["paired_analysis"].get("complete_pairs") == 6
        ),
    }
    for name, passed in checks.items():
        if not passed:
            errors.append(f"assessment check failed: {name}")
    paired = assessment.get("paired_analysis")
    paired_metrics = (
        paired.get("attack_minus_placebo")
        if isinstance(paired, dict)
        else None
    )
    if not isinstance(paired_metrics, dict):
        errors.append("assessment paired metric summaries are absent")
    else:
        for metric in METRICS:
            summary = paired_metrics.get(metric)
            if not isinstance(summary, dict) or summary.get("n") != 6:
                errors.append(
                    f"assessment paired {metric} summary does not have n=6"
                )
                continue
            for field in ("mean", "ci95_low", "ci95_high"):
                if finite_number(summary.get(field)) is None:
                    errors.append(
                        f"assessment paired {metric}.{field} is non-finite"
                    )
    rows = assessment_run_map(assessment, errors)
    if set(rows) != set(EXPECTED_METADATA):
        errors.append("assessment run-name set is not the exact planned cohort")
    for name in sorted(set(rows) & set(EXPECTED_METADATA)):
        row = rows[name]
        if row.get("eligible_for_analysis") is not True:
            errors.append(f"assessment marks {name} ineligible")
        if row.get("status") != "complete":
            errors.append(f"assessment status for {name} is not complete")
        if row.get("failed_requests") != 0:
            errors.append(f"assessment reports request failures for {name}")
        if row.get("post_windows") != 6:
            errors.append(f"assessment does not report six post windows for {name}")
    return rows


def validate_selected_token(
    result_root: Path,
    observed_token_ids: set[Any],
    errors: list[str],
) -> dict[str, Any]:
    preflight = result_root / "token_preflight"
    selected: int | None = None
    if not (preflight / "COMPLETE").is_file():
        errors.append("token preflight COMPLETE marker is absent")
    try:
        raw = (preflight / "selected_token_id.txt").read_text().strip()
        if not re.fullmatch(r"[0-9]+", raw):
            raise ValueError("selected token is not a non-negative integer")
        selected = int(raw)
    except (OSError, ValueError) as exc:
        errors.append(f"selected token: {type(exc).__name__}: {exc}")

    ordinary_path = result_root.parent / "ordinary_tokens.json"
    ordinary_match = False
    ordinary_model_valid = False
    preflight_acceptance: dict[int, float] = {}
    try:
        ordinary = load_object(ordinary_path)
        ordinary_model_valid = (
            ordinary.get("model") == TARGET_MODEL
            and ordinary.get("revision") == TARGET_REVISION
        )
        if not ordinary_model_valid:
            errors.append("ordinary-token artifact model or revision differs")
        special_ids = ordinary.get("special_token_ids")
        candidates = ordinary.get("ordinary_single_tokens")
        if not isinstance(special_ids, list) or not isinstance(candidates, list):
            raise ValueError("ordinary-token candidate lists are malformed")
        ordinary_match = selected is not None and any(
            isinstance(candidate, dict)
            and candidate.get("token_id") == selected
            for candidate in candidates
        )
        if not ordinary_match:
            errors.append("selected token is not an ordinary-token candidate")
        if selected is not None and selected in special_ids:
            errors.append("selected token is listed as a special token")
        candidate_ids = [
            candidate.get("token_id")
            for candidate in candidates[:6]
            if isinstance(candidate, dict)
            and nonnegative_integer(candidate.get("token_id")) is not None
        ]
        if len(candidate_ids) != 6:
            errors.append("token preflight does not have six valid candidates")
        for candidate_id in candidate_ids:
            candidate_path = preflight / f"token_{candidate_id}.json"
            candidate_payload = load_object(candidate_path)
            candidate_config = candidate_payload.get("config")
            candidate_summary = candidate_payload.get("summary")
            if (
                not isinstance(candidate_config, dict)
                or candidate_config.get("allowed_token_id") != candidate_id
                or not isinstance(candidate_summary, dict)
            ):
                raise ValueError(
                    f"candidate {candidate_id} artifact is malformed"
                )
            drafted = nonnegative_integer(candidate_summary.get("draft_tokens"))
            acceptance = finite_number(
                candidate_summary.get("draft_acceptance_rate")
            )
            if (
                drafted is None
                or drafted <= 0
                or acceptance is None
                or acceptance < 0
                or acceptance > 1
            ):
                raise ValueError(
                    f"candidate {candidate_id} has invalid speculative metrics"
                )
            preflight_acceptance[candidate_id] = acceptance
        if (
            selected is not None
            and preflight_acceptance
            and preflight_acceptance.get(selected)
            != min(preflight_acceptance.values())
        ):
            errors.append("selected token is not the minimum-acceptance candidate")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"ordinary token artifact: {type(exc).__name__}: {exc}")

    cohort_match = selected is not None and observed_token_ids == {selected}
    if not cohort_match:
        errors.append("cohort poison token does not match token preflight")
    return {
        "selected_token_id": selected,
        "cohort_match": cohort_match,
        "ordinary_candidate_match": ordinary_match,
        "ordinary_model_revision_match": ordinary_model_valid,
        "candidate_acceptance_rates": dict(sorted(preflight_acceptance.items())),
    }


def validate_environments(
    result_root: Path,
    errors: list[str],
) -> dict[str, Any]:
    manifest_path = result_root.parent / "manifest.txt"
    manifest_bytes: bytes | None = None
    manifest_sha: str | None = None
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest_sha = bytes_sha256(manifest_bytes)
        manifest_text = manifest_bytes.decode()
        if f"vllm_sha={TARGET_VLLM_SHA}\n" not in manifest_text:
            errors.append("manifest does not contain the pinned vLLM SHA")
    except (OSError, UnicodeError) as exc:
        errors.append(f"manifest: {type(exc).__name__}: {exc}")

    mismatched: list[str] = []
    hashes: dict[str, str | None] = {}
    for run_name in sorted(EXPECTED_METADATA):
        path = result_root / run_name / "environment.txt"
        try:
            value = path.read_bytes()
            hashes[run_name] = bytes_sha256(value)
            if manifest_bytes is None or value != manifest_bytes:
                mismatched.append(run_name)
        except OSError as exc:
            hashes[run_name] = None
            mismatched.append(run_name)
            errors.append(
                f"{run_name}/environment.txt: {type(exc).__name__}: {exc}"
            )
    if mismatched:
        errors.append(
            "run environment snapshots differ from manifest: "
            + ", ".join(sorted(set(mismatched)))
        )
    return {
        "manifest_sha256": manifest_sha,
        "run_environment_sha256": hashes,
        "all_match": not mismatched and manifest_bytes is not None,
    }


def exact_token_match_raw(
    baseline_path: Path,
    post_path: Path,
) -> dict[str, Any]:
    expected = EXPECTED_REQUESTS["post_01"]
    errors: list[str] = []
    matches = 0
    comparable = 0
    try:
        baseline_records = load_object(baseline_path).get("records")
        post_records = load_object(post_path).get("records")
        if not isinstance(baseline_records, list) or not isinstance(
            post_records, list
        ):
            raise ValueError("records are missing")
        if len(baseline_records) != EXPECTED_REQUESTS["baseline"]:
            errors.append("baseline record count is not 2048")
        if len(post_records) != expected:
            errors.append("post-1 record count is not 1024")
        for index in range(min(expected, len(baseline_records), len(post_records))):
            left = baseline_records[index]
            right = post_records[index]
            if not isinstance(left, dict) or not isinstance(right, dict):
                continue
            left_ids = left.get("token_ids")
            right_ids = right.get("token_ids")
            if (
                not isinstance(left_ids, list)
                or not isinstance(right_ids, list)
                or len(left_ids) != MAX_TOKENS
                or len(right_ids) != MAX_TOKENS
            ):
                continue
            comparable += 1
            matches += left_ids == right_ids
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    rate = matches / comparable if comparable else None
    passes = comparable == expected and matches == expected and not errors
    return {
        "expected": expected,
        "comparable": comparable,
        "matches": matches,
        "match_rate": rate,
        "passes": passes,
        "errors": errors,
    }


def raw_budget_trace(path: Path) -> dict[str, Any]:
    errors: list[str] = []
    events: list[dict[str, Any]] = []
    phase_events: dict[str, list[dict[str, Any]]] = {
        phase: [] for phase in PHASES
    }
    begins = {phase: 0 for phase in PHASES}
    ends = {phase: 0 for phase in PHASES}
    active_phase: str | None = None
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as exc:
        return {
            "valid": False,
            "errors": [f"{type(exc).__name__}: {exc}"],
            "phases": {},
        }
    for line_number, line in enumerate(lines, start=1):
        phase_match = PHASE_PATTERN.search(line)
        if phase_match:
            marker = phase_match.group(1)
            if marker.endswith("_begin"):
                phase = marker.removesuffix("_begin")
                if phase in phase_events:
                    if active_phase is not None:
                        errors.append(
                            f"line {line_number}: phase begins while another is active"
                        )
                    active_phase = phase
                    begins[phase] += 1
            elif marker.endswith("_end"):
                phase = marker.removesuffix("_end")
                if phase in phase_events:
                    if active_phase != phase:
                        errors.append(
                            f"line {line_number}: phase end does not match begin"
                        )
                    ends[phase] += 1
                    active_phase = None
            else:
                active_phase = None
            continue
        budget_match = BUDGET_PATTERN.search(line)
        if not budget_match:
            continue
        try:
            row = json.loads(budget_match.group(1))
            if not isinstance(row, dict):
                raise ValueError("budget payload is not an object")
            step = nonnegative_integer(row.get("step"))
            maximum = nonnegative_integer(row.get("max_draft_budget"))
            budget = nonnegative_integer(row.get("draft_budget"))
            scheduled = nonnegative_integer(row.get("scheduled_drafts"))
            if step is None or step < 1:
                raise ValueError("step is not a positive integer")
            if maximum is None or budget is None or scheduled is None:
                raise ValueError("budget fields are not non-negative integers")
            if budget > maximum or maximum > scheduled:
                raise ValueError("draft budget bounds are inconsistent")
            event = {
                "step": step,
                "max_draft_budget": maximum,
                "draft_budget": budget,
                "scheduled_drafts": scheduled,
                "phase": active_phase,
            }
            events.append(event)
            if active_phase is not None:
                phase_events[active_phase].append(event)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            errors.append(
                f"line {line_number}: {type(exc).__name__}: {exc}"
            )

    steps = [event["step"] for event in events]
    if not steps:
        errors.append("no AVEP_BUDGET telemetry events were found")
    elif steps != list(range(1, len(steps) + 1)):
        errors.append("AVEP_BUDGET step sequence is not contiguous from one")

    summaries: dict[str, Any] = {}
    for phase in PHASES:
        if begins[phase] != 1 or ends[phase] != 1:
            errors.append(
                f"{phase} does not have exactly one begin/end marker"
            )
        usable = [
            event
            for event in phase_events[phase]
            if event["max_draft_budget"] > 0
        ]
        if not usable:
            errors.append(f"{phase} has no usable budget observations")
            mean_ratio = None
            weighted_ratio = None
        else:
            mean_ratio = statistics.fmean(
                event["draft_budget"] / event["max_draft_budget"]
                for event in usable
            )
            weighted_ratio = sum(
                event["draft_budget"] for event in usable
            ) / sum(event["max_draft_budget"] for event in usable)
        summaries[phase] = {
            "event_count": len(phase_events[phase]),
            "usable_event_count": len(usable),
            "mean_of_ratios": mean_ratio,
            "weighted_ratio": weighted_ratio,
        }
    return {
        "valid": not errors,
        "errors": errors,
        "total_event_count": len(events),
        "first_step": steps[0] if steps else None,
        "last_step": steps[-1] if steps else None,
        "phases": summaries,
    }


def mechanism_analysis(
    result_root: Path,
    assessment_rows: dict[str, dict[str, Any]],
    errors: list[str],
) -> dict[str, Any]:
    runs: dict[str, Any] = {}
    for arm in ("attack", "placebo"):
        name = f"mechanism_{arm}"
        run_dir = result_root / name
        row = assessment_rows.get(name, {})
        analyzer_fields: dict[str, float | None] = {}
        for field in (
            "baseline_budget_ratio",
            "intervention_budget_ratio",
            "post1_budget_ratio",
            "baseline_post1_exact_token_match",
        ):
            value = finite_number(row.get(field))
            analyzer_fields[field] = value
            if value is None:
                errors.append(f"assessment {name}.{field} is missing or non-finite")
            elif value < 0 or value > 1:
                errors.append(f"assessment {name}.{field} is outside [0, 1]")

        trace = raw_budget_trace(run_dir / "server.log")
        errors.extend(f"{name} telemetry: {error}" for error in trace["errors"])
        raw_mean = {
            phase: trace.get("phases", {}).get(phase, {}).get("mean_of_ratios")
            for phase in ("baseline", "intervention", "post_01")
        }
        raw_weighted = {
            phase: trace.get("phases", {}).get(phase, {}).get("weighted_ratio")
            for phase in ("baseline", "intervention", "post_01")
        }
        analyzer_mapping = {
            "baseline": "baseline_budget_ratio",
            "intervention": "intervention_budget_ratio",
            "post_01": "post1_budget_ratio",
        }
        for phase, analyzer_field in analyzer_mapping.items():
            raw_value = finite_number(raw_mean[phase])
            analyzer_value = analyzer_fields[analyzer_field]
            if (
                raw_value is None
                or analyzer_value is None
                or not math.isclose(
                    raw_value,
                    analyzer_value,
                    rel_tol=1e-12,
                    abs_tol=1e-12,
                )
            ):
                errors.append(
                    f"raw/analyzer {name} {phase} budget ratio mismatch"
                )

        token_match = exact_token_match_raw(
            run_dir / "baseline.json",
            run_dir / "post_01.json",
        )
        errors.extend(
            f"{name} exact-token check: {error}"
            for error in token_match["errors"]
        )
        analyzer_match = analyzer_fields["baseline_post1_exact_token_match"]
        raw_match = finite_number(token_match["match_rate"])
        if (
            analyzer_match is None
            or raw_match is None
            or not math.isclose(
                analyzer_match,
                raw_match,
                rel_tol=1e-12,
                abs_tol=1e-12,
            )
        ):
            errors.append(f"raw/analyzer {name} exact-token ratio mismatch")

        baseline = finite_number(raw_mean["baseline"])
        intervention = finite_number(raw_mean["intervention"])
        post = finite_number(raw_mean["post_01"])
        weighted_baseline = finite_number(raw_weighted["baseline"])
        weighted_intervention = finite_number(raw_weighted["intervention"])
        weighted_post = finite_number(raw_weighted["post_01"])
        runs[arm] = {
            "analyzer_fields": analyzer_fields,
            "telemetry": trace,
            "exact_token_match": token_match,
            "mean_of_ratios": {
                "baseline": baseline,
                "intervention": intervention,
                "post_01": post,
            },
            "weighted_ratio": {
                "baseline": weighted_baseline,
                "intervention": weighted_intervention,
                "post_01": weighted_post,
            },
            "mean_intervention_minus_baseline": (
                intervention - baseline
                if intervention is not None and baseline is not None
                else None
            ),
            "mean_post1_minus_baseline": (
                post - baseline
                if post is not None and baseline is not None
                else None
            ),
            "weighted_intervention_minus_baseline": (
                weighted_intervention - weighted_baseline
                if weighted_intervention is not None
                and weighted_baseline is not None
                else None
            ),
            "weighted_post1_minus_baseline": (
                weighted_post - weighted_baseline
                if weighted_post is not None and weighted_baseline is not None
                else None
            ),
        }
    attack = runs["attack"]
    placebo = runs["placebo"]
    budget_rules: dict[str, Any] = {}
    for method, field in (
        ("mean_of_ratios", "mean_post1_minus_baseline"),
        ("weighted_ratio", "weighted_post1_minus_baseline"),
    ):
        attack_delta = attack[field]
        placebo_delta = placebo[field]
        difference_in_differences = (
            attack_delta - placebo_delta
            if attack_delta is not None and placebo_delta is not None
            else None
        )
        passes = bool(
            attack_delta is not None
            and difference_in_differences is not None
            and attack_delta < 0
            and difference_in_differences < 0
        )
        budget_rules[method] = {
            "attack_post1_minus_baseline": attack_delta,
            "placebo_post1_minus_baseline": placebo_delta,
            "attack_minus_placebo_change": difference_in_differences,
            "passes": passes,
        }
    budget_change_consistent = all(
        rule["passes"] for rule in budget_rules.values()
    )
    token_match_sanity = all(
        run["exact_token_match"]["passes"] for run in runs.values()
    )
    telemetry_coverage_valid = all(
        run["telemetry"]["valid"] for run in runs.values()
    )
    return {
        "source": "raw server logs and raw request records",
        "runs": runs,
        "budget_change_rule": (
            "For both the per-step mean of budget ratios and the weighted "
            "budget ratio, attack post-1 minus baseline is negative and its "
            "change is more negative than placebo. Intervention is descriptive "
            "because its workload differs from the victim workload."
        ),
        "budget_rules": budget_rules,
        "budget_change_consistent": budget_change_consistent,
        "telemetry_coverage_valid": telemetry_coverage_valid,
        "token_match_sanity": token_match_sanity,
        "passes": (
            budget_change_consistent
            and telemetry_coverage_valid
            and token_match_sanity
        ),
    }


def compare_assessment_ratios(
    raw_runs: dict[str, dict[str, Any]],
    assessment_rows: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    for name in sorted(set(raw_runs) & set(assessment_rows)):
        for metric in METRICS:
            raw = raw_runs[name]["post_mean_ratios"].get(metric)
            analyzed = finite_number(
                assessment_rows[name].get(f"post_mean_{metric}_ratio")
            )
            if raw is None or analyzed is None:
                errors.append(f"cannot compare {name} {metric} analyzer ratio")
            elif not math.isclose(raw, analyzed, rel_tol=1e-12, abs_tol=1e-12):
                errors.append(f"raw/analyzer {name} {metric} ratio mismatch")


def compare_paired_summaries(
    paired: dict[str, Any],
    assessment: dict[str, Any],
    errors: list[str],
) -> None:
    analyzed = assessment.get("paired_analysis")
    if not isinstance(analyzed, dict):
        return
    summaries = analyzed.get("attack_minus_placebo")
    if not isinstance(summaries, dict):
        return
    for metric in METRICS:
        raw_summary = paired["summary"][metric]
        analyzed_summary = summaries.get(metric)
        if not isinstance(analyzed_summary, dict):
            continue
        for field in ("mean", "ci95_low", "ci95_high"):
            raw_value = finite_number(raw_summary.get(field))
            analyzed_value = finite_number(analyzed_summary.get(field))
            if raw_value is None or analyzed_value is None:
                continue
            if not math.isclose(
                raw_value,
                analyzed_value,
                rel_tol=1e-12,
                abs_tol=1e-12,
            ):
                errors.append(
                    f"raw/analyzer paired {metric}.{field} mismatch"
                )


def validate_archive(
    result_root: Path,
    assessment_path: Path,
    archive_path: Path,
    sidecar_path: Path,
    errors: list[str],
) -> dict[str, Any]:
    archive_sha: str | None = None
    recorded_sha: str | None = None
    sidecar_name: str | None = None
    archive_files: dict[str, str] = {}
    captured_contents: dict[str, bytes] = {}
    live_files: dict[str, str] = {}
    archive_errors: list[str] = []

    try:
        sidecar_lines = [
            line for line in sidecar_path.read_text().splitlines() if line.strip()
        ]
        if len(sidecar_lines) != 1:
            raise ValueError("sidecar must contain exactly one non-empty line")
        match = re.fullmatch(
            r"([0-9A-Fa-f]{64})\s+[*]?(.+)",
            sidecar_lines[0],
        )
        if match is None:
            raise ValueError("sidecar is not in sha256sum format")
        recorded_sha = match.group(1).lower()
        sidecar_name = match.group(2).strip()
        if PurePosixPath(sidecar_name).name != archive_path.name:
            raise ValueError("sidecar names a different archive")
    except (OSError, ValueError) as exc:
        archive_errors.append(f"sidecar: {type(exc).__name__}: {exc}")

    try:
        archive_sha = file_sha256(archive_path)
        if recorded_sha is None or archive_sha != recorded_sha:
            archive_errors.append("archive SHA-256 does not match sidecar")
    except OSError as exc:
        archive_errors.append(f"archive hash: {type(exc).__name__}: {exc}")

    for path in sorted(result_root.rglob("*")):
        try:
            if path.is_symlink():
                archive_errors.append(
                    "live result tree contains symlink: "
                    f"{path.relative_to(result_root)}"
                )
            elif path.is_file():
                member_name = (
                    PurePosixPath("paper_results")
                    / PurePosixPath(path.relative_to(result_root).as_posix())
                ).as_posix()
                live_files[member_name] = file_sha256(path)
        except OSError as exc:
            archive_errors.append(
                f"live inventory {path}: {type(exc).__name__}: {exc}"
            )

    required_root_files = {
        "manifest.txt",
        "ordinary_tokens.json",
        "paper_setup.log",
        "PAPER_SETUP_COMPLETE",
        "avep_paper_instrumentation.patch",
        "paper_probe.py",
        "find_ordinary_tokens.py",
        "analyze_paper_trials.py",
        "run_paper_trials.sh",
        "setup_paper_instance.sh",
    }
    seen_names: set[str] = set()
    unexpected_top_level: set[str] = set()
    capture_names = {"manifest.txt", "paper_results/EXPERIMENT_COMPLETE"}
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive:
                name = member.name.removeprefix("./")
                path = PurePosixPath(name)
                normalized = path.as_posix()
                if (
                    path.is_absolute()
                    or not path.parts
                    or ".." in path.parts
                    or "\\" in name
                    or not name
                    or normalized != name.rstrip("/")
                ):
                    archive_errors.append(f"unsafe archive member name: {member.name}")
                    continue
                name = normalized
                top_level = path.parts[0]
                if top_level != "paper_results" and top_level not in (
                    required_root_files
                ):
                    unexpected_top_level.add(top_level)
                if name in seen_names:
                    archive_errors.append(f"duplicate archive member: {name}")
                    continue
                seen_names.add(name)
                if member.issym() or member.islnk():
                    archive_errors.append(f"archive link member is forbidden: {name}")
                    continue
                if not member.isfile():
                    if not member.isdir():
                        archive_errors.append(
                            f"archive special member is forbidden: {name}"
                        )
                    continue
                source = archive.extractfile(member)
                if source is None:
                    archive_errors.append(f"cannot read archive member: {name}")
                    continue
                digest = hashlib.sha256()
                captured = bytearray()
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
                    if name in capture_names:
                        captured.extend(block)
                archive_files[name] = digest.hexdigest()
                if name in capture_names:
                    captured_contents[name] = bytes(captured)
    except (OSError, tarfile.TarError, EOFError) as exc:
        archive_errors.append(f"tar archive: {type(exc).__name__}: {exc}")
    if unexpected_top_level:
        archive_errors.append(
            "unexpected top-level archive members: "
            + ", ".join(sorted(unexpected_top_level))
        )

    archived_result_files = {
        name: digest
        for name, digest in archive_files.items()
        if name.startswith("paper_results/")
    }
    missing_live = sorted(set(live_files) - set(archived_result_files))
    extra_archive = sorted(set(archived_result_files) - set(live_files))
    content_mismatches = sorted(
        name
        for name in set(live_files) & set(archived_result_files)
        if live_files[name] != archived_result_files[name]
    )
    if missing_live:
        archive_errors.append(
            "live result files absent from archive: " + ", ".join(missing_live)
        )
    if extra_archive:
        archive_errors.append(
            "archive result files absent from live tree: "
            + ", ".join(extra_archive)
        )
    if content_mismatches:
        archive_errors.append(
            "live/archive content mismatches: "
            + ", ".join(content_mismatches)
        )

    missing_root_files = sorted(required_root_files - set(archive_files))
    if missing_root_files:
        archive_errors.append(
            "archive lacks required root files: " + ", ".join(missing_root_files)
        )
    for name in sorted(required_root_files & set(archive_files)):
        live_path = result_root.parent / name
        try:
            if file_sha256(live_path) != archive_files[name]:
                archive_errors.append(f"live/archive root file mismatch: {name}")
        except OSError as exc:
            archive_errors.append(
                f"live root file {name}: {type(exc).__name__}: {exc}"
            )

    complete_member = "paper_results/EXPERIMENT_COMPLETE"
    failed_member = "paper_results/EXPERIMENT_FAILED"
    required_result_files = {
        complete_member,
        "paper_results/paper_assessment.json",
        "paper_results/paper_assessment.stdout.json",
        "paper_results/paper_trials.csv",
        "paper_results/token_preflight/COMPLETE",
        "paper_results/token_preflight/selected_token_id.txt",
        "paper_results/PREDECLARED_DECISION_RULES.md",
    }
    missing_result_files = sorted(required_result_files - set(archive_files))
    if missing_result_files:
        archive_errors.append(
            "archive lacks required result files: "
            + ", ".join(missing_result_files)
        )
    if complete_member not in archive_files:
        archive_errors.append("archive lacks EXPERIMENT_COMPLETE")
    else:
        try:
            complete_text = captured_contents[complete_member].decode().strip()
            completed_at = datetime.fromisoformat(complete_text)
            if completed_at.tzinfo is None:
                raise ValueError("completion timestamp has no timezone")
        except (KeyError, UnicodeError, ValueError) as exc:
            archive_errors.append(
                f"invalid EXPERIMENT_COMPLETE: {type(exc).__name__}: {exc}"
            )
    if failed_member in archive_files:
        archive_errors.append("archive contains EXPERIMENT_FAILED")

    for member_name, trusted_sha in TRUSTED_ARTIFACT_SHA256.items():
        observed_sha = archive_files.get(member_name)
        if observed_sha is None:
            archive_errors.append(
                f"archive lacks trusted artifact: {member_name}"
            )
        elif observed_sha != trusted_sha:
            archive_errors.append(
                f"trusted artifact hash mismatch: {member_name}"
            )

    manifest_hash_fields = {
        "paper_patch_sha256": "avep_paper_instrumentation.patch",
        "probe_sha256": "paper_probe.py",
        "analyzer_sha256": "analyze_paper_trials.py",
        "runner_sha256": "run_paper_trials.sh",
    }
    try:
        manifest_text = captured_contents["manifest.txt"].decode()
        manifest_values = dict(
            line.split("=", 1)
            for line in manifest_text.splitlines()
            if "=" in line
        )
        for field, member_name in manifest_hash_fields.items():
            declared = manifest_values.get(field)
            if declared is None or not SHA256_PATTERN.fullmatch(declared):
                archive_errors.append(f"manifest lacks valid {field}")
            elif archive_files.get(member_name) != declared:
                archive_errors.append(
                    f"manifest hash does not match {member_name}"
                )
    except (KeyError, UnicodeError, ValueError) as exc:
        archive_errors.append(f"archive manifest: {type(exc).__name__}: {exc}")
    try:
        assessment_member = "paper_results/paper_assessment.json"
        if (
            assessment_member not in archive_files
            or file_sha256(assessment_path) != archive_files[assessment_member]
        ):
            archive_errors.append("assessment input is not archive-bound")
    except OSError as exc:
        archive_errors.append(
            f"assessment archive binding: {type(exc).__name__}: {exc}"
        )

    errors.extend(f"archive: {error}" for error in archive_errors)
    return {
        "valid": not archive_errors,
        "archive": str(archive_path),
        "sidecar": str(sidecar_path),
        "archive_sha256": archive_sha,
        "recorded_sha256": recorded_sha,
        "sidecar_archive_name": sidecar_name,
        "live_result_file_count": len(live_files),
        "archived_result_file_count": len(archived_result_files),
        "missing_live_files": missing_live,
        "extra_archive_files": extra_archive,
        "content_mismatches": content_mismatches,
        "unexpected_top_level": sorted(unexpected_top_level),
        "errors": archive_errors,
    }


def evaluate(
    result_root: Path,
    assessment_path: Path,
    archive_path: Path,
    sidecar_path: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    assessment: dict[str, Any] = {}
    try:
        assessment = load_object(assessment_path)
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"assessment: {type(exc).__name__}: {exc}")

    discovered: list[Path] = []
    try:
        discovered = sorted(
            path
            for path in result_root.iterdir()
            if path.is_dir()
            and (
                RUN_PATTERN.fullmatch(path.name)
                or (path / "metadata.json").exists()
            )
        )
    except OSError as exc:
        errors.append(f"result root: {type(exc).__name__}: {exc}")

    discovered_names = {path.name for path in discovered}
    expected_names = set(EXPECTED_METADATA)
    missing = sorted(expected_names - discovered_names)
    unexpected = sorted(discovered_names - expected_names)
    if missing:
        errors.append("missing planned runs: " + ", ".join(missing))
    if unexpected:
        errors.append("unexpected run directories: " + ", ".join(unexpected))

    raw_runs = {path.name: inspect_run(path) for path in discovered}
    for name in sorted(raw_runs):
        errors.extend(f"{name}: {error}" for error in raw_runs[name]["errors"])
    coefficient_dimensions = {
        len(movement["baseline"])
        for name, run in raw_runs.items()
        if name in EXPECTED_METADATA
        and EXPECTED_METADATA[name]["adaptive"]
        and (movement := run["estimator_movement"]) is not None
    }
    if coefficient_dimensions != {SPECULATIVE_STEPS + 1}:
        errors.append(
            "estimator coefficient-vector dimensions are not uniformly five"
        )
    token_ids = {
        raw_runs[name]["metadata"].get("poison_token_id")
        for name in expected_names & set(raw_runs)
        if nonnegative_integer(
            raw_runs[name]["metadata"].get("poison_token_id")
        )
        is not None
    }
    if len(token_ids) != 1:
        errors.append("the planned cohort does not use one poison token ID")
    selected_token = validate_selected_token(result_root, token_ids, errors)
    environments = validate_environments(result_root, errors)

    assessment_rows = validate_assessment(assessment, errors)
    compare_assessment_ratios(raw_runs, assessment_rows, errors)
    paired = raw_paired_effects(raw_runs, errors)
    compare_paired_summaries(paired, assessment, errors)
    estimator = estimator_analysis(raw_runs, errors)
    controls = control_analysis(raw_runs, errors)
    mechanism = mechanism_analysis(result_root, assessment_rows, errors)
    archive = validate_archive(
        result_root,
        assessment_path,
        archive_path,
        sidecar_path,
        errors,
    )

    throughput = paired["summary"]["throughput"]
    latency_p50 = paired["summary"]["latency_p50"]
    latency_p95 = paired["summary"]["latency_p95"]
    primary_complete = throughput["n"] == 6
    primary_adverse = bool(
        primary_complete
        and throughput["mean"] is not None
        and throughput["mean"] < 0
        and throughput["ci95_high"] is not None
        and throughput["ci95_high"] < 0
    )
    primary_non_adverse = bool(
        primary_complete
        and throughput["ci95_low"] is not None
        and throughput["ci95_low"] >= 0
    )
    latency_corroborates = bool(
        latency_p50["n"] == 6
        and latency_p95["n"] == 6
        and latency_p50["mean"] is not None
        and latency_p95["mean"] is not None
        and latency_p50["mean"] > 0
        and latency_p95["mean"] > 0
    )
    integrity_valid = not errors
    reproduced_evidence = bool(
        integrity_valid
        and primary_adverse
        and latency_corroborates
        and estimator["stronger_after_attack"]
        and controls["all_controls_pass"]
        and mechanism["passes"]
    )
    if not integrity_valid:
        classification = "INCONCLUSIVE"
        reason = "Required data or integrity checks are incomplete or invalid."
    elif primary_non_adverse:
        classification = "NEGATIVE"
        reason = "The throughput interval is wholly non-adverse."
    elif reproduced_evidence:
        classification = "REPRODUCED"
        reason = "All predeclared primary and supporting rules pass."
    else:
        classification = "INCONCLUSIVE"
        reason = "The complete evidence does not satisfy a terminal rule."

    run_diagnostics = {
        name: {
            "metadata_mismatches": run["metadata_mismatches"],
            "phase_errors": run["phase_errors"],
            "errors": run["errors"],
        }
        for name, run in sorted(raw_runs.items())
    }
    return {
        "schema_version": 2,
        "classification": classification,
        "classification_reason": reason,
        "decision_rules_source": "PREDECLARED_DECISION_RULES.md",
        "archive_required": True,
        "archive_note": (
            "The final classification is valid only after SHA-256, member, "
            "completion-marker, and live/archive byte-equivalence checks pass."
        ),
        "integrity": {
            "valid": integrity_valid,
            "expected_run_count": len(EXPECTED_METADATA),
            "discovered_run_count": len(discovered),
            "missing_runs": missing,
            "unexpected_runs": unexpected,
            "poison_token_ids": sorted(token_ids),
            "selected_token": selected_token,
            "environments": environments,
            "archive": archive,
            "errors": errors,
            "runs": run_diagnostics,
        },
        "paired_effects": paired,
        "estimator_coefficient_movement": estimator,
        "control_attenuation": controls,
        "mechanism_sanity": mechanism,
        "decision": {
            "integrity_valid": integrity_valid,
            "primary_complete": primary_complete,
            "primary_adverse_ci": primary_adverse,
            "primary_wholly_non_adverse_ci": primary_non_adverse,
            "latency_corroborates": latency_corroborates,
            "estimator_movement_stronger_after_attack": (
                estimator["stronger_after_attack"]
            ),
            "control_attenuation_passes": controls["all_controls_pass"],
            "mechanism_sanity_passes": mechanism["passes"],
            "reproduced_evidence_passes": reproduced_evidence,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply the AVEP predeclared postflight decision rules."
    )
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--assessment", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = evaluate(
        args.result_root,
        args.assessment,
        args.archive,
        args.archive_sha256,
    )
    rendered = json.dumps(
        result,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ) + "\n"
    args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
