#!/usr/bin/env python
"""Fail-closed offline analysis for the bounded AVEP follow-up."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "avep-tenant-short-followup-v2"
TARGET_MODEL = "Qwen/Qwen3-4B"
BASE_URL = "http://127.0.0.1:8001/v1"
PROBE_SEED = 20260918
SPECULATIVE_STEPS = 4
SCREEN_TOKEN_COUNT = 12
SCREEN_TOKEN_IDS = (
    279,
    323,
    6303,
    8251,
    23811,
    3015,
    8094,
    12095,
    13,
    11,
    0,
    30,
)
SCREEN_TOKEN_PATTERN = re.compile(r"token_([0-9]+)\.json")
PERFORMANCE_RUN_PATTERN = re.compile(
    r"perf_pair_([0-9][0-9])_(attack|placebo)"
)
PHASE_MARKER_PATTERN = re.compile(r"===== AVEP_PHASE (\S+)")
BUDGET_PATTERN = re.compile(r"AVEP_BUDGET\s+(\{.*\})")

PRE_PHASES = tuple(f"pre_{index:02d}" for index in range(1, 5))
POST_PHASES = tuple(f"post_{index:02d}" for index in range(1, 9))
WORKLOAD_PHASES = ("warmup", *PRE_PHASES, "intervention", *POST_PHASES)
PHASE_REQUESTS = {
    "warmup": 1024,
    **{phase: 128 for phase in PRE_PHASES},
    "intervention": 4096,
    **{phase: 128 for phase in POST_PHASES},
}
SCREEN_WARMUP_REQUESTS = 512
SCREEN_REQUESTS = 256
CONCURRENCY = 8
# Two generated tokens expose at most the prefill-sampled token and one initial
# speculative verification round; longer within-request repetition is excluded.
MAX_TOKENS = 2

POTENCY_THRESHOLDS = {
    "attack_acceptance_max": 0.05,
    "placebo_minus_attack_acceptance_min": 0.10,
    "intercept0_delta_delta_max": -0.50,
    "post1_budget_attack_minus_placebo_max": -0.05,
}
RULE_PATTERNS = {
    "attack_acceptance_max": re.compile(
        r"attack\s+acceptance[^\n]*<=\s*0\.0?5", re.IGNORECASE
    ),
    "placebo_minus_attack_acceptance_min": re.compile(
        r"placebo\s*-\s*attack[^\n]*>=\s*0\.10", re.IGNORECASE
    ),
    "intercept0_delta_delta_max": re.compile(
        r"delta-delta\s+intercept(?:\[0\]|0)[^\n]*<=\s*-0\.50",
        re.IGNORECASE,
    ),
    "post1_budget_attack_minus_placebo_max": re.compile(
        r"normalized\s+post-?1\s+budget\s+attack\s*-\s*placebo"
        r"[^\n]*<=\s*-0\.05",
        re.IGNORECASE,
    ),
}
METRICS = {
    "throughput": "aggregate_output_tokens_per_second",
    "latency_p50": "latency_ms_p50",
    "latency_p95": "latency_ms_p95",
}
DECLARED_INPUT_FILES = (
    "run_tenant_short_followup.sh",
    "analyze_tenant_short_followup.py",
    "test_analyze_tenant_short_followup.py",
    "tenant_probe.py",
    "tenant_gateway.py",
    "TENANT_SHORT_FOLLOWUP_DECISION_RULES.md",
    "TENANT_SHORT_FOLLOWUP_PROTOCOL.md",
    "avep_paper_instrumentation.patch",
)


def finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def nonnegative_integer(value: Any) -> int | None:
    if isinstance(value, bool) or value.__class__ is not int:
        return None
    return value if value >= 0 else None


def threshold_at_most(value: Any, limit: float) -> bool:
    number = finite_number(value)
    return number is not None and (
        number <= limit
        or math.isclose(number, limit, rel_tol=1e-12, abs_tol=1e-12)
    )


def threshold_at_least(value: Any, limit: float) -> bool:
    number = finite_number(value)
    return number is not None and (
        number >= limit
        or math.isclose(number, limit, rel_tol=1e-12, abs_tol=1e-12)
    )


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


def expected_declared_schedule() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "screen": {
            "token_ids": list(SCREEN_TOKEN_IDS),
            "warmup": {
                "requests": SCREEN_WARMUP_REQUESTS,
                "concurrency": 32,
                "max_tokens": 32,
            },
            "candidate": {
                "requests": SCREEN_REQUESTS,
                "concurrency": CONCURRENCY,
                "max_tokens": MAX_TOKENS,
            },
        },
        "gate_order": ["placebo", "attack"],
        "performance_orders": [
            ["placebo", "attack"],
            ["attack", "placebo"],
            ["attack", "placebo"],
            ["placebo", "attack"],
        ],
        "adaptive_workload": {
            "reset_after_server_ready": True,
            "warmup": {
                "requests": 1024,
                "concurrency": 32,
                "max_tokens": 32,
            },
            "pre": {
                "windows": 4,
                "requests_per_window": 128,
                "concurrency": 32,
                "max_tokens": 32,
            },
            "intervention": {
                "requests": 4096,
                "concurrency": CONCURRENCY,
                "max_tokens": MAX_TOKENS,
            },
            "post": {
                "windows": 8,
                "requests_per_window": 128,
                "concurrency": 32,
                "max_tokens": 32,
            },
        },
        "tenant_topology": {
            "gateway_url": BASE_URL,
            "upstream_url": "http://127.0.0.1:8000/v1",
            "intervention_tenant": "attacker",
            "all_other_workload_tenant": "victim",
            "same_worker_required": True,
            "negative_auth_tests_required": True,
            "audit_join_required": True,
        },
    }


def validate_sha_sidecar(target: Path, sidecar: Path) -> list[str]:
    errors: list[str] = []
    try:
        fields = sidecar.read_text().strip().split()
        digest = file_sha256(target)
        if fields != [digest, target.name]:
            errors.append(f"{sidecar.name} does not match {target.name}")
    except OSError as exc:
        errors.append(f"{sidecar.name}: {type(exc).__name__}: {exc}")
    return errors


def parse_aware_timestamp(value: str, label: str) -> tuple[datetime | None, str | None]:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timestamp has no UTC offset")
        return parsed, None
    except (AttributeError, TypeError, ValueError) as exc:
        return None, f"{label}: {type(exc).__name__}: {exc}"


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def bootstrap_mean_ci(
    values: list[float], *, samples: int = 20_000, seed: int = PROBE_SEED
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


def expected_phase_config(
    phase: str,
    *,
    arm: str,
    poison_token_id: int,
    return_token_ids: bool,
) -> dict[str, Any]:
    intervention = phase == "intervention"
    requests = PHASE_REQUESTS[phase]
    concurrency = CONCURRENCY if intervention else 32
    max_tokens = MAX_TOKENS if intervention else 32
    return {
        "phase": phase,
        "principal": "attacker" if intervention else "victim",
        "model": TARGET_MODEL,
        "base_url": BASE_URL,
        "requests": requests,
        "concurrency": concurrency,
        "max_tokens": max_tokens,
        "allowed_token_id": (
            poison_token_id if intervention and arm == "attack" else None
        ),
        "seed": PROBE_SEED,
        "return_token_ids": return_token_ids,
    }


def _detailed_metric_errors(
    metric: Any,
    *,
    require_positive_evidence: bool,
) -> tuple[list[str], dict[str, int] | None]:
    errors: list[str] = []
    if not isinstance(metric, dict):
        return ["speculative_decoding metrics are missing"], None
    steps = nonnegative_integer(metric.get("num_spec_steps"))
    drafted = nonnegative_integer(metric.get("num_draft_tokens"))
    accepted = nonnegative_integer(metric.get("num_accepted_draft_tokens"))
    spec_tokens = nonnegative_integer(metric.get("num_spec_tokens"))
    if steps is None:
        errors.append("num_spec_steps is not a non-negative integer")
    elif require_positive_evidence and steps == 0:
        errors.append("num_spec_steps is not positive")
    if drafted is None:
        errors.append("num_draft_tokens is not a non-negative integer")
    elif require_positive_evidence and drafted == 0:
        errors.append("num_draft_tokens is not positive")
    if accepted is None:
        errors.append("num_accepted_draft_tokens is not non-negative")
    if spec_tokens is None or spec_tokens == 0:
        errors.append("num_spec_tokens is not a positive integer")
    if drafted is not None and accepted is not None and accepted > drafted:
        errors.append("accepted draft tokens exceed drafted tokens")

    raw_rate = metric.get("draft_acceptance_rate")
    rate = finite_number(raw_rate)
    if drafted:
        if rate is None or rate < 0 or rate > 1:
            errors.append("draft_acceptance_rate is not in [0, 1]")
        elif accepted is not None and not math.isclose(
            rate, accepted / drafted, rel_tol=1e-12, abs_tol=1e-12
        ):
            errors.append("draft_acceptance_rate is internally inconsistent")
    elif drafted == 0 and raw_rate is not None and rate != 0.0:
        errors.append("zero-draft acceptance rate is neither null nor zero")

    per_step_drafted = metric.get("per_step_drafted")
    per_step_accepted = metric.get("per_step_accepted")
    if steps == 0:
        valid_step_lists = (
            per_step_drafted in (None, []) and per_step_accepted in (None, [])
        )
    else:
        valid_step_lists = (
            isinstance(per_step_drafted, list)
            and isinstance(per_step_accepted, list)
            and steps is not None
            and len(per_step_drafted) == steps
            and len(per_step_accepted) == steps
            and all(
                nonnegative_integer(value) is not None
                for value in per_step_drafted
            )
            and all(
                nonnegative_integer(value) is not None
                for value in per_step_accepted
            )
        )
    if not valid_step_lists:
        errors.append("per-step detailed metrics are missing or malformed")
    else:
        drafted_steps = per_step_drafted or []
        accepted_steps = per_step_accepted or []
        if any(
            accepted_value > drafted_value
            for accepted_value, drafted_value in zip(
                accepted_steps, drafted_steps, strict=True
            )
        ):
            errors.append("a per-step accepted count exceeds its draft count")
        if drafted is not None and sum(drafted_steps) != drafted:
            errors.append("per-step drafted counts do not sum to total")
        if accepted is not None and sum(accepted_steps) != accepted:
            errors.append("per-step accepted counts do not sum to total")

    histogram = metric.get("acceptance_histogram")
    histogram_values_valid = isinstance(histogram, list) and all(
        nonnegative_integer(value) is not None for value in histogram
    )
    if steps == 0:
        valid_histogram = (
            histogram_values_valid
            and spec_tokens is not None
            and (
                len(histogram) == 0
                or (
                    len(histogram) == spec_tokens + 1
                    and sum(histogram) == 0
                )
            )
        )
    else:
        valid_histogram = (
            histogram_values_valid
            and spec_tokens is not None
            and len(histogram) == spec_tokens + 1
        )
    if not valid_histogram:
        errors.append("acceptance_histogram is missing or malformed")
    elif steps is not None and sum(histogram) != steps:
        errors.append("acceptance_histogram does not sum to num_spec_steps")
    elif accepted is not None and sum(
        index * count for index, count in enumerate(histogram)
    ) != accepted:
        errors.append("acceptance_histogram does not sum to accepted tokens")

    mean_acceptance = finite_number(metric.get("mean_acceptance_length"))
    expected_mean = (
        1.0 + accepted / steps
        if steps not in (None, 0) and accepted is not None
        else 1.0
    )
    if mean_acceptance is None or not math.isclose(
        mean_acceptance, expected_mean, rel_tol=1e-12, abs_tol=1e-12
    ):
        errors.append("mean_acceptance_length is internally inconsistent")

    if errors or steps is None or drafted is None or accepted is None:
        return errors, None
    return errors, {"steps": steps, "drafted": drafted, "accepted": accepted}


def inspect_phase(
    path: Path,
    expected_config: dict[str, Any],
    *,
    require_detailed_metrics: bool,
    require_positive_detailed_per_request: bool = False,
    require_positive_detailed_aggregate: bool = False,
    forced_token_id: int | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    timing: dict[str, int] | None = None
    summary_values: dict[str, float] = {}
    acceptance: float | None = None
    try:
        payload = load_object(path)
        config = payload.get("config")
        if not isinstance(config, dict):
            raise ValueError("config is missing or is not an object")
        for field, expected in expected_config.items():
            actual = config.get(field)
            if actual != expected:
                errors.append(
                    f"config.{field} is {actual!r}, expected {expected!r}"
                )

        started_ns = nonnegative_integer(payload.get("started_ns"))
        finished_ns = nonnegative_integer(payload.get("finished_ns"))
        if started_ns is None or finished_ns is None:
            errors.append("top-level timestamps are not non-negative integers")
        elif finished_ns <= started_ns:
            errors.append("top-level finished_ns is not after started_ns")
        else:
            timing = {"started_ns": started_ns, "finished_ns": finished_ns}

        requests_expected = expected_config["requests"]
        max_tokens = expected_config["max_tokens"]
        summary = payload.get("summary")
        if not isinstance(summary, dict):
            raise ValueError("summary is missing or is not an object")
        for field, expected in (
            ("requests", requests_expected),
            ("successful", requests_expected),
            ("failed", 0),
            ("completion_tokens", requests_expected * max_tokens),
        ):
            actual = nonnegative_integer(summary.get(field))
            if actual != expected:
                errors.append(f"summary.{field} is {actual!r}, expected {expected}")

        records = payload.get("records")
        if not isinstance(records, list):
            errors.append("records is not a list")
            records = []
        elif len(records) != requests_expected:
            errors.append(
                f"records has {len(records)} entries, expected {requests_expected}"
            )

        bad_indices = 0
        unsuccessful = 0
        bad_times = 0
        bad_usage = 0
        bad_token_ids = 0
        detailed_errors = 0
        record_starts: list[int] = []
        record_finishes: list[int] = []
        latencies: list[float] = []
        all_token_ids: list[int] = []
        spec_totals = {"steps": 0, "drafted": 0, "accepted": 0}
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                unsuccessful += 1
                continue
            if nonnegative_integer(record.get("index")) != index:
                bad_indices += 1
            if record.get("ok") is not True:
                unsuccessful += 1
            record_start = nonnegative_integer(record.get("started_ns"))
            record_finish = nonnegative_integer(record.get("finished_ns"))
            latency = finite_number(record.get("latency_ms"))
            if (
                record_start is None
                or record_finish is None
                or record_finish <= record_start
                or latency is None
                or latency <= 0
            ):
                bad_times += 1
            else:
                record_starts.append(record_start)
                record_finishes.append(record_finish)
                latencies.append(latency)

            usage = record.get("usage")
            record_tokens = (
                nonnegative_integer(usage.get("completion_tokens"))
                if isinstance(usage, dict)
                else None
            )
            if record_tokens != max_tokens:
                bad_usage += 1

            token_ids = record.get("token_ids")
            if expected_config["return_token_ids"]:
                valid_ids = (
                    isinstance(token_ids, list)
                    and len(token_ids) == max_tokens
                    and all(
                        nonnegative_integer(token_id) is not None
                        for token_id in token_ids
                    )
                )
                if not valid_ids:
                    bad_token_ids += 1
                else:
                    assert isinstance(token_ids, list)
                    all_token_ids.extend(token_ids)
                    if forced_token_id is not None and any(
                        token_id != forced_token_id for token_id in token_ids
                    ):
                        bad_token_ids += 1
            elif token_ids not in (None, []):
                bad_token_ids += 1

            if require_detailed_metrics:
                metrics = record.get("metrics")
                speculative = (
                    metrics.get("speculative_decoding")
                    if isinstance(metrics, dict)
                    else None
                )
                metric_errors, totals = _detailed_metric_errors(
                    speculative,
                    require_positive_evidence=(
                        require_positive_detailed_per_request
                    ),
                )
                detailed_errors += bool(metric_errors)
                if totals is not None:
                    for key in spec_totals:
                        spec_totals[key] += totals[key]

        for count, message in (
            (bad_indices, "records have non-canonical indices"),
            (unsuccessful, "records are not successful objects"),
            (bad_times, "records have invalid timing data"),
            (bad_usage, "records have unexpected completion counts"),
            (bad_token_ids, "records have invalid token-ID evidence"),
            (detailed_errors, "records have invalid detailed metrics"),
        ):
            if count:
                errors.append(f"{count} {message}")

        if timing is not None and record_starts and record_finishes:
            if min(record_starts) < timing["started_ns"]:
                errors.append("a record starts before the phase timestamp")
            if max(record_finishes) > timing["finished_ns"]:
                errors.append("a record finishes after the phase timestamp")

        if len(latencies) == requests_expected:
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
                        observed, recomputed, rel_tol=1e-12, abs_tol=1e-9
                    )
                ):
                    errors.append(f"summary.{key} does not match records")

        wall_seconds = finite_number(summary.get("wall_seconds"))
        throughput = finite_number(
            summary.get("aggregate_output_tokens_per_second")
        )
        completion_tokens = requests_expected * max_tokens
        if wall_seconds is None or wall_seconds <= 0:
            errors.append("summary.wall_seconds is not finite and positive")
        else:
            if record_starts and record_finishes:
                raw_wall = (
                    max(record_finishes) - min(record_starts)
                ) / 1_000_000_000
                if not math.isclose(
                    wall_seconds, raw_wall, rel_tol=1e-12, abs_tol=1e-9
                ):
                    errors.append("summary.wall_seconds does not match records")
            expected_throughput = completion_tokens / wall_seconds
            if throughput is None or not math.isclose(
                throughput,
                expected_throughput,
                rel_tol=1e-12,
                abs_tol=1e-9,
            ):
                errors.append("summary throughput is internally inconsistent")

        for short_name, key in METRICS.items():
            value = finite_number(summary.get(key))
            if value is None or value <= 0:
                errors.append(f"summary.{key} is not finite and positive")
            else:
                summary_values[short_name] = value

        if require_detailed_metrics and not detailed_errors:
            if (
                require_positive_detailed_aggregate
                and spec_totals["steps"] == 0
            ):
                errors.append("phase aggregate has no speculative steps")
            if (
                require_positive_detailed_aggregate
                and spec_totals["drafted"] == 0
            ):
                errors.append("phase aggregate has no drafted tokens")
            expected_summary = {
                "spec_requests": requests_expected,
                "spec_steps": spec_totals["steps"],
                "draft_tokens": spec_totals["drafted"],
                "accepted_draft_tokens": spec_totals["accepted"],
            }
            for field, expected in expected_summary.items():
                actual = nonnegative_integer(summary.get(field))
                if actual != expected:
                    errors.append(
                        f"summary.{field} is {actual!r}, expected {expected}"
                    )
            if spec_totals["drafted"]:
                acceptance = (
                    spec_totals["accepted"] / spec_totals["drafted"]
                )
                observed = finite_number(summary.get("draft_acceptance_rate"))
                if observed is None or not math.isclose(
                    observed, acceptance, rel_tol=1e-12, abs_tol=1e-12
                ):
                    errors.append(
                        "summary.draft_acceptance_rate does not match records"
                    )
            elif "draft_acceptance_rate" not in summary:
                errors.append("summary.draft_acceptance_rate is missing")
            elif summary["draft_acceptance_rate"] is not None:
                errors.append(
                    "summary.draft_acceptance_rate must be null with no drafts"
                )

        if forced_token_id is not None:
            fraction = (
                sum(token_id == forced_token_id for token_id in all_token_ids)
                / len(all_token_ids)
                if all_token_ids
                else None
            )
            observed = finite_number(summary.get("control_token_fraction"))
            if fraction != 1.0:
                errors.append("forced token fraction is not exactly one")
            if observed != 1.0:
                errors.append("summary.control_token_fraction is not one")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "timing": timing,
        "metrics": summary_values,
        "draft_acceptance_rate": acceptance,
    }


def _metadata_errors(
    metadata: dict[str, Any], expected: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    for field, expected_value in expected.items():
        actual = metadata.get(field)
        if actual != expected_value:
            errors.append(
                f"metadata.{field} is {actual!r}, expected {expected_value!r}"
            )
    token_id = metadata.get("poison_token_id")
    if token_id is not None and nonnegative_integer(token_id) is None:
        errors.append(
            "metadata.poison_token_id must be a non-negative integer or null"
        )
    return errors


def _all_finite_numbers(value: Any) -> bool:
    if isinstance(value, list):
        return all(_all_finite_numbers(item) for item in value)
    return finite_number(value) is not None


def _all_zero_numbers(value: Any) -> bool:
    if isinstance(value, list):
        return all(_all_zero_numbers(item) for item in value)
    number = finite_number(value)
    return number is not None and math.isclose(number, 0.0, abs_tol=1e-7)


def available_state_errors(state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if state.get("available") is not True:
        return ["estimator state is unavailable"]
    for field in ("steps_since_refit", "refits"):
        if nonnegative_integer(state.get(field)) is None:
            errors.append(f"{field} is not a non-negative integer")
    if finite_number(state.get("slope")) is None:
        errors.append("slope is not finite")
    intercepts = state.get("intercepts")
    if (
        not isinstance(intercepts, list)
        or len(intercepts) != SPECULATIVE_STEPS
        or not _all_finite_numbers(intercepts)
    ):
        errors.append(
            f"intercepts does not contain {SPECULATIVE_STEPS} finite values"
        )
    shapes = {
        "counts": (SPECULATIVE_STEPS,),
        "info": (SPECULATIVE_STEPS, 3),
        "grad": (SPECULATIVE_STEPS, 2),
    }
    for field, shape in shapes.items():
        value = state.get(field)
        valid = isinstance(value, list) and len(value) == shape[0]
        if valid and len(shape) == 2:
            valid = all(
                isinstance(row, list) and len(row) == shape[1]
                for row in value
            )
        if not valid or not _all_finite_numbers(value):
            errors.append(f"{field} is missing, non-finite, or has wrong shape")
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
        if not _all_zero_numbers(state.get(field)):
            errors.append(f"clean-state {field} is not all zero")
    return errors


def estimator_state(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    try:
        payload = load_object(path)
        results = payload.get("results")
        if not isinstance(results, list) or len(results) != 1:
            raise ValueError("results must contain exactly one worker state")
        state = results[0]
        if not isinstance(state, dict):
            raise ValueError("worker state is not an object")
        errors.extend(available_state_errors(state))
        return state, errors
    except (OSError, ValueError, TypeError) as exc:
        return None, [f"{type(exc).__name__}: {exc}"]


def startup_reset_evidence(run_dir: Path) -> dict[str, Any]:
    errors: list[str] = []
    server_ready, state_errors = estimator_state(
        run_dir / "state_server_ready.json"
    )
    errors.extend(
        f"state_server_ready.json: {error}" for error in state_errors
    )
    reset_state, state_errors = estimator_state(run_dir / "state_reset.json")
    errors.extend(f"state_reset.json: {error}" for error in state_errors)
    if reset_state is not None:
        errors.extend(
            f"state_reset.json: {error}"
            for error in clean_state_errors(reset_state)
        )

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
            raise ValueError("reset response lacks reset object")
        before = reset.get("before")
        after = reset.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ValueError("reset response lacks before/after states")
        errors.extend(
            f"estimator_reset.before: {error}"
            for error in available_state_errors(before)
        )
        errors.extend(
            f"estimator_reset.after: {error}"
            for error in clean_state_errors(after)
        )
        if server_ready is None or not structures_close(before, server_ready):
            errors.append(
                "estimator_reset.before does not match state_server_ready.json"
            )
        if reset_state is None or not structures_close(after, reset_state):
            errors.append("estimator_reset.after does not match state_reset.json")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"estimator_reset.json: {type(exc).__name__}: {exc}")

    try:
        markers = [
            match.group(1)
            for line in (run_dir / "server.log").read_text(
                errors="replace"
            ).splitlines()
            if (match := PHASE_MARKER_PATTERN.search(line))
        ]
        required = (
            "server_ready",
            "startup_reset_begin",
            "startup_reset_end",
            "warmup_begin",
        )
        for marker in required:
            if markers.count(marker) != 1:
                errors.append(f"server.log must contain one {marker} marker")
        if all(markers.count(marker) == 1 for marker in required):
            positions = [markers.index(marker) for marker in required]
            if positions != sorted(positions):
                errors.append("startup reset markers are not in required order")
            reset_end = markers.index("startup_reset_end")
            workload_before_reset = [
                marker
                for marker in markers[:reset_end]
                if marker.removesuffix("_begin") in WORKLOAD_PHASES
            ]
            if workload_before_reset:
                errors.append("a workload phase begins before startup reset ends")
    except OSError as exc:
        errors.append(f"server.log: {type(exc).__name__}: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "server_ready": server_ready,
        "reset": reset_state,
    }


def raw_budget_trace(path: Path) -> dict[str, Any]:
    errors: list[str] = []
    events: list[dict[str, Any]] = []
    phase_events: dict[str, list[dict[str, Any]]] = {
        phase: [] for phase in WORKLOAD_PHASES
    }
    begins = {phase: 0 for phase in WORKLOAD_PHASES}
    ends = {phase: 0 for phase in WORKLOAD_PHASES}
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
        marker_match = PHASE_MARKER_PATTERN.search(line)
        if marker_match:
            marker = marker_match.group(1)
            if marker.endswith("_begin"):
                phase = marker.removesuffix("_begin")
                if phase in phase_events:
                    if active_phase is not None:
                        errors.append(
                            f"line {line_number}: a phase begins while one is active"
                        )
                    active_phase = phase
                    begins[phase] += 1
                else:
                    active_phase = None
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
                raise ValueError("budget bounds are inconsistent")
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
            errors.append(f"line {line_number}: {type(exc).__name__}: {exc}")

    steps = [event["step"] for event in events]
    if not steps:
        errors.append("no AVEP_BUDGET telemetry events were found")
    elif steps != list(range(1, len(steps) + 1)):
        errors.append("AVEP_BUDGET step sequence is not contiguous from one")

    phase_summaries: dict[str, Any] = {}
    for phase in WORKLOAD_PHASES:
        if begins[phase] != 1 or ends[phase] != 1:
            errors.append(f"{phase} does not have exactly one begin/end marker")
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
        phase_summaries[phase] = {
            "event_count": len(phase_events[phase]),
            "usable_event_count": len(usable),
            "mean_normalized_budget": mean_ratio,
            "weighted_normalized_budget": weighted_ratio,
        }
    return {
        "valid": not errors,
        "errors": errors,
        "total_event_count": len(events),
        "phases": phase_summaries,
    }


def inspect_screen(result_root: Path) -> dict[str, Any]:
    screen_dir = result_root / "screen"
    errors: list[str] = []
    metadata: dict[str, Any] = {}
    try:
        metadata = load_object(screen_dir / "metadata.json")
        errors.extend(
            _metadata_errors(
                metadata,
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "run_name": "screen",
                    "stage": "screen",
                    "pair_id": None,
                    "arm": "screen",
                    "adaptive": False,
                    "telemetry": False,
                    "detailed_metrics": True,
                    "poison_token_id": None,
                },
            )
        )
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"metadata.json: {type(exc).__name__}: {exc}")
    if not (screen_dir / "COMPLETE").is_file():
        errors.append("COMPLETE marker is absent")

    warmup_config = {
        "phase": "warmup",
        "principal": "victim",
        "model": TARGET_MODEL,
        "base_url": BASE_URL,
        "requests": SCREEN_WARMUP_REQUESTS,
        "concurrency": 32,
        "max_tokens": 32,
        "allowed_token_id": None,
        "seed": PROBE_SEED,
        "return_token_ids": False,
    }
    warmup = inspect_phase(
        screen_dir / "warmup.json",
        warmup_config,
        require_detailed_metrics=False,
    )
    errors.extend(f"warmup.json: {error}" for error in warmup["errors"])

    try:
        token_paths = {
            int(match.group(1)): path
            for path in screen_dir.iterdir()
            if (match := SCREEN_TOKEN_PATTERN.fullmatch(path.name))
        }
    except OSError as exc:
        token_paths = {}
        errors.append(f"screen directory: {type(exc).__name__}: {exc}")
    if len(token_paths) != SCREEN_TOKEN_COUNT:
        errors.append(
            f"screen has {len(token_paths)} token artifacts, expected "
            f"{SCREEN_TOKEN_COUNT}"
        )

    actual_ids = set(token_paths)
    expected_ids = set(SCREEN_TOKEN_IDS)
    if actual_ids != expected_ids:
        missing = sorted(expected_ids - actual_ids)
        unexpected = sorted(actual_ids - expected_ids)
        if missing:
            errors.append(f"screen token ids missing: {missing}")
        if unexpected:
            errors.append(f"screen token ids unexpected: {unexpected}")

    candidates: list[dict[str, Any]] = []
    ordered_timings: list[tuple[str, dict[str, int] | None]] = [
        ("warmup", warmup["timing"])
    ]
    for position, token_id in enumerate(SCREEN_TOKEN_IDS):
        path = token_paths.get(token_id)
        if path is None:
            continue
        config = {
            "phase": f"token_{token_id}",
            "principal": "attacker",
            "model": TARGET_MODEL,
            "base_url": BASE_URL,
            "requests": SCREEN_REQUESTS,
            "concurrency": CONCURRENCY,
            "max_tokens": MAX_TOKENS,
            "allowed_token_id": token_id,
            "seed": PROBE_SEED,
            "return_token_ids": True,
        }
        inspected = inspect_phase(
            path,
            config,
            require_detailed_metrics=True,
            require_positive_detailed_per_request=False,
            require_positive_detailed_aggregate=True,
            forced_token_id=token_id,
        )
        errors.extend(f"{path.name}: {error}" for error in inspected["errors"])
        ordered_timings.append((path.stem, inspected["timing"]))
        candidates.append(
            {
                "token_id": token_id,
                "tie_break_position": position,
                "draft_acceptance_rate": inspected["draft_acceptance_rate"],
                "valid": inspected["valid"],
            }
        )

    if all(timing is not None for _, timing in ordered_timings):
        for (left_name, left), (right_name, right) in zip(
            ordered_timings, ordered_timings[1:], strict=False
        ):
            assert left is not None and right is not None
            if left["finished_ns"] > right["started_ns"]:
                errors.append(f"{left_name} overlaps or follows {right_name}")

    selected_token_id: int | None = None
    valid_candidates = [
        candidate
        for candidate in candidates
        if candidate["valid"]
        and finite_number(candidate["draft_acceptance_rate"]) is not None
    ]
    if len(valid_candidates) == SCREEN_TOKEN_COUNT:
        selected = min(
            valid_candidates,
            key=lambda item: (
                item["draft_acceptance_rate"],
                item["tie_break_position"],
            ),
        )
        selected_token_id = selected["token_id"]
    else:
        errors.append("not all screen candidates are valid and rankable")

    selection_path = screen_dir / "selected_token_id.txt"
    try:
        declared = int(selection_path.read_text().strip())
        if selected_token_id is None or declared != selected_token_id:
            errors.append(
                "selected_token_id.txt does not match deterministic selection"
            )
    except (OSError, ValueError) as exc:
        errors.append(f"selected_token_id.txt: {type(exc).__name__}: {exc}")
    try:
        selection = load_object(screen_dir / "selected_token.json")
        selected_candidate = next(
            (
                candidate
                for candidate in candidates
                if candidate["token_id"] == selected_token_id
            ),
            None,
        )
        expected_selection = (
            {
                "selected_token_id": selected_candidate["token_id"],
                "selected_acceptance_rate": selected_candidate[
                    "draft_acceptance_rate"
                ],
                "tie_break_position": selected_candidate[
                    "tie_break_position"
                ],
            }
            if selected_candidate is not None
            else None
        )
        if expected_selection is None or not structures_close(
            selection, expected_selection
        ):
            errors.append(
                "selected_token.json does not match deterministic selection"
            )
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"selected_token.json: {type(exc).__name__}: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "metadata": metadata,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "selection_rule": "minimum acceptance, then fixed-list position",
        "selected_token_id": selected_token_id,
    }


def inspect_experimental_run(
    run_dir: Path,
    *,
    stage: str,
    pair_id: str,
    arm: str,
    poison_token_id: int,
) -> dict[str, Any]:
    errors: list[str] = []
    metadata: dict[str, Any] = {}
    gate = stage == "gate"
    expected_name = (
        f"gate_{arm}" if gate else f"perf_pair_{pair_id}_{arm}"
    )
    try:
        metadata = load_object(run_dir / "metadata.json")
        errors.extend(
            _metadata_errors(
                metadata,
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "stage": stage,
                    "run_name": expected_name,
                    "pair_id": pair_id,
                    "arm": arm,
                    "adaptive": True,
                    "telemetry": gate,
                    "detailed_metrics": gate,
                    "poison_token_id": poison_token_id,
                },
            )
        )
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"metadata.json: {type(exc).__name__}: {exc}")
    if not (run_dir / "COMPLETE").is_file():
        errors.append("COMPLETE marker is absent")

    phases: dict[str, Any] = {}
    timings: list[tuple[str, dict[str, int]]] = []
    for phase in WORKLOAD_PHASES:
        inspected = inspect_phase(
            run_dir / f"{phase}.json",
            expected_phase_config(
                phase,
                arm=arm,
                poison_token_id=poison_token_id,
                return_token_ids=gate,
            ),
            require_detailed_metrics=gate,
            require_positive_detailed_aggregate=(
                gate and phase == "intervention"
            ),
            forced_token_id=(
                poison_token_id
                if gate and arm == "attack" and phase == "intervention"
                else None
            ),
        )
        phases[phase] = inspected
        errors.extend(
            f"{phase}.json: {error}" for error in inspected["errors"]
        )
        if inspected["timing"] is not None:
            timings.append((phase, inspected["timing"]))
    if len(timings) == len(WORKLOAD_PHASES):
        for (left_name, left), (right_name, right) in zip(
            timings, timings[1:], strict=False
        ):
            if left["finished_ns"] > right["started_ns"]:
                errors.append(f"{left_name} overlaps or follows {right_name}")

    state_summary: dict[str, Any] = {}
    budget: dict[str, Any] | None = None
    reset = startup_reset_evidence(run_dir)
    errors.extend(f"startup reset: {error}" for error in reset["errors"])
    if gate:
        states: dict[str, dict[str, Any]] = {}
        for phase in WORKLOAD_PHASES:
            state, state_errors = estimator_state(
                run_dir / f"state_{phase}.json"
            )
            errors.extend(
                f"state_{phase}.json: {error}" for error in state_errors
            )
            if state is not None:
                states[phase] = state
        if "pre_04" in states and "intervention" in states:
            before = finite_number(states["pre_04"]["intercepts"][0])
            after = finite_number(states["intervention"]["intercepts"][0])
            if before is not None and after is not None:
                state_summary = {
                    "pre_04_intercept0": before,
                    "intervention_intercept0": after,
                    "intervention_delta_intercept0": after - before,
                }
        budget = raw_budget_trace(run_dir / "server.log")
        errors.extend(f"server.log: {error}" for error in budget["errors"])

    return {
        "valid": not errors,
        "errors": errors,
        "metadata": metadata,
        "phases": phases,
        "estimator": state_summary,
        "startup_reset": reset,
        "budget": budget,
    }


def validate_rules(result_root: Path, rules_path: Path) -> dict[str, Any]:
    errors: list[str] = []
    digest: str | None = None
    try:
        raw = rules_path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        text = raw.decode()
        normalized = (
            text.replace("≤", "<=")
            .replace("≥", ">=")
            .replace("−", "-")
            .replace("`", "")
            .replace("*", "")
        )
        for name, pattern in RULE_PATTERNS.items():
            if not pattern.search(normalized):
                errors.append(f"rules do not declare {name}")
        declared = result_root / "DECLARED_DECISION_RULES.md"
        if declared.read_bytes() != raw:
            errors.append("DECLARED_DECISION_RULES.md is not byte-identical")
        sidecar = result_root / "DECLARED_DECISION_RULES.md.sha256"
        fields = sidecar.read_text().strip().split()
        if len(fields) != 2:
            errors.append("decision-rules SHA-256 sidecar is malformed")
        elif fields != [digest, declared.name]:
            errors.append("decision-rules SHA-256 sidecar does not match")
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append(f"rules: {type(exc).__name__}: {exc}")
    return {"valid": not errors, "errors": errors, "sha256": digest}


def validate_declared_inputs(
    result_root: Path, rules_path: Path
) -> dict[str, Any]:
    errors: list[str] = []
    schedule: dict[str, Any] | None = None
    schedule_path = result_root / "DECLARED_SCHEDULE.json"
    try:
        schedule = load_object(schedule_path)
        if schedule != expected_declared_schedule():
            errors.append("DECLARED_SCHEDULE.json does not match fixed protocol")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"DECLARED_SCHEDULE.json: {type(exc).__name__}: {exc}")
    errors.extend(
        validate_sha_sidecar(
            schedule_path,
            result_root / "DECLARED_SCHEDULE.json.sha256",
        )
    )

    declared_hashes: dict[str, str] = {}
    try:
        for line_number, line in enumerate(
            (result_root / "DECLARED_INPUTS.sha256").read_text().splitlines(),
            start=1,
        ):
            match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
            if match is None:
                errors.append(
                    f"DECLARED_INPUTS.sha256 line {line_number} is malformed"
                )
                continue
            digest, name = match.groups()
            if name in declared_hashes:
                errors.append(f"DECLARED_INPUTS.sha256 repeats {name}")
            declared_hashes[name] = digest
        if set(declared_hashes) != set(DECLARED_INPUT_FILES):
            errors.append("DECLARED_INPUTS.sha256 has the wrong file inventory")
        for name in DECLARED_INPUT_FILES:
            declared = declared_hashes.get(name)
            if declared is None:
                continue
            actual_path = rules_path.parent / name
            if file_sha256(actual_path) != declared:
                errors.append(f"declared input hash mismatch: {name}")
    except OSError as exc:
        errors.append(f"DECLARED_INPUTS.sha256: {type(exc).__name__}: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "schedule": schedule,
        "input_hashes": declared_hashes,
    }


def validate_run_provenance(
    result_root: Path,
    rules_path: Path,
    *,
    performance_present: bool,
) -> dict[str, Any]:
    errors: list[str] = []
    sequence = ["screen", "gate_placebo", "gate_attack"]
    if performance_present:
        orders = expected_declared_schedule()["performance_orders"]
        for pair_number, arms in enumerate(orders, start=1):
            pair_id = f"{pair_number:02d}"
            sequence.extend(
                f"perf_pair_{pair_id}_{arm}" for arm in arms
            )

    manifest_path = rules_path.parent / "manifest.txt"
    try:
        manifest = manifest_path.read_bytes()
    except OSError as exc:
        manifest = None
        errors.append(f"manifest.txt: {type(exc).__name__}: {exc}")

    try:
        declared_text = (result_root / "DECLARED_AT_UTC.txt").read_text()
        declared_at, timestamp_error = parse_aware_timestamp(
            declared_text, "DECLARED_AT_UTC.txt"
        )
        if timestamp_error is not None:
            errors.append(timestamp_error)
    except OSError as exc:
        declared_at = None
        errors.append(f"DECLARED_AT_UTC.txt: {type(exc).__name__}: {exc}")

    timeline: list[dict[str, Any]] = []
    for name in sequence:
        run_dir = result_root / name
        created_at: datetime | None = None
        completed_at: datetime | None = None
        try:
            metadata = load_object(run_dir / "metadata.json")
            created_at, timestamp_error = parse_aware_timestamp(
                metadata.get("created_at"), f"{name}/metadata.created_at"
            )
            if timestamp_error is not None:
                errors.append(timestamp_error)
        except (OSError, ValueError, TypeError) as exc:
            errors.append(f"{name}/metadata.json: {type(exc).__name__}: {exc}")
        try:
            complete_text = (run_dir / "COMPLETE").read_text()
            completed_at, timestamp_error = parse_aware_timestamp(
                complete_text, f"{name}/COMPLETE"
            )
            if timestamp_error is not None:
                errors.append(timestamp_error)
        except OSError as exc:
            errors.append(f"{name}/COMPLETE: {type(exc).__name__}: {exc}")
        if (
            created_at is not None
            and completed_at is not None
            and created_at >= completed_at
        ):
            errors.append(f"{name} completion is not after creation")
        if manifest is not None:
            try:
                if (run_dir / "environment.txt").read_bytes() != manifest:
                    errors.append(f"{name}/environment.txt differs from manifest")
            except OSError as exc:
                errors.append(
                    f"{name}/environment.txt: {type(exc).__name__}: {exc}"
                )
        timeline.append(
            {
                "run": name,
                "created_at": created_at,
                "completed_at": completed_at,
            }
        )

    if declared_at is not None and timeline:
        first_created = timeline[0]["created_at"]
        if first_created is not None and declared_at >= first_created:
            errors.append("protocol declaration is not before screen creation")
    for left, right in zip(timeline, timeline[1:], strict=False):
        completed_at = left["completed_at"]
        created_at = right["created_at"]
        if (
            completed_at is not None
            and created_at is not None
            and completed_at > created_at
        ):
            errors.append(
                f"process order violation: {left['run']} before {right['run']}"
            )
    rendered_timeline = [
        {
            "run": item["run"],
            "created_at": (
                item["created_at"].isoformat()
                if item["created_at"] is not None
                else None
            ),
            "completed_at": (
                item["completed_at"].isoformat()
                if item["completed_at"] is not None
                else None
            ),
        }
        for item in timeline
    ]
    return {
        "valid": not errors,
        "errors": errors,
        "fixed_process_order": sequence,
        "timeline": rendered_timeline,
        "manifest_sha256": (
            hashlib.sha256(manifest).hexdigest() if manifest is not None else None
        ),
    }


def _normalized_post_metrics(
    run: dict[str, Any]
) -> dict[str, dict[str, float]]:
    pre_means: dict[str, float] = {}
    for metric in METRICS:
        pre_values = [
            run["phases"][phase]["metrics"].get(metric)
            for phase in PRE_PHASES
        ]
        if any(finite_number(value) is None for value in pre_values):
            continue
        pre_mean = statistics.fmean(float(value) for value in pre_values)
        if pre_mean > 0:
            pre_means[metric] = pre_mean
    normalized: dict[str, dict[str, float]] = {}
    for phase in POST_PHASES:
        normalized[phase] = {}
        for metric, pre_mean in pre_means.items():
            post_value = finite_number(
                run["phases"][phase]["metrics"].get(metric)
            )
            if post_value is not None:
                normalized[phase][metric] = post_value / pre_mean
    return normalized


def _recovery_summary(
    values_by_phase: dict[str, float], metric: str
) -> dict[str, Any]:
    values = [values_by_phase[phase] for phase in POST_PHASES]

    def adverse(value: float) -> bool:
        return value < 0 if metric == "throughput" else value > 0

    adverse_values = [value for value in values if adverse(value)]
    first_sustained = None
    for index, phase in enumerate(POST_PHASES):
        if all(not adverse(value) for value in values[index:]):
            first_sustained = phase
            break
    return {
        "post_01": values[0],
        "post_08": values[-1],
        "mean_over_8": statistics.fmean(values),
        "worst_adverse": (
            min(adverse_values)
            if metric == "throughput" and adverse_values
            else max(adverse_values)
            if adverse_values
            else None
        ),
        "adverse_window_count": len(adverse_values),
        "first_sustained_non_adverse_window": first_sustained,
    }


def inspect_performance(
    result_root: Path,
    poison_token_id: int | None,
    *,
    required: bool,
) -> dict[str, Any]:
    expected_names = {
        f"perf_pair_{pair_id}_{arm}"
        for pair_id in (f"{index:02d}" for index in range(1, 5))
        for arm in ("attack", "placebo")
    }
    try:
        present_names = {
            path.name
            for path in result_root.iterdir()
            if path.is_dir() and PERFORMANCE_RUN_PATTERN.fullmatch(path.name)
        }
    except OSError:
        present_names = set()
    present = bool(present_names)
    errors: list[str] = []
    if not present:
        if required:
            errors.append("performance cohort is required but absent")
        return {
            "present": False,
            "required": required,
            "valid": not errors,
            "errors": errors,
            "exploratory_only": True,
            "runs": {},
            "paired_post1_effects": None,
            "recovery_trajectory": None,
            "classification": "EXPLORATORY_INCONCLUSIVE",
        }
    if present_names != expected_names:
        missing = sorted(expected_names - present_names)
        unexpected = sorted(present_names - expected_names)
        if missing:
            errors.append("missing performance runs: " + ", ".join(missing))
        if unexpected:
            errors.append(
                "unexpected performance runs: " + ", ".join(unexpected)
            )
    if poison_token_id is None:
        errors.append("performance cohort cannot be tied to a selected token")

    runs: dict[str, Any] = {}
    if poison_token_id is not None:
        for name in sorted(expected_names & present_names):
            match = PERFORMANCE_RUN_PATTERN.fullmatch(name)
            assert match is not None
            pair_id, arm = match.groups()
            inspected = inspect_experimental_run(
                result_root / name,
                stage="performance",
                pair_id=pair_id,
                arm=arm,
                poison_token_id=poison_token_id,
            )
            runs[name] = inspected
            errors.extend(f"{name}: {error}" for error in inspected["errors"])

    paired: dict[str, Any] | None = None
    trajectory: dict[str, Any] | None = None
    classification = "EXPLORATORY_INCONCLUSIVE"
    if not errors and len(runs) == 8:
        per_pair: dict[str, dict[str, Any]] = {}
        effects: dict[str, dict[str, list[float]]] = {
            phase: {metric: [] for metric in METRICS}
            for phase in POST_PHASES
        }
        for pair_id in (f"{index:02d}" for index in range(1, 5)):
            attack = _normalized_post_metrics(
                runs[f"perf_pair_{pair_id}_attack"]
            )
            placebo = _normalized_post_metrics(
                runs[f"perf_pair_{pair_id}_placebo"]
            )
            pair_windows: dict[str, Any] = {}
            for phase in POST_PHASES:
                pair_effects = {
                    metric: attack[phase][metric] - placebo[phase][metric]
                    for metric in METRICS
                }
                pair_windows[phase] = {
                    "attack_normalized": attack[phase],
                    "placebo_normalized": placebo[phase],
                    "attack_minus_placebo": pair_effects,
                }
                for metric, value in pair_effects.items():
                    effects[phase][metric].append(value)
            per_pair[pair_id] = pair_windows
        aggregate = {
            phase: {
                metric: bootstrap_mean_ci(values)
                for metric, values in phase_effects.items()
            }
            for phase, phase_effects in effects.items()
        }
        per_pair_recovery = {
            pair_id: {
                metric: _recovery_summary(
                    {
                        phase: windows[phase]["attack_minus_placebo"][metric]
                        for phase in POST_PHASES
                    },
                    metric,
                )
                for metric in METRICS
            }
            for pair_id, windows in per_pair.items()
        }
        aggregate_recovery = {
            metric: _recovery_summary(
                {
                    phase: aggregate[phase][metric]["mean"]
                    for phase in POST_PHASES
                },
                metric,
            )
            for metric in METRICS
        }
        trajectory = {
            "definition": (
                "per-arm post window/pre-window mean; paired effect is "
                "attack minus placebo"
            ),
            "per_pair": per_pair,
            "aggregate": aggregate,
            "recovery_summary": {
                "per_pair": per_pair_recovery,
                "aggregate": aggregate_recovery,
            },
        }
        post1_per_pair = {
            pair_id: windows["post_01"]["attack_minus_placebo"]
            for pair_id, windows in per_pair.items()
        }
        post1_bootstrap = aggregate["post_01"]
        paired = {
            "definition": (
                "attack post_01/pre-window-mean minus "
                "placebo post_01/pre-window-mean"
            ),
            "per_pair": post1_per_pair,
            "bootstrap": post1_bootstrap,
        }
        throughput_values = [
            pair["throughput"] for pair in post1_per_pair.values()
        ]
        negative_count = sum(value < 0 for value in throughput_values)
        upper = finite_number(post1_bootstrap["throughput"]["ci95_high"])
        if negative_count >= 3 and upper is not None and upper < 0:
            classification = "EXPLORATORY_SHORT_HORIZON_SIGNAL"
        paired["throughput_negative_pairs"] = negative_count
    return {
        "present": present,
        "required": required,
        "valid": not errors,
        "errors": errors,
        "exploratory_only": True,
        "runs": runs,
        "paired_post1_effects": paired,
        "recovery_trajectory": trajectory,
        "classification": classification,
    }


def potency_result(
    attack: dict[str, Any], placebo: dict[str, Any]
) -> dict[str, Any]:
    attack_acceptance = attack["phases"]["intervention"].get(
        "draft_acceptance_rate"
    )
    placebo_acceptance = placebo["phases"]["intervention"].get(
        "draft_acceptance_rate"
    )
    acceptance_gap = None
    if (
        finite_number(attack_acceptance) is not None
        and finite_number(placebo_acceptance) is not None
    ):
        acceptance_gap = placebo_acceptance - attack_acceptance

    attack_delta = attack["estimator"].get(
        "intervention_delta_intercept0"
    )
    placebo_delta = placebo["estimator"].get(
        "intervention_delta_intercept0"
    )
    delta_delta = None
    if (
        finite_number(attack_delta) is not None
        and finite_number(placebo_delta) is not None
    ):
        delta_delta = attack_delta - placebo_delta

    attack_budget = None
    placebo_budget = None
    if attack.get("budget") is not None:
        attack_pre = [
            attack["budget"]["phases"][phase].get(
                "mean_normalized_budget"
            )
            for phase in PRE_PHASES
        ]
        attack_post = attack["budget"]["phases"]["post_01"].get(
            "mean_normalized_budget"
        )
        if (
            all(finite_number(value) is not None for value in attack_pre)
            and finite_number(attack_post) is not None
        ):
            attack_pre_mean = statistics.fmean(attack_pre)
            if attack_pre_mean > 0:
                attack_budget = attack_post / attack_pre_mean
    if placebo.get("budget") is not None:
        placebo_pre = [
            placebo["budget"]["phases"][phase].get(
                "mean_normalized_budget"
            )
            for phase in PRE_PHASES
        ]
        placebo_post = placebo["budget"]["phases"]["post_01"].get(
            "mean_normalized_budget"
        )
        if (
            all(finite_number(value) is not None for value in placebo_pre)
            and finite_number(placebo_post) is not None
        ):
            placebo_pre_mean = statistics.fmean(placebo_pre)
            if placebo_pre_mean > 0:
                placebo_budget = placebo_post / placebo_pre_mean
    budget_effect = None
    if (
        finite_number(attack_budget) is not None
        and finite_number(placebo_budget) is not None
    ):
        budget_effect = attack_budget - placebo_budget

    checks = {
        "attack_acceptance": threshold_at_most(
            attack_acceptance,
            POTENCY_THRESHOLDS["attack_acceptance_max"],
        ),
        "placebo_minus_attack_acceptance": threshold_at_least(
            acceptance_gap,
            POTENCY_THRESHOLDS["placebo_minus_attack_acceptance_min"],
        ),
        "intercept0_delta_delta": threshold_at_most(
            delta_delta,
            POTENCY_THRESHOLDS["intercept0_delta_delta_max"],
        ),
        "post1_budget_attack_minus_placebo": threshold_at_most(
            budget_effect,
            POTENCY_THRESHOLDS[
                "post1_budget_attack_minus_placebo_max"
            ],
        ),
    }
    return {
        "thresholds": POTENCY_THRESHOLDS,
        "observed": {
            "attack_acceptance": attack_acceptance,
            "placebo_acceptance": placebo_acceptance,
            "placebo_minus_attack_acceptance": acceptance_gap,
            "attack_intercept0_delta": attack_delta,
            "placebo_intercept0_delta": placebo_delta,
            "intercept0_delta_delta": delta_delta,
            "attack_post1_over_pre_budget_mean": attack_budget,
            "placebo_post1_over_pre_budget_mean": placebo_budget,
            "post1_budget_attack_minus_placebo": budget_effect,
        },
        "gates": checks,
        "pass": all(checks.values()),
    }


HEX_SHA256 = re.compile(r"[0-9a-f]{64}")


def validate_tenant_declaration(result_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    payload: dict[str, Any] = {}
    path = result_root / "DECLARED_TENANTS.json"
    try:
        payload = load_object(path)
        expected_fields = {
            "schema_version",
            "protocol_version",
            "gateway_url",
            "upstream_url",
            "tenants",
            "upstream_key_sha256",
        }
        if set(payload) != expected_fields:
            errors.append("declaration has unexpected or missing fields")
        if payload.get("schema_version") != 1:
            errors.append("schema_version is not 1")
        if payload.get("protocol_version") != PROTOCOL_VERSION:
            errors.append("protocol_version does not match")
        if payload.get("gateway_url") != BASE_URL:
            errors.append("gateway_url does not match")
        if payload.get("upstream_url") != "http://127.0.0.1:8000/v1":
            errors.append("upstream_url does not match")
        tenants = payload.get("tenants")
        if not isinstance(tenants, dict) or set(tenants) != {"attacker", "victim"}:
            errors.append("tenants must contain exactly attacker and victim")
            fingerprints: list[str] = []
        else:
            fingerprints = []
            for tenant in ("attacker", "victim"):
                entry = tenants.get(tenant)
                if not isinstance(entry, dict) or set(entry) != {"key_sha256"}:
                    errors.append(f"{tenant} declaration fields are invalid")
                value = entry.get("key_sha256") if isinstance(entry, dict) else None
                if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
                    errors.append(f"{tenant} key fingerprint is invalid")
                else:
                    fingerprints.append(value)
        upstream = payload.get("upstream_key_sha256")
        if not isinstance(upstream, str) or HEX_SHA256.fullmatch(upstream) is None:
            errors.append("upstream key fingerprint is invalid")
        else:
            fingerprints.append(upstream)
        if len(fingerprints) == 3 and len(set(fingerprints)) != 3:
            errors.append("tenant and upstream key fingerprints are not distinct")
        errors.extend(
            validate_sha_sidecar(
                path, result_root / "DECLARED_TENANTS.json.sha256"
            )
        )
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"DECLARED_TENANTS.json: {type(exc).__name__}: {exc}")
    return {"valid": not errors, "errors": errors, "declaration": payload}


def _load_audit(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        return [], [f"{type(exc).__name__}: {exc}"]
    if not lines:
        return [], ["audit log is empty"]
    for line_number, line in enumerate(lines, start=1):
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("event is not an object")
            events.append(event)
        except (json.JSONDecodeError, ValueError) as exc:
            errors.append(f"line {line_number}: {type(exc).__name__}: {exc}")
    event_ids = [event.get("event_id") for event in events]
    if any(not isinstance(event_id, str) or not event_id for event_id in event_ids):
        errors.append("an audit event has no valid event_id")
    elif len(set(event_ids)) != len(event_ids):
        errors.append("audit event IDs are not unique")
    return events, errors


def _tenant_phase_map(run_name: str) -> dict[str, str]:
    if run_name == "screen":
        return {
            "warmup": "victim",
            **{f"token_{token_id}": "attacker" for token_id in SCREEN_TOKEN_IDS},
        }
    return {
        phase: "attacker" if phase == "intervention" else "victim"
        for phase in WORKLOAD_PHASES
    }


def validate_tenant_run(
    run_dir: Path, declaration: dict[str, Any]
) -> dict[str, Any]:
    errors: list[str] = []
    run_name = run_dir.name
    tenants = declaration.get("tenants")
    fingerprints = {
        name: tenants.get(name, {}).get("key_sha256")
        if isinstance(tenants, dict)
        else None
        for name in ("attacker", "victim")
    }
    topology: dict[str, Any] = {}
    gateway_instance: str | None = None
    upstream_marker: str | None = None
    try:
        topology = load_object(run_dir / "tenant_topology.json")
        if set(topology) != {
            "schema_version",
            "protocol_version",
            "run_name",
            "gateway",
            "upstream",
            "key_fingerprints",
        }:
            errors.append("topology has unexpected or missing fields")
        for field, expected in (
            ("schema_version", 1),
            ("protocol_version", PROTOCOL_VERSION),
            ("run_name", run_name),
        ):
            if topology.get(field) != expected:
                errors.append(f"topology.{field} does not match")
        gateway = topology.get("gateway")
        upstream = topology.get("upstream")
        if (
            not isinstance(gateway, dict)
            or set(gateway) != {"listen", "instance_id"}
            or gateway.get("listen") != "127.0.0.1:8001"
        ):
            errors.append("topology gateway is invalid")
        else:
            gateway_instance = gateway.get("instance_id")
            if not isinstance(gateway_instance, str) or not gateway_instance:
                errors.append("topology gateway instance is invalid")
        if (
            not isinstance(upstream, dict)
            or set(upstream)
            != {"listen", "marker", "server_pid", "server_pgid"}
            or upstream.get("listen") != "127.0.0.1:8000"
        ):
            errors.append("topology upstream is invalid")
        else:
            upstream_marker = upstream.get("marker")
            if not isinstance(upstream_marker, str) or not upstream_marker:
                errors.append("topology upstream marker is invalid")
            for filename, field in (
                ("server.pid", "server_pid"),
                ("server.pgid", "server_pgid"),
            ):
                observed = int((run_dir / filename).read_text().strip())
                if upstream.get(field) != observed:
                    errors.append(f"topology {field} differs from {filename}")
            marker_file = (run_dir / "server.marker").read_text().strip()
            if upstream_marker != marker_file:
                errors.append("topology marker differs from server.marker")
        expected_fingerprints = {
            **fingerprints,
            "upstream": declaration.get("upstream_key_sha256"),
        }
        if topology.get("key_fingerprints") != expected_fingerprints:
            errors.append("topology fingerprints differ from declaration")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"tenant_topology.json: {type(exc).__name__}: {exc}")

    auth_event_ids: set[str] = set()
    auth_event_expectations: dict[str, dict[str, Any]] = {}
    try:
        auth = load_object(run_dir / "auth_self_test.json")
        if auth.get("schema_version") != 1 or auth.get("valid") is not True:
            errors.append("auth self-test is not valid")
        if auth.get("base_url") != BASE_URL:
            errors.append("auth self-test base URL differs")
        cases = {
            "attacker_ok": (200, "attacker"),
            "victim_ok": (200, "victim"),
            "missing_key": (401, None),
            "wrong_key": (401, None),
            "attacker_claims_victim": (403, None),
            "victim_claims_attacker": (403, None),
        }
        raw_results = auth.get("results")
        by_name = {
            item.get("name"): item
            for item in raw_results
            if isinstance(item, dict)
        } if isinstance(raw_results, list) else {}
        if set(by_name) != set(cases):
            errors.append("auth self-test cases are incomplete or unexpected")
        for name, (status, tenant) in cases.items():
            item = by_name.get(name, {})
            if item.get("status") != status or item.get("expected_status") != status:
                errors.append(f"auth self-test {name} status differs")
            if item.get("authenticated_tenant") != tenant:
                errors.append(f"auth self-test {name} tenant differs")
            if item.get("gateway_instance_id") != gateway_instance:
                errors.append(f"auth self-test {name} gateway differs")
            if item.get("upstream_marker") != upstream_marker:
                errors.append(f"auth self-test {name} upstream differs")
            event_id = item.get("audit_event_id")
            if not isinstance(event_id, str) or not event_id:
                errors.append(f"auth self-test {name} lacks an audit event")
            else:
                auth_event_ids.add(event_id)
                actual_tenant = {
                    "attacker_ok": "attacker",
                    "victim_ok": "victim",
                    "attacker_claims_victim": "attacker",
                    "victim_claims_attacker": "victim",
                }.get(name)
                claimed_tenant = {
                    "attacker_ok": "attacker",
                    "victim_ok": "victim",
                    "missing_key": "victim",
                    "wrong_key": "victim",
                    "attacker_claims_victim": "victim",
                    "victim_claims_attacker": "attacker",
                }[name]
                auth_event_expectations[event_id] = {
                    "status": status,
                    "authenticated_tenant": actual_tenant,
                    "claimed_principal": claimed_tenant,
                    "forwarded": status == 200,
                    "key_sha256": (
                        fingerprints[actual_tenant]
                        if actual_tenant is not None
                        else (
                            hashlib.sha256(
                                b"invalid-key-material-for-negative-control"
                            ).hexdigest()
                            if name == "wrong_key"
                            else None
                        )
                    ),
                }
        if len(auth_event_ids) != len(cases):
            errors.append("auth self-test event IDs are not unique")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"auth_self_test.json: {type(exc).__name__}: {exc}")

    audit, audit_errors = _load_audit(run_dir / "gateway_audit.jsonl")
    errors.extend(f"gateway audit: {error}" for error in audit_errors)
    audit_by_id = {
        event["event_id"]: event
        for event in audit
        if isinstance(event.get("event_id"), str)
    }
    workload_event_ids: set[str] = set()
    for phase, tenant in _tenant_phase_map(run_name).items():
        try:
            payload = load_object(run_dir / f"{phase}.json")
            config = payload.get("config")
            if not isinstance(config, dict):
                raise ValueError("config is not an object")
            expected_config = {
                "principal": tenant,
                "run_id": run_name,
                "tenant_key_sha256": fingerprints[tenant],
                "gateway_instance_id": gateway_instance,
                "upstream_marker": upstream_marker,
            }
            for field, expected in expected_config.items():
                if config.get(field) != expected:
                    errors.append(f"{phase}.json config.{field} differs")
            records = payload.get("records")
            if not isinstance(records, list):
                raise ValueError("records is not a list")
            for index, record in enumerate(records):
                if not isinstance(record, dict):
                    errors.append(f"{phase}.json record {index} is invalid")
                    continue
                request_id = f"avep-{run_name}-{tenant}-{phase}-{index:05d}"
                expected_record = {
                    "request_id": request_id,
                    "authenticated_tenant": tenant,
                    "gateway_instance_id": gateway_instance,
                    "upstream_marker": upstream_marker,
                }
                for field, expected in expected_record.items():
                    if record.get(field) != expected:
                        errors.append(f"{phase}.json record {index} {field} differs")
                event_id = record.get("audit_event_id")
                if not isinstance(event_id, str) or not event_id:
                    errors.append(f"{phase}.json record {index} lacks audit evidence")
                    continue
                if event_id in workload_event_ids:
                    errors.append("a workload audit event is reused")
                workload_event_ids.add(event_id)
                event = audit_by_id.get(event_id)
                if event is None:
                    errors.append(f"{phase}.json record {index} audit event is missing")
                    continue
                expected_event = {
                    "schema_version": 1,
                    "gateway_instance_id": gateway_instance,
                    "authenticated_tenant": tenant,
                    "key_sha256": fingerprints[tenant],
                    "claimed_principal": tenant,
                    "method": "POST",
                    "path": "/v1/completions",
                    "purpose": "workload",
                    "request_id": request_id,
                    "status": 200,
                    "forwarded": True,
                    "upstream_host": "127.0.0.1",
                    "upstream_port": 8000,
                    "upstream_marker": upstream_marker,
                }
                for field, expected in expected_event.items():
                    if event.get(field) != expected:
                        errors.append(f"audit {event_id} field {field} differs")
                times = (
                    nonnegative_integer(record.get("started_ns")),
                    nonnegative_integer(event.get("received_ns")),
                    nonnegative_integer(event.get("finished_ns")),
                    nonnegative_integer(record.get("finished_ns")),
                )
                invalid_timing = any(value is None for value in times)
                if invalid_timing or list(times) != sorted(times):
                    errors.append(f"audit {event_id} timing is inconsistent")
        except (OSError, ValueError, TypeError) as exc:
            errors.append(f"{phase}.json tenant evidence: {type(exc).__name__}: {exc}")

    for event_id in auth_event_ids:
        event = audit_by_id.get(event_id)
        if event is None:
            errors.append(f"auth audit event {event_id} is missing")
            continue
        expected_auth_event = {
            "schema_version": 1,
            "gateway_instance_id": gateway_instance,
            "method": "GET",
            "path": "/v1/models",
            "purpose": "auth-self-test",
            "request_id": None,
            "upstream_host": "127.0.0.1",
            "upstream_port": 8000,
            "upstream_marker": upstream_marker,
            **auth_event_expectations[event_id],
        }
        for field, expected in expected_auth_event.items():
            if event.get(field) != expected:
                errors.append(f"auth audit {event_id} field {field} differs")
    if set(audit_by_id) != workload_event_ids | auth_event_ids:
        errors.append("gateway audit contains missing or unjoined events")
    if any(
        event.get("gateway_instance_id") != gateway_instance
        or event.get("upstream_marker") != upstream_marker
        for event in audit
    ):
        errors.append("gateway audit crosses gateway instances or workers")
    return {
        "valid": not errors,
        "errors": errors,
        "run_name": run_name,
        "gateway_instance_id": gateway_instance,
        "upstream_marker": upstream_marker,
        "workload_event_count": len(workload_event_ids),
        "auth_event_count": len(auth_event_ids),
    }


def validate_tenant_evidence(
    result_root: Path, *, performance_present: bool
) -> dict[str, Any]:
    declaration = validate_tenant_declaration(result_root)
    errors = [f"declaration: {error}" for error in declaration["errors"]]
    run_names = ["screen", "gate_placebo", "gate_attack"]
    if performance_present:
        for pair_number, arms in enumerate(
            expected_declared_schedule()["performance_orders"], start=1
        ):
            pair_id = f"{pair_number:02d}"
            run_names.extend(f"perf_pair_{pair_id}_{arm}" for arm in arms)
    runs: dict[str, Any] = {}
    for run_name in run_names:
        run = validate_tenant_run(
            result_root / run_name, declaration["declaration"]
        )
        runs[run_name] = run
        errors.extend(f"{run_name}: {error}" for error in run["errors"])
    return {
        "valid": not errors,
        "errors": errors,
        "declaration": declaration,
        "runs": runs,
        "claim_scope": "two proxy-authenticated principals on one vLLM worker",
    }


def analyze(
    result_root: Path,
    rules_path: Path,
    *,
    require_performance: bool = False,
    gate_only: bool = False,
) -> dict[str, Any]:
    if gate_only and require_performance:
        raise ValueError("gate_only and require_performance are mutually exclusive")
    errors: list[str] = []
    rules = validate_rules(result_root, rules_path)
    errors.extend(f"rules: {error}" for error in rules["errors"])
    declarations = validate_declared_inputs(result_root, rules_path)
    errors.extend(
        f"declarations: {error}" for error in declarations["errors"]
    )
    screen = inspect_screen(result_root)
    errors.extend(f"screen: {error}" for error in screen["errors"])

    selected_token_id = screen.get("selected_token_id")
    gate_runs: dict[str, Any] = {}
    if nonnegative_integer(selected_token_id) is not None:
        for arm in ("attack", "placebo"):
            name = f"gate_{arm}"
            inspected = inspect_experimental_run(
                result_root / name,
                stage="gate",
                pair_id="gate",
                arm=arm,
                poison_token_id=selected_token_id,
            )
            gate_runs[arm] = inspected
            errors.extend(f"{name}: {error}" for error in inspected["errors"])
    else:
        errors.append("gate runs cannot be tied to a valid selected token")

    if set(gate_runs) == {"attack", "placebo"}:
        potency = potency_result(gate_runs["attack"], gate_runs["placebo"])
    else:
        potency = {
            "thresholds": POTENCY_THRESHOLDS,
            "observed": {},
            "gates": {},
            "pass": False,
        }

    if gate_only:
        performance = {
            "present": False,
            "required": False,
            "valid": True,
            "errors": [],
            "exploratory_only": True,
            "runs": {},
            "paired_post1_effects": None,
            "recovery_trajectory": None,
            "classification": "EXPLORATORY_INCONCLUSIVE",
            "ignored_by_gate_only": True,
        }
    else:
        performance = inspect_performance(
            result_root,
            selected_token_id,
            required=require_performance,
        )
    errors.extend(
        f"performance: {error}" for error in performance["errors"]
    )
    if performance["present"] and not potency["pass"]:
        errors.append("performance artifacts exist after a failed potency gate")
    provenance = validate_run_provenance(
        result_root,
        rules_path,
        performance_present=performance["present"],
    )
    errors.extend(
        f"provenance: {error}" for error in provenance["errors"]
    )
    tenant_evidence = validate_tenant_evidence(
        result_root, performance_present=performance["present"]
    )
    errors.extend(
        f"tenant evidence: {error}" for error in tenant_evidence["errors"]
    )
    structural_valid = not errors
    if not structural_valid:
        potency["pass"] = False
    classification = (
        performance["classification"]
        if structural_valid
        else "EXPLORATORY_INCONCLUSIVE"
    )
    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "analysis_mode": "gate_only" if gate_only else "full",
        "structural_valid": structural_valid,
        "valid": structural_valid,
        "errors": errors,
        "rules": rules,
        "declarations": declarations,
        "provenance": provenance,
        "tenant_evidence": tenant_evidence,
        "screen": screen,
        "gate": gate_runs,
        "potency": potency,
        "performance": performance,
        "classification": classification,
        "interpretation": (
            "bounded two-tenant potency gate with optional exploratory effects"
        ),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--gate-only", action="store_true")
    mode.add_argument("--require-performance", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = analyze(
        args.result_root,
        args.rules,
        require_performance=args.require_performance,
        gate_only=args.gate_only,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    args.output.write_text(rendered)
    print(rendered, end="")
    return 0 if report["structural_valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
