#!/usr/bin/env python
"""Analyze fresh-process AVEP paper trials without pseudo-replication."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any


METRICS = {
    "throughput": "aggregate_output_tokens_per_second",
    "latency_p50": "latency_ms_p50",
    "latency_p95": "latency_ms_p95",
}
PHASE_PATTERN = re.compile(r"===== AVEP_PHASE (\S+)")
BUDGET_PATTERN = re.compile(r"AVEP_BUDGET\s+(\{.*\})")
POST_PHASE_PATTERN = re.compile(r"post_[0-9][0-9]")
RUN_DIR_PATTERN = re.compile(
    r"(?:pair_[0-9][0-9]_(?:attack|placebo)"
    r"|reset_[0-9][0-9]"
    r"|adaptive_off_[0-9][0-9]"
    r"|mechanism_(?:attack|placebo))"
)
REQUIRED_PHASES = ("warmup", "baseline", "intervention")
REQUIRED_POST_PHASES = tuple(f"post_{index:02d}" for index in range(1, 7))
VALID_ARMS = frozenset({"attack", "placebo", "reset", "adaptive_off"})
EXPECTED_RUN_METADATA: dict[str, dict[str, Any]] = {
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


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def ratio(numerator: Any, denominator: Any) -> float | None:
    if numerator is None or denominator in (None, 0):
        return None
    value = float(numerator) / float(denominator)
    return value if math.isfinite(value) else None


def mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


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


def phase_summary(run_dir: Path, phase: str) -> dict[str, Any]:
    return load_json(run_dir / f"{phase}.json")["summary"]


def workload_artifacts(run_dir: Path) -> dict[str, Path]:
    artifacts = {
        phase: run_dir / f"{phase}.json"
        for phase in REQUIRED_PHASES
        if (run_dir / f"{phase}.json").exists()
    }
    artifacts.update(
        {
            path.stem: path
            for path in sorted(run_dir.glob("post_[0-9][0-9].json"))
            if POST_PHASE_PATTERN.fullmatch(path.stem)
        }
    )
    return artifacts


def nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(float(value)):
        return None
    integer = int(value)
    if integer != value or integer < 0:
        return None
    return integer


def phase_inventory(run_dir: Path) -> dict[str, Any]:
    artifacts = workload_artifacts(run_dir)
    failed_by_phase: dict[str, int] = {}
    requests_by_phase: dict[str, int] = {}
    artifact_errors: dict[str, str] = {}
    for phase, path in artifacts.items():
        try:
            payload = load_json(path)
            if not isinstance(payload, dict):
                raise ValueError("top-level artifact is not an object")
            summary = payload.get("summary")
            if not isinstance(summary, dict):
                raise ValueError("top-level summary is missing or is not an object")
            failed = nonnegative_int(summary.get("failed"))
            requests = nonnegative_int(summary.get("requests"))
            if failed is None:
                raise ValueError("summary.failed is not a non-negative integer")
            if requests is None:
                raise ValueError("summary.requests is not a non-negative integer")
            if failed > requests:
                raise ValueError("summary.failed exceeds summary.requests")
            failed_by_phase[phase] = failed
            requests_by_phase[phase] = requests
        except (OSError, ValueError, TypeError) as exc:
            artifact_errors[phase] = f"{type(exc).__name__}: {exc}"

    missing = [
        phase
        for phase in (*REQUIRED_PHASES, *REQUIRED_POST_PHASES)
        if phase not in artifacts
    ]
    return {
        "present_phases": list(artifacts),
        "missing_required_artifacts": missing,
        "artifact_errors": artifact_errors,
        "failed_requests_by_phase": failed_by_phase,
        "requests_by_phase": requests_by_phase,
        "failed_requests": sum(failed_by_phase.values()),
        "failed_requests_warmup": failed_by_phase.get("warmup"),
        "failed_requests_baseline": failed_by_phase.get("baseline"),
        "failed_requests_intervention": failed_by_phase.get("intervention"),
        "failed_requests_post": sum(
            failed
            for phase, failed in failed_by_phase.items()
            if phase.startswith("post_")
        ),
    }


def estimator_state(run_dir: Path, phase: str) -> dict[str, Any] | None:
    path = run_dir / f"state_{phase}.json"
    if not path.exists():
        return None
    payload = load_json(path)
    results = payload.get("results") or []
    if not results or not isinstance(results[0], dict):
        return None
    return results[0]


def exact_output_match(left: Path, right: Path) -> float | None:
    if not left.exists() or not right.exists():
        return None
    left_records = load_json(left).get("records", [])
    right_records = load_json(right).get("records", [])
    count = min(len(left_records), len(right_records))
    if not count:
        return None
    matches = 0
    comparable = 0
    for index in range(count):
        left_ids = left_records[index].get("token_ids") or []
        right_ids = right_records[index].get("token_ids") or []
        if not left_ids or not right_ids:
            continue
        comparable += 1
        matches += left_ids == right_ids
    return matches / comparable if comparable else None


def budget_ratios(server_log: Path) -> dict[str, float]:
    observations: dict[str, list[float]] = defaultdict(list)
    phase: str | None = None
    for line in server_log.read_text(errors="replace").splitlines():
        phase_match = PHASE_PATTERN.search(line)
        if phase_match:
            marker = phase_match.group(1)
            phase = marker.removesuffix("_begin") if marker.endswith("_begin") else None
            continue
        budget_match = BUDGET_PATTERN.search(line)
        if phase is None or not budget_match:
            continue
        row = json.loads(budget_match.group(1))
        if row["max_draft_budget"]:
            observations[phase].append(
                row["draft_budget"] / row["max_draft_budget"]
            )
    return {
        phase_name: statistics.fmean(values)
        for phase_name, values in observations.items()
        if values
    }


def summarize_run(run_dir: Path) -> dict[str, Any]:
    metadata = load_json(run_dir / "metadata.json")
    warmup = phase_summary(run_dir, "warmup")
    baseline = phase_summary(run_dir, "baseline")
    intervention = phase_summary(run_dir, "intervention")
    post_paths = [run_dir / f"{phase}.json" for phase in REQUIRED_POST_PHASES]
    post_summaries = [load_json(path)["summary"] for path in post_paths]
    row: dict[str, Any] = {
        "run": run_dir.name,
        "pair_id": metadata.get("pair_id"),
        "arm": metadata["arm"],
        "adaptive": metadata["adaptive"],
        "telemetry": metadata["telemetry"],
        "poison_token_id": metadata.get("poison_token_id"),
        "post_windows": len(post_summaries),
        "failed_requests": warmup["failed"]
        + baseline["failed"]
        + intervention["failed"]
        + sum(summary["failed"] for summary in post_summaries),
    }
    for short_name, key in METRICS.items():
        baseline_value = baseline.get(key)
        ratios = [ratio(summary.get(key), baseline_value) for summary in post_summaries]
        finite = [value for value in ratios if value is not None]
        row[f"post1_{short_name}_ratio"] = finite[0] if finite else None
        row[f"post_mean_{short_name}_ratio"] = mean(finite)
        if short_name == "throughput":
            row[f"post_worst_{short_name}_ratio"] = min(finite) if finite else None
        else:
            row[f"post_worst_{short_name}_ratio"] = max(finite) if finite else None

    before = estimator_state(run_dir, "baseline")
    after = estimator_state(run_dir, "intervention")
    if before and before.get("available") and after and after.get("available"):
        row["slope_before"] = before["slope"]
        row["slope_after"] = after["slope"]
        row["intercept0_before"] = before["intercepts"][0]
        row["intercept0_after"] = after["intercepts"][0]
    reset = estimator_state(run_dir, "reset")
    if reset and reset.get("available"):
        row["slope_after_reset"] = reset["slope"]
        row["intercept0_after_reset"] = reset["intercepts"][0]
    if metadata["telemetry"]:
        budgets = budget_ratios(run_dir / "server.log")
        row["baseline_budget_ratio"] = budgets.get("baseline")
        row["intervention_budget_ratio"] = budgets.get("intervention")
        row["post1_budget_ratio"] = budgets.get("post_01")
    row["baseline_post1_exact_token_match"] = exact_output_match(
        run_dir / "baseline.json", run_dir / "post_01.json"
    )
    return row


def validate_metadata(metadata: dict[str, Any]) -> None:
    arm = metadata.get("arm")
    if not isinstance(arm, str) or arm not in VALID_ARMS:
        raise ValueError(f"metadata.arm must be one of {sorted(VALID_ARMS)}")
    for field in ("adaptive", "telemetry"):
        if not isinstance(metadata.get(field), bool):
            raise ValueError(f"metadata.{field} must be a boolean")
    pair_id = metadata.get("pair_id")
    if pair_id is not None and not isinstance(pair_id, str):
        raise ValueError("metadata.pair_id must be a string or null")
    token_id = metadata.get("poison_token_id")
    if (
        isinstance(token_id, bool)
        or not isinstance(token_id, int)
        or token_id < 0
    ):
        raise ValueError("metadata.poison_token_id must be a non-negative integer")


def inspect_run(run_dir: Path) -> dict[str, Any]:
    complete_marker = (run_dir / "COMPLETE").exists()
    inventory = phase_inventory(run_dir)
    try:
        metadata = load_json(run_dir / "metadata.json")
        if not isinstance(metadata, dict):
            raise ValueError("metadata is not an object")
        validate_metadata(metadata)
    except (OSError, ValueError, TypeError) as exc:
        return {
            "run": run_dir.name,
            "pair_id": None,
            "arm": None,
            "adaptive": None,
            "telemetry": None,
            "poison_token_id": None,
            "complete_marker": complete_marker,
            "status": "invalid_metadata",
            "eligible_for_analysis": False,
            "exclusion_reasons": [f"{type(exc).__name__}: {exc}"],
            **inventory,
        }

    row: dict[str, Any] = {
        "run": run_dir.name,
        "pair_id": metadata.get("pair_id"),
        "arm": metadata.get("arm"),
        "adaptive": metadata.get("adaptive"),
        "telemetry": metadata.get("telemetry"),
        "poison_token_id": metadata.get("poison_token_id"),
        "complete_marker": complete_marker,
        **inventory,
    }
    reasons: list[str] = []
    if not complete_marker:
        reasons.append("COMPLETE marker is absent")
    if inventory["missing_required_artifacts"]:
        reasons.append(
            "missing required workload artifacts: "
            + ", ".join(inventory["missing_required_artifacts"])
        )
    if inventory["artifact_errors"]:
        reasons.append(
            "unreadable workload artifacts: "
            + ", ".join(sorted(inventory["artifact_errors"]))
        )
    if inventory["failed_requests"]:
        reasons.append(
            f"{inventory['failed_requests']} workload requests failed"
        )

    if complete_marker and not reasons:
        try:
            row.update(summarize_run(run_dir))
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            AttributeError,
        ) as exc:
            reasons.append(f"analysis failed: {type(exc).__name__}: {exc}")

    if not complete_marker:
        if inventory["artifact_errors"]:
            status = "incomplete_artifact_error"
        elif inventory["failed_requests"]:
            status = "incomplete_with_request_failures"
        else:
            status = "incomplete"
    elif inventory["artifact_errors"] or inventory["missing_required_artifacts"]:
        status = "invalid_complete_artifacts"
    elif inventory["failed_requests"]:
        status = "complete_with_request_failures"
    elif reasons:
        status = "invalid_complete_analysis"
    else:
        status = "complete"
    row["status"] = status
    row["eligible_for_analysis"] = status == "complete"
    row["exclusion_reasons"] = reasons
    return row


def paired_effects(rows: list[dict[str, Any]]) -> dict[str, Any]:
    pairs: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        if row["pair_id"] is not None:
            pairs[str(row["pair_id"])][row["arm"]] = row

    effects: dict[str, list[float]] = defaultdict(list)
    complete_pairs = 0
    for arms in pairs.values():
        if "attack" not in arms or "placebo" not in arms:
            continue
        complete_pairs += 1
        attack = arms["attack"]
        placebo = arms["placebo"]
        for metric in METRICS:
            key = f"post_mean_{metric}_ratio"
            if attack.get(key) is not None and placebo.get(key) is not None:
                effects[metric].append(attack[key] - placebo[key])
    return {
        "complete_pairs": complete_pairs,
        "attack_minus_placebo": {
            metric: bootstrap_mean_ci(values)
            for metric, values in sorted(effects.items())
        },
    }


def validate_complete_cohort(rows: list[dict[str, Any]]) -> dict[str, Any]:
    rows_by_name = {row["run"]: row for row in rows}
    expected_names = set(EXPECTED_RUN_METADATA)
    discovered_names = set(rows_by_name)
    missing_runs = sorted(expected_names - discovered_names)
    unexpected_runs = sorted(discovered_names - expected_names)
    incomplete_runs = sorted(
        name
        for name in expected_names & discovered_names
        if not rows_by_name[name]["eligible_for_analysis"]
    )
    metadata_mismatches: dict[str, dict[str, Any]] = {}
    for name in sorted(expected_names & discovered_names):
        row = rows_by_name[name]
        mismatches = {
            field: {"expected": expected, "actual": row.get(field)}
            for field, expected in EXPECTED_RUN_METADATA[name].items()
            if row.get(field) != expected
        }
        if mismatches:
            metadata_mismatches[name] = mismatches

    valid = not (
        missing_runs
        or unexpected_runs
        or incomplete_runs
        or metadata_mismatches
    )
    return {
        "valid": valid,
        "expected_run_count": len(EXPECTED_RUN_METADATA),
        "missing_runs": missing_runs,
        "unexpected_runs": unexpected_runs,
        "incomplete_runs": incomplete_runs,
        "metadata_mismatches": metadata_mismatches,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    args = parser.parse_args()

    run_dirs = sorted(
        path
        for path in args.result_root.iterdir()
        if path.is_dir()
        and (
            (path / "metadata.json").exists()
            or RUN_DIR_PATTERN.fullmatch(path.name)
        )
    )
    all_rows = [inspect_run(run_dir) for run_dir in run_dirs]
    cohort_validation = validate_complete_cohort(all_rows)
    rows = [row for row in all_rows if row["eligible_for_analysis"]]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["arm"]].append(row)
    discovered_grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in all_rows:
        discovered_grouped[str(row["arm"])].append(row)
    status_counts: dict[str, int] = defaultdict(int)
    for row in all_rows:
        status_counts[row["status"]] += 1
    excluded = [
        {
            "run": row["run"],
            "pair_id": row["pair_id"],
            "arm": row["arm"],
            "status": row["status"],
            "failed_requests": row["failed_requests"],
            "failed_requests_by_phase": row["failed_requests_by_phase"],
            "exclusion_reasons": row["exclusion_reasons"],
        }
        for row in all_rows
        if not row["eligible_for_analysis"]
    ]

    assessment = {
        "scope": (
            "Fresh server processes are the experimental units. Per-request "
            "observations are not treated as independent replicates."
        ),
        "run_count": len(rows),
        "discovered_run_count": len(all_rows),
        "excluded_run_count": len(excluded),
        "cohort_validation": cohort_validation,
        "arm_counts": {arm: len(group) for arm, group in sorted(grouped.items())},
        "discovered_arm_counts": {
            arm: len(group) for arm, group in sorted(discovered_grouped.items())
        },
        "run_status_counts": dict(sorted(status_counts.items())),
        "attrition": {
            "discovered_runs": len(all_rows),
            "analyzed_runs": len(rows),
            "excluded_runs": len(excluded),
            "excluded": excluded,
        },
        "paired_analysis": paired_effects(rows),
        "performance_arm_summaries": {
            arm: {
                metric: bootstrap_mean_ci(
                    [
                        row[f"post_mean_{metric}_ratio"]
                        for row in group
                        if row.get(f"post_mean_{metric}_ratio") is not None
                    ]
                )
                for metric in METRICS
            }
            for arm, arm_rows in sorted(grouped.items())
            if (group := [row for row in arm_rows if not row["telemetry"]])
        },
        "runs": all_rows,
    }
    args.output.write_text(json.dumps(assessment, indent=2, sort_keys=True) + "\n")

    fieldnames = sorted({key for row in all_rows for key in row})
    with args.csv_output.open("w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(
            {
                key: (
                    json.dumps(value, sort_keys=True)
                    if isinstance(value, (dict, list))
                    else value
                )
                for key, value in row.items()
            }
            for row in all_rows
        )
    print(json.dumps(assessment, indent=2, sort_keys=True))
    if not cohort_validation["valid"]:
        raise SystemExit("planned cohort is incomplete or invalid")


if __name__ == "__main__":
    main()
