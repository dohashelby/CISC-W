#!/usr/bin/env python
"""Fail-closed analysis for the AVEP v2 factorial confirmation."""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

import analyze_factorial_confirmatory as v1

PROTOCOL_VERSION = "avep-factorial-confirmatory-v2"
RULES_SOURCE = "FACTORIAL_CONFIRMATORY_V2_DECISION_RULES.md"
PROTOCOL_SOURCE = "FACTORIAL_CONFIRMATORY_V2_PROTOCOL.md"
DRIVER_SOURCE = "run_factorial_confirmatory_v2.sh"
ANALYZER_SOURCE = "analyze_factorial_confirmatory_v2.py"
TEST_SOURCE = "test_analyze_factorial_confirmatory_v2.py"

# The shared inspection helpers compare metadata against this module global.
# Set it once before any run is inspected; v1 artifacts are never reclassified.
v1.PROTOCOL_VERSION = PROTOCOL_VERSION

ARMS = v1.ARMS
GATE_ORDER = v1.GATE_ORDER
PERFORMANCE_ORDERS = v1.PERFORMANCE_ORDERS
PRE_PHASES = v1.PRE_PHASES
POST_PHASES = v1.POST_PHASES
METRICS = v1.METRICS


def expected_schedule() -> dict[str, Any]:
    schedule = v1.expected_schedule()
    schedule["protocol_version"] = PROTOCOL_VERSION
    return schedule


def validate_declarations(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    work_dir = root.parent
    try:
        schedule = v1.load_object(root / "DECLARED_SCHEDULE.json")
        if schedule != expected_schedule():
            errors.append("declared schedule does not equal the fixed v2 schedule")
        fields = (root / "DECLARED_SCHEDULE.json.sha256").read_text().split()
        if fields != [
            v1.sha256(root / "DECLARED_SCHEDULE.json"),
            "DECLARED_SCHEDULE.json",
        ]:
            errors.append("schedule SHA-256 sidecar does not match")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"schedule: {type(exc).__name__}: {exc}")
    try:
        if (root / "DECLARED_DECISION_RULES.md").read_bytes() != (
            work_dir / RULES_SOURCE
        ).read_bytes():
            errors.append("declared rules differ from archived v2 rules")
    except OSError as exc:
        errors.append(f"rules: {type(exc).__name__}: {exc}")
    try:
        lines = (root / "DECLARED_INPUTS.sha256").read_text().splitlines()
        if not lines:
            errors.append("declared input hash list is empty")
        for line in lines:
            digest, name = line.split(maxsplit=1)
            name = name.lstrip("* ")
            path = work_dir / name
            if not path.is_file() or v1.sha256(path) != digest:
                errors.append(f"declared input mismatch: {name}")
    except (OSError, ValueError) as exc:
        errors.append(f"inputs: {type(exc).__name__}: {exc}")
    try:
        environment = (work_dir / "factorial_environment.txt").read_text()
        if f"vllm_sha={v1.PINNED_SHA}\n" not in environment:
            errors.append("environment does not identify the pinned vLLM commit")
    except OSError as exc:
        errors.append(f"environment: {type(exc).__name__}: {exc}")
    return {"valid": not errors, "errors": errors}


def normalized_window_mean(
    run: dict[str, Any], key: str, phases: tuple[str, ...] = POST_PHASES
) -> float:
    return statistics.fmean(v1.normalized_metric(run, key, phase) for phase in phases)


def mechanism_gate(runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    checks: dict[str, bool] = {}
    try:
        acceptance: dict[str, float] = {}
        for arm in ARMS:
            value = v1.finite(
                runs[arm]["phases"]["intervention"]["summary"].get(
                    "draft_acceptance_rate"
                )
            )
            if value is None:
                raise ValueError(f"{arm} acceptance is unavailable")
            acceptance[arm] = value
        observed["acceptance_rates"] = acceptance
        checks["attack_acceptance_at_most_0_05"] = (
            acceptance["attack_shared"] <= 0.05
            and acceptance["attack_blocked"] <= 0.05
        )
        checks["attack_acceptance_difference_at_most_0_02"] = abs(
            acceptance["attack_shared"] - acceptance["attack_blocked"]
        ) <= 0.02
        placebo_margins = {
            mode: acceptance[f"placebo_{mode}"] - acceptance[f"attack_{mode}"]
            for mode in ("shared", "blocked")
        }
        observed["placebo_minus_attack_acceptance"] = placebo_margins
        checks["placebo_acceptance_margins_at_least_0_10"] = all(
            value >= 0.10 for value in placebo_margins.values()
        )
        checks["both_blocked_states_invariant"] = all(
            bool(runs[f"{workload}_blocked"]["blocked_state_invariant"])
            for workload in ("placebo", "attack")
        )

        intercept_deltas = {
            arm: v1.estimator_delta(run, "intercepts", 0)
            for arm, run in runs.items()
        }
        observed["intercept0_deltas"] = intercept_deltas
        observed["intercept0_interaction"] = v1.factorial_interaction(
            intercept_deltas
        )
        checks["intercept0_interaction_at_most_minus_0_50"] = (
            observed["intercept0_interaction"] <= -0.50
        )

        budget_trajectories = {
            arm: {
                phase: v1.normalized_budget(run, phase)
                for phase in POST_PHASES
            }
            for arm, run in runs.items()
        }
        budget_interactions = {
            phase: v1.factorial_interaction(
                {
                    arm: budget_trajectories[arm][phase]
                    for arm in ARMS
                }
            )
            for phase in POST_PHASES
        }
        mean_budget_interaction = statistics.fmean(
            budget_interactions.values()
        )
        observed["normalized_post_budget_trajectories"] = budget_trajectories
        observed["normalized_post_budget_interactions"] = budget_interactions
        observed["mean_normalized_post_budget_interaction"] = (
            mean_budget_interaction
        )
        checks["mean_budget_interaction_at_most_minus_0_05"] = (
            mean_budget_interaction <= -0.05
        )
    except (KeyError, TypeError, ValueError, statistics.StatisticsError) as exc:
        observed["error"] = f"{type(exc).__name__}: {exc}"
    return {
        "observed": observed,
        "checks": checks,
        "pass": len(checks) == 6 and all(checks.values()),
    }


def performance_result(runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    interactions: dict[str, list[float]] = {metric: [] for metric in METRICS}
    trajectories: dict[str, list[float]] = {phase: [] for phase in POST_PHASES}
    blocks: list[dict[str, Any]] = []
    errors: list[str] = []
    for block_number in range(1, 9):
        block_id = f"{block_number:02d}"
        arm_runs = {
            arm: runs.get(f"perf_block_{block_id}_{arm}") for arm in ARMS
        }
        if any(run is None for run in arm_runs.values()):
            errors.append(f"block {block_id} is incomplete")
            continue
        complete_runs = {
            arm: run for arm, run in arm_runs.items() if run is not None
        }
        block: dict[str, Any] = {
            "block_id": block_id,
            "window_mean_normalized_outcomes": {},
            "interactions": {},
        }
        try:
            for metric, key in METRICS.items():
                values = {
                    arm: normalized_window_mean(run, key)
                    for arm, run in complete_runs.items()
                }
                interaction = v1.factorial_interaction(values)
                interactions[metric].append(interaction)
                block["window_mean_normalized_outcomes"][metric] = values
                block["interactions"][metric] = interaction
                block.setdefault("simple_update_effects", {})[metric] = {
                    workload: values[f"{workload}_shared"]
                    - values[f"{workload}_blocked"]
                    for workload in ("attack", "placebo")
                }
            for phase in POST_PHASES:
                values = {
                    arm: v1.normalized_metric(run, METRICS["throughput"], phase)
                    for arm, run in complete_runs.items()
                }
                trajectories[phase].append(v1.factorial_interaction(values))

            wall = {
                arm: sum(
                    float(run["phases"][phase]["summary"]["wall_seconds"])
                    for phase in POST_PHASES
                )
                for arm, run in complete_runs.items()
            }
            cumulative_wall_interaction = v1.factorial_interaction(wall)
            attack_work = float(
                complete_runs["attack_shared"]["phases"]["intervention"][
                    "summary"
                ]["wall_seconds"]
            )
            block["cumulative_post_wall_seconds"] = wall
            block["cumulative_post_wall_interaction_seconds"] = (
                cumulative_wall_interaction
            )
            block["attack_shared_intervention_wall_seconds"] = attack_work
            block["victim_harm_to_attacker_wall_ratio"] = (
                max(0.0, cumulative_wall_interaction) / attack_work
                if attack_work > 0
                else None
            )
        except (KeyError, TypeError, ValueError, statistics.StatisticsError) as exc:
            errors.append(f"block {block_id}: {type(exc).__name__}: {exc}")
        blocks.append(block)

    summaries = {
        metric: v1.bootstrap(values) if len(values) == 8 else None
        for metric, values in interactions.items()
    }
    throughput = interactions["throughput"]
    negative_count = sum(value < 0 for value in throughput)
    sign_probability = (
        v1.exact_negative_sign_probability(negative_count, len(throughput))
        if len(throughput) == 8
        else None
    )
    signal = (
        not errors
        and len(throughput) == 8
        and negative_count >= 7
        and sign_probability is not None
        and sign_probability <= 0.05
        and summaries["throughput"] is not None
        and summaries["throughput"]["ci95_high"] < 0
    )
    trajectory_summary = {
        phase: statistics.fmean(values) if len(values) == 8 else None
        for phase, values in trajectories.items()
    }
    harm_ratios = [
        block.get("victim_harm_to_attacker_wall_ratio") for block in blocks
    ]
    usable_harm_ratios = [
        value for value in harm_ratios if isinstance(value, int | float)
    ]
    return {
        "valid": not errors,
        "errors": errors,
        "primary_endpoint": (
            "mean of pre-normalized throughput across post_01 through post_08"
        ),
        "blocks": blocks,
        "block_interactions": interactions,
        "summaries": summaries,
        "negative_throughput_block_count": negative_count,
        "one_sided_exact_sign_probability": sign_probability,
        "throughput_interaction_trajectory": trajectory_summary,
        "mean_victim_harm_to_attacker_wall_ratio": (
            statistics.fmean(usable_harm_ratios)
            if len(usable_harm_ratios) == 8
            else None
        ),
        "signal": signal,
    }


def compact_run(run: dict[str, Any]) -> dict[str, Any]:
    compact_phases: dict[str, Any] = {}
    for phase, artifact in run.get("phases", {}).items():
        compact_phases[phase] = {
            key: artifact.get(key)
            for key in ("config", "started_ns", "finished_ns", "summary")
        }
    return {
        key: value
        for key, value in run.items()
        if key != "phases"
    } | {"phases": compact_phases}


def analyze(
    root: Path, *, require_performance: bool, gate_only: bool
) -> dict[str, Any]:
    errors: list[str] = []
    declarations = validate_declarations(root)
    errors.extend(f"declarations: {error}" for error in declarations["errors"])
    gate_runs: dict[str, dict[str, Any]] = {}
    for arm in GATE_ORDER:
        name = f"gate_{arm}"
        run = v1.inspect_run(root / name, stage="gate", block_id="gate", arm=arm)
        gate_runs[name] = run
        errors.extend(f"{name}: {error}" for error in run["errors"])
    gate_by_arm = {
        arm: gate_runs[f"gate_{arm}"] for arm in GATE_ORDER
    }
    gate = mechanism_gate(gate_by_arm)
    if not gate["pass"]:
        errors.append("v2 mechanism gate did not pass")

    performance_runs: dict[str, dict[str, Any]] = {}
    if not gate_only:
        for block_number, order in enumerate(PERFORMANCE_ORDERS, start=1):
            block_id = f"{block_number:02d}"
            for arm in order:
                name = f"perf_block_{block_id}_{arm}"
                run = v1.inspect_run(
                    root / name,
                    stage="performance",
                    block_id=block_id,
                    arm=arm,
                )
                performance_runs[name] = run
                errors.extend(f"{name}: {error}" for error in run["errors"])
        performance = performance_result(performance_runs)
        errors.extend(f"performance: {error}" for error in performance["errors"])
    else:
        performance = {
            "valid": True,
            "errors": [],
            "signal": False,
            "not_evaluated": True,
        }
    if require_performance and len(performance_runs) != 32:
        errors.append("the required thirty-two performance runs are not present")

    expected_names = {f"gate_{arm}" for arm in GATE_ORDER}
    if not gate_only:
        expected_names.update(performance_runs)
    actual_names = {
        path.name
        for path in root.iterdir()
        if path.is_dir()
        and path.name != "_incomplete"
        and (path.name.startswith("gate_") or path.name.startswith("perf_block_"))
    }
    if not gate_only and actual_names != expected_names:
        errors.append("complete run-directory set differs from the fixed cohort")

    ordered_names = [f"gate_{arm}" for arm in GATE_ORDER]
    if not gate_only:
        for block_number, order in enumerate(PERFORMANCE_ORDERS, start=1):
            block_id = f"{block_number:02d}"
            ordered_names.extend(
                f"perf_block_{block_id}_{arm}" for arm in order
            )
    try:
        all_runs = {**gate_runs, **performance_runs}
        timestamps = [
            datetime.fromisoformat(
                all_runs[name]["created_at"].replace("Z", "+00:00")
            )
            for name in ordered_names
        ]
        if timestamps != sorted(timestamps) or len(set(timestamps)) != len(
            timestamps
        ):
            errors.append("run creation timestamps violate the fixed order")
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        errors.append(f"run order: {type(exc).__name__}: {exc}")

    valid = not errors
    classification = "INVALID"
    if valid:
        classification = (
            "CONFIRMATORY_FACTORIAL_SIGNAL"
            if performance.get("signal")
            else "CONFIRMATORY_FACTORIAL_INCONCLUSIVE"
        )
        if gate_only:
            classification = "CONFIRMATORY_FACTORIAL_INCONCLUSIVE"
    return {
        "schema_version": 2,
        "protocol_version": PROTOCOL_VERSION,
        "analysis_mode": "gate_only" if gate_only else "full",
        "valid": valid,
        "errors": errors,
        "declarations": declarations,
        "mechanism_gate": gate,
        "gate_runs": {
            name: compact_run(run) for name, run in gate_runs.items()
        },
        "performance": performance,
        "classification": classification,
        "claim_scope": (
            "attack-by-update factorial interaction for two "
            "gateway-authenticated principals on one pinned vLLM worker"
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gate-only", action="store_true")
    parser.add_argument("--require-performance", action="store_true")
    args = parser.parse_args()
    if args.gate_only and args.require_performance:
        parser.error("--gate-only and --require-performance are exclusive")
    return args


def main() -> int:
    args = parse_args()
    result = analyze(
        args.result_root,
        require_performance=args.require_performance,
        gate_only=args.gate_only,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "valid": result["valid"],
                "classification": result["classification"],
                "mechanism_gate_pass": result["mechanism_gate"]["pass"],
                "errors": result["errors"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
