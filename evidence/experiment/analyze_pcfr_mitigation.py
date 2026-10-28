#!/usr/bin/env python
"""Fail-closed analysis for the PCFR mitigation experiment."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

import analyze_factorial_confirmatory as base

PROTOCOL_VERSION = "avep-pcfr-mitigation-v1"
RULES_SOURCE = "PCFR_MITIGATION_DECISION_RULES.md"
PROTOCOL_SOURCE = "PCFR_MITIGATION_PROTOCOL.md"
DESIGN_SOURCE = "PCFR_MITIGATION_DESIGN.md"
DRIVER_SOURCE = "run_pcfr_mitigation.sh"
ANALYZER_SOURCE = "analyze_pcfr_mitigation.py"
TEST_SOURCE = "test_analyze_pcfr_mitigation.py"
PATCH_SOURCE = "avep_pcfr_mitigation.patch"
ENVIRONMENT_SOURCE = "pcfr_environment.txt"

TOKEN_ID = 279
PRE_PHASES = base.PRE_PHASES
POST_PHASES = base.POST_PHASES
PHASES = base.PHASES
METRICS = base.METRICS
STATE_FIELDS = (
    "steps_since_refit",
    "refits",
    "slope",
    "intercepts",
    "counts",
    "info",
    "grad",
)

GATE_ORDER = (
    "placebo_shared",
    "placebo_route",
    "attack_drop",
    "attack_route",
    "attack_shared",
)
PERFORMANCE_ARMS = (
    "attack_shared",
    "attack_route",
    "placebo_shared",
    "placebo_route",
)
PERFORMANCE_ORDERS = (
    ("attack_shared", "attack_route", "placebo_route", "placebo_shared"),
    ("attack_route", "placebo_shared", "attack_shared", "placebo_route"),
    ("placebo_shared", "placebo_route", "attack_route", "attack_shared"),
    ("placebo_route", "attack_shared", "placebo_shared", "attack_route"),
    ("attack_shared", "attack_route", "placebo_route", "placebo_shared"),
    ("attack_route", "placebo_shared", "attack_shared", "placebo_route"),
    ("placebo_shared", "placebo_route", "attack_route", "attack_shared"),
    ("placebo_route", "attack_shared", "placebo_shared", "attack_route"),
)

# The imported helpers compare against module globals for phase validation.
base.PROTOCOL_VERSION = PROTOCOL_VERSION


def expected_schedule() -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "token_id": TOKEN_ID,
        "gate_order": list(GATE_ORDER),
        "performance_orders": [list(order) for order in PERFORMANCE_ORDERS],
        "workload": {
            "warmup": {"requests": 1024, "concurrency": 32, "max_tokens": 32},
            "pre": {
                "windows": 4,
                "requests": 128,
                "concurrency": 32,
                "max_tokens": 32,
            },
            "intervention": {
                "requests": 4096,
                "concurrency": 8,
                "max_tokens": 2,
                "attack_allowed_token_id": TOKEN_ID,
                "placebo_allowed_token_id": None,
                "return_token_ids": True,
            },
            "post": {
                "windows": 8,
                "requests": 128,
                "concurrency": 32,
                "max_tokens": 32,
            },
        },
    }


def validate_declarations(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    work_dir = root.parent
    try:
        schedule = base.load_object(root / "DECLARED_SCHEDULE.json")
        if schedule != expected_schedule():
            errors.append("declared schedule does not equal the fixed schedule")
        fields = (root / "DECLARED_SCHEDULE.json.sha256").read_text().split()
        if fields != [
            base.sha256(root / "DECLARED_SCHEDULE.json"),
            "DECLARED_SCHEDULE.json",
        ]:
            errors.append("schedule SHA-256 sidecar does not match")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"schedule: {type(exc).__name__}: {exc}")
    try:
        if (root / "DECLARED_DECISION_RULES.md").read_bytes() != (
            work_dir / RULES_SOURCE
        ).read_bytes():
            errors.append("declared rules differ from archived rules")
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
            if not path.is_file() or base.sha256(path) != digest:
                errors.append(f"declared input mismatch: {name}")
    except (OSError, ValueError) as exc:
        errors.append(f"inputs: {type(exc).__name__}: {exc}")
    try:
        environment = (work_dir / ENVIRONMENT_SOURCE).read_text()
        if f"vllm_sha={base.PINNED_SHA}\n" not in environment:
            errors.append("environment does not identify the pinned commit")
    except OSError as exc:
        errors.append(f"environment: {type(exc).__name__}: {exc}")
    return {"valid": not errors, "errors": errors}


def split_arm(arm: str) -> tuple[str, str]:
    workload, mode = arm.split("_", 1)
    if workload not in {"attack", "placebo"}:
        raise ValueError(f"unknown workload in {arm}")
    if mode not in {"shared", "drop", "route"}:
        raise ValueError(f"unknown mitigation mode in {arm}")
    return workload, mode


def domain_state(state: dict[str, Any], domain: int) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in STATE_FIELDS:
        value = state.get(field)
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError(f"{field} is not a two-domain value")
        result[field] = value[domain]
    return result


def finite_tree(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int | float):
        return math.isfinite(float(value))
    if isinstance(value, list):
        return all(finite_tree(item) for item in value)
    return False


def state_changed(
    before: dict[str, Any], after: dict[str, Any], domain: int
) -> bool:
    return domain_state(before, domain) != domain_state(after, domain)


def inspect_run(
    run_dir: Path, *, stage: str, block_id: str, arm: str
) -> dict[str, Any]:
    errors: list[str] = []
    phases: dict[str, dict[str, Any]] = {}
    states: dict[str, dict[str, Any]] = {}
    created_at: str | None = None
    detailed = stage == "gate"
    try:
        workload, mode = split_arm(arm)
    except ValueError as exc:
        return {"valid": False, "errors": [str(exc)], "run_name": run_dir.name}

    try:
        metadata = base.load_object(run_dir / "metadata.json")
        expected = {
            "protocol_version": PROTOCOL_VERSION,
            "run_name": run_dir.name,
            "stage": stage,
            "block_id": block_id,
            "arm": arm,
            "workload": workload,
            "mitigation_mode": mode,
            "poison_token_id": TOKEN_ID,
            "telemetry": detailed,
            "detailed_metrics": detailed,
        }
        for key, value in expected.items():
            if metadata.get(key) != value:
                errors.append(f"metadata {key} is not {value!r}")
        created_at = metadata.get("created_at")
        if not isinstance(created_at, str):
            errors.append("metadata has no creation timestamp")
            created_at = None
        else:
            parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                errors.append("metadata timestamp has no UTC offset")
        if not (run_dir / "COMPLETE").is_file():
            errors.append("run has no COMPLETE marker")
        if (run_dir / "environment.txt").read_bytes() != (
            run_dir.parent.parent / ENVIRONMENT_SOURCE
        ).read_bytes():
            errors.append("run environment differs from declaration")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"metadata: {type(exc).__name__}: {exc}")

    for phase in PHASES:
        try:
            phases[phase] = base.load_phase(
                run_dir,
                phase,
                detailed=detailed,
                workload=workload,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{phase}: {type(exc).__name__}: {exc}")
    if set(phases) == set(PHASES):
        errors.extend(base.validate_auth_and_audit(run_dir, phases, workload))
        if phases["intervention"].get("finished_ns", math.inf) > phases[
            "post_01"
        ].get("started_ns", -math.inf):
            errors.append("intervention overlaps post traffic")

    for name in ("pre_intervention", "intervention"):
        try:
            states[name] = base.unwrap_result(run_dir / f"state_{name}.json")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"state_{name}: {type(exc).__name__}: {exc}")
    if set(states) == {"pre_intervention", "intervention"}:
        for name, state in states.items():
            if state.get("pcfr_mode") != mode:
                errors.append(f"{name} reports the wrong PCFR mode")
            try:
                for domain in range(2):
                    if not finite_tree(domain_state(state, domain)):
                        errors.append(
                            f"{name}: domain {domain} has a non-finite value"
                        )
            except ValueError as exc:
                errors.append(f"{name}: {exc}")

    for phase, artifact in phases.items():
        summary = artifact.get("summary", {})
        for key in (*METRICS.values(), "wall_seconds"):
            value = base.finite(summary.get(key))
            if value is None or value <= 0:
                errors.append(f"{phase}: {key} is non-finite or non-positive")

    budgets = None
    if detailed:
        try:
            budgets = base.budget_trace(run_dir / "server.log")
            errors.extend(f"budget: {item}" for item in budgets["errors"])
        except OSError as exc:
            errors.append(f"budget: {type(exc).__name__}: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "run_name": run_dir.name,
        "arm": arm,
        "workload": workload,
        "mitigation_mode": mode,
        "created_at": created_at,
        "phases": phases,
        "states": states,
        "budgets": budgets,
    }


def normalized_window_mean(run: dict[str, Any], key: str) -> float:
    return statistics.fmean(
        base.normalized_metric(run, key, phase) for phase in POST_PHASES
    )


def normalized_budget_mean(run: dict[str, Any]) -> float:
    return statistics.fmean(base.normalized_budget(run, phase) for phase in POST_PHASES)


def mitigation_interaction(values: dict[str, float]) -> float:
    return (
        values["attack_route"]
        - values["attack_shared"]
        - values["placebo_route"]
        + values["placebo_shared"]
    )


def mechanism_gate(runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    checks: dict[str, bool] = {}
    try:
        acceptance = {
            arm: base.finite(
                run["phases"]["intervention"]["summary"].get(
                    "draft_acceptance_rate"
                )
            )
            for arm, run in runs.items()
        }
        if any(value is None for value in acceptance.values()):
            raise ValueError("an intervention acceptance rate is unavailable")
        observed["acceptance_rates"] = acceptance
        attack_acceptance = [
            float(acceptance[arm])
            for arm in ("attack_shared", "attack_drop", "attack_route")
        ]
        checks["attack_acceptance_at_most_0_05"] = all(
            value <= 0.05 for value in attack_acceptance
        )
        checks["attack_acceptance_range_at_most_0_02"] = (
            max(attack_acceptance) - min(attack_acceptance) <= 0.02
        )

        transitions: dict[str, dict[str, bool]] = {}
        for arm, run in runs.items():
            before = run["states"]["pre_intervention"]
            after = run["states"]["intervention"]
            transitions[arm] = {
                "canonical_changed": state_changed(before, after, 0),
                "transformed_changed": state_changed(before, after, 1),
            }
        observed["domain_transitions"] = transitions
        checks["attack_shared_canonical_changed"] = transitions[
            "attack_shared"
        ]["canonical_changed"]
        checks["attack_route_canonical_invariant"] = not transitions[
            "attack_route"
        ]["canonical_changed"]
        checks["attack_route_transformed_changed"] = transitions[
            "attack_route"
        ]["transformed_changed"]
        checks["attack_drop_both_domains_invariant"] = not any(
            transitions["attack_drop"].values()
        )
        checks["placebo_route_canonical_changed"] = transitions[
            "placebo_route"
        ]["canonical_changed"]

        budget_values = {
            arm: normalized_budget_mean(runs[arm])
            for arm in PERFORMANCE_ARMS
        }
        budget_effect = mitigation_interaction(budget_values)
        observed["mean_normalized_post_budgets"] = budget_values
        observed["mitigation_budget_interaction"] = budget_effect
        checks["budget_interaction_at_least_0_05"] = budget_effect >= 0.05
    except (KeyError, TypeError, ValueError, statistics.StatisticsError) as exc:
        observed["error"] = f"{type(exc).__name__}: {exc}"
    return {
        "observed": observed,
        "checks": checks,
        "pass": len(checks) == 8 and all(checks.values()),
    }


def exact_positive_sign_probability(positive_count: int, n: int) -> float:
    return sum(math.comb(n, value) for value in range(positive_count, n + 1)) / (
        2**n
    )


def performance_result(runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    interactions: dict[str, list[float]] = {metric: [] for metric in METRICS}
    blocks: list[dict[str, Any]] = []
    errors: list[str] = []
    placebo_throughput_effects: list[float] = []
    for block_number in range(1, 9):
        block_id = f"{block_number:02d}"
        arm_runs = {
            arm: runs.get(f"perf_block_{block_id}_{arm}")
            for arm in PERFORMANCE_ARMS
        }
        if any(run is None for run in arm_runs.values()):
            errors.append(f"block {block_id} is incomplete")
            continue
        complete = {arm: run for arm, run in arm_runs.items() if run is not None}
        block: dict[str, Any] = {"block_id": block_id, "outcomes": {}}
        try:
            for metric, key in METRICS.items():
                values = {
                    arm: normalized_window_mean(run, key)
                    for arm, run in complete.items()
                }
                effect = mitigation_interaction(values)
                interactions[metric].append(effect)
                block["outcomes"][metric] = values
                block.setdefault("interactions", {})[metric] = effect
                if metric == "throughput":
                    placebo_throughput_effects.append(
                        values["placebo_route"] - values["placebo_shared"]
                    )
        except (KeyError, TypeError, ValueError, statistics.StatisticsError) as exc:
            errors.append(f"block {block_id}: {type(exc).__name__}: {exc}")
        blocks.append(block)

    summaries = {
        metric: base.bootstrap(values) if len(values) == 8 else None
        for metric, values in interactions.items()
    }
    throughput = interactions["throughput"]
    positive_count = sum(value > 0 for value in throughput)
    sign_probability = (
        exact_positive_sign_probability(positive_count, len(throughput))
        if len(throughput) == 8
        else None
    )
    placebo_summary = (
        base.bootstrap(placebo_throughput_effects)
        if len(placebo_throughput_effects) == 8
        else None
    )
    signal = (
        not errors
        and len(throughput) == 8
        and positive_count >= 7
        and sign_probability is not None
        and sign_probability <= 0.05
        and summaries["throughput"] is not None
        and summaries["throughput"]["ci95_low"] > 0
    )
    guardrail = bool(
        placebo_summary is not None and abs(placebo_summary["mean"]) <= 0.05
    )
    equivalence = bool(
        placebo_summary is not None
        and placebo_summary["ci95_low"] >= -0.05
        and placebo_summary["ci95_high"] <= 0.05
    )
    return {
        "valid": not errors,
        "errors": errors,
        "primary_endpoint": (
            "mean pre-normalized throughput across post_01 through post_08"
        ),
        "blocks": blocks,
        "block_interactions": interactions,
        "summaries": summaries,
        "positive_throughput_block_count": positive_count,
        "one_sided_exact_sign_probability": sign_probability,
        "placebo_route_minus_shared_throughput": placebo_summary,
        "benign_overhead_guardrail_pass": guardrail,
        "benign_equivalence_interval_pass": equivalence,
        "signal": signal,
    }


def order_errors(runs: list[dict[str, Any]], expected: tuple[str, ...]) -> list[str]:
    if any(run.get("created_at") is None for run in runs):
        return ["run order cannot be checked without timestamps"]
    observed = tuple(
        run["arm"]
        for run in sorted(
            runs,
            key=lambda item: datetime.fromisoformat(
                item["created_at"].replace("Z", "+00:00")
            ),
        )
    )
    return [] if observed == expected else [f"order {observed!r} != {expected!r}"]


def analyze(
    root: Path, *, gate_only: bool, require_performance: bool
) -> dict[str, Any]:
    errors: list[str] = []
    declarations = validate_declarations(root)
    errors.extend(f"declarations: {item}" for item in declarations["errors"])

    gate_runs: dict[str, dict[str, Any]] = {}
    for arm in GATE_ORDER:
        run = inspect_run(root / f"gate_{arm}", stage="gate", block_id="gate", arm=arm)
        gate_runs[arm] = run
        errors.extend(f"gate_{arm}: {item}" for item in run["errors"])
    errors.extend(
        f"gate: {item}"
        for item in order_errors(list(gate_runs.values()), GATE_ORDER)
    )
    gate = mechanism_gate(gate_runs)
    if not gate["pass"]:
        errors.append("mechanism gate did not pass")

    performance_runs: dict[str, dict[str, Any]] = {}
    if not gate_only:
        for block_number, order in enumerate(PERFORMANCE_ORDERS, start=1):
            block_id = f"{block_number:02d}"
            block_runs: list[dict[str, Any]] = []
            for arm in order:
                name = f"perf_block_{block_id}_{arm}"
                run = inspect_run(
                    root / name,
                    stage="performance",
                    block_id=block_id,
                    arm=arm,
                )
                performance_runs[name] = run
                block_runs.append(run)
                errors.extend(f"{name}: {item}" for item in run["errors"])
            errors.extend(
                f"block {block_id}: {item}"
                for item in order_errors(block_runs, order)
            )
        performance = performance_result(performance_runs)
        errors.extend(f"performance: {item}" for item in performance["errors"])
    else:
        performance = {
            "valid": True,
            "errors": [],
            "signal": False,
            "not_evaluated": True,
        }
    if require_performance and len(performance_runs) != 32:
        errors.append("the required thirty-two performance runs are absent")

    valid = not errors
    if not valid:
        classification = "INVALID"
    elif performance.get("signal"):
        classification = "PCFR_MITIGATION_SIGNAL"
    else:
        classification = "PCFR_MITIGATION_INCONCLUSIVE"
    return {
        "protocol_version": PROTOCOL_VERSION,
        "valid": valid,
        "errors": errors,
        "declarations": declarations,
        "mechanism_gate": gate,
        "performance": performance,
        "classification": classification,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gate-only", action="store_true")
    parser.add_argument("--require-performance", action="store_true")
    args = parser.parse_args()
    result = analyze(
        args.result_root,
        gate_only=args.gate_only,
        require_performance=args.require_performance,
    )
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
