#!/usr/bin/env python
"""Fail-closed analysis for the AVEP estimator-update causal ablation."""

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

PROTOCOL_VERSION = "avep-causal-ablation-v2"
TARGET_MODEL = "Qwen/Qwen3-4B"
BASE_URL = "http://127.0.0.1:8001/v1"
TOKEN_ID = 279
SEED = 20260918
PINNED_SHA = "4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c"
PRE_PHASES = tuple(f"pre_{index:02d}" for index in range(1, 5))
POST_PHASES = tuple(f"post_{index:02d}" for index in range(1, 9))
PHASES = ("warmup", *PRE_PHASES, "intervention", *POST_PHASES)
PERFORMANCE_ORDERS = (
    ("shared", "blocked"),
    ("blocked", "shared"),
    ("shared", "blocked"),
    ("blocked", "shared"),
    ("shared", "blocked"),
    ("blocked", "shared"),
)
STATE_FIELDS = (
    "steps_since_refit",
    "refits",
    "slope",
    "intercepts",
    "counts",
    "info",
    "grad",
)
METRICS = {
    "throughput": "aggregate_output_tokens_per_second",
    "latency_p50": "latency_ms_p50",
    "latency_p95": "latency_ms_p95",
}
PHASE_MARKER = re.compile(r"AVEP_CAUSAL_PHASE\s+(\S+)")
BUDGET_EVENT = re.compile(r"AVEP_BUDGET\s+(\{.*\})")


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value is not an object")
    return value


def finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def unwrap_result(path: Path) -> dict[str, Any]:
    payload = load_object(path)
    results = payload.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise ValueError(f"{path}: expected exactly one worker result")
    result = results[0]
    if not isinstance(result, dict) or result.get("available") is not True:
        raise ValueError(f"{path}: estimator result is unavailable")
    return result


def expected_schedule() -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "token_id": TOKEN_ID,
        "gate_order": ["blocked", "shared"],
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
                "allowed_token_id": TOKEN_ID,
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
        schedule = load_object(root / "DECLARED_SCHEDULE.json")
        if schedule != expected_schedule():
            errors.append("declared schedule does not equal the fixed schedule")
        fields = (root / "DECLARED_SCHEDULE.json.sha256").read_text().split()
        if fields != [sha256(root / "DECLARED_SCHEDULE.json"),
                      "DECLARED_SCHEDULE.json"]:
            errors.append("schedule SHA-256 sidecar does not match")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"schedule: {type(exc).__name__}: {exc}")
    try:
        if (root / "DECLARED_DECISION_RULES.md").read_bytes() != (
            work_dir / "CAUSAL_ABLATION_DECISION_RULES.md"
        ).read_bytes():
            errors.append("declared rules differ from archived source rules")
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
            if not path.is_file() or sha256(path) != digest:
                errors.append(f"declared input mismatch: {name}")
    except (OSError, ValueError) as exc:
        errors.append(f"inputs: {type(exc).__name__}: {exc}")
    try:
        environment = (work_dir / "causal_environment.txt").read_text()
        if f"vllm_sha={PINNED_SHA}\n" not in environment:
            errors.append("environment does not identify the pinned vLLM commit")
    except OSError as exc:
        errors.append(f"environment: {type(exc).__name__}: {exc}")
    return {"valid": not errors, "errors": errors}


def phase_expected(phase: str) -> dict[str, Any]:
    if phase == "warmup":
        return {"principal": "victim", "requests": 1024,
                "concurrency": 32, "max_tokens": 32,
                "allowed_token_id": None}
    if phase == "intervention":
        return {"principal": "attacker", "requests": 4096,
                "concurrency": 8, "max_tokens": 2,
                "allowed_token_id": TOKEN_ID}
    return {"principal": "victim", "requests": 128,
            "concurrency": 32, "max_tokens": 32,
            "allowed_token_id": None}


def load_phase(run_dir: Path, phase: str, *, detailed: bool) -> dict[str, Any]:
    artifact = load_object(run_dir / f"{phase}.json")
    config = artifact.get("config")
    summary = artifact.get("summary")
    records = artifact.get("records")
    if not isinstance(config, dict) or not isinstance(summary, dict):
        raise ValueError(f"{phase}: config or summary is not an object")
    if not isinstance(records, list):
        raise ValueError(f"{phase}: records is not a list")
    expected = phase_expected(phase)
    expected.update({
        "phase": phase,
        "model": TARGET_MODEL,
        "base_url": BASE_URL,
        "seed": SEED,
        "return_token_ids": detailed or phase == "intervention",
    })
    for key, value in expected.items():
        if config.get(key) != value:
            raise ValueError(
                f"{phase}: config {key}={config.get(key)!r}, expected {value!r}"
            )
    requests = expected["requests"]
    if config.get("run_id") != run_dir.name:
        raise ValueError(f"{phase}: run_id does not match directory")
    if len(records) != requests:
        raise ValueError(f"{phase}: record count is not {requests}")
    if summary.get("requests") != requests \
        or summary.get("successful") != requests \
        or summary.get("failed") != 0:
        raise ValueError(f"{phase}: request success counts are invalid")
    if summary.get("completion_tokens") != requests * expected["max_tokens"]:
        raise ValueError(f"{phase}: completion-token count is invalid")
    if summary.get("authenticated_tenant_counts") != {
        expected["principal"]: requests
    }:
        raise ValueError(f"{phase}: authenticated tenant summary is invalid")
    if summary.get("unique_audit_event_ids") != requests \
        or summary.get("missing_audit_event_ids") != 0:
        raise ValueError(f"{phase}: audit event summary is invalid")
    if phase == "intervention" and summary.get("control_token_fraction") != 1:
        raise ValueError("intervention did not preserve the selected token")
    if detailed and summary.get("spec_requests") != requests:
        raise ValueError(f"{phase}: detailed speculative metrics are missing")
    return artifact


def validate_auth_and_audit(
    run_dir: Path, phases: dict[str, dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    try:
        auth = load_object(run_dir / "auth_self_test.json")
        if auth.get("valid") is not True or len(auth.get("results", [])) != 6:
            errors.append("authentication self-test is invalid")
        topology = load_object(run_dir / "tenant_topology.json")
        gateway_id = topology.get("gateway_instance_id")
        worker_marker = topology.get("upstream_marker")
        audit_rows = [
            json.loads(line)
            for line in (run_dir / "gateway_audit.jsonl").read_text().splitlines()
            if line.strip()
        ]
        event_ids = [row.get("event_id") for row in audit_rows]
        if len(event_ids) != len(set(event_ids)):
            errors.append("gateway audit contains duplicate event IDs")
        workload_rows = {
            row.get("event_id"): row
            for row in audit_rows
            if row.get("purpose") == "workload"
        }
        expected_workload = sum(
            phase_expected(phase)["requests"] for phase in PHASES
        )
        if len(workload_rows) != expected_workload:
            errors.append("gateway audit workload event count is invalid")
        for phase, artifact in phases.items():
            principal = phase_expected(phase)["principal"]
            for record in artifact["records"]:
                event = workload_rows.get(record.get("audit_event_id"))
                if event is None:
                    errors.append(f"{phase}: record has no joined audit event")
                    break
                if any((
                    event.get("request_id") != record.get("request_id"),
                    event.get("authenticated_tenant") != principal,
                    event.get("claimed_principal") != principal,
                    event.get("gateway_instance_id") != gateway_id,
                    event.get("upstream_marker") != worker_marker,
                    event.get("forwarded") is not True,
                    event.get("status") != 200,
                )):
                    errors.append(f"{phase}: joined audit event is inconsistent")
                    break
        if len(audit_rows) != expected_workload + 6:
            errors.append("gateway audit has missing or extra events")
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"audit: {type(exc).__name__}: {exc}")
    return errors


def budget_trace(path: Path) -> dict[str, Any]:
    phase_events: dict[str, list[tuple[int, int]]] = {
        phase: [] for phase in PHASES
    }
    active: str | None = None
    errors: list[str] = []
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        marker = PHASE_MARKER.search(line)
        if marker:
            label = marker.group(1)
            if label.endswith("_begin"):
                candidate = label.removesuffix("_begin")
                active = candidate if candidate in phase_events else None
            elif label.endswith("_end"):
                active = None
            continue
        match = BUDGET_EVENT.search(line)
        if not match or active is None:
            continue
        try:
            event = json.loads(match.group(1))
            budget = int(event["draft_budget"])
            maximum = int(event["max_draft_budget"])
            if maximum < 0 or budget < 0 or budget > maximum:
                raise ValueError("invalid budget bounds")
            if maximum:
                phase_events[active].append((budget, maximum))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"line {number}: {type(exc).__name__}: {exc}")
    ratios: dict[str, float | None] = {}
    for phase, events in phase_events.items():
        if not events:
            errors.append(f"{phase}: no usable budget events")
            ratios[phase] = None
        else:
            ratios[phase] = sum(b for b, _ in events) / sum(m for _, m in events)
    return {"valid": not errors, "errors": errors, "ratios": ratios}


def inspect_run(
    run_dir: Path, *, stage: str, pair_id: str, arm: str
) -> dict[str, Any]:
    errors: list[str] = []
    created_at: str | None = None
    phases: dict[str, dict[str, Any]] = {}
    states: dict[str, dict[str, Any]] = {}
    detailed = stage == "gate"
    try:
        metadata = load_object(run_dir / "metadata.json")
        expected_metadata = {
            "protocol_version": PROTOCOL_VERSION,
            "run_name": run_dir.name,
            "stage": stage,
            "pair_id": pair_id,
            "arm": arm,
            "poison_token_id": TOKEN_ID,
            "telemetry": detailed,
            "detailed_metrics": detailed,
        }
        for key, value in expected_metadata.items():
            if metadata.get(key) != value:
                errors.append(f"metadata {key} is not {value!r}")
        if not isinstance(metadata.get("created_at"), str):
            errors.append("metadata has no creation timestamp")
        else:
            created_at = metadata["created_at"]
            parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                errors.append("metadata creation timestamp has no UTC offset")
        if not (run_dir / "COMPLETE").is_file():
            errors.append("run has no COMPLETE marker")
        environment = (run_dir / "environment.txt").read_bytes()
        declared_environment = (
            run_dir.parent.parent / "causal_environment.txt"
        ).read_bytes()
        if environment != declared_environment:
            errors.append("run environment differs from declared environment")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"metadata: {type(exc).__name__}: {exc}")
    for phase in PHASES:
        try:
            phases[phase] = load_phase(run_dir, phase, detailed=detailed)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{phase}: {type(exc).__name__}: {exc}")
    if set(phases) == set(PHASES):
        errors.extend(validate_auth_and_audit(run_dir, phases))
        if phases["intervention"].get("finished_ns", math.inf) > phases[
            "post_01"
        ].get("started_ns", -math.inf):
            errors.append("intervention overlaps the first victim post phase")
    for name in ("pre_intervention", "intervention", "reenabled"):
        try:
            states[name] = unwrap_result(run_dir / f"state_{name}.json")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"state_{name}: {type(exc).__name__}: {exc}")
    gate_results: dict[str, Any] = {}
    for label in ("before_intervention", "after_intervention"):
        try:
            result = unwrap_result(run_dir / f"update_gate_{label}.json")
            gate = result.get("update_gate")
            if not isinstance(gate, dict):
                raise ValueError("update_gate is not an object")
            gate_results[label] = gate
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"update gate {label}: {type(exc).__name__}: {exc}")
    expected_before = (
        {"before": True, "after": False}
        if arm == "blocked"
        else {"before": True, "after": True}
    )
    expected_after = (
        {"before": False, "after": True}
        if arm == "blocked"
        else {"before": True, "after": True}
    )
    if gate_results.get("before_intervention") != expected_before:
        errors.append("pre-intervention update gate transition is invalid")
    if gate_results.get("after_intervention") != expected_after:
        errors.append("post-intervention update gate transition is invalid")
    state_invariant = False
    if set(states) == {"pre_intervention", "intervention", "reenabled"}:
        expected_enabled = arm == "shared"
        if states["pre_intervention"].get("updates_enabled") is not expected_enabled:
            errors.append("pre-intervention state has the wrong update-gate value")
        if states["intervention"].get("updates_enabled") is not expected_enabled:
            errors.append("intervention state has the wrong update-gate value")
        if states["reenabled"].get("updates_enabled") is not True:
            errors.append("updates were not restored before victim post traffic")
        state_invariant = all(
            states["pre_intervention"].get(field)
            == states["intervention"].get(field)
            for field in STATE_FIELDS
        )
        if arm == "blocked" and not state_invariant:
            errors.append("blocked estimator state moved during intervention")
    budgets = None
    if detailed:
        try:
            budgets = budget_trace(run_dir / "server.log")
            errors.extend(f"budget: {error}" for error in budgets["errors"])
        except OSError as exc:
            errors.append(f"budget: {type(exc).__name__}: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "run_name": run_dir.name,
        "arm": arm,
        "created_at": created_at,
        "phases": phases,
        "states": states,
        "update_gates": gate_results,
        "blocked_state_invariant": state_invariant if arm == "blocked" else None,
        "budgets": budgets,
    }


def normalized_metric(run: dict[str, Any], key: str, phase: str) -> float:
    phases = run["phases"]
    pre = [finite(phases[name]["summary"].get(key)) for name in PRE_PHASES]
    value = finite(phases[phase]["summary"].get(key))
    if value is None or any(item is None or item <= 0 for item in pre):
        raise ValueError(f"non-finite or non-positive metric {key}")
    return value / statistics.fmean(item for item in pre if item is not None)


def bootstrap(values: list[float], samples: int = 20_000) -> dict[str, Any]:
    rng = random.Random(20260919)
    draws = [
        statistics.fmean(values[rng.randrange(len(values))] for _ in values)
        for _ in range(samples)
    ]
    draws.sort()
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "ci95_low": draws[int(samples * 0.025)],
        "ci95_high": draws[min(int(samples * 0.975), samples - 1)],
    }


def mechanism_gate(shared: dict[str, Any], blocked: dict[str, Any]) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    checks: dict[str, bool] = {}
    try:
        shared_acceptance = finite(
            shared["phases"]["intervention"]["summary"].get(
                "draft_acceptance_rate"
            )
        )
        blocked_acceptance = finite(
            blocked["phases"]["intervention"]["summary"].get(
                "draft_acceptance_rate"
            )
        )
        if shared_acceptance is None or blocked_acceptance is None:
            raise ValueError("intervention acceptance is unavailable")
        observed["shared_acceptance_rate"] = shared_acceptance
        observed["blocked_acceptance_rate"] = blocked_acceptance
        observed["acceptance_absolute_difference"] = abs(
            shared_acceptance - blocked_acceptance
        )
        checks["both_acceptance_at_most_0_05"] = (
            shared_acceptance <= 0.05 and blocked_acceptance <= 0.05
        )
        checks["acceptance_difference_at_most_0_02"] = (
            abs(shared_acceptance - blocked_acceptance) <= 0.02
        )
        checks["blocked_state_invariant"] = bool(
            blocked["blocked_state_invariant"]
        )
        shared_pre = shared["states"]["pre_intervention"]["intercepts"][0]
        shared_after = shared["states"]["intervention"]["intercepts"][0]
        observed["shared_intercept0_delta"] = shared_after - shared_pre
        checks["shared_intercept0_delta_at_most_minus_0_50"] = (
            observed["shared_intercept0_delta"] <= -0.50
        )
        normalized_budgets: dict[str, float] = {}
        for arm, run in (("shared", shared), ("blocked", blocked)):
            ratios = run["budgets"]["ratios"]
            pre_mean = statistics.fmean(ratios[phase] for phase in PRE_PHASES)
            normalized_budgets[arm] = ratios["post_01"] / pre_mean
        observed["normalized_post1_budget"] = normalized_budgets
        observed["shared_minus_blocked_normalized_post1_budget"] = (
            normalized_budgets["shared"] - normalized_budgets["blocked"]
        )
        checks["budget_difference_at_most_minus_0_05"] = (
            observed["shared_minus_blocked_normalized_post1_budget"] <= -0.05
        )
    except (KeyError, TypeError, ValueError, statistics.StatisticsError) as exc:
        observed["error"] = f"{type(exc).__name__}: {exc}"
    return {"observed": observed, "checks": checks,
            "pass": len(checks) == 5 and all(checks.values())}


def performance_result(runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    effects: dict[str, list[float]] = {metric: [] for metric in METRICS}
    trajectories: dict[str, list[float]] = {phase: [] for phase in POST_PHASES}
    pairs: list[dict[str, Any]] = []
    errors: list[str] = []
    for pair_number in range(1, 7):
        pair_id = f"{pair_number:02d}"
        shared = runs.get(f"perf_pair_{pair_id}_shared")
        blocked = runs.get(f"perf_pair_{pair_id}_blocked")
        if shared is None or blocked is None:
            errors.append(f"pair {pair_id} is incomplete")
            continue
        pair: dict[str, Any] = {"pair_id": pair_id, "effects": {}}
        try:
            for metric, key in METRICS.items():
                effect = normalized_metric(shared, key, "post_01") \
                    - normalized_metric(blocked, key, "post_01")
                effects[metric].append(effect)
                pair["effects"][metric] = effect
            for phase in POST_PHASES:
                trajectories[phase].append(
                    normalized_metric(shared, METRICS["throughput"], phase)
                    - normalized_metric(blocked, METRICS["throughput"], phase)
                )
            pair["intervention_wall_seconds"] = {
                arm: run["phases"]["intervention"]["summary"]["wall_seconds"]
                for arm, run in (("shared", shared), ("blocked", blocked))
            }
        except (KeyError, TypeError, ValueError, statistics.StatisticsError) as exc:
            errors.append(f"pair {pair_id}: {type(exc).__name__}: {exc}")
        pairs.append(pair)
    summaries = {
        metric: bootstrap(values) if len(values) == 6 else None
        for metric, values in effects.items()
    }
    throughput = effects["throughput"]
    negative_count = sum(value < 0 for value in throughput)
    signal = (
        not errors
        and len(throughput) == 6
        and negative_count >= 5
        and summaries["throughput"]["ci95_high"] < 0
    )
    trajectory_summary = {
        phase: statistics.fmean(values) if len(values) == 6 else None
        for phase, values in trajectories.items()
    }
    return {
        "valid": not errors,
        "errors": errors,
        "pairs": pairs,
        "paired_effects": effects,
        "summaries": summaries,
        "negative_throughput_pair_count": negative_count,
        "throughput_trajectory_shared_minus_blocked": trajectory_summary,
        "signal": signal,
    }


def analyze(
    root: Path, *, require_performance: bool, gate_only: bool
) -> dict[str, Any]:
    errors: list[str] = []
    declarations = validate_declarations(root)
    errors.extend(f"declarations: {error}" for error in declarations["errors"])
    runs: dict[str, dict[str, Any]] = {}
    for arm in ("blocked", "shared"):
        name = f"gate_{arm}"
        run = inspect_run(root / name, stage="gate", pair_id="gate", arm=arm)
        runs[name] = run
        errors.extend(f"{name}: {error}" for error in run["errors"])
    gate = mechanism_gate(runs["gate_shared"], runs["gate_blocked"])
    if not gate["pass"]:
        errors.append("mechanism gate did not pass")
    performance_runs: dict[str, dict[str, Any]] = {}
    if not gate_only:
        for pair_number, order in enumerate(PERFORMANCE_ORDERS, start=1):
            pair_id = f"{pair_number:02d}"
            for arm in order:
                name = f"perf_pair_{pair_id}_{arm}"
                run = inspect_run(
                    root / name,
                    stage="performance",
                    pair_id=pair_id,
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
    if require_performance and len(performance_runs) != 12:
        errors.append("the required twelve performance runs are not present")
    expected_names = {"gate_blocked", "gate_shared"}
    if not gate_only:
        expected_names.update(performance_runs)
    actual_names = {
        path.name
        for path in root.iterdir()
        if path.is_dir()
        and path.name != "_incomplete"
        and (path.name.startswith("gate_") or path.name.startswith("perf_pair_"))
    }
    if not gate_only and actual_names != expected_names:
        errors.append("complete run-directory set differs from the fixed cohort")
    ordered_names = ["gate_blocked", "gate_shared"]
    if not gate_only:
        for pair_number, order in enumerate(PERFORMANCE_ORDERS, start=1):
            pair_id = f"{pair_number:02d}"
            ordered_names.extend(
                f"perf_pair_{pair_id}_{arm}" for arm in order
            )
    try:
        all_runs = {**runs, **performance_runs}
        timestamps = [
            datetime.fromisoformat(
                all_runs[name]["created_at"].replace("Z", "+00:00")
            )
            for name in ordered_names
        ]
        if timestamps != sorted(timestamps) or len(set(timestamps)) != len(timestamps):
            errors.append("run creation timestamps violate the fixed order")
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        errors.append(f"run order: {type(exc).__name__}: {exc}")
    valid = not errors
    classification = "INVALID"
    if valid:
        classification = (
            "TARGETED_CAUSAL_SIGNAL"
            if performance.get("signal")
            else "TARGETED_CAUSAL_INCONCLUSIVE"
        )
        if gate_only:
            classification = "TARGETED_CAUSAL_INCONCLUSIVE"
    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "analysis_mode": "gate_only" if gate_only else "full",
        "valid": valid,
        "errors": errors,
        "declarations": declarations,
        "mechanism_gate": gate,
        "gate_runs": runs,
        "performance": performance,
        "classification": classification,
        "claim_scope": (
            "estimator-update causal ablation for two gateway-authenticated "
            "principals on one pinned vLLM worker"
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
    print(json.dumps({
        "valid": result["valid"],
        "classification": result["classification"],
        "mechanism_gate_pass": result["mechanism_gate"]["pass"],
        "errors": result["errors"],
    }, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
