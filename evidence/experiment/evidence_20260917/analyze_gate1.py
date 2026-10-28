#!/usr/bin/env python
"""Create a bounded, explicitly non-conclusive AVEP Gate 1 assessment."""

from __future__ import annotations

import argparse
import collections
import json
import math
import re
from pathlib import Path
from typing import Any


REFIT_PATTERN = re.compile(r"AVEP_ESTIMATOR\s+(\{.*\})")
BUDGET_PATTERN = re.compile(r"AVEP_BUDGET\s+(\{.*\})")
PHASE_PATTERN = re.compile(r"===== AVEP_PHASE (\S+)")


def load_summary(result_dir: Path, phase: str) -> dict[str, Any]:
    path = result_dir / f"{phase}.json"
    return json.loads(path.read_text())["summary"]


def finite_ratio(numerator: Any, denominator: Any) -> float | None:
    if numerator is None or denominator in (None, 0):
        return None
    ratio = float(numerator) / float(denominator)
    return ratio if math.isfinite(ratio) else None


def parse_refits(server_log: Path) -> list[dict[str, Any]]:
    refits = []
    for line in server_log.read_text(errors="replace").splitlines():
        match = REFIT_PATTERN.search(line)
        if match:
            refits.append(json.loads(match.group(1)))
    return refits


def parse_budget_telemetry(server_log: Path) -> dict[str, dict[str, Any]]:
    """Summarize the selector's observed verification budgets by phase."""
    observations: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    phase: str | None = None
    for line in server_log.read_text(errors="replace").splitlines():
        phase_match = PHASE_PATTERN.search(line)
        if phase_match:
            marker = phase_match.group(1)
            phase = marker.removesuffix("_begin") if marker.endswith("_begin") else None
            continue
        budget_match = BUDGET_PATTERN.search(line)
        if phase is not None and budget_match:
            observations[phase].append(json.loads(budget_match.group(1)))

    result = {}
    for name, rows in observations.items():
        ratios = [
            row["draft_budget"] / row["max_draft_budget"]
            for row in rows
            if row["max_draft_budget"]
        ]
        result[name] = {
            "observations": len(rows),
            "mean_draft_budget": sum(row["draft_budget"] for row in rows)
            / len(rows),
            "mean_max_draft_budget": sum(
                row["max_draft_budget"] for row in rows
            )
            / len(rows),
            "mean_budget_ratio": sum(ratios) / len(ratios) if ratios else None,
            "min_draft_budget": min(row["draft_budget"] for row in rows),
            "max_draft_budget": max(row["draft_budget"] for row in rows),
            "zero_budget_observations": sum(
                row["draft_budget"] == 0 for row in rows
            ),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    phases = {
        phase: load_summary(args.result_dir, phase)
        for phase in (
            "warmup",
            "baseline",
            "poison",
            "post_poison_victim",
            "recovery_1",
            "recovery_2",
            "fresh_warmup",
            "fresh_process_victim",
        )
    }
    baseline = phases["baseline"]
    victim = phases["post_poison_victim"]
    fresh = phases["fresh_process_victim"]
    poison = phases["poison"]
    refits = parse_refits(args.result_dir / "server.log")
    budget_telemetry = parse_budget_telemetry(args.result_dir / "server.log")

    baseline_budget_ratio = budget_telemetry.get("baseline", {}).get(
        "mean_budget_ratio"
    )
    victim_budget_ratio = budget_telemetry.get("post_poison_victim", {}).get(
        "mean_budget_ratio"
    )
    fresh_budget_ratio = budget_telemetry.get("fresh_process_victim", {}).get(
        "mean_budget_ratio"
    )

    comparison = {
        "victim_to_baseline_aggregate_tps": finite_ratio(
            victim["aggregate_output_tokens_per_second"],
            baseline["aggregate_output_tokens_per_second"],
        ),
        "victim_to_baseline_latency_p50": finite_ratio(
            victim["latency_ms_p50"], baseline["latency_ms_p50"]
        ),
        "victim_to_baseline_latency_p95": finite_ratio(
            victim["latency_ms_p95"], baseline["latency_ms_p95"]
        ),
        "victim_to_baseline_drafted_per_step": finite_ratio(
            victim["mean_drafted_per_step"], baseline["mean_drafted_per_step"]
        ),
        "fresh_to_baseline_aggregate_tps": finite_ratio(
            fresh["aggregate_output_tokens_per_second"],
            baseline["aggregate_output_tokens_per_second"],
        ),
        "fresh_to_baseline_drafted_per_step": finite_ratio(
            fresh["mean_drafted_per_step"], baseline["mean_drafted_per_step"]
        ),
        "victim_to_baseline_verification_budget_ratio": finite_ratio(
            victim_budget_ratio, baseline_budget_ratio
        ),
        "fresh_to_baseline_verification_budget_ratio": finite_ratio(
            fresh_budget_ratio, baseline_budget_ratio
        ),
        "fresh_to_victim_verification_budget_ratio": finite_ratio(
            fresh_budget_ratio, victim_budget_ratio
        ),
    }

    poison_reached = (
        poison["control_token_fraction"] is not None
        and poison["control_token_fraction"] >= 0.99
        and poison["draft_tokens"] > 0
    )
    estimator_refit_seen = bool(refits)
    draft_budget_shift = (
        comparison["victim_to_baseline_verification_budget_ratio"] is not None
        and comparison["victim_to_baseline_verification_budget_ratio"] < 0.9
    )
    measurable_slowdown = (
        comparison["victim_to_baseline_aggregate_tps"] is not None
        and comparison["victim_to_baseline_aggregate_tps"] < 0.9
    ) or (
        comparison["victim_to_baseline_latency_p50"] is not None
        and comparison["victim_to_baseline_latency_p50"] > 1.1
    )
    fresh_reset_signal = (
        comparison["fresh_to_victim_verification_budget_ratio"] is not None
        and comparison["fresh_to_victim_verification_budget_ratio"] > 1.1
    )

    if poison_reached and estimator_refit_seen and draft_budget_shift:
        verdict = "POSITIVE_GATE1_MECHANISM_SIGNAL"
        if measurable_slowdown and fresh_reset_signal:
            verdict = "POSITIVE_GATE1_CROSS_REQUEST_IMPACT_SIGNAL"
    else:
        verdict = "NO_POSITIVE_GATE1_SIGNAL"

    assessment = {
        "verdict": verdict,
        "scope": (
            "Single bounded run only; this is not vulnerability verification, "
            "severity evidence, or a disclosure-ready result."
        ),
        "checks": {
            "poison_request_reached_target_constraint": poison_reached,
            "estimator_refit_telemetry_seen": estimator_refit_seen,
            "post_poison_draft_budget_shift_over_10_percent": draft_budget_shift,
            "post_poison_slowdown_over_10_percent": measurable_slowdown,
            "fresh_process_reset_signal": fresh_reset_signal,
        },
        "comparison": comparison,
        "phases": phases,
        "budget_telemetry": budget_telemetry,
        "refit_count": len(refits),
        "first_refit": refits[0] if refits else None,
        "last_refit": refits[-1] if refits else None,
    }
    args.output.write_text(json.dumps(assessment, indent=2, sort_keys=True) + "\n")
    print(json.dumps(assessment, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
