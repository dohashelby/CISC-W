#!/usr/bin/env python
"""Unit tests for the v2 factorial-confirmatory decision logic."""

from __future__ import annotations

import unittest

from analyze_factorial_confirmatory_v2 import (
    ARMS,
    METRICS,
    PERFORMANCE_ORDERS,
    POST_PHASES,
    PRE_PHASES,
    mechanism_gate,
    performance_result,
)


def gate_run(*, workload: str, update_mode: str) -> dict:
    acceptance = 0.0 if workload == "attack" else 0.2
    intercept_after = -1.0 if (
        workload == "attack" and update_mode == "shared"
    ) else 0.0
    budgets = {phase: 1.0 for phase in PRE_PHASES}
    for index, phase in enumerate(POST_PHASES):
        budgets[phase] = (
            1.2 if index == 0 else 0.6
        ) if workload == "attack" and update_mode == "shared" else 1.0
    return {
        "phases": {
            "intervention": {
                "summary": {"draft_acceptance_rate": acceptance}
            }
        },
        "states": {
            "pre_intervention": {"intercepts": [0.0, 0.0, 0.0, 0.0]},
            "intervention": {
                "intercepts": [intercept_after, 0.0, 0.0, 0.0]
            },
        },
        "blocked_state_invariant": update_mode == "blocked",
        "budgets": {"ratios": budgets},
    }


def performance_run(*, workload: str, update_mode: str) -> dict:
    harmed = workload == "attack" and update_mode == "shared"
    phases = {}
    for phase in PRE_PHASES:
        phases[phase] = {
            "summary": {
                METRICS["throughput"]: 100.0,
                METRICS["latency_p50"]: 100.0,
                METRICS["latency_p95"]: 100.0,
                "wall_seconds": 10.0,
            }
        }
    for index, phase in enumerate(POST_PHASES):
        effective_harm = harmed and index > 0
        phases[phase] = {
            "summary": {
                METRICS["throughput"]: 80.0 if effective_harm else 100.0,
                METRICS["latency_p50"]: 120.0 if effective_harm else 100.0,
                METRICS["latency_p95"]: 140.0 if effective_harm else 100.0,
                "wall_seconds": 12.0 if effective_harm else 10.0,
            }
        }
    phases["intervention"] = {"summary": {"wall_seconds": 30.0}}
    return {"phases": phases}


class FactorialV2DecisionTests(unittest.TestCase):
    def test_schedule_balances_positions_and_predecessors(self) -> None:
        self.assertEqual(len(PERFORMANCE_ORDERS), 8)
        for arm in ARMS:
            positions = [
                position
                for order in PERFORMANCE_ORDERS
                for position, value in enumerate(order)
                if value == arm
            ]
            self.assertEqual(sorted(positions), [0, 0, 1, 1, 2, 2, 3, 3])

    def test_gate_uses_fixed_full_post_horizon(self) -> None:
        runs = {
            arm: gate_run(
                workload=arm.split("_", 1)[0],
                update_mode=arm.split("_", 1)[1],
            )
            for arm in ARMS
        }
        result = mechanism_gate(runs)
        self.assertTrue(result["pass"])
        self.assertGreater(
            result["observed"]["normalized_post_budget_interactions"][
                "post_01"
            ],
            0,
        )
        self.assertLess(
            result["observed"]["mean_normalized_post_budget_interaction"],
            -0.05,
        )

    def test_gate_still_requires_blocked_state_invariance(self) -> None:
        runs = {
            arm: gate_run(
                workload=arm.split("_", 1)[0],
                update_mode=arm.split("_", 1)[1],
            )
            for arm in ARMS
        }
        runs["attack_blocked"]["blocked_state_invariant"] = False
        self.assertFalse(mechanism_gate(runs)["pass"])

    def test_primary_averages_all_eight_fixed_post_windows(self) -> None:
        runs = {}
        for block_number in range(1, 9):
            block_id = f"{block_number:02d}"
            for arm in ARMS:
                workload, update_mode = arm.split("_", 1)
                runs[f"perf_block_{block_id}_{arm}"] = performance_run(
                    workload=workload,
                    update_mode=update_mode,
                )
        result = performance_result(runs)
        self.assertTrue(result["signal"])
        self.assertEqual(result["negative_throughput_block_count"], 8)
        self.assertAlmostEqual(
            result["summaries"]["throughput"]["mean"],
            -0.175,
        )
        self.assertEqual(
            result["throughput_interaction_trajectory"]["post_01"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
