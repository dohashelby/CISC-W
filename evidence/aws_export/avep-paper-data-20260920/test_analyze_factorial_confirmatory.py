#!/usr/bin/env python
"""Unit tests for factorial-confirmatory decision logic."""

from __future__ import annotations

import unittest

from analyze_factorial_confirmatory import (
    ARMS,
    METRICS,
    PERFORMANCE_ORDERS,
    POST_PHASES,
    PRE_PHASES,
    exact_negative_sign_probability,
    factorial_interaction,
    mechanism_gate,
    performance_result,
)


def gate_run(*, workload: str, update_mode: str) -> dict:
    acceptance = 0.0 if workload == "attack" else 0.2
    intercept_after = -1.0 if (
        workload == "attack" and update_mode == "shared"
    ) else 0.0
    post_budget = 0.6 if (
        workload == "attack" and update_mode == "shared"
    ) else 1.0
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
        "budgets": {
            "ratios": {
                **{phase: 1.0 for phase in PRE_PHASES},
                "post_01": post_budget,
            }
        },
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
    for phase in POST_PHASES:
        phases[phase] = {
            "summary": {
                METRICS["throughput"]: 80.0 if harmed else 100.0,
                METRICS["latency_p50"]: 120.0 if harmed else 100.0,
                METRICS["latency_p95"]: 140.0 if harmed else 100.0,
                "wall_seconds": 12.0 if harmed else 10.0,
            }
        }
    phases["intervention"] = {"summary": {"wall_seconds": 30.0}}
    return {"phases": phases}


class FactorialDecisionTests(unittest.TestCase):
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

        first_half_pairs = [
            (order[index], order[index + 1])
            for order in PERFORMANCE_ORDERS[:4]
            for index in range(3)
        ]
        self.assertEqual(len(first_half_pairs), len(set(first_half_pairs)))
        self.assertEqual(len(first_half_pairs), 12)

    def test_factorial_interaction(self) -> None:
        values = {
            "attack_shared": 0.8,
            "attack_blocked": 1.0,
            "placebo_shared": 1.0,
            "placebo_blocked": 1.0,
        }
        self.assertAlmostEqual(factorial_interaction(values), -0.2)

    def test_mechanism_gate_requires_attack_specific_shared_update(self) -> None:
        runs = {
            arm: gate_run(
                workload=arm.split("_", 1)[0],
                update_mode=arm.split("_", 1)[1],
            )
            for arm in ARMS
        }
        result = mechanism_gate(runs)
        self.assertTrue(result["pass"])
        runs["attack_blocked"]["blocked_state_invariant"] = False
        self.assertFalse(mechanism_gate(runs)["pass"])

    def test_performance_signal_resamples_eight_complete_blocks(self) -> None:
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
        self.assertEqual(result["summaries"]["throughput"]["n"], 8)
        self.assertEqual(result["negative_throughput_block_count"], 8)
        self.assertEqual(
            result["one_sided_exact_sign_probability"], 1 / 256
        )
        self.assertAlmostEqual(
            result["summaries"]["throughput"]["mean"], -0.2
        )

    def test_sign_probability_counts_zeros_as_nonnegative(self) -> None:
        self.assertAlmostEqual(exact_negative_sign_probability(7, 8), 9 / 256)
        self.assertAlmostEqual(exact_negative_sign_probability(8, 8), 1 / 256)


if __name__ == "__main__":
    unittest.main()
