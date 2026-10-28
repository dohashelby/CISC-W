#!/usr/bin/env python
"""Unit tests for the PCFR mitigation decision logic."""

from __future__ import annotations

import unittest

from analyze_pcfr_mitigation import (
    METRICS,
    PERFORMANCE_ARMS,
    PERFORMANCE_ORDERS,
    POST_PHASES,
    PRE_PHASES,
    domain_state,
    exact_positive_sign_probability,
    finite_tree,
    mechanism_gate,
    mitigation_interaction,
    performance_result,
    state_changed,
)


def estimator_state(*, canonical: float = 0.0, transformed: float = 0.0) -> dict:
    values = [canonical, transformed]
    return {
        "steps_since_refit": [int(canonical), int(transformed)],
        "refits": [int(canonical), int(transformed)],
        "slope": values,
        "intercepts": [[value] * 4 for value in values],
        "counts": [[value] * 4 for value in values],
        "info": [[[value] * 3 for _ in range(4)] for value in values],
        "grad": [[[value] * 2 for _ in range(4)] for value in values],
    }


def gate_run(arm: str) -> dict:
    workload, mode = arm.split("_", 1)
    before = estimator_state()
    if arm == "attack_shared" or arm == "placebo_route":
        after = estimator_state(canonical=1.0)
    elif arm == "attack_route":
        after = estimator_state(transformed=1.0)
    else:
        after = estimator_state()

    post_budget = 1.0
    if arm == "attack_shared":
        post_budget = 0.6
    budgets = {phase: 1.0 for phase in PRE_PHASES}
    budgets.update({phase: post_budget for phase in POST_PHASES})
    return {
        "phases": {
            "intervention": {
                "summary": {
                    "draft_acceptance_rate": 0.01
                    if workload == "attack"
                    else 0.25
                }
            }
        },
        "states": {
            "pre_intervention": before,
            "intervention": after,
        },
        "budgets": {"ratios": budgets},
        "mitigation_mode": mode,
    }


def performance_run(arm: str) -> dict:
    workload, mode = arm.split("_", 1)
    harmed = workload == "attack" and mode == "shared"
    phases = {}
    for phase in PRE_PHASES:
        phases[phase] = {
            "summary": {
                METRICS["throughput"]: 100.0,
                METRICS["latency_p50"]: 100.0,
                METRICS["latency_p95"]: 100.0,
            }
        }
    for phase in POST_PHASES:
        phases[phase] = {
            "summary": {
                METRICS["throughput"]: 80.0 if harmed else 100.0,
                METRICS["latency_p50"]: 120.0 if harmed else 100.0,
                METRICS["latency_p95"]: 140.0 if harmed else 100.0,
            }
        }
    return {"phases": phases}


class PCFRDecisionTests(unittest.TestCase):
    def test_schedule_balances_every_arm_position(self) -> None:
        self.assertEqual(len(PERFORMANCE_ORDERS), 8)
        for arm in PERFORMANCE_ARMS:
            positions = [
                position
                for order in PERFORMANCE_ORDERS
                for position, value in enumerate(order)
                if value == arm
            ]
            self.assertEqual(sorted(positions), [0, 0, 1, 1, 2, 2, 3, 3])

    def test_interaction_has_positive_mitigation_direction(self) -> None:
        values = {
            "attack_shared": 0.8,
            "attack_route": 1.0,
            "placebo_shared": 1.0,
            "placebo_route": 1.0,
        }
        self.assertAlmostEqual(mitigation_interaction(values), 0.2)

    def test_domain_comparison_includes_refit_clock_and_statistics(self) -> None:
        before = estimator_state()
        after = estimator_state()
        after["steps_since_refit"][1] = 1
        self.assertFalse(state_changed(before, after, 0))
        self.assertTrue(state_changed(before, after, 1))
        self.assertEqual(domain_state(after, 1)["steps_since_refit"], 1)

    def test_state_validation_rejects_non_finite_nested_values(self) -> None:
        self.assertTrue(finite_tree([[0.0, 1.0], [2, 3]]))
        self.assertFalse(finite_tree([[0.0], [float("nan")]]))

    def test_gate_requires_noninterference_and_routed_learning(self) -> None:
        arms = (
            "placebo_shared",
            "placebo_route",
            "attack_drop",
            "attack_route",
            "attack_shared",
        )
        runs = {arm: gate_run(arm) for arm in arms}
        result = mechanism_gate(runs)
        self.assertTrue(result["pass"])
        runs["attack_route"]["states"]["intervention"] = estimator_state(
            canonical=1.0,
            transformed=1.0,
        )
        self.assertFalse(mechanism_gate(runs)["pass"])

    def test_performance_signal_uses_eight_complete_blocks(self) -> None:
        runs = {}
        for block_number in range(1, 9):
            block_id = f"{block_number:02d}"
            for arm in PERFORMANCE_ARMS:
                name = f"perf_block_{block_id}_{arm}"
                runs[name] = performance_run(arm)
        result = performance_result(runs)
        self.assertTrue(result["signal"])
        self.assertEqual(result["positive_throughput_block_count"], 8)
        self.assertEqual(result["one_sided_exact_sign_probability"], 1 / 256)
        self.assertAlmostEqual(
            result["summaries"]["throughput"]["mean"],
            0.2,
        )
        self.assertTrue(result["benign_overhead_guardrail_pass"])
        self.assertTrue(result["benign_equivalence_interval_pass"])

    def test_sign_probability_counts_only_strictly_positive_blocks(self) -> None:
        self.assertAlmostEqual(exact_positive_sign_probability(7, 8), 9 / 256)
        self.assertAlmostEqual(exact_positive_sign_probability(8, 8), 1 / 256)


if __name__ == "__main__":
    unittest.main()
