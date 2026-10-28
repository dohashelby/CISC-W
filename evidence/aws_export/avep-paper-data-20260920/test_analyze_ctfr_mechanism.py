#!/usr/bin/env python
"""Unit tests for the CTFR mechanism decision logic."""

from __future__ import annotations

import unittest

from analyze_ctfr_mechanism import (
    METRICS,
    PERFORMANCE_ARMS,
    PERFORMANCE_ORDERS,
    POST_PHASES,
    PRE_PHASES,
    committed_state,
    domain_state,
    exact_positive_sign_probability,
    finite_tree,
    mechanism_gate,
    mitigation_interaction,
    performance_result,
    shadow_feedback_changed,
    state_changed,
)


def estimator_state(
    *,
    canonical: float = 0.0,
    transformed: float = 0.0,
    attacker_shadow: float = 0.0,
    victim_shadow: float = 0.0,
) -> dict:
    values = [canonical, transformed, attacker_shadow, victim_shadow]
    return {
        "committed_version": 0,
        "ctfr_influence_credits": [2.0, 2.0],
        "steps_since_refit": [int(value) for value in values],
        "refits": [int(value) for value in values],
        "slope": values,
        "intercepts": [[value] * 4 for value in values],
        "counts": [[value] * 4 for value in values],
        "info": [[[value] * 3 for _ in range(4)] for value in values],
        "grad": [[[value] * 2 for _ in range(4)] for value in values],
    }


def gate_run(arm: str) -> dict:
    workload, mode = arm.split("_", 1)
    before = estimator_state()
    if arm == "attack_shared":
        after = estimator_state(canonical=1.0)
    elif arm == "attack_route":
        after = estimator_state(transformed=1.0)
    elif mode == "ctfr-shadow":
        after = estimator_state(attacker_shadow=1.0)
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


def performance_run(
    arm: str,
    *,
    shared_attack_throughput: float = 80.0,
    ctfr_attack_throughput: float = 100.0,
    ctfr_stationary_multiplier: float = 1.0,
) -> dict:
    workload, mode = arm.split("_", 1)
    harmed = workload == "attack" and mode == "shared"
    ctfr = mode == "ctfr-shadow"
    baseline_throughput = 100.0 * (
        ctfr_stationary_multiplier if ctfr else 1.0
    )
    baseline_latency = 100.0 / (
        ctfr_stationary_multiplier if ctfr else 1.0
    )
    phases = {}
    for phase in PRE_PHASES:
        phases[phase] = {
            "summary": {
                METRICS["throughput"]: baseline_throughput,
                METRICS["latency_p50"]: baseline_latency,
                METRICS["latency_p95"]: baseline_latency,
            }
        }
    for phase in POST_PHASES:
        throughput = baseline_throughput
        if harmed:
            throughput = shared_attack_throughput
        elif workload == "attack" and ctfr:
            throughput = ctfr_attack_throughput * ctfr_stationary_multiplier
        phases[phase] = {
            "summary": {
                METRICS["throughput"]: throughput,
                METRICS["latency_p50"]: 120.0 if harmed else baseline_latency,
                METRICS["latency_p95"]: 140.0 if harmed else baseline_latency,
            }
        }
    return {"phases": phases}


class CTFRDecisionTests(unittest.TestCase):
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
            "attack_ctfr-shadow": 1.0,
            "placebo_shared": 1.0,
            "placebo_ctfr-shadow": 1.0,
        }
        self.assertAlmostEqual(mitigation_interaction(values), 0.2)

    def test_domain_comparison_includes_refit_clock_and_statistics(self) -> None:
        before = estimator_state()
        after = estimator_state()
        after["steps_since_refit"][2] = 1
        self.assertFalse(state_changed(before, after, 0))
        self.assertTrue(state_changed(before, after, 2))
        self.assertEqual(domain_state(after, 2)["steps_since_refit"], 1)
        self.assertEqual(committed_state(before), committed_state(after))

    def test_shadow_feedback_requires_statistics_counts_and_clock(self) -> None:
        before = estimator_state()
        clock_only = estimator_state()
        clock_only["steps_since_refit"][2] = 1
        self.assertFalse(shadow_feedback_changed(before, clock_only, 2))
        complete = estimator_state(attacker_shadow=1.0)
        self.assertTrue(shadow_feedback_changed(before, complete, 2))

    def test_committed_state_rejects_missing_metadata(self) -> None:
        state = estimator_state()
        del state["committed_version"]
        with self.assertRaises(ValueError):
            committed_state(state)

    def test_state_validation_rejects_non_finite_nested_values(self) -> None:
        self.assertTrue(finite_tree([[0.0, 1.0], [2, 3]]))
        self.assertFalse(finite_tree([[0.0], [float("nan")]]))

    def test_gate_requires_noninterference_and_routed_learning(self) -> None:
        arms = (
            "placebo_shared",
            "attack_shared",
            "attack_route",
            "placebo_ctfr-shadow",
            "attack_ctfr-shadow",
        )
        runs = {arm: gate_run(arm) for arm in arms}
        result = mechanism_gate(runs)
        self.assertTrue(result["pass"])
        runs["attack_ctfr-shadow"]["states"]["intervention"] = (
            estimator_state(canonical=1.0, attacker_shadow=1.0)
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
        self.assertEqual(result["shared_adverse_throughput_block_count"], 8)
        self.assertEqual(result["positive_throughput_block_count"], 8)
        self.assertEqual(result["one_sided_exact_sign_probability"], 1 / 256)
        self.assertAlmostEqual(
            result["summaries"]["throughput"]["mean"],
            0.2,
        )
        self.assertTrue(result["benign_overhead_guardrail_pass"])
        self.assertTrue(result["benign_equivalence_interval_pass"])

    def test_signal_rejects_positive_interaction_without_shared_harm(self) -> None:
        runs = {}
        for block_number in range(1, 9):
            block_id = f"{block_number:02d}"
            for arm in PERFORMANCE_ARMS:
                name = f"perf_block_{block_id}_{arm}"
                runs[name] = performance_run(
                    arm,
                    shared_attack_throughput=100.0,
                    ctfr_attack_throughput=120.0,
                )
        result = performance_result(runs)
        self.assertGreater(
            result["summaries"]["throughput"]["ci95_low"], 0
        )
        self.assertEqual(result["shared_adverse_throughput_block_count"], 0)
        self.assertFalse(result["signal"])

    def test_signal_rejects_ctfr_attack_throughput_below_floor(self) -> None:
        runs = {}
        for block_number in range(1, 9):
            block_id = f"{block_number:02d}"
            for arm in PERFORMANCE_ARMS:
                name = f"perf_block_{block_id}_{arm}"
                runs[name] = performance_run(
                    arm,
                    shared_attack_throughput=50.0,
                    ctfr_attack_throughput=90.0,
                )
        result = performance_result(runs)
        self.assertGreater(
            result["summaries"]["throughput"]["ci95_low"], 0
        )
        self.assertLess(result["mean_attack_ctfr_normalized_throughput"], 0.95)
        self.assertFalse(result["signal"])

    def test_absolute_overhead_is_not_erased_by_pre_normalization(self) -> None:
        runs = {}
        for block_number in range(1, 9):
            block_id = f"{block_number:02d}"
            for arm in PERFORMANCE_ARMS:
                name = f"perf_block_{block_id}_{arm}"
                runs[name] = performance_run(
                    arm,
                    ctfr_stationary_multiplier=0.8,
                )
        result = performance_result(runs)
        self.assertGreater(
            result["summaries"]["throughput"]["ci95_low"], 0
        )
        self.assertFalse(result["benign_overhead_guardrail_pass"])
        self.assertFalse(result["signal"])

    def test_sign_probability_counts_only_strictly_positive_blocks(self) -> None:
        self.assertAlmostEqual(exact_positive_sign_probability(7, 8), 9 / 256)
        self.assertAlmostEqual(exact_positive_sign_probability(8, 8), 1 / 256)


if __name__ == "__main__":
    unittest.main()
