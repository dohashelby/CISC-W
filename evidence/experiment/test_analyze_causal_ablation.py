#!/usr/bin/env python
"""Unit tests for causal-ablation decision logic."""

from __future__ import annotations

import unittest

from analyze_causal_ablation import (
    METRICS,
    POST_PHASES,
    PRE_PHASES,
    mechanism_gate,
    performance_result,
)


def gate_run(*, arm: str) -> dict:
    before = {"intercepts": [0.0, 0.0, 0.0, 0.0]}
    after = {
        "intercepts": (
            [-1.0, 0.0, 0.0, 0.0]
            if arm == "shared"
            else [0.0, 0.0, 0.0, 0.0]
        )
    }
    return {
        "phases": {
            "intervention": {
                "summary": {"draft_acceptance_rate": 0.0}
            }
        },
        "states": {
            "pre_intervention": before,
            "intervention": after,
        },
        "blocked_state_invariant": arm == "blocked",
        "budgets": {
            "ratios": {
                **{phase: 1.0 for phase in PRE_PHASES},
                "post_01": 0.7 if arm == "shared" else 1.0,
            }
        },
    }


def performance_run(*, shared: bool) -> dict:
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
                METRICS["throughput"]: 80.0 if shared else 100.0,
                METRICS["latency_p50"]: 120.0 if shared else 100.0,
                METRICS["latency_p95"]: 140.0 if shared else 100.0,
            }
        }
    phases["intervention"] = {"summary": {"wall_seconds": 30.0}}
    return {"phases": phases}


class CausalDecisionTests(unittest.TestCase):
    def test_mechanism_gate_passes_only_with_mediator_severed(self) -> None:
        shared = gate_run(arm="shared")
        blocked = gate_run(arm="blocked")
        result = mechanism_gate(shared, blocked)
        self.assertTrue(result["pass"])
        blocked["blocked_state_invariant"] = False
        self.assertFalse(mechanism_gate(shared, blocked)["pass"])

    def test_performance_signal_resamples_six_process_pairs(self) -> None:
        runs = {}
        for pair_number in range(1, 7):
            pair_id = f"{pair_number:02d}"
            runs[f"perf_pair_{pair_id}_shared"] = performance_run(shared=True)
            runs[f"perf_pair_{pair_id}_blocked"] = performance_run(shared=False)
        result = performance_result(runs)
        self.assertTrue(result["signal"])
        self.assertEqual(result["summaries"]["throughput"]["n"], 6)
        self.assertEqual(result["negative_throughput_pair_count"], 6)


if __name__ == "__main__":
    unittest.main()

