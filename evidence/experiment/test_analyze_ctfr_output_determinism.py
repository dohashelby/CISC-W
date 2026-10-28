#!/usr/bin/env python
"""Unit tests for the CTFR exact-output determinism diagnostic."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from analyze_ctfr_output_determinism import analyze, first_divergence


def manifest() -> dict:
    return {
        "entries": [
            {
                "ordinal": 0,
                "prompt_id": "prompt-a",
                "seed": 10,
            },
            {
                "ordinal": 1,
                "prompt_id": "prompt-a",
                "seed": 10,
            },
            {
                "ordinal": 2,
                "prompt_id": "prompt-a",
                "seed": 11,
            },
        ]
    }


def write_arm(
    root: Path,
    arm: str,
    baseline: list[list[int]],
    evaluation: list[list[int]],
) -> None:
    run = root / f"gate_stage_d_{arm}"
    run.mkdir()
    for phase, outputs in (
        ("baseline_evaluation", baseline),
        ("evaluation", evaluation),
    ):
        records = [
            {"ok": True, "ordinal": ordinal, "token_ids": tokens}
            for ordinal, tokens in enumerate(outputs)
        ]
        (run / f"{phase}.json").write_text(
            json.dumps({"records": records})
        )


class OutputDeterminismTests(unittest.TestCase):
    def test_first_divergence_handles_tokens_and_length(self) -> None:
        self.assertIsNone(first_divergence((1, 2), (1, 2)))
        self.assertEqual(first_divergence((1, 2), (1, 3)), 1)
        self.assertEqual(first_divergence((1,), (1, 2)), 1)

    def test_identical_controls_are_classified_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = [[1, 2], [1, 2], [1, 2]]
            for arm in ("shared", "frozen", "ctfr-shadow"):
                write_arm(root, arm, outputs, outputs)
            manifests = {
                "baseline_evaluation.json": manifest(),
                "shifted_evaluation.json": manifest(),
            }
            result = analyze(root, manifests)
        self.assertEqual(
            result["classification"],
            "exact_output_reproducible_in_observed_controls",
        )

    def test_divergent_frozen_shadow_control_detects_nondeterminism(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stable = [[1, 2], [1, 2], [1, 2]]
            divergent = [[1, 2], [1, 2], [1, 9]]
            write_arm(root, "shared", stable, stable)
            write_arm(root, "frozen", stable, stable)
            write_arm(root, "ctfr-shadow", stable, divergent)
            manifests = {
                "baseline_evaluation.json": manifest(),
                "shifted_evaluation.json": manifest(),
            }
            result = analyze(root, manifests)
        self.assertEqual(
            result["classification"],
            "execution_nondeterminism_detected",
        )
        comparison = result["phases"]["evaluation"][
            "identical_policy_controls"
        ]["frozen__ctfr-shadow"]
        self.assertEqual(comparison["exact_equal"], 2)
        self.assertEqual(
            comparison["first_divergence_examples"],
            [{"ordinal": 2, "first_divergence_position": 1}],
        )

    def test_within_arm_repeated_prompt_variants_are_counted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stable = [[1], [1], [1]]
            frozen = [[1], [2], [3]]
            write_arm(root, "shared", stable, stable)
            write_arm(root, "frozen", frozen, frozen)
            write_arm(root, "ctfr-shadow", frozen, frozen)
            manifests = {
                "baseline_evaluation.json": manifest(),
                "shifted_evaluation.json": manifest(),
            }
            result = analyze(root, manifests)
        within = result["phases"]["evaluation"]["arms"]["frozen"][
            "within_arm"
        ]
        self.assertEqual(within["max_outputs_for_one_prompt"], 3)
        self.assertEqual(
            within["identical_prompt_seed_groups_with_multiple_outputs"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
