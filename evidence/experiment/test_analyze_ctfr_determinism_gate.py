#!/usr/bin/env python
"""Unit tests for the CTFR exact-output determinism gate analyzer."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from analyze_ctfr_determinism_gate import RUN_SPECS, analyze


def write_fixture(
    root: Path,
    variants: dict[tuple[str, int], list[list[int]]],
) -> None:
    (root / "DECLARED_SCHEDULE.json").write_text(
        json.dumps(
            {
                "schema": "ctfr-determinism-gate-v1",
                "evaluation_requests": 3,
            }
        ),
        encoding="utf-8",
    )
    default_outputs = [[1, 2], [3, 4], [5, 6]]
    for spec in RUN_SPECS:
        condition = root / spec.name
        condition.mkdir()
        (condition / "metadata.json").write_text(
            json.dumps(
                {
                    "execution_mode": spec.execution_mode,
                    "process_uuid": f"process-{spec.name}",
                }
            ),
            encoding="utf-8",
        )
        for repetition in range(1, spec.repetitions + 1):
            outputs = variants.get(
                (spec.name, repetition),
                default_outputs,
            )
            records = [
                {
                    "ok": True,
                    "ordinal": ordinal,
                    "token_ids": tokens,
                }
                for ordinal, tokens in enumerate(outputs)
            ]
            artifact = {
                "config": {
                    "concurrency": spec.concurrency,
                    "waves_per_batch": spec.waves_per_batch,
                    "return_token_ids": True,
                    "manifest_sha256": "a" * 64,
                },
                "summary": {"evidence_ok": True},
                "records": records,
            }
            (condition / f"evaluation_{repetition:02d}.json").write_text(
                json.dumps(artifact),
                encoding="utf-8",
            )


class DeterminismGateTests(unittest.TestCase):
    def analyze_variants(
        self,
        variants: dict[tuple[str, int], list[list[int]]],
    ) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, variants)
            return analyze(root)

    def test_realistic_gate_is_selected_when_every_control_is_exact(self) -> None:
        result = self.analyze_variants({})
        self.assertEqual(
            result["classification"],
            "realistic_fresh_process_exact_replay_supported",
        )

    def test_small_batch_gate_is_selected_after_c32_divergence(self) -> None:
        result = self.analyze_variants(
            {("graph_c32_b", 1): [[1, 2], [3, 9], [5, 6]]}
        )
        self.assertEqual(
            result["classification"],
            "small_batch_graph_exact_replay_supported",
        )
        comparison = result["comparisons"][
            "fresh_process_graph_c32"
        ]
        self.assertEqual(comparison["exact_equal"], 2)
        self.assertEqual(
            comparison["first_divergence_examples"],
            [{"ordinal": 1, "first_divergence_position": 1}],
        )

    def test_eager_gate_is_selected_after_graph_divergence(self) -> None:
        divergent = [[9], [8], [7]]
        result = self.analyze_variants(
            {
                ("graph_c32_b", 1): divergent,
                ("graph_c2_b", 1): divergent,
            }
        )
        self.assertEqual(
            result["classification"],
            "eager_small_batch_exact_replay_supported",
        )

    def test_non_hash_fallback_is_selected_when_all_modes_diverge(self) -> None:
        divergent = [[9], [8], [7]]
        result = self.analyze_variants(
            {
                ("graph_c32_b", 1): divergent,
                ("graph_c2_b", 1): divergent,
                ("eager_c2_b", 1): divergent,
            }
        )
        self.assertEqual(
            result["classification"],
            "cross_process_exact_replay_not_supported",
        )

    def test_probe_configuration_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, {})
            path = root / "graph_c32_a" / "evaluation_01.json"
            artifact = json.loads(path.read_text(encoding="utf-8"))
            artifact["config"]["concurrency"] = 31
            path.write_text(json.dumps(artifact), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "concurrency"):
                analyze(root)


if __name__ == "__main__":
    unittest.main()
