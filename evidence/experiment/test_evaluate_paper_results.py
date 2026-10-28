#!/usr/bin/env python
"""Fail-closed synthetic fixtures for the AVEP postflight evaluator.

These tests deliberately avoid real experiment outputs.  They exercise the
integrity boundaries that must prevent a false ``REPRODUCED`` classification.
"""

from __future__ import annotations

import importlib.util
import json
import tarfile
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("evaluate_paper_results.py")
SPEC = importlib.util.spec_from_file_location("avep_evaluator", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load evaluator from {MODULE_PATH}")
EVALUATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVALUATOR)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def clean_state() -> dict[str, object]:
    return {
        "available": True,
        "steps_since_refit": 0,
        "refits": 0,
        "slope": 0.5,
        "intercepts": [-0.2] * EVALUATOR.SPECULATIVE_STEPS,
        "counts": [0.0] * EVALUATOR.SPECULATIVE_STEPS,
        "info": [[0.0] * 3 for _ in range(EVALUATOR.SPECULATIVE_STEPS)],
        "grad": [[0.0] * 2 for _ in range(EVALUATOR.SPECULATIVE_STEPS)],
    }


def profiled_state() -> dict[str, object]:
    state = clean_state()
    state["steps_since_refit"] = 6
    state["counts"] = [66.0, 0.0, 0.0, 0.0]
    state["info"][0] = [1.0, 2.0, 3.0]
    state["grad"][0] = [4.0, 5.0]
    return state


def unavailable_state() -> dict[str, object]:
    return {
        "available": False,
        "reason": "No online acceptance estimator is active",
    }


class SyntheticFixtureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.requests_patch = mock.patch.dict(
            EVALUATOR.EXPECTED_REQUESTS,
            {phase: 1 for phase in EVALUATOR.PHASES},
            clear=True,
        )
        self.requests_patch.start()

    def tearDown(self) -> None:
        self.requests_patch.stop()
        self.temporary.cleanup()

    def phase_payload(
        self,
        run_name: str,
        phase: str,
        *,
        token_id: int = 42,
    ) -> dict[str, object]:
        phase_index = EVALUATOR.PHASES.index(phase)
        started = 1_000_000_000 + phase_index * 1_000_000_000
        finished = started + 100_000_000
        config = EVALUATOR.expected_phase_config(
            run_name,
            phase,
            token_id,
        )
        token_ids: list[int] | None = None
        if config["return_token_ids"]:
            allowed = config["allowed_token_id"]
            emitted = token_id if allowed is None else allowed
            token_ids = [emitted] * EVALUATOR.MAX_TOKENS
        return {
            "config": config,
            "started_ns": started,
            "finished_ns": finished,
            "summary": {
                "requests": 1,
                "successful": 1,
                "failed": 0,
                "completion_tokens": EVALUATOR.MAX_TOKENS,
                "wall_seconds": 0.01,
                "aggregate_output_tokens_per_second": (
                    float(EVALUATOR.MAX_TOKENS) / 0.01
                ),
                "latency_ms_p50": 10.0,
                "latency_ms_p95": 10.0,
            },
            "records": [
                {
                    "index": 0,
                    "ok": True,
                    "started_ns": started + 10_000_000,
                    "finished_ns": started + 20_000_000,
                    "latency_ms": 10.0,
                    "usage": {"completion_tokens": EVALUATOR.MAX_TOKENS},
                    "token_ids": token_ids,
                }
            ],
        }

    def write_run(self, run_name: str, *, token_id: int = 42) -> Path:
        run_dir = self.root / run_name
        run_dir.mkdir()
        expected = EVALUATOR.EXPECTED_METADATA[run_name]
        metadata = {
            "run_name": run_name,
            "poison_token_id": token_id,
            **expected,
        }
        write_json(run_dir / "metadata.json", metadata)
        (run_dir / "COMPLETE").write_text("complete\n")
        (run_dir / "server.log").write_text("")
        for phase in EVALUATOR.PHASES:
            payload = self.phase_payload(run_name, phase, token_id=token_id)
            write_json(
                run_dir / f"{phase}.json",
                payload,
            )
            write_json(run_dir / f"{phase}.summary.json", payload["summary"])

        state_names = [
            "initial",
            "warmup",
            "baseline",
            "intervention",
            *(f"post_{index:02d}" for index in range(1, 7)),
        ]
        if expected["arm"] == "reset":
            state_names.append("reset")
        for state_name in state_names:
            if not expected["adaptive"]:
                state = unavailable_state()
            elif state_name == "initial":
                state = profiled_state()
            else:
                state = clean_state()
            write_json(run_dir / f"state_{state_name}.json", {"results": [state]})

        if expected["arm"] == "reset":
            write_json(
                run_dir / "estimator_reset.json",
                {
                    "results": [
                        {
                            "available": True,
                            "reset": {
                                "before": clean_state(),
                                "after": clean_state(),
                            },
                        }
                    ]
                },
            )
        return run_dir

    def test_wrong_phase_config_and_token_are_rejected(self) -> None:
        expected = EVALUATOR.expected_phase_config(
            "pair_01_attack",
            "intervention",
            42,
        )
        payload = self.phase_payload("pair_01_attack", "intervention")
        payload["config"]["phase"] = "post_01"
        payload["config"]["allowed_token_id"] = 999
        path = self.root / "intervention.json"
        write_json(path, payload)

        _, errors, _ = EVALUATOR.inspect_phase(
            path,
            "intervention",
            expected,
        )

        self.assertTrue(any("config.phase" in error for error in errors))
        self.assertTrue(
            any("config.allowed_token_id" in error for error in errors)
        )

    def test_overlapping_phase_times_are_rejected(self) -> None:
        run_dir = self.write_run("pair_01_attack")
        baseline_path = run_dir / "baseline.json"
        baseline = EVALUATOR.load_object(baseline_path)
        intervention = EVALUATOR.load_object(run_dir / "intervention.json")
        baseline["finished_ns"] = intervention["started_ns"] + 1
        write_json(baseline_path, baseline)

        result = EVALUATOR.inspect_run(run_dir)

        self.assertTrue(
            any("baseline overlaps or follows intervention" in error
                for error in result["errors"])
        )

    def test_large_nanosecond_timestamps_are_preserved_exactly(self) -> None:
        phase = "baseline"
        payload = self.phase_payload("pair_01_attack", phase)
        origin = 1_000_000_000_000_000_000
        record_start = origin + 1
        record_finish = origin + 10_000_063
        wall_seconds = (record_finish - record_start) / 1_000_000_000
        payload["started_ns"] = origin
        payload["finished_ns"] = origin + 100_000_000
        payload["records"][0]["started_ns"] = record_start
        payload["records"][0]["finished_ns"] = record_finish
        payload["summary"]["wall_seconds"] = wall_seconds
        payload["summary"]["aggregate_output_tokens_per_second"] = (
            EVALUATOR.MAX_TOKENS / wall_seconds
        )
        path = self.root / "baseline.json"
        write_json(path, payload)

        _, errors, timing = EVALUATOR.inspect_phase(
            path,
            phase,
            EVALUATOR.expected_phase_config(
                "pair_01_attack",
                phase,
                42,
            ),
        )

        self.assertEqual(errors, [])
        self.assertEqual(
            timing,
            {
                "started_ns": origin,
                "finished_ns": origin + 100_000_000,
            },
        )
        self.assertEqual(EVALUATOR.nonnegative_integer(record_start), record_start)
        self.assertIsNone(EVALUATOR.nonnegative_integer(True))
        self.assertIsNone(EVALUATOR.nonnegative_integer(3.0))
        self.assertIsNone(EVALUATOR.nonnegative_integer(1e18))

    def test_mismatched_profiled_initial_states_are_rejected(self) -> None:
        names = ("pair_01_attack", "pair_01_placebo")
        expected = {
            name: EVALUATOR.EXPECTED_METADATA[name] for name in names
        }
        with mock.patch.dict(EVALUATOR.EXPECTED_METADATA, expected, clear=True):
            attack_dir = self.write_run(names[0])
            placebo_dir = self.write_run(names[1])
            placebo = EVALUATOR.load_object(
                placebo_dir / "state_initial.json"
            )
            placebo["results"][0]["info"][0][0] = 9.0
            write_json(placebo_dir / "state_initial.json", placebo)
            errors: list[str] = []

            result = EVALUATOR.validate_adaptive_initial_states(
                self.root,
                errors,
            )

        self.assertEqual(EVALUATOR.inspect_run(attack_dir)["errors"], [])
        self.assertFalse(result["valid"])
        self.assertFalse(result["semantically_identical"])
        self.assertFalse(result["byte_identical"])
        self.assertTrue(
            any("not semantically identical" in error for error in errors)
        )

    def test_identical_invalid_startup_profiles_are_rejected(self) -> None:
        names = ("pair_01_attack", "pair_01_placebo")
        expected = {
            name: EVALUATOR.EXPECTED_METADATA[name] for name in names
        }
        cases = (
            ("slope", 0.75, "slope is not 0.5"),
            ("steps_since_refit", 5, "steps_since_refit is not 6"),
            ("counts", [65.0, 0.0, 0.0, 0.0], "counts are not"),
        )
        with mock.patch.dict(EVALUATOR.EXPECTED_METADATA, expected, clear=True):
            run_dirs = [self.write_run(name) for name in names]
            for field, value, expected_error in cases:
                with self.subTest(field=field):
                    state = profiled_state()
                    state[field] = value
                    for run_dir in run_dirs:
                        write_json(
                            run_dir / "state_initial.json",
                            {"results": [state]},
                        )
                    errors: list[str] = []
                    result = EVALUATOR.validate_adaptive_initial_states(
                        self.root,
                        errors,
                    )

                    self.assertFalse(result["valid"])
                    self.assertTrue(result["semantically_identical"])
                    self.assertTrue(result["byte_identical"])
                    self.assertFalse(result["startup_profile_valid"])
                    self.assertTrue(
                        any(expected_error in error for error in errors)
                    )

    def test_cold_reset_after_profiled_initial_is_accepted(self) -> None:
        run_dir = self.write_run("reset_01")

        result = EVALUATOR.inspect_run(run_dir)

        self.assertEqual(result["errors"], [])

    def test_failed_reset_is_rejected(self) -> None:
        run_dir = self.write_run("reset_01")
        reset = EVALUATOR.load_object(run_dir / "estimator_reset.json")
        reset["results"][0]["reset"]["after"]["slope"] = 0.75
        write_json(run_dir / "estimator_reset.json", reset)

        result = EVALUATOR.inspect_run(run_dir)

        self.assertTrue(
            any("reset.after" in error for error in result["errors"])
        )
        self.assertTrue(
            any("does not match state_reset" in error
                for error in result["errors"])
        )

    def test_adaptive_off_active_estimator_is_rejected(self) -> None:
        run_dir = self.write_run("adaptive_off_01")
        write_json(
            run_dir / "state_initial.json",
            {"results": [clean_state()]},
        )

        result = EVALUATOR.inspect_run(run_dir)

        self.assertTrue(
            any("adaptive-off run exposes an active estimator" in error
                for error in result["errors"])
        )

    def test_budget_telemetry_step_gap_and_empty_phase_are_rejected(self) -> None:
        lines: list[str] = []
        for index, phase in enumerate(EVALUATOR.PHASES):
            step = index + 1 if index < 3 else index + 2
            maximum = 0 if phase == "post_06" else 4
            budget = 0 if maximum == 0 else 2
            event = {
                "step": step,
                "max_draft_budget": maximum,
                "draft_budget": budget,
                "scheduled_drafts": maximum,
            }
            lines.extend(
                [
                    f"===== AVEP_PHASE {phase}_begin",
                    "AVEP_BUDGET " + json.dumps(event),
                    f"===== AVEP_PHASE {phase}_end",
                ]
            )
        path = self.root / "server.log"
        path.write_text("\n".join(lines) + "\n")

        result = EVALUATOR.raw_budget_trace(path)

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("step sequence is not contiguous" in error
                for error in result["errors"])
        )
        self.assertTrue(
            any("post_06 has no usable budget observations" in error
                for error in result["errors"])
        )

    def test_raw_analyzer_ratio_mismatch_is_rejected(self) -> None:
        raw_runs = {
            "pair_01_attack": {
                "post_mean_ratios": {
                    "throughput": 0.8,
                    "latency_p50": 1.2,
                    "latency_p95": 1.3,
                }
            }
        }
        assessment_rows = {
            "pair_01_attack": {
                "post_mean_throughput_ratio": 0.9,
                "post_mean_latency_p50_ratio": 1.2,
                "post_mean_latency_p95_ratio": 1.3,
            }
        }
        errors: list[str] = []

        EVALUATOR.compare_assessment_ratios(
            raw_runs,
            assessment_rows,
            errors,
        )

        self.assertIn(
            "raw/analyzer pair_01_attack throughput ratio mismatch",
            errors,
        )

    def test_bad_archive_hash_is_rejected(self) -> None:
        result_root = self.root / "paper_results"
        result_root.mkdir()
        assessment = result_root / "paper_assessment.json"
        write_json(assessment, {})
        (result_root / "paper_assessment.stdout.json").write_text("{}\n")
        (result_root / "paper_trials.csv").write_text("run\n")
        (result_root / "PREDECLARED_DECISION_RULES.md").write_text("rules\n")
        (result_root / "EXPERIMENT_COMPLETE").write_text(
            "2026-09-18T00:00:00+00:00\n"
        )
        preflight = result_root / "token_preflight"
        preflight.mkdir()
        (preflight / "COMPLETE").write_text("complete\n")
        (preflight / "selected_token_id.txt").write_text("42\n")

        root_files = {
            "manifest.txt",
            "ordinary_tokens.json",
            "paper_setup.log",
            "PAPER_SETUP_COMPLETE",
            "avep_paper_instrumentation.patch",
            "paper_probe.py",
            "find_ordinary_tokens.py",
            "analyze_paper_trials.py",
            "run_paper_trials.sh",
            "setup_paper_instance.sh",
        }
        for name in root_files:
            (self.root / name).write_text(f"fixture {name}\n")

        archive = self.root / "avep-paper-results.tgz"
        with tarfile.open(archive, "w:gz") as output:
            for name in sorted(root_files):
                output.add(self.root / name, arcname=name)
            output.add(result_root, arcname="paper_results")
        sidecar = self.root / "avep-paper-results.tgz.sha256"
        sidecar.write_text(f"{'0' * 64}  {archive.name}\n")
        errors: list[str] = []

        result = EVALUATOR.validate_archive(
            result_root,
            assessment,
            archive,
            sidecar,
            errors,
        )

        self.assertFalse(result["valid"])
        self.assertIn(
            "archive SHA-256 does not match sidecar",
            result["errors"],
        )
        self.assertIn(
            "archive: archive SHA-256 does not match sidecar",
            errors,
        )


class ClassificationGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.result_root = self.root / "paper_results"
        self.result_root.mkdir()
        self.assessment = self.result_root / "paper_assessment.json"
        write_json(self.assessment, {})
        self.archive = self.root / "evidence.tgz"
        self.archive.write_bytes(b"fixture")
        self.sidecar = self.root / "evidence.tgz.sha256"
        self.sidecar.write_text(f"{'0' * 64}  evidence.tgz\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def paired_summary(*, crossing_zero: bool) -> dict[str, object]:
        throughput_high = 0.01 if crossing_zero else -0.05
        return {
            "summary": {
                "throughput": {
                    "n": 6,
                    "mean": -0.1,
                    "ci95_low": -0.2,
                    "ci95_high": throughput_high,
                },
                "latency_p50": {
                    "n": 6,
                    "mean": 0.1,
                    "ci95_low": 0.05,
                    "ci95_high": 0.2,
                },
                "latency_p95": {
                    "n": 6,
                    "mean": 0.2,
                    "ci95_low": 0.1,
                    "ci95_high": 0.3,
                },
            }
        }

    @staticmethod
    def inspected_run(path: Path) -> dict[str, object]:
        return {
            "run": path.name,
            "metadata": {"poison_token_id": 42},
            "metadata_mismatches": {},
            "phase_errors": {},
            "post_mean_ratios": {},
            "estimator_movement": {
                "baseline": [0.5, -0.2, -0.2, -0.2, -0.2],
                "intervention": [0.6, -0.1, -0.1, -0.1, -0.1],
                "delta": [0.1] * 5,
                "l2_norm": 0.5,
            },
            "errors": [],
        }

    def evaluate_with_mocks(
        self,
        *,
        names: set[str],
        crossing_zero: bool,
        archive_invalid: bool = False,
    ) -> dict[str, object]:
        for name in names:
            (self.result_root / name).mkdir()

        def validate_archive(
            _result_root: Path,
            _assessment: Path,
            _archive: Path,
            _sidecar: Path,
            errors: list[str],
        ) -> dict[str, object]:
            if archive_invalid:
                errors.append("archive: archive SHA-256 does not match sidecar")
            return {"valid": not archive_invalid}

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "inspect_run",
                    side_effect=self.inspected_run,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "validate_selected_token",
                    return_value={"valid": True},
                )
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "validate_environments",
                    return_value={"all_match": True},
                )
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "validate_adaptive_initial_states",
                    return_value={"valid": True},
                )
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "validate_assessment",
                    return_value={},
                )
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "compare_assessment_ratios",
                )
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "raw_paired_effects",
                    return_value=self.paired_summary(
                        crossing_zero=crossing_zero
                    ),
                )
            )
            stack.enter_context(
                mock.patch.object(EVALUATOR, "compare_paired_summaries")
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "estimator_analysis",
                    return_value={"stronger_after_attack": True},
                )
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "control_analysis",
                    return_value={"all_controls_pass": True},
                )
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "mechanism_analysis",
                    return_value={"passes": True},
                )
            )
            stack.enter_context(
                mock.patch.object(
                    EVALUATOR,
                    "validate_archive",
                    side_effect=validate_archive,
                )
            )
            return EVALUATOR.evaluate(
                self.result_root,
                self.assessment,
                self.archive,
                self.sidecar,
            )

    def test_missing_run_cannot_be_reproduced(self) -> None:
        names = set(EVALUATOR.EXPECTED_METADATA)
        names.remove("pair_06_placebo")

        result = self.evaluate_with_mocks(
            names=names,
            crossing_zero=False,
        )

        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertIn("pair_06_placebo", result["integrity"]["missing_runs"])
        self.assertFalse(result["decision"]["reproduced_evidence_passes"])

    def test_bad_archive_hash_cannot_be_reproduced(self) -> None:
        result = self.evaluate_with_mocks(
            names=set(EVALUATOR.EXPECTED_METADATA),
            crossing_zero=False,
            archive_invalid=True,
        )

        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertFalse(result["integrity"]["archive"]["valid"])
        self.assertFalse(result["decision"]["reproduced_evidence_passes"])

    def test_throughput_ci_crossing_zero_is_inconclusive(self) -> None:
        result = self.evaluate_with_mocks(
            names=set(EVALUATOR.EXPECTED_METADATA),
            crossing_zero=True,
        )

        self.assertTrue(result["integrity"]["valid"])
        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertFalse(result["decision"]["primary_adverse_ci"])
        self.assertFalse(result["decision"]["reproduced_evidence_passes"])


if __name__ == "__main__":
    unittest.main()
