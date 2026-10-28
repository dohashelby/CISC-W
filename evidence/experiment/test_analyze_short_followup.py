#!/usr/bin/env python
"""Synthetic unit tests for the bounded AVEP follow-up analyzer."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("analyze_short_followup.py")
SPEC = importlib.util.spec_from_file_location("short_followup", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load analyzer from {MODULE_PATH}")
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_state(*, intercept0: float = -0.2) -> dict[str, object]:
    return {
        "available": True,
        "steps_since_refit": 0,
        "refits": 0,
        "slope": 0.5,
        "intercepts": [intercept0, -0.2, -0.2, -0.2],
        "counts": [0.0, 0.0, 0.0, 0.0],
        "info": [[0.0, 0.0, 0.0] for _ in range(4)],
        "grad": [[0.0, 0.0] for _ in range(4)],
    }


def speculative_metric(accepted: int, drafted: int = 100) -> dict[str, object]:
    if drafted == 0:
        return {
            "num_spec_steps": 0,
            "num_draft_tokens": 0,
            "num_accepted_draft_tokens": 0,
            "num_spec_tokens": 4,
            "draft_acceptance_rate": 0.0,
            "mean_acceptance_length": 1.0,
            "acceptance_histogram": [0, 0, 0, 0, 0],
        }
    steps = drafted // 4
    remaining = accepted
    per_step_accepted = []
    for _ in range(steps):
        value = min(4, remaining)
        per_step_accepted.append(value)
        remaining -= value
    histogram = [per_step_accepted.count(value) for value in range(5)]
    return {
        "num_spec_steps": steps,
        "num_draft_tokens": drafted,
        "num_accepted_draft_tokens": accepted,
        "num_spec_tokens": 4,
        "draft_acceptance_rate": accepted / drafted,
        "mean_acceptance_length": 1.0 + accepted / steps,
        "per_step_drafted": [4] * steps,
        "per_step_accepted": per_step_accepted,
        "acceptance_histogram": histogram,
    }


def phase_payload(
    config: dict[str, object],
    base_ns: int,
    *,
    accepted: int | None,
    duration_ns: int = 1_000_000,
) -> dict[str, object]:
    max_tokens = int(config["max_tokens"])
    record_start = base_ns + 10
    record_finish = record_start + duration_ns
    wall_seconds = duration_ns / 1_000_000_000
    allowed = config["allowed_token_id"]
    return_ids = bool(config["return_token_ids"])
    token_id = int(allowed) if allowed is not None else 7
    metric = speculative_metric(accepted or 0) if accepted is not None else None
    record = {
        "index": 0,
        "ok": True,
        "started_ns": record_start,
        "finished_ns": record_finish,
        "latency_ms": duration_ns / 1_000_000,
        "usage": {"completion_tokens": max_tokens},
        "token_ids": [token_id] * max_tokens if return_ids else [],
        "metrics": {"speculative_decoding": metric} if metric else {},
    }
    summary: dict[str, object] = {
        "requests": 1,
        "successful": 1,
        "failed": 0,
        "completion_tokens": max_tokens,
        "wall_seconds": wall_seconds,
        "aggregate_output_tokens_per_second": max_tokens / wall_seconds,
        "latency_ms_p50": duration_ns / 1_000_000,
        "latency_ms_p95": duration_ns / 1_000_000,
        "control_token_fraction": 1.0 if allowed is not None else None,
    }
    if metric is not None:
        summary.update(
            {
                "spec_requests": 1,
                "spec_steps": metric["num_spec_steps"],
                "draft_tokens": metric["num_draft_tokens"],
                "accepted_draft_tokens": metric[
                    "num_accepted_draft_tokens"
                ],
                "draft_acceptance_rate": metric["draft_acceptance_rate"],
            }
        )
    return {
        "config": config,
        "started_ns": base_ns,
        "finished_ns": record_finish + 10,
        "summary": summary,
        "records": [record],
    }


class FixedProtocolTest(unittest.TestCase):
    def test_adaptive_phase_configs_are_exact(self) -> None:
        self.assertEqual(ANALYZER.MAX_TOKENS, 2)
        self.assertEqual(
            ANALYZER.expected_declared_schedule()["screen"]["candidate"][
                "max_tokens"
            ],
            2,
        )
        self.assertGreaterEqual(ANALYZER.MAX_TOKENS, 2)
        self.assertEqual(ANALYZER.MAX_TOKENS, 2)
        warmup = ANALYZER.expected_phase_config(
            "warmup",
            arm="attack",
            poison_token_id=279,
            return_token_ids=True,
        )
        pre = ANALYZER.expected_phase_config(
            "pre_01",
            arm="attack",
            poison_token_id=279,
            return_token_ids=True,
        )
        intervention = ANALYZER.expected_phase_config(
            "intervention",
            arm="attack",
            poison_token_id=279,
            return_token_ids=True,
        )

        self.assertEqual(
            (warmup["requests"], warmup["concurrency"], warmup["max_tokens"]),
            (1024, 32, 32),
        )
        self.assertEqual(
            (pre["requests"], pre["concurrency"], pre["max_tokens"]),
            (128, 32, 32),
        )
        self.assertEqual(
            (
                intervention["requests"],
                intervention["concurrency"],
                intervention["max_tokens"],
            ),
            (4096, 8, 2),
        )
        self.assertEqual(intervention["allowed_token_id"], 279)

    def test_screen_tie_break_order_is_predeclared_order(self) -> None:
        self.assertEqual(
            ANALYZER.SCREEN_TOKEN_IDS,
            (279, 323, 6303, 8251, 23811, 3015, 8094, 12095, 13, 11, 0, 30),
        )
        tied = [
            {"token_id": token_id, "rate": 0.01, "position": position}
            for position, token_id in enumerate(ANALYZER.SCREEN_TOKEN_IDS)
            if token_id in (0, 279)
        ]
        selected = min(tied, key=lambda row: (row["rate"], row["position"]))
        self.assertEqual(selected["token_id"], 279)

    def test_detailed_metrics_fail_closed_on_zero_evidence(self) -> None:
        metric = {
            "num_spec_steps": 0,
            "num_draft_tokens": 0,
            "num_accepted_draft_tokens": 0,
            "num_spec_tokens": 4,
            "draft_acceptance_rate": 0.0,
            "per_step_drafted": [],
            "per_step_accepted": [],
            "acceptance_histogram": [0, 0, 0, 0, 0],
        }

        errors, totals = ANALYZER._detailed_metric_errors(
            metric, require_positive_evidence=True
        )

        self.assertIsNone(totals)
        self.assertTrue(any("num_spec_steps" in error for error in errors))
        self.assertTrue(any("num_draft_tokens" in error for error in errors))

    def test_recovery_with_no_adverse_windows_has_no_worst_value(self) -> None:
        values = {phase: 0.1 for phase in ANALYZER.POST_PHASES}

        summary = ANALYZER._recovery_summary(values, "throughput")

        self.assertEqual(summary["adverse_window_count"], 0)
        self.assertIsNone(summary["worst_adverse"])
        self.assertEqual(
            summary["first_sustained_non_adverse_window"], "post_01"
        )


class PotencyTest(unittest.TestCase):
    @staticmethod
    def synthetic_run(
        acceptance: float,
        intercept_delta: float,
        *,
        pre_budget: float,
        post_budget: float,
    ) -> dict[str, object]:
        phases = {
            phase: {"draft_acceptance_rate": None}
            for phase in ANALYZER.WORKLOAD_PHASES
        }
        phases["intervention"]["draft_acceptance_rate"] = acceptance
        budget_phases = {
            phase: {"mean_normalized_budget": 0.5}
            for phase in ANALYZER.WORKLOAD_PHASES
        }
        for phase in ANALYZER.PRE_PHASES:
            budget_phases[phase]["mean_normalized_budget"] = pre_budget
        budget_phases["post_01"]["mean_normalized_budget"] = post_budget
        return {
            "phases": phases,
            "estimator": {
                "intervention_delta_intercept0": intercept_delta,
            },
            "budget": {"phases": budget_phases},
        }

    def test_all_exact_potency_gates_pass(self) -> None:
        attack = self.synthetic_run(
            0.05,
            -0.6,
            pre_budget=0.5,
            post_budget=0.4,
        )
        placebo = self.synthetic_run(
            0.15,
            0.0,
            pre_budget=0.5,
            post_budget=0.5,
        )

        result = ANALYZER.potency_result(attack, placebo)

        self.assertTrue(result["pass"])
        self.assertAlmostEqual(
            result["observed"]["post1_budget_attack_minus_placebo"],
            -0.2,
        )

    def test_negative_potency_is_not_structural_failure(self) -> None:
        attack = self.synthetic_run(
            0.06,
            -0.4,
            pre_budget=0.5,
            post_budget=0.5,
        )
        placebo = self.synthetic_run(
            0.15,
            0.0,
            pre_budget=0.5,
            post_budget=0.5,
        )

        result = ANALYZER.potency_result(attack, placebo)

        self.assertFalse(result["pass"])
        self.assertFalse(result["gates"]["attack_acceptance"])
        self.assertFalse(result["gates"]["placebo_minus_attack_acceptance"])


class FullArtifactTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work = Path(self.temporary.name)
        self.result_root = self.work / "followup_results"
        self.result_root.mkdir()
        self.patches = [
            mock.patch.object(ANALYZER, "SCREEN_TOKEN_IDS", (279, 323)),
            mock.patch.object(ANALYZER, "SCREEN_TOKEN_COUNT", 2),
            mock.patch.object(ANALYZER, "SCREEN_WARMUP_REQUESTS", 1),
            mock.patch.object(ANALYZER, "SCREEN_REQUESTS", 1),
            mock.patch.dict(
                ANALYZER.PHASE_REQUESTS,
                {phase: 1 for phase in ANALYZER.WORKLOAD_PHASES},
                clear=True,
            ),
        ]
        for patcher in self.patches:
            patcher.start()
        self.rules = self.work / "SHORT_FOLLOWUP_DECISION_RULES.md"
        self.base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self._write_declarations()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary.cleanup()

    def _write_declarations(self) -> None:
        rules_text = "\n".join(
            (
                "attack acceptance <= 0.05",
                "placebo - attack >= 0.10",
                "delta-delta intercept[0] <= -0.50",
                "normalized post-1 budget attack - placebo <= -0.05",
            )
        ) + "\n"
        for name in ANALYZER.DECLARED_INPUT_FILES:
            path = self.work / name
            path.write_text(rules_text if path == self.rules else f"{name}\n")
        (self.work / "manifest.txt").write_text("fixed environment\n")

        declared_rules = self.result_root / "DECLARED_DECISION_RULES.md"
        declared_rules.write_bytes(self.rules.read_bytes())
        (self.result_root / "DECLARED_DECISION_RULES.md.sha256").write_text(
            f"{digest(declared_rules)}  {declared_rules.name}\n"
        )
        schedule = self.result_root / "DECLARED_SCHEDULE.json"
        write_json(schedule, ANALYZER.expected_declared_schedule())
        (self.result_root / "DECLARED_SCHEDULE.json.sha256").write_text(
            f"{digest(schedule)}  {schedule.name}\n"
        )
        input_lines = [
            f"{digest(self.work / name)}  {name}"
            for name in ANALYZER.DECLARED_INPUT_FILES
        ]
        (self.result_root / "DECLARED_INPUTS.sha256").write_text(
            "\n".join(input_lines) + "\n"
        )
        (self.result_root / "DECLARED_AT_UTC.txt").write_text(
            self.base_time.isoformat() + "\n"
        )

    def _metadata(
        self,
        run_dir: Path,
        *,
        name: str,
        stage: str,
        pair_id: str | None,
        arm: str,
        adaptive: bool,
        telemetry: bool,
        detailed: bool,
        token_id: int | None,
        created: datetime,
    ) -> None:
        write_json(
            run_dir / "metadata.json",
            {
                "protocol_version": ANALYZER.PROTOCOL_VERSION,
                "run_name": name,
                "stage": stage,
                "pair_id": pair_id,
                "arm": arm,
                "adaptive": adaptive,
                "telemetry": telemetry,
                "detailed_metrics": detailed,
                "poison_token_id": token_id,
                "created_at": created.isoformat(),
            },
        )

    def _finish_run(self, run_dir: Path, completed: datetime) -> None:
        (run_dir / "environment.txt").write_bytes(
            (self.work / "manifest.txt").read_bytes()
        )
        (run_dir / "COMPLETE").write_text(completed.isoformat() + "\n")

    def _write_screen(self, created: datetime, completed: datetime) -> None:
        run_dir = self.result_root / "screen"
        run_dir.mkdir()
        self._metadata(
            run_dir,
            name="screen",
            stage="screen",
            pair_id=None,
            arm="screen",
            adaptive=False,
            telemetry=False,
            detailed=True,
            token_id=None,
            created=created,
        )
        warmup_config = {
            "phase": "warmup",
            "principal": "victim",
            "model": ANALYZER.TARGET_MODEL,
            "base_url": ANALYZER.BASE_URL,
            "requests": 1,
            "concurrency": 32,
            "max_tokens": 32,
            "allowed_token_id": None,
            "seed": ANALYZER.PROBE_SEED,
            "return_token_ids": False,
        }
        write_json(
            run_dir / "warmup.json",
            phase_payload(warmup_config, 1_000_000, accepted=None),
        )
        acceptances = {279: 0, 323: 20}
        for position, token_id in enumerate(ANALYZER.SCREEN_TOKEN_IDS):
            config = {
                "phase": f"token_{token_id}",
                "principal": "attacker",
                "model": ANALYZER.TARGET_MODEL,
                "base_url": ANALYZER.BASE_URL,
                "requests": 1,
                "concurrency": 8,
                "max_tokens": 2,
                "allowed_token_id": token_id,
                "seed": ANALYZER.PROBE_SEED,
                "return_token_ids": True,
            }
            write_json(
                run_dir / f"token_{token_id}.json",
                phase_payload(
                    config,
                    3_000_000 + position * 2_000_000,
                    accepted=acceptances[token_id],
                ),
            )
        write_json(
            run_dir / "selected_token.json",
            {
                "selected_token_id": 279,
                "selected_acceptance_rate": 0.0,
                "tie_break_position": 0,
            },
        )
        (run_dir / "selected_token_id.txt").write_text("279\n")
        self._finish_run(run_dir, completed)

    def _write_adaptive_run(
        self,
        *,
        name: str,
        stage: str,
        pair_id: str,
        arm: str,
        created: datetime,
        completed: datetime,
        adverse: bool = True,
    ) -> None:
        run_dir = self.result_root / name
        run_dir.mkdir()
        gate = stage == "gate"
        self._metadata(
            run_dir,
            name=name,
            stage=stage,
            pair_id=pair_id,
            arm=arm,
            adaptive=True,
            telemetry=gate,
            detailed=gate,
            token_id=279,
            created=created,
        )
        reset_state = clean_state()
        write_json(run_dir / "state_server_ready.json", {"results": [reset_state]})
        write_json(run_dir / "state_reset.json", {"results": [reset_state]})
        write_json(
            run_dir / "estimator_reset.json",
            {
                "results": [
                    {
                        "available": True,
                        "reset": {"before": reset_state, "after": reset_state},
                    }
                ]
            },
        )

        log_lines = [
            "===== AVEP_PHASE server_ready fixture =====",
            "===== AVEP_PHASE startup_reset_begin fixture =====",
            "===== AVEP_PHASE startup_reset_end fixture =====",
        ]
        budget_step = 0
        for phase_index, phase in enumerate(ANALYZER.WORKLOAD_PHASES):
            config = ANALYZER.expected_phase_config(
                phase,
                arm=arm,
                poison_token_id=279,
                return_token_ids=gate,
            )
            accepted = None
            if gate:
                accepted = 20
                if phase == "intervention" and arm == "attack":
                    accepted = 4
            duration_ns = 1_000_000
            if stage == "performance" and phase in ANALYZER.POST_PHASES:
                post_index = ANALYZER.POST_PHASES.index(phase) + 1
                if arm == "attack" and adverse:
                    duration_ns += (9 - post_index) * 100_000
            write_json(
                run_dir / f"{phase}.json",
                phase_payload(
                    config,
                    10_000_000 + phase_index * 10_000_000,
                    accepted=accepted,
                    duration_ns=duration_ns,
                ),
            )
            log_lines.append(f"===== AVEP_PHASE {phase}_begin fixture =====")
            if gate:
                budget_step += 1
                budget = 5
                if phase == "post_01" and arm == "attack":
                    budget = 4
                event = {
                    "step": budget_step,
                    "max_draft_budget": 10,
                    "draft_budget": budget,
                    "scheduled_drafts": 10,
                }
                log_lines.append("AVEP_BUDGET " + json.dumps(event))
                intercept = -0.2
                if phase == "intervention" and arm == "attack":
                    intercept = -0.8
                write_json(
                    run_dir / f"state_{phase}.json",
                    {"results": [clean_state(intercept0=intercept)]},
                )
            log_lines.append(f"===== AVEP_PHASE {phase}_end fixture =====")
        (run_dir / "server.log").write_text("\n".join(log_lines) + "\n")
        self._finish_run(run_dir, completed)

    def build(self, *, performance: bool, signal: bool = True) -> None:
        cursor = self.base_time + timedelta(minutes=1)
        self._write_screen(cursor, cursor + timedelta(minutes=1))
        cursor += timedelta(minutes=2)
        for arm in ("placebo", "attack"):
            self._write_adaptive_run(
                name=f"gate_{arm}",
                stage="gate",
                pair_id="gate",
                arm=arm,
                created=cursor,
                completed=cursor + timedelta(minutes=1),
            )
            cursor += timedelta(minutes=2)
        if not performance:
            return
        orders = ANALYZER.expected_declared_schedule()["performance_orders"]
        for pair_number, arms in enumerate(orders, start=1):
            pair_id = f"{pair_number:02d}"
            for arm in arms:
                adverse = signal or pair_number <= 2
                self._write_adaptive_run(
                    name=f"perf_pair_{pair_id}_{arm}",
                    stage="performance",
                    pair_id=pair_id,
                    arm=arm,
                    created=cursor,
                    completed=cursor + timedelta(minutes=1),
                    adverse=adverse,
                )
                cursor += timedelta(minutes=2)

    def test_full_artifact_signal_and_eight_window_recovery(self) -> None:
        self.build(performance=True)

        result = ANALYZER.analyze(
            self.result_root, self.rules, require_performance=True
        )

        self.assertTrue(result["structural_valid"], result["errors"])
        self.assertEqual(
            result["classification"],
            "EXPLORATORY_SHORT_HORIZON_SIGNAL",
        )
        recovery = result["performance"]["recovery_trajectory"]
        self.assertEqual(set(recovery["aggregate"]), set(ANALYZER.POST_PHASES))
        self.assertEqual(len(recovery["per_pair"]), 4)
        self.assertTrue(
            all(
                summary["throughput"]["n"] == 4
                for summary in recovery["aggregate"].values()
            )
        )
        summary = recovery["recovery_summary"]
        self.assertEqual(len(summary["per_pair"]), 4)
        self.assertEqual(
            summary["aggregate"]["throughput"]["adverse_window_count"],
            8,
        )
        self.assertIsNone(
            summary["aggregate"]["throughput"][
                "first_sustained_non_adverse_window"
            ]
        )

    def test_full_artifact_inconclusive_classification(self) -> None:
        self.build(performance=True, signal=False)

        result = ANALYZER.analyze(
            self.result_root, self.rules, require_performance=True
        )

        self.assertTrue(result["structural_valid"], result["errors"])
        self.assertEqual(
            result["classification"], "EXPLORATORY_INCONCLUSIVE"
        )

    def test_integrity_artifacts_fail_closed(self) -> None:
        self.build(performance=False)
        schedule = self.result_root / "DECLARED_SCHEDULE.json"
        payload = json.loads(schedule.read_text())
        payload["screen"]["candidate"]["max_tokens"] = 1
        write_json(schedule, payload)
        sidecar = self.result_root / "DECLARED_SCHEDULE.json.sha256"
        sidecar.write_text(f"{digest(schedule)}  {schedule.name}\n")

        result = ANALYZER.analyze(self.result_root, self.rules)

        self.assertFalse(result["structural_valid"])
        self.assertTrue(
            any("fixed protocol" in error for error in result["errors"])
        )

    def test_gate_only_ignores_partial_performance_but_final_fails(self) -> None:
        self.build(performance=False)
        partial = self.result_root / "perf_pair_01_placebo"
        partial.mkdir()
        (partial / "intervention.json.partial").write_text("incomplete\n")

        gate = ANALYZER.analyze(
            self.result_root,
            self.rules,
            gate_only=True,
        )
        final = ANALYZER.analyze(
            self.result_root,
            self.rules,
            require_performance=True,
        )

        self.assertTrue(gate["structural_valid"], gate["errors"])
        self.assertTrue(gate["potency"]["pass"])
        self.assertEqual(gate["analysis_mode"], "gate_only")
        self.assertTrue(gate["performance"]["ignored_by_gate_only"])
        self.assertFalse(final["structural_valid"])
        self.assertEqual(final["analysis_mode"], "full")
        self.assertTrue(
            any("missing performance runs" in error for error in final["errors"])
        )

    def test_process_order_environment_and_input_hash_fail_closed(self) -> None:
        self.build(performance=False)
        attack = self.result_root / "gate_attack" / "metadata.json"
        metadata = json.loads(attack.read_text())
        metadata["created_at"] = (self.base_time + timedelta(minutes=3)).isoformat()
        write_json(attack, metadata)
        (self.result_root / "gate_placebo" / "environment.txt").write_text(
            "different\n"
        )
        (self.work / "paper_probe.py").write_text("tampered\n")

        result = ANALYZER.analyze(self.result_root, self.rules)

        self.assertFalse(result["structural_valid"])
        self.assertTrue(any("process order" in error for error in result["errors"]))
        self.assertTrue(any("environment" in error for error in result["errors"]))
        self.assertTrue(any("hash mismatch" in error for error in result["errors"]))


class DetailedInterventionTest(unittest.TestCase):
    def _payload(
        self,
        metrics: list[dict[str, object]],
        *,
        phase: str = "intervention",
    ) -> dict[str, object]:
        config = ANALYZER.expected_phase_config(
            phase,
            arm="placebo",
            poison_token_id=279,
            return_token_ids=True,
        )
        max_tokens = int(config["max_tokens"])
        records = []
        for index, metric in enumerate(metrics):
            start = 1_000_000 + index * 2_000_000
            records.append(
                {
                    "index": index,
                    "ok": True,
                    "started_ns": start,
                    "finished_ns": start + 1_000_000,
                    "latency_ms": 1.0,
                    "usage": {"completion_tokens": max_tokens},
                    "token_ids": [7] * max_tokens,
                    "metrics": {"speculative_decoding": metric},
                }
            )
        steps = sum(int(metric["num_spec_steps"]) for metric in metrics)
        drafted = sum(int(metric["num_draft_tokens"]) for metric in metrics)
        accepted = sum(
            int(metric["num_accepted_draft_tokens"]) for metric in metrics
        )
        first_start = records[0]["started_ns"]
        last_finish = records[-1]["finished_ns"]
        wall = (last_finish - first_start) / 1_000_000_000
        return {
            "config": config,
            "started_ns": first_start - 1,
            "finished_ns": last_finish + 1,
            "summary": {
                "requests": len(records),
                "successful": len(records),
                "failed": 0,
                "completion_tokens": len(records) * max_tokens,
                "wall_seconds": wall,
                "aggregate_output_tokens_per_second": (
                    len(records) * max_tokens / wall
                ),
                "latency_ms_p50": 1.0,
                "latency_ms_p95": 1.0,
                "spec_requests": len(records),
                "spec_steps": steps,
                "draft_tokens": drafted,
                "accepted_draft_tokens": accepted,
                "draft_acceptance_rate": (
                    accepted / drafted if drafted else None
                ),
                "control_token_fraction": None,
            },
            "records": records,
        }

    def test_mixed_zero_draft_intervention_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "intervention.json"
            with mock.patch.dict(
                ANALYZER.PHASE_REQUESTS, {"intervention": 2}
            ):
                payload = self._payload(
                    [speculative_metric(0, 0), speculative_metric(4)]
                )
                write_json(path, payload)
                result = ANALYZER.inspect_phase(
                    path,
                    payload["config"],
                    require_detailed_metrics=True,
                    require_positive_detailed_aggregate=True,
                )

        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["draft_acceptance_rate"], 0.04)

    def test_all_zero_draft_intervention_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "intervention.json"
            with mock.patch.dict(
                ANALYZER.PHASE_REQUESTS, {"intervention": 2}
            ):
                payload = self._payload(
                    [speculative_metric(0, 0), speculative_metric(0, 0)]
                )
                write_json(path, payload)
                result = ANALYZER.inspect_phase(
                    path,
                    payload["config"],
                    require_detailed_metrics=True,
                    require_positive_detailed_aggregate=True,
                )

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("aggregate has no drafted" in error for error in result["errors"])
        )

    def test_all_zero_draft_post_phase_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "post_01.json"
            with mock.patch.dict(ANALYZER.PHASE_REQUESTS, {"post_01": 2}):
                payload = self._payload(
                    [speculative_metric(0, 0), speculative_metric(0, 0)],
                    phase="post_01",
                )
                write_json(path, payload)
                result = ANALYZER.inspect_phase(
                    path,
                    payload["config"],
                    require_detailed_metrics=True,
                )

        self.assertTrue(result["valid"], result["errors"])
        self.assertIsNone(result["draft_acceptance_rate"])

    def test_one_token_intervention_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "intervention.json"
            with mock.patch.dict(
                ANALYZER.PHASE_REQUESTS, {"intervention": 1}
            ):
                expected = ANALYZER.expected_phase_config(
                    "intervention",
                    arm="attack",
                    poison_token_id=279,
                    return_token_ids=True,
                )
                actual = dict(expected)
                actual["max_tokens"] = 1
                payload = phase_payload(
                    actual,
                    1_000_000,
                    accepted=4,
                )
                write_json(path, payload)
                result = ANALYZER.inspect_phase(
                    path,
                    expected,
                    require_detailed_metrics=True,
                    forced_token_id=279,
                )

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("config.max_tokens" in error for error in result["errors"])
        )


if __name__ == "__main__":
    unittest.main()
