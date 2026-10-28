#!/usr/bin/env python
"""Unit tests for the CTFR Stage D/E fail-closed analyzer."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import analyze_ctfr_full_study as analyzer
from analyze_ctfr_full_study import (
    PRINCIPALS,
    STAGE_D_ARMS,
    STAGE_D_BLOCKS,
    analyze_overhead,
    analyze_stage_d,
    analyze_stage_d_gate,
    analyze_stage_e,
    barrier_log_counts,
    baseline_digest,
    baseline_normalized_outcomes,
    bootstrap,
    close_values,
    compare_eval_counts,
    committed_projection,
    derive_eval_counts_by_position,
    discover_runs,
    load_declared_principals,
    parse_eval_metrics,
    parse_eval_reset,
    parse_resource_samples,
    policy_projection,
    validate_binding_telemetry,
    validate_compile_state,
    validate_drain_evidence,
    validate_failed_retirement,
    validate_frozen_baseline,
    validate_gateway_evidence,
    validate_no_action_barrier,
    validate_phase_chain,
    validate_probe,
    validate_run_baseline,
    validate_stage_d_transition,
    validate_stage_e_transition,
    validate_successful_retirement,
)

DIGEST = "a" * 64
PRINCIPAL_FINGERPRINTS = {
    "attacker": "a" * 64,
    "victim": "b" * 64,
    "upstream": "c" * 64,
}


def detailed_metric(
    drafted: list[int] | None = None,
    accepted: list[int] | None = None,
    *,
    spec_tokens: int = 4,
) -> dict:
    drafted = [4] if drafted is None else drafted
    accepted = [3] if accepted is None else accepted
    histogram = [0] * (spec_tokens + 1)
    for value in accepted:
        histogram[value] += 1
    total_drafted = sum(drafted)
    total_accepted = sum(accepted)
    steps = len(drafted)
    return {
        "num_spec_steps": steps,
        "num_spec_tokens": spec_tokens,
        "num_draft_tokens": total_drafted,
        "num_accepted_draft_tokens": total_accepted,
        "draft_acceptance_rate": (
            total_accepted / total_drafted if total_drafted else None
        ),
        "mean_acceptance_length": (
            1.0 + total_accepted / steps if steps else 1.0
        ),
        "per_step_drafted": drafted,
        "per_step_accepted": accepted,
        "acceptance_histogram": histogram,
    }


def write_baseline_pilot(
    work: Path,
    slope: float,
    intercepts: list[float],
) -> Path:
    pilot = work / "ctfr_baseline_pilot_v2"
    pilot.mkdir()
    (pilot / "state_learned.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "available": True,
                        "slope": [slope],
                        "intercepts": [intercepts],
                    }
                ]
            }
        )
    )
    (pilot / "COMPLETE").write_text("complete\n")
    lines = []
    for path in sorted(
        (pilot / name for name in ("COMPLETE", "state_learned.json")),
        key=lambda value: value.name,
    ):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}\n")
    (pilot / "PROVENANCE.sha256").write_text("".join(lines))
    return pilot


def state(mode: str, *, feedback: bool = False) -> dict:
    values = [0.5, 0.5, 0.5, 0.5]
    counts = [[0.0, 0.0] for _ in range(4)]
    info = [[[0.0, 0.0], [0.0, 0.0]] for _ in range(4)]
    grad = [[[0.0, 0.0], [0.0, 0.0]] for _ in range(4)]
    steps = [0, 0, 0, 0]
    if feedback:
        for domain in (2, 3):
            counts[domain] = [64.0, 64.0]
            info[domain] = [[1.0, 0.0], [0.0, 1.0]]
            grad[domain] = [[0.5, 0.0], [0.0, 0.5]]
            steps[domain] = 128
    return {
        "available": True,
        "pcfr_mode": mode,
        "baseline_sha256": DIGEST,
        "shadow_memory_bound_bytes": 1024,
        "shadow_memory_bound_scope": analyzer.SHADOW_MEMORY_BOUND_SCOPE,
        "committed_version": 0,
        "ctfr_influence_credits": [1.0, 1.0],
        "tenant_local_versions": [0, 0],
        "bank_roles": (
            ["canonical", "policy-transformed", "tenant-0", "tenant-1"]
            if mode == "tenant-local"
            else ["canonical", "policy-transformed", "shadow-0", "shadow-1"]
        ),
        "principal_bank_map": {"0": 2, "1": 3},
        "feedback_principal_slots": [-1, -1, -1, -1],
        "retirement_hyperparameters": {
            "min_observations": 100,
            "delta_clip": 0.2,
            "min_cosine": 0.8,
            "max_commit_norm": 0.2,
            "max_probability_shift": 0.1,
            "bucket_capacity": 1.0,
        },
        "steps_since_refit": steps,
        "refits": [0, 0, 0, 0],
        "updates_enabled": True,
        "eval_metrics_enabled": True,
        "slope": values,
        "intercepts": [[-0.2, -0.2] for _ in range(4)],
        "counts": counts,
        "info": info,
        "grad": grad,
    }


def successful_retirement() -> dict:
    return {
        "retired": True,
        "version_before": 0,
        "version_after": 1,
        "observation_counts": [128.0, 128.0],
        "raw_delta_norms": [0.1, 0.1],
        "clipped_delta_norms": [0.1, 0.1],
        "cosine": 1.0,
        "aggregate_norm": 0.1,
        "max_probability_shift": 0.02,
        "remaining_influence_credits": [0.9, 0.9],
        "base_coefficients": [0.5, -0.2, -0.2],
        "raw_deltas": [[0.1, 0.0, 0.0], [0.1, 0.0, 0.0]],
        "clipped_deltas": [[0.1, 0.0, 0.0], [0.1, 0.0, 0.0]],
        "aggregate_delta": [0.1, 0.0, 0.0],
        "proposed_coefficients": [0.6, -0.2, -0.2],
    }


def retired_state() -> dict:
    result = state("ctfr-full")
    result["committed_version"] = 1
    result["ctfr_influence_credits"] = [0.9, 0.9]
    result["slope"][0] = 0.6
    result["refits"][0] = 1
    for domain in (2, 3):
        result["slope"][domain] = 0.6
        result["refits"][domain] = 1
    result["updates_enabled"] = False
    return result


def tenant_refitted_state() -> dict:
    result = state("tenant-local")
    result["tenant_local_versions"] = [1, 1]
    for domain in (2, 3):
        result["slope"][domain] = 0.6
        result["intercepts"][domain] = [-0.1, -0.1]
        result["refits"][domain] = 1
    result["updates_enabled"] = False
    return result


def base_metadata(arm: str, block_id: str) -> dict:
    return {
        "process_uuid": f"process-{block_id}-{arm}",
        "baseline_sha256": DIGEST,
        "shadow_memory_bound_bytes": 1024,
        "shadow_memory_bound_scope": analyzer.SHADOW_MEMORY_BOUND_SCOPE,
        "source_sha256": "b" * 64,
        "target_model_revision": "target-revision",
        "draft_model_revision": "draft-revision",
        "sampling_policy_sha256": "c" * 64,
        "feature_contract_version": "feature-v1",
        "adaptation_manifest_sha256": "d" * 64,
        "evaluation_manifest_sha256": "e" * 64,
        "observation_budget_by_principal": {
            "attacker": 128,
            "victim": 128,
        },
        "evaluation_budget_by_principal": {
            "attacker": 64,
            "victim": 64,
        },
    }


def outcomes(
    throughput: float,
    *,
    log_loss: float,
    brier: float,
    p95: float = 10.0,
) -> dict[str, float]:
    result = {
        "system_throughput": throughput,
        "system_latency_p50": p95 * 0.6,
        "system_latency_p95": p95,
        "balanced_log_loss": log_loss,
        "weighted_log_loss": log_loss,
        "balanced_brier": brier,
        "weighted_brier": brier,
    }
    for principal in PRINCIPALS:
        result[f"{principal}_throughput"] = throughput
        result[f"{principal}_latency_p50"] = p95 * 0.6
        result[f"{principal}_latency_p95"] = p95
        result[f"{principal}_log_loss"] = log_loss
        result[f"{principal}_brier"] = brier
    for key, value in list(result.items()):
        result[f"baseline_raw_{key}"] = value
        result[f"evaluation_raw_{key}"] = value
    return result


def semantic_records() -> list[dict]:
    return [
        {
            "ok": True,
            "ordinal": ordinal,
            "principal": principal,
            "output_sha256": DIGEST,
            "token_ids": [ordinal + 1],
        }
        for ordinal, principal in enumerate(PRINCIPALS)
    ]


def stage_d_run(
    arm: str,
    block_id: str,
    *,
    throughput: float,
    log_loss: float,
    brier: float,
) -> dict:
    mode = {
        "frozen": "shared",
        "ctfr-full-no-retire": "ctfr-full",
    }.get(arm, arm)
    before = state(mode)
    accumulated = state(mode, feedback=arm in {
        "tenant-local",
        "ctfr-shadow",
        "ctfr-full",
        "ctfr-full-no-retire",
    })
    if arm == "shared":
        accumulated["slope"][0] = 0.7
        accumulated["refits"][0] = 1
    if arm == "ctfr-full":
        after = retired_state()
        barrier = {
            "called": True,
            "method": "avep_retire_ctfr",
            "response": {
                "results": [
                    {
                        "available": True,
                        "retirement": successful_retirement(),
                    }
                ]
            },
        }
    elif arm == "tenant-local":
        after = tenant_refitted_state()
        barrier = {
            "called": True,
            "method": "avep_refit_tenant_local",
            "response": {
                "results": [
                    {
                        "available": True,
                        "tenant_local_refit": {
                            "refit": True,
                            "observation_counts": [128.0, 128.0],
                            "versions_before": [0, 0],
                            "versions_after": [1, 1],
                            "delta_norms": [0.1, 0.1],
                            "parameters_before": [
                                [0.5, -0.2, -0.2],
                                [0.5, -0.2, -0.2],
                            ],
                            "parameters_after": [
                                [0.6, -0.1, -0.1],
                                [0.6, -0.1, -0.1],
                            ],
                        },
                    }
                ]
            },
        }
    else:
        after = copy.deepcopy(accumulated)
        after["updates_enabled"] = False
        barrier = {"called": False, "method": None, "response": None}
    post = copy.deepcopy(after)
    post["feedback_principal_slots"] = [0, 1, 0, 1]
    block_number = 0 if block_id == "gate" else int(block_id)
    arm_number = (
        STAGE_D_ARMS.index(arm) if arm in STAGE_D_ARMS else len(STAGE_D_ARMS)
    )
    adaptation_started_ns = block_number * 1_000 + arm_number * 10 + 1
    run = {
        "valid": True,
        "errors": [],
        "run_id": f"stage_d_{block_id}_{arm}",
        "stage": "D",
        "block_id": block_id,
        "arm": arm,
        "scenario": None,
        "metadata": base_metadata(arm, block_id),
        "compile_warmup": {"config": {"manifest_sha256": "f" * 64}},
        "baseline_evaluation": {
            "config": {"manifest_sha256": "1" * 64}
        },
        "adaptation": {
            "records": semantic_records(),
            "started_ns": adaptation_started_ns,
        },
        "evaluation": {"records": semantic_records()},
        "states": {
            "before": before,
            "accumulated": accumulated,
            "after_barrier": after,
            "post_evaluation": post,
        },
        "barrier": barrier,
        "barrier_log_counts": {
            "ctfr_retire_calls": 1 if arm == "ctfr-full" else 0,
            "ctfr_retire": 1 if arm == "ctfr-full" else 0,
            "tenant_local_refit_calls": 1 if arm == "tenant-local" else 0,
            "tenant_local_refit": 1 if arm == "tenant-local" else 0,
        },
        "gateway_evidence": {
            "observed": {
                "gateway_instance_id": f"gateway-{block_id}-{arm}",
            }
        },
        "outcomes": outcomes(
            throughput,
            log_loss=log_loss,
            brier=brier,
        ),
    }
    transition_errors = validate_stage_d_transition(run)
    if transition_errors:
        raise AssertionError(transition_errors)
    return run


def complete_stage_d_runs(*, tenant_throughput: float = 107.0) -> list[dict]:
    values = {
        "shared": (110.0, 0.20, 0.10),
        "frozen": (100.0, 0.40, 0.20),
        "tenant-local": (tenant_throughput, 0.25, 0.13),
        "ctfr-shadow": (100.0, 0.40, 0.20),
        "ctfr-full": (109.0, 0.22, 0.11),
    }
    return [
        stage_d_run(
            arm,
            block,
            throughput=values[arm][0],
            log_loss=values[arm][1],
            brier=values[arm][2],
        )
        for block in STAGE_D_BLOCKS
        for arm in STAGE_D_ARMS
    ]


def overhead_run(block: str, arm: str, multiplier: float) -> dict:
    throughput = 100.0 * multiplier
    p95 = 10.0 / multiplier
    source_arm = "frozen" if arm == "shared" else arm
    result = stage_d_run(
        source_arm,
        block,
        throughput=throughput,
        log_loss=0.2,
        brier=0.1,
    )
    result["stage"] = "E"
    result["scenario"] = "stationary-overhead"
    result["arm"] = arm
    result["run_id"] = f"overhead_{block}_{arm}"
    result["resources"] = {
        "gpu_peak_bytes": 1000.0
        + (20.0 if arm == "ctfr-full-no-retire" else 0.0),
        "host_peak_bytes": 2000.0
        + (30.0 if arm == "ctfr-full-no-retire" else 0.0),
        "server_cpu_percent_mean": (
            20.0 if arm == "ctfr-full-no-retire" else 19.0
        ),
        "gateway_cpu_percent_mean": 2.0,
    }
    result["outcomes"] = outcomes(
        throughput,
        log_loss=0.2,
        brier=0.1,
        p95=p95,
    )
    result["adaptation_outcomes"] = {
        "system_throughput": throughput,
        "system_latency_p50": p95 * 0.6,
        "system_latency_p95": p95,
    }
    return result


class CTFRFullStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.original_bootstrap_samples = analyzer.BOOTSTRAP_SAMPLES
        analyzer.BOOTSTRAP_SAMPLES = 1_000

    @classmethod
    def tearDownClass(cls) -> None:
        analyzer.BOOTSTRAP_SAMPLES = cls.original_bootstrap_samples

    def test_close_values_handles_nested_float_rounding(self) -> None:
        self.assertTrue(close_values({"x": [0.1]}, {"x": [0.10000001]}))
        self.assertFalse(close_values({"x": [0.1]}, {"x": [0.2]}))

    def test_bootstrap_is_block_level_and_deterministic(self) -> None:
        first = bootstrap([1.0] * 8)
        second = bootstrap([1.0] * 8)
        self.assertEqual(first, second)
        self.assertEqual(first["n_blocks"], 8)
        self.assertEqual(first["ci95_low"], 1.0)
        self.assertEqual(first["ci95_high"], 1.0)

    def test_baseline_normalization_preserves_raw_and_relative_outcomes(self) -> None:
        result = baseline_normalized_outcomes(
            {"system_throughput": 100.0, "balanced_log_loss": 0.4},
            {"system_throughput": 110.0, "balanced_log_loss": 0.3},
        )
        self.assertAlmostEqual(result["system_throughput"], 1.1)
        self.assertAlmostEqual(result["balanced_log_loss"], -0.1)
        self.assertEqual(result["baseline_raw_system_throughput"], 100.0)
        self.assertEqual(result["evaluation_raw_system_throughput"], 110.0)

    def test_binding_telemetry_requires_consistent_mixed_batch(self) -> None:
        line = (
            'AVEP_CTFR_BINDING {"persistent_slots":[2,3],'
            '"principals":[0,1],"request_ids":['
            '"cmpl-ctfr-auth-attacker-a",'
            '"cmpl-ctfr-auth-victim-b"]}\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text(line)
            result = validate_binding_telemetry(
                path,
                require_mixed_batch=True,
            )
            self.assertTrue(result["valid"])
            self.assertEqual(result["mixed_principal_batch_count"], 1)
            path.write_text(line.replace("victim-b", "attacker-b"))
            result = validate_binding_telemetry(
                path,
                require_mixed_batch=True,
            )
            self.assertFalse(result["valid"])

    def test_binding_telemetry_requires_per_run_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text("")
            result = validate_binding_telemetry(
                path,
                require_mixed_batch=False,
                require_events=True,
            )
        self.assertFalse(result["valid"])
        self.assertIn("binding telemetry contains no events", result["errors"])

    def test_binding_telemetry_exact_join_succeeds(self) -> None:
        attacker_base = "cmpl-ctfr-auth-attacker-a"
        victim_base = "cmpl-ctfr-auth-victim-b"
        attacker = f"{attacker_base}-0-0123abcd"
        victim = f"{victim_base}-1-deadbeef"
        line = json.dumps(
            {
                "persistent_slots": [2, 3],
                "principals": [0, 1],
                "request_ids": [attacker, victim],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text(f"AVEP_CTFR_BINDING {line}\n")
            result = validate_binding_telemetry(
                path,
                require_mixed_batch=True,
                require_events=True,
                expected_id_principals={
                    attacker_base: "attacker",
                    victim_base: "victim",
                },
            )
        self.assertTrue(result["valid"])
        self.assertEqual(result["observed_request_ids"], [attacker, victim])
        self.assertEqual(result["mixed_principal_batch_count"], 1)

    def test_binding_telemetry_rejects_untrusted_same_prefix_id(self) -> None:
        expected = "cmpl-ctfr-auth-attacker-expected"
        untrusted = "cmpl-ctfr-auth-attacker-untrusted-0-0123abcd"
        line = json.dumps(
            {
                "persistent_slots": [2],
                "principals": [0],
                "request_ids": [untrusted],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text(f"AVEP_CTFR_BINDING {line}\n")
            result = validate_binding_telemetry(
                path,
                require_mixed_batch=False,
                require_events=True,
                expected_id_principals={expected: "attacker"},
            )
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("unexpected request id" in item for item in result["errors"])
        )

    def test_binding_telemetry_rejects_missing_expected_id(self) -> None:
        first = "cmpl-ctfr-auth-attacker-first"
        second = "cmpl-ctfr-auth-attacker-second"
        line = json.dumps(
            {
                "persistent_slots": [2],
                "principals": [0],
                "request_ids": [f"{first}-0-0123abcd"],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text(f"AVEP_CTFR_BINDING {line}\n")
            result = validate_binding_telemetry(
                path,
                require_mixed_batch=False,
                require_events=True,
                expected_id_principals={
                    first: "attacker",
                    second: "attacker",
                },
            )
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("missing expected" in item for item in result["errors"])
        )

    def test_binding_telemetry_rejects_principal_mismatch(self) -> None:
        expected = "cmpl-ctfr-auth-attacker-a"
        request_id = f"{expected}-0-0123abcd"
        line = json.dumps(
            {
                "persistent_slots": [2],
                "principals": [1],
                "request_ids": [request_id],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text(f"AVEP_CTFR_BINDING {line}\n")
            result = validate_binding_telemetry(
                path,
                require_mixed_batch=False,
                require_events=True,
                expected_id_principals={expected: "attacker"},
            )
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("principal mismatch" in item for item in result["errors"])
        )

    def test_binding_telemetry_rejects_bool_and_float_principals(self) -> None:
        expected = "cmpl-ctfr-auth-attacker-a"
        for principal in (False, True, 0.0, 1.0):
            with self.subTest(principal=principal):
                event = {
                    "persistent_slots": [2],
                    "principals": [principal],
                    "request_ids": [f"{expected}-0-0123abcd"],
                }
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "server.log"
                    path.write_text(
                        f"AVEP_CTFR_BINDING {json.dumps(event)}\n"
                    )
                    result = validate_binding_telemetry(
                        path,
                        require_mixed_batch=False,
                        require_events=True,
                        expected_id_principals={expected: "attacker"},
                    )
                self.assertFalse(result["valid"])
                self.assertTrue(
                    any(
                        "invalid identity" in item
                        for item in result["errors"]
                    )
                )

    def test_binding_telemetry_rejects_malformed_worker_suffixes(self) -> None:
        expected = "cmpl-ctfr-auth-attacker-a"
        malformed = (
            expected,
            f"{expected}-00-0123abcd",
            f"{expected}-0-0123ABCd",
            f"{expected}-0-0123abc",
            f"{expected}--1-0123abcd",
            f"{expected}-0-0123abcd-extra",
        )
        for request_id in malformed:
            with self.subTest(request_id=request_id):
                line = json.dumps(
                    {
                        "persistent_slots": [2],
                        "principals": [0],
                        "request_ids": [request_id],
                    }
                )
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "server.log"
                    path.write_text(f"AVEP_CTFR_BINDING {line}\n")
                    result = validate_binding_telemetry(
                        path,
                        require_mixed_batch=False,
                        require_events=True,
                        expected_id_principals={expected: "attacker"},
                    )
                self.assertFalse(result["valid"])
                self.assertTrue(
                    any(
                        "unexpected request id" in item
                        for item in result["errors"]
                    )
                )

    def test_binding_telemetry_allows_only_strict_internal_warmups(
        self,
    ) -> None:
        valid = {
            "persistent_slots": [0],
            "principals": [-1],
            "request_ids": ["_warmup_0_"],
        }
        invalid = (
            {**valid, "request_ids": ["_warmup_00_"]},
            {**valid, "request_ids": ["_warmup_-1_"]},
            {**valid, "request_ids": ["_warmup_0_extra_"]},
            {**valid, "principals": [-1.0]},
            {**valid, "principals": [False]},
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text(f"AVEP_CTFR_BINDING {json.dumps(valid)}\n")
            result = validate_binding_telemetry(
                path,
                require_mixed_batch=False,
                require_events=True,
            )
            self.assertTrue(result["valid"], result["errors"])
            for event in invalid:
                with self.subTest(event=event):
                    path.write_text(
                        f"AVEP_CTFR_BINDING {json.dumps(event)}\n"
                    )
                    result = validate_binding_telemetry(
                        path,
                        require_mixed_batch=False,
                        require_events=True,
                    )
                    self.assertFalse(result["valid"])

    def test_binding_telemetry_derives_exact_kernel_counts(self) -> None:
        attacker = "cmpl-ctfr-auth-attacker-a"
        victim = "cmpl-ctfr-auth-victim-b"
        event = {
            "persistent_slots": [2, 3, 0],
            "principals": [0, 1, -1],
            "request_ids": [
                f"{attacker}-0-0123abcd",
                f"{victim}-1-deadbeef",
                "_warmup_0_",
            ],
            "num_sampled": [4, 2, 5],
            "num_rejected": [1, 2, 0],
            "num_speculative_steps": 4,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text(f"AVEP_CTFR_BINDING {json.dumps(event)}\n")
            result = validate_binding_telemetry(
                path,
                require_mixed_batch=True,
                require_events=True,
                expected_id_principals={
                    attacker: "attacker",
                    victim: "victim",
                },
                expected_id_phases={
                    attacker: "adaptation",
                    victim: "evaluation",
                },
                require_verification_counters=True,
            )
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["num_speculative_steps"], 4)
        self.assertEqual(
            result["verification_counts_by_phase"]["adaptation"],
            {
                "attacker": [1, 1, 1, 1],
                "victim": [0, 0, 0, 0],
            },
        )
        self.assertEqual(
            result["verification_counts_by_phase"]["evaluation"],
            {
                "attacker": [0, 0, 0, 0],
                "victim": [1, 1, 0, 0],
            },
        )
        reported = {
            "attacker": {
                "count": 4,
                "counts_by_position": [1, 1, 1, 1],
            },
            "victim": {
                "count": 0,
                "counts_by_position": [0, 0, 0, 0],
            },
        }
        observed = result["verification_counts_by_phase"]["adaptation"]
        self.assertEqual(
            compare_eval_counts(observed, reported, label="telemetry"),
            [],
        )
        reported["attacker"]["count"] = 3
        self.assertTrue(
            compare_eval_counts(observed, reported, label="telemetry")
        )

    def test_binding_telemetry_rejects_invalid_counter_schema(self) -> None:
        expected = "cmpl-ctfr-auth-attacker-a"
        base = {
            "persistent_slots": [2],
            "principals": [0],
            "request_ids": [f"{expected}-0-0123abcd"],
            "num_sampled": [2],
            "num_rejected": [1],
            "num_speculative_steps": 4,
        }
        invalid = (
            {**base, "num_sampled": []},
            {**base, "num_rejected": [True]},
            {**base, "num_sampled": [2.0]},
            {**base, "num_speculative_steps": 0},
            {**base, "num_speculative_steps": 4.0},
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            for event in invalid:
                with self.subTest(event=event):
                    path.write_text(
                        f"AVEP_CTFR_BINDING {json.dumps(event)}\n"
                    )
                    result = validate_binding_telemetry(
                        path,
                        require_mixed_batch=False,
                        require_events=True,
                        expected_id_principals={expected: "attacker"},
                        expected_id_phases={expected: "adaptation"},
                        require_verification_counters=True,
                    )
                    self.assertFalse(result["valid"])
                    self.assertTrue(
                        any(
                            "invalid verification counters" in item
                            for item in result["errors"]
                        )
                    )

    def test_gateway_evidence_returns_authenticated_worker_ids(self) -> None:
        metadata = {
            "protocol_version": analyzer.PROTOCOL_VERSION,
            "run_id": "run",
            "process_uuid": "worker-uuid",
        }
        gateway_id = "gateway-uuid"
        auth_specs = {
            "attacker_ok": (200, "attacker", "attacker", True),
            "victim_ok": (200, "victim", "victim", True),
            "missing_key": (401, None, "victim", False),
            "wrong_key": (401, None, "victim", False),
            "attacker_claims_victim": (
                403,
                "attacker",
                "victim",
                False,
            ),
            "victim_claims_attacker": (
                403,
                "victim",
                "attacker",
                False,
            ),
        }
        auth_results = []
        audit_rows = []
        for ordinal, (name, spec) in enumerate(auth_specs.items()):
            status, tenant, claimed, forwarded = spec
            event_id = f"auth-{ordinal}"
            auth_results.append(
                {
                    "name": name,
                    "expected_status": status,
                    "status": status,
                    "authenticated_tenant": tenant if forwarded else None,
                    "audit_event_id": event_id,
                    "gateway_instance_id": gateway_id,
                    "upstream_marker": "worker-uuid",
                }
            )
            audit_rows.append(
                {
                    "schema_version": 2,
                    "run_id": "run",
                    "event_id": event_id,
                    "purpose": "auth-self-test",
                    "path": "/v1/models",
                    "status": status,
                    "forwarded": forwarded,
                    "authenticated_tenant": tenant,
                    "claimed_principal": claimed,
                    "key_sha256": (
                        PRINCIPAL_FINGERPRINTS[tenant]
                        if tenant in PRINCIPAL_FINGERPRINTS
                        else "d" * 64
                    ),
                    "gateway_instance_id": gateway_id,
                    "upstream_marker": "worker-uuid",
                }
            )
        artifacts = {}
        expected_ids = {}
        expected_phases = {}
        for ordinal, phase in enumerate(
            (
                "compile_warmup",
                "baseline_evaluation",
                "adaptation",
                "evaluation",
            )
        ):
            external = (
                "cmpl-ctfr-auth-victim-client-spoof-00000"
                if phase == "compile_warmup"
                else f"external-{phase}"
            )
            upstream = f"ctfr-auth-attacker-{phase}"
            event_id = f"phase-{ordinal}"
            artifacts[phase] = {
                "config": {
                    "gateway_instance_id": gateway_id,
                    "upstream_marker": "worker-uuid",
                },
                "records": [
                    {
                        "principal": "attacker",
                        "external_request_id": external,
                        "audit_event_id": event_id,
                        "authenticated_tenant": "attacker",
                        "gateway_instance_id": gateway_id,
                        "upstream_marker": "worker-uuid",
                    }
                ],
            }
            audit_rows.append(
                {
                    "schema_version": 2,
                    "run_id": "run",
                    "event_id": event_id,
                    "purpose": phase,
                    "path": "/v1/completions",
                    "request_id": external,
                    "upstream_request_id": upstream,
                    "status": 200,
                    "forwarded": True,
                    "authenticated_tenant": "attacker",
                    "claimed_principal": "attacker",
                    "key_sha256": PRINCIPAL_FINGERPRINTS["attacker"],
                    "gateway_instance_id": gateway_id,
                    "upstream_marker": "worker-uuid",
                }
            )
            expected_ids[f"cmpl-{upstream}"] = "attacker"
            expected_phases[f"cmpl-{upstream}"] = phase
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "DECLARED_PRINCIPALS.json").write_text(
                json.dumps(PRINCIPAL_FINGERPRINTS)
            )
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "auth_self_test.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "valid": True,
                        "results": auth_results,
                    }
                )
            )
            (run_dir / "tenant_topology.json").write_text(
                json.dumps(
                    {
                        "protocol_version": analyzer.PROTOCOL_VERSION,
                        "run_id": "run",
                        "process_uuid": "worker-uuid",
                        "gateway_instance_id": gateway_id,
                        "upstream_marker": "worker-uuid",
                        "key_fingerprints": PRINCIPAL_FINGERPRINTS,
                    }
                )
            )
            (run_dir / "gateway_audit.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in audit_rows)
            )
            result = validate_gateway_evidence(
                run_dir,
                artifacts,
                metadata,
            )
            audit_rows[-1]["key_sha256"] = "d" * 64
            (run_dir / "gateway_audit.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in audit_rows)
            )
            key_mismatch = validate_gateway_evidence(
                run_dir,
                artifacts,
                metadata,
            )
            audit_rows[-1]["key_sha256"] = PRINCIPAL_FINGERPRINTS[
                "attacker"
            ]
            (run_dir / "gateway_audit.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in audit_rows)
            )
            topology = json.loads(
                (run_dir / "tenant_topology.json").read_text()
            )
            topology["key_fingerprints"]["victim"] = "d" * 64
            (run_dir / "tenant_topology.json").write_text(
                json.dumps(topology)
            )
            mismatch = validate_gateway_evidence(
                run_dir,
                artifacts,
                metadata,
            )
        self.assertTrue(result["valid"], result["errors"])
        self.assertFalse(key_mismatch["valid"])
        self.assertIn(
            "evaluation key fingerprint differs from declaration",
            key_mismatch["errors"],
        )
        self.assertFalse(mismatch["valid"])
        self.assertIn(
            "gateway topology key fingerprints differ from declaration",
            mismatch["errors"],
        )
        self.assertEqual(
            result["observed"]["expected_worker_completion_principals"],
            expected_ids,
        )
        self.assertEqual(
            result["observed"]["expected_worker_completion_phases"],
            expected_phases,
        )

    def test_declared_principal_fingerprints_fail_closed(self) -> None:
        invalid = {
            "missing": {
                "attacker": "a" * 64,
                "victim": "b" * 64,
            },
            "extra": {
                **PRINCIPAL_FINGERPRINTS,
                "other": "d" * 64,
            },
            "short": {
                **PRINCIPAL_FINGERPRINTS,
                "victim": "b" * 63,
            },
            "uppercase": {
                **PRINCIPAL_FINGERPRINTS,
                "victim": "B" * 64,
            },
            "non_string": {
                **PRINCIPAL_FINGERPRINTS,
                "victim": 1,
            },
            "duplicate": {
                **PRINCIPAL_FINGERPRINTS,
                "victim": "a" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "DECLARED_PRINCIPALS.json"
            path.write_text(json.dumps(PRINCIPAL_FINGERPRINTS))
            self.assertEqual(
                load_declared_principals(root),
                PRINCIPAL_FINGERPRINTS,
            )
            for name, payload in invalid.items():
                with self.subTest(name=name):
                    path.write_text(json.dumps(payload))
                    with self.assertRaises(ValueError):
                        load_declared_principals(root)

    def test_probe_requires_constrained_tokens_and_speculative_metrics(self) -> None:
        records = []
        for ordinal, principal in enumerate(PRINCIPALS):
            records.append(
                {
                    "ok": True,
                    "ordinal": ordinal,
                    "principal": principal,
                    "authenticated_tenant": principal,
                    "audit_event_id": f"audit-{ordinal}",
                    "external_request_id": f"external-{ordinal}",
                    "started_ns": ordinal + 1,
                    "finished_ns": ordinal + 2,
                    "token_ids": [1],
                    "allowed_token_ids": [1, 2],
                    "output_sha256": DIGEST,
                    "metrics": {
                        "speculative_decoding": detailed_metric()
                    },
                }
            )
        artifact = {
            "config": {
                "phase": "adaptation",
                "run_id": "run",
                "manifest_sha256": DIGEST,
                "spoof_identity_headers": False,
                "return_token_ids": True,
            },
            "summary": {
                "evidence_ok": True,
                "requests": 2,
                "successful": 2,
                "failed": 0,
                "expected_principal_counts": {
                    "attacker": 1,
                    "victim": 1,
                },
                "authenticated_principal_counts": {
                    "attacker": 1,
                    "victim": 1,
                },
                "unique_audit_event_ids": 2,
                "missing_audit_event_ids": 0,
                "spec_requests": 2,
                "draft_tokens": 8,
                "accepted_draft_tokens": 6,
                "draft_acceptance_rate": 0.75,
                "by_principal": {
                    principal: {
                        "spec_requests": 1,
                        "draft_tokens": 4,
                        "accepted_draft_tokens": 3,
                        "draft_acceptance_rate": 0.75,
                    }
                    for principal in PRINCIPALS
                },
            },
            "records": records,
            "started_ns": 1,
            "finished_ns": 4,
        }
        errors = validate_probe(
            artifact,
            run_id="run",
            phase="adaptation",
            manifest_sha256=DIGEST,
            expected_counts={"attacker": 1, "victim": 1},
        )
        self.assertEqual(errors, [])
        artifact["records"][0]["token_ids"] = [99]
        errors = validate_probe(
            artifact,
            run_id="run",
            phase="adaptation",
            manifest_sha256=DIGEST,
            expected_counts={"attacker": 1, "victim": 1},
        )
        self.assertIn(
            "adaptation: output contains a token outside its constraint",
            errors,
        )
        artifact["records"][0]["token_ids"] = [1]
        artifact["records"][0]["metrics"]["speculative_decoding"][
            "acceptance_histogram"
        ] = [1, 0, 0, 0, 0]
        errors = validate_probe(
            artifact,
            run_id="run",
            phase="adaptation",
            manifest_sha256=DIGEST,
            expected_counts={"attacker": 1, "victim": 1},
        )
        self.assertTrue(
            any("acceptance_histogram" in item for item in errors)
        )

    def test_barrier_markers_are_counted_without_payload_suffixes(self) -> None:
        log = "\n".join(
            (
                "INFO AVEP_CTFR_RETIRE_CALL",
                'INFO AVEP_CTFR_RETIRE {"retired":true}',
                "INFO AVEP_TENANT_LOCAL_REFIT_CALL",
                'INFO AVEP_TENANT_LOCAL_REFIT {"refit":true}',
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_text(log)
            counts = barrier_log_counts(path)
        self.assertEqual(
            counts,
            {
                "ctfr_retire_calls": 1,
                "ctfr_retire": 1,
                "tenant_local_refit_calls": 1,
                "tenant_local_refit": 1,
            },
        )

    def test_drain_evidence_requires_two_zero_samples_before_barrier(self) -> None:
        rows = (
            '{"label":"adaptation","sampled_at":'
            '"2024-01-01T00:00:00+00:00","running":0,"waiting":0,'
            '"running_series":1,"waiting_series":1}\n'
            '{"label":"adaptation","sampled_at":'
            '"2024-01-01T00:00:01+00:00","running":0,"waiting":0,'
            '"running_series":1,"waiting_series":1}\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "drain_evidence.jsonl"
            path.write_text(rows)
            valid = validate_drain_evidence(
                path,
                barrier_called_after_ns=1_704_067_202_000_000_000,
            )
            invalid = validate_drain_evidence(
                path,
                barrier_called_after_ns=1_704_067_200_500_000_000,
            )
        self.assertTrue(valid["valid"])
        self.assertFalse(invalid["valid"])

    def test_resource_cpu_percent_is_bound_to_proc_tick_deltas(self) -> None:
        rows = []
        for second in (0, 1):
            rows.append(
                {
                    "sampled_at": f"2024-01-01T00:00:0{second}+00:00",
                    "cpu_measurement": {
                        "source": "proc-stat-interval-delta",
                        "window_ns": 1_000_000_000,
                        "clock_ticks_per_second": 100,
                    },
                    "server": {
                        "rss_kib": 100,
                        "cpu_percent": 2.0,
                        "cpu_ticks_delta": 2,
                        "processes": 1,
                    },
                    "gateway": {
                        "rss_kib": 50,
                        "cpu_percent": 1.0,
                        "cpu_ticks_delta": 1,
                        "processes": 1,
                    },
                    "gpu": {"memory_mib": 10},
                }
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resource_samples.jsonl"
            path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            result = parse_resource_samples(path)
            self.assertEqual(result["server_cpu_percent_mean"], 2.0)
            rows[1]["server"]["cpu_percent"] = 20.0
            path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            with self.assertRaises(ValueError):
                parse_resource_samples(path)

    def test_phase_chain_rejects_a_phase_that_moves_backward(self) -> None:
        metadata = {
            "barrier_evidence": {
                "called_after_ns": 50,
                "completed_ns": 60,
            }
        }
        phases = {
            "compile": {"started_ns": 10, "finished_ns": 20},
            "baseline": {"started_ns": 21, "finished_ns": 30},
            "adaptation": {"started_ns": 31, "finished_ns": 40},
            "evaluation": {"started_ns": 61, "finished_ns": 70},
        }
        self.assertEqual(
            validate_phase_chain(
                metadata,
                phases["compile"],
                phases["baseline"],
                phases["adaptation"],
                phases["evaluation"],
            ),
            [],
        )
        phases["adaptation"]["started_ns"] = 29
        self.assertTrue(
            validate_phase_chain(
                metadata,
                phases["compile"],
                phases["baseline"],
                phases["adaptation"],
                phases["evaluation"],
            )
        )

    def test_successful_retirement_checks_publication_and_credits(self) -> None:
        before = state("ctfr-full")
        accumulated = state("ctfr-full", feedback=True)
        after = retired_state()
        self.assertEqual(
            validate_successful_retirement(
                before,
                accumulated,
                after,
                successful_retirement(),
            ),
            [],
        )
        after["ctfr_influence_credits"] = [1.0, 1.0]
        self.assertIn(
            "influence credits were not debited exactly once",
            validate_successful_retirement(
                before,
                accumulated,
                after,
                successful_retirement(),
            ),
        )

    def test_compile_warmup_requires_mode_specific_accumulation(self) -> None:
        shared = state("shared")
        shared["counts"][0] = [2.0, 1.0]
        shared["info"][0] = [[1.0, 0.0], [0.0, 1.0]]
        shared["steps_since_refit"][0] = 1
        self.assertEqual(validate_compile_state(shared, mode="shared"), [])
        ctfr = state("ctfr-full", feedback=True)
        self.assertEqual(validate_compile_state(ctfr, mode="ctfr-full"), [])
        ctfr["counts"][3] = [0.0, 0.0]
        self.assertTrue(validate_compile_state(ctfr, mode="ctfr-full"))

    def test_frozen_baseline_is_loaded_into_all_before_state_banks(self) -> None:
        slope = 0.5
        intercepts = [-0.2, -0.2]
        digest = baseline_digest(slope, intercepts)
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            root = work / "results"
            run_dir = root / "run"
            run_dir.mkdir(parents=True)
            (work / "ctfr_baseline_committed_state_v2.json").write_text(
                json.dumps(
                    {
                        "schema": "ctfr-baseline-v1",
                        "slope": slope,
                        "intercepts": intercepts,
                        "coefficient_sha256": digest,
                    }
                )
            )
            write_baseline_pilot(work, slope, intercepts)
            frozen = validate_frozen_baseline(root)
            self.assertTrue(frozen["valid"])
            (run_dir / "baseline_load.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "available": True,
                                "baseline": {
                                    "loaded": True,
                                    "baseline_sha256": digest,
                                    "slope": slope,
                                    "intercepts": intercepts,
                                },
                            }
                        ]
                    }
                )
            )
            before = state("shared")
            errors, evidence = validate_run_baseline(
                run_dir,
                {"baseline_sha256": digest},
                before,
                frozen["baseline"],
            )
            self.assertEqual(errors, [])
            self.assertTrue(evidence["all_four_banks_initialized"])
            before["slope"][3] += 0.1
            errors, _ = validate_run_baseline(
                run_dir,
                {"baseline_sha256": digest},
                before,
                frozen["baseline"],
            )
            self.assertIn(
                "before-state banks do not share the frozen slope",
                errors,
            )

    def test_baseline_pilot_provenance_rejects_missing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            slope = 0.5
            intercepts = [-0.2, -0.2]
            (work / "ctfr_baseline_committed_state_v2.json").write_text(
                json.dumps(
                    {
                        "schema": "ctfr-baseline-v1",
                        "slope": slope,
                        "intercepts": intercepts,
                        "coefficient_sha256": baseline_digest(
                            slope, intercepts
                        ),
                    }
                )
            )
            pilot = write_baseline_pilot(work, slope, intercepts)
            provenance = pilot / "PROVENANCE.sha256"
            provenance.write_text(provenance.read_text().splitlines()[0] + "\n")
            result = validate_frozen_baseline(work / "results")
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("missing or extra" in item for item in result["errors"])
        )

    def test_baseline_pilot_provenance_rejects_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            slope = 0.5
            intercepts = [-0.2, -0.2]
            (work / "ctfr_baseline_committed_state_v2.json").write_text(
                json.dumps(
                    {
                        "schema": "ctfr-baseline-v1",
                        "slope": slope,
                        "intercepts": intercepts,
                        "coefficient_sha256": baseline_digest(
                            slope, intercepts
                        ),
                    }
                )
            )
            pilot = write_baseline_pilot(work, slope, intercepts)
            (pilot / "state_learned.json").write_text("{}\n")
            result = validate_frozen_baseline(work / "results")
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("hash mismatch" in item for item in result["errors"])
        )

    def test_frozen_baseline_must_match_pilot_bank_zero_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            baseline_slope = 0.5
            pilot_slope = 0.6
            intercepts = [-0.2, -0.2]
            (work / "ctfr_baseline_committed_state_v2.json").write_text(
                json.dumps(
                    {
                        "schema": "ctfr-baseline-v1",
                        "slope": baseline_slope,
                        "intercepts": intercepts,
                        "coefficient_sha256": baseline_digest(
                            baseline_slope, intercepts
                        ),
                    }
                )
            )
            write_baseline_pilot(work, pilot_slope, intercepts)
            result = validate_frozen_baseline(work / "results")
        self.assertFalse(result["valid"])
        self.assertIn(
            "frozen baseline does not exactly match the pilot snapshot",
            result["errors"],
        )

    def test_ephemeral_attribution_slots_do_not_break_invariance(self) -> None:
        run = stage_d_run(
            "ctfr-shadow",
            "01",
            throughput=100.0,
            log_loss=0.4,
            brier=0.2,
        )
        run["states"]["post_evaluation"]["feedback_principal_slots"] = [
            1,
            0,
            1,
            0,
        ]
        self.assertEqual(validate_stage_d_transition(run), [])

    def test_post_evaluation_policy_change_is_rejected(self) -> None:
        run = stage_d_run(
            "ctfr-shadow",
            "01",
            throughput=100.0,
            log_loss=0.4,
            brier=0.2,
        )
        run["states"]["post_evaluation"]["slope"][0] += 0.1
        self.assertIn(
            "held-out evaluation changed policy state",
            validate_stage_d_transition(run),
        )

    def test_no_action_barrier_marker_is_exact(self) -> None:
        self.assertEqual(
            validate_no_action_barrier(
                {"called": False, "method": None, "response": None}
            ),
            [],
        )
        self.assertTrue(
            validate_no_action_barrier(
                {
                    "called": False,
                    "method": None,
                    "response": None,
                    "extra": True,
                }
            )
        )

    def test_stage_d_allows_adaptation_and_tenant_local_advantage_claims(self) -> None:
        result = analyze_stage_d(complete_stage_d_runs())
        self.assertTrue(result["valid"])
        self.assertEqual(result["complete_blocks"], 8)
        self.assertTrue(
            result["claims"]["pre_retirement_committed_state_invariance"]
        )
        self.assertTrue(
            result["claims"]["held_out_output_semantic_equivalence"]
        )
        self.assertTrue(result["claims"]["adaptation_opportunity_established"])
        self.assertTrue(result["claims"]["benign_adaptation_retained"])
        self.assertTrue(result["claims"]["preferable_to_tenant_local"])
        self.assertAlmostEqual(result["adaptation_recovery"]["ratio"], 0.9)
        self.assertGreater(
            result["comparisons"]["ctfr_vs_frozen_log_loss"]["ci95_low"],
            0,
        )

    def test_stage_d_does_not_infer_advantage_from_a_tie(self) -> None:
        result = analyze_stage_d(
            complete_stage_d_runs(tenant_throughput=109.0)
        )
        self.assertTrue(result["claims"]["benign_adaptation_retained"])
        self.assertFalse(result["claims"]["preferable_to_tenant_local"])

    def test_stage_d_requires_shared_over_frozen_adaptation_opportunity(
        self,
    ) -> None:
        runs = complete_stage_d_runs()
        for run in runs:
            if run["arm"] == "shared":
                run["outcomes"]["system_throughput"] = 100.0
        result = analyze_stage_d(runs)
        self.assertTrue(result["valid"])
        self.assertFalse(
            result["claims"]["adaptation_opportunity_established"]
        )
        self.assertFalse(result["claims"]["benign_adaptation_retained"])

    def test_stage_d_requires_exact_cross_arm_observation_balance(self) -> None:
        runs = complete_stage_d_runs()
        target = next(
            run
            for run in runs
            if run["block_id"] == "01" and run["arm"] == "ctfr-full"
        )
        target["states"]["accumulated"]["counts"][2][0] -= 1.0
        result = analyze_stage_d(runs)
        self.assertFalse(result["valid"])
        self.assertIn(
            "block 01 has unequal graded observation counts",
            result["errors"],
        )

    def test_stage_d_rejects_cross_arm_output_mismatch(self) -> None:
        runs = complete_stage_d_runs()
        target = next(
            run
            for run in runs
            if run["block_id"] == "01" and run["arm"] == "ctfr-full"
        )
        target["evaluation"]["records"][0]["token_ids"] = [99]
        result = analyze_stage_d(runs)
        self.assertFalse(result["valid"])
        self.assertIn(
            "block 01 held-out outputs differ across arms",
            result["errors"],
        )

    def test_stage_d_rejects_swapped_declared_arm_order(self) -> None:
        runs = complete_stage_d_runs()
        declared = {
            block: list(STAGE_D_ARMS) for block in STAGE_D_BLOCKS
        }
        self.assertTrue(
            analyze_stage_d(
                runs,
                declared_order_by_block=declared,
            )["valid"]
        )
        shared = next(
            run
            for run in runs
            if run["block_id"] == "01" and run["arm"] == "shared"
        )
        frozen = next(
            run
            for run in runs
            if run["block_id"] == "01" and run["arm"] == "frozen"
        )
        shared["adaptation"]["started_ns"], frozen["adaptation"][
            "started_ns"
        ] = (
            frozen["adaptation"]["started_ns"],
            shared["adaptation"]["started_ns"],
        )
        result = analyze_stage_d(
            runs,
            declared_order_by_block=declared,
        )
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("differs from declaration" in item for item in result["errors"])
        )

    def test_stage_d_gate_requires_an_adaptation_opportunity(self) -> None:
        values = {
            "shared": 1.10,
            "frozen": 1.00,
            "tenant-local": 1.07,
            "ctfr-shadow": 1.00,
            "ctfr-full": 1.09,
        }
        runs = [
            stage_d_run(
                arm,
                "gate",
                throughput=values[arm],
                log_loss=0.2,
                brier=0.1,
            )
            for arm in STAGE_D_ARMS
        ]
        for run in runs:
            run["binding_telemetry"] = {
                "valid": True,
                "mixed_principal_batch_count": 1,
            }
        result = analyze_stage_d_gate(runs)
        self.assertTrue(result["valid"])
        self.assertTrue(result["shared_over_frozen_adaptation_opportunity"])
        self.assertTrue(result["ctfr_retirement_geometry_valid"])
        self.assertTrue(result["tenant_local_refit_valid"])
        shared = next(run for run in runs if run["arm"] == "shared")
        shared["outcomes"]["system_throughput"] = 0.99
        result = analyze_stage_d_gate(runs)
        self.assertFalse(result["valid"])

    def test_stage_d_rejects_incomplete_blocks(self) -> None:
        runs = complete_stage_d_runs()
        runs.pop()
        result = analyze_stage_d(runs)
        self.assertFalse(result["valid"])
        self.assertFalse(result["claims"]["benign_adaptation_retained"])

    def test_stage_d_rejects_reused_process_identity(self) -> None:
        runs = complete_stage_d_runs()
        runs[1]["metadata"]["process_uuid"] = runs[0]["metadata"][
            "process_uuid"
        ]
        result = analyze_stage_d(runs)
        self.assertFalse(result["valid"])
        self.assertIn(
            "fresh-process identifiers are not globally unique",
            result["errors"],
        )

    def test_stage_d_rejects_reused_gateway_instance(self) -> None:
        runs = complete_stage_d_runs()
        first_id = runs[0]["gateway_evidence"]["observed"][
            "gateway_instance_id"
        ]
        runs[1]["gateway_evidence"]["observed"][
            "gateway_instance_id"
        ] = first_id
        result = analyze_stage_d(runs)
        self.assertFalse(result["valid"])
        self.assertIn(
            "Stage D reuses a gateway instance identity",
            result["errors"],
        )

    def test_eval_metrics_requires_two_finite_principal_rows(self) -> None:
        payload = {
            "results": [
                {
                    "available": True,
                    "eval_metrics": {
                        "enabled": True,
                        "principals": [
                            {
                                "principal": 0,
                                "count": 2.0,
                                "mean_log_loss": 0.2,
                                "mean_brier": 0.1,
                                "counts_by_position": [1.0, 1.0],
                            },
                            {
                                "principal": 1,
                                "count": 2.0,
                                "mean_log_loss": 0.3,
                                "mean_brier": 0.2,
                                "counts_by_position": [1.0, 1.0],
                            },
                        ],
                    },
                }
            ]
        }
        result = parse_eval_metrics(payload)
        self.assertEqual(result["attacker"]["log_loss"], 0.2)
        self.assertEqual(
            result["attacker"]["counts_by_position"], [1.0, 1.0]
        )
        payload["results"][0]["eval_metrics"]["principals"].pop()
        with self.assertRaises(ValueError):
            parse_eval_metrics(payload)

    def test_eval_counts_match_detailed_authenticated_request_evidence(
        self,
    ) -> None:
        artifact = {
            "records": [
                {
                    "ok": True,
                    "authenticated_tenant": "attacker",
                    "metrics": {
                        "speculative_decoding": detailed_metric(
                            [4, 2],
                            [1, 2],
                        )
                    },
                },
                {
                    "ok": True,
                    "authenticated_tenant": "victim",
                    "metrics": {
                        "speculative_decoding": detailed_metric([3], [0])
                    },
                },
            ]
        }
        observed = derive_eval_counts_by_position(
            artifact,
            label="evaluation",
        )
        self.assertEqual(observed["attacker"], [2.0, 2.0, 0.0, 0.0])
        self.assertEqual(observed["victim"], [1.0, 0.0, 0.0, 0.0])
        reported = {
            "attacker": {
                "count": 4.0,
                "counts_by_position": [2.0, 2.0, 0.0, 0.0],
            },
            "victim": {
                "count": 1.0,
                "counts_by_position": [1.0, 0.0, 0.0, 0.0],
            },
        }
        self.assertEqual(
            compare_eval_counts(observed, reported, label="eval_metrics"),
            [],
        )
        reported["attacker"]["counts_by_position"][2] = 1.0
        self.assertTrue(
            compare_eval_counts(observed, reported, label="eval_metrics")
        )

    def test_eval_reset_requires_exact_zero_after_counters(self) -> None:
        zero_rows = [
            {
                "principal": principal_id,
                "count": 0.0,
                "mean_log_loss": None,
                "mean_brier": None,
                "counts_by_position": [0.0, 0.0, 0.0, 0.0],
            }
            for principal_id in (0, 1)
        ]
        payload = {
            "results": [
                {
                    "available": True,
                    "eval_metrics": {
                        "before": {
                            "enabled": True,
                            "principals": copy.deepcopy(zero_rows),
                        },
                        "after": {
                            "enabled": True,
                            "principals": copy.deepcopy(zero_rows),
                        },
                    },
                }
            ]
        }
        result = parse_eval_reset(
            payload,
            label="eval_reset_compile",
            expected_enabled=True,
        )
        self.assertEqual(result["after"]["attacker"]["count"], 0.0)
        after = payload["results"][0]["eval_metrics"]["after"]
        after["principals"][0].update(
            {
                "count": 1.0,
                "mean_log_loss": 0.2,
                "mean_brier": 0.1,
                "counts_by_position": [1.0, 0.0, 0.0, 0.0],
            }
        )
        with self.assertRaises(ValueError):
            parse_eval_reset(
                payload,
                label="eval_reset_compile",
                expected_enabled=True,
            )

    def test_failed_retirement_requires_declared_reason_and_no_mutation(self) -> None:
        accumulated = state("ctfr-full", feedback=True)
        after = copy.deepcopy(accumulated)
        after["updates_enabled"] = False
        run = {
            "barrier": {
                "called": True,
                "method": "avep_retire_ctfr",
                "response": {
                    "results": [
                        {
                            "available": True,
                            "retirement": {
                                "retired": False,
                                "reason": "independent-principal candidates disagree",
                            },
                        }
                    ]
                },
            },
            "states": {
                "accumulated": accumulated,
                "after_barrier": after,
            },
        }
        self.assertEqual(
            validate_failed_retirement(run, reason_fragment="disagree"),
            [],
        )

    def test_stage_e_requires_one_call_and_matching_success_event(self) -> None:
        run = stage_d_run(
            "ctfr-full",
            "01",
            throughput=1.0,
            log_loss=0.2,
            brier=0.1,
        )
        run["scenario"] = "sybil-quorum-capture"
        run["metadata"]["credential_control_by_principal"] = {
            "attacker": "attacker",
            "victim": "attacker",
        }
        self.assertEqual(validate_stage_e_transition(run), [])
        run["barrier_log_counts"]["ctfr_retire"] = 0
        self.assertIn(
            "Stage E retirement event count disagrees with the result",
            validate_stage_e_transition(run),
        )

    def test_overhead_guardrails_use_absolute_between_arm_ratios(self) -> None:
        passing = [
            overhead_run(
                block,
                arm,
                0.98 if arm == "ctfr-full-no-retire" else 1.0,
            )
            for block in STAGE_D_BLOCKS
            for arm in ("shared", "ctfr-full-no-retire")
        ]
        result = analyze_overhead(passing)
        self.assertTrue(result["guardrails_pass"])
        failing = [
            overhead_run(
                block,
                arm,
                0.80 if arm == "ctfr-full-no-retire" else 1.0,
            )
            for block in STAGE_D_BLOCKS
            for arm in ("shared", "ctfr-full-no-retire")
        ]
        result = analyze_overhead(failing)
        self.assertFalse(result["guardrails_pass"])
        self.assertAlmostEqual(
            result["ctfr_over_shared_throughput"]["mean"],
            0.8,
        )

    def test_missing_stage_e_never_claims_sybil_resistance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = analyze_stage_e(
                [], origin_binding_path=Path(directory) / "missing.json"
            )
        self.assertFalse(result["complete"])
        self.assertFalse(result["claims"]["sybil_resistant"])
        self.assertFalse(result["claims"]["single_identity_quorum_rejected"])
        self.assertFalse(result["claims"]["overhead_guardrails_pass"])

    def test_discovery_rejects_failed_quarantined_and_hidden_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "results"
            root.mkdir()
            (root / "CTFR_FULL_STUDY_FAILED.txt").write_text("failed\n")
            incomplete = root / "_incomplete" / "old-run"
            incomplete.mkdir(parents=True)
            (incomplete / "artifact").write_text("partial\n")
            wrong = root / "foreign_run"
            wrong.mkdir()
            (wrong / "metadata.json").write_text(
                json.dumps({"protocol_version": "unexpected"})
            )
            direct = root / "stage_d_block_01_shared"
            direct.mkdir()
            (direct / "metadata.json").write_text(
                json.dumps({"protocol_version": analyzer.PROTOCOL_VERSION})
            )
            _, errors, _ = discover_runs(root)
        self.assertTrue(
            any("CTFR_FULL_STUDY_FAILED" in item for item in errors)
        )
        self.assertTrue(any("nonempty _incomplete" in item for item in errors))
        self.assertTrue(
            any("unexpected protocol version" in item for item in errors)
        )
        self.assertTrue(any("protocol run is incomplete" in item for item in errors))

    def test_committed_projection_includes_refit_statistics_and_credits(self) -> None:
        first = state("ctfr-shadow")
        second = copy.deepcopy(first)
        second["feedback_principal_slots"] = [0, 1, -1, -1]
        self.assertEqual(committed_projection(first), committed_projection(second))
        self.assertEqual(policy_projection(first), policy_projection(second))
        second["ctfr_influence_credits"][0] -= 0.1
        self.assertNotEqual(
            committed_projection(first), committed_projection(second)
        )


if __name__ == "__main__":
    unittest.main()
