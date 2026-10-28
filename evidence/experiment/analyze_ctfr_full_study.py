#!/usr/bin/env python
"""Fail-closed analysis for the CTFR Stage D/E confirmatory study.

The independent statistical unit is a fresh-process temporal block.  Request
records are used only to validate evidence and calculate one run-level outcome;
they are never treated as independent replicates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "avep-ctfr-full-study-v2"
SCHEMA_VERSION = "ctfr-full-analysis-v1"
SEED = 20260920
BOOTSTRAP_SAMPLES = 20_000
SHADOW_MEMORY_BOUND_SCOPE = (
    "Persistent shadow-state tensors only; excludes transient retirement and "
    "validation workspace."
)
PRINCIPALS = ("attacker", "victim")
PRINCIPAL_IDS = {"attacker": 0, "victim": 1}
STAGE_D_ARMS = (
    "shared",
    "frozen",
    "tenant-local",
    "ctfr-shadow",
    "ctfr-full",
)
STAGE_D_BLOCKS = tuple(f"{value:02d}" for value in range(1, 9))
STAGE_E_SCENARIOS = (
    "sybil-single",
    "sybil-disagree",
    "sybil-quorum-capture",
)
STUDY_STAGES = (
    "stage-d-gate",
    "stage-d",
    "stage-e1",
    "stage-e2",
    "stage-e3",
    "overhead",
)
MODE_BY_ARM = {
    "shared": "shared",
    "frozen": "shared",
    "tenant-local": "tenant-local",
    "ctfr-shadow": "ctfr-shadow",
    "ctfr-full": "ctfr-full",
    "ctfr-full-no-retire": "ctfr-full",
}
STATE_FIELDS = (
    "steps_since_refit",
    "refits",
    "slope",
    "intercepts",
    "counts",
    "info",
    "grad",
)
CONTEXT_FIELDS = (
    "source_sha256",
    "target_model_revision",
    "draft_model_revision",
    "sampling_policy_sha256",
    "feature_contract_version",
)
DIGEST_FIELDS = (
    "baseline_sha256",
    "source_sha256",
    "sampling_policy_sha256",
    "adaptation_manifest_sha256",
    "evaluation_manifest_sha256",
)
BINDING_EVENT = re.compile(r"AVEP_CTFR_BINDING\s+(\{.*\})")
CANONICAL_NONNEGATIVE_INTEGER = r"(?:0|[1-9][0-9]*)"
WORKER_COMPLETION_ID = re.compile(
    rf"^(?P<base>.+)-{CANONICAL_NONNEGATIVE_INTEGER}-[0-9a-f]{{8}}$"
)
WARMUP_REQUEST_ID = re.compile(
    rf"^_warmup_{CANONICAL_NONNEGATIVE_INTEGER}_$"
)
BINDING_PHASES = (
    "compile_warmup",
    "baseline_evaluation",
    "adaptation",
    "evaluation",
)
REQUIRED_DECLARED_INPUTS = {
    "CTFR_EXPERIMENT_PROTOCOL.md",
    "CTFR_DECISION_RULES.md",
    "CTFR_FROZEN_HYPERPARAMETERS.json",
    "CTFR_SAMPLING_POLICY.json",
    "CTFR_MANIFEST_SCHEMA.md",
    "CTFR_DEPLOYMENT_FILELIST.txt",
    "CTFR_V1_GATE_DIAGNOSTIC.md",
    "ctfr_frozen_corpus.json",
    "generate_ctfr_manifests.py",
    "avep_paper_instrumentation.patch",
    "avep_causal_ablation.patch",
    "avep_pcfr_mitigation.patch",
    "avep_ctfr_mitigation.patch",
    "avep_ctfr_experiment_support.patch",
    "avep_ctfr_triton_compat.patch",
    "avep_ctfr_telemetry_v2.patch",
    "prepare_ctfr_source.sh",
    "run_factorial_confirmatory.sh",
    "run_ctfr_full_study.sh",
    "ctfr_gateway.py",
    "ctfr_dual_probe.py",
    "test_ctfr_dual_probe.py",
    "ctfr_resource_sampler.sh",
    "extract_ctfr_baseline.py",
    "test_extract_ctfr_baseline.py",
    "analyze_ctfr_mechanism.py",
    "test_analyze_ctfr_mechanism.py",
    "test_generate_ctfr_manifests.py",
    "analyze_ctfr_full_study.py",
    "test_analyze_ctfr_full_study.py",
    "ctfr_baseline_committed_state_v2.json",
    "ctfr_baseline_pilot_v2/COMPLETE",
    "ctfr_baseline_pilot_v2/PROVENANCE.sha256",
    "ctfr_full_environment_v2.txt",
    *{
        f"ctfr_manifests_v2/{name}.json"
        for name in (
            "compile_warmup",
            "baseline_adaptation",
            "baseline_evaluation",
            "shifted_adaptation",
            "shifted_evaluation",
            "stationary_adaptation",
            "e1_one_identity",
            "e2_disagreement",
            "e3_two_credentials",
        )
    },
}


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value is not an object")
    return value


def finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def finite_tree(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int | float):
        return math.isfinite(float(value))
    if isinstance(value, list):
        return all(finite_tree(item) for item in value)
    return False


def is_sha256(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def load_declared_principals(root: Path) -> dict[str, str]:
    value = load_object(root / "DECLARED_PRINCIPALS.json")
    names = ("attacker", "victim", "upstream")
    if (
        set(value) != set(names)
        or any(not is_sha256(value.get(name)) for name in names)
        or len({value[name] for name in names}) != len(names)
    ):
        raise ValueError("declared principal fingerprints are invalid")
    return {name: value[name] for name in names}


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None or result.utcoffset() is None:
        return None
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def baseline_digest(slope: float, intercepts: list[float]) -> str:
    canonical = json.dumps(
        {"slope": float(slope), "intercepts": intercepts},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def extract_pilot_baseline(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("pilot snapshot is not an object")
    results = payload.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise ValueError("pilot snapshot does not contain one worker")
    state = results[0]
    if not isinstance(state, dict) or state.get("available") is not True:
        raise ValueError("pilot estimator state is unavailable")
    slopes = state.get("slope")
    intercept_banks = state.get("intercepts")
    if not isinstance(slopes, list) or not slopes:
        raise ValueError("pilot slope banks are absent")
    if not isinstance(intercept_banks, list) or not intercept_banks:
        raise ValueError("pilot intercept banks are absent")
    slope = finite(slopes[0])
    intercepts = intercept_banks[0]
    if slope is None or not isinstance(intercepts, list) or not intercepts:
        raise ValueError("pilot canonical coefficients are invalid")
    if any(finite(value) is None for value in intercepts):
        raise ValueError("pilot canonical intercepts are invalid")
    normalized = [float(value) for value in intercepts]
    return {
        "schema": "ctfr-baseline-v1",
        "slope": float(slope),
        "intercepts": normalized,
        "coefficient_sha256": baseline_digest(float(slope), normalized),
    }


def validate_pilot_provenance(pilot: Path) -> list[str]:
    errors: list[str] = []
    if not pilot.is_dir() or pilot.is_symlink():
        return ["baseline pilot directory is absent or symbolic"]
    provenance = pilot / "PROVENANCE.sha256"
    complete = pilot / "COMPLETE"
    if not complete.is_file() or complete.is_symlink():
        errors.append("baseline pilot COMPLETE marker is absent")
    try:
        actual: set[str] = set()
        for path in pilot.rglob("*"):
            if path.is_symlink():
                errors.append("baseline pilot contains a symbolic link")
                continue
            if path.is_file() and path != provenance:
                actual.add(path.relative_to(pilot).as_posix())
        lines = provenance.read_text().splitlines()
        declared: dict[str, str] = {}
        if not lines:
            errors.append("baseline pilot provenance is empty")
        for line in lines:
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                errors.append("baseline pilot provenance line is malformed")
                continue
            digest, raw_name = parts
            name = raw_name.lstrip("* ")
            if name.startswith("./"):
                name = name[2:]
            relative = Path(name)
            if (
                not is_sha256(digest)
                or not name
                or relative.is_absolute()
                or ".." in relative.parts
                or name in declared
            ):
                errors.append(
                    f"baseline pilot provenance entry is invalid: {raw_name}"
                )
                continue
            declared[name] = digest
        if set(declared) != actual:
            errors.append(
                "baseline pilot provenance has missing or extra entries"
            )
        for name, digest in declared.items():
            target = pilot / name
            if (
                name not in actual
                or not target.is_file()
                or target.is_symlink()
                or sha256(target) != digest
            ):
                errors.append(
                    f"baseline pilot provenance hash mismatch: {name}"
                )
    except (OSError, ValueError) as exc:
        errors.append(
            f"baseline pilot provenance: {type(exc).__name__}: {exc}"
        )
    return errors


def validate_frozen_baseline(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    baseline: dict[str, Any] = {}
    path = root.parent / "ctfr_baseline_committed_state_v2.json"
    try:
        payload = load_object(path)
        slope = finite(payload.get("slope"))
        intercepts = payload.get("intercepts")
        if payload.get("schema") != "ctfr-baseline-v1":
            errors.append("frozen baseline schema is invalid")
        if slope is None or slope < 0:
            errors.append("frozen baseline slope is invalid")
        if (
            not isinstance(intercepts, list)
            or not intercepts
            or not finite_tree(intercepts)
        ):
            errors.append("frozen baseline intercepts are invalid")
        if not errors:
            normalized_intercepts = [float(value) for value in intercepts]
            digest = baseline_digest(float(slope), normalized_intercepts)
            if payload.get("coefficient_sha256") != digest:
                errors.append("frozen baseline coefficient digest is invalid")
            baseline = {
                "slope": float(slope),
                "intercepts": normalized_intercepts,
                "coefficient_sha256": digest,
                "path": str(path),
            }
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"frozen baseline: {type(exc).__name__}: {exc}")
    pilot = root.parent / "ctfr_baseline_pilot_v2"
    errors.extend(validate_pilot_provenance(pilot))
    try:
        learned = load_object(pilot / "state_learned.json")
        extracted = extract_pilot_baseline(learned)
        committed = load_object(path)
        if committed != extracted:
            errors.append(
                "frozen baseline does not exactly match the pilot snapshot"
            )
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"baseline pilot state: {type(exc).__name__}: {exc}")
    return {"valid": not errors, "errors": errors, "baseline": baseline}


def validate_run_baseline(
    run_dir: Path,
    metadata: dict[str, Any],
    before: dict[str, Any],
    frozen: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    observed: dict[str, Any] = {}
    try:
        worker = unwrap_worker(
            load_object(run_dir / "baseline_load.json"),
            "baseline_load",
        )
        loaded = worker.get("baseline")
        if not isinstance(loaded, dict) or loaded.get("loaded") is not True:
            raise ValueError("baseline load did not report loaded=true")
        expected_digest = frozen["coefficient_sha256"]
        expected_slope = frozen["slope"]
        expected_intercepts = frozen["intercepts"]
        if metadata.get("baseline_sha256") != expected_digest:
            errors.append("metadata does not identify the frozen baseline")
        if loaded.get("baseline_sha256") != expected_digest:
            errors.append("baseline-load digest does not match the frozen baseline")
        if loaded.get("slope") != expected_slope:
            errors.append("baseline-load slope differs from the frozen baseline")
        if loaded.get("intercepts") != expected_intercepts:
            errors.append(
                "baseline-load intercepts differ from the frozen baseline"
            )
        slopes = before.get("slope")
        intercept_banks = before.get("intercepts")
        if (
            not isinstance(slopes, list)
            or len(slopes) != 4
            or any(value != expected_slope for value in slopes)
        ):
            errors.append("before-state banks do not share the frozen slope")
        if (
            not isinstance(intercept_banks, list)
            or len(intercept_banks) != 4
            or any(bank != expected_intercepts for bank in intercept_banks)
        ):
            errors.append(
                "before-state banks do not share the frozen intercepts"
            )
        if not all(statistics_cleared(before, domain) for domain in range(4)):
            errors.append("before-state contains pre-adaptation statistics")
        if before.get("refits") != [0, 0, 0, 0]:
            errors.append("before-state refit counters were not reset")
        if before.get("committed_version") != 0:
            errors.append("before-state committed version was not reset")
        if before.get("tenant_local_versions") != [0, 0]:
            errors.append("before-state tenant-local versions were not reset")
        hyperparameters = before.get("retirement_hyperparameters")
        capacity = (
            finite(hyperparameters.get("bucket_capacity"))
            if isinstance(hyperparameters, dict)
            else None
        )
        if capacity is None or not close_values(
            before.get("ctfr_influence_credits"), [capacity, capacity]
        ):
            errors.append("before-state influence credits were not reset")
        observed = {
            "loaded": loaded.get("loaded"),
            "coefficient_sha256": loaded.get("baseline_sha256"),
            "all_four_banks_initialized": not errors,
        }
    except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError) as exc:
        errors.append(f"baseline load: {type(exc).__name__}: {exc}")
    return errors, observed


def read_json_lines(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}: line {number} is not an object")
        rows.append(value)
    return rows


def validate_declaration(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    bound: int | None = None
    scope: str | None = None
    principal_fingerprints: dict[str, str] = {}
    stage_d_order: dict[str, list[str]] = {}
    stage_e_order: dict[str, list[str]] = {}
    overhead_order: dict[str, list[str]] = {}
    try:
        schedule = load_object(root / "DECLARED_SCHEDULE.json")
        expected_fixed = {
            "stage_d_blocks": 8,
            "stage_d_arms": list(STAGE_D_ARMS),
            "stage_e": [
                "e1-one-identity",
                "e2-disagreement",
                "e3-two-credentials",
            ],
            "stage_e_initial": "e1-one-identity",
            "overhead_blocks": 8,
            "overhead_arms": ["shared", "ctfr-full-no-retire"],
            "fresh_process_per_arm": True,
            "barrier_attempts_per_run": 1,
            "bootstrap_seed": SEED,
            "fixed_shadow_tensor_bound_bytes": 1024,
        }
        expected_keys = {
            *expected_fixed,
            "stage_d_order_by_block",
            "stage_e_order_by_block",
            "overhead_order_by_block",
        }
        if set(schedule) != expected_keys or any(
            schedule.get(name) != value
            for name, value in expected_fixed.items()
        ):
            errors.append("declared schedule is not the frozen full-study schedule")
        raw_stage_d_order = schedule.get("stage_d_order_by_block")
        raw_stage_e_order = schedule.get("stage_e_order_by_block")
        raw_overhead_order = schedule.get("overhead_order_by_block")
        if (
            not isinstance(raw_stage_d_order, dict)
            or set(raw_stage_d_order) != set(STAGE_D_BLOCKS)
            or any(
                not isinstance(order, list)
                or len(order) != len(STAGE_D_ARMS)
                or set(order) != set(STAGE_D_ARMS)
                for order in raw_stage_d_order.values()
            )
        ):
            errors.append("declared Stage D arm orders are invalid")
        else:
            stage_d_order = raw_stage_d_order
        expected_stage_e_order = [
            "e2-disagreement",
            "e3-two-credentials",
        ]
        if (
            not isinstance(raw_stage_e_order, dict)
            or set(raw_stage_e_order) != set(STAGE_D_BLOCKS)
            or any(
                order != expected_stage_e_order
                for order in raw_stage_e_order.values()
            )
        ):
            errors.append("declared Stage E scenario orders are invalid")
        else:
            stage_e_order = raw_stage_e_order
        overhead_arms = {"shared", "ctfr-full-no-retire"}
        if (
            not isinstance(raw_overhead_order, dict)
            or set(raw_overhead_order) != set(STAGE_D_BLOCKS)
            or any(
                not isinstance(order, list)
                or len(order) != len(overhead_arms)
                or set(order) != overhead_arms
                for order in raw_overhead_order.values()
            )
        ):
            errors.append("declared overhead arm orders are invalid")
        else:
            overhead_order = raw_overhead_order
        bound_value = schedule.get("fixed_shadow_tensor_bound_bytes")
        if isinstance(bound_value, int) and not isinstance(bound_value, bool):
            bound = bound_value
        sidecar = (root / "DECLARED_SCHEDULE.json.sha256").read_text().split()
        if sidecar != [sha256(root / "DECLARED_SCHEDULE.json"),
                       "DECLARED_SCHEDULE.json"]:
            errors.append("declared schedule SHA-256 sidecar does not match")
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"schedule declaration: {type(exc).__name__}: {exc}")
    try:
        rules_copy = root / "DECLARED_DECISION_RULES.md"
        rules_source = root.parent / "CTFR_DECISION_RULES.md"
        sidecar = (
            root / "DECLARED_DECISION_RULES.md.sha256"
        ).read_text().split()
        if sidecar != [sha256(rules_copy), "DECLARED_DECISION_RULES.md"]:
            errors.append(
                "declared decision-rules SHA-256 sidecar does not match"
            )
        if sha256(rules_copy) != sha256(rules_source):
            errors.append(
                "declared decision-rules snapshot differs from frozen input"
            )
    except (OSError, ValueError) as exc:
        errors.append(
            f"decision-rules declaration: {type(exc).__name__}: {exc}"
        )
    try:
        principal_fingerprints = load_declared_principals(root)
        sidecar = (
            root / "DECLARED_PRINCIPALS.json.sha256"
        ).read_text().split()
        if sidecar != [
            sha256(root / "DECLARED_PRINCIPALS.json"),
            "DECLARED_PRINCIPALS.json",
        ]:
            errors.append(
                "declared principal SHA-256 sidecar does not match"
            )
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(
            f"principal declaration: {type(exc).__name__}: {exc}"
        )
    try:
        lines = (root / "DECLARED_INPUTS.sha256").read_text().splitlines()
        if not lines:
            errors.append("declared input hash list is empty")
        declared_names: set[str] = set()
        for line in lines:
            digest, name = line.split(maxsplit=1)
            clean_name = name.lstrip("* ")
            relative = Path(clean_name)
            if (
                not is_sha256(digest)
                or relative.is_absolute()
                or ".." in relative.parts
                or clean_name in declared_names
            ):
                errors.append(f"invalid declared input entry: {name}")
                continue
            declared_names.add(clean_name)
            path = root.parent / relative
            if not path.is_file() or sha256(path) != digest:
                errors.append(f"declared input mismatch: {name}")
        missing = sorted(REQUIRED_DECLARED_INPUTS - declared_names)
        if missing:
            errors.append(f"required declared inputs are absent: {missing}")
    except (OSError, ValueError) as exc:
        errors.append(f"input declaration: {type(exc).__name__}: {exc}")
    try:
        hyperparameters = load_object(
            root.parent / "CTFR_FROZEN_HYPERPARAMETERS.json"
        )
        if hyperparameters.get("fixed_shadow_tensor_bound_bytes") != bound:
            errors.append("shadow bound disagrees with frozen hyperparameters")
        if (
            hyperparameters.get("fixed_shadow_tensor_scope")
            != SHADOW_MEMORY_BOUND_SCOPE
        ):
            errors.append("frozen shadow-bound scope is invalid")
        else:
            scope = SHADOW_MEMORY_BOUND_SCOPE
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"frozen hyperparameters: {type(exc).__name__}: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "shadow_bound_bytes": bound,
        "shadow_bound_scope": scope,
        "principal_fingerprints": principal_fingerprints,
        "stage_d_order_by_block": stage_d_order,
        "stage_e_order_by_block": stage_e_order,
        "overhead_order_by_block": overhead_order,
    }


def unwrap_worker(payload: dict[str, Any], label: str) -> dict[str, Any]:
    results = payload.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise ValueError(f"{label}: expected exactly one worker result")
    result = results[0]
    if not isinstance(result, dict) or result.get("available") is not True:
        raise ValueError(f"{label}: estimator worker result is unavailable")
    return result


def close_values(left: Any, right: Any, tolerance: float = 1.0e-6) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right
    if isinstance(left, int | float) and isinstance(right, int | float):
        left_value = float(left)
        right_value = float(right)
        if not math.isfinite(left_value) or not math.isfinite(right_value):
            return False
        scale = max(1.0, abs(left_value), abs(right_value))
        return abs(left_value - right_value) <= tolerance * scale
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            close_values(a, b, tolerance) for a, b in zip(left, right)
        )
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            close_values(left[key], right[key], tolerance) for key in left
        )
    return left == right


def state_bank(state: dict[str, Any], domain: int) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in STATE_FIELDS:
        values = state.get(field)
        if not isinstance(values, list) or len(values) != 4:
            raise ValueError(f"state field {field} is not a four-bank value")
        result[field] = values[domain]
    return result


def coefficients(state: dict[str, Any], domain: int) -> list[float]:
    bank = state_bank(state, domain)
    slope = finite(bank["slope"])
    intercepts = bank["intercepts"]
    if slope is None or not isinstance(intercepts, list) or not intercepts:
        raise ValueError("coefficient bank has an invalid shape")
    if not finite_tree(intercepts):
        raise ValueError("coefficient bank contains a non-finite value")
    return [slope, *(float(value) for value in intercepts)]


def committed_projection(state: dict[str, Any]) -> dict[str, Any]:
    version = state.get("committed_version")
    credits = state.get("ctfr_influence_credits")
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError("committed_version is not a non-negative integer")
    if (
        not isinstance(credits, list)
        or len(credits) != 2
        or not finite_tree(credits)
        or any(float(value) < 0 for value in credits)
    ):
        raise ValueError("ctfr_influence_credits is invalid")
    return {
        "bank": state_bank(state, 0),
        "version": version,
        "credits": credits,
        "baseline_sha256": state.get("baseline_sha256"),
    }


def policy_projection(
    state: dict[str, Any], *, include_update_gate: bool = True
) -> dict[str, Any]:
    """Return policy-relevant state, excluding attribution and eval counters."""
    result = {field: state[field] for field in STATE_FIELDS}
    result.update(
        {
            "committed_version": state["committed_version"],
            "ctfr_influence_credits": state["ctfr_influence_credits"],
            "tenant_local_versions": state["tenant_local_versions"],
            "baseline_sha256": state["baseline_sha256"],
        }
    )
    if include_update_gate:
        result["updates_enabled"] = state["updates_enabled"]
    return result


def observation_count(state: dict[str, Any], domain: int) -> float:
    counts = state_bank(state, domain)["counts"]
    if not isinstance(counts, list) or not finite_tree(counts):
        raise ValueError("observation count bank is invalid")
    return sum(float(value) for value in counts)


def feedback_changed(
    before: dict[str, Any], after: dict[str, Any], domain: int
) -> bool:
    first = state_bank(before, domain)
    second = state_bank(after, domain)
    return bool(
        observation_count(after, domain) > observation_count(before, domain)
        and second["steps_since_refit"] != first["steps_since_refit"]
        and (
            second["info"] != first["info"]
            or second["grad"] != first["grad"]
        )
    )


def statistics_cleared(state: dict[str, Any], domain: int) -> bool:
    bank = state_bank(state, domain)
    return bool(
        close_values(bank["counts"], [0.0] * len(bank["counts"]))
        and close_values(
            bank["info"],
            [
                [0.0] * len(row)
                for row in bank["info"]
            ],
        )
        and close_values(
            bank["grad"],
            [
                [0.0] * len(row)
                for row in bank["grad"]
            ],
        )
        and bank["steps_since_refit"] == 0
    )


def validate_compile_state(state: dict[str, Any], *, mode: str) -> list[str]:
    errors: list[str] = []
    if state.get("pcfr_mode") != mode:
        errors.append("compile warmup snapshot reports the wrong mode")
    if state.get("updates_enabled") is not True:
        errors.append("compile warmup did not run with updates enabled")
    domains = (0,) if mode == "shared" else (2, 3)
    for domain in domains:
        try:
            bank = state_bank(state, domain)
            info = bank["info"]
            if (
                observation_count(state, domain) <= 0
                or not isinstance(bank["steps_since_refit"], int)
                or bank["steps_since_refit"] <= 0
                or not finite_tree(info)
                or not any(
                    abs(float(value)) > 0
                    for row in info
                    for value in row
                )
            ):
                errors.append(
                    f"compile warmup bank {domain} has no accumulated evidence"
                )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                f"compile warmup bank {domain}: {type(exc).__name__}: {exc}"
            )
    return errors


def validate_state(
    state: dict[str, Any],
    *,
    mode: str,
    baseline_sha256: str,
    eval_metrics_enabled: bool,
) -> list[str]:
    errors: list[str] = []
    if state.get("pcfr_mode") != mode:
        errors.append("snapshot reports the wrong feedback mode")
    if state.get("baseline_sha256") != baseline_sha256:
        errors.append("snapshot baseline hash does not match metadata")
    if state.get("eval_metrics_enabled") is not eval_metrics_enabled:
        errors.append("evaluation-metric instrumentation has the wrong state")
    roles = state.get("bank_roles")
    expected_roles = (
        ["canonical", "policy-transformed", "tenant-0", "tenant-1"]
        if mode == "tenant-local"
        else ["canonical", "policy-transformed", "shadow-0", "shadow-1"]
    )
    if roles != expected_roles:
        errors.append("snapshot bank roles do not match the mode")
    if state.get("principal_bank_map") != {"0": 2, "1": 3}:
        errors.append("snapshot principal-to-bank map is invalid")
    versions = state.get("tenant_local_versions")
    if (
        not isinstance(versions, list)
        or len(versions) != 2
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in versions
        )
    ):
        errors.append("tenant-local versions are invalid")
    try:
        committed_projection(state)
        for domain in range(4):
            bank = state_bank(state, domain)
            if not all(finite_tree(bank[field]) for field in STATE_FIELDS):
                errors.append(f"bank {domain} contains a non-finite value")
            coefficients(state, domain)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"state shape: {type(exc).__name__}: {exc}")
    hyperparameters = state.get("retirement_hyperparameters")
    required_hyperparameters = (
        "min_observations",
        "delta_clip",
        "min_cosine",
        "max_commit_norm",
        "max_probability_shift",
        "bucket_capacity",
    )
    if not isinstance(hyperparameters, dict):
        errors.append("retirement hyperparameters are absent")
    else:
        for name in required_hyperparameters:
            value = finite(hyperparameters.get(name))
            if value is None or value < 0:
                errors.append(f"retirement hyperparameter {name} is invalid")
    return errors


def validate_metadata(run_dir: Path, metadata: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    stage = metadata.get("stage")
    arm = metadata.get("arm")
    if metadata.get("protocol_version") != PROTOCOL_VERSION:
        errors.append("protocol version is not the frozen version")
    if metadata.get("run_id") != run_dir.name:
        errors.append("run_id does not match the directory name")
    if stage not in STUDY_STAGES:
        errors.append("stage is not a declared CTFR study stage")
    if not isinstance(metadata.get("block_id"), str):
        errors.append("block_id is absent")
    if not isinstance(arm, str):
        errors.append("arm is absent")
    expected_confirmatory = stage != "stage-d-gate"
    if metadata.get("confirmatory") is not expected_confirmatory:
        errors.append("confirmatory flag does not match the declared stage")
    if metadata.get("fresh_process") is not True:
        errors.append("run is not marked as a fresh process")
    expected_eval_metrics = stage != "overhead"
    if metadata.get("evaluation_metrics_enabled") is not expected_eval_metrics:
        errors.append("evaluation_metrics_enabled does not match the stage")
    expected_updates = not (
        arm == "frozen" or (stage == "overhead" and arm == "shared")
    )
    if metadata.get("adaptation_updates_enabled") is not expected_updates:
        errors.append("adaptation_updates_enabled does not match the arm")
    expected_binding_telemetry = stage in {"stage-d-gate", "stage-e1"}
    if (
        metadata.get("binding_telemetry_enabled")
        is not expected_binding_telemetry
    ):
        errors.append("binding_telemetry_enabled does not match the stage")
    expected_window = "adaptation-only" if stage == "overhead" else "whole-run"
    if metadata.get("resource_measurement_window") != expected_window:
        errors.append("resource measurement window does not match the stage")
    process_uuid = metadata.get("process_uuid")
    if not isinstance(process_uuid, str) or not process_uuid:
        errors.append("process_uuid is absent")
    if parse_time(metadata.get("created_at")) is None:
        errors.append("created_at is not a timezone-aware timestamp")
    for field in DIGEST_FIELDS:
        if not is_sha256(metadata.get(field)):
            errors.append(f"{field} is not a lowercase SHA-256 digest")
    for field in CONTEXT_FIELDS:
        value = metadata.get(field)
        if not isinstance(value, str) or not value:
            errors.append(f"fixed-context field {field} is absent")
    shadow_bound = metadata.get("shadow_memory_bound_bytes")
    if (
        isinstance(shadow_bound, bool)
        or not isinstance(shadow_bound, int)
        or shadow_bound <= 0
    ):
        errors.append("shadow_memory_bound_bytes is not a positive integer")
    if metadata.get("shadow_memory_bound_scope") != SHADOW_MEMORY_BOUND_SCOPE:
        errors.append("shadow_memory_bound_scope is not the frozen scope")
    for name in (
        "observation_budget_by_principal",
        "evaluation_budget_by_principal",
    ):
        budget = metadata.get(name)
        if not isinstance(budget, dict) or set(budget) != set(PRINCIPALS):
            errors.append(f"{name} does not name both principals")
            continue
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in budget.values()
        ):
            errors.append(f"{name} contains an invalid request count")
    scenario = metadata.get("scenario")
    if stage in {"stage-d", "stage-d-gate"}:
        if arm not in STAGE_D_ARMS:
            errors.append("Stage D arm is unknown")
        if scenario != "benign-adaptation":
            errors.append("Stage D scenario is not benign-adaptation")
    elif stage in {"stage-e1", "stage-e2", "stage-e3"}:
        expected_scenario = {
            "stage-e1": "sybil-single",
            "stage-e2": "sybil-disagree",
            "stage-e3": "sybil-quorum-capture",
        }[stage]
        if scenario != expected_scenario:
            errors.append("Stage E scenario does not match the substage")
        if arm != "ctfr-full":
            errors.append("Sybil-boundary runs must use ctfr-full")
    elif stage == "overhead":
        if scenario != "stationary-overhead":
            errors.append("overhead scenario is not stationary-overhead")
        if arm not in {"shared", "ctfr-full-no-retire"}:
            errors.append("overhead arm is unknown")
    evidence = metadata.get("barrier_evidence")
    if not isinstance(evidence, dict):
        errors.append("quiescent barrier evidence is absent")
    else:
        admitted = evidence.get("admitted_requests")
        completed = evidence.get("completed_requests")
        active = evidence.get("active_requests")
        if evidence.get("queue_drained") is not True:
            errors.append("barrier does not attest a drained queue")
        if (
            isinstance(admitted, bool)
            or not isinstance(admitted, int)
            or admitted < 0
            or completed != admitted
            or active != 0
        ):
            errors.append("barrier admission/completion counters are invalid")
        for name in ("called_after_ns", "completed_ns"):
            value = evidence.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                errors.append(f"barrier evidence {name} is invalid")
    return errors


def nonnegative_integer(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def validate_detailed_speculative_metric(
    metric: Any,
) -> tuple[list[str], dict[str, Any] | None]:
    errors: list[str] = []
    if not isinstance(metric, dict):
        return ["speculative-decoding metrics are absent"], None
    steps = nonnegative_integer(metric.get("num_spec_steps"))
    drafted = nonnegative_integer(metric.get("num_draft_tokens"))
    accepted = nonnegative_integer(metric.get("num_accepted_draft_tokens"))
    spec_tokens = nonnegative_integer(metric.get("num_spec_tokens"))
    if steps is None:
        errors.append("num_spec_steps is invalid")
    if drafted is None:
        errors.append("num_draft_tokens is invalid")
    if accepted is None:
        errors.append("num_accepted_draft_tokens is invalid")
    if spec_tokens is None or spec_tokens == 0:
        errors.append("num_spec_tokens is not positive")
    if drafted is not None and accepted is not None and accepted > drafted:
        errors.append("accepted draft tokens exceed drafted tokens")

    per_step_drafted = metric.get("per_step_drafted")
    per_step_accepted = metric.get("per_step_accepted")
    arrays_valid = (
        isinstance(per_step_drafted, list)
        and isinstance(per_step_accepted, list)
        and steps is not None
        and len(per_step_drafted) == steps
        and len(per_step_accepted) == steps
        and all(
            nonnegative_integer(value) is not None
            for value in per_step_drafted
        )
        and all(
            nonnegative_integer(value) is not None
            for value in per_step_accepted
        )
    )
    if not arrays_valid:
        errors.append("per-step speculative arrays are malformed")
        drafted_steps: list[int] = []
        accepted_steps: list[int] = []
    else:
        drafted_steps = per_step_drafted
        accepted_steps = per_step_accepted
        if any(
            accepted_value > drafted_value
            for accepted_value, drafted_value in zip(
                accepted_steps, drafted_steps, strict=True
            )
        ):
            errors.append("a per-step accepted count exceeds its draft count")
        if spec_tokens is not None and any(
            drafted_value > spec_tokens for drafted_value in drafted_steps
        ):
            errors.append("a per-step draft count exceeds num_spec_tokens")
        if drafted is not None and sum(drafted_steps) != drafted:
            errors.append("per-step drafted counts do not sum to total")
        if accepted is not None and sum(accepted_steps) != accepted:
            errors.append("per-step accepted counts do not sum to total")

    histogram = metric.get("acceptance_histogram")
    histogram_valid = (
        isinstance(histogram, list)
        and spec_tokens is not None
        and len(histogram) == spec_tokens + 1
        and all(nonnegative_integer(value) is not None for value in histogram)
    )
    if not histogram_valid:
        errors.append("acceptance_histogram is malformed")
    else:
        if steps is not None and sum(histogram) != steps:
            errors.append("acceptance_histogram does not sum to num_spec_steps")
        if accepted is not None and sum(
            index * count for index, count in enumerate(histogram)
        ) != accepted:
            errors.append("acceptance_histogram does not sum to accepted tokens")
        if arrays_valid:
            expected_histogram = [0] * len(histogram)
            for value in accepted_steps:
                if value >= len(expected_histogram):
                    errors.append(
                        "per-step acceptance exceeds the histogram domain"
                    )
                    break
                expected_histogram[value] += 1
            else:
                if histogram != expected_histogram:
                    errors.append(
                        "acceptance_histogram disagrees with per-step values"
                    )

    rate = finite(metric.get("draft_acceptance_rate"))
    if drafted is not None and drafted > 0:
        if (
            rate is None
            or accepted is None
            or not math.isclose(
                rate,
                accepted / drafted,
                rel_tol=1.0e-12,
                abs_tol=1.0e-12,
            )
        ):
            errors.append("draft_acceptance_rate is inconsistent")
    elif drafted == 0 and metric.get("draft_acceptance_rate") not in (None, 0, 0.0):
        errors.append("zero-draft acceptance rate is invalid")
    mean_acceptance = finite(metric.get("mean_acceptance_length"))
    expected_mean = (
        1.0 + accepted / steps
        if steps not in (None, 0) and accepted is not None
        else 1.0
    )
    if mean_acceptance is None or not math.isclose(
        mean_acceptance,
        expected_mean,
        rel_tol=1.0e-12,
        abs_tol=1.0e-12,
    ):
        errors.append("mean_acceptance_length is inconsistent")
    if errors or None in (steps, drafted, accepted, spec_tokens):
        return errors, None
    return errors, {
        "steps": steps,
        "drafted": drafted,
        "accepted": accepted,
        "spec_tokens": spec_tokens,
        "per_step_drafted": drafted_steps,
        "per_step_accepted": accepted_steps,
    }


def validate_probe(
    artifact: dict[str, Any],
    *,
    run_id: str,
    phase: str,
    manifest_sha256: str,
    expected_counts: dict[str, int],
    spoof_identity_headers: bool = False,
) -> list[str]:
    errors: list[str] = []
    config = artifact.get("config")
    summary = artifact.get("summary")
    records = artifact.get("records")
    if not isinstance(config, dict) or not isinstance(summary, dict):
        return [f"{phase}: config or summary is not an object"]
    if not isinstance(records, list):
        return [f"{phase}: records is not a list"]
    if (
        not isinstance(expected_counts, dict)
        or set(expected_counts) != set(PRINCIPALS)
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for value in expected_counts.values()
        )
    ):
        return [f"{phase}: expected principal counts are invalid"]
    expected_requests = sum(expected_counts.values())
    expected_nonzero = {
        principal: count
        for principal, count in expected_counts.items()
        if count > 0
    }
    expected_config = {
        "phase": phase,
        "run_id": run_id,
        "manifest_sha256": manifest_sha256,
        "spoof_identity_headers": spoof_identity_headers,
        "return_token_ids": True,
    }
    for key, value in expected_config.items():
        if config.get(key) != value:
            errors.append(f"{phase}: config {key} is not {value!r}")
    if summary.get("evidence_ok") is not True:
        errors.append(f"{phase}: probe evidence gate did not pass")
    if (
        summary.get("requests") != expected_requests
        or summary.get("successful") != expected_requests
        or summary.get("failed") != 0
        or len(records) != expected_requests
    ):
        errors.append(f"{phase}: request completion counts are invalid")
    if summary.get("expected_principal_counts") != expected_nonzero:
        errors.append(f"{phase}: expected principal counts are invalid")
    if summary.get("authenticated_principal_counts") != expected_nonzero:
        errors.append(f"{phase}: authenticated principal counts are invalid")
    if (
        summary.get("unique_audit_event_ids") != expected_requests
        or summary.get("missing_audit_event_ids") != 0
    ):
        errors.append(f"{phase}: audit-event joins are incomplete")
    observed_counts = {principal: 0 for principal in PRINCIPALS}
    audit_ids: set[str] = set()
    external_ids: set[str] = set()
    ordinals: set[int] = set()
    speculative_requests = 0
    total_draft_tokens = 0
    total_accepted_tokens = 0
    principal_speculative = {
        principal: {"requests": 0, "drafted": 0, "accepted": 0}
        for principal in PRINCIPALS
    }
    request_times: list[tuple[int, int]] = []
    for record in records:
        if not isinstance(record, dict) or record.get("ok") is not True:
            errors.append(f"{phase}: a request record is unsuccessful")
            continue
        principal = record.get("principal")
        if principal not in PRINCIPALS:
            errors.append(f"{phase}: a record has an unknown principal")
            continue
        observed_counts[principal] += 1
        if record.get("authenticated_tenant") != principal:
            errors.append(f"{phase}: authenticated principal mismatch")
        ordinal = record.get("ordinal")
        if (
            isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal < 0
            or ordinal in ordinals
        ):
            errors.append(f"{phase}: record ordinal is invalid or duplicated")
        else:
            ordinals.add(ordinal)
        token_ids = record.get("token_ids")
        token_ids_valid = not (
            not isinstance(token_ids, list)
            or not token_ids
            or any(
                isinstance(token_id, bool)
                or not isinstance(token_id, int)
                or token_id < 0
                for token_id in token_ids
            )
        )
        if not token_ids_valid:
            errors.append(f"{phase}: token-id evidence is missing or invalid")
        allowed_token_ids = record.get("allowed_token_ids")
        if isinstance(allowed_token_ids, list):
            allowed_valid = bool(allowed_token_ids) and all(
                not isinstance(token_id, bool)
                and isinstance(token_id, int)
                and token_id >= 0
                for token_id in allowed_token_ids
            )
            if not allowed_valid:
                errors.append(f"{phase}: allowed-token evidence is invalid")
            elif token_ids_valid and any(
                token_id not in set(allowed_token_ids)
                for token_id in token_ids
            ):
                errors.append(
                    f"{phase}: output contains a token outside its constraint"
                )
        output_sha256 = record.get("output_sha256")
        if not is_sha256(output_sha256):
            errors.append(f"{phase}: output digest is invalid")
        if phase in {"baseline_evaluation", "adaptation", "evaluation"}:
            metrics = record.get("metrics")
            speculative = (
                metrics.get("speculative_decoding")
                if isinstance(metrics, dict)
                else None
            )
            metric_errors, parsed = validate_detailed_speculative_metric(
                speculative
            )
            errors.extend(f"{phase}: {item}" for item in metric_errors)
            if parsed is not None:
                speculative_requests += 1
                total_draft_tokens += parsed["drafted"]
                total_accepted_tokens += parsed["accepted"]
                principal_speculative[principal]["requests"] += 1
                principal_speculative[principal]["drafted"] += parsed[
                    "drafted"
                ]
                principal_speculative[principal]["accepted"] += parsed[
                    "accepted"
                ]
        audit_id = record.get("audit_event_id")
        external_id = record.get("external_request_id")
        if not isinstance(audit_id, str) or audit_id in audit_ids:
            errors.append(f"{phase}: missing or duplicate audit event id")
        else:
            audit_ids.add(audit_id)
        if not isinstance(external_id, str) or external_id in external_ids:
            errors.append(f"{phase}: missing or duplicate external request id")
        else:
            external_ids.add(external_id)
        started = record.get("started_ns")
        finished = record.get("finished_ns")
        if (
            isinstance(started, bool)
            or not isinstance(started, int)
            or isinstance(finished, bool)
            or not isinstance(finished, int)
            or finished <= started
        ):
            errors.append(f"{phase}: invalid request timestamps")
        else:
            request_times.append((started, finished))
    if observed_counts != expected_counts:
        errors.append(f"{phase}: record principal counts are invalid")
    if ordinals != set(range(expected_requests)):
        errors.append(f"{phase}: record ordinals are not contiguous from zero")
    if phase in {"baseline_evaluation", "adaptation", "evaluation"}:
        expected_rate = (
            total_accepted_tokens / total_draft_tokens
            if total_draft_tokens
            else None
        )
        if (
            summary.get("spec_requests") != expected_requests
            or summary.get("draft_tokens") != total_draft_tokens
            or summary.get("accepted_draft_tokens") != total_accepted_tokens
            or speculative_requests != expected_requests
            or not close_values(
                summary.get("draft_acceptance_rate"), expected_rate
            )
        ):
            errors.append(f"{phase}: speculative summary is inconsistent")
        by_principal = summary.get("by_principal")
        if not isinstance(by_principal, dict):
            errors.append(f"{phase}: per-principal summary is absent")
        else:
            for principal, expected in principal_speculative.items():
                observed = by_principal.get(principal)
                expected_principal_rate = (
                    expected["accepted"] / expected["drafted"]
                    if expected["drafted"]
                    else None
                )
                if not isinstance(observed, dict) or any(
                    (
                        observed.get("spec_requests") != expected["requests"],
                        observed.get("draft_tokens") != expected["drafted"],
                        observed.get("accepted_draft_tokens")
                        != expected["accepted"],
                        not close_values(
                            observed.get("draft_acceptance_rate"),
                            expected_principal_rate,
                        ),
                    )
                ):
                    errors.append(
                        f"{phase}: {principal} speculative summary is "
                        "inconsistent"
                    )
    started_ns = artifact.get("started_ns")
    finished_ns = artifact.get("finished_ns")
    if (
        isinstance(started_ns, bool)
        or not isinstance(started_ns, int)
        or isinstance(finished_ns, bool)
        or not isinstance(finished_ns, int)
        or finished_ns <= started_ns
    ):
        errors.append(f"{phase}: artifact timestamps are invalid")
    elif any(
        started < started_ns or finished > finished_ns
        for started, finished in request_times
    ):
        errors.append(f"{phase}: request timestamps escape artifact bounds")
    return errors


def validate_compile_warmup(
    artifact: dict[str, Any], *, run_id: str
) -> list[str]:
    errors: list[str] = []
    config = artifact.get("config")
    summary = artifact.get("summary")
    if not isinstance(config, dict) or not isinstance(summary, dict):
        return ["compile_warmup: config or summary is not an object"]
    counts = summary.get("expected_principal_counts")
    if (
        not isinstance(counts, dict)
        or set(counts) != set(PRINCIPALS)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in counts.values()
        )
    ):
        return ["compile_warmup: both principal counts must be positive"]
    manifest = config.get("manifest_sha256")
    if not is_sha256(manifest):
        errors.append("compile_warmup: manifest digest is invalid")
    errors.extend(
        validate_probe(
            artifact,
            run_id=run_id,
            phase="compile_warmup",
            manifest_sha256=str(manifest),
            expected_counts=counts,
            spoof_identity_headers=True,
        )
    )
    if config.get("spoof_identity_headers") is not True:
        errors.append("compile_warmup: request-ID spoof control is not enabled")
    return errors


def validate_baseline_evaluation(
    artifact: dict[str, Any], *, run_id: str
) -> list[str]:
    config = artifact.get("config")
    summary = artifact.get("summary")
    if not isinstance(config, dict) or not isinstance(summary, dict):
        return ["baseline_evaluation: config or summary is not an object"]
    counts = summary.get("expected_principal_counts")
    manifest = config.get("manifest_sha256")
    if (
        not isinstance(counts, dict)
        or set(counts) != set(PRINCIPALS)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in counts.values()
        )
        or not is_sha256(manifest)
    ):
        return ["baseline_evaluation: declaration is invalid"]
    errors = validate_probe(
        artifact,
        run_id=run_id,
        phase="baseline_evaluation",
        manifest_sha256=str(manifest),
        expected_counts=counts,
    )
    if config.get("spoof_identity_headers") is not False:
        errors.append("baseline_evaluation: identity spoofing is enabled")
    return errors


def validate_gateway_evidence(
    run_dir: Path,
    artifacts: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    observed: dict[str, Any] = {}
    try:
        auth = load_object(run_dir / "auth_self_test.json")
        rows = auth.get("results")
        auth_by_name: dict[str, dict[str, Any]] = {}
        expected_status = {
            "attacker_ok": 200,
            "victim_ok": 200,
            "missing_key": 401,
            "wrong_key": 401,
            "attacker_claims_victim": 403,
            "victim_claims_attacker": 403,
        }
        if (
            auth.get("schema_version") != 1
            or auth.get("valid") is not True
            or not isinstance(rows, list)
        ):
            errors.append("gateway authentication self-test did not pass")
        else:
            auth_by_name = {
                row.get("name"): row for row in rows if isinstance(row, dict)
            }
            if (
                len(rows) != len(expected_status)
                or len(auth_by_name) != len(expected_status)
                or set(auth_by_name) != set(expected_status)
            ):
                errors.append("gateway authentication cases are incomplete")
            for name, status in expected_status.items():
                row = auth_by_name.get(name, {})
                if (
                    row.get("status") != status
                    or row.get("expected_status") != status
                ):
                    errors.append(f"gateway authentication case {name} failed")

        topology = load_object(run_dir / "tenant_topology.json")
        declared_principals = load_declared_principals(run_dir.parent)
        gateway_id = topology.get("gateway_instance_id")
        upstream_marker = topology.get("upstream_marker")
        if topology.get("key_fingerprints") != declared_principals:
            errors.append(
                "gateway topology key fingerprints differ from declaration"
            )
        if topology.get("protocol_version") != metadata.get("protocol_version"):
            errors.append("gateway topology protocol version is inconsistent")
        if topology.get("run_id") != metadata.get("run_id"):
            errors.append("gateway topology run identity is inconsistent")
        if topology.get("process_uuid") != metadata.get("process_uuid"):
            errors.append("gateway topology process identity is inconsistent")
        if not isinstance(gateway_id, str) or not gateway_id:
            errors.append("gateway topology has no instance identity")
        if not isinstance(upstream_marker, str) or not upstream_marker:
            errors.append("gateway topology has no worker marker")
        elif upstream_marker != metadata.get("process_uuid"):
            errors.append("gateway topology marker does not bind the process")

        audit_rows = read_json_lines(run_dir / "gateway_audit.jsonl")
        event_ids = [row.get("event_id") for row in audit_rows]
        if any(not isinstance(value, str) for value in event_ids):
            errors.append("gateway audit contains a missing event identity")
        if len(event_ids) != len(set(event_ids)):
            errors.append("gateway audit contains duplicate event identities")
        audit_by_id = {
            row.get("event_id"): row
            for row in audit_rows
            if isinstance(row.get("event_id"), str)
        }
        auth_expectations = {
            "attacker_ok": ("attacker", "attacker", True),
            "victim_ok": ("victim", "victim", True),
            "missing_key": (None, "victim", False),
            "wrong_key": (None, "victim", False),
            "attacker_claims_victim": ("attacker", "victim", False),
            "victim_claims_attacker": ("victim", "attacker", False),
        }
        joined_auth_ids: set[str] = set()
        for name, status in expected_status.items():
            result = auth_by_name.get(name, {})
            audit_id = result.get("audit_event_id")
            event = audit_by_id.get(audit_id)
            tenant, claimed, forwarded = auth_expectations[name]
            if not isinstance(audit_id, str) or not isinstance(event, dict):
                errors.append(f"authentication case {name} has no audit event")
                continue
            if audit_id in joined_auth_ids:
                errors.append("authentication cases reuse an audit identity")
            joined_auth_ids.add(audit_id)
            expected_result_tenant = tenant if forwarded else None
            if any(
                (
                    event.get("schema_version") != 2,
                    event.get("run_id") != metadata.get("run_id"),
                    event.get("purpose") != "auth-self-test",
                    event.get("path") != "/v1/models",
                    event.get("status") != status,
                    event.get("forwarded") is not forwarded,
                    event.get("authenticated_tenant") != tenant,
                    event.get("claimed_principal") != claimed,
                    event.get("gateway_instance_id") != gateway_id,
                    event.get("upstream_marker") != upstream_marker,
                    result.get("authenticated_tenant")
                    != expected_result_tenant,
                    result.get("gateway_instance_id") != gateway_id,
                    result.get("upstream_marker") != upstream_marker,
                )
            ):
                errors.append(f"authentication case {name} audit join failed")
            if (
                tenant in PRINCIPALS
                and event.get("key_sha256")
                != declared_principals.get(str(tenant))
            ):
                errors.append(
                    f"authentication case {name} key fingerprint differs "
                    "from declaration"
                )
        upstream_ids: set[str] = set()
        worker_principals: dict[str, str] = {}
        worker_phases: dict[str, str] = {}
        joined_event_ids: set[str] = set()
        spoofed_ids = 0
        phase_counts: dict[str, int] = {}
        for phase in (
            "compile_warmup",
            "baseline_evaluation",
            "adaptation",
            "evaluation",
        ):
            artifact = artifacts.get(phase)
            records = artifact.get("records") if isinstance(artifact, dict) else None
            config = artifact.get("config") if isinstance(artifact, dict) else None
            if (
                not isinstance(config, dict)
                or config.get("gateway_instance_id") != gateway_id
                or config.get("upstream_marker") != upstream_marker
            ):
                errors.append(f"{phase} probe config is not gateway-bound")
            phase_rows = {
                row.get("event_id"): row
                for row in audit_rows
                if row.get("purpose") == phase
                and row.get("path") == "/v1/completions"
            }
            if not isinstance(records, list) or len(phase_rows) != len(records):
                errors.append(f"{phase} does not join one-to-one with audit")
                continue
            phase_counts[phase] = len(records)
            for record in records:
                if not isinstance(record, dict):
                    errors.append(f"{phase} contains a non-object record")
                    continue
                audit_id = record.get("audit_event_id")
                event = phase_rows.get(audit_id)
                if not isinstance(event, dict):
                    errors.append(f"{phase} record has no gateway audit event")
                    continue
                if audit_id in joined_event_ids:
                    errors.append("probe records reuse a gateway audit identity")
                elif isinstance(audit_id, str):
                    joined_event_ids.add(audit_id)
                principal = record.get("principal")
                external = record.get("external_request_id")
                upstream = event.get("upstream_request_id")
                expected_prefix = f"ctfr-auth-{principal}-"
                key_fingerprint_matches = (
                    principal in PRINCIPALS
                    and event.get("key_sha256")
                    == declared_principals.get(str(principal))
                )
                if not key_fingerprint_matches:
                    errors.append(
                        f"{phase} key fingerprint differs from declaration"
                    )
                if phase == "compile_warmup":
                    other = (
                        "victim" if principal == "attacker" else "attacker"
                    )
                    spoof_prefix = (
                        f"cmpl-ctfr-auth-{other}-client-spoof-"
                    )
                    if (
                        isinstance(external, str)
                        and external.startswith(spoof_prefix)
                    ):
                        spoofed_ids += 1
                    else:
                        errors.append(
                            "compile warmup did not use opposite-prefix spoof"
                        )
                if any(
                    (
                        principal not in PRINCIPALS,
                        event.get("purpose") != phase,
                        event.get("path") != "/v1/completions",
                        event.get("schema_version") != 2,
                        event.get("run_id") != metadata.get("run_id"),
                        event.get("request_id") != external,
                        event.get("authenticated_tenant") != principal,
                        event.get("claimed_principal") != principal,
                        event.get("gateway_instance_id") != gateway_id,
                        event.get("upstream_marker") != upstream_marker,
                        record.get("authenticated_tenant") != principal,
                        record.get("gateway_instance_id") != gateway_id,
                        record.get("upstream_marker") != upstream_marker,
                        event.get("forwarded") is not True,
                        event.get("status") != 200,
                        not isinstance(upstream, str),
                        not str(upstream).startswith(expected_prefix),
                        upstream == external,
                    )
                ):
                    errors.append(f"{phase} origin binding is inconsistent")
                if isinstance(upstream, str):
                    if upstream in upstream_ids:
                        errors.append(
                            "gateway reused an internal request identity"
                        )
                    upstream_ids.add(upstream)
                    worker_id = f"cmpl-{upstream}"
                    prior = worker_principals.get(worker_id)
                    if prior is not None and prior != principal:
                        errors.append(
                            "worker completion identity maps to two principals"
                        )
                    elif principal in PRINCIPALS:
                        worker_principals[worker_id] = principal
                        worker_phases[worker_id] = phase
        observed.update(
            {
                "gateway_instance_id": gateway_id,
                "phase_records": phase_counts,
                "spoofed_external_ids": spoofed_ids,
                "unique_internal_ids": len(upstream_ids),
                "expected_worker_completion_principals": dict(
                    sorted(worker_principals.items())
                ),
                "expected_worker_completion_phases": dict(
                    sorted(worker_phases.items())
                ),
            }
        )
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"gateway evidence: {type(exc).__name__}: {exc}")
    return {"valid": not errors, "errors": errors, "observed": observed}


def validate_binding_telemetry(
    path: Path,
    *,
    require_mixed_batch: bool,
    require_events: bool = False,
    expected_id_principals: dict[str, str] | None = None,
    expected_id_phases: dict[str, str] | None = None,
    require_verification_counters: bool = False,
) -> dict[str, Any]:
    errors: list[str] = []
    events: list[dict[str, Any]] = []
    valid_events = 0
    mixed = 0
    observed_ids: set[str] = set()
    observed_expected_ids: set[str] = set()
    verification_depth: int | None = None
    verification_counts: dict[str, dict[str, list[int]]] = {}
    exact_binding = expected_id_principals is not None
    expected = (
        expected_id_principals
        if isinstance(expected_id_principals, dict)
        else {}
    )
    if exact_binding and (
        not isinstance(expected_id_principals, dict)
        or not expected
        or any(
            not isinstance(request_id, str)
            or not request_id.startswith("cmpl-")
            or principal not in PRINCIPALS
            for request_id, principal in expected.items()
        )
    ):
        errors.append("expected worker completion binding is invalid")
    expected_phases = (
        expected_id_phases if isinstance(expected_id_phases, dict) else {}
    )
    phase_binding_valid = expected_id_phases is None or (
        isinstance(expected_id_phases, dict)
        and exact_binding
        and set(expected_phases) == set(expected)
        and all(phase in BINDING_PHASES for phase in expected_phases.values())
    )
    if not phase_binding_valid:
        errors.append("expected worker completion phases are invalid")
    if require_verification_counters and (
        expected_id_phases is None or not phase_binding_valid
    ):
        errors.append("verification counters require exact request phases")
    try:
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            match = BINDING_EVENT.search(line)
            if not match:
                continue
            try:
                event = json.loads(match.group(1))
            except json.JSONDecodeError as exc:
                errors.append(f"binding telemetry line {number}: {exc}")
                continue
            if not isinstance(event, dict):
                errors.append(f"binding telemetry line {number} is not an object")
                continue
            request_ids = event.get("request_ids")
            slots = event.get("persistent_slots")
            principals = event.get("principals")
            num_sampled = event.get("num_sampled")
            num_rejected = event.get("num_rejected")
            num_speculative_steps = event.get("num_speculative_steps")
            event_valid = True
            if (
                not isinstance(request_ids, list)
                or not isinstance(slots, list)
                or not isinstance(principals, list)
                or not request_ids
                or len(request_ids) != len(slots)
                or len(request_ids) != len(principals)
            ):
                errors.append(f"binding telemetry line {number} has invalid arrays")
                continue
            if (
                any(
                    isinstance(slot, bool)
                    or not isinstance(slot, int)
                    or slot < 0
                    for slot in slots
                )
                or len(slots) != len(set(slots))
            ):
                errors.append(f"binding telemetry line {number} has invalid slots")
                event_valid = False
            if require_verification_counters:
                if (
                    not isinstance(num_sampled, list)
                    or not isinstance(num_rejected, list)
                    or len(num_sampled) != len(request_ids)
                    or len(num_rejected) != len(request_ids)
                    or any(
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or value < 0
                        for value in (*num_sampled, *num_rejected)
                    )
                    or isinstance(num_speculative_steps, bool)
                    or not isinstance(num_speculative_steps, int)
                    or num_speculative_steps <= 0
                ):
                    errors.append(
                        f"binding telemetry line {number} has invalid "
                        "verification counters"
                    )
                    event_valid = False
                elif (
                    verification_depth is not None
                    and verification_depth != num_speculative_steps
                ):
                    errors.append(
                        f"binding telemetry line {number} changes the "
                        "speculative depth"
                    )
                    event_valid = False
            if len(request_ids) != len(set(request_ids)):
                errors.append(
                    f"binding telemetry line {number} repeats a request id"
                )
                event_valid = False
            labels: list[str] = []
            normalized_ids: list[str | None] = []
            for request_id, principal in zip(request_ids, principals):
                if (
                    isinstance(request_id, str)
                    and WARMUP_REQUEST_ID.fullmatch(request_id)
                    and type(principal) is int
                    and principal == -1
                ):
                    normalized_ids.append(None)
                    continue
                label = (
                    "attacker"
                    if type(principal) is int and principal == 0
                    else "victim"
                    if type(principal) is int and principal == 1
                    else None
                )
                if label is None or not isinstance(request_id, str):
                    errors.append(
                        f"binding telemetry line {number} has invalid identity"
                    )
                    event_valid = False
                    normalized_ids.append(None)
                    continue
                labels.append(label)
                if exact_binding:
                    match = WORKER_COMPLETION_ID.fullmatch(request_id)
                    normalized = match.group("base") if match else None
                    normalized_ids.append(normalized)
                    if normalized not in expected:
                        errors.append(
                            f"binding telemetry line {number} has an "
                            "unexpected request id"
                        )
                        event_valid = False
                    elif expected[normalized] != label:
                        errors.append(
                            f"binding telemetry line {number} has a "
                            "principal mismatch"
                        )
                        event_valid = False
                else:
                    normalized_ids.append(request_id)
                    if not request_id.startswith(
                        (
                            f"ctfr-auth-{label}-",
                            f"cmpl-ctfr-auth-{label}-",
                        )
                    ):
                        errors.append(
                            f"binding telemetry line {number} has a "
                            "prefix mismatch"
                        )
                        event_valid = False
            if event_valid:
                valid_events += 1
                observed_ids.update(request_ids)
                observed_expected_ids.update(
                    request_id
                    for request_id in normalized_ids
                    if request_id is not None
                )
                if set(labels) == set(PRINCIPALS):
                    mixed += 1
                if require_verification_counters and phase_binding_valid:
                    assert isinstance(num_sampled, list)
                    assert isinstance(num_rejected, list)
                    assert isinstance(num_speculative_steps, int)
                    if verification_depth is None:
                        verification_depth = num_speculative_steps
                        verification_counts = {
                            phase: {
                                principal: [0] * verification_depth
                                for principal in PRINCIPALS
                            }
                            for phase in sorted(set(expected_phases.values()))
                        }
                    for principal, sampled, rejected, normalized in zip(
                        principals,
                        num_sampled,
                        num_rejected,
                        normalized_ids,
                        strict=True,
                    ):
                        if normalized is None:
                            continue
                        label = PRINCIPALS[principal]
                        phase = expected_phases[normalized]
                        accepted = max(sampled - 1, 0)
                        admitted = accepted + rejected
                        for step in range(num_speculative_steps):
                            if step <= accepted and step < admitted:
                                verification_counts[phase][label][step] += 1
            events.append(event)
    except OSError as exc:
        errors.append(f"binding telemetry: {type(exc).__name__}: {exc}")
    if require_events and not events:
        errors.append("binding telemetry contains no events")
    if exact_binding:
        missing = sorted(set(expected) - observed_expected_ids)
        if missing:
            errors.append(
                f"binding telemetry is missing expected request ids: {missing}"
            )
    if require_mixed_batch and mixed == 0:
        errors.append("telemetry gate observed no mixed-principal GPU batch")
    return {
        "valid": not errors,
        "errors": errors,
        "event_count": len(events),
        "valid_event_count": valid_events,
        "mixed_principal_batch_count": mixed,
        "observed_request_ids": sorted(observed_ids),
        "observed_expected_worker_ids": sorted(observed_expected_ids),
        "verification_counts_by_phase": verification_counts,
        "num_speculative_steps": verification_depth,
        "events_required": require_events,
        "mixed_batch_required": require_mixed_batch,
        "verification_counters_required": require_verification_counters,
    }


def barrier_log_counts(path: Path) -> dict[str, int]:
    text = path.read_text(errors="replace")
    return {
        "ctfr_retire_calls": len(
            re.findall(r"AVEP_CTFR_RETIRE_CALL(?=\s|$)", text)
        ),
        "ctfr_retire": len(
            re.findall(r"AVEP_CTFR_RETIRE(?=\s|$)", text)
        ),
        "tenant_local_refit_calls": len(
            re.findall(r"AVEP_TENANT_LOCAL_REFIT_CALL(?=\s|$)", text)
        ),
        "tenant_local_refit": len(
            re.findall(r"AVEP_TENANT_LOCAL_REFIT(?=\s|$)", text)
        ),
    }


def parse_resource_samples(path: Path) -> dict[str, Any]:
    rows = read_json_lines(path)
    if len(rows) < 2:
        raise ValueError("resource sampler produced fewer than two rows")
    gpu_memory: list[float] = []
    host_rss: list[float] = []
    server_cpu: list[float] = []
    gateway_cpu: list[float] = []
    timestamps: list[datetime] = []
    for row in rows:
        timestamp = parse_time(row.get("sampled_at"))
        server = row.get("server")
        gateway = row.get("gateway")
        gpu = row.get("gpu")
        cpu_measurement = row.get("cpu_measurement")
        if (
            timestamp is None
            or not isinstance(server, dict)
            or not isinstance(gateway, dict)
            or not isinstance(gpu, dict)
            or not isinstance(cpu_measurement, dict)
        ):
            raise ValueError("resource sample has an invalid shape")
        window_ns = nonnegative_integer(cpu_measurement.get("window_ns"))
        clock_ticks = nonnegative_integer(
            cpu_measurement.get("clock_ticks_per_second")
        )
        if (
            cpu_measurement.get("source") != "proc-stat-interval-delta"
            or window_ns in (None, 0)
            or clock_ticks in (None, 0)
        ):
            raise ValueError("resource sample CPU window is invalid")
        server_rss = finite(server.get("rss_kib"))
        gateway_rss = finite(gateway.get("rss_kib"))
        server_cpu_value = finite(server.get("cpu_percent"))
        gateway_cpu_value = finite(gateway.get("cpu_percent"))
        gpu_memory_value = finite(gpu.get("memory_mib"))
        server_processes = server.get("processes")
        gateway_processes = gateway.get("processes")
        server_ticks = nonnegative_integer(server.get("cpu_ticks_delta"))
        gateway_ticks = nonnegative_integer(gateway.get("cpu_ticks_delta"))
        if (
            isinstance(server_processes, bool)
            or not isinstance(server_processes, int)
            or server_processes < 1
            or isinstance(gateway_processes, bool)
            or not isinstance(gateway_processes, int)
            or gateway_processes < 1
            or server_ticks is None
            or gateway_ticks is None
        ):
            raise ValueError("resource sample did not observe both process groups")
        values = (
            server_rss,
            gateway_rss,
            server_cpu_value,
            gateway_cpu_value,
            gpu_memory_value,
        )
        if any(value is None or value < 0 for value in values):
            raise ValueError("resource sample contains an invalid measurement")
        expected_server_cpu = (
            100.0 * server_ticks * 1_000_000_000 / clock_ticks / window_ns
        )
        expected_gateway_cpu = (
            100.0 * gateway_ticks * 1_000_000_000 / clock_ticks / window_ns
        )
        if not math.isclose(
            float(server_cpu_value),
            expected_server_cpu,
            rel_tol=1.0e-6,
            abs_tol=1.0e-4,
        ) or not math.isclose(
            float(gateway_cpu_value),
            expected_gateway_cpu,
            rel_tol=1.0e-6,
            abs_tol=1.0e-4,
        ):
            raise ValueError("resource sample CPU percentage is inconsistent")
        timestamps.append(timestamp)
        host_rss.append(float(server_rss) + float(gateway_rss))
        server_cpu.append(float(server_cpu_value))
        gateway_cpu.append(float(gateway_cpu_value))
        gpu_memory.append(float(gpu_memory_value))
    if timestamps != sorted(timestamps):
        raise ValueError("resource sample timestamps are not ordered")
    return {
        "samples": len(rows),
        "sampled_at_ns": [
            int(timestamp.timestamp() * 1_000_000_000)
            for timestamp in timestamps
        ],
        "gpu_peak_bytes": max(gpu_memory) * 1024 * 1024,
        "host_peak_bytes": max(host_rss) * 1024,
        "server_cpu_percent_mean": statistics.fmean(server_cpu),
        "server_cpu_percent_peak": max(server_cpu),
        "gateway_cpu_percent_mean": statistics.fmean(gateway_cpu),
        "gateway_cpu_percent_peak": max(gateway_cpu),
        "attribution": (
            "coarse whole-process samples; no isolated shadow-manager CPU or "
            "memory attribution"
        ),
    }


def validate_drain_evidence(
    path: Path, *, barrier_called_after_ns: int
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        rows = read_json_lines(path)
        adaptation = [row for row in rows if row.get("label") == "adaptation"]
        if len(adaptation) < 2:
            errors.append("fewer than two adaptation drain samples exist")
        else:
            final = adaptation[-2:]
            timestamps: list[int] = []
            for row in final:
                sampled_at = parse_time(row.get("sampled_at"))
                if sampled_at is None:
                    errors.append("adaptation drain timestamp is invalid")
                    continue
                timestamps.append(int(sampled_at.timestamp() * 1_000_000_000))
                if row.get("running") != 0 or row.get("waiting") != 0:
                    errors.append("final adaptation drain samples are not zero")
                for field in ("running_series", "waiting_series"):
                    count = row.get(field)
                    if (
                        isinstance(count, bool)
                        or not isinstance(count, int)
                        or count < 1
                    ):
                        errors.append(
                            f"final adaptation drain sample has invalid {field}"
                        )
            if timestamps != sorted(timestamps):
                errors.append("adaptation drain samples are not ordered")
            if any(value >= barrier_called_after_ns for value in timestamps):
                errors.append("barrier began before the two zero drain samples")
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"drain evidence: {type(exc).__name__}: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "required_consecutive_zero_samples": 2,
    }


def normalize_eval_metrics(
    metrics: Any,
    *,
    label: str,
    expected_enabled: bool,
    require_positive: bool,
) -> dict[str, dict[str, Any]]:
    if (
        not isinstance(metrics, dict)
        or metrics.get("enabled") is not expected_enabled
    ):
        raise ValueError(f"{label}: enabled flag is inconsistent")
    rows = metrics.get("principals")
    if not isinstance(rows, list) or len(rows) != 2:
        raise ValueError(f"{label}: expected two principal rows")
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError(f"{label}: a principal row is not an object")
    result: dict[str, dict[str, Any]] = {}
    for principal, principal_id in PRINCIPAL_IDS.items():
        matching = [row for row in rows if row.get("principal") == principal_id]
        if len(matching) != 1:
            raise ValueError(f"{label}: row for {principal} is ambiguous")
        row = matching[0]
        count = finite(row.get("count"))
        log_loss = finite(row.get("mean_log_loss"))
        brier = finite(row.get("mean_brier"))
        positions = row.get("counts_by_position")
        if (
            count is None
            or count < 0
            or not isinstance(positions, list)
            or not positions
            or not finite_tree(positions)
            or any(float(value) < 0 for value in positions)
            or not close_values(sum(float(value) for value in positions), count)
        ):
            raise ValueError(f"{label}: counters for {principal} are invalid")
        if count == 0:
            if require_positive or log_loss is not None or brier is not None:
                raise ValueError(
                    f"{label}: zero row for {principal} is invalid"
                )
        elif (
            log_loss is None
            or log_loss < 0
            or brier is None
            or not 0 <= brier <= 1
        ):
            raise ValueError(f"{label}: values for {principal} are invalid")
        result[principal] = {
            "count": count,
            "log_loss": log_loss,
            "brier": brier,
            "counts_by_position": [float(value) for value in positions],
        }
    return result


def parse_eval_metrics(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    worker = unwrap_worker(payload, "eval_metrics")
    return normalize_eval_metrics(
        worker.get("eval_metrics"),
        label="eval_metrics",
        expected_enabled=True,
        require_positive=True,
    )


def derive_eval_counts_by_position(
    artifact: dict[str, Any], *, label: str
) -> dict[str, list[float]]:
    records = artifact.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError(f"{label}: records are absent")
    depth: int | None = None
    result: dict[str, list[float]] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("ok") is not True:
            raise ValueError(f"{label}: a record is invalid")
        principal = record.get("authenticated_tenant")
        if principal not in PRINCIPALS:
            raise ValueError(f"{label}: authenticated principal is invalid")
        metrics = record.get("metrics")
        speculative = (
            metrics.get("speculative_decoding")
            if isinstance(metrics, dict)
            else None
        )
        metric_errors, parsed = validate_detailed_speculative_metric(
            speculative
        )
        if metric_errors or parsed is None:
            raise ValueError(f"{label}: {metric_errors}")
        if depth is None:
            depth = parsed["spec_tokens"]
            result = {
                name: [0.0] * depth
                for name in PRINCIPALS
            }
        elif parsed["spec_tokens"] != depth:
            raise ValueError(f"{label}: num_spec_tokens varies by request")
        for drafted, accepted in zip(
            parsed["per_step_drafted"],
            parsed["per_step_accepted"],
            strict=True,
        ):
            for position in range(min(drafted, accepted + 1)):
                result[principal][position] += 1.0
    return result


def compare_eval_counts(
    observed: dict[str, list[float]],
    reported: dict[str, dict[str, Any]],
    *,
    label: str,
) -> list[str]:
    errors: list[str] = []
    for principal in PRINCIPALS:
        positions = observed.get(principal)
        row = reported.get(principal)
        if (
            not isinstance(positions, list)
            or not isinstance(row, dict)
            or row.get("counts_by_position") != positions
            or row.get("count") != sum(positions)
        ):
            errors.append(
                f"{label}: {principal} counters do not match request evidence"
            )
    return errors


def parse_eval_reset(
    payload: dict[str, Any], *, label: str, expected_enabled: bool
) -> dict[str, dict[str, dict[str, Any]]]:
    worker = unwrap_worker(payload, label)
    reset = worker.get("eval_metrics")
    if not isinstance(reset, dict) or set(reset) != {"before", "after"}:
        raise ValueError(f"{label}: reset result is malformed")
    before = normalize_eval_metrics(
        reset.get("before"),
        label=f"{label}.before",
        expected_enabled=expected_enabled,
        require_positive=False,
    )
    after = normalize_eval_metrics(
        reset.get("after"),
        label=f"{label}.after",
        expected_enabled=expected_enabled,
        require_positive=False,
    )
    for principal, row in after.items():
        if row["count"] != 0 or any(row["counts_by_position"]):
            raise ValueError(f"{label}.after: {principal} counters are nonzero")
    return {"before": before, "after": after}


def probe_outcomes(
    evaluation: dict[str, Any],
    calibration: dict[str, dict[str, Any]],
) -> dict[str, float]:
    summary = evaluation["summary"]
    by_principal = summary["by_principal"]
    result: dict[str, float] = {}
    metric_map = {
        "throughput": "aggregate_output_tokens_per_second",
        "latency_p50": "latency_ms_p50",
        "latency_p95": "latency_ms_p95",
    }
    for name, key in metric_map.items():
        value = finite(summary.get(key))
        if value is None or value <= 0:
            raise ValueError(f"evaluation summary {key} is invalid")
        result[f"system_{name}"] = value
        for principal in PRINCIPALS:
            principal_value = finite(by_principal[principal].get(key))
            if principal_value is None or principal_value <= 0:
                raise ValueError(f"{principal} evaluation {key} is invalid")
            result[f"{principal}_{name}"] = principal_value
    for metric in ("log_loss", "brier"):
        values = [calibration[principal][metric] for principal in PRINCIPALS]
        result[f"balanced_{metric}"] = statistics.fmean(values)
        for principal in PRINCIPALS:
            result[f"{principal}_{metric}"] = calibration[principal][metric]
    total_count = sum(calibration[principal]["count"] for principal in PRINCIPALS)
    for metric in ("log_loss", "brier"):
        result[f"weighted_{metric}"] = sum(
            calibration[principal][metric] * calibration[principal]["count"]
            for principal in PRINCIPALS
        ) / total_count
    return result


def baseline_normalized_outcomes(
    baseline: dict[str, float], evaluation: dict[str, float]
) -> dict[str, float]:
    if baseline.keys() != evaluation.keys():
        raise ValueError("baseline and evaluation outcome fields differ")
    result: dict[str, float] = {}
    for key in baseline:
        first = baseline[key]
        second = evaluation[key]
        result[f"baseline_raw_{key}"] = first
        result[f"evaluation_raw_{key}"] = second
        if key.endswith("throughput"):
            if first <= 0:
                raise ValueError(f"baseline {key} denominator is non-positive")
            result[key] = second / first
        else:
            result[key] = second - first
    return result


def adaptation_performance(artifact: dict[str, Any]) -> dict[str, float]:
    summary = artifact.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("adaptation summary is absent")
    result: dict[str, float] = {}
    for name, key in (
        ("system_throughput", "aggregate_output_tokens_per_second"),
        ("system_latency_p50", "latency_ms_p50"),
        ("system_latency_p95", "latency_ms_p95"),
    ):
        value = finite(summary.get(key))
        if value is None or value <= 0:
            raise ValueError(f"adaptation performance {key} is invalid")
        result[name] = value
    return result


def validate_barrier_order(
    metadata: dict[str, Any],
    adaptation: dict[str, Any],
    evaluation: dict[str, Any],
) -> list[str]:
    evidence = metadata["barrier_evidence"]
    errors: list[str] = []
    admitted = evidence["admitted_requests"]
    if admitted != adaptation["summary"]["successful"]:
        errors.append("barrier admitted count does not match adaptation probe")
    ordered = (
        adaptation["finished_ns"],
        evidence["called_after_ns"],
        evidence["completed_ns"],
        evaluation["started_ns"],
    )
    if list(ordered) != sorted(ordered):
        errors.append("adaptation, barrier, and evaluation are not ordered")
    return errors


def validate_phase_chain(
    metadata: dict[str, Any],
    compile_warmup: dict[str, Any],
    baseline_evaluation: dict[str, Any],
    adaptation: dict[str, Any],
    evaluation: dict[str, Any],
) -> list[str]:
    evidence = metadata.get("barrier_evidence")
    if not isinstance(evidence, dict):
        return ["phase chain has no barrier evidence"]
    ordered = (
        compile_warmup.get("started_ns"),
        compile_warmup.get("finished_ns"),
        baseline_evaluation.get("started_ns"),
        baseline_evaluation.get("finished_ns"),
        adaptation.get("started_ns"),
        adaptation.get("finished_ns"),
        evidence.get("called_after_ns"),
        evidence.get("completed_ns"),
        evaluation.get("started_ns"),
        evaluation.get("finished_ns"),
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in ordered
    ):
        return ["phase chain contains an invalid timestamp"]
    if list(ordered) != sorted(ordered):
        return [
            "compile, baseline, adaptation, barrier, and evaluation are not "
            "ordered"
        ]
    return []


def validate_run_order_by_block(
    indexed: dict[str, dict[str, dict[str, Any]]],
    declared: dict[str, list[str]] | None,
    *,
    label: str,
) -> list[str]:
    if declared is None:
        return []
    errors: list[str] = []
    for block in STAGE_D_BLOCKS:
        expected = declared.get(block)
        arms = indexed.get(block, {})
        if not isinstance(expected, list) or set(arms) != set(expected):
            errors.append(f"{label} block {block} cannot verify declared order")
            continue
        starts: list[tuple[int, str]] = []
        for arm, run in arms.items():
            started = run.get("adaptation", {}).get("started_ns")
            if (
                isinstance(started, bool)
                or not isinstance(started, int)
                or started <= 0
            ):
                errors.append(
                    f"{label} block {block} {arm} has no trustworthy start"
                )
                break
            starts.append((started, arm))
        else:
            if len({started for started, _ in starts}) != len(starts):
                errors.append(f"{label} block {block} has tied start times")
            actual = [arm for _, arm in sorted(starts)]
            if actual != expected:
                errors.append(
                    f"{label} block {block} order {actual} differs from "
                    f"declaration {expected}"
                )
    return errors


def validate_unique_gateway_instances(
    runs: list[dict[str, Any]], *, label: str
) -> list[str]:
    identifiers = [
        run.get("gateway_evidence", {})
        .get("observed", {})
        .get("gateway_instance_id")
        for run in runs
    ]
    if any(not isinstance(value, str) or not value for value in identifiers):
        return [f"{label} has a missing gateway instance identity"]
    if len(identifiers) != len(set(identifiers)):
        return [f"{label} reuses a gateway instance identity"]
    return []


def validate_no_action_barrier(barrier: dict[str, Any]) -> list[str]:
    if barrier != {"called": False, "method": None, "response": None}:
        return ["contextual arm does not have the exact no-barrier marker"]
    return []


def retirement_payload(barrier: dict[str, Any]) -> dict[str, Any]:
    if barrier.get("called") is not True:
        raise ValueError("retirement RPC was not called")
    if barrier.get("method") != "avep_retire_ctfr":
        raise ValueError("barrier called the wrong retirement method")
    response = barrier.get("response")
    if not isinstance(response, dict):
        raise ValueError("retirement response is absent")
    worker = unwrap_worker(response, "retirement")
    retirement = worker.get("retirement")
    if not isinstance(retirement, dict):
        raise ValueError("retirement result is absent")
    return retirement


def tenant_refit_payload(barrier: dict[str, Any]) -> dict[str, Any]:
    if barrier.get("called") is not True:
        raise ValueError("tenant-local refit RPC was not called")
    if barrier.get("method") != "avep_refit_tenant_local":
        raise ValueError("barrier called the wrong tenant-local method")
    response = barrier.get("response")
    if not isinstance(response, dict):
        raise ValueError("tenant-local refit response is absent")
    worker = unwrap_worker(response, "tenant-local refit")
    refit = worker.get("tenant_local_refit")
    if not isinstance(refit, dict):
        raise ValueError("tenant-local refit result is absent")
    return refit


def validate_successful_retirement(
    before: dict[str, Any],
    accumulated: dict[str, Any],
    after: dict[str, Any],
    retirement: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if retirement.get("retired") is not True:
        return ["the declared benign retirement did not retire"]
    if committed_projection(before) != committed_projection(accumulated):
        errors.append("committed state changed before retirement")
    before_version = before["committed_version"]
    if (
        retirement.get("version_before") != before_version
        or retirement.get("version_after") != before_version + 1
        or after["committed_version"] != before_version + 1
    ):
        errors.append("retirement version transition is invalid")
    base = coefficients(accumulated, 0)
    proposed = retirement.get("proposed_coefficients")
    aggregate = retirement.get("aggregate_delta")
    if (
        not isinstance(proposed, list)
        or not finite_tree(proposed)
        or not isinstance(aggregate, list)
        or not finite_tree(aggregate)
        or len(proposed) != len(base)
        or len(aggregate) != len(base)
    ):
        errors.append("retirement coefficient evidence is invalid")
    else:
        expected = [left + delta for left, delta in zip(base, aggregate)]
        if not close_values(retirement.get("base_coefficients"), base):
            errors.append("retirement base coefficients do not match snapshot")
        if not close_values(proposed, expected):
            errors.append("proposed coefficients do not equal base plus delta")
        if not close_values(coefficients(after, 0), proposed):
            errors.append("published coefficients do not match the proposal")
    counts = retirement.get("observation_counts")
    observed_counts = [
        observation_count(accumulated, domain) for domain in (2, 3)
    ]
    if not close_values(counts, observed_counts):
        errors.append("retirement observation counts do not match shadows")
    hyperparameters = accumulated["retirement_hyperparameters"]
    clipped = retirement.get("clipped_delta_norms")
    credits_before = accumulated["ctfr_influence_credits"]
    credits_after = after["ctfr_influence_credits"]
    if not isinstance(clipped, list) or len(clipped) != 2 or not finite_tree(clipped):
        errors.append("clipped influence norms are invalid")
    else:
        credit_debits = clipped
        if "retirement_scale_steps" in hyperparameters:
            reported_debits = retirement.get("credit_debits")
            if (
                not isinstance(reported_debits, list)
                or len(reported_debits) != 2
                or not finite_tree(reported_debits)
            ):
                errors.append("fractional influence debits are invalid")
                credit_debits = []
            else:
                credit_debits = reported_debits
        expected_credits = [
            float(credit) - float(debit)
            for credit, debit in zip(credits_before, credit_debits)
        ]
        if credit_debits and not close_values(credits_after, expected_credits):
            errors.append("influence credits were not debited exactly once")
        if not close_values(
            retirement.get("remaining_influence_credits"), credits_after
        ):
            errors.append("reported remaining influence credits are inconsistent")
    cosine = finite(retirement.get("cosine"))
    aggregate_norm = finite(retirement.get("aggregate_norm"))
    probability_shift = finite(retirement.get("max_probability_shift"))
    if cosine is None or cosine < float(hyperparameters["min_cosine"]):
        errors.append("retired candidates do not meet directional agreement")
    if (
        aggregate_norm is None
        or aggregate_norm > float(hyperparameters["max_commit_norm"])
    ):
        errors.append("retired candidate violates the parameter trust region")
    if (
        probability_shift is None
        or probability_shift
        > float(hyperparameters["max_probability_shift"])
    ):
        errors.append("retired candidate violates the decision trust region")
    scale_steps = hyperparameters.get("retirement_scale_steps")
    if scale_steps is not None:
        errors.extend(
            validate_fractional_retirement_evidence(
                base,
                clipped if isinstance(clipped, list) else [],
                hyperparameters,
                retirement,
            )
        )
    if not all(statistics_cleared(after, domain) for domain in (2, 3)):
        errors.append("retirement did not clear both shadow statistics")
    for domain in (0, 2, 3):
        if after["refits"][domain] != accumulated["refits"][domain] + 1:
            errors.append(f"retirement refit counter for bank {domain} is invalid")
    return errors


def _vector_norm(values: list[float]) -> float:
    return math.sqrt(math.fsum(float(value) ** 2 for value in values))


def _sigmoid(value: float) -> float:
    if value >= 0.0:
        return 1.0 / (1.0 + math.exp(-value))
    exp_value = math.exp(value)
    return exp_value / (1.0 + exp_value)


def _retirement_probability_shift(
    base: list[float],
    delta: list[float],
) -> float:
    maximum = 0.0
    for index in range(161):
        feature = -40.0 + 80.0 * index / 160
        old_slope = base[0] * feature
        new_slope = (base[0] + delta[0]) * feature
        for position in range(1, len(base)):
            old_probability = _sigmoid(old_slope + base[position])
            new_probability = _sigmoid(
                new_slope + base[position] + delta[position]
            )
            maximum = max(
                maximum,
                abs(new_probability - old_probability),
            )
    return maximum


def validate_fractional_retirement_evidence(
    base: list[float],
    clipped_norms: list[float],
    hyperparameters: dict[str, Any],
    retirement: dict[str, Any],
) -> list[str]:
    """Independently validate v3 projection, grid, and debit evidence."""
    errors: list[str] = []
    steps = hyperparameters.get("retirement_scale_steps")
    if isinstance(steps, bool) or not isinstance(steps, int) or steps <= 0:
        return ["fractional retirement scale grid is invalid"]
    if retirement.get("retirement_scale_steps") != steps:
        errors.append("reported retirement scale grid is inconsistent")

    candidate = retirement.get("candidate_aggregate_delta")
    projected = retirement.get("parameter_projected_delta")
    aggregate = retirement.get("aggregate_delta")
    vectors = (candidate, projected, aggregate)
    if any(
        not isinstance(value, list)
        or len(value) != len(base)
        or not finite_tree(value)
        for value in vectors
    ):
        return errors + ["fractional retirement vectors are invalid"]

    candidate_norm = _vector_norm(candidate)
    projected_norm = _vector_norm(projected)
    aggregate_norm = _vector_norm(aggregate)
    maximum_norm = float(hyperparameters["max_commit_norm"])
    parameter_scale = finite(retirement.get("parameter_projection_scale"))
    decision_scale = finite(retirement.get("decision_scale"))
    retirement_scale = finite(retirement.get("retirement_scale"))
    if candidate_norm == 0.0 or parameter_scale is None:
        errors.append("fractional parameter projection is invalid")
    else:
        expected_parameter_scale = min(1.0, maximum_norm / candidate_norm)
        if not close_values(parameter_scale, expected_parameter_scale):
            errors.append(
                "parameter projection did not use the declared norm bound"
            )
    if not close_values(
        retirement.get("candidate_aggregate_norm"), candidate_norm
    ):
        errors.append("candidate aggregate norm is inconsistent")
    if not close_values(
        retirement.get("parameter_projected_norm"), projected_norm
    ):
        errors.append("parameter-projected norm is inconsistent")
    if not close_values(retirement.get("aggregate_norm"), aggregate_norm):
        errors.append("committed aggregate norm is inconsistent")
    if parameter_scale is not None and not close_values(
        projected,
        [value * parameter_scale for value in candidate],
    ):
        errors.append("parameter-projected delta is inconsistent")

    if (
        decision_scale is None
        or not 0.0 < decision_scale <= 1.0
        or not close_values(decision_scale * steps, round(decision_scale * steps))
    ):
        errors.append("decision scale is not on the declared positive grid")
    elif not close_values(
        aggregate,
        [value * decision_scale for value in projected],
    ):
        errors.append("committed delta does not match the decision scale")
    if (
        parameter_scale is None
        or decision_scale is None
        or retirement_scale is None
        or not close_values(
            retirement_scale,
            parameter_scale * decision_scale,
        )
    ):
        errors.append("total retirement scale is inconsistent")

    evaluations = retirement.get("evaluated_scales")
    if not isinstance(evaluations, list) or not evaluations:
        errors.append("fractional grid evaluation evidence is absent")
    elif decision_scale is not None:
        selected_numerator = round(decision_scale * steps)
        expected_scales = [
            numerator / steps
            for numerator in range(steps, selected_numerator - 1, -1)
        ]
        observed_scales: list[float] = []
        observed_shifts: list[float] = []
        for evaluation in evaluations:
            if not isinstance(evaluation, dict):
                continue
            scale = finite(evaluation.get("scale"))
            shift = finite(evaluation.get("max_probability_shift"))
            if scale is not None and shift is not None:
                observed_scales.append(scale)
                observed_shifts.append(shift)
        if not close_values(observed_scales, expected_scales):
            errors.append("fractional grid was not evaluated in declared order")
        maximum_shift = float(hyperparameters["max_probability_shift"])
        if (
            not observed_shifts
            or any(shift <= maximum_shift for shift in observed_shifts[:-1])
            or observed_shifts[-1] > maximum_shift
        ):
            errors.append("selected scale is not the largest admissible grid point")
        elif not close_values(
            retirement.get("max_probability_shift"), observed_shifts[-1]
        ):
            errors.append("selected decision shift is inconsistent")

    recomputed_shift = _retirement_probability_shift(base, aggregate)
    if not close_values(
        retirement.get("max_probability_shift"),
        recomputed_shift,
        tolerance=2.0e-6,
    ):
        errors.append("decision shift does not match the committed coefficients")
    if retirement_scale is not None and len(clipped_norms) == 2:
        expected_debits = [
            float(value) * retirement_scale for value in clipped_norms
        ]
        if not close_values(retirement.get("credit_debits"), expected_debits):
            errors.append("fractional credit debits are inconsistent")
    return errors


def validate_tenant_refit(
    before: dict[str, Any],
    accumulated: dict[str, Any],
    after: dict[str, Any],
    refit: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if refit.get("refit") is not True:
        return ["tenant-local barrier did not refit both banks"]
    if committed_projection(before) != committed_projection(after):
        errors.append("tenant-local refit changed canonical committed state")
    observed_counts = [
        observation_count(accumulated, domain) for domain in (2, 3)
    ]
    if not close_values(refit.get("observation_counts"), observed_counts):
        errors.append("tenant-local observation counts do not match snapshots")
    versions_before = accumulated["tenant_local_versions"]
    versions_after = [value + 1 for value in versions_before]
    if (
        refit.get("versions_before") != versions_before
        or refit.get("versions_after") != versions_after
        or after["tenant_local_versions"] != versions_after
    ):
        errors.append("tenant-local version transition is invalid")
    parameters = refit.get("parameters_after")
    if (
        not isinstance(parameters, list)
        or len(parameters) != 2
        or not finite_tree(parameters)
    ):
        errors.append("tenant-local fitted parameters are invalid")
    else:
        for offset, domain in enumerate((2, 3)):
            if not close_values(parameters[offset], coefficients(after, domain)):
                errors.append(
                    f"tenant-local published bank {domain} mismatches response"
                )
    if not all(statistics_cleared(after, domain) for domain in (2, 3)):
        errors.append("tenant-local refit did not clear both statistics banks")
    return errors


def validate_stage_d_transition(run: dict[str, Any]) -> list[str]:
    arm = run["arm"]
    before = run["states"]["before"]
    accumulated = run["states"]["accumulated"]
    after = run["states"]["after_barrier"]
    post = run["states"]["post_evaluation"]
    barrier = run["barrier"]
    barrier_counts = run.get("barrier_log_counts", {})
    errors: list[str] = []
    if any(
        run["metadata"]["observation_budget_by_principal"][principal] <= 0
        for principal in PRINCIPALS
    ):
        errors.append("Stage D requires observations from both principals")
    if post.get("updates_enabled") is not False:
        errors.append("held-out evaluation did not disable estimator updates")
    if policy_projection(after) != policy_projection(post):
        errors.append("held-out evaluation changed policy state")

    if arm in {"ctfr-shadow", "ctfr-full"}:
        if committed_projection(before) != committed_projection(accumulated):
            errors.append("unretired shadows changed committed state")
        for domain in (2, 3):
            if not feedback_changed(before, accumulated, domain):
                errors.append(f"shadow bank {domain} did not receive feedback")
    elif arm == "tenant-local":
        if committed_projection(before) != committed_projection(accumulated):
            errors.append("tenant-local accumulation changed canonical state")
        for domain in (2, 3):
            if not feedback_changed(before, accumulated, domain):
                errors.append(f"tenant bank {domain} did not receive feedback")

    if arm == "ctfr-full":
        if barrier_counts.get("ctfr_retire_calls") != 1:
            errors.append("CTFR-full run has other than one server-side call")
        if barrier_counts.get("ctfr_retire") != 1:
            errors.append("CTFR-full run has other than one retirement event")
        try:
            retirement = retirement_payload(barrier)
            errors.extend(
                validate_successful_retirement(
                    before, accumulated, after, retirement
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"retirement: {type(exc).__name__}: {exc}")
    elif arm == "tenant-local":
        if barrier_counts.get("tenant_local_refit_calls") != 1:
            errors.append("tenant-local run has other than one server-side call")
        if barrier_counts.get("tenant_local_refit") != 1:
            errors.append("tenant-local run has other than one refit event")
        try:
            refit = tenant_refit_payload(barrier)
            errors.extend(validate_tenant_refit(before, accumulated, after, refit))
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"tenant refit: {type(exc).__name__}: {exc}")
    else:
        if any(barrier_counts.values()):
            errors.append("contextual arm contains an unexpected barrier event")
        errors.extend(validate_no_action_barrier(barrier))
        if policy_projection(
            accumulated, include_update_gate=False
        ) != policy_projection(after, include_update_gate=False):
            errors.append("no-action barrier changed policy state")
    if arm == "frozen" and policy_projection(
        before, include_update_gate=False
    ) != policy_projection(accumulated, include_update_gate=False):
        errors.append("frozen baseline accumulated adaptive state")
    return errors


def inspect_run(
    run_dir: Path, *, frozen_baseline: dict[str, Any] | None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        metadata = load_object(run_dir / "metadata.json")
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        return {
            "valid": False,
            "errors": [f"metadata: {type(exc).__name__}: {exc}"],
            "run_id": run_dir.name,
        }
    errors.extend(validate_metadata(run_dir, metadata))
    if not (run_dir / "COMPLETE").is_file():
        errors.append("run has no COMPLETE marker")
    mode = MODE_BY_ARM.get(str(metadata.get("arm")))
    is_overhead = metadata.get("stage") == "overhead"

    states: dict[str, dict[str, Any]] = {}
    state_files = {
        "before": "state_before.json",
        "accumulated": "state_accumulated.json",
        "after_barrier": "state_after_barrier.json",
        "post_evaluation": "state_post_evaluation.json",
    }
    for name, filename in state_files.items():
        try:
            states[name] = unwrap_worker(load_object(run_dir / filename), name)
            errors.extend(
                f"{name}: {item}"
                for item in validate_state(
                    states[name],
                    mode=str(mode),
                    baseline_sha256=str(metadata.get("baseline_sha256")),
                    eval_metrics_enabled=metadata.get("stage") != "overhead",
                )
            )
        except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
            errors.append(f"{name}: {type(exc).__name__}: {exc}")

    compile_state: dict[str, Any] = {}
    try:
        compile_state = unwrap_worker(
            load_object(run_dir / "state_compile_warmup.json"),
            "compile_warmup_state",
        )
        errors.extend(
            validate_compile_state(compile_state, mode=str(mode))
        )
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"compile warmup state: {type(exc).__name__}: {exc}")

    baseline_load: dict[str, Any] = {}
    if frozen_baseline is None:
        errors.append("frozen baseline could not be validated")
    elif "before" in states:
        baseline_errors, baseline_load = validate_run_baseline(
            run_dir,
            metadata,
            states["before"],
            frozen_baseline,
        )
        errors.extend(baseline_errors)

    compile_warmup: dict[str, Any] = {}
    try:
        compile_warmup.update(load_object(run_dir / "compile_warmup.json"))
        errors.extend(
            validate_compile_warmup(
                compile_warmup,
                run_id=run_dir.name,
            )
        )
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"compile_warmup: {type(exc).__name__}: {exc}")

    adaptation: dict[str, Any] = {}
    evaluation: dict[str, Any] = {}
    for phase, target in (("adaptation", adaptation), ("evaluation", evaluation)):
        try:
            artifact = load_object(run_dir / f"{phase}.json")
            target.update(artifact)
            budget_name = (
                "observation_budget_by_principal"
                if phase == "adaptation"
                else "evaluation_budget_by_principal"
            )
            errors.extend(
                validate_probe(
                    artifact,
                    run_id=run_dir.name,
                    phase=phase,
                    manifest_sha256=str(
                        metadata.get(f"{phase}_manifest_sha256")
                    ),
                    expected_counts=metadata.get(budget_name, {}),
                )
            )
        except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
            errors.append(f"{phase}: {type(exc).__name__}: {exc}")

    baseline_evaluation: dict[str, Any] = {}
    try:
        baseline_evaluation.update(
            load_object(run_dir / "baseline_evaluation.json")
        )
        errors.extend(
            validate_baseline_evaluation(
                baseline_evaluation,
                run_id=run_dir.name,
            )
        )
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"baseline evaluation: {type(exc).__name__}: {exc}")

    try:
        barrier = load_object(run_dir / "barrier_response.json")
        if set(barrier) != {"called", "method", "response"}:
            errors.append("barrier response has missing or extra fields")
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        barrier = {}
        errors.append(f"barrier: {type(exc).__name__}: {exc}")

    calibration: dict[str, dict[str, Any]] = {}
    baseline_calibration: dict[str, dict[str, Any]] = {}
    if not is_overhead:
        try:
            calibration = parse_eval_metrics(
                load_object(run_dir / "eval_metrics.json")
            )
        except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
            errors.append(f"eval metrics: {type(exc).__name__}: {exc}")
        try:
            baseline_calibration = parse_eval_metrics(
                load_object(run_dir / "baseline_eval_metrics.json")
            )
        except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
            errors.append(
                f"baseline eval metrics: {type(exc).__name__}: {exc}"
            )

    eval_resets: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}
    for reset_name in ("compile", "baseline", "adaptation", "evaluation"):
        try:
            eval_resets[reset_name] = parse_eval_reset(
                load_object(run_dir / f"eval_reset_{reset_name}.json"),
                label=f"eval_reset_{reset_name}",
                expected_enabled=not is_overhead,
            )
        except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
            errors.append(
                f"eval reset {reset_name}: {type(exc).__name__}: {exc}"
            )

    eval_count_evidence: dict[str, Any] = {"response_derived_auxiliary": {}}
    if not is_overhead:
        try:
            baseline_counts = derive_eval_counts_by_position(
                baseline_evaluation,
                label="baseline_evaluation",
            )
            eval_count_evidence["response_derived_auxiliary"][
                "baseline_evaluation"
            ] = baseline_counts
            evaluation_counts = derive_eval_counts_by_position(
                evaluation,
                label="evaluation",
            )
            eval_count_evidence["response_derived_auxiliary"][
                "evaluation"
            ] = evaluation_counts
            adaptation_counts = derive_eval_counts_by_position(
                adaptation,
                label="adaptation",
            )
            eval_count_evidence["response_derived_auxiliary"][
                "adaptation"
            ] = adaptation_counts
        except (KeyError, TypeError, ValueError) as exc:
            eval_count_evidence["response_derived_auxiliary_error"] = (
                f"{type(exc).__name__}: {exc}"
            )
        try:
            reset_adaptation = eval_resets["adaptation"]["before"]
            if not close_values(reset_adaptation, baseline_calibration):
                errors.append(
                    "eval_reset_adaptation.before does not match "
                    "baseline_eval_metrics"
                )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                "eval reset counter binding: "
                f"{type(exc).__name__}: {exc}"
            )

    gateway = validate_gateway_evidence(
        run_dir,
        {
            "compile_warmup": compile_warmup,
            "baseline_evaluation": baseline_evaluation,
            "adaptation": adaptation,
            "evaluation": evaluation,
        },
        metadata,
    )
    errors.extend(f"gateway: {item}" for item in gateway["errors"])
    binding_stage = metadata.get("stage")
    binding_enabled = metadata.get("binding_telemetry_enabled") is True
    binding = validate_binding_telemetry(
        run_dir / "server.log",
        require_mixed_batch=(
            binding_enabled and binding_stage == "stage-d-gate"
        ),
        require_events=binding_enabled,
        expected_id_principals=(
            gateway.get("observed", {}).get(
                "expected_worker_completion_principals"
            )
            if binding_enabled
            else None
        ),
        expected_id_phases=(
            gateway.get("observed", {}).get(
                "expected_worker_completion_phases"
            )
            if binding_enabled
            else None
        ),
        require_verification_counters=(binding_enabled and not is_overhead),
    )
    errors.extend(f"binding: {item}" for item in binding["errors"])
    if binding_enabled and not is_overhead:
        telemetry_counts = binding.get("verification_counts_by_phase")
        eval_count_evidence["telemetry_derived"] = telemetry_counts
        try:
            if not isinstance(telemetry_counts, dict):
                raise ValueError("telemetry counts are absent")
            errors.extend(
                compare_eval_counts(
                    telemetry_counts["baseline_evaluation"],
                    baseline_calibration,
                    label="baseline_eval_metrics",
                )
            )
            errors.extend(
                compare_eval_counts(
                    telemetry_counts["adaptation"],
                    eval_resets["evaluation"]["before"],
                    label="eval_reset_evaluation.before",
                )
            )
            errors.extend(
                compare_eval_counts(
                    telemetry_counts["evaluation"],
                    calibration,
                    label="eval_metrics",
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                f"eval counter binding: {type(exc).__name__}: {exc}"
            )
    evidence = metadata.get("barrier_evidence")
    if isinstance(evidence, dict) and isinstance(
        evidence.get("called_after_ns"), int
    ):
        drain = validate_drain_evidence(
            run_dir / "drain_evidence.jsonl",
            barrier_called_after_ns=evidence["called_after_ns"],
        )
    else:
        drain = {
            "valid": False,
            "errors": ["barrier called_after_ns is unavailable"],
        }
    errors.extend(f"drain: {item}" for item in drain["errors"])
    try:
        barrier_counts = barrier_log_counts(run_dir / "server.log")
    except OSError as exc:
        barrier_counts = {}
        errors.append(f"barrier log: {type(exc).__name__}: {exc}")
    try:
        resources = parse_resource_samples(run_dir / "resource_samples.jsonl")
        if is_overhead:
            started_ns = adaptation.get("started_ns")
            finished_ns = adaptation.get("finished_ns")
            sampled_at_ns = resources.get("sampled_at_ns", [])
            if (
                isinstance(started_ns, bool)
                or not isinstance(started_ns, int)
                or isinstance(finished_ns, bool)
                or not isinstance(finished_ns, int)
                or finished_ns < started_ns
                or not any(
                    started_ns <= sampled <= finished_ns
                    for sampled in sampled_at_ns
                )
            ):
                errors.append(
                    "resources: no sample falls within the adaptation probe"
                )
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        resources = {}
        errors.append(f"resources: {type(exc).__name__}: {exc}")

    if adaptation and evaluation and isinstance(metadata.get("barrier_evidence"), dict):
        try:
            errors.extend(validate_barrier_order(metadata, adaptation, evaluation))
            errors.extend(
                validate_phase_chain(
                    metadata,
                    compile_warmup,
                    baseline_evaluation,
                    adaptation,
                    evaluation,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"barrier order: {type(exc).__name__}: {exc}")
    outcomes: dict[str, float] = {}
    if not is_overhead:
        try:
            raw_baseline = probe_outcomes(
                baseline_evaluation,
                baseline_calibration,
            )
            raw_evaluation = probe_outcomes(evaluation, calibration)
            outcomes = baseline_normalized_outcomes(
                raw_baseline, raw_evaluation
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            statistics.StatisticsError,
        ) as exc:
            errors.append(f"outcomes: {type(exc).__name__}: {exc}")
    try:
        adaptation_outcomes = adaptation_performance(adaptation)
    except (KeyError, TypeError, ValueError) as exc:
        adaptation_outcomes = {}
        errors.append(f"adaptation outcomes: {type(exc).__name__}: {exc}")

    run = {
        "valid": False,
        "errors": errors,
        "run_id": run_dir.name,
        "stage": metadata.get("stage"),
        "block_id": metadata.get("block_id"),
        "arm": metadata.get("arm"),
        "scenario": metadata.get("scenario"),
        "metadata": metadata,
        "states": states,
        "compile_warmup_state": compile_state,
        "compile_warmup": compile_warmup,
        "adaptation": adaptation,
        "baseline_evaluation": baseline_evaluation,
        "baseline_load": baseline_load,
        "evaluation": evaluation,
        "barrier": barrier,
        "calibration": calibration,
        "baseline_calibration": baseline_calibration,
        "eval_resets": eval_resets,
        "eval_count_evidence": eval_count_evidence,
        "gateway_evidence": gateway,
        "binding_telemetry": binding,
        "drain_evidence": drain,
        "barrier_log_counts": barrier_counts,
        "resources": resources,
        "outcomes": outcomes,
        "adaptation_outcomes": adaptation_outcomes,
    }
    if metadata.get("stage") in {"stage-d", "stage-d-gate"} and len(
        states
    ) == 4:
        try:
            errors.extend(validate_stage_d_transition(run))
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"Stage D transition: {type(exc).__name__}: {exc}")
    run["valid"] = not errors
    return run


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        raise ValueError("cannot calculate a percentile of no values")
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def bootstrap(values: list[float], *, seed: int = SEED) -> dict[str, Any]:
    if not values or any(not math.isfinite(value) for value in values):
        raise ValueError("bootstrap values must be finite and non-empty")
    generator = random.Random(seed)
    size = len(values)
    samples = [
        statistics.fmean(generator.choice(values) for _ in range(size))
        for _ in range(BOOTSTRAP_SAMPLES)
    ]
    return {
        "n_blocks": size,
        "values": values,
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "ci95_low": percentile(samples, 0.025),
        "ci95_high": percentile(samples, 0.975),
        "bootstrap_seed": seed,
        "bootstrap_samples": BOOTSTRAP_SAMPLES,
    }


def comparison(
    block_runs: dict[str, dict[str, dict[str, Any]]],
    *,
    treatment: str,
    control: str,
    outcome: str,
    lower_is_better: bool = False,
) -> dict[str, Any]:
    values: list[float] = []
    blocks: list[str] = []
    for block_id in STAGE_D_BLOCKS:
        treatment_value = float(block_runs[block_id][treatment]["outcomes"][outcome])
        control_value = float(block_runs[block_id][control]["outcomes"][outcome])
        value = (
            control_value - treatment_value
            if lower_is_better
            else treatment_value - control_value
        )
        values.append(value)
        blocks.append(block_id)
    result = bootstrap(values, seed=SEED + len(outcome) + len(treatment))
    result.update(
        {
            "blocks": blocks,
            "treatment": treatment,
            "control": control,
            "outcome": outcome,
            "direction": (
                "control_minus_treatment; positive favors treatment"
                if lower_is_better
                else "treatment_minus_control; positive favors treatment"
            ),
        }
    )
    return result


def recovery_summary(
    block_runs: dict[str, dict[str, dict[str, Any]]]
) -> dict[str, Any]:
    triples = [
        (
            float(block_runs[block]["ctfr-full"]["outcomes"]["system_throughput"]),
            float(block_runs[block]["shared"]["outcomes"]["system_throughput"]),
            float(block_runs[block]["frozen"]["outcomes"]["system_throughput"]),
        )
        for block in STAGE_D_BLOCKS
    ]
    ctfr_gain = statistics.fmean(ctfr - drop for ctfr, _, drop in triples)
    shared_gain = statistics.fmean(shared - drop for _, shared, drop in triples)
    point = ctfr_gain / shared_gain if shared_gain > 0 else None
    generator = random.Random(SEED + 404)
    samples: list[float] = []
    for _ in range(BOOTSTRAP_SAMPLES):
        selected = [generator.choice(triples) for _ in triples]
        numerator = statistics.fmean(
            ctfr - drop for ctfr, _, drop in selected
        )
        denominator = statistics.fmean(
            shared - drop for _, shared, drop in selected
        )
        if denominator > 0:
            samples.append(numerator / denominator)
    return {
        "definition": "mean(CTFR-full - frozen) / mean(shared - frozen)",
        "ctfr_gain": ctfr_gain,
        "shared_gain": shared_gain,
        "ratio": point,
        "ci95_low": percentile(samples, 0.025) if samples else None,
        "ci95_high": percentile(samples, 0.975) if samples else None,
        "finite_bootstrap_samples": len(samples),
        "threshold": 0.80,
    }


def probe_semantics(
    run: dict[str, Any], *, phase: str
) -> dict[tuple[int, str], Any]:
    records = run.get(phase, {}).get("records")
    if not isinstance(records, list) or not records:
        raise ValueError(f"{phase} records are absent")
    result: dict[tuple[int, str], Any] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("ok") is not True:
            raise ValueError(f"{phase} contains an invalid record")
        ordinal = record.get("ordinal")
        principal = record.get("principal")
        token_ids = record.get("token_ids")
        output_sha256 = record.get("output_sha256")
        if (
            isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal < 0
            or principal not in PRINCIPALS
            or not isinstance(token_ids, list)
            or not token_ids
            or not all(
                not isinstance(token_id, bool)
                and isinstance(token_id, int)
                and token_id >= 0
                for token_id in token_ids
            )
            or not is_sha256(output_sha256)
        ):
            raise ValueError(f"{phase} semantics are malformed")
        key = (ordinal, principal)
        if key in result:
            raise ValueError(f"{phase} semantic key is duplicated")
        result[key] = (output_sha256, tuple(token_ids))
    return result


def evaluation_semantics(run: dict[str, Any]) -> dict[tuple[int, str], Any]:
    return probe_semantics(run, phase="evaluation")


def analyze_stage_d(
    runs: list[dict[str, Any]],
    *,
    declared_order_by_block: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    indexed: dict[str, dict[str, dict[str, Any]]] = {
        block: {} for block in STAGE_D_BLOCKS
    }
    observation_balance: dict[str, Any] = {}
    semantic_equivalence: dict[str, Any] = {}
    for run in runs:
        block_id = run.get("block_id")
        arm = run.get("arm")
        if block_id not in indexed or arm not in STAGE_D_ARMS:
            errors.append(f"unexpected Stage D run {run.get('run_id')}")
            continue
        if arm in indexed[block_id]:
            errors.append(f"duplicate Stage D run for block {block_id}, arm {arm}")
        indexed[block_id][arm] = run
    for block_id, arms in indexed.items():
        missing = sorted(set(STAGE_D_ARMS) - set(arms))
        if missing:
            errors.append(f"block {block_id} is missing arms {missing}")
        for arm, run in arms.items():
            if not run.get("valid"):
                errors.extend(
                    f"block {block_id} {arm}: {item}" for item in run["errors"]
                )
        if {"ctfr-full", "tenant-local"}.issubset(arms):
            try:
                ctfr_counts = [
                    observation_count(
                        arms["ctfr-full"]["states"]["accumulated"], domain
                    )
                    for domain in (2, 3)
                ]
                tenant_counts = [
                    observation_count(
                        arms["tenant-local"]["states"]["accumulated"], domain
                    )
                    for domain in (2, 3)
                ]
                matched = ctfr_counts == tenant_counts
                observation_balance[block_id] = {
                    "ctfr_full": ctfr_counts,
                    "tenant_local": tenant_counts,
                    "absolute_tolerance": 0,
                    "matched": matched,
                }
                if not matched:
                    errors.append(
                        f"block {block_id} has unequal graded observation counts"
                    )
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(
                    f"block {block_id} observation balance: "
                    f"{type(exc).__name__}: {exc}"
                )
        if set(STAGE_D_ARMS).issubset(arms):
            try:
                semantic_maps = {
                    arm: evaluation_semantics(arms[arm])
                    for arm in STAGE_D_ARMS
                }
                reference = semantic_maps["frozen"]
                matched = all(
                    semantics == reference
                    for semantics in semantic_maps.values()
                )
                semantic_equivalence[block_id] = {
                    "record_count": len(reference),
                    "reference_arm": "frozen",
                    "matched": matched,
                }
                if not matched:
                    errors.append(
                        f"block {block_id} held-out outputs differ across arms"
                    )
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(
                    f"block {block_id} semantic equivalence: "
                    f"{type(exc).__name__}: {exc}"
                )

    complete = not errors
    all_runs = [run for arms in indexed.values() for run in arms.values()]
    errors.extend(
        validate_run_order_by_block(
            indexed,
            declared_order_by_block,
            label="Stage D",
        )
    )
    process_ids = [run["metadata"].get("process_uuid") for run in all_runs]
    if len(process_ids) != len(set(process_ids)):
        errors.append("fresh-process identifiers are not globally unique")
    errors.extend(
        validate_unique_gateway_instances(all_runs, label="Stage D")
    )
    for field in (
        "baseline_sha256",
        "shadow_memory_bound_bytes",
        "shadow_memory_bound_scope",
        *CONTEXT_FIELDS,
    ):
        values = {run["metadata"].get(field) for run in all_runs}
        if len(values) != 1:
            errors.append(f"fixed Stage D field {field} varies across runs")
    for phase in ("compile_warmup", "baseline_evaluation"):
        values = {
            run.get(phase, {}).get("config", {}).get("manifest_sha256")
            for run in all_runs
        }
        if len(values) != 1 or None in values:
            errors.append(f"fixed Stage D {phase} manifest varies across runs")
    for block_id, arms in indexed.items():
        for field in (
            "adaptation_manifest_sha256",
            "evaluation_manifest_sha256",
            "observation_budget_by_principal",
            "evaluation_budget_by_principal",
        ):
            serialized = {
                json.dumps(run["metadata"].get(field), sort_keys=True)
                for run in arms.values()
            }
            if len(serialized) > 1:
                errors.append(f"block {block_id} has unequal {field}")
    complete = complete and not errors
    if not complete:
        return {
            "valid": False,
            "errors": errors,
            "complete_blocks": 0,
            "observation_count_balance": observation_balance,
            "semantic_equivalence_by_block": semantic_equivalence,
            "comparisons": {},
            "secondary_calibration_metrics": {
                "interpretation": (
                    "descriptive and selection-biased; no causal calibration "
                    "claim is permitted without fixed common-depth replay"
                ),
                "observation_support": {},
            },
            "claims": {
                "pre_retirement_committed_state_invariance": False,
                "adaptation_opportunity_established": False,
                "held_out_output_semantic_equivalence": False,
                "benign_adaptation_retained": False,
                "preferable_to_tenant_local": False,
            },
        }

    comparisons: dict[str, Any] = {}
    comparison_specs = (
        (
            "ctfr_vs_frozen_throughput",
            "ctfr-full",
            "frozen",
            "system_throughput",
            False,
        ),
        (
            "shared_vs_frozen_throughput",
            "shared",
            "frozen",
            "system_throughput",
            False,
        ),
        (
            "ctfr_vs_tenant_local_throughput",
            "ctfr-full",
            "tenant-local",
            "system_throughput",
            False,
        ),
        (
            "ctfr_vs_frozen_log_loss",
            "ctfr-full",
            "frozen",
            "balanced_log_loss",
            True,
        ),
        (
            "ctfr_vs_tenant_local_log_loss",
            "ctfr-full",
            "tenant-local",
            "balanced_log_loss",
            True,
        ),
        (
            "ctfr_vs_frozen_brier",
            "ctfr-full",
            "frozen",
            "balanced_brier",
            True,
        ),
        (
            "ctfr_vs_tenant_local_brier",
            "ctfr-full",
            "tenant-local",
            "balanced_brier",
            True,
        ),
    )
    for name, treatment, control, outcome, lower in comparison_specs:
        comparisons[name] = comparison(
            indexed,
            treatment=treatment,
            control=control,
            outcome=outcome,
            lower_is_better=lower,
        )
    principal_results: dict[str, Any] = {}
    for principal in PRINCIPALS:
        principal_results[principal] = {
            "ctfr_vs_frozen_throughput": comparison(
                indexed,
                treatment="ctfr-full",
                control="frozen",
                outcome=f"{principal}_throughput",
            ),
            "ctfr_vs_tenant_local_throughput": comparison(
                indexed,
                treatment="ctfr-full",
                control="tenant-local",
                outcome=f"{principal}_throughput",
            ),
            "ctfr_vs_frozen_log_loss": comparison(
                indexed,
                treatment="ctfr-full",
                control="frozen",
                outcome=f"{principal}_log_loss",
                lower_is_better=True,
            ),
        }
    recovery = recovery_summary(indexed)
    ctfr_frozen = comparisons["ctfr_vs_frozen_throughput"]
    shared_frozen = comparisons["shared_vs_frozen_throughput"]
    ctfr_tenant = comparisons["ctfr_vs_tenant_local_throughput"]
    invariance = all(
        committed_projection(run["states"]["before"])
        == committed_projection(run["states"]["accumulated"])
        for block in indexed.values()
        for arm, run in block.items()
        if arm in {"ctfr-shadow", "ctfr-full"}
    )
    adaptation_opportunity = shared_frozen["ci95_low"] > 0
    retained = bool(
        invariance
        and adaptation_opportunity
        and ctfr_frozen["ci95_low"] > 0
        and recovery["ratio"] is not None
        and recovery["ratio"] >= 0.80
    )
    preferable = bool(retained and ctfr_tenant["ci95_low"] > 0)
    calibration_support: dict[str, Any] = {}
    for block_id, arms in indexed.items():
        block_support: dict[str, Any] = {}
        for arm, run in arms.items():
            baseline_rows = run.get("baseline_calibration")
            shifted_rows = run.get("calibration")
            if isinstance(baseline_rows, dict) and isinstance(
                shifted_rows, dict
            ):
                block_support[arm] = {
                    "baseline": baseline_rows,
                    "shifted_evaluation": shifted_rows,
                }
        if block_support:
            calibration_support[block_id] = block_support
    return {
        "valid": True,
        "errors": [],
        "complete_blocks": len(STAGE_D_BLOCKS),
        "observation_count_balance": observation_balance,
        "semantic_equivalence_by_block": semantic_equivalence,
        "independent_unit": "fresh-process temporal block",
        "primary_endpoint": (
            "held-out system output-token throughput divided by the same "
            "process's frozen-baseline throughput"
        ),
        "comparisons": comparisons,
        "secondary_calibration_metrics": {
            "interpretation": (
                "descriptive and selection-biased: each arm observes only "
                "its admitted draft positions; these results do not identify "
                "a causal calibration effect without fixed common-depth replay"
            ),
            "observation_support": calibration_support,
        },
        "principal_stratified_results": principal_results,
        "adaptation_recovery": recovery,
        "claims": {
            "pre_retirement_committed_state_invariance": invariance,
            "adaptation_opportunity_established": adaptation_opportunity,
            "held_out_output_semantic_equivalence": True,
            "benign_adaptation_retained": retained,
            "preferable_to_tenant_local": preferable,
        },
    }


def analyze_stage_d_gate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    by_arm: dict[str, dict[str, Any]] = {}
    binding_verified = True
    for run in runs:
        arm = run.get("arm")
        if arm not in STAGE_D_ARMS:
            errors.append(f"unexpected gate run {run.get('run_id')}")
            continue
        if arm in by_arm:
            errors.append(f"duplicate gate run for arm {arm}")
        by_arm[arm] = run
        if run.get("block_id") != "gate":
            errors.append(f"gate run {run.get('run_id')} has the wrong block id")
        if not run.get("valid"):
            errors.extend(f"gate {arm}: {item}" for item in run["errors"])
        binding = run.get("binding_telemetry", {})
        if (
            binding.get("valid") is not True
            or binding.get("mixed_principal_batch_count", 0) < 1
        ):
            binding_verified = False
            errors.append(f"gate {arm} has no valid mixed-principal attribution")
    missing = sorted(set(STAGE_D_ARMS) - set(by_arm))
    if missing:
        binding_verified = False
        errors.append(f"gate is missing arms {missing}")
    process_ids = [run["metadata"].get("process_uuid") for run in by_arm.values()]
    if len(process_ids) != len(set(process_ids)):
        errors.append("gate arms reuse a process identity")
    errors.extend(
        validate_unique_gateway_instances(
            list(by_arm.values()),
            label="Stage D gate",
        )
    )
    for field in (
        "baseline_sha256",
        "shadow_memory_bound_bytes",
        "shadow_memory_bound_scope",
        *CONTEXT_FIELDS,
    ):
        if len({run["metadata"].get(field) for run in by_arm.values()}) != 1:
            errors.append(f"fixed gate field {field} varies across arms")
    for phase in ("compile_warmup", "baseline_evaluation"):
        values = {
            run.get(phase, {}).get("config", {}).get("manifest_sha256")
            for run in by_arm.values()
        }
        if len(values) != 1 or None in values:
            errors.append(f"fixed gate {phase} manifest varies across arms")
    for field in (
        "adaptation_manifest_sha256",
        "evaluation_manifest_sha256",
        "observation_budget_by_principal",
        "evaluation_budget_by_principal",
    ):
        values = {
            json.dumps(run["metadata"].get(field), sort_keys=True)
            for run in by_arm.values()
        }
        if len(values) != 1:
            errors.append(f"gate field {field} varies across arms")
    invariance = False
    adaptation_opportunity = False
    ctfr_retirement_geometry = False
    tenant_local_refit = False
    if not missing:
        try:
            invariance = all(
                committed_projection(by_arm[arm]["states"]["before"])
                == committed_projection(by_arm[arm]["states"]["accumulated"])
                for arm in ("ctfr-shadow", "ctfr-full")
            )
            if not invariance:
                errors.append("gate did not preserve unretired committed state")
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                f"gate invariance: {type(exc).__name__}: {exc}"
            )
        shared_throughput = finite(
            by_arm["shared"].get("outcomes", {}).get("system_throughput")
        )
        frozen_throughput = finite(
            by_arm["frozen"].get("outcomes", {}).get("system_throughput")
        )
        if shared_throughput is None or frozen_throughput is None:
            errors.append("gate normalized throughput is unavailable")
        elif shared_throughput <= frozen_throughput:
            errors.append(
                "gate observed no shared-over-frozen adaptation opportunity"
            )
        else:
            adaptation_opportunity = True
        try:
            ctfr = by_arm["ctfr-full"]
            retirement_errors = validate_successful_retirement(
                ctfr["states"]["before"],
                ctfr["states"]["accumulated"],
                ctfr["states"]["after_barrier"],
                retirement_payload(ctfr["barrier"]),
            )
            if retirement_errors:
                errors.extend(
                    f"gate CTFR retirement: {item}"
                    for item in retirement_errors
                )
            else:
                ctfr_retirement_geometry = True
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                f"gate CTFR retirement: {type(exc).__name__}: {exc}"
            )
        try:
            local = by_arm["tenant-local"]
            refit_errors = validate_tenant_refit(
                local["states"]["before"],
                local["states"]["accumulated"],
                local["states"]["after_barrier"],
                tenant_refit_payload(local["barrier"]),
            )
            if refit_errors:
                errors.extend(
                    f"gate tenant-local refit: {item}"
                    for item in refit_errors
                )
            else:
                tenant_local_refit = True
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                f"gate tenant-local refit: {type(exc).__name__}: {exc}"
            )
    return {
        "valid": not errors,
        "errors": errors,
        "arm_count": len(by_arm),
        "mixed_principal_binding_verified": binding_verified,
        "pre_retirement_committed_state_invariance": invariance,
        "shared_over_frozen_adaptation_opportunity": adaptation_opportunity,
        "ctfr_retirement_geometry_valid": ctfr_retirement_geometry,
        "tenant_local_refit_valid": tenant_local_refit,
    }


def validate_failed_retirement(
    run: dict[str, Any], *, reason_fragment: str
) -> list[str]:
    errors: list[str] = []
    try:
        retirement = retirement_payload(run["barrier"])
        if retirement.get("retired") is not False:
            errors.append("candidate unexpectedly retired")
        reason = retirement.get("reason")
        if not isinstance(reason, str) or reason_fragment not in reason:
            errors.append("retirement failed for an unexpected reason")
        accumulated = run["states"]["accumulated"]
        after = run["states"]["after_barrier"]
        if policy_projection(
            accumulated, include_update_gate=False
        ) != policy_projection(after, include_update_gate=False):
            errors.append("failed retirement changed policy state")
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"failed retirement evidence: {type(exc).__name__}: {exc}")
    return errors


def validate_stage_e_transition(run: dict[str, Any]) -> list[str]:
    """Validate security-boundary and stationary-overhead state transitions."""
    errors: list[str] = []
    scenario = run["scenario"]
    arm = run["arm"]
    before = run["states"]["before"]
    accumulated = run["states"]["accumulated"]
    after = run["states"]["after_barrier"]
    post = run["states"]["post_evaluation"]
    budget = run["metadata"]["observation_budget_by_principal"]
    barrier_counts = run.get("barrier_log_counts", {})
    if post.get("updates_enabled") is not False:
        errors.append("Stage E held-out evaluation left updates enabled")
    if policy_projection(after) != policy_projection(post):
        errors.append("Stage E held-out evaluation changed policy state")

    if arm in {"ctfr-full", "ctfr-full-no-retire"}:
        if committed_projection(before) != committed_projection(accumulated):
            errors.append("Stage E shadows changed committed state before barrier")
        for principal, domain in zip(PRINCIPALS, (2, 3)):
            if budget[principal] > 0:
                if not feedback_changed(before, accumulated, domain):
                    errors.append(
                        f"Stage E bank {domain} did not receive declared feedback"
                    )
            elif state_bank(before, domain) != state_bank(accumulated, domain):
                errors.append(
                    f"Stage E bank {domain} changed without declared feedback"
                )

    sybil_scenarios = {
        "sybil-single",
        "sybil-disagree",
        "sybil-quorum-capture",
    }
    if scenario in sybil_scenarios:
        if barrier_counts.get("ctfr_retire_calls") != 1:
            errors.append("Stage E run has other than one server-side call")
        try:
            retired = retirement_payload(run["barrier"]).get("retired")
            if not isinstance(retired, bool):
                raise ValueError("retirement result has no Boolean retired flag")
            expected_success_events = 1 if retired else 0
            if barrier_counts.get("ctfr_retire") != expected_success_events:
                errors.append(
                    "Stage E retirement event count disagrees with the result"
                )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                f"Stage E barrier evidence: {type(exc).__name__}: {exc}"
            )

    control = run["metadata"].get("credential_control_by_principal")
    if scenario == "sybil-single":
        if sorted(budget.values()) != [0, max(budget.values())] or max(
            budget.values()
        ) <= 0:
            errors.append("single-identity scenario does not use exactly one bank")
        if not isinstance(control, dict) or sorted(control.values()) != [
            "absent",
            "attacker",
        ]:
            errors.append("single-identity credential control is not attested")
    elif scenario == "sybil-disagree":
        if any(budget[principal] <= 0 for principal in PRINCIPALS):
            errors.append("disagreement scenario does not populate both banks")
        if control != {
            "attacker": "attacker",
            "victim": "experiment-benign",
        }:
            errors.append("disagreement credential control is not attested")
    elif scenario == "sybil-quorum-capture":
        if any(budget[principal] <= 0 for principal in PRINCIPALS):
            errors.append("quorum-capture scenario does not populate both banks")
        if control != {"attacker": "attacker", "victim": "attacker"}:
            errors.append("quorum-capture credential control is not attested")
    elif scenario == "stationary-overhead":
        if arm == "shared":
            if any(barrier_counts.values()):
                errors.append("shared overhead run contains a barrier event")
            if policy_projection(
                before, include_update_gate=False
            ) != policy_projection(accumulated, include_update_gate=False):
                errors.append("shared overhead control adapted during measurement")
            errors.extend(validate_no_action_barrier(run["barrier"]))
            if policy_projection(
                accumulated, include_update_gate=False
            ) != policy_projection(after, include_update_gate=False):
                errors.append("shared overhead barrier changed policy state")
        elif arm == "ctfr-full-no-retire":
            if any(barrier_counts.values()):
                errors.append("no-retire overhead run contains a barrier event")
            errors.extend(validate_no_action_barrier(run["barrier"]))
            if policy_projection(
                accumulated, include_update_gate=False
            ) != policy_projection(after, include_update_gate=False):
                errors.append("no-retire overhead barrier changed policy state")
    return errors


def resource_metrics(run: dict[str, Any]) -> dict[str, float]:
    resources = run.get("resources")
    names = (
        "gpu_peak_bytes",
        "host_peak_bytes",
        "server_cpu_percent_mean",
        "gateway_cpu_percent_mean",
    )
    if not isinstance(resources, dict):
        raise ValueError("coarse whole-process resource samples are absent")
    result: dict[str, float] = {}
    for name in names:
        value = finite(resources.get(name))
        if value is None or value < 0:
            raise ValueError(f"resource metric {name} is invalid")
        result[name] = value
    bound = finite(run["metadata"].get("shadow_memory_bound_bytes"))
    if bound is None or bound <= 0:
        raise ValueError("analytical fixed-shadow tensor bound is invalid")
    result["shadow_memory_bound_bytes"] = bound
    if run["metadata"].get(
        "shadow_memory_bound_scope"
    ) != SHADOW_MEMORY_BOUND_SCOPE:
        raise ValueError("analytical fixed-shadow tensor scope is invalid")
    return result


def bootstrap_ratios(
    pairs: list[tuple[float, float]], *, seed: int
) -> dict[str, Any]:
    ratios = [left / right for left, right in pairs if right > 0]
    if len(ratios) != len(pairs):
        raise ValueError("ratio denominator must be positive")
    return bootstrap(ratios, seed=seed)


def analyze_overhead(
    runs: list[dict[str, Any]],
    *,
    declared_order_by_block: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    indexed: dict[str, dict[str, dict[str, Any]]] = {}
    semantic_equivalence: dict[str, Any] = {}
    for run in runs:
        block = run.get("block_id")
        arm = run.get("arm")
        if block not in STAGE_D_BLOCKS or arm not in {
            "shared",
            "ctfr-full-no-retire",
        }:
            errors.append(f"unexpected overhead run {run.get('run_id')}")
            continue
        if arm in indexed.setdefault(block, {}):
            errors.append(f"duplicate overhead run for block {block}, arm {arm}")
        indexed[block][arm] = run
        if not run.get("valid"):
            errors.extend(f"{run.get('run_id')}: {item}" for item in run["errors"])
        try:
            errors.extend(
                f"{run.get('run_id')}: {item}"
                for item in validate_stage_e_transition(run)
            )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                f"{run.get('run_id')}: transition: {type(exc).__name__}: {exc}"
            )

    for block in STAGE_D_BLOCKS:
        if set(indexed.get(block, {})) != {
            "shared",
            "ctfr-full-no-retire",
        }:
            errors.append(f"overhead block {block} is incomplete")
            continue
        shared = indexed[block]["shared"]
        ctfr = indexed[block]["ctfr-full-no-retire"]
        for field in (
            "adaptation_manifest_sha256",
            "evaluation_manifest_sha256",
            "observation_budget_by_principal",
            "evaluation_budget_by_principal",
        ):
            if shared["metadata"].get(field) != ctfr["metadata"].get(field):
                errors.append(f"overhead block {block} has unequal {field}")
        try:
            shared_semantics = probe_semantics(shared, phase="adaptation")
            ctfr_semantics = probe_semantics(ctfr, phase="adaptation")
            matched = shared_semantics == ctfr_semantics
            semantic_equivalence[block] = {
                "record_count": len(shared_semantics),
                "matched": matched,
            }
            if not matched:
                errors.append(
                    f"overhead block {block} adaptation outputs differ"
                )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                f"overhead block {block} semantic equivalence: "
                f"{type(exc).__name__}: {exc}"
            )
    process_ids = [run["metadata"].get("process_uuid") for run in runs]
    if len(process_ids) != len(set(process_ids)):
        errors.append("overhead runs reuse a process identity")
    errors.extend(
        validate_unique_gateway_instances(runs, label="overhead")
    )
    errors.extend(
        validate_run_order_by_block(
            indexed,
            declared_order_by_block,
            label="overhead",
        )
    )
    for field in (
        "baseline_sha256",
        "shadow_memory_bound_bytes",
        "shadow_memory_bound_scope",
        *CONTEXT_FIELDS,
        "adaptation_manifest_sha256",
        "evaluation_manifest_sha256",
    ):
        values = {run["metadata"].get(field) for run in runs}
        if len(values) != 1:
            errors.append(f"fixed overhead field {field} varies across runs")
    if errors:
        return {
            "valid": False,
            "errors": errors,
            "guardrails_pass": False,
            "adaptation_semantic_equivalence_by_block": semantic_equivalence,
        }
    throughput_pairs: list[tuple[float, float]] = []
    p95_pairs: list[tuple[float, float]] = []
    resource_deltas: dict[str, list[float]] = {
        "gpu_peak_bytes": [],
        "host_peak_bytes": [],
        "server_cpu_percent_mean": [],
        "gateway_cpu_percent_mean": [],
    }
    memory_pass = True
    for block in STAGE_D_BLOCKS:
        shared = indexed[block]["shared"]
        ctfr = indexed[block]["ctfr-full-no-retire"]
        throughput_pairs.append(
            (
                ctfr["adaptation_outcomes"]["system_throughput"],
                shared["adaptation_outcomes"]["system_throughput"],
            )
        )
        p95_pairs.append(
            (
                ctfr["adaptation_outcomes"]["system_latency_p95"],
                shared["adaptation_outcomes"]["system_latency_p95"],
            )
        )
        try:
            shared_resources = resource_metrics(shared)
            ctfr_resources = resource_metrics(ctfr)
        except ValueError as exc:
            errors.append(f"overhead block {block}: {exc}")
            continue
        for name in resource_deltas:
            resource_deltas[name].append(
                ctfr_resources[name] - shared_resources[name]
            )
        memory_pass = memory_pass and (
            ctfr_resources["shadow_memory_bound_bytes"] == 1024
        )
    if errors:
        return {"valid": False, "errors": errors, "guardrails_pass": False}
    throughput = bootstrap_ratios(throughput_pairs, seed=SEED + 701)
    p95 = bootstrap_ratios(p95_pairs, seed=SEED + 702)
    resources = {
        name: bootstrap(values, seed=SEED + 710 + index)
        for index, (name, values) in enumerate(resource_deltas.items())
    }
    point_guardrail = bool(
        throughput["mean"] >= 0.95 and p95["mean"] <= 1.05 and memory_pass
    )
    equivalence = bool(
        throughput["ci95_low"] >= 0.95
        and throughput["ci95_high"] <= 1.05
        and p95["ci95_low"] >= 0.95
        and p95["ci95_high"] <= 1.05
    )
    return {
        "valid": True,
        "errors": [],
        "ctfr_over_shared_throughput": throughput,
        "ctfr_over_shared_p95_latency": p95,
        "performance_endpoint": (
            "absolute adaptation-probe performance while shadow accumulation "
            "is active; post-evaluation performance is not used"
        ),
        "resource_deltas_ctfr_minus_shared": resources,
        "fixed_shadow_tensor_bound_bytes": 1024,
        "fixed_shadow_tensor_bound_scope": SHADOW_MEMORY_BOUND_SCOPE,
        "fixed_shadow_tensor_bound_declared_consistently": memory_pass,
        "adaptation_semantic_equivalence_by_block": semantic_equivalence,
        "resource_measurement_scope": (
            "GPU/host memory and CPU are coarse whole-process samples; the "
            "1024-byte analytical bound covers persistent shadow-state "
            "tensors only, not transient workspace or total process memory; "
            "the study does not isolate shadow-manager CPU or memory."
        ),
        "guardrails_pass": point_guardrail,
        "equivalence_interval_pass": equivalence,
    }


def analyze_origin_binding(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"tested": False, "pass": False, "errors": ["artifact absent"]}
    errors: list[str] = []
    try:
        artifact = load_object(path)
        if artifact.get("schema") != "ctfr-origin-binding-v1":
            errors.append("origin-binding schema is invalid")
        attempts = artifact.get("attempts")
        if not isinstance(attempts, list):
            raise ValueError("attempts is not a list")
        if any(not isinstance(attempt, dict) for attempt in attempts):
            raise ValueError("an origin-binding attempt is not an object")
        by_case = {attempt.get("case"): attempt for attempt in attempts}
        if set(by_case) != {
            "victim-prefix-request-id",
            "conflicting-identity-header",
            "missing-credential",
        }:
            errors.append("origin-binding cases are incomplete")
        for name in (
            "victim-prefix-request-id",
            "conflicting-identity-header",
        ):
            attempt = by_case.get(name, {})
            if any(
                (
                    attempt.get("status") != 200,
                    attempt.get("authenticated_principal") != "attacker",
                    attempt.get("worker_principal") != 0,
                    not isinstance(attempt.get("internal_request_id"), str),
                    not str(attempt.get("internal_request_id", "")).startswith(
                        "ctfr-auth-attacker-"
                    ),
                    attempt.get("internal_request_id")
                    == attempt.get("external_request_id"),
                )
            ):
                errors.append(f"origin binding failed for {name}")
        missing = by_case.get("missing-credential", {})
        if missing.get("status") not in {401, 403} or missing.get("forwarded"):
            errors.append("missing credentials were not rejected before forwarding")
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"origin binding: {type(exc).__name__}: {exc}")
    return {"tested": True, "pass": not errors, "errors": errors}


def analyze_stage_e(
    runs: list[dict[str, Any]],
    *,
    origin_binding_path: Path,
    declared_order_by_block: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    scenarios: dict[str, list[dict[str, Any]]] = {
        name: [] for name in STAGE_E_SCENARIOS
    }
    for run in runs:
        scenario = run.get("scenario")
        if scenario not in scenarios:
            errors.append(f"unexpected Stage E run {run.get('run_id')}")
            continue
        scenarios[scenario].append(run)
        if not run.get("valid"):
            errors.extend(f"{run.get('run_id')}: {item}" for item in run["errors"])
        try:
            transition_errors = validate_stage_e_transition(run)
            run["stage_e_transition_errors"] = transition_errors
            errors.extend(
                f"{run.get('run_id')}: {item}"
                for item in transition_errors
            )
        except (KeyError, TypeError, ValueError) as exc:
            run["stage_e_transition_errors"] = [
                f"transition: {type(exc).__name__}: {exc}"
            ]
            errors.append(
                f"{run.get('run_id')}: transition: {type(exc).__name__}: {exc}"
            )

    single_blocks = [
        run.get("block_id") for run in scenarios["sybil-single"]
    ]
    if single_blocks and single_blocks != ["e1"]:
        errors.append("single-identity scenario is not exactly block e1")
    for name in ("sybil-disagree", "sybil-quorum-capture"):
        blocks = [run.get("block_id") for run in scenarios[name]]
        if blocks and (
            len(blocks) != len(STAGE_D_BLOCKS)
            or set(blocks) != set(STAGE_D_BLOCKS)
        ):
            errors.append(
                f"{name} does not contain each block 01 through 08 exactly once"
            )
    process_ids = [run["metadata"].get("process_uuid") for run in runs]
    if len(process_ids) != len(set(process_ids)):
        errors.append("Stage E runs reuse a process identity")
    errors.extend(
        validate_unique_gateway_instances(runs, label="Stage E")
    )
    secondary_indexed: dict[str, dict[str, dict[str, Any]]] = {
        block: {} for block in STAGE_D_BLOCKS
    }
    declared_name_by_scenario = {
        "sybil-disagree": "e2-disagreement",
        "sybil-quorum-capture": "e3-two-credentials",
    }
    for scenario, declared_name in declared_name_by_scenario.items():
        for run in scenarios[scenario]:
            block = run.get("block_id")
            if block in secondary_indexed:
                secondary_indexed[block][declared_name] = run
    errors.extend(
        validate_run_order_by_block(
            secondary_indexed,
            declared_order_by_block,
            label="Stage E",
        )
    )
    if scenarios["sybil-single"]:
        initial_start = scenarios["sybil-single"][0].get(
            "adaptation", {}
        ).get("started_ns")
        later_starts = [
            run.get("adaptation", {}).get("started_ns")
            for scenario in ("sybil-disagree", "sybil-quorum-capture")
            for run in scenarios[scenario]
        ]
        if (
            isinstance(initial_start, bool)
            or not isinstance(initial_start, int)
            or initial_start <= 0
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= initial_start
                for value in later_starts
            )
        ):
            errors.append("Stage E1 did not precede every Stage E2/E3 run")
    for field in (
        "baseline_sha256",
        "shadow_memory_bound_bytes",
        "shadow_memory_bound_scope",
        *CONTEXT_FIELDS,
    ):
        values = {run["metadata"].get(field) for run in runs}
        if len(values) > 1:
            errors.append(f"fixed Stage E field {field} varies across runs")
    for phase in ("compile_warmup", "baseline_evaluation"):
        values = {
            run.get(phase, {}).get("config", {}).get("manifest_sha256")
            for run in runs
        }
        if len(values) > 1:
            errors.append(f"fixed Stage E {phase} manifest varies across runs")
    for scenario, scenario_runs in scenarios.items():
        for field in (
            "adaptation_manifest_sha256",
            "evaluation_manifest_sha256",
            "observation_budget_by_principal",
            "evaluation_budget_by_principal",
        ):
            values = {
                json.dumps(run["metadata"].get(field), sort_keys=True)
                for run in scenario_runs
            }
            if len(values) > 1:
                errors.append(f"{scenario} field {field} varies across blocks")

    sybil_results: dict[str, Any] = {}
    reason_fragments = {
        "sybil-single": "insufficient",
        "sybil-disagree": "disagree",
    }
    for scenario, fragment in reason_fragments.items():
        scenario_errors: list[str] = []
        if not scenarios[scenario]:
            scenario_errors.append("scenario was not run")
        for run in scenarios[scenario]:
            scenario_errors.extend(run.get("errors", []))
            scenario_errors.extend(run.get("stage_e_transition_errors", []))
            scenario_errors.extend(
                validate_failed_retirement(run, reason_fragment=fragment)
            )
        sybil_results[scenario] = {
            "tested": bool(scenarios[scenario]),
            "pass": bool(scenarios[scenario]) and not scenario_errors,
            "errors": scenario_errors,
        }

    capture_runs = scenarios["sybil-quorum-capture"]
    capture_retired: list[bool] = []
    capture_errors: list[str] = []
    for run in capture_runs:
        capture_errors.extend(run.get("errors", []))
        capture_errors.extend(run.get("stage_e_transition_errors", []))
        try:
            result = retirement_payload(run["barrier"])
            retired = result.get("retired")
            if not isinstance(retired, bool):
                raise ValueError("negative-control result has no retired flag")
            capture_retired.append(retired)
            if retired:
                capture_errors.extend(
                    validate_successful_retirement(
                        run["states"]["before"],
                        run["states"]["accumulated"],
                        run["states"]["after_barrier"],
                        result,
                    )
                )
            elif policy_projection(
                run["states"]["accumulated"], include_update_gate=False
            ) != (
                policy_projection(
                    run["states"]["after_barrier"],
                    include_update_gate=False,
                )
            ):
                capture_errors.append("squashed negative control changed state")
        except (KeyError, TypeError, ValueError) as exc:
            capture_errors.append(f"negative control: {type(exc).__name__}: {exc}")
    sybil_results["sybil-quorum-capture"] = {
        "tested": bool(capture_runs),
        "valid": bool(capture_runs) and not capture_errors,
        "retired_results": capture_retired,
        "quorum_capture_limitation_observed": any(capture_retired),
        "errors": capture_errors,
    }

    overhead = {
        "valid": False,
        "errors": ["overhead is analyzed by the separate overhead stage"],
        "guardrails_pass": False,
        "not_applicable": True,
    }
    origin_artifact = analyze_origin_binding(origin_binding_path)
    run_origin = {
        "tested": bool(runs),
        "pass": bool(runs)
        and all(
            run.get("gateway_evidence", {}).get("valid") is True
            for run in runs
        ),
        "errors": [
            item
            for run in runs
            for item in run.get("gateway_evidence", {}).get("errors", [])
        ],
    }
    origin = {
        "tested": run_origin["tested"],
        "pass": bool(
            run_origin["pass"]
            and (
                not origin_artifact["tested"]
                or origin_artifact["pass"]
            )
        ),
        "errors": [
            *run_origin["errors"],
            *(
                origin_artifact["errors"]
                if origin_artifact["tested"]
                else []
            ),
        ],
        "supplemental_origin_artifact_tested": origin_artifact["tested"],
    }
    expected_counts = {
        "sybil-single": 1,
        "sybil-disagree": 8,
        "sybil-quorum-capture": 8,
    }
    sybil_complete = all(
        len(scenarios[name]) == count
        for name, count in expected_counts.items()
    )
    complete = bool(
        not errors
        and sybil_complete
        and sybil_results["sybil-single"]["pass"]
        and sybil_results["sybil-disagree"]["pass"]
        and sybil_results["sybil-quorum-capture"]["valid"]
        and origin["pass"]
    )
    single_pass = bool(sybil_results["sybil-single"]["pass"] and not errors)
    disagree_pass = bool(
        sybil_results["sybil-disagree"]["pass"] and not errors
    )
    capture_observed = bool(
        sybil_results["sybil-quorum-capture"][
            "quorum_capture_limitation_observed"
        ]
        and not errors
    )
    return {
        "valid": not errors,
        "errors": errors,
        "complete": complete,
        "sybil_complete": sybil_complete,
        "sybil_boundary": sybil_results,
        "overhead": overhead,
        "origin_binding": origin,
        "claims": {
            "single_identity_quorum_rejected": single_pass,
            "disagreeing_candidate_squashed": disagree_pass,
            "quorum_capture_limitation_observed": capture_observed,
            "sybil_resistant": False,
            "overhead_guardrails_pass": bool(
                overhead["guardrails_pass"] and not errors
            ),
            "origin_binding_robust": bool(origin["pass"] and not errors),
        },
    }


def discover_runs(
    root: Path,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    errors: list[str] = []
    runs: list[dict[str, Any]] = []
    frozen_baseline = validate_frozen_baseline(root)
    errors.extend(
        f"frozen baseline: {item}" for item in frozen_baseline["errors"]
    )
    baseline = (
        frozen_baseline["baseline"] if frozen_baseline["valid"] else None
    )
    if (root / "CTFR_FULL_STUDY_FAILED.txt").exists():
        errors.append("result root contains CTFR_FULL_STUDY_FAILED.txt")
    try:
        children = sorted(root.iterdir())
    except OSError as exc:
        return (
            [],
            [f"result root: {type(exc).__name__}: {exc}"],
            frozen_baseline,
        )
    run_name = re.compile(
        r"^(?:gate_stage_d_|stage_d_block_|stage_e_|stage_e[23]_block_|"
        r"overhead_block_)"
    )
    for child in children:
        if child.is_dir() and (
            child.name == "_incomplete"
            or "quarantine" in child.name.lower()
        ):
            try:
                if any(child.iterdir()):
                    errors.append(
                        f"result root contains nonempty {child.name} directory"
                    )
            except OSError as exc:
                errors.append(
                    f"{child.name}: directory audit: "
                    f"{type(exc).__name__}: {exc}"
                )
            continue
        if not child.is_dir():
            continue
        metadata_path = child / "metadata.json"
        if not metadata_path.is_file():
            if run_name.match(child.name):
                errors.append(
                    f"{child.name}: direct run directory has no metadata"
                )
            continue
        try:
            metadata = load_object(metadata_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{child.name}: metadata: {type(exc).__name__}: {exc}")
            continue
        if metadata.get("protocol_version") != PROTOCOL_VERSION:
            errors.append(
                f"{child.name}: unexpected protocol version in run metadata"
            )
            continue
        if not (child / "COMPLETE").is_file():
            errors.append(f"{child.name}: protocol run is incomplete")
        runs.append(inspect_run(child, frozen_baseline=baseline))
    if not runs:
        errors.append("no CTFR full-study run directories were found")
    return runs, errors, frozen_baseline


def analyze(
    root: Path,
    *,
    stage: str = "all",
    require_complete: bool = False,
) -> dict[str, Any]:
    runs, errors, frozen_baseline = discover_runs(root)
    declaration = validate_declaration(root)
    errors.extend(f"declaration: {item}" for item in declaration["errors"])
    gate_runs = [run for run in runs if run.get("stage") == "stage-d-gate"]
    stage_d_runs = [run for run in runs if run.get("stage") == "stage-d"]
    stage_e_runs = [
        run
        for run in runs
        if run.get("stage") in {"stage-e1", "stage-e2", "stage-e3"}
    ]
    overhead_runs = [run for run in runs if run.get("stage") == "overhead"]

    gate = analyze_stage_d_gate(gate_runs) if gate_runs else {
        "valid": False,
        "errors": ["Stage D gate was not run"],
        "not_tested": True,
        "pre_retirement_committed_state_invariance": False,
    }
    stage_d = analyze_stage_d(
        stage_d_runs,
        declared_order_by_block=declaration.get(
            "stage_d_order_by_block"
        ),
    )
    stage_e = analyze_stage_e(
        stage_e_runs,
        origin_binding_path=root / "origin_binding.json",
        declared_order_by_block=declaration.get(
            "stage_e_order_by_block"
        ),
    )
    overhead = (
        analyze_overhead(
            overhead_runs,
            declared_order_by_block=declaration.get(
                "overhead_order_by_block"
            ),
        )
        if overhead_runs
        else {
            "valid": False,
            "errors": ["overhead study was not run"],
            "guardrails_pass": False,
            "not_tested": True,
        }
    )

    if stage == "stage-d-gate":
        if not gate["valid"]:
            errors.extend(f"Stage D gate: {item}" for item in gate["errors"])
    elif stage == "stage-d":
        if not stage_d["valid"]:
            errors.extend(f"Stage D: {item}" for item in stage_d["errors"])
    elif stage == "stage-e":
        if not stage_e["valid"]:
            errors.extend(f"Stage E: {item}" for item in stage_e["errors"])
        if not stage_e["sybil_complete"]:
            errors.append("complete Stage E Sybil-boundary evidence is absent")
    elif stage == "overhead":
        if not overhead["valid"]:
            errors.extend(f"overhead: {item}" for item in overhead["errors"])
    elif stage == "all":
        if not stage_d["valid"]:
            errors.extend(f"Stage D: {item}" for item in stage_d["errors"])
        if gate_runs and not gate["valid"]:
            errors.extend(f"Stage D gate: {item}" for item in gate["errors"])
        if stage_e_runs and not stage_e["valid"]:
            errors.extend(f"Stage E: {item}" for item in stage_e["errors"])
        if overhead_runs and not overhead["valid"]:
            errors.extend(f"overhead: {item}" for item in overhead["errors"])
        if require_complete and not (
            gate["valid"]
            and stage_d["valid"]
            and stage_e["sybil_complete"]
            and overhead["valid"]
        ):
            errors.append("complete Stage D/E/overhead evidence is absent")
    else:
        errors.append(f"unknown analysis stage {stage!r}")

    bound = declaration.get("shadow_bound_bytes")
    scope = declaration.get("shadow_bound_scope")
    for run in runs:
        if bound is not None and run.get("metadata", {}).get(
            "shadow_memory_bound_bytes"
        ) != bound:
            errors.append(
                f"{run.get('run_id')}: shadow bound differs from declaration"
            )
        if scope is not None and run.get("metadata", {}).get(
            "shadow_memory_bound_scope"
        ) != scope:
            errors.append(
                f"{run.get('run_id')}: shadow scope differs from declaration"
            )

    valid = not errors
    claims = {
        "pre_retirement_committed_state_invariance": bool(
            stage_d.get("claims", {}).get(
                "pre_retirement_committed_state_invariance"
            )
            if stage in {"stage-d", "all"}
            else gate.get("pre_retirement_committed_state_invariance", False)
        ),
        "benign_adaptation_retained": bool(
            stage_d.get("claims", {}).get("benign_adaptation_retained")
            and stage in {"stage-d", "all"}
        ),
        "adaptation_opportunity_established": bool(
            stage_d.get("claims", {}).get(
                "adaptation_opportunity_established"
            )
            and stage in {"stage-d", "all"}
        ),
        "held_out_output_semantic_equivalence": bool(
            stage_d.get("claims", {}).get(
                "held_out_output_semantic_equivalence"
            )
            and stage in {"stage-d", "all"}
        ),
        "preferable_to_tenant_local": bool(
            stage_d.get("claims", {}).get("preferable_to_tenant_local")
            and stage in {"stage-d", "all"}
        ),
        "single_identity_quorum_rejected": bool(
            stage_e["claims"]["single_identity_quorum_rejected"]
            and stage in {"stage-e", "all"}
        ),
        "disagreeing_candidate_squashed": bool(
            stage_e["claims"]["disagreeing_candidate_squashed"]
            and stage in {"stage-e", "all"}
        ),
        "quorum_capture_limitation_observed": bool(
            stage_e["claims"]["quorum_capture_limitation_observed"]
            and stage in {"stage-e", "all"}
        ),
        "overhead_guardrails_pass": bool(
            overhead.get("guardrails_pass")
            and stage in {"overhead", "all"}
        ),
        "sybil_resistant": False,
        "controller_decision_noninterference": False,
        "benignness_oracle": False,
        "arbitrary_poisoning_resistance": False,
        "cross_engine_validation": False,
    }
    if not valid:
        claims = {name: False for name in claims}
    if not valid:
        classification = "INVALID"
    elif claims["preferable_to_tenant_local"]:
        classification = "CTFR_UTILITY_AND_TENANT_LOCAL_ADVANTAGE"
    elif claims["benign_adaptation_retained"]:
        classification = "CTFR_SECURITY_UTILITY_CHARACTERIZATION"
    elif stage == "stage-d-gate" and gate["valid"]:
        classification = "CTFR_MECHANISM_GATE_PASSED"
    else:
        classification = "CTFR_STRUCTURAL_OR_INCONCLUSIVE"
    allowed: list[str] = []
    if valid and claims["pre_retirement_committed_state_invariance"]:
        allowed.append(
            "exact pre-retirement committed-estimator-state invariance in the "
            "pinned single-worker configuration"
        )
    if valid and claims["benign_adaptation_retained"]:
        allowed.append("CTFR preserved useful adaptation for the frozen workload")
    if valid and claims["adaptation_opportunity_established"]:
        allowed.append(
            "shared adaptation outperformed the frozen policy on the "
            "predeclared normalized-throughput endpoint"
        )
    if valid and claims["held_out_output_semantic_equivalence"]:
        allowed.append(
            "held-out output token sequences were exactly identical across "
            "all Stage D arms for the frozen deterministic workload"
        )
    if valid and claims["preferable_to_tenant_local"]:
        allowed.append(
            "CTFR improved the predeclared held-out throughput endpoint over "
            "tenant-local adaptation"
        )
    return {
        "schema": SCHEMA_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "analysis_stage": stage,
        "valid": valid,
        "errors": errors,
        "declaration": declaration,
        "frozen_baseline": frozen_baseline,
        "run_count": len(runs),
        "stage_d_gate": gate,
        "stage_d": stage_d,
        "stage_e": stage_e,
        "overhead": overhead,
        "claims": claims,
        "allowed_paper_phrases": allowed,
        "always_disallowed_without_separate_evidence": [
            "controller-decision noninterference",
            "Sybil-resistant",
            "benignness oracle",
            "arbitrary poisoning resistance",
            "concurrent or crash-safe publication",
            "cross-engine validation",
            "isolated shadow-manager CPU overhead",
            "causal calibration improvement without fixed common-depth replay",
        ],
        "classification": classification,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--stage",
        choices=("stage-d-gate", "stage-d", "stage-e", "overhead", "all"),
        default="all",
    )
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    result = analyze(
        args.result_root,
        stage=args.stage,
        require_complete=args.require_complete,
    )
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
