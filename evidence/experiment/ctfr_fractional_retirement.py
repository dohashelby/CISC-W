#!/usr/bin/env python
"""Pure-Python reference for CTFR bounded fractional retirement.

The GPU implementation deliberately mirrors this small reference model.  It
is kept free of vLLM and PyTorch imports so the trust-region logic can be unit
tested before any paid GPU run.
"""

from __future__ import annotations

import math
from typing import Any, Sequence

MAX_LOG_ODDS = 40.0
FEATURE_GRID_POINTS = 161
RETIREMENT_SCALE_STEPS = 160


def _finite_vector(name: str, value: Sequence[float]) -> list[float]:
    result = [float(item) for item in value]
    if not result or any(not math.isfinite(item) for item in result):
        raise ValueError(f"{name} must be a non-empty finite vector")
    return result


def _positive_finite(name: str, value: float) -> float:
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise ValueError(f"{name} must be positive and finite")
    return result


def _sigmoid(value: float) -> float:
    if value >= 0.0:
        return 1.0 / (1.0 + math.exp(-value))
    exp_value = math.exp(value)
    return exp_value / (1.0 + exp_value)


def vector_norm(value: Sequence[float]) -> float:
    return math.sqrt(math.fsum(float(item) ** 2 for item in value))


def max_probability_shift(
    base: Sequence[float],
    delta: Sequence[float],
) -> float:
    """Return the maximum sigmoid-output shift on the frozen feature grid."""
    base_vector = _finite_vector("base", base)
    delta_vector = _finite_vector("delta", delta)
    if len(base_vector) != len(delta_vector) or len(base_vector) < 2:
        raise ValueError("base and delta must have the same length >= 2")

    maximum = 0.0
    for index in range(FEATURE_GRID_POINTS):
        feature = -MAX_LOG_ODDS + (
            2.0 * MAX_LOG_ODDS * index / (FEATURE_GRID_POINTS - 1)
        )
        old_slope = base_vector[0] * feature
        new_slope = (base_vector[0] + delta_vector[0]) * feature
        for position in range(1, len(base_vector)):
            old_probability = _sigmoid(old_slope + base_vector[position])
            new_probability = _sigmoid(
                new_slope
                + base_vector[position]
                + delta_vector[position]
            )
            maximum = max(
                maximum,
                abs(new_probability - old_probability),
            )
    return maximum


def select_fractional_retirement(
    *,
    base: Sequence[float],
    candidate_aggregate: Sequence[float],
    clipped_delta_norms: Sequence[float],
    influence_credits: Sequence[float],
    max_commit_norm: float,
    max_probability_shift_limit: float,
    scale_steps: int = RETIREMENT_SCALE_STEPS,
) -> dict[str, Any]:
    """Select the largest predeclared scale satisfying both trust regions.

    The parameter projection is continuous and deterministic.  The decision
    projection then searches a fixed descending grid, so the selected scale is
    auditable and cannot depend on a data-dependent optimizer tolerance.
    """
    base_vector = _finite_vector("base", base)
    candidate = _finite_vector("candidate_aggregate", candidate_aggregate)
    if len(base_vector) != len(candidate) or len(base_vector) < 2:
        raise ValueError(
            "base and candidate_aggregate must have the same length >= 2"
        )
    maximum_norm = _positive_finite("max_commit_norm", max_commit_norm)
    maximum_shift = _positive_finite(
        "max_probability_shift_limit",
        max_probability_shift_limit,
    )
    if type(scale_steps) is not int or scale_steps <= 0:
        raise ValueError("scale_steps must be a positive integer")

    clipped_norms = _finite_vector(
        "clipped_delta_norms", clipped_delta_norms
    )
    credits = _finite_vector("influence_credits", influence_credits)
    if len(clipped_norms) != len(credits) or any(
        value < 0.0 for value in (*clipped_norms, *credits)
    ):
        raise ValueError(
            "clipped norms and credits must be equally sized and non-negative"
        )

    candidate_norm = vector_norm(candidate)
    if candidate_norm == 0.0:
        return {
            "retired": False,
            "reason": "non-finite or zero aggregate update",
            "candidate_aggregate_norm": candidate_norm,
        }

    parameter_scale = min(1.0, maximum_norm / candidate_norm)
    projected = [value * parameter_scale for value in candidate]
    projected_norm = vector_norm(projected)
    evaluations: list[dict[str, float]] = []
    selected_scale: float | None = None
    selected_shift: float | None = None
    for numerator in range(scale_steps, 0, -1):
        scale = numerator / scale_steps
        final_delta = [value * scale for value in projected]
        probability_shift = max_probability_shift(base_vector, final_delta)
        evaluations.append(
            {
                "scale": scale,
                "max_probability_shift": probability_shift,
            }
        )
        if probability_shift <= maximum_shift:
            selected_scale = scale
            selected_shift = probability_shift
            break

    common = {
        "candidate_aggregate_delta": candidate,
        "candidate_aggregate_norm": candidate_norm,
        "parameter_projection_scale": parameter_scale,
        "parameter_projected_delta": projected,
        "parameter_projected_norm": projected_norm,
        "retirement_scale_steps": scale_steps,
        "evaluated_scales": evaluations,
    }
    if selected_scale is None or selected_shift is None:
        return {
            "retired": False,
            "reason": "no positive grid scale satisfies decision trust region",
            **common,
        }

    retirement_scale = parameter_scale * selected_scale
    final_delta = [value * selected_scale for value in projected]
    final_norm = vector_norm(final_delta)
    credit_debits = [value * retirement_scale for value in clipped_norms]
    exhausted = [
        index
        for index, (debit, credit) in enumerate(
            zip(credit_debits, credits)
        )
        if debit > credit
    ]
    if exhausted:
        return {
            "retired": False,
            "reason": "principal influence budget exhausted",
            "exhausted_principals": exhausted,
            "decision_scale": selected_scale,
            "retirement_scale": retirement_scale,
            "max_probability_shift": selected_shift,
            "aggregate_delta": final_delta,
            "aggregate_norm": final_norm,
            "credit_debits": credit_debits,
            **common,
        }

    return {
        "retired": True,
        "decision_scale": selected_scale,
        "retirement_scale": retirement_scale,
        "max_probability_shift": selected_shift,
        "aggregate_delta": final_delta,
        "aggregate_norm": final_norm,
        "credit_debits": credit_debits,
        "proposed_coefficients": [
            coefficient + delta
            for coefficient, delta in zip(base_vector, final_delta)
        ],
        **common,
    }
