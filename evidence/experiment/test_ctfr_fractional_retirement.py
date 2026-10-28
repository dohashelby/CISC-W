#!/usr/bin/env python
"""Unit tests for the CTFR bounded fractional-retirement reference."""

from __future__ import annotations

import math
import unittest

from ctfr_fractional_retirement import (
    RETIREMENT_SCALE_STEPS,
    max_probability_shift,
    select_fractional_retirement,
)


def select(
    candidate: list[float],
    *,
    max_norm: float = 1.0,
    max_shift: float = 0.15,
    credits: list[float] | None = None,
) -> dict:
    return select_fractional_retirement(
        base=[0.5, -0.2, -0.2],
        candidate_aggregate=candidate,
        clipped_delta_norms=[0.8, 0.8],
        influence_credits=[2.0, 2.0] if credits is None else credits,
        max_commit_norm=max_norm,
        max_probability_shift_limit=max_shift,
    )


class FractionalRetirementTests(unittest.TestCase):
    def test_in_bound_update_keeps_legacy_scale_one(self) -> None:
        result = select([0.01, 0.02, 0.02])
        self.assertTrue(result["retired"])
        self.assertEqual(result["parameter_projection_scale"], 1.0)
        self.assertEqual(result["decision_scale"], 1.0)
        self.assertEqual(result["retirement_scale"], 1.0)
        self.assertEqual(result["aggregate_delta"], [0.01, 0.02, 0.02])
        self.assertEqual(result["credit_debits"], [0.8, 0.8])

    def test_slight_decision_region_excess_is_fractionally_committed(self) -> None:
        candidate = [0.0, 0.62, 0.62]
        self.assertGreater(
            max_probability_shift([0.5, -0.2, -0.2], candidate),
            0.15,
        )
        result = select(candidate)
        self.assertTrue(result["retired"])
        self.assertGreater(result["decision_scale"], 0.0)
        self.assertLess(result["decision_scale"], 1.0)
        self.assertLessEqual(result["max_probability_shift"], 0.15)
        self.assertEqual(
            result["decision_scale"] * RETIREMENT_SCALE_STEPS,
            round(result["decision_scale"] * RETIREMENT_SCALE_STEPS),
        )

    def test_parameter_projection_precedes_decision_projection(self) -> None:
        result = select([2.0, 0.0, 0.0], max_norm=0.5)
        self.assertTrue(result["retired"])
        self.assertAlmostEqual(result["parameter_projection_scale"], 0.25)
        self.assertLessEqual(result["parameter_projected_norm"], 0.5)
        self.assertLessEqual(result["aggregate_norm"], 0.5)

    def test_no_positive_safe_grid_scale_fails_closed(self) -> None:
        result = select([0.0, 0.62, 0.62], max_shift=1.0e-12)
        self.assertFalse(result["retired"])
        self.assertEqual(
            result["reason"],
            "no positive grid scale satisfies decision trust region",
        )
        self.assertNotIn("proposed_coefficients", result)

    def test_credit_shortage_fails_closed_after_scaling(self) -> None:
        result = select(
            [0.01, 0.02, 0.02],
            credits=[0.79, 2.0],
        )
        self.assertFalse(result["retired"])
        self.assertEqual(result["exhausted_principals"], [0])

    def test_zero_and_non_finite_inputs_fail_closed(self) -> None:
        zero = select([0.0, 0.0, 0.0])
        self.assertFalse(zero["retired"])
        with self.assertRaises(ValueError):
            select_fractional_retirement(
                base=[0.5, -0.2],
                candidate_aggregate=[math.nan, 0.1],
                clipped_delta_norms=[0.1, 0.1],
                influence_credits=[1.0, 1.0],
                max_commit_norm=1.0,
                max_probability_shift_limit=0.15,
            )

    def test_selection_is_deterministic(self) -> None:
        first = select([0.0, 0.62, 0.62])
        second = select([0.0, 0.62, 0.62])
        self.assertEqual(first, second)

    def test_credit_debit_tracks_the_final_committed_scale(self) -> None:
        result = select([0.0, 0.62, 0.62])
        expected = 0.8 * result["retirement_scale"]
        self.assertAlmostEqual(result["credit_debits"][0], expected)
        self.assertAlmostEqual(result["credit_debits"][1], expected)


if __name__ == "__main__":
    unittest.main()
