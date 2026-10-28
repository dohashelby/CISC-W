from __future__ import annotations

import unittest

from extract_ctfr_baseline import extract


class ExtractBaselineTest(unittest.TestCase):
    def test_extracts_bank_zero(self) -> None:
        result = extract(
            {
                "results": [
                    {
                        "available": True,
                        "slope": [0.7, 1.0, 1.1, 1.2],
                        "intercepts": [
                            [0.1, 0.2],
                            [0.3, 0.4],
                            [0.5, 0.6],
                            [0.7, 0.8],
                        ],
                    }
                ]
            }
        )
        self.assertEqual(result["slope"], 0.7)
        self.assertEqual(result["intercepts"], [0.1, 0.2])
        self.assertEqual(len(result["coefficient_sha256"]), 64)

    def test_rejects_multiple_workers(self) -> None:
        with self.assertRaises(ValueError):
            extract({"results": [{"available": True}, {"available": True}]})

    def test_integral_coefficients_have_float_canonicalization(self) -> None:
        def snapshot(slope: float | int, intercepts: list[float | int]):
            return {
                "results": [
                    {
                        "available": True,
                        "slope": [slope],
                        "intercepts": [intercepts],
                    }
                ]
            }

        integers = extract(snapshot(1, [-1, 0]))
        floats = extract(snapshot(1.0, [-1.0, 0.0]))
        self.assertEqual(integers, floats)

    def test_rejects_boolean_coefficients(self) -> None:
        with self.assertRaises(ValueError):
            extract(
                {
                    "results": [
                        {
                            "available": True,
                            "slope": [True],
                            "intercepts": [[0.0]],
                        }
                    ]
                }
            )


if __name__ == "__main__":
    unittest.main()
