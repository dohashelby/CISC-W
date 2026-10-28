#!/usr/bin/env python
"""Extract a canonical CTFR baseline from a collective-RPC state snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any


def unwrap_state(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("snapshot must contain a JSON object")
    results = payload.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise ValueError("single-worker snapshot must contain exactly one result")
    state = results[0]
    if not isinstance(state, dict) or state.get("available") is not True:
        raise ValueError("acceptance-estimator state is unavailable")
    return state


def extract(payload: Any) -> dict[str, Any]:
    state = unwrap_state(payload)
    slopes = state.get("slope")
    intercept_banks = state.get("intercepts")
    if not isinstance(slopes, list) or not slopes:
        raise ValueError("snapshot slope banks are missing")
    if not isinstance(intercept_banks, list) or not intercept_banks:
        raise ValueError("snapshot intercept banks are missing")
    slope = slopes[0]
    intercepts = intercept_banks[0]
    if (
        isinstance(slope, bool)
        or not isinstance(slope, (int, float))
        or not math.isfinite(slope)
    ):
        raise ValueError("canonical slope is not finite")
    if not isinstance(intercepts, list) or not intercepts:
        raise ValueError("canonical intercepts are missing")
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        for value in intercepts
    ):
        raise ValueError("canonical intercepts are not finite")
    baseline = {
        "slope": float(slope),
        "intercepts": [float(value) for value in intercepts],
    }
    canonical = json.dumps(
        baseline, sort_keys=True, separators=(",", ":")
    ).encode()
    return {
        "schema": "ctfr-baseline-v1",
        **baseline,
        "coefficient_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    baseline = extract(json.loads(args.state.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n")
    print(json.dumps(baseline, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
