#!/usr/bin/env python
"""Bounded localhost workload generator for the AVEP paper experiments."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


CANARY_PROMPTS = (
    "The capital of France is",
    "2 + 2 equals",
    "In one word, the color of the sky is",
    "A triangle has three sides. Therefore",
    "Water freezes at a temperature of",
    "The opposite of hot is",
    "Complete the sequence: 1, 2, 3,",
    "A week contains seven",
)


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def prompt_for(index: int) -> str:
    """Return the same prompt distribution for every experimental arm."""
    return CANARY_PROMPTS[index % len(CANARY_PROMPTS)]


def send_request(args: argparse.Namespace, index: int) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": args.model,
        "prompt": prompt_for(index),
        "temperature": 0.0,
        "max_tokens": args.max_tokens,
        "ignore_eos": True,
        "seed": args.seed + index,
        "stream": False,
        "return_token_ids": args.return_token_ids,
        "request_id": (
            f"avep-{args.principal}-{args.phase}-{index:05d}"
        ),
    }
    if args.allowed_token_id is not None:
        payload["allowed_token_ids"] = [args.allowed_token_id]

    request = urllib.request.Request(
        f"{args.base_url.rstrip('/')}/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {args.api_key}",
            "Content-Type": "application/json",
            "X-AVEP-Principal": args.principal,
        },
        method="POST",
    )
    started_ns = time.time_ns()
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            body = json.loads(response.read())
        finished_ns = time.time_ns()
        choice = body["choices"][0]
        text = choice.get("text", "")
        return {
            "index": index,
            "ok": True,
            "started_ns": started_ns,
            "finished_ns": finished_ns,
            "latency_ms": (finished_ns - started_ns) / 1_000_000,
            "finish_reason": choice.get("finish_reason"),
            "output_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "token_ids": choice.get("token_ids") or [],
            "usage": body.get("usage") or {},
            "metrics": body.get("metrics") or {},
        }
    except urllib.error.HTTPError as exc:
        finished_ns = time.time_ns()
        return {
            "index": index,
            "ok": False,
            "started_ns": started_ns,
            "finished_ns": finished_ns,
            "latency_ms": (finished_ns - started_ns) / 1_000_000,
            "error": (
                f"HTTP {exc.code}: "
                f"{exc.read().decode(errors='replace')[:500]}"
            ),
        }
    except Exception as exc:
        finished_ns = time.time_ns()
        return {
            "index": index,
            "ok": False,
            "started_ns": started_ns,
            "finished_ns": finished_ns,
            "latency_ms": (finished_ns - started_ns) / 1_000_000,
            "error": f"{type(exc).__name__}: {exc}",
        }


def summarize(
    records: list[dict[str, Any]], allowed_token_id: int | None
) -> dict[str, Any]:
    successful = [record for record in records if record["ok"]]
    failed = [record for record in records if not record["ok"]]
    latencies = [record["latency_ms"] for record in successful]
    per_request_tps = [
        float(record["metrics"]["tokens_per_second"])
        for record in successful
        if record.get("metrics", {}).get("tokens_per_second") is not None
    ]
    spec_metrics = [
        record["metrics"]["speculative_decoding"]
        for record in successful
        if record.get("metrics", {}).get("speculative_decoding") is not None
    ]
    total_completion_tokens = sum(
        int(record.get("usage", {}).get("completion_tokens", 0))
        for record in successful
    )
    total_spec_steps = sum(int(metric["num_spec_steps"]) for metric in spec_metrics)
    total_drafted = sum(int(metric["num_draft_tokens"]) for metric in spec_metrics)
    total_accepted = sum(
        int(metric["num_accepted_draft_tokens"]) for metric in spec_metrics
    )

    wall_seconds = 0.0
    if successful:
        first_start = min(record["started_ns"] for record in successful)
        last_finish = max(record["finished_ns"] for record in successful)
        wall_seconds = (last_finish - first_start) / 1_000_000_000

    all_token_ids = [
        int(token_id)
        for record in successful
        for token_id in record.get("token_ids", [])
    ]
    control_fraction = None
    if allowed_token_id is not None and all_token_ids:
        control_fraction = sum(
            token_id == allowed_token_id for token_id in all_token_ids
        ) / len(all_token_ids)

    ordered_hashes = [record["output_sha256"] for record in successful]
    phase_digest = hashlib.sha256("".join(ordered_hashes).encode()).hexdigest()
    output_counts = Counter(ordered_hashes)
    return {
        "requests": len(records),
        "successful": len(successful),
        "failed": len(failed),
        "wall_seconds": wall_seconds,
        "completion_tokens": total_completion_tokens,
        "aggregate_output_tokens_per_second": (
            total_completion_tokens / wall_seconds if wall_seconds else None
        ),
        "latency_ms_p50": percentile(latencies, 0.50),
        "latency_ms_p95": percentile(latencies, 0.95),
        "latency_ms_p99": percentile(latencies, 0.99),
        "per_request_tokens_per_second_p50": percentile(per_request_tps, 0.50),
        "per_request_tokens_per_second_p95": percentile(per_request_tps, 0.95),
        "spec_requests": len(spec_metrics),
        "spec_steps": total_spec_steps,
        "draft_tokens": total_drafted,
        "accepted_draft_tokens": total_accepted,
        "draft_acceptance_rate": (
            total_accepted / total_drafted if total_drafted else None
        ),
        "phase_output_digest": phase_digest,
        "unique_output_count": len(output_counts),
        "most_common_output_count": (
            output_counts.most_common(1)[0][1] if output_counts else 0
        ),
        "control_token_fraction": control_fraction,
        "errors": [record.get("error") for record in failed[:10]],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    parser.add_argument("--principal", choices=("attacker", "victim"), required=True)
    parser.add_argument("--model", default="Qwen/Qwen3-4B")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/v1")
    parser.add_argument("--api-key", default="local-research-only")
    parser.add_argument("--requests", type=int, required=True)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--max-tokens", type=int, default=32)
    parser.add_argument("--allowed-token-id", type=int)
    parser.add_argument("--seed", type=int, default=20260918)
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--return-token-ids", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.requests < 1 or args.concurrency < 1 or args.max_tokens < 1:
        parser.error("requests, concurrency, and max-tokens must be positive")
    if args.concurrency > 64:
        parser.error("bounded probe caps concurrency at 64")
    if args.requests > 4096:
        parser.error("bounded probe caps requests at 4096")
    if args.max_tokens > 64:
        parser.error("bounded probe caps max-tokens at 64")
    return args


def main() -> None:
    args = parse_args()
    started_ns = time.time_ns()
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.concurrency
    ) as executor:
        futures = [
            executor.submit(send_request, args, index)
            for index in range(args.requests)
        ]
        records = [future.result() for future in futures]
    records.sort(key=lambda record: record["index"])
    finished_ns = time.time_ns()
    summary = summarize(records, args.allowed_token_id)
    artifact = {
        "config": {
            "phase": args.phase,
            "principal": args.principal,
            "model": args.model,
            "base_url": args.base_url,
            "requests": args.requests,
            "concurrency": args.concurrency,
            "max_tokens": args.max_tokens,
            "allowed_token_id": args.allowed_token_id,
            "seed": args.seed,
            "return_token_ids": args.return_token_ids,
        },
        "started_ns": started_ns,
        "finished_ns": finished_ns,
        "summary": summary,
        "records": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["failed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
