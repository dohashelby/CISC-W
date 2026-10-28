#!/usr/bin/env python
"""Run a frozen, interleaved two-principal CTFR workload manifest."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PRINCIPALS = ("attacker", "victim")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def load_credentials(path: Path) -> dict[str, str]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise ValueError("credential file must contain a JSON object")
    credentials: dict[str, str] = {}
    for principal in PRINCIPALS:
        value = payload.get(principal)
        if not isinstance(value, str) or len(value) < 32:
            raise ValueError(f"credential for {principal} is missing or short")
        credentials[principal] = value
    if credentials["attacker"] == credentials["victim"]:
        raise ValueError("principal credentials must be distinct")
    return credentials


def validate_manifest(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("manifest must be a JSON object")
    if payload.get("schema") != "ctfr-workload-manifest-v1":
        raise ValueError("unsupported workload-manifest schema")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("manifest entries must be a non-empty list")
    if len(entries) > 8192:
        raise ValueError("bounded probe accepts at most 8192 entries")
    ordinals: set[int] = set()
    normalized: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each manifest entry must be an object")
        ordinal = entry.get("ordinal")
        wave = entry.get("wave")
        principal = entry.get("principal")
        prompt = entry.get("prompt")
        max_tokens = entry.get("max_tokens")
        seed = entry.get("seed")
        temperature = entry.get("temperature", 0.0)
        allowed = entry.get("allowed_token_ids")
        if (
            isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal < 0
            or ordinal in ordinals
        ):
            raise ValueError("entry ordinals must be unique non-negative integers")
        if isinstance(wave, bool) or not isinstance(wave, int) or wave < 0:
            raise ValueError("entry wave must be a non-negative integer")
        if principal not in PRINCIPALS:
            raise ValueError("entry principal must be attacker or victim")
        if not isinstance(prompt, str) or not prompt:
            raise ValueError("entry prompt must be a non-empty string")
        if (
            isinstance(max_tokens, bool)
            or not isinstance(max_tokens, int)
            or not 1 <= max_tokens <= 64
        ):
            raise ValueError("entry max_tokens must be in [1, 64]")
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ValueError("entry seed must be a non-negative integer")
        if (
            isinstance(temperature, bool)
            or not isinstance(temperature, (int, float))
            or temperature < 0
        ):
            raise ValueError("entry temperature must be non-negative")
        if allowed is not None and (
            not isinstance(allowed, list)
            or not allowed
            or any(
                isinstance(token, bool)
                or not isinstance(token, int)
                or token < 0
                for token in allowed
            )
        ):
            raise ValueError("allowed_token_ids must be null or token integers")
        ordinals.add(ordinal)
        normalized.append(dict(entry))
    normalized.sort(key=lambda entry: entry["ordinal"])
    if [entry["ordinal"] for entry in normalized] != list(range(len(entries))):
        raise ValueError("entry ordinals must be contiguous from zero")
    return normalized


def send_request(
    args: argparse.Namespace,
    credentials: dict[str, str],
    entry: dict[str, Any],
) -> dict[str, Any]:
    principal = entry["principal"]
    ordinal = entry["ordinal"]
    claimed_id_principal = principal
    if args.spoof_identity_headers:
        claimed_id_principal = (
            "victim" if principal == "attacker" else "attacker"
        )
    external_request_id = (
        "cmpl-ctfr-auth-"
        f"{claimed_id_principal}-client-spoof-{ordinal:05d}"
    )
    payload: dict[str, Any] = {
        "model": args.model,
        "prompt": entry["prompt"],
        "temperature": entry.get("temperature", 0.0),
        "max_tokens": entry["max_tokens"],
        "ignore_eos": True,
        "seed": entry["seed"],
        "stream": False,
        "return_token_ids": args.return_token_ids,
        "request_id": external_request_id,
    }
    if entry.get("allowed_token_ids") is not None:
        payload["allowed_token_ids"] = entry["allowed_token_ids"]
    request = urllib.request.Request(
        f"{args.base_url.rstrip('/')}/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {credentials[principal]}",
            "Content-Type": "application/json",
            "X-AVEP-Principal": principal,
            "X-AVEP-Purpose": args.phase,
            "X-Request-ID": (
                f"cmpl-ctfr-auth-{claimed_id_principal}-header-spoofed"
                if args.spoof_identity_headers
                else external_request_id
            ),
        },
        method="POST",
    )
    started_ns = time.time_ns()
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            body = json.loads(response.read())
            headers = response.headers
        finished_ns = time.time_ns()
        choice = body["choices"][0]
        text = choice.get("text", "")
        return {
            "ordinal": ordinal,
            "wave": entry["wave"],
            "principal": principal,
            "allowed_token_ids": entry.get("allowed_token_ids"),
            "external_request_id": external_request_id,
            "ok": True,
            "started_ns": started_ns,
            "finished_ns": finished_ns,
            "latency_ms": (finished_ns - started_ns) / 1_000_000,
            "finish_reason": choice.get("finish_reason"),
            "output_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "token_ids": choice.get("token_ids") or [],
            "usage": body.get("usage") or {},
            "metrics": body.get("metrics") or {},
            "authenticated_tenant": headers.get(
                "X-AVEP-Authenticated-Tenant"
            ),
            "audit_event_id": headers.get("X-AVEP-Audit-Event-ID"),
            "gateway_instance_id": headers.get("X-AVEP-Gateway-Instance"),
            "upstream_marker": headers.get("X-AVEP-Upstream-Marker"),
        }
    except urllib.error.HTTPError as exc:
        finished_ns = time.time_ns()
        return {
            "ordinal": ordinal,
            "wave": entry["wave"],
            "principal": principal,
            "external_request_id": external_request_id,
            "ok": False,
            "latency_ms": (finished_ns - started_ns) / 1_000_000,
            "error": f"HTTP {exc.code}: {exc.read().decode(errors='replace')[:500]}",
        }
    except Exception as exc:
        finished_ns = time.time_ns()
        return {
            "ordinal": ordinal,
            "wave": entry["wave"],
            "principal": principal,
            "external_request_id": external_request_id,
            "ok": False,
            "latency_ms": (finished_ns - started_ns) / 1_000_000,
            "error": f"{type(exc).__name__}: {exc}",
        }


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [record for record in records if record["ok"]]
    latencies = [float(record["latency_ms"]) for record in successful]
    completion_tokens = sum(
        int(record.get("usage", {}).get("completion_tokens", 0))
        for record in successful
    )
    wall_seconds = 0.0
    if successful:
        first = min(record["started_ns"] for record in successful)
        last = max(record["finished_ns"] for record in successful)
        wall_seconds = (last - first) / 1_000_000_000
    spec_metrics = [
        record["metrics"]["speculative_decoding"]
        for record in successful
        if record.get("metrics", {}).get("speculative_decoding") is not None
    ]
    drafted = sum(int(metric["num_draft_tokens"]) for metric in spec_metrics)
    accepted = sum(
        int(metric["num_accepted_draft_tokens"]) for metric in spec_metrics
    )
    return {
        "requests": len(records),
        "successful": len(successful),
        "failed": len(records) - len(successful),
        "completion_tokens": completion_tokens,
        "wall_seconds": wall_seconds,
        "aggregate_output_tokens_per_second": (
            completion_tokens / wall_seconds if wall_seconds else None
        ),
        "latency_ms_p50": percentile(latencies, 0.50),
        "latency_ms_p95": percentile(latencies, 0.95),
        "latency_ms_p99": percentile(latencies, 0.99),
        "spec_requests": len(spec_metrics),
        "draft_tokens": drafted,
        "accepted_draft_tokens": accepted,
        "draft_acceptance_rate": accepted / drafted if drafted else None,
    }


def summarize(
    records: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record["principal"]].append(record)
    successful = [record for record in records if record["ok"]]
    expected = Counter(entry["principal"] for entry in entries)
    authenticated = Counter(
        record.get("authenticated_tenant") for record in successful
    )
    audit_ids = [record.get("audit_event_id") for record in successful]
    summary = summarize_records(records)
    summary["by_principal"] = {
        principal: summarize_records(grouped[principal])
        for principal in PRINCIPALS
    }
    summary["expected_principal_counts"] = dict(expected)
    summary["authenticated_principal_counts"] = dict(authenticated)
    summary["unique_audit_event_ids"] = len(set(audit_ids))
    summary["missing_audit_event_ids"] = sum(
        audit_id is None for audit_id in audit_ids
    )
    summary["gateway_instance_counts"] = dict(
        Counter(record.get("gateway_instance_id") for record in successful)
    )
    summary["upstream_marker_counts"] = dict(
        Counter(record.get("upstream_marker") for record in successful)
    )
    summary["evidence_ok"] = (
        summary["failed"] == 0
        and authenticated == expected
        and summary["unique_audit_event_ids"] == len(entries)
        and summary["missing_audit_event_ids"] == 0
        and summary["gateway_instance_counts"]
        == {args.gateway_instance_id: len(entries)}
        and summary["upstream_marker_counts"]
        == {args.upstream_marker: len(entries)}
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--gateway-instance-id", required=True)
    parser.add_argument("--upstream-marker", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default="Qwen/Qwen3-4B")
    parser.add_argument("--base-url", default="http://127.0.0.1:8001/v1")
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--waves-per-batch", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--return-token-ids", action="store_true")
    parser.add_argument("--spoof-identity-headers", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.concurrency <= 64:
        parser.error("concurrency must be in [1, 64]")
    if not 1 <= args.waves_per_batch <= 64:
        parser.error("waves-per-batch must be in [1, 64]")
    return args


def main() -> None:
    args = parse_args()
    manifest = read_json(args.manifest)
    entries = validate_manifest(manifest)
    credentials = load_credentials(args.credentials)
    by_wave: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        by_wave[entry["wave"]].append(entry)

    started_ns = time.time_ns()
    records: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.concurrency
    ) as executor:
        waves = sorted(by_wave)
        for offset in range(0, len(waves), args.waves_per_batch):
            batch_waves = waves[offset : offset + args.waves_per_batch]
            batch_entries = [
                entry
                for wave in batch_waves
                for entry in by_wave[wave]
            ]
            if len(batch_entries) > args.concurrency:
                raise ValueError(
                    "waves-per-batch creates more entries than configured "
                    "concurrency"
                )
            futures = [
                executor.submit(send_request, args, credentials, entry)
                for entry in batch_entries
            ]
            records.extend(future.result() for future in futures)
    records.sort(key=lambda record: record["ordinal"])
    finished_ns = time.time_ns()
    summary = summarize(records, entries, args)
    artifact = {
        "config": {
            "phase": args.phase,
            "run_id": args.run_id,
            "gateway_instance_id": args.gateway_instance_id,
            "upstream_marker": args.upstream_marker,
            "model": args.model,
            "base_url": args.base_url,
            "concurrency": args.concurrency,
            "waves_per_batch": args.waves_per_batch,
            "manifest_sha256": canonical_sha256(manifest),
            "manifest_path": str(args.manifest),
            "return_token_ids": args.return_token_ids,
            "spoof_identity_headers": args.spoof_identity_headers,
            "credential_sha256": {
                principal: hashlib.sha256(value.encode()).hexdigest()
                for principal, value in credentials.items()
            },
        },
        "started_ns": started_ns,
        "finished_ns": finished_ns,
        "summary": summary,
        "records": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not summary["evidence_ok"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
