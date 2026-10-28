#!/usr/bin/env python
"""Local two-principal gateway with origin-bound CTFR request identities.

The gateway is deliberately small and localhost-only.  It authenticates two
opaque bearer keys, binds each key to one experimental principal, removes all
client-supplied identity headers, replaces client request IDs with an internal
authenticated-principal prefix, and forwards both principals to one pinned
vLLM worker. It never records bearer-key material or prompt/output bodies.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

MAX_BODY_BYTES = 1024 * 1024
TENANTS = ("attacker", "victim")


def load_credentials(path: Path) -> dict[str, str]:
    payload = json.loads(path.read_text())
    expected = {"attacker", "victim", "upstream"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ValueError("credential file must contain attacker, victim, upstream")
    credentials: dict[str, str] = {}
    for name in sorted(expected):
        value = payload.get(name)
        if not isinstance(value, str) or len(value) < 32:
            raise ValueError(f"credential {name} is missing or too short")
        credentials[name] = value
    if len(set(credentials.values())) != len(credentials):
        raise ValueError("all three credentials must be distinct")
    return credentials


def fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def write(self, event: dict[str, Any]) -> None:
        rendered = json.dumps(event, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._stream.write(rendered + "\n")
            self._stream.flush()


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(
        self,
        address: tuple[str, int],
        *,
        credentials: dict[str, str],
        upstream_host: str,
        upstream_port: int,
        run_id: str,
        gateway_instance_id: str,
        upstream_marker: str,
        audit_path: Path,
    ) -> None:
        super().__init__(address, GatewayHandler)
        self.credentials = credentials
        self.key_fingerprints = {
            name: fingerprint(value) for name, value in credentials.items()
        }
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.run_id = run_id
        self.gateway_instance_id = gateway_instance_id
        self.upstream_marker = upstream_marker
        self.audit = AuditLog(audit_path)

    def authenticate(self, header: str | None) -> tuple[str | None, str | None]:
        if header is None or not header.startswith("Bearer "):
            return None, None
        supplied = header.removeprefix("Bearer ")
        for tenant in TENANTS:
            if hmac.compare_digest(supplied, self.credentials[tenant]):
                return tenant, self.key_fingerprints[tenant]
        return None, fingerprint(supplied)


class GatewayHandler(BaseHTTPRequestHandler):
    server: GatewayServer
    protocol_version = "HTTP/1.1"
    server_version = "AVEP-Tenant-Gateway/1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def _send_json(
        self,
        status: int,
        body: dict[str, Any],
        *,
        event_id: str,
        tenant: str | None = None,
    ) -> None:
        raw = json.dumps(body, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.send_header("X-AVEP-Audit-Event-ID", event_id)
        self.send_header(
            "X-AVEP-Gateway-Instance", self.server.gateway_instance_id
        )
        self.send_header("X-AVEP-Upstream-Marker", self.server.upstream_marker)
        if tenant is not None:
            self.send_header("X-AVEP-Authenticated-Tenant", tenant)
        self.end_headers()
        self.wfile.write(raw)

    def _audit(
        self,
        *,
        event_id: str,
        received_ns: int,
        finished_ns: int,
        tenant: str | None,
        key_fingerprint: str | None,
        claimed_principal: str | None,
        status: int,
        forwarded: bool,
        body: bytes,
        request_id: str | None,
        purpose: str,
        upstream_request_id: str | None = None,
    ) -> None:
        self.server.audit.write(
            {
                "schema_version": 2,
                "run_id": self.server.run_id,
                "event_id": event_id,
                "gateway_instance_id": self.server.gateway_instance_id,
                "received_ns": received_ns,
                "finished_ns": finished_ns,
                "authenticated_tenant": tenant,
                "key_sha256": key_fingerprint,
                "claimed_principal": claimed_principal,
                "method": self.command,
                "path": self.path,
                "purpose": purpose,
                "request_id": request_id,
                "upstream_request_id": upstream_request_id,
                "request_body_sha256": hashlib.sha256(body).hexdigest(),
                "status": status,
                "forwarded": forwarded,
                "upstream_host": self.server.upstream_host,
                "upstream_port": self.server.upstream_port,
                "upstream_marker": self.server.upstream_marker,
            }
        )

    def _handle(self) -> None:
        received_ns = time.time_ns()
        event_id = uuid.uuid4().hex
        tenant, key_fingerprint = self.server.authenticate(
            self.headers.get("Authorization")
        )
        claimed = self.headers.get("X-AVEP-Principal")
        purpose = self.headers.get("X-AVEP-Purpose", "workload")

        if self.path not in ("/v1/models", "/v1/completions"):
            status = 404
            self._audit(
                event_id=event_id,
                received_ns=received_ns,
                finished_ns=time.time_ns(),
                tenant=tenant,
                key_fingerprint=key_fingerprint,
                claimed_principal=claimed,
                status=status,
                forwarded=False,
                body=b"",
                request_id=None,
                purpose=purpose,
            )
            self._send_json(status, {"error": "route not allowed"}, event_id=event_id)
            return
        if tenant is None:
            status = 401
            self._audit(
                event_id=event_id,
                received_ns=received_ns,
                finished_ns=time.time_ns(),
                tenant=None,
                key_fingerprint=key_fingerprint,
                claimed_principal=claimed,
                status=status,
                forwarded=False,
                body=b"",
                request_id=None,
                purpose=purpose,
            )
            self._send_json(status, {"error": "unauthorized"}, event_id=event_id)
            return
        if claimed != tenant:
            status = 403
            self._audit(
                event_id=event_id,
                received_ns=received_ns,
                finished_ns=time.time_ns(),
                tenant=tenant,
                key_fingerprint=key_fingerprint,
                claimed_principal=claimed,
                status=status,
                forwarded=False,
                body=b"",
                request_id=None,
                purpose=purpose,
            )
            self._send_json(status, {"error": "principal mismatch"}, event_id=event_id)
            return

        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            status = 413
            self._audit(
                event_id=event_id,
                received_ns=received_ns,
                finished_ns=time.time_ns(),
                tenant=tenant,
                key_fingerprint=key_fingerprint,
                claimed_principal=claimed,
                status=status,
                forwarded=False,
                body=b"",
                request_id=None,
                purpose=purpose,
            )
            self._send_json(status, {"error": "invalid body size"}, event_id=event_id)
            return
        body = self.rfile.read(length) if length else b""
        request_id = None
        upstream_request_id = None
        forward_body = body
        if body:
            try:
                parsed = json.loads(body)
                candidate = (
                    parsed.get("request_id") if isinstance(parsed, dict) else None
                )
                request_id = candidate if isinstance(candidate, str) else None
                if self.path == "/v1/completions" and isinstance(parsed, dict):
                    upstream_request_id = (
                        f"ctfr-auth-{tenant}-{uuid.uuid4().hex}"
                    )
                    parsed["request_id"] = upstream_request_id
                    forward_body = json.dumps(
                        parsed, sort_keys=True, separators=(",", ":")
                    ).encode()
            except (UnicodeDecodeError, json.JSONDecodeError):
                request_id = None

        headers = {
            "Authorization": f"Bearer {self.server.credentials['upstream']}",
            "Content-Type": "application/json",
            "X-AVEP-Authenticated-Tenant": tenant,
            "X-AVEP-Gateway-Instance": self.server.gateway_instance_id,
        }
        upstream_url = (
            f"http://{self.server.upstream_host}:"
            f"{self.server.upstream_port}{self.path}"
        )
        upstream = urllib.request.Request(
            upstream_url,
            data=forward_body if self.command == "POST" else None,
            headers=headers,
            method=self.command,
        )
        response_headers: Any = None
        try:
            with urllib.request.urlopen(upstream, timeout=900) as response:
                status = response.status
                response_body = response.read()
                response_headers = response.headers
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_body = exc.read()
            response_headers = exc.headers
        except Exception as exc:
            status = 502
            response_body = json.dumps(
                {"error": f"upstream {type(exc).__name__}"}, sort_keys=True
            ).encode()

        self._audit(
            event_id=event_id,
            received_ns=received_ns,
            finished_ns=time.time_ns(),
            tenant=tenant,
            key_fingerprint=key_fingerprint,
            claimed_principal=claimed,
            status=status,
            forwarded=True,
            body=body,
            request_id=request_id,
            purpose=purpose,
            upstream_request_id=upstream_request_id,
        )
        self.send_response(status)
        content_type = (
            response_headers.get("Content-Type")
            if response_headers is not None
            else "application/json"
        )
        self.send_header("Content-Type", content_type or "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Connection", "close")
        self.send_header("X-AVEP-Authenticated-Tenant", tenant)
        self.send_header("X-AVEP-Audit-Event-ID", event_id)
        self.send_header(
            "X-AVEP-Gateway-Instance", self.server.gateway_instance_id
        )
        self.send_header("X-AVEP-Upstream-Marker", self.server.upstream_marker)
        self.end_headers()
        self.wfile.write(response_body)


def self_test(args: argparse.Namespace) -> int:
    credentials = load_credentials(args.credentials)
    cases = (
        ("attacker_ok", credentials["attacker"], "attacker", 200),
        ("victim_ok", credentials["victim"], "victim", 200),
        ("missing_key", None, "victim", 401),
        ("wrong_key", "invalid-key-material-for-negative-control", "victim", 401),
        ("attacker_claims_victim", credentials["attacker"], "victim", 403),
        ("victim_claims_attacker", credentials["victim"], "attacker", 403),
    )
    results = []
    for name, key, claimed, expected in cases:
        headers = {
            "X-AVEP-Principal": claimed,
            "X-AVEP-Purpose": "auth-self-test",
        }
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"
        request = urllib.request.Request(
            f"{args.base_url.rstrip('/')}/models", headers=headers, method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status = response.status
                response.read()
                response_headers = response.headers
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.read()
            response_headers = exc.headers
        result = {
            "name": name,
            "expected_status": expected,
            "status": status,
            "authenticated_tenant": response_headers.get(
                "X-AVEP-Authenticated-Tenant"
            ),
            "audit_event_id": response_headers.get("X-AVEP-Audit-Event-ID"),
            "gateway_instance_id": response_headers.get(
                "X-AVEP-Gateway-Instance"
            ),
            "upstream_marker": response_headers.get("X-AVEP-Upstream-Marker"),
        }
        results.append(result)
    valid = all(item["status"] == item["expected_status"] for item in results)
    valid = valid and results[0]["authenticated_tenant"] == "attacker"
    valid = valid and results[1]["authenticated_tenant"] == "victim"
    valid = valid and all(item["audit_event_id"] for item in results)
    artifact = {
        "schema_version": 1,
        "valid": valid,
        "base_url": args.base_url,
        "results": results,
    }
    args.output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    return 0 if valid else 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8001)
    serve.add_argument("--upstream-host", default="127.0.0.1")
    serve.add_argument("--upstream-port", type=int, default=8000)
    serve.add_argument("--credentials", type=Path, required=True)
    serve.add_argument("--run-id")
    serve.add_argument("--gateway-instance-id", required=True)
    serve.add_argument("--upstream-marker", required=True)
    serve.add_argument("--audit", type=Path, required=True)

    verify = subparsers.add_parser("self-test")
    verify.add_argument("--base-url", required=True)
    verify.add_argument("--credentials", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "self-test":
        return self_test(args)
    credentials = load_credentials(args.credentials)
    run_id = args.run_id or args.audit.parent.name
    if not run_id or run_id in {".", ".."}:
        raise ValueError("run identity is unavailable")
    server = GatewayServer(
        (args.host, args.port),
        credentials=credentials,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        run_id=run_id,
        gateway_instance_id=args.gateway_instance_id,
        upstream_marker=args.upstream_marker,
        audit_path=args.audit,
    )
    server.serve_forever(poll_interval=0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
