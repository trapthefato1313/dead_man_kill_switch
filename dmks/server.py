"""HTTP API.

Deliberately small. The only ways to change a switch's fate are `checkin`
(from an enrolled device, HMAC-authenticated) and `cancel` (owner-authenticated).
Everything else is read-only, plus `/api/tick` which only advances evaluation.
"""

from __future__ import annotations

import hmac
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import engine, liveness, runner, store
from .config import Config
from .deliver import Transport, build_transport

MAX_BODY = 64 * 1024


@dataclass
class Context:
    cfg: Config
    conn: sqlite3.Connection
    audit_key: bytes
    transport: Transport
    lock: threading.Lock = threading.Lock()
    now: Any = time.time


def _int(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise liveness.AuthError(f"{field} must be an integer") from exc


def _str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise liveness.AuthError(f"{field} must be a non-empty string")
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "dmks"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def ctx(self) -> Context:
        return self.server.ctx  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    def _send(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise liveness.AuthError("body too large")
        return json.loads(self.rfile.read(length))

    def _bearer(self) -> str:
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[7:].strip()
        return ""

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send(HTTPStatus.OK, {"ok": True, "at": int(self.ctx.now())})
            return
        if path == "/api/status":
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            switch_id = params.get("switch", "")
            with self.ctx.lock:
                try:
                    self._require_owner(switch_id)
                    payload = engine.status(self.ctx.conn, switch_id, int(self.ctx.now()))
                except KeyError:
                    self._send(HTTPStatus.NOT_FOUND, {"error": "unknown switch"})
                    return
                except liveness.AuthError as exc:
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
                    return
            self._send(HTTPStatus.OK, payload)
            return
        self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            payload = self._read_json()
        except (json.JSONDecodeError, liveness.AuthError) as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": f"bad body: {exc}"})
            return

        try:
            if path == "/api/checkin":
                self._handle_checkin(payload)
            elif path == "/api/cancel":
                self._handle_cancel(payload)
            elif path == "/api/tick":
                self._handle_tick()
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except liveness.AuthError as exc:
            self._send(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - never leak a stack trace to the client
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})

    def _handle_checkin(self, payload: dict) -> None:
        switch_id = _str(payload.get("switch"), "switch")
        device_id = _str(payload.get("device"), "device")
        ts = _int(payload.get("ts"), "ts")
        nonce = _str(payload.get("nonce"), "nonce")
        token = _str(payload.get("token"), "token")
        now = int(self.ctx.now())
        with self.ctx.lock:
            result = liveness.checkin(
                self.ctx.conn, self.ctx.audit_key, switch_id, device_id, ts, nonce, token, now
            )
        self._send(
            HTTPStatus.OK,
            {
                "ok": True,
                "at": result.at,
                "silence_broken": True,
                "note": "check-in accepted; escalation reset",
            },
        )

    def _handle_cancel(self, payload: dict) -> None:
        switch_id = _str(payload.get("switch"), "switch")
        ts = _int(payload.get("ts"), "ts")
        nonce = _str(payload.get("nonce"), "nonce")
        token = _str(payload.get("token"), "token")
        now = int(self.ctx.now())
        with self.ctx.lock:
            previous = liveness.cancel(
                self.ctx.conn, self.ctx.audit_key, switch_id, ts, nonce, token, now
            )
        self._send(HTTPStatus.OK, {"ok": True, "from_state": previous, "state": "ok"})

    def _handle_tick(self) -> None:
        expected = self.ctx.cfg.server.tick_token
        if not expected:
            self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "tick_token not configured"})
            return
        if not hmac.compare_digest(self._bearer(), expected):
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "bad tick token"})
            return
        with self.ctx.lock:
            summary = runner.run_tick(
                self.ctx.conn, self.ctx.audit_key, self.ctx.cfg, self.ctx.transport, int(self.ctx.now())
            )
        self._send(HTTPStatus.OK, summary)

    def _require_owner(self, switch_id: str) -> None:
        switch = store.get_switch(self.ctx.conn, switch_id)
        if switch is None:
            raise KeyError(switch_id)
        supplied = self.headers.get("X-Owner-Token", "")
        if not supplied:
            raise liveness.AuthError("X-Owner-Token header required")
        ts = int(self.ctx.now())
        if not liveness.owner_key_matches(switch["owner_key"], switch_id, ts, supplied):
            raise liveness.AuthError("bad owner token")


def serve(cfg: Config, conn: sqlite3.Connection, audit_key: bytes, *, verbose: bool = False) -> ThreadingHTTPServer:
    transport = build_transport(cfg)
    context = Context(cfg=cfg, conn=conn, audit_key=audit_key, transport=transport)
    httpd = ThreadingHTTPServer((cfg.server.host, cfg.server.port), Handler)
    httpd.ctx = context  # type: ignore[attr-defined]
    httpd.verbose = verbose  # type: ignore[attr-defined]
    httpd.daemon_threads = True
    return httpd