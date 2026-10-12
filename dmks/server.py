"""HTTP interface.

Two audiences, deliberately separated:

  * the panel (browser) - authenticates with an owner password, gets an
    in-memory session, and can check in from any device without an enrolled
    secret. The password is re-asked for the check-in itself, so a stolen
    cookie cannot keep the switch alive on its own.

  * the API (programs) - unchanged: `checkin` from an enrolled device with an
    HMAC token, `cancel` with the owner token, `tick` with the tick token.

The owner secret never leaves the server in either case.
"""

from __future__ import annotations

import hmac
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import audit, clockguard, engine, liveness, runner, store
from .config import Config
from .deliver import Transport, build_transport
from .webui import PAGE

MAX_BODY = 64 * 1024
SESSION_TTL = 3600
COOKIE = "dmks_session"
LOGIN_WINDOW = 900
LOGIN_MAX_FAILURES = 10


class TooManyAttempts(liveness.AuthError):
    """Raised when a password has been guessed at too often from one source."""


@dataclass
class Context:
    cfg: Config
    conn: sqlite3.Connection
    audit_key: bytes
    transport: Transport
    lock: threading.Lock = threading.Lock()
    now: Any = time.time
    sessions: dict[str, tuple[str, float]] = field(default_factory=dict)
    failures: dict[str, list[float]] = field(default_factory=dict)

    def _prune_failures(self, who: str) -> list[float]:
        cutoff = self.now() - LOGIN_WINDOW
        kept = [t for t in self.failures.get(who, []) if t > cutoff]
        self.failures[who] = kept
        return kept

    def note_password_failure(self, who: str) -> None:
        """Count a wrong password. The panel is on the public internet; without
        this, the owner password is the only thing between an attacker and the
        ability to keep the switch quiet forever."""
        with self.lock:
            self._prune_failures(who).append(self.now())

    def password_throttled(self, who: str) -> bool:
        with self.lock:
            return len(self._prune_failures(who)) >= LOGIN_MAX_FAILURES

    def clear_password_failures(self, who: str) -> None:
        with self.lock:
            self.failures.pop(who, None)

    def session_for(self, token: str) -> str | None:
        """Return the switch a session may act on, sliding the expiry.

        Sessions are in memory only. A restart logs the owner out, which is the
        safe direction to fail in.
        """
        if not token:
            return None
        with self.lock:
            entry = self.sessions.get(token)
            if entry is None:
                return None
            switch_id, expires = entry
            if expires < self.now():
                self.sessions.pop(token, None)
                return None
            self.sessions[token] = (switch_id, self.now() + SESSION_TTL)
            return switch_id

    def open_session(self, switch_id: str) -> str:
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[token] = (switch_id, self.now() + SESSION_TTL)
        return token


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

    def _cookie(self) -> str:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return value
        return ""

    def _send_html(self, status: HTTPStatus, body: str) -> None:
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(raw)

    def _send(self, status: HTTPStatus, payload: dict, cookie: str | None = None) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie:
            self.send_header(
                "Set-Cookie", f"{COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"
            )
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
        if path == "/":
            self._send_html(HTTPStatus.OK, PAGE)
            return
        if path == "/health":
            self._send(HTTPStatus.OK, {"ok": True, "at": int(self.ctx.now())})
            return
        if path == "/api/panel":
            self._handle_panel()
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

    def _first_switch(self) -> str:
        row = self.ctx.conn.execute("SELECT id FROM switches ORDER BY created_at LIMIT 1").fetchone()
        if row is None:
            raise KeyError("no switch")
        return row["id"]

    def _require_session(self) -> str:
        """The panel gate. A session cookie only, never the owner token header."""
        switch_id = self.ctx.session_for(self._cookie())
        if not switch_id:
            raise liveness.AuthError("no session")
        with self.ctx.lock:
            if store.get_switch(self.ctx.conn, switch_id) is None:
                raise liveness.AuthError("unknown switch")
        return switch_id

    def _verify_password(self, switch_id: str, password: str, who: str) -> None:
        """Read the hash under the lock, then verify outside it.

        Verification is pure CPU, and note_password_failure takes the same lock,
        so keeping the two apart is what stops a self-deadlock on wrong input.
        """
        with self.ctx.lock:
            encoded = store.get_owner_pwhash(self.ctx.conn, switch_id)
        if not encoded:
            raise liveness.AuthError(
                "no owner password set for this switch; set one with: dmks owner-password"
            )
        if not liveness.verify_password(encoded, password):
            self.ctx.note_password_failure(who)
            raise liveness.AuthError("wrong password")

    def _handle_panel(self) -> None:
        try:
            switch_id = self._require_session()
            now = int(self.ctx.now())
            with self.ctx.lock:
                status = engine.status(self.ctx.conn, switch_id, now)
                switch = store.get_switch(self.ctx.conn, switch_id)
                status["warn_after_seconds"] = switch["warn_after"]
                status["arm_after_seconds"] = switch["arm_after"]
                status["release_after_seconds"] = switch["release_after"]
                status["last_checkin_at"] = store.last_checkin_at(self.ctx.conn, switch_id)
                status["notes"] = []
                watermark = store.clock_watermark(self.ctx.conn) or now
                ok, count, bad, reason = audit.verify(self.ctx.conn, self.ctx.audit_key)
                sources = tuple(
                    url for sw in self.ctx.cfg.switches.values() for url in (sw.time_sources or ())
                )
                verdict = clockguard.assess(now, sources)
                configured = self.ctx.cfg.switches.get(switch_id)
                max_credit = configured.max_credit if configured else 3 * 86400
            self._send(
                HTTPStatus.OK,
                {
                    "status": status,
                    "clock": {
                        "status": verdict.status,
                        "external": verdict.external,
                        "max_credit": max_credit,
                    },
                    "audit": {"ok": ok, "count": count, "reason": reason},
                    "watermark": watermark,
                },
            )
        except KeyError:
            self._send(HTTPStatus.NOT_FOUND, {"error": "no switch"})
        except liveness.AuthError as exc:
            self._send(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            payload = self._read_json()
        except (json.JSONDecodeError, liveness.AuthError) as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": f"bad body: {exc}"})
            return

        try:
            if path == "/api/login":
                self._handle_login(payload)
            elif path == "/api/logout":
                self._handle_logout()
            elif path == "/api/confirm":
                self._handle_confirm(payload)
            elif path == "/api/checkin":
                self._handle_checkin(payload)
            elif path == "/api/cancel":
                self._handle_cancel(payload)
            elif path == "/api/tick":
                self._handle_tick()
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except TooManyAttempts as exc:
            self._send(HTTPStatus.TOO_MANY_REQUESTS, {"error": str(exc)})
        except liveness.AuthError as exc:
            self._send(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - never leak a stack trace to the client
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})

    def _throttle(self) -> None:
        who = self.client_address[0]
        if self.ctx.password_throttled(who):
            raise TooManyAttempts(
                f"too many wrong passwords from {who}; wait {LOGIN_WINDOW // 60} minutes"
            )

    def _handle_login(self, payload: dict) -> None:
        password = _str(payload.get("password"), "password")
        who = self.client_address[0]
        self._throttle()
        with self.ctx.lock:
            switch_id = self._first_switch()
        self._verify_password(switch_id, password, who)
        self.ctx.clear_password_failures(who)
        token = self.ctx.open_session(switch_id)
        self._send(HTTPStatus.OK, {"ok": True, "switch": switch_id}, cookie=token)

    def _handle_logout(self) -> None:
        with self.ctx.lock:
            self.ctx.sessions.pop(self._cookie(), None)
        self._send(HTTPStatus.OK, {"ok": True})

    def _handle_confirm(self, payload: dict) -> None:
        """The panel button. Password again on purpose.

        The session proves the owner is at this browser; the password is asked
        again because a session that could check in by itself would let anyone
        who found an open tab keep the switch quiet forever.
        """
        password = _str(payload.get("password"), "password")
        switch_id = self._require_session()
        now = int(self.ctx.now())
        who = self.client_address[0]
        self._throttle()
        self._verify_password(switch_id, password, who)
        with self.ctx.lock:
            result = liveness.owner_checkin(self.ctx.conn, self.ctx.audit_key, switch_id, now)
        self.ctx.clear_password_failures(who)
        self._send(HTTPStatus.OK, result)

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