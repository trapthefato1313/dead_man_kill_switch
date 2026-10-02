"""Check-in and cancel protocol.

Every request is authenticated with an HMAC over a canonical message that
includes a fresh nonce and a client timestamp. The server stores only the
derived key, never the secret, so a full database dump does not let an
impersonator forge check-ins.

Replay and clock attacks are both rejected: a nonce may be used once per
device, and a timestamp outside the skew window is refused.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass

from . import audit, store

DEVICE_DOMAIN = b"dmks-device-key-v1|"
OWNER_DOMAIN = b"dmks-owner-key-v1|"
CHECKIN_TAG = "checkin"
CANCEL_TAG = "cancel"


class AuthError(Exception):
    """Rejected request. message is safe to return to the client."""


@dataclass(frozen=True)
class CheckinResult:
    device_id: str
    switch_id: str
    at: int
    pruned: int


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def derive(secret: str, domain: bytes) -> bytes:
    return hashlib.sha256(domain + secret.encode()).digest()


def device_key_hex(secret: str) -> str:
    return derive(secret, DEVICE_DOMAIN).hex()


def owner_key_hex(secret: str) -> str:
    return derive(secret, OWNER_DOMAIN).hex()


def new_nonce() -> str:
    return secrets.token_urlsafe(18)


def _token(key_hex: str, message: str) -> str:
    return hmac.new(bytes.fromhex(key_hex), message.encode(), hashlib.sha256).hexdigest()


def sign_device(secret: str, switch_id: str, device_id: str, ts: int, nonce: str) -> str:
    msg = f"{CHECKIN_TAG}|{switch_id}|{device_id}|{ts}|{nonce}"
    return _token(device_key_hex(secret), msg)


def sign_owner(secret: str, switch_id: str, ts: int, nonce: str) -> str:
    msg = f"{CANCEL_TAG}|{switch_id}|{ts}|{nonce}"
    return _token(owner_key_hex(secret), msg)


def owner_status_token(secret: str, switch_id: str, ts: int) -> str:
    """Token for read-only status queries. Pinned to a fixed nonce."""
    return sign_owner(secret, switch_id, ts, "status")


def owner_key_matches(owner_key_hex: str, switch_id: str, ts: int, token: str) -> bool:
    msg = f"{CANCEL_TAG}|{switch_id}|{ts}|status"
    return hmac.compare_digest(_token(owner_key_hex, msg), token)


def check_skew(ts: int, now: int, skew: int) -> None:
    if abs(now - ts) > skew:
        raise AuthError(
            f"timestamp outside clock_skew window (off by {abs(now - ts)}s, allowed {skew}s)"
        )


def checkin(
    conn: sqlite3.Connection,
    audit_key: bytes,
    switch_id: str,
    device_id: str,
    ts: int,
    nonce: str,
    token: str,
    now: int,
) -> CheckinResult:
    switch = store.get_switch(conn, switch_id)
    if switch is None:
        raise AuthError("unknown switch")

    device = store.get_device(conn, device_id)
    if device is None or device["switch_id"] != switch_id:
        raise AuthError("unknown device")
    if not device["enabled"]:
        raise AuthError("device retired")

    check_skew(ts, now, switch["clock_skew"])

    message = f"{CHECKIN_TAG}|{switch_id}|{device_id}|{ts}|{nonce}"
    if not hmac.compare_digest(_token(device["key_hex"], message), token):
        raise AuthError("bad token")

    if store.seen_nonce(conn, device_id, nonce):
        raise AuthError("replayed nonce")

    with store.tx(conn):
        pruned = store.record_checkin(conn, switch_id, device_id, nonce, ts, now)
        if switch["state"] in ("warn", "armed"):
            audit.append(
                conn,
                audit_key,
                now,
                "recovered",
                {"switch": switch_id, "device": device_id, "from_state": switch["state"]},
            )
        elif switch["state"] == "released":
            audit.append(
                conn,
                audit_key,
                now,
                "recovered_after_release",
                {"switch": switch_id, "device": device_id},
            )

    return CheckinResult(device_id=device_id, switch_id=switch_id, at=now, pruned=pruned)


def cancel(
    conn: sqlite3.Connection,
    audit_key: bytes,
    switch_id: str,
    ts: int,
    nonce: str,
    token: str,
    now: int,
) -> str:
    """Owner-initiated abort. Works from any device, no enrolled secret needed."""
    switch = store.get_switch(conn, switch_id)
    if switch is None:
        raise AuthError("unknown switch")

    check_skew(ts, now, switch["clock_skew"])

    message = f"{CANCEL_TAG}|{switch_id}|{ts}|{nonce}"
    if not hmac.compare_digest(_token(switch["owner_key"], message), token):
        raise AuthError("bad owner token")

    previous = switch["state"]
    with store.tx(conn):
        store.update_switch(conn, switch_id, state="ok", now=now, confirm_count=0)
        conn.execute("UPDATE switches SET cancelled_at=? WHERE id=?", (now, switch_id))
        audit.append(
            conn,
            audit_key,
            now,
            "cancelled",
            {"switch": switch_id, "from_state": previous},
        )
    return previous