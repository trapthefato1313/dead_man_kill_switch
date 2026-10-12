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
FORCE_TAG = "force-release"
OWNER_DEVICE = "owner"


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


def sign_owner_force(secret: str, switch_id: str, ts: int, nonce: str) -> str:
    """Owner token for an explicit release, distinct from cancel."""
    msg = f"{FORCE_TAG}|{switch_id}|{ts}|{nonce}"
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


def hash_password(password: str, *, iterations: int = 200_000) -> str:
    """PBKDF2 verifier for the web panel.

    This never replaces `owner_key`: the owner secret still never leaves the
    server. The password only gates the panel, and is verified against a salted
    hash so a stolen database does not hand over the panel.
    """
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(encoded: str, password: str) -> bool:
    try:
        algo, iterations, salt_hex, digest_hex = encoded.split("$")
        if algo != "pbkdf2_sha256":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, actual)


def owner_checkin(
    conn: sqlite3.Connection,
    audit_key: bytes,
    switch_id: str,
    now: int,
) -> dict:
    """Proof of life from the owner, from any device, with no enrolled secret.

    This is what the panel button calls. The owner typing their password is the
    signal: it cannot be produced by a cron, so a scheduled task cannot keep the
    switch quiet on its own. It records under the reserved device id `owner`, so
    it flows through the same pruning, the same silence computation and the same
    audit chain as a device check-in, and cannot be mistaken for one.
    """
    switch = store.get_switch(conn, switch_id)
    if switch is None:
        raise AuthError("unknown switch")

    previous = switch["state"]
    # A fresh nonce every time. The device path gets its nonce from the client
    # to prove freshness; the owner path has no client, but checkins is
    # UNIQUE(device_id, nonce), so a fixed value here would allow exactly one
    # lifetime check-in and then start throwing IntegrityError.
    nonce = new_nonce()
    if previous == "released":
        # Terminal on purpose. Proof of life after release is good news for the
        # owner and worth a record, but it must never un-send the packet.
        with store.tx(conn):
            store.record_checkin(conn, switch_id, OWNER_DEVICE, nonce, now, now)
            head = audit.append(
                conn, audit_key, now, "owner_confirmed_after_release", {"switch": switch_id}
            )
    else:
        with store.tx(conn):
            store.record_checkin(conn, switch_id, OWNER_DEVICE, nonce, now, now)
            # Reset now, not on the next tick. The evidence is already durable;
            # leaving the switch on AVISO after the owner proved they are alive
            # would be a lie, and `armed` would be worse.
            store.update_switch(conn, switch_id, state="ok", now=now, confirm_count=0)
            head = audit.append(
                conn,
                audit_key,
                now,
                "owner_confirmed",
                {
                    "switch": switch_id,
                    "from_state": previous,
                    "note": "owner typed the panel password; a human is present",
                },
            )
    return {
        "switch": switch_id,
        "at": now,
        "from_state": previous,
        "state": store.get_switch(conn, switch_id)["state"],
        "receipt": {
            "audit_seq": head["seq"],
            "audit_hash": head["hash"],
            "prev_hash": head["prev_hash"],
            "at": now,
            "from_state": previous,
        },
    }


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


def force_release(
    conn: sqlite3.Connection,
    audit_key: bytes,
    switch_id: str,
    ts: int,
    nonce: str,
    token: str,
    now: int,
) -> str:
    """Owner-initiated release, bypassing the silence ladder.

    The owner is the only one who can do this, it needs the owner secret, and it
    is written to the audit log as an explicit act, so a release that did not
    come from silence is always distinguishable afterwards.

    Refuses a switch with nothing sealed: releasing an empty switch would
    destroy the evidence trail while delivering nothing.
    """
    switch = store.get_switch(conn, switch_id)
    if switch is None:
        raise AuthError("unknown switch")

    check_skew(ts, now, switch["clock_skew"])

    message = f"{FORCE_TAG}|{switch_id}|{ts}|{nonce}"
    if not hmac.compare_digest(_token(switch["owner_key"], message), token):
        raise AuthError("bad owner token")

    if not store.active_packets(conn, switch_id):
        raise AuthError("nothing sealed: seal a packet before forcing a release")

    previous = switch["state"]
    with store.tx(conn):
        store.update_switch(
            conn, switch_id, state="released", now=now, released_at=now, confirm_count=0
        )
        audit.append(
            conn,
            audit_key,
            now,
            "force_release",
            {"switch": switch_id, "from_state": previous},
        )
    return previous