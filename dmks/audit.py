"""Tamper-evident audit log.

Each entry commits to its predecessor, so removing, reordering or editing any
past entry breaks the chain from that point on. The chain key never leaves the
server, which means the log is verifiable by whoever holds the key but is not
proof to a third party on its own. Export the chain plus the key fingerprint if
you need to hand evidence to someone else.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from typing import Any, Iterator

GENESIS = "0" * 64


def canonical(detail: Any) -> str:
    return json.dumps(detail, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(key: bytes, prev: str, seq: int, at: int, event: str, detail: Any) -> str:
    msg = "|".join([prev, str(seq), str(at), event, canonical(detail)]).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def append(
    conn: sqlite3.Connection, key: bytes, at: int, event: str, detail: Any = None
) -> sqlite3.Row:
    row = conn.execute(
        "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    prev = row["hash"] if row else GENESIS
    seq = (row["seq"] + 1) if row else 1
    digest = entry_hash(key, prev, seq, at, event, detail)

    conn.execute(
        "INSERT INTO audit_log(seq, at, event, detail, prev_hash, hash) VALUES(?,?,?,?,?,?)",
        (seq, at, event, canonical(detail), prev, digest),
    )
    return conn.execute("SELECT * FROM audit_log WHERE seq=?", (seq,)).fetchone()


def verify(conn: sqlite3.Connection, key: bytes) -> tuple[bool, int, int | None, str | None]:
    """Walk the whole chain. Returns (ok, entries, first_bad_seq, reason)."""
    prev = GENESIS
    expected_seq = 1
    count = 0
    for row in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        count += 1
        if row["seq"] != expected_seq:
            return False, count, row["seq"], f"expected seq {expected_seq}, found {row['seq']}"
        if row["prev_hash"] != prev:
            return False, count, row["seq"], "prev_hash does not match previous entry"
        detail = json.loads(row["detail"])
        if not hmac.compare_digest(
            row["hash"], entry_hash(key, prev, row["seq"], row["at"], row["event"], detail)
        ):
            return False, count, row["seq"], "entry hash mismatch"
        prev = row["hash"]
        expected_seq += 1
    return True, count, None, None


def iter_entries(conn: sqlite3.Connection, after_seq: int = 0) -> Iterator[sqlite3.Row]:
    for row in conn.execute("SELECT * FROM audit_log WHERE seq > ? ORDER BY seq", (after_seq,)):
        yield row


def head(conn: sqlite3.Connection) -> tuple[int, str]:
    row = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    return (row["seq"], row["hash"]) if row else (0, GENESIS)


def export(conn: sqlite3.Connection, key: bytes) -> str:
    """Self-contained export: entries plus the key fingerprint needed to verify."""
    ok, count, bad, reason = verify(conn, key)
    return json.dumps(
        {
            "format": "dmks-audit-v1",
            "chain_key_fingerprint": key_fingerprint(key),
            "verified": ok,
            "entries": count,
            "first_bad_seq": bad,
            "reason": reason,
            "log": [
                {
                    "seq": r["seq"],
                    "at": r["at"],
                    "event": r["event"],
                    "detail": json.loads(r["detail"]),
                    "prev_hash": r["prev_hash"],
                    "hash": r["hash"],
                }
                for r in iter_entries(conn)
            ],
        },
        indent=2,
        sort_keys=True,
    )


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(b"dmks-audit-key-fingerprint|" + key).hexdigest()[:32]