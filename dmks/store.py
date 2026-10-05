"""Durable state. SQLite in WAL mode with FULL sync.

Reliability notes:
  * synchronous=FULL so a committed escalation survives power loss.
  * Every state change is written in the same transaction as the audit entry
    that records it, so the log and the state can never disagree.
  * The clock watermark lives here: it stops a backwards clock jump from
    un-escalating or prematurely releasing a switch.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS switches (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    warn_after     INTEGER NOT NULL,
    arm_after      INTEGER NOT NULL,
    release_after  INTEGER NOT NULL,
    device_grace   INTEGER NOT NULL,
    quorum_mode    TEXT NOT NULL,
    quorum_n       INTEGER NOT NULL,
    confirmations  INTEGER NOT NULL,
    release_mode   TEXT NOT NULL,
    clock_skew     INTEGER NOT NULL,
    recipients     TEXT NOT NULL,
    owner_key      TEXT NOT NULL,
    state          TEXT NOT NULL,
    state_since    INTEGER NOT NULL,
    confirm_count  INTEGER NOT NULL DEFAULT 0,
    confirm_target TEXT,
    last_evaluated INTEGER NOT NULL,
    released_at    INTEGER,
    cancelled_at   INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq       INTEGER PRIMARY KEY,
    at        INTEGER NOT NULL,
    event     TEXT NOT NULL,
    detail    TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id          TEXT PRIMARY KEY,
    switch_id   TEXT NOT NULL REFERENCES switches(id),
    label       TEXT NOT NULL,
    key_hex     TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    enrolled_at INTEGER NOT NULL,
    retired_at  INTEGER,
    last_seen   INTEGER
);
CREATE INDEX IF NOT EXISTS devices_by_switch ON devices(switch_id, enabled);

CREATE TABLE IF NOT EXISTS checkins (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    nonce     TEXT NOT NULL,
    client_ts INTEGER NOT NULL,
    at        INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS checkins_nonce ON checkins(device_id, nonce);
CREATE INDEX IF NOT EXISTS checkins_recent ON checkins(switch_id, at);

CREATE TABLE IF NOT EXISTS packets (
    id           TEXT PRIMARY KEY,
    switch_id    TEXT NOT NULL REFERENCES switches(id),
    filename     TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size         INTEGER NOT NULL,
    recipients   TEXT NOT NULL,
    note         TEXT,
    created_at   INTEGER NOT NULL,
    retired_at   INTEGER
);
CREATE INDEX IF NOT EXISTS packets_by_switch ON packets(switch_id, retired_at);

CREATE TABLE IF NOT EXISTS deliveries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id  TEXT NOT NULL,
    packet_id  TEXT NOT NULL,
    target     TEXT NOT NULL,
    mode       TEXT NOT NULL,
    channel    TEXT NOT NULL DEFAULT '',
    ok         INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 1,
    last_error TEXT,
    at         INTEGER NOT NULL,
    UNIQUE(switch_id, packet_id, target, mode, channel)
);

CREATE TABLE IF NOT EXISTS notices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    bucket     TEXT NOT NULL,
    ok         INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 1,
    last_error TEXT,
    at         INTEGER NOT NULL,
    UNIQUE(switch_id, kind, bucket)
);

CREATE TABLE IF NOT EXISTS watchdog (
    key         TEXT PRIMARY KEY,
    last_tick   INTEGER NOT NULL,
    last_alert  INTEGER
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    _migrate(conn)
    _set_meta(conn, "schema_version", str(SCHEMA_VERSION))
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}


def _migrate(conn: sqlite3.Connection) -> None:
    """v1 -> v2: deliveries gains a per-channel column.

    The UNIQUE constraint changed too, which SQLite cannot alter in place, so
    the table is rebuilt. Pre-v2 rows carry channel '' and stay delivered.
    """
    if "channel" in _columns(conn, "deliveries"):
        return
    conn.executescript(
        """
        BEGIN IMMEDIATE;
        ALTER TABLE deliveries RENAME TO deliveries_v1;
        CREATE TABLE deliveries (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            switch_id  TEXT NOT NULL,
            packet_id  TEXT NOT NULL,
            target     TEXT NOT NULL,
            mode       TEXT NOT NULL,
            channel    TEXT NOT NULL DEFAULT '',
            ok         INTEGER NOT NULL,
            attempts   INTEGER NOT NULL DEFAULT 1,
            last_error TEXT,
            at         INTEGER NOT NULL,
            UNIQUE(switch_id, packet_id, target, mode, channel)
        );
        INSERT INTO deliveries(switch_id, packet_id, target, mode, channel,
                               ok, attempts, last_error, at)
        SELECT switch_id, packet_id, target, mode, '', ok, attempts, last_error, at
          FROM deliveries_v1;
        DROP TABLE deliveries_v1;
        COMMIT;
        """
    )


class tx:
    """Immediate transaction. Nested use joins the outer transaction."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.outermost = False

    def __enter__(self) -> sqlite3.Connection:
        self.outermost = not self.conn.in_transaction
        if self.outermost:
            self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self.outermost:
            if exc_type is None:
                self.conn.execute("COMMIT")
            else:
                self.conn.execute("ROLLBACK")
        return False


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    _set_meta(conn, key, value)


def clock_watermark(conn: sqlite3.Connection) -> int:
    raw = get_meta(conn, "clock_watermark", "0")
    try:
        return int(raw or 0)
    except ValueError:
        return 0


def _resolve_arm(warn: int, arm: int | None, release: int) -> int:
    """Two deadlines are enough: the armed step is the midpoint.

    Stored explicitly so the engine never has to guess and the value that
    actually governs the state machine is the one on disk.
    """
    if arm is not None:
        return arm
    return warn + max(1, (release - warn) // 2)


def credit_time(
    conn: sqlite3.Connection,
    observed: int,
    max_credit: int,
    corroborated: bool = False,
    reference: int | None = None,
) -> tuple[int, int | None]:
    """Advance trusted time by at most `max_credit`, returning (now, discarded).

    The watermark stores *credited* time, not observed time. That distinction is
    the whole fix: if it stored observed time, a single large jump would push it
    decades into the future and the next tick would credit all of it.

    A backwards clock yields the watermark unchanged and discards nothing: the
    regression is simply not real time. A forwards jump is capped unless a
    second clock corroborated it, so a ten-year NTP step cannot turn into ten
    years of silence. Real downtime is still caught, just over several
    evaluations instead of one.

    `reference` anchors the very first reading to when the switch was created.
    Without it a fresh database would adopt a badly wrong clock without
    complaint, and the switch could never have more history than its own life.
    """
    raw = get_meta(conn, "clock_watermark")
    if raw is None:
        base = observed if reference is None else int(reference)
        adopted = observed if corroborated else min(observed, base + max_credit)
        set_meta(conn, "clock_watermark", str(adopted))
        return adopted, (observed - adopted) or None
    watermark = int(raw)
    if observed <= watermark:
        return watermark, None
    delta = observed - watermark
    if corroborated:
        credited = delta
    else:
        credited = min(delta, max_credit)
    effective = watermark + credited
    set_meta(conn, "clock_watermark", str(effective))
    return effective, delta - credited or None


def create_switch(
    conn: sqlite3.Connection,
    switch_id: str,
    *,
    name: str,
    owner_key: str,
    recipients: Iterable[dict],
    now: int,
    **thresholds: Any,
) -> None:
    import json

    columns = (
        "id", "name", "created_at", "warn_after", "arm_after", "release_after",
        "device_grace", "quorum_mode", "quorum_n", "confirmations", "release_mode",
        "clock_skew", "recipients", "owner_key", "state", "state_since",
        "confirm_count", "confirm_target", "last_evaluated",
    )
    values = (
        switch_id,
        name,
        now,
        thresholds["warn_after"],
        _resolve_arm(thresholds["warn_after"], thresholds["arm_after"], thresholds["release_after"]),
        thresholds["release_after"],
        thresholds["device_grace"],
        thresholds["quorum_mode"],
        thresholds["quorum_n"],
        thresholds["confirmations"],
        thresholds["release_mode"],
        thresholds["clock_skew"],
        json.dumps(list(recipients)),
        owner_key,
        "ok",
        now,
        0,
        None,
        now,
    )
    placeholders = ", ".join("?" * len(columns))
    conn.execute(
        f"INSERT INTO switches({', '.join(columns)}) VALUES({placeholders})",
        values,
    )


def get_switch(conn: sqlite3.Connection, switch_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM switches WHERE id=?", (switch_id,)).fetchone()


def list_switches(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM switches ORDER BY created_at, id"))


def update_switch(
    conn: sqlite3.Connection,
    switch_id: str,
    *,
    state: str,
    now: int,
    released_at: int | None = None,
    confirm_count: int | None = None,
    confirm_target: str | None = None,
) -> None:
    sets = ["state=?", "state_since=?", "last_evaluated=?"]
    args: list[Any] = [state, now, now]
    if released_at is not None:
        sets.append("released_at=?")
        args.append(released_at)
    if confirm_count is not None:
        sets.append("confirm_count=?")
        args.append(confirm_count)
    if confirm_target is not None:
        sets.append("confirm_target=?")
        args.append(confirm_target)
    args.append(switch_id)
    conn.execute(f"UPDATE switches SET {', '.join(sets)} WHERE id=?", args)


def add_device(
    conn: sqlite3.Connection, device_id: str, switch_id: str, label: str, key_hex: str, now: int
) -> None:
    conn.execute(
        "INSERT INTO devices(id, switch_id, label, key_hex, enabled, enrolled_at, last_seen) "
        "VALUES(?,?,?,?,1,?,?)",
        (device_id, switch_id, label, key_hex, now, now),
    )


def get_device(conn: sqlite3.Connection, device_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()


def list_devices(conn: sqlite3.Connection, switch_id: str, enabled_only: bool = True) -> list[sqlite3.Row]:
    sql = "SELECT * FROM devices WHERE switch_id=?"
    if enabled_only:
        sql += " AND enabled=1"
    sql += " ORDER BY enrolled_at, id"
    return list(conn.execute(sql, (switch_id,)))


def retire_device(conn: sqlite3.Connection, device_id: str, now: int) -> None:
    conn.execute(
        "UPDATE devices SET enabled=0, retired_at=? WHERE id=? AND enabled=1",
        (now, device_id),
    )


def seen_nonce(conn: sqlite3.Connection, device_id: str, nonce: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM checkins WHERE device_id=? AND nonce=?", (device_id, nonce)
        ).fetchone()
        is not None
    )


def record_checkin(
    conn: sqlite3.Connection, switch_id: str, device_id: str, nonce: str, client_ts: int, now: int
) -> int:
    conn.execute(
        "INSERT INTO checkins(switch_id, device_id, nonce, client_ts, at) VALUES(?,?,?,?,?)",
        (switch_id, device_id, nonce, client_ts, now),
    )
    conn.execute(
        "UPDATE devices SET last_seen=? WHERE id=? AND (last_seen IS NULL OR last_seen < ?)",
        (now, device_id, now),
    )
    conn.execute(
        "UPDATE switches SET confirm_count=0, cancelled_at=NULL WHERE id=?", (switch_id,)
    )
    return prune_checkins(conn, switch_id, now)


def prune_checkins(conn: sqlite3.Connection, switch_id: str, now: int, keep: int = 400) -> int:
    """Drop old nonces. Replay window stays bounded by clock_skew, not by retention."""
    rows = conn.execute(
        "SELECT seq FROM checkins WHERE switch_id=? ORDER BY seq DESC LIMIT 1 OFFSET ?",
        (switch_id, keep),
    ).fetchall()
    if not rows:
        return 0
    cutoff = rows[-1]["seq"]
    cur = conn.execute("DELETE FROM checkins WHERE switch_id=? AND seq < ?", (switch_id, cutoff))
    return cur.rowcount or 0


def last_checkin_at(conn: sqlite3.Connection, switch_id: str) -> int | None:
    row = conn.execute(
        "SELECT MAX(at) AS ts FROM checkins WHERE switch_id=?", (switch_id,)
    ).fetchone()
    return row["ts"] if row and row["ts"] is not None else None


def add_packet(
    conn: sqlite3.Connection,
    packet_id: str,
    switch_id: str,
    filename: str,
    sha256: str,
    size: int,
    recipients: Iterable[dict],
    note: str | None,
    now: int,
) -> None:
    import json

    conn.execute(
        "INSERT INTO packets(id, switch_id, filename, sha256, size, recipients, note, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (packet_id, switch_id, filename, sha256, size, json.dumps(list(recipients)), note, now),
    )


def active_packets(conn: sqlite3.Connection, switch_id: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT * FROM packets WHERE switch_id=? AND retired_at IS NULL ORDER BY created_at",
            (switch_id,),
        )
    )


def get_packet(conn: sqlite3.Connection, packet_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM packets WHERE id=?", (packet_id,)).fetchone()


def delivered_before(
    conn: sqlite3.Connection,
    switch_id: str,
    packet_id: str,
    target: str,
    mode: str,
    channel: str | None = None,
) -> bool:
    """channel=None means 'through any channel'; a str pins one channel."""
    sql = "SELECT 1 FROM deliveries WHERE switch_id=? AND packet_id=? AND target=? AND mode=? AND ok=1"
    args: list[object] = [switch_id, packet_id, target, mode]
    if channel is not None:
        sql += " AND channel=?"
        args.append(channel)
    return conn.execute(sql, args).fetchone() is not None


def delivered_channels(conn: sqlite3.Connection, switch_id: str, packet_id: str, target: str, mode: str) -> set[str]:
    return {
        r["channel"]
        for r in conn.execute(
            "SELECT DISTINCT channel FROM deliveries "
            "WHERE switch_id=? AND packet_id=? AND target=? AND mode=? AND ok=1",
            (switch_id, packet_id, target, mode),
        )
    }


def record_delivery(
    conn: sqlite3.Connection,
    switch_id: str,
    packet_id: str,
    target: str,
    mode: str,
    ok: bool,
    now: int,
    error: str | None = None,
    channel: str = "",
) -> None:
    conn.execute(
        "INSERT INTO deliveries(switch_id, packet_id, target, mode, channel, ok, attempts, last_error, at) "
        "VALUES(?,?,?,?,?,?,1,?,?) "
        "ON CONFLICT(switch_id, packet_id, target, mode, channel) DO UPDATE SET "
        "ok=excluded.ok, attempts=deliveries.attempts+1, last_error=excluded.last_error, at=excluded.at",
        (switch_id, packet_id, target, mode, channel, 1 if ok else 0, error, now),
    )


def pending_deliveries(conn: sqlite3.Connection, switch_id: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT * FROM deliveries WHERE switch_id=? AND ok=0 ORDER BY at", (switch_id,)
        )
    )


def notice_done(conn: sqlite3.Connection, switch_id: str, kind: str, bucket: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM notices WHERE switch_id=? AND kind=? AND bucket=? AND ok=1",
            (switch_id, kind, bucket),
        ).fetchone()
        is not None
    )


def record_notice(
    conn: sqlite3.Connection,
    switch_id: str,
    kind: str,
    bucket: str,
    ok: bool,
    now: int,
    error: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO notices(switch_id, kind, bucket, ok, attempts, last_error, at) "
        "VALUES(?,?,?,?,1,?,?) "
        "ON CONFLICT(switch_id, kind, bucket) DO UPDATE SET "
        "ok=excluded.ok, attempts=notices.attempts+1, last_error=excluded.last_error, at=excluded.at",
        (switch_id, kind, bucket, 1 if ok else 0, error, now),
    )


def pending_notices(conn: sqlite3.Connection, switch_id: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT * FROM notices WHERE switch_id=? AND ok=0 ORDER BY at", (switch_id,)
        )
    )


def watchdog_tick(conn: sqlite3.Connection, key: str, now: int) -> int | None:
    row = conn.execute("SELECT last_tick FROM watchdog WHERE key=?", (key,)).fetchone()
    previous = row["last_tick"] if row else None
    conn.execute(
        "INSERT INTO watchdog(key, last_tick) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET last_tick=excluded.last_tick",
        (key, now),
    )
    return previous


def watchdog_alerted(conn: sqlite3.Connection, key: str) -> int | None:
    row = conn.execute("SELECT last_alert FROM watchdog WHERE key=?", (key,)).fetchone()
    return row["last_alert"] if row else None


def set_watchdog_alert(conn: sqlite3.Connection, key: str, now: int) -> None:
    conn.execute(
        "INSERT INTO watchdog(key, last_tick, last_alert) VALUES(?,0,?) "
        "ON CONFLICT(key) DO UPDATE SET last_alert=excluded.last_alert",
        (key, now),
    )