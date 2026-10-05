"""Escalation engine.

Design rules, in priority order:

1. Full recomputation from durable state. Nothing is derived from "how many
   times did the tick run", so a process that was down for a week still reaches
   the correct verdict on its first run back.
2. Monotonic clock. The effective time is the server clock, but it can never
   move backwards past the stored watermark, so a bad NTP correction or a
   timezone bug cannot un-escalate or release early.
3. Escalation needs the quorum met N evaluations in a row. A single anomalous
   tick can never reach `released`.
4. De-escalation is immediate and cheap. Coming back to life must always be
   faster than dying looks.
5. `released` is terminal. A check-in afterwards is recorded, not undone, and
   the packet has already left the building.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from . import audit, store

STATE_ORDER = {"ok": 0, "warn": 1, "armed": 2, "released": 3, "cancelled": 0}


@dataclass
class Evaluation:
    switch_id: str
    state: str
    previous_state: str
    silenced_for: int
    would_be_state: str
    silent_devices: list[str] = field(default_factory=list)
    quorum_met: bool = False
    confirmations: int = 0
    escalated: bool = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "switch": self.switch_id,
            "state": self.state,
            "previous_state": self.previous_state,
            "would_be_state": self.would_be_state,
            "silenced_for_seconds": self.silenced_for,
            "silent_devices": self.silent_devices,
            "quorum_met": self.quorum_met,
            "confirmations": self.confirmations,
            "escalated": self.escalated,
            "notes": self.notes,
        }


def silenced_for(conn: sqlite3.Connection, switch: sqlite3.Row, now: int) -> int:
    last = store.last_checkin_at(conn, switch["id"])
    reference = last if last is not None else switch["created_at"]
    return max(0, now - reference)


def silent_devices(conn: sqlite3.Connection, switch: sqlite3.Row, now: int) -> list[sqlite3.Row]:
    grace = switch["device_grace"]
    silent = []
    for device in store.list_devices(conn, switch["id"], enabled_only=True):
        reference = device["last_seen"] or switch["created_at"]
        if now - reference >= grace:
            silent.append(device)
    return silent


def quorum_met(conn: sqlite3.Connection, switch: sqlite3.Row, silent: list[sqlite3.Row]) -> bool:
    total = enabled_count(conn, switch["id"])
    if total == 0:
        return False
    if switch["quorum_mode"] == "all":
        return len(silent) == total
    return len(silent) >= switch["quorum_n"]


def enabled_count(conn: sqlite3.Connection, switch_id: str) -> int:
    return len(store.list_devices(conn, switch_id, enabled_only=True))


def would_be_state(switch: sqlite3.Row, silence: int) -> str:
    if silence >= switch["release_after"]:
        return "released"
    if silence >= switch["arm_after"]:
        return "armed"
    if silence >= switch["warn_after"]:
        return "warn"
    return "ok"


def evaluate(
    conn: sqlite3.Connection,
    audit_key: bytes,
    switch_id: str,
    now: int,
    max_credit: int = 3 * 86400,
    corroborated: bool = False,
    clock_ok: bool = True,
) -> Evaluation:
    switch = store.get_switch(conn, switch_id)
    if switch is None:
        raise KeyError(switch_id)

    notes: list[str] = []

    # Fail-secure: when the clock cannot be trusted, the irreversible step does
    # not happen at all. We stay exactly where we are and the caller is expected
    # to alert the owner, who is alive and can fix it.
    if not clock_ok:
        last_trusted = store.clock_watermark(conn) or now
        notes.append(
            "clock_untrusted: clocks disagree, escalation refused, state left unchanged"
        )
        return Evaluation(
            switch_id=switch_id,
            state=switch["state"],
            previous_state=switch["state"],
            silenced_for=silenced_for(conn, switch, last_trusted),
            would_be_state=switch["state"],
            confirmations=0,
            escalated=False,
            notes=notes,
        )

    effective_now, discarded = store.credit_time(
        conn, now, max_credit, corroborated, reference=switch["created_at"]
    )
    if now < effective_now:
        notes.append(
            f"clock_regression_ignored: server={now} watermark={effective_now}, using watermark"
        )
    if discarded:
        notes.append(
            f"clock_jump_capped: wanted {discarded}s more than one evaluation may credit "
            f"without corroboration, crediting at most {max_credit}s per tick instead"
        )

    previous = switch["state"]
    silence = silenced_for(conn, switch, effective_now)
    silent = silent_devices(conn, switch, effective_now)
    total = enabled_count(conn, switch_id)
    target = would_be_state(switch, silence)

    if total == 0:
        quorum = False
        notes.append("no_device_enrolled: switch will never fire, enroll at least one device")
    else:
        quorum = quorum_met(conn, switch, silent)
        if target != "ok" and silence < switch["device_grace"]:
            quorum = False
            notes.append("within_device_grace")

    if quorum and target != "ok" and switch["quorum_mode"] == "all" and len(silent) < total:
        notes.append(f"blocked_by_live_device: {total - len(silent)} still checking in")

    if target == "released" and switch["release_mode"] != "hold":
        if not store.active_packets(conn, switch_id):
            notes.append("awaiting_packet: nothing sealed yet, holding at armed")
            target = "armed"

    if target != "ok" and not quorum:
        target = "ok"

    confirm_count = switch["confirm_count"]
    confirm_target = switch["confirm_target"]
    escalated = False

    if previous == "released":
        target = "released"
        confirm_count, confirm_target = 0, None
    elif target == "ok":
        escalated = previous != "ok"
        confirm_count, confirm_target = 0, None
    elif target == previous:
        confirm_count, confirm_target = 0, None
    else:
        if confirm_target == target:
            confirm_count += 1
        else:
            confirm_target = target
            confirm_count = 1
        if confirm_count >= switch["confirmations"]:
            escalated = True
            confirm_count, confirm_target = 0, None
        else:
            notes.append(
                f"confirmation_{confirm_count}/{switch['confirmations']}: holding at {previous}"
            )
            target = previous

    with store.tx(conn):
        store.update_switch(
            conn,
            switch_id,
            state=target,
            now=effective_now,
            released_at=effective_now if target == "released" else None,
            confirm_count=confirm_count,
            confirm_target=confirm_target,
        )
        if escalated:
            audit.append(
                conn,
                audit_key,
                effective_now,
                "state_change",
                {
                    "switch": switch_id,
                    "from": previous,
                    "to": target,
                    "silenced_for": silence,
                    "silent_devices": [d["id"] for d in silent],
                },
            )

    return Evaluation(
        switch_id=switch_id,
        state=target,
        previous_state=previous,
        silenced_for=silence,
        would_be_state=would_be_state(switch, silence),
        silent_devices=[d["id"] for d in silent],
        quorum_met=quorum,
        confirmations=confirm_count,
        escalated=escalated,
        notes=notes,
    )


def tick_all(
    conn: sqlite3.Connection,
    audit_key: bytes,
    now: int,
    max_credit: int = 3 * 86400,
    corroborated: bool = False,
    clock_ok: bool = True,
) -> list[Evaluation]:
    return [
        evaluate(conn, audit_key, row["id"], now, max_credit, corroborated, clock_ok)
        for row in store.list_switches(conn)
    ]


def status(conn: sqlite3.Connection, switch_id: str, now: int) -> dict:
    switch = store.get_switch(conn, switch_id)
    if switch is None:
        raise KeyError(switch_id)
    silence = silenced_for(conn, switch, now)
    silent = silent_devices(conn, switch, now)
    return {
        "switch": switch_id,
        "name": switch["name"],
        "state": switch["state"],
        "would_be_state": would_be_state(switch, silence),
        "silenced_for_seconds": silence,
        "seconds_to_warn": max(0, switch["warn_after"] - silence),
        "seconds_to_arm": max(0, switch["arm_after"] - silence),
        "seconds_to_release": max(0, switch["release_after"] - silence),
        "release_mode": switch["release_mode"],
        "confirmations": f"{switch['confirm_count']}/{switch['confirmations']}",
        "quorum": f"{len(silent)}/{enabled_count(conn, switch_id)} silent ({switch['quorum_mode']})",
        "silent_devices": [d["id"] for d in silent],
        "packets": [p["id"] for p in store.active_packets(conn, switch_id)],
        "recipients": json.loads(switch["recipients"]),
    }