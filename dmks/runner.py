"""One evaluation cycle, shared by the local worker and the HTTP tick endpoint.

Both callers do exactly the same thing, so an external cron driving
`POST /api/tick` is a genuine second opinion rather than a different code path
with different bugs.
"""

from __future__ import annotations

import json
import sqlite3

from . import deliver, engine, store
from .config import Config
from .deliver import Transport

REMINDER_INTERVAL = 86400


def run_tick(
    conn: sqlite3.Connection,
    audit_key: bytes,
    cfg: Config,
    transport: Transport,
    now: int,
) -> dict:
    evaluations = engine.tick_all(conn, audit_key, now)
    summary: dict = {"at": now, "switches": [], "deliveries": [], "watchdog": None}

    for evaluation in evaluations:
        switch = store.get_switch(conn, evaluation.switch_id)
        if switch is None:
            continue

        summary["switches"].append(evaluation.as_dict())

        if evaluation.state in ("warn", "armed"):
            deliver.notify(
                conn, audit_key, cfg, switch,
                kind=f"state:{evaluation.state}",
                bucket=f"entered:{evaluation.state}",
                subject=f"[dead man's switch] switch em {evaluation.state.upper()}",
                body=_state_body(evaluation),
                transport=transport,
                now=now,
            )
            last = _last_notice_at(conn, switch["id"], f"reminder:{evaluation.state}")
            if last is None or now - last >= REMINDER_INTERVAL:
                deliver.notify(
                    conn, audit_key, cfg, switch,
                    kind=f"reminder:{evaluation.state}",
                    bucket=str(int(now // 86400)),
                    subject=f"[dead man's switch] ainda em {evaluation.state.upper()}",
                    body=_state_body(evaluation) + "\n\nEste aviso repete-se todos os dias.",
                    transport=transport,
                    now=now,
                )

        if evaluation.state == "released":
            for packet in store.active_packets(conn, switch["id"]):
                summary["deliveries"].extend(
                    deliver.deliver_packet(conn, audit_key, cfg, switch, packet, transport, now)
                )

    summary["deliveries"].extend(deliver.retry_pending(conn, audit_key, cfg, transport, now))
    summary["watchdog"] = deliver.watchdog(conn, audit_key, cfg, transport, now)
    return summary


def _last_notice_at(conn: sqlite3.Connection, switch_id: str, kind: str) -> int | None:
    row = conn.execute(
        "SELECT MAX(at) AS ts FROM notices WHERE switch_id=? AND kind=?", (switch_id, kind)
    ).fetchone()
    return row["ts"] if row and row["ts"] is not None else None


def _state_body(evaluation: engine.Evaluation) -> str:
    state = evaluation.state
    total = evaluation.silent_devices
    if state == "warn":
        headline = (
            f"O switch passou a {state.upper()}. Ainda nada foi enviado.\n"
            f"Dispositivos silenciosos: {', '.join(total) or 'nenhum'}"
        )
    else:
        headline = (
            f"O switch passou a {state.upper()}. A contagem para a entrega comecou.\n"
            f"Dispositivos silenciosos: {', '.join(total) or 'nenhum'}\n"
            "Se ainda estas vivo, cancela imediatamente com: dmks cancel " + evaluation.switch_id
        )
    lines = [headline]
    if evaluation.notes:
        lines.append("")
        lines.append("Notas:")
        lines.extend(f"- {note}" for note in evaluation.notes)
    return "\n".join(lines)


def render(summary: dict) -> str:
    return json.dumps(summary, indent=2, sort_keys=True, default=str)