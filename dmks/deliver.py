"""Delivery with exactly-once semantics and at-least-once retry.

Two separate mechanisms, deliberately:

  * Packets  -> `deliveries`, unique per (switch, packet, target, mode). The row
    is the idempotency key. A crash between "state=released" and "email sent"
    is safe: the next tick sees the missing row and sends. A crash after the
    email is safe: the row is already committed.
  * Notices  -> `notices`, unique per (switch, kind, bucket), so the owner is
    warned once per state entry and once per day while escalated.

Nothing here trusts in-memory state, so any process can be killed at any point
and the next run converges without duplicates.
"""

from __future__ import annotations

import base64
import json
import shutil
import smtplib
import sqlite3
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol

from . import audit, seal, store
from .config import Config

MAX_ATTEMPTS = 8
WEBHOOK_ATTACHMENT_LIMIT = 4 * 1024 * 1024


class TransportError(Exception):
    pass


class Transport(Protocol):
    def send(self, target: dict, subject: str, body: str, attachment: Path | None = None) -> None: ...


@dataclass
class NullTransport:
    sent: list[tuple[dict, str, str]] = field(default_factory=list)
    fail: bool = False

    def send(self, target: dict, subject: str, body: str, attachment: Path | None = None) -> None:
        if self.fail:
            raise TransportError("NullTransport configured to fail")
        self.sent.append((target, subject, body))


@dataclass
class SmtpTransport:
    host: str
    port: int
    sender: str
    user: str | None = None
    password: str | None = None
    starttls: bool = True

    def send(self, target: dict, subject: str, body: str, attachment: Path | None = None) -> None:
        address = target["address"]
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = address
        message["Subject"] = subject
        message.set_content(body)
        if attachment is not None:
            message.add_attachment(
                attachment.read_bytes(),
                maintype="application",
                subtype="octet-stream",
                filename=attachment.name,
            )
        with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
            if self.starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.user:
                smtp.login(self.user, self.password or "")
            smtp.send_message(message)


@dataclass
class WebhookTransport:
    url: str

    def send(self, target: dict, subject: str, body: str, attachment: Path | None = None) -> None:
        payload: dict[str, Any] = {"subject": subject, "text": body}
        if attachment is not None and attachment.stat().st_size <= WEBHOOK_ATTACHMENT_LIMIT:
            payload["packet"] = {
                "filename": attachment.name,
                "sha256": seal.sha256_file(attachment),
                "content_b64": base64.b64encode(attachment.read_bytes()).decode(),
            }
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status >= 400:
                    raise TransportError(f"webhook returned {response.status}")
        except urllib.error.HTTPError as exc:
            raise TransportError(f"webhook returned {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise TransportError(f"webhook unreachable: {exc.reason}") from exc


@dataclass
class Channel:
    """One named route out. Every channel is attempted, never just the first."""

    name: str
    transport: Transport

    def send(self, target: dict, subject: str, body: str, attachment: Path | None = None) -> None:
        self.transport.send(target, subject, body, attachment)


@dataclass
class FailoverTransport:
    """A pool of interchangeable relays for the same recipient.

    Unlike the fan-out fleet, where every node keeps its own copy, these nodes
    all deliver to the *same* inbox, so trying them all would mail the dossier
    several times. The point is only that one working node gets it out before
    the others are censored or seized, so the first success ends the attempt and
    the rest are touched only if the previous one failed.
    """

    channels: list[Channel]
    last: str | None = None

    def send(self, target: dict, subject: str, body: str, attachment: Path | None = None) -> None:
        errors: list[str] = []
        for channel in self.channels:
            try:
                channel.send(target, subject, body, attachment)
                self.last = channel.name
                return
            except Exception as exc:  # noqa: BLE001 - the next relay is tried
                errors.append(f"{channel.name}: {type(exc).__name__}: {exc}")
        raise TransportError("every relay node failed: " + "; ".join(errors))


@dataclass
class FanOut:
    """Sends to every channel and reports each result separately.

    A dead man's switch must not depend on one route: if the only channel is
    silently swallowed by the receiving service, the evidence is gone. So all
    channels get the packet, and the target only counts as delivered when all
    of them confirmed it.
    """

    channels: list[Channel]

    def deliver(
        self,
        target: dict,
        subject: str,
        body: str,
        attachment: Path | None = None,
        only: set[str] | None = None,
    ) -> dict[str, str | None]:
        results: dict[str, str | None] = {}
        for channel in self.channels:
            if only is not None and channel.name not in only:
                continue
            try:
                channel.send(target, subject, body, attachment)
                results[channel.name] = None
            except Exception as exc:  # noqa: BLE001 - recorded per channel, retried, never fatal
                results[channel.name] = f"{type(channel.transport).__name__}: {exc}"
        return results


def _send_all(
    transport: Transport,
    target: dict,
    subject: str,
    body: str,
    attachment: Path | None = None,
    only: set[str] | None = None,
) -> dict[str, str | None]:
    """Every outstanding channel is attempted. Returns channel -> error.

    `only` exists so a retry never re-sends through a route that already took
    the packet. Accepts a plain single-channel transport too, so tests and the
    NullTransport keep working unchanged.
    """
    if isinstance(transport, FanOut):
        return transport.deliver(target, subject, body, attachment, only=only)
    if only is not None and "default" not in only:
        return {}
    try:
        transport.send(target, subject, body, attachment)
    except Exception as exc:  # noqa: BLE001
        return {"default": f"{type(transport).__name__}: {exc}"}
    return {"default": None}


def build_transport(cfg: Config, override: Transport | None = None) -> Transport:
    if override is not None:
        return override
    server = cfg.server
    channels: list[Channel] = []
    if server.smtp_host and server.smtp_from:
        channels.append(
            Channel(
                name="smtp",
                transport=SmtpTransport(
                    host=server.smtp_host,
                    port=server.smtp_port,
                    sender=server.smtp_from,
                    user=server.smtp_user,
                    password=server.smtp_password,
                    starttls=server.smtp_starttls,
                ),
            )
        )
    # The fleet: one independent channel per SMTP node.
    #
    # fanout   - every node receives the packet; the target counts as delivered
    #            only when all of them confirmed (private stores / cofres).
    # failover - the nodes are relays for the same inbox; they collapse into a
    #            single channel that stops at the first success (real MTA pool).
    def _server_transport(entry: dict, index: int) -> SmtpTransport:
        return SmtpTransport(
            host=entry["host"],
            port=int(entry.get("port", server.smtp_port)),
            sender=entry.get("from") or server.smtp_from,
            user=entry.get("user") or server.smtp_user,
            password=entry.get("password") or server.smtp_password,
            starttls=bool(entry.get("starttls", True)),
        )

    if server.smtp_strategy == "failover" and server.smtp_servers:
        relays = [
            Channel(
                name=f"smtp:{entry.get('name') or f'relay-{index}'}",
                transport=_server_transport(entry, index),
            )
            for index, entry in enumerate(server.smtp_servers)
        ]
        channels.append(Channel(name="smtp:relay", transport=FailoverTransport(channels=relays)))
    else:
        for index, entry in enumerate(server.smtp_servers):
            label = entry.get("name") or f"fleet-{index}"
            channels.append(
                Channel(name=f"smtp:{label}", transport=_server_transport(entry, index))
            )
    for index, url in enumerate(server.all_webhook_urls()):
        channels.append(Channel(name=f"webhook:{index}", transport=WebhookTransport(url)))
    if not channels:
        return NullTransport()
    return FanOut(channels)


def due(row: sqlite3.Row, now: int) -> bool:
    if row["ok"]:
        return False
    attempts = row["attempts"]
    if attempts >= MAX_ATTEMPTS:
        return False
    backoff = min(3600, 60 * (2 ** min(attempts, 6)))
    return now - row["at"] >= backoff


def deliver_packet(
    conn: sqlite3.Connection,
    audit_key: bytes,
    cfg: Config,
    switch: sqlite3.Row,
    packet: sqlite3.Row,
    transport: Transport,
    now: int,
) -> list[dict]:
    recipients = json.loads(packet["recipients"]) or json.loads(switch["recipients"])
    path = cfg.packets_dir / packet["filename"]

    if switch["release_mode"] == "hold":
        with store.tx(conn):
            store.record_delivery(conn, switch["id"], packet["id"], "*hold*", "hold", True, now)
            audit.append(
                conn, audit_key, now, "release_held",
                {"switch": switch["id"], "packet": packet["id"],
                 "reason": "release_mode=hold, nothing was sent"},
            )
        return [{"target": "*hold*", "ok": True, "note": "held, nothing sent"}]

    problems = seal.verify_container(
        path, packet["sha256"], [r.get("gpg", "") for r in recipients if r.get("gpg")]
    )
    outcomes: list[dict] = []
    for target in recipients:
        label = target.get("address", "")
        already = store.delivered_channels(conn, switch["id"], packet["id"], label, "release")
        outstanding = [
            name for name in _channel_names(transport) if name not in already
        ]
        if not outstanding:
            outcomes.append({"target": label, "skipped": "already_delivered", "channels": sorted(already)})
            continue

        if problems:
            error = "; ".join(problems)
            with store.tx(conn):
                store.record_delivery(conn, switch["id"], packet["id"], label, "release", False, now, error)
                for name in outstanding:
                    store.record_delivery(
                        conn, switch["id"], packet["id"], label, "release", False, now, error, channel=name
                    )
                audit.append(
                    conn, audit_key, now, "delivery_refused",
                    {"switch": switch["id"], "packet": packet["id"], "target": label, "problems": problems},
                )
            outcomes.append({"target": label, "ok": False, "error": error})
            continue

        results = _send_all(
            transport,
            target,
            f"[dead man's switch] {switch['name']}: pacote selado {packet['id']}",
            _release_body(switch, packet),
            attachment=path,
            only=set(outstanding),
        )
        # Delivered only when every outstanding channel confirmed, and only if
        # every outstanding channel was actually reached.
        all_ok = (
            bool(results)
            and set(results) == set(outstanding)
            and all(err is None for err in results.values())
        )
        with store.tx(conn):
            for name, err in results.items():
                store.record_delivery(
                    conn, switch["id"], packet["id"], label, "release", err is None, now, err, channel=name
                )
            store.record_delivery(
                conn, switch["id"], packet["id"], label, "release", all_ok, now,
                None if all_ok else "; ".join(e for e in results.values() if e) or None,
            )
            if all_ok:
                audit.append(
                    conn, audit_key, now, "delivered",
                    {"switch": switch["id"], "packet": packet["id"], "target": label,
                     "sha256": packet["sha256"], "mode": switch["release_mode"],
                     "channels": sorted(results)},
                )
        outcomes.append(
            {"target": label, "ok": all_ok,
             "channels": {name: ("sent" if err is None else err) for name, err in results.items()}}
        )

    if switch["release_mode"] == "publish":
        outcomes.append(publish(cfg, switch, packet))

    return outcomes


def _channel_names(transport: Transport) -> list[str]:
    channels = getattr(transport, "channels", None)
    if isinstance(channels, list):
        return [c.name for c in channels]
    return ["default"]


def _release_body(switch: sqlite3.Row, packet: sqlite3.Row) -> str:
    return (
        f"O switch '{switch['name']}' atingiu o estado released.\n\n"
        f"O ficheiro '{packet['filename']}' e um pacote OpenPGP cifrado para a tua chave.\n"
        f"SHA-256: {packet['sha256']}\n"
        f"Tamanho: {packet['size']} bytes\n"
        f"Selado em: {packet['created_at']}\n\n"
        "Desencripta com:\n"
        f"  gpg --decrypt {packet['filename']}\n\n"
        "Se ainda estas vivo e nao foi isto que quiseste, o registo de auditoria\n"
        "explica a linha do tempo toda. Verifica-o antes de agir."
    )


def publish(cfg: Config, switch: sqlite3.Row, packet: sqlite3.Row) -> dict:
    target_dir = Path(cfg.server.publish_dir or "")
    source = cfg.packets_dir / packet["filename"]
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        destination = target_dir / packet["filename"]
        shutil.copyfile(source, destination)
        manifest = {
            "switch": switch["name"],
            "packet": packet["id"],
            "filename": packet["filename"],
            "sha256": packet["sha256"],
            "sealed_at": packet["created_at"],
            "released_at": switch["released_at"],
            "note": packet["note"],
        }
        (target_dir / f"{packet['id']}.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        return {"target": str(target_dir), "ok": True}
    except OSError as exc:
        return {"target": str(target_dir), "ok": False, "error": str(exc)}


def retry_pending(
    conn: sqlite3.Connection,
    audit_key: bytes,
    cfg: Config,
    transport: Transport,
    now: int,
) -> list[dict]:
    """Re-attempt any release that failed. Runs on every tick."""
    results: list[dict] = []
    for switch in store.list_switches(conn):
        if switch["state"] != "released" or switch["release_mode"] == "hold":
            continue
        for row in store.pending_deliveries(conn, switch["id"]):
            if not due(row, now):
                continue
            packet = store.get_packet(conn, row["packet_id"])
            if packet is None:
                continue
            results.extend(deliver_packet(conn, audit_key, cfg, switch, packet, transport, now))
    return results


def notify(
    conn: sqlite3.Connection,
    audit_key: bytes,
    cfg: Config,
    switch: sqlite3.Row,
    kind: str,
    bucket: str,
    subject: str,
    body: str,
    transport: Transport,
    now: int,
) -> bool:
    """Idempotent notice to the owner. Returns True if it actually went out."""
    if store.notice_done(conn, switch["id"], kind, bucket):
        return False
    targets = _owner_targets(cfg, switch)
    if not targets:
        return False
    failures = []
    for target in targets:
        for channel, error in _send_all(transport, target, subject, body).items():
            if error:
                failures.append(f"{target.get('address')} via {channel}: {error}")
    ok = not failures
    with store.tx(conn):
        store.record_notice(conn, switch["id"], kind, bucket, ok, now, "; ".join(failures) or None)
        audit.append(
            conn, audit_key, now, "notice",
            {"switch": switch["id"], "kind": kind, "bucket": bucket, "ok": ok,
             "error": "; ".join(failures) or None},
        )
    return ok


def _owner_targets(cfg: Config, switch: sqlite3.Row) -> list[dict]:
    recipients = json.loads(switch["recipients"])
    owner = [r for r in recipients if r.get("owner")]
    if owner:
        return owner
    if cfg.server.owner_email:
        return [{"kind": "email", "address": cfg.server.owner_email}]
    return []


def watchdog(
    conn: sqlite3.Connection,
    audit_key: bytes,
    cfg: Config,
    transport: Transport,
    now: int,
) -> dict | None:
    """Detect the failure nobody sees: the server itself going silent.

    If the switch cannot be evaluated, the switch cannot fire. This is the one
    failure mode where silence looks identical to success, so it gets its own
    alert to the owner.
    """
    interval = cfg.server.tick_seconds
    overdue_after = interval * 3
    report: dict[str, Any] = {"packet_problems": [], "last_tick": None, "alerted": None}

    last = store.watchdog_tick(conn, "tick", now)
    report["last_tick"] = last

    for switch in store.list_switches(conn):
        for packet in store.active_packets(conn, switch["id"]):
            recipients = json.loads(packet["recipients"])
            problems = seal.verify_container(
                cfg.packets_dir / packet["filename"],
                packet["sha256"],
                [r.get("gpg", "") for r in recipients if r.get("gpg")],
            )
            if problems:
                report["packet_problems"].append(
                    {"switch_id": switch["id"], "packet": packet["id"], "problems": problems}
                )

    silence = None if last is None else now - last
    stale = silence is not None and silence > overdue_after

    if report["packet_problems"]:
        for entry in report["packet_problems"]:
            affected = store.get_switch(conn, entry["switch_id"])
            if affected is None:
                continue
            notify(
                conn, audit_key, cfg, affected,
                "packet_health",
                f"{entry['packet']}:{entry['problems'][0][:40]}",
                "[dead man's switch] pacote selado com problema",
                f"O pacote {entry['packet']} nao esta intacto:\n"
                + "\n".join(entry["problems"])
                + "\n\nVolta a selar o pacote antes de precisares dele.",
                transport, now,
            )

    first_switch = store.list_switches(conn)
    if stale and first_switch and now - (store.watchdog_alerted(conn, "tick") or 0) > overdue_after:
        notify(
            conn, audit_key, cfg, first_switch[0],
            "watchdog",
            str(int(now // 3600)),
            "[dead man's switch] servidor possivelmente parado",
            f"O ultimo tick foi ha {silence}s (limite {overdue_after}s).\n"
            "Se o worker morreu, o switch nunca dispara. Verifica o servico.",
            transport, now,
        )
        store.set_watchdog_alert(conn, "tick", now)
        report["alerted"] = "watchdog"
    return report