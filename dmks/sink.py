"""An independent SMTP receiving node for the delivery fleet.

The fleet is what gives the switch genuine redundancy: one of these runs on
each computer of a private network, and the switch fans the evidence out to
every node. A seizure or a censored provider taking a single machine only ever
removes one copy, and the surviving nodes still prove the packet existed.

This node is deliberately tiny and stdlib-only, so it installs with a `pip
install` of this repo (or a plain `cp`) on whatever computers you happen to
control. It speaks just enough SMTP to receive mail and produces a durable
receipt for each message: the bytes on disk, their SHA-256, the sender and the
recipients. Later, that journal is the evidence that reaching your network is
not the same as being destroyed.

Security notes:
  * Bind it to a private address, not a public SENDIP, or bots will happily
    store spam on it. `--bind 127.0.0.1` is the safe default.
  * It is a store, not a relay: it never forwards a message onwards, so it can
    never be abused as an open relay.
  * STARTTLS is not implemented here. On a hostile network link the switch
    itself must do the encryption; the sink is the last hop on your own wire.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

MAX_MESSAGE = 256 * 1024 * 1024

BANNER = b"220 dmks sink ready"
DATA_PROMPT = b"354 end data with <CR><LF>.<CR><LF>"


@dataclass
class Receipt:
    sha256: str
    size: int
    sender: str
    recipients: list[str]
    at: int
    filename: str | None
    peer: str | None = None
    message: bytes = b""

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "size": self.size,
            "sender": self.sender,
            "recipients": self.recipients,
            "at": self.at,
            "filename": self.filename,
            "peer": self.peer,
        }


def _quote_address(raw: bytes) -> str:
    """Extract the bare address from `MAIL FROM:<a@b>` / `RCPT TO:<a@b>`."""
    text = raw.decode(errors="replace").split(":", 1)[-1].strip()
    if "<" in text:
        text = text[text.index("<") + 1 : text.rfind(">")] if text.rfind(">") > text.index("<") else text
    return text.strip() or "(unknown)"


class Sink:
    """One SMTP receiver, running its own thread and event loop.

    `port=0` asks the OS for a free port, which `start()` resolves into
    `self.port`. That makes tests hermetic: no two runs collide.
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 2525,
        spool: str | Path | None = None,
        name: str = "node",
        max_message: int = MAX_MESSAGE,
    ) -> None:
        self.name = name
        self._host = host
        self._port = port
        self.max_message = max_message
        self.spool = Path(spool).expanduser() if spool else None
        if self.spool:
            self.spool.mkdir(parents=True, exist_ok=True)
            self.journal = self.spool / "receipts.jsonl"
        else:
            self.journal = None

        self.port = port
        self.received: list[Receipt] = []
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.base_events.Server | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._error: Exception | None = None
        self._counter = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "Sink":
        self._thread = threading.Thread(
            target=self._run, name=f"dmks-sink-{self.name}", daemon=True
        )
        self._thread.start()
        if not self._ready.wait(timeout=15):
            raise RuntimeError(f"sink {self.name} failed to start: {self._error}")
        return self

    def stop(self) -> None:
        if self._loop and self._server:
            async def _close() -> None:
                self._server.close()
                await self._server.wait_closed()

            future = asyncio.run_coroutine_threadsafe(_close(), self._loop)
            try:
                future.result(timeout=5)
            except Exception:  # noqa: BLE001 - already closing
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        # A client breaking the connection mid-dialogue must not spam stderr at
        # interpreter shutdown (a daemon thread writing while the interpreter is
        # finalising is precisely how a test process dies with a broken stderr
        # lock). Swallow async noise quietly; receipts are the only sink record.
        self._loop.set_exception_handler(lambda loop, context: None)

        async def serve() -> None:
            try:
                self._server = await asyncio.start_server(
                    self._handle, self._host, self._port
                )
                sockets = self._server.sockets
                if sockets:
                    self.port = sockets[0].getsockname()[1]
                self._ready.set()
                async with self._server:
                    await self._server.serve_forever()
            except asyncio.CancelledError:
                # stop() closes the server; a quiet exit is not an error.
                pass

        try:
            self._loop.run_until_complete(serve())
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001
            self._error = exc
            if not self._ready.is_set():
                self._ready.set()

    # -- protocol ----------------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        await self._reply(writer, BANNER)
        envelope_from = ""
        envelope_to: list[str] = []
        data: bytearray | None = None

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if data is not None:
                    stripped = line.rstrip(b"\r\n")
                    if stripped == b".":
                        message = bytes(data)
                        self._store(message, envelope_from, envelope_to, peer)
                        filename = self._last_filename()
                        await self._reply(
                            writer, ("250 2.0.0 OK queued as " + (filename or "dmks")).encode()
                        )
                        data = None
                        envelope_from, envelope_to = "", []
                        continue
                    if len(data) >= self.max_message:
                        await self._reply(writer, b"552 5.3.4 message size exceeds limit")
                        continue
                    if stripped.startswith(b".."):
                        line = line[1:]
                    data += line
                    continue

                upper = line.strip().upper()
                if upper == b"QUIT":
                    await self._reply(writer, b"221 2.0.0 bye")
                    break
                if upper == b"RSET" or upper == b"NOOP":
                    if upper == b"RSET":
                        envelope_from, envelope_to = "", []
                    await self._reply(writer, b"250 OK")
                elif upper.startswith(b"HELO") or upper.startswith(b"EHLO"):
                    await self._reply(writer, b"250-" + self.name.encode())
                    await self._reply(writer, b"250 OK")
                elif upper.startswith(b"MAIL FROM:"):
                    envelope_from = _quote_address(line)
                    envelope_to = []
                    await self._reply(writer, b"250 2.1.0 OK")
                elif upper.startswith(b"RCPT TO:"):
                    envelope_to.append(_quote_address(line))
                    await self._reply(writer, b"250 2.1.5 OK")
                elif upper == b"DATA":
                    data = bytearray()
                    await self._reply(writer, DATA_PROMPT)
                elif upper.startswith(b"STARTTLS"):
                    await self._reply(writer, b"500 STARTTLS not implemented, run the sink on a private network")
                elif upper.startswith(b"VRFY"):
                    await self._reply(writer, b"252 cannot verify, will accept")
                else:
                    await self._reply(writer, b"500 5.5.2 unrecognised command")
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _reply(self, writer: asyncio.StreamWriter, payload: bytes) -> None:
        writer.write(payload + b"\r\n")
        await writer.drain()

    # -- storage -----------------------------------------------------------

    def _store(self, message: bytes, sender: str, recipients: list[str], peer) -> Receipt:
        digest = hashlib.sha256(message).hexdigest()
        self._counter += 1
        receipt = Receipt(
            sha256=digest,
            size=len(message),
            sender=sender,
            recipients=recipients,
            at=int(time.time()),
            filename=None,
            peer=str(peer),
            message=message,
        )
        if self.spool and self.journal:
            # Recreate on demand: a disk that was wiped or a spool dir that was
            # moved away must not make the node silently swallow mail.
            self.spool.mkdir(parents=True, exist_ok=True)
            name = f"{receipt.at}-{self._counter:06d}-{uuid.uuid4().hex[:8]}.eml"
            path = self.spool / name
            path.write_bytes(message)
            path.chmod(0o600)
            receipt.filename = name
            with self.journal.open("a") as handle:
                handle.write(json.dumps(receipt.to_dict(), sort_keys=True) + "\n")
        with self._lock:
            self.received.append(receipt)
        return receipt

    def _last_filename(self) -> str | None:
        with self._lock:
            return self.received[-1].filename if self.received else None

    def received_count(self) -> int:
        with self._lock:
            return len(self.received)