"""Shared test scaffolding. Everything runs on a fake clock and a temp dir."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dmks import clockguard, config as config_mod, liveness, runner, seal, store
from dmks.deliver import NullTransport, Transport

T0 = 1_700_000_000
DAY = 86400

OWNER_SECRET = "owner-secret-for-tests"
DEVICE_SECRET = "device-secret-for-tests"


class Base(unittest.TestCase):
    release_mode = "hold"
    quorum_mode = "all"
    quorum_n = 1
    confirmations = 2
    recipients = None
    throttle_gpg = True

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        self.key = config_mod.new_audit_key()
        self.cfg = config_mod.Config(data_dir=self.root, audit_key=self.key)
        self.cfg.server.tick_seconds = 3600
        self.cfg.server.owner_email = "eu@exemplo.pt"
        self.cfg.packets_dir.mkdir(parents=True, exist_ok=True)
        self.conn = store.connect(self.cfg.db_path)
        self.transport = NullTransport()
        self.now = T0

        recipients = self.recipients if self.recipients is not None else [
            {"kind": "email", "address": "advogado@exemplo.pt", "gpg": None, "owner": False},
            {"kind": "email", "address": "eu@exemplo.pt", "owner": True},
        ]

        with store.tx(self.conn):
            store.create_switch(
                self.conn,
                "s",
                name="teste",
                owner_key=liveness.owner_key_hex(OWNER_SECRET),
                recipients=recipients,
                now=self.now,
                warn_after=7 * DAY,
                arm_after=14 * DAY,
                release_after=30 * DAY,
                device_grace=2 * DAY,
                quorum_mode=self.quorum_mode,
                quorum_n=self.quorum_n,
                confirmations=self.confirmations,
                release_mode=self.release_mode,
                clock_skew=300,
            )

        if self.throttle_gpg:
            self._skip_gpg = self.patch_gpg()

    def tearDown(self) -> None:
        self.conn.close()

    def patch_gpg(self):
        """Deliveries call seal.verify_container; stub it so tests stay hermetic."""
        from unittest import mock

        patcher = mock.patch.object(seal, "verify_container", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)
        return patcher

    def enroll(self, device_id: str, secret: str = DEVICE_SECRET) -> None:
        with store.tx(self.conn):
            store.add_device(
                self.conn, device_id, "s", device_id, liveness.device_key_hex(secret), self.now
            )

    def checkin(self, device_id: str, secret: str = DEVICE_SECRET) -> None:
        nonce = liveness.new_nonce()
        token = liveness.sign_device(secret, "s", device_id, self.now, nonce)
        liveness.checkin(self.conn, self.key, "s", device_id, self.now, nonce, token, self.now)

    def cancel(self) -> str:
        nonce = liveness.new_nonce()
        token = liveness.sign_owner(OWNER_SECRET, "s", self.now, nonce)
        return liveness.cancel(self.conn, self.key, "s", self.now, nonce, token, self.now)

    def advance(self, seconds: int) -> None:
        self.now += seconds

    def tick(self, transport: Transport | None = None, corroborated: bool = True) -> dict:
        """corroborated=True models real downtime: the server was off and an
        independent clock confirms the gap, so the full elapsed time is credited.
        corroborated=False models a lone clock that jumped, which is capped."""
        return runner.run_tick(
            self.conn, self.key, self.cfg, transport or self.transport, self.now,
            verdict=clockguard.Verdict("ok" if corroborated else "uncorroborated"),
        )

    def state(self) -> str:
        return store.get_switch(self.conn, "s")["state"]

    def add_packet(self, packet_id: str = "p1", sha256: str = "a" * 64) -> None:
        path = self.cfg.packets_dir / f"{packet_id}.gpg"
        path.write_bytes(b"-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----\n")
        import json

        with store.tx(self.conn):
            store.add_packet(
                self.conn, packet_id, "s", path.name, sha256, path.stat().st_size,
                json.loads(store.get_switch(self.conn, "s")["recipients"]), None, self.now,
            )