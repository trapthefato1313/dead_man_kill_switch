"""Fan-out: the packet must leave by every channel, independently.

The previous behaviour returned on the first transport that worked, which meant
a working SMTP silently starved the webhooks. For a dead man's switch that is
the worst possible failure: the evidence sits in exactly one place.
"""

import json
import unittest

from dmks import deliver, store

from .helpers import DAY, Base


class Recorder:
    def __init__(self, name: str, fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.sent: list[dict] = []

    def send(self, target, subject, body, attachment=None):
        if self.fail:
            raise deliver.TransportError(f"{self.name} indisponivel")
        self.sent.append(target)


class FanOutBase(Base):
    release_mode = "notify"

    def fan_out(self, *recorders):
        return deliver.FanOut(
            [deliver.Channel(name=r.name, transport=r) for r in recorders]
        )


class EveryChannelGetsThePacket(FanOutBase):
    def setUp(self):
        super().setUp()
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)

    def test_all_channels_receive_it(self):
        smtp = Recorder("smtp")
        hook = Recorder("webhook:0")
        self.tick()
        self.tick(self.fan_out(smtp, hook))
        addresses = {t["address"] for t in smtp.sent} & {t["address"] for t in hook.sent}
        self.assertIn("advogado@exemplo.pt", addresses)
        self.assertIn("eu@exemplo.pt", addresses)

    def test_one_broken_channel_does_not_starve_the_other(self):
        smtp = Recorder("smtp", fail=True)
        hook = Recorder("webhook:0")
        self.tick()
        self.tick(self.fan_out(smtp, hook))
        self.assertTrue(hook.sent, "webhook must still be attempted after SMTP fails")
        self.assertEqual(smtp.sent, [])

    def test_partial_failure_is_not_reported_as_delivered(self):
        smtp = Recorder("smtp")
        hook = Recorder("webhook:0", fail=True)
        self.tick()
        self.tick(self.fan_out(smtp, hook))
        rows = [
            r for r in self.conn.execute(
                "SELECT * FROM deliveries WHERE mode='release' AND channel=''"
            )
        ]
        self.assertTrue(rows)
        self.assertFalse(rows[0]["ok"], "target is not delivered until every channel confirms")

    def test_retry_only_resends_through_the_broken_channel(self):
        smtp = Recorder("smtp")
        hook = Recorder("webhook:0", fail=True)
        self.tick()
        self.tick(self.fan_out(smtp, hook))
        first_round = len(smtp.sent)
        self.assertTrue(first_round, "smtp took the packet on the first round")

        fixed = Recorder("webhook:0")
        smtp_again = Recorder("smtp")
        self.tick(self.fan_out(smtp_again, fixed))
        self.assertEqual(smtp_again.sent, [], "smtp already took it, must not resend")
        self.assertTrue(fixed.sent, "the failed channel is retried")

    def test_all_channels_ok_marks_the_target_delivered(self):
        smtp = Recorder("smtp")
        hook = Recorder("webhook:0")
        self.tick()
        self.tick(self.fan_out(smtp, hook))
        row = self.conn.execute(
            "SELECT * FROM deliveries WHERE mode='release' AND channel='' AND ok=1"
        ).fetchone()
        self.assertIsNotNone(row)

    def test_audit_names_the_channels_used(self):
        smtp = Recorder("smtp")
        hook = Recorder("webhook:0")
        self.tick()
        self.tick(self.fan_out(smtp, hook))
        rows = list(
            self.conn.execute("SELECT detail FROM audit_log WHERE event='delivered'")
        )
        channels = set()
        for r in rows:
            channels.update(json.loads(r["detail"]).get("channels", []))
        self.assertEqual(channels, {"smtp", "webhook:0"})


class ChannelNaming(Base):
    def test_single_transport_is_one_channel(self):
        self.assertEqual(deliver._channel_names(deliver.NullTransport()), ["default"])

    def test_fan_out_lists_its_channels(self):
        fan = deliver.FanOut([deliver.Channel("smtp", Recorder("smtp"))])
        self.assertEqual(deliver._channel_names(fan), ["smtp"])

    def test_webhook_urls_are_deduplicated(self):
        from dmks import config as config_mod

        cfg = config_mod.ServerConfig(webhook_url="https://a", webhook_urls=["https://a", "https://b"])
        self.assertEqual(cfg.all_webhook_urls(), ["https://a", "https://b"])

    def test_build_transport_fans_out_over_every_webhook(self):
        from dmks import config as config_mod

        cfg = config_mod.Config(data_dir=__import__("pathlib").Path("/tmp"), audit_key=b"x" * 32)
        cfg.server.webhook_urls = ["https://a", "https://b"]
        fan = deliver.build_transport(cfg)
        self.assertEqual(
            deliver._channel_names(fan), ["webhook:0", "webhook:1"]
        )


class MigrationFromV1(unittest.TestCase):
    """A server already running on v1 must keep its delivery history."""

    def _make_v1(self, path):
        import sqlite3

        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE deliveries (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                switch_id  TEXT NOT NULL,
                packet_id  TEXT NOT NULL,
                target     TEXT NOT NULL,
                mode       TEXT NOT NULL,
                ok         INTEGER NOT NULL,
                attempts   INTEGER NOT NULL DEFAULT 1,
                last_error TEXT,
                at         INTEGER NOT NULL,
                UNIQUE(switch_id, packet_id, target, mode)
            );
            INSERT INTO deliveries(switch_id, packet_id, target, mode, ok, attempts, at)
            VALUES('s','p1','advogado@exemplo.pt','release',1,1,100);
            """
        )
        conn.commit()
        conn.close()

    def test_v1_rows_survive_and_keep_counting_as_delivered(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "d.sqlite3"
            self._make_v1(path)
            conn = store.connect(path)
            self.assertEqual(store.get_meta(conn, "schema_version"), "3")
            # v2 -> v3 adds a nullable owner password. An old switch has none, so
            # the panel refuses it until an owner sets one: closed, never open.
            self.assertIsNone(store.get_owner_pwhash(conn, "s"))
            self.assertTrue(
                store.delivered_before(conn, "s", "p1", "advogado@exemplo.pt", "release")
            )
            self.assertEqual(
                store.delivered_channels(conn, "s", "p1", "advogado@exemplo.pt", "release"), {""}
            )
            conn.close()

    def test_v1_row_does_not_block_a_named_channel(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "d.sqlite3"
            self._make_v1(path)
            conn = store.connect(path)
            self.assertFalse(
                store.delivered_before(conn, "s", "p1", "advogado@exemplo.pt", "release", channel="smtp")
            )
            with store.tx(conn):
                store.record_delivery(
                    conn, "s", "p1", "advogado@exemplo.pt", "release", True, 200, channel="smtp"
                )
            self.assertTrue(
                store.delivered_before(conn, "s", "p1", "advogado@exemplo.pt", "release", channel="smtp")
            )
            self.assertEqual(
                store.delivered_channels(conn, "s", "p1", "advogado@exemplo.pt", "release"), {"", "smtp"}
            )
            conn.close()


class TwoDeadlineSwitches(unittest.TestCase):
    def test_arm_is_the_midpoint(self):
        from dmks import config as config_mod

        sw = config_mod.SwitchConfig(name="x", warn_after=2 * DAY, arm_after=None, release_after=10 * DAY)
        self.assertEqual(config_mod.resolve_arm(sw), 6 * DAY)

    def test_explicit_arm_wins(self):
        from dmks import config as config_mod

        sw = config_mod.SwitchConfig(name="x", warn_after=2 * DAY, arm_after=3 * DAY, release_after=10 * DAY)
        self.assertEqual(config_mod.resolve_arm(sw), 3 * DAY)

    def test_midpoint_still_validates(self):
        from dmks import config as config_mod

        sw = config_mod.SwitchConfig(
            name="x", warn_after=2 * DAY, arm_after=None, release_after=10 * DAY,
            quorum_mode="all", release_mode="hold",
        )
        sw.recipients = [{"address": "a@b.pt"}]
        cfg = config_mod.Config(data_dir=__import__("pathlib").Path("/tmp"), audit_key=b"x" * 32)
        cfg.switches = {"x": sw}
        self.assertEqual([p for p in config_mod.validate(cfg) if "increasing" in p], [])

    def test_stored_arm_is_resolved_at_write_time(self):
        import tempfile
        from pathlib import Path

        from dmks import liveness
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.connect(Path(tmp) / "d.sqlite3")
            with store.tx(conn):
                store.create_switch(
                    conn, "s", name="t", owner_key=liveness.owner_key_hex("k"),
                    recipients=[{"address": "a@b.pt"}], now=0,
                    warn_after=2 * DAY, arm_after=None, release_after=10 * DAY,
                    device_grace=DAY, quorum_mode="all", quorum_n=1,
                    confirmations=2, release_mode="hold", clock_skew=300,
                )
            row = store.get_switch(conn, "s")
            self.assertEqual(row["arm_after"], 6 * DAY)
            conn.close()
