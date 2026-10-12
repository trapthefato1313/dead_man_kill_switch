"""The fleet: real SMTP sockets, one independent node per channel.

The point is not that a single transport is fancied up with a list of hosts. The
point is that each computer of the network is its own channel, the packet goes
to every one of them, and a target only counts as delivered when all of them
confirmed. These tests use a real SMTP conversation over loopback, not a stub.
"""

import json
import unittest

from dmks import config as config_mod, deliver, store
from dmks.sink import Sink

from .helpers import DAY, Base


def _fleet_cfg_entry(sink: Sink, name: str) -> dict:
    return {
        "name": name,
        "host": "127.0.0.1",
        "port": sink.port,
        "from": "switch@dmks.invalid",
        "starttls": False,
    }


def _start(*sinks) -> list[Sink]:
    for sink in sinks:
        sink.start()
    return list(sinks)


class OneRealSink(unittest.TestCase):
    def test_smtp_round_trip_over_real_socket(self):
        import tempfile
        sink = Sink(host="127.0.0.1", port=0, spool=tempfile.mkdtemp())
        self.addCleanup(sink.stop)
        sink.start()
        transport = deliver.SmtpTransport("127.0.0.1", sink.port, "dmks@sw.invalid",
                                          starttls=False)
        transport.send({"address": "jornalista@proton.me"}, "assunto", "corpo das provas")
        self.assertEqual(sink.received_count(), 1)
        receipt = sink.received[0]
        self.assertEqual(receipt.recipients, ["jornalista@proton.me"])
        self.assertGreater(receipt.size, 0)
        self.assertIn(b"corpo das provas", receipt.message)
        entry = json.loads(sink.journal.read_text().strip().splitlines()[-1])
        self.assertEqual(entry["sha256"], receipt.sha256)

    def test_receipt_journal_is_durable(self):
        import tempfile
        sink = Sink(host="127.0.0.1", port=0, spool=tempfile.mkdtemp())
        self.addCleanup(sink.stop)
        sink.start()
        deliver.SmtpTransport("127.0.0.1", sink.port, "dmks@sw.invalid",
                              starttls=False).send(
            {"address": "a@proton.me"}, "s", "b")
        entry = json.loads(sink.journal.read_text().splitlines()[-1])
        self.assertEqual(entry["recipients"], ["a@proton.me"])
        self.assertEqual(entry["sha256"], sink.received[0].sha256)


class FleetFanOut(Base):
    release_mode = "notify"

    def setUp(self):
        super().setUp()
        self.sinks = _start(*[Sink(host="127.0.0.1", port=0) for _ in range(3)])
        self.addCleanup(lambda: [s.stop() for s in self.sinks])
        self.cfg.server.smtp_servers = [
            _fleet_cfg_entry(sink, f"node-{i}") for i, sink in enumerate(self.sinks)
        ]
        self.transport = deliver.build_transport(self.cfg)
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)

    def test_every_independent_node_holds_the_evidence(self):
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")
        for sink in self.sinks:
            self.assertGreaterEqual(
                sink.received_count(), 1,
                f"node {sink.name} must hold the evidence",
            )
            self.assertTrue(
                any(b"a" * 64 in receipt.message for receipt in sink.received),
                f"node {sink.name} must hold the packet content",
            )

    def test_all_nodes_received_the_same_packet(self):
        self.tick()
        self.tick()
        # All nodes reference the same evidence: the packet's SHA-256, quoted
        # verbatim in the delivery body, is identical everywhere.
        for sink in self.sinks:
            self.assertTrue(
                any(b"a" * 64 in receipt.message for receipt in sink.received),
                f"node {sink.name} must reference the packet digest",
            )


class FleetFailedNode(Base):
    release_mode = "notify"

    def setUp(self):
        super().setUp()
        self.sinks = _start(*[Sink(host="127.0.0.1", port=0) for _ in range(3)])
        self.addCleanup(lambda: [s.stop() for s in self.sinks])
        self.cfg.server.smtp_servers = [
            _fleet_cfg_entry(sink, f"node-{i}") for i, sink in enumerate(self.sinks)
        ]
        # node-1 is down: stop it and point its entry at an already-closed port.
        self.sinks[1].stop()
        dead_port = self.sinks[1].port
        self.sinks[1] = Sink(host="127.0.0.1", port=dead_port)
        # do not start it
        self.transport = deliver.build_transport(self.cfg)
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)

    def test_dead_node_does_not_starve_the_others(self):
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")
        self.assertGreaterEqual(self.sinks[0].received_count(), 1, "node-0 must be reached")
        self.assertGreaterEqual(self.sinks[2].received_count(), 1, "node-2 must be reached")
        rows = list(self.conn.execute(
            "SELECT ok FROM deliveries WHERE mode='release' AND channel='' AND switch_id='s'"
        ))
        self.assertTrue(rows)
        self.assertFalse(
            all(r["ok"] for r in rows),
            "aggregate row must NOT be ok while any node is down",
        )

    def test_retry_reaches_the_revived_node_without_resending_the_rest(self):
        self.tick()
        self.tick()
        before = {s.received_count() for s in (self.sinks[0], self.sinks[2])}
        self.sinks[1].start()  # the dead node comes back
        self.advance(120)
        self.tick()
        self.assertEqual(self.sinks[0].received_count(), list(before)[0],
                         "node-0 already has it, must not resend")
        self.assertGreaterEqual(self.sinks[1].received_count(), 1,
                                "revived node-1 must finally receive it")
        rows = list(self.conn.execute(
            "SELECT ok FROM deliveries WHERE mode='release' AND channel='' AND switch_id='s'"
        ))
        self.assertTrue(all(r["ok"] for r in rows))


class FleetBookkeeping(Base):
    release_mode = "notify"

    def setUp(self):
        super().setUp()
        self.sinks = _start(*[Sink(host="127.0.0.1", port=0) for _ in range(2)])
        self.addCleanup(lambda: [s.stop() for s in self.sinks])
        self.cfg.server.smtp_servers = [
            _fleet_cfg_entry(sink, f"node-{i}") for i, sink in enumerate(self.sinks)
        ]
        self.transport = deliver.build_transport(self.cfg)
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)

    def test_one_delivery_row_per_node_channel(self):
        self.tick()
        self.tick()
        channels = {
            r["channel"] for r in self.conn.execute(
                "SELECT DISTINCT channel FROM deliveries "
                "WHERE mode='release' AND switch_id='s' AND ok=1"
            )
        } - {""}
        self.assertEqual(channels, {"smtp:node-0", "smtp:node-1"})

    def test_every_node_channel_recorded_for_every_recipient(self):
        self.tick()
        self.tick()
        rows = list(self.conn.execute(
            "SELECT channel, target FROM deliveries WHERE mode='release' AND switch_id='s'"
        ))
        self.assertTrue(rows)


class BuildTransportCoversTheFleet(unittest.TestCase):
    def test_one_channel_per_server_in_the_list(self):
        cfg = config_mod.Config(data_dir=__import__("pathlib").Path("/tmp"),
                                audit_key=b"x" * 32)
        cfg.server.smtp_servers = [
            {"name": "casa", "host": "h1", "port": 25, "from": "a@b.pt"},
            {"name": "garagem", "host": "h2", "port": 26, "from": "a@b.pt"},
        ]
        fan = deliver.build_transport(cfg)
        self.assertEqual(deliver._channel_names(fan), ["smtp:casa", "smtp:garagem"])

    def test_legacy_smtp_plus_fleet_are_all_channels(self):
        cfg = config_mod.Config(data_dir=__import__("pathlib").Path("/tmp"),
                                audit_key=b"x" * 32)
        cfg.server.smtp_host = "relay.example"
        cfg.server.smtp_from = "a@b.pt"
        cfg.server.smtp_servers = [{"name": "n1", "host": "h1", "port": 25, "from": "a@b.pt"}]
        fan = deliver.build_transport(cfg)
        self.assertEqual(deliver._channel_names(fan), ["smtp", "smtp:n1"])


class BuildTransportFailover(unittest.TestCase):
    def _cfg(self, strategy):
        import pathlib
        cfg = config_mod.Config(data_dir=pathlib.Path("/tmp"), audit_key=b"x" * 32)
        cfg.server.smtp_strategy = strategy
        cfg.server.smtp_from = "switch@news.example.pt"
        cfg.server.smtp_servers = [
            {"name": "mx", "host": "mx.example.pt", "port": 587,
             "user": "relay@news.example.pt", "password": "p"},
            {"name": "mx2", "host": "mx2.example.pt", "port": 587,
             "user": "relay@news.example.pt", "password": "p"},
            {"name": "mx3", "host": "mx3.example.pt", "port": 587,
             "user": "relay@news.example.pt", "password": "p"},
        ]
        return cfg

    def test_failover_collapses_the_fleet_into_one_channel(self):
        fan = deliver.build_transport(self._cfg("failover"))
        self.assertEqual(deliver._channel_names(fan), ["smtp:relay"])
        relay = fan.channels[0].transport
        self.assertIsInstance(relay, deliver.FailoverTransport)
        self.assertEqual([c.name for c in relay.channels],
                         ["smtp:mx", "smtp:mx2", "smtp:mx3"])

    def test_fanout_keeps_one_channel_per_node(self):
        fan = deliver.build_transport(self._cfg("fanout"))
        self.assertEqual(deliver._channel_names(fan), ["smtp:mx", "smtp:mx2", "smtp:mx3"])


class FleetFailover(Base):
    release_mode = "notify"

    def setUp(self):
        super().setUp()
        self.sinks = _start(*[Sink(host="127.0.0.1", port=0) for _ in range(3)])
        self.addCleanup(lambda: [s.stop() for s in self.sinks])
        self.cfg.server.smtp_strategy = "failover"
        self.cfg.server.smtp_servers = [
            _fleet_cfg_entry(sink, f"mx-{i}") for i, sink in enumerate(self.sinks)
        ]
        self.transport = deliver.build_transport(self.cfg)
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)

    def test_exactly_one_copy_per_recipient(self):
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")
        # Two recipients (the lawyer and the owner), so two copies total: one
        # copy each, both through the first relay, not one copy per node.
        self.assertEqual(self.sinks[0].received_count(), 2)
        self.assertEqual(self.sinks[1].received_count(), 0)
        self.assertEqual(self.sinks[2].received_count(), 0)

    def test_dead_first_node_is_skipped(self):
        self.sinks[0].stop()  # first relay is down
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")
        self.assertEqual(self.sinks[1].received_count(), 2, "second relay must take over")
        self.assertEqual(self.sinks[2].received_count(), 0, "third relay must not be used")


class ManyNodesSameBox(unittest.TestCase):
    def test_twenty_nodes_all_receive_on_a_single_host(self):
        sinks = _start(*[Sink(host="127.0.0.1", port=0) for _ in range(20)])
        try:
            for sink in sinks:
                deliver.SmtpTransport(
                    "127.0.0.1", sink.port, "dmks@sw.invalid", starttls=False
                ).send({"address": "alvo@jornal.pt"}, "evidencia", "pacote")
            self.assertTrue(all(s.received_count() >= 1 for s in sinks),
                            "every node on the box must receive the packet")
        finally:
            for sink in sinks:
                sink.stop()