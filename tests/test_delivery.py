import json
import unittest
from unittest import mock

from dmks import deliver, store

from .helpers import DAY, Base


class FailingTransport:
    def __init__(self) -> None:
        self.attempts = 0

    def send(self, target, subject, body, attachment=None):
        self.attempts += 1
        raise deliver.TransportError("servidor smtp indisponivel")


class HoldMode(Base):
    release_mode = "hold"

    def test_hold_mode_sends_nothing(self):
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")
        self.assertEqual(self.transport.sent, [])

    def test_hold_mode_records_why(self):
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)
        self.tick()
        self.tick()
        events = [r["event"] for r in self.conn.execute("SELECT event FROM audit_log ORDER BY seq")]
        self.assertIn("release_held", events)


class NotifyMode(Base):
    release_mode = "notify"

    def test_release_sends_to_every_recipient(self):
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)
        self.tick()
        self.tick()
        recipients = {t["address"] for t, _, _ in self.transport.sent}
        self.assertIn("advogado@exemplo.pt", recipients)
        self.assertEqual(self.state(), "released")

    def test_delivery_is_exactly_once(self):
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)
        self.tick()
        for _ in range(10):
            self.tick()
            self.advance(DAY)
        sends = [t for t, _, _ in self.transport.sent if t["address"] == "advogado@exemplo.pt"]
        self.assertEqual(len(sends), 1)

    def test_crash_between_release_and_delivery_still_delivers(self):
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)

        self.tick()
        self.assertEqual(self.state(), "ok")

        self.tick()
        self.assertEqual(self.state(), "released")
        delivered = [t for t, _, _ in self.transport.sent if t["address"] == "advogado@exemplo.pt"]
        self.assertEqual(len(delivered), 1)

        with store.tx(self.conn):
            self.conn.execute("DELETE FROM deliveries")
        self.transport.sent.clear()

        self.tick()
        recovered = [t for t, _, _ in self.transport.sent if t["address"] == "advogado@exemplo.pt"]
        self.assertEqual(len(recovered), 1)

    def test_failed_delivery_is_retried(self):
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)

        failing = FailingTransport()
        self.tick(failing)
        self.assertEqual(self.state(), "ok")
        self.tick(failing)
        self.assertEqual(self.state(), "released")
        self.assertEqual(failing.attempts, 2)
        self.assertEqual(self.transport.sent, [])

        self.advance(120)
        self.tick()
        delivered = [t for t, _, _ in self.transport.sent if t["address"] == "advogado@exemplo.pt"]
        self.assertEqual(len(delivered), 1)

    def test_corrupt_packet_is_never_sent(self):
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)
        with mock.patch.object(
            deliver.seal, "verify_container",
            return_value=["ciphertext hash mismatch: expected aaa, got bbb"],
        ):
            self.tick()
            self.tick()
        self.assertEqual(self.state(), "released")
        outsiders = [t for t, _, _ in self.transport.sent if not t.get("owner")]
        self.assertEqual(outsiders, [])
        events = [r["event"] for r in self.conn.execute("SELECT event FROM audit_log ORDER BY seq")]
        self.assertIn("delivery_refused", events)

    def test_release_holds_without_a_packet(self):
        self.enroll("phone")
        self.advance(400 * DAY)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "armed")
        outsiders = [t for t, _, _ in self.transport.sent if not t.get("owner")]
        self.assertEqual(outsiders, [])


class OwnerNotices(Base):
    release_mode = "notify"

    def test_owner_is_warned_at_every_stage(self):
        self.enroll("phone")
        self.advance(8 * DAY)
        self.tick()
        self.tick()
        subjects = [s for _, s, _ in self.transport.sent]
        self.assertTrue(any("WARN" in s for s in subjects), subjects)

    def test_warning_sent_once_per_state_entry(self):
        self.enroll("phone")
        self.advance(8 * DAY)
        for _ in range(5):
            self.tick()
            self.advance(3600)
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM notices WHERE kind='state:warn'"
        ).fetchone()
        self.assertEqual(row["c"], 1)

    def test_silence_without_warnings_is_reported(self):
        self.enroll("phone")
        self.advance(8 * DAY)
        for _ in range(5):
            self.tick()
            self.advance(3600)
        status = self.tick()["switches"][0]
        self.assertTrue(status["quorum_met"])
        self.assertGreaterEqual(status["silenced_for_seconds"], 8 * DAY)

    def test_repeat_warning_next_day(self):
        self.enroll("phone")
        self.advance(8 * DAY)
        self.tick()
        self.tick()
        first = len([s for _, s, _ in self.transport.sent if "WARN" in s])
        self.advance(DAY + 60)
        self.tick()
        second = len([s for _, s, _ in self.transport.sent if "WARN" in s])
        self.assertEqual(second, first + 1)


class Watchdog(Base):
    def test_packet_corruption_is_alerted_while_alive(self):
        self.enroll("phone")
        self.checkin("phone")
        self.add_packet(sha256="b" * 64)
        with mock.patch.object(
            deliver.seal, "verify_container", return_value=["ciphertext hash mismatch"]
        ):
            report = self.tick()["watchdog"]
        self.assertTrue(report["packet_problems"])
        bodies = [b for _, _, b in self.transport.sent]
        self.assertTrue(any("pacote" in b for b in bodies))

    def test_stale_tick_is_alerted(self):
        self.enroll("phone")
        self.tick()
        self.transport.sent.clear()
        self.advance(30 * 3600)
        report = self.tick()["watchdog"]
        self.assertEqual(report["alerted"], "watchdog")
        subjects = [s for _, s, _ in self.transport.sent]
        self.assertTrue(any("parado" in s for s in subjects), subjects)


if __name__ == "__main__":
    unittest.main()