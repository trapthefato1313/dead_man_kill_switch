import unittest

from dmks import engine, store

from .helpers import DAY, Base


class Escalation(Base):
    def setUp(self):
        super().setUp()
        self.enroll("phone")
        self.checkin("phone")

    def drive(self, days: float) -> None:
        self.advance(int(days * DAY))

    def test_stays_ok_while_checking_in(self):
        for _ in range(40):
            self.drive(1)
            self.tick()
            self.checkin("phone")
        self.assertEqual(self.state(), "ok")

    def test_warn_armed_released_sequence(self):
        self.drive(8)
        self.tick()
        self.assertEqual(self.state(), "ok")
        self.tick()
        self.assertEqual(self.state(), "warn")
        self.drive(8)
        self.tick()
        self.assertEqual(self.state(), "warn")
        self.tick()
        self.assertEqual(self.state(), "armed")
        self.drive(20)
        self.tick()
        self.assertEqual(self.state(), "armed")
        self.tick()
        self.assertEqual(self.state(), "released")

    def test_single_tick_never_reaches_release(self):
        self.drive(365)
        summary = self.tick()
        self.assertNotEqual(summary["switches"][0]["state"], "released")
        self.assertEqual(summary["switches"][0]["state"], self.state())

    def test_confirmations_required(self):
        with store.tx(self.conn):
            self.conn.execute("UPDATE switches SET confirmations=3 WHERE id='s'")
        self.drive(8)
        for expected in ("ok", "ok", "warn"):
            self.tick()
            self.assertEqual(self.state(), expected)

    def test_long_downtime_catches_up(self):
        self.drive(400)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")

    def test_checkin_resets_to_ok(self):
        self.drive(20)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "armed")
        self.checkin("phone")
        self.tick()
        self.assertEqual(self.state(), "ok")

    def test_released_is_terminal(self):
        self.drive(400)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")
        self.checkin("phone")
        self.drive(1)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")

    def test_never_releases_without_a_device(self):
        with store.tx(self.conn):
            store.retire_device(self.conn, "phone", self.now)
        self.drive(400)
        for _ in range(5):
            self.tick()
        self.assertEqual(self.state(), "ok")


class ClockSafety(Base):
    def setUp(self):
        super().setUp()
        self.enroll("phone")

    def test_backwards_clock_cannot_unrelease(self):
        self.advance(400 * DAY)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")
        self.now = 1_600_000_000
        summary = self.tick()
        self.assertEqual(self.state(), "released")
        self.assertTrue(
            any("clock_regression" in n for n in summary["switches"][0]["notes"]),
            summary["switches"][0]["notes"],
        )

    def test_backwards_clock_cannot_early_release(self):
        self.advance(400 * DAY)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")
        self.now = 1_600_000_000
        with store.tx(self.conn):
            store.update_switch(self.conn, "s", state="ok", now=1_600_000_000, confirm_count=0)
        for _ in range(4):
            self.tick()
        self.assertEqual(self.state(), "released")

    def test_watermark_only_moves_forward(self):
        self.advance(1000)
        self.tick()
        self.assertEqual(store.clock_watermark(self.conn), self.now)
        self.now -= 5000
        self.tick()
        self.assertEqual(store.clock_watermark(self.conn), self.now + 5000)


class Quorum(Base):
    quorum_mode = "all"

    def test_all_quorum_needs_every_device(self):
        self.enroll("phone")
        self.enroll("laptop")
        self.advance(400 * DAY)
        for _ in range(6):
            self.checkin("laptop")
            self.tick()
            self.advance(DAY)
        self.assertEqual(self.state(), "ok")

    def test_all_quorum_fires_when_all_silent(self):
        self.enroll("phone")
        self.enroll("laptop")
        self.advance(400 * DAY)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")

    def test_device_grace_delays_counting(self):
        self.enroll("phone")
        self.enroll("laptop")
        self.advance(DAY)
        summary = self.tick()
        self.assertEqual(summary["switches"][0]["silent_devices"], [])
        self.assertFalse(summary["switches"][0]["quorum_met"])
        self.advance(2 * DAY)
        summary = self.tick()
        self.assertEqual(sorted(summary["switches"][0]["silent_devices"]), ["laptop", "phone"])


class QuorumN(Base):
    quorum_mode = "n"
    quorum_n = 2

    def test_n_of_m(self):
        self.enroll("a")
        self.enroll("b")
        self.enroll("c")
        self.advance(400 * DAY)
        self.checkin("c")
        for _ in range(6):
            self.tick()
            self.advance(DAY)
            self.checkin("c")
        self.assertEqual(self.state(), "ok")

        self.advance(400 * DAY)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")


if __name__ == "__main__":
    unittest.main()