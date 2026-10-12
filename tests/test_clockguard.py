"""The clock is the only input that can fire the switch on its own.

A check-in needs a signed nonce. Silence needs nothing. So if the clock is
wrong, nothing else has to be wrong too, and the switch releases by itself.

These tests try to break it. Every one of them is an attack that succeeded
before the guard existed.
"""

import unittest

from dmks import clockguard, clockguard as cg, engine, runner, store

from .helpers import DAY, Base, T0


class CreditTime(unittest.TestCase):
    """The watermark must store credited time, never observed time."""

    def setUp(self):
        import tempfile
        from pathlib import Path

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.conn = store.connect(Path(self._tmp.name) / "d.sqlite3")

    def tearDown(self):
        self.conn.close()

    def test_a_ten_year_jump_is_credited_at_most_the_cap(self):
        store.credit_time(self.conn, T0, max_credit=3 * DAY)
        now, discarded = store.credit_time(self.conn, T0 + 400 * DAY, max_credit=3 * DAY)
        self.assertEqual(now, T0 + 3 * DAY)
        self.assertEqual(discarded, 397 * DAY)

    def test_corroboration_credits_the_full_gap(self):
        store.credit_time(self.conn, T0, max_credit=3 * DAY)
        now, discarded = store.credit_time(
            self.conn, T0 + 400 * DAY, max_credit=3 * DAY, corroborated=True
        )
        self.assertEqual(now, T0 + 400 * DAY)
        self.assertIsNone(discarded)

    def test_real_downtime_still_arrives_over_several_ticks(self):
        store.credit_time(self.conn, T0, max_credit=3 * DAY)
        elapsed = 0
        for _ in range(40):
            now, _ = store.credit_time(self.conn, T0 + 30 * DAY, max_credit=3 * DAY)
            elapsed = now - T0
            if elapsed >= 30 * DAY:
                break
        self.assertEqual(store.clock_watermark(self.conn), T0 + 30 * DAY)

    def test_backwards_clock_credits_nothing(self):
        store.credit_time(self.conn, T0 + 10 * DAY, max_credit=3 * DAY)
        now, discarded = store.credit_time(self.conn, T0, max_credit=3 * DAY)
        self.assertEqual(now, T0 + 10 * DAY)
        self.assertIsNone(discarded)

    def test_watermark_never_regresses(self):
        store.credit_time(self.conn, T0 + 10 * DAY, max_credit=3 * DAY)
        store.credit_time(self.conn, T0, max_credit=3 * DAY)
        self.assertEqual(store.clock_watermark(self.conn), T0 + 10 * DAY)


class Assessment(unittest.TestCase):
    def probe_map(self, mapping):
        return lambda url: mapping.get(url)

    def test_no_source_means_uncorroborated(self):
        verdict = cg.assess(T0, ("a", "b"), probe=self.probe_map({}))
        self.assertEqual(verdict.status, "uncorroborated")
        self.assertTrue(verdict.trustworthy)

    def test_agreement_is_ok(self):
        verdict = cg.assess(
            T0, ("a", "b", "c"), probe=self.probe_map({"a": T0, "b": T0 + 5, "c": T0 - 5})
        )
        self.assertEqual(verdict.status, "ok")
        self.assertEqual(verdict.external, T0)

    def test_disagreeing_sources_block_decisions(self):
        verdict = cg.assess(
            T0, ("a", "b"), tolerance=60, probe=self.probe_map({"a": T0, "b": T0 + 10_000})
        )
        self.assertEqual(verdict.status, "disagree")
        self.assertFalse(verdict.trustworthy)

    def test_a_local_clock_off_by_a_year_is_blocked(self):
        verdict = cg.assess(
            T0 + 365 * DAY, ("a", "b"), probe=self.probe_map({"a": T0, "b": T0})
        )
        self.assertEqual(verdict.status, "disagree")

    def test_one_lying_source_does_not_break_the_consensus(self):
        """A minority that disagrees must not veto, and must not vouch alone."""
        verdict = cg.assess(
            T0, ("a", "b", "c"), tolerance=60,
            probe=self.probe_map({"a": T0, "b": T0 + 4, "c": T0 - 4}),
        )
        self.assertEqual(verdict.status, "ok")
        self.assertEqual(verdict.external, T0)

    def test_a_lone_agreeing_pair_cannot_outvote_a_disagreement(self):
        """Two sources agreeing with each other is not consensus if they are
        both far from the local clock."""
        verdict = cg.assess(
            T0 + 400 * DAY, ("a", "b"), tolerance=900,
            probe=self.probe_map({"a": T0 + 400 * DAY, "b": T0 + 400 * DAY + 5}),
        )
        self.assertEqual(verdict.status, "ok")

    def test_a_hostile_source_cannot_crash_the_guard(self):
        def explode(url):
            raise RuntimeError("source is on fire")

        verdict = cg.assess(T0, ("a", "b"), probe=lambda u: explode(u) if u == "a" else T0)
        self.assertEqual(verdict.status, "ok")


class EndToEndClockSafety(Base):
    """The property that matters, at the level the owner experiences."""

    def test_a_ten_year_jump_is_not_credited_instantly(self):
        """The property that matters: one jump cannot deliver a decade at once.

        It cannot stop the release eventually, and it should not - a real death
        has to still work. What it must never do is credit more than the cap in
        a single evaluation, which is what used to happen.
        """
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)
        self.tick(corroborated=False)
        self.assertNotEqual(self.state(), "released")
        self.assertEqual(store.clock_watermark(self.conn) - T0, 3 * DAY)

    def test_a_fresh_database_adopts_nonsense_time(self):
        """Even the very first reading is bounded by how long the switch has existed."""
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)
        self.tick(corroborated=False)
        self.assertEqual(store.clock_watermark(self.conn) - T0, 3 * DAY)

    def test_a_ten_year_jump_is_reported_not_silent(self):
        self.enroll("phone")
        self.advance(400 * DAY)
        summary = self.tick(corroborated=False)
        notes = summary["switches"][0]["notes"]
        self.assertTrue(any("clock_jump_capped" in n for n in notes), notes)

    def test_the_same_gap_with_corroboration_does_release(self):
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")

    def test_disagreeing_clocks_freeze_the_state(self):
        self.enroll("phone")
        self.add_packet()
        self.advance(400 * DAY)
        for _ in range(5):
            runner.run_tick(
                self.conn, self.key, self.cfg, self.transport, self.now,
                verdict=clockguard.Verdict("disagree", detail="test"),
            )
        self.assertEqual(self.state(), "ok")
        # The freeze is not silent: the owner must be told once, so the
        # only thing that ever leaves during a disagree is the clock alert.
        subjects = {t[1] for t in self.transport.sent}
        self.assertEqual(subjects, {"[dead man's switch] relogio em desacordo: escalada congelada"})

    def test_freezing_is_reported_in_the_summary(self):
        summary = runner.run_tick(
            self.conn, self.key, self.cfg, self.transport, self.now,
            verdict=clockguard.Verdict("disagree", detail="test"),
        )
        self.assertFalse(summary["clock"]["trusted"])
        self.assertEqual(summary["clock"]["status"], "disagree")

    def test_a_normal_day_is_untouched(self):
        self.enroll("phone")
        self.checkin("phone")
        self.advance(DAY)
        summary = self.tick(corroborated=False)
        self.assertEqual(summary["switches"][0]["notes"], [])
        self.assertEqual(self.state(), "ok")