import unittest

from dmks import liveness, store

from .helpers import DEVICE_SECRET, Base


class CheckinAuth(Base):
    def setUp(self):
        super().setUp()
        self.enroll("phone")

    def _token(self, **overrides):
        fields = {
            "switch": "s",
            "device": "phone",
            "ts": self.now,
            "nonce": liveness.new_nonce(),
            "secret": DEVICE_SECRET,
        }
        fields.update(overrides)
        return fields["switch"], fields["device"], fields["ts"], fields["nonce"], \
            liveness.sign_device(fields["secret"], fields["switch"], fields["device"],
                                 fields["ts"], fields["nonce"])

    def _checkin(self, **overrides):
        switch, device, ts, nonce, token = self._token(**overrides)
        return liveness.checkin(self.conn, self.key, switch, device, ts, nonce, token, self.now)

    def test_valid_checkin(self):
        result = self._checkin()
        self.assertEqual(result.device_id, "phone")

    def test_replayed_nonce_is_rejected(self):
        switch, device, ts, nonce, token = self._token()
        liveness.checkin(self.conn, self.key, switch, device, ts, nonce, token, self.now)
        with self.assertRaises(liveness.AuthError) as ctx:
            liveness.checkin(self.conn, self.key, switch, device, ts, nonce, token, self.now)
        self.assertIn("replayed", str(ctx.exception))

    def test_wrong_secret_is_rejected(self):
        with self.assertRaises(liveness.AuthError) as ctx:
            self._checkin(secret="adivinhado")
        self.assertIn("bad token", str(ctx.exception))

    def test_timestamp_from_the_future_is_rejected(self):
        with self.assertRaises(liveness.AuthError) as ctx:
            self._checkin(ts=self.now + 4000)
        self.assertIn("clock_skew", str(ctx.exception))

    def test_timestamp_from_the_past_is_rejected(self):
        with self.assertRaises(liveness.AuthError) as ctx:
            self._checkin(ts=self.now - 4000)
        self.assertIn("clock_skew", str(ctx.exception))

    def test_unknown_device_is_rejected(self):
        switch, device, ts, nonce, token = self._token(device="fantasma")
        with self.assertRaises(liveness.AuthError) as ctx:
            liveness.checkin(self.conn, self.key, switch, device, ts, nonce, token, self.now)
        self.assertIn("unknown device", str(ctx.exception))

    def test_device_of_another_switch_is_rejected(self):
        with store.tx(self.conn):
            store.create_switch(
                self.conn, "outro", name="outro",
                owner_key=liveness.owner_key_hex("x"),
                recipients=[], now=self.now,
                warn_after=1, arm_after=2, release_after=3, device_grace=1,
                quorum_mode="all", quorum_n=1, confirmations=1,
                release_mode="hold", clock_skew=300,
            )
        switch, device, ts, nonce, token = self._token(switch="outro")
        with self.assertRaises(liveness.AuthError):
            liveness.checkin(self.conn, self.key, switch, device, ts, nonce, token, self.now)

    def test_retired_device_cannot_check_in(self):
        with store.tx(self.conn):
            store.retire_device(self.conn, "phone", self.now)
        with self.assertRaises(liveness.AuthError) as ctx:
            self._checkin()
        self.assertIn("retired", str(ctx.exception))

    def test_replayed_nonce_is_rejected_even_after_other_checkins(self):
        switch, device, ts, nonce, token = self._token()
        liveness.checkin(self.conn, self.key, switch, device, ts, nonce, token, self.now)
        self.advance(60)
        self._checkin()
        with self.assertRaises(liveness.AuthError):
            liveness.checkin(self.conn, self.key, switch, device, ts, nonce, token, self.now)

    def test_nonce_reuse_on_different_device_is_allowed(self):
        _, _, _, nonce, _ = self._token()
        self.enroll("laptop", "outro-secret")
        token = liveness.sign_device("outro-secret", "s", "laptop", self.now, nonce)
        liveness.checkin(self.conn, self.key, "s", "laptop", self.now, nonce, token, self.now)


class CancelAuth(Base):
    def test_owner_can_cancel(self):
        self.enroll("phone")
        self.advance(30 * 86400)
        self.tick()
        self.tick()
        self.assertEqual(self.state(), "released")
        previous = self.cancel()
        self.assertEqual(previous, "released")
        self.assertEqual(self.state(), "ok")

    def test_wrong_owner_secret_is_rejected(self):
        nonce = liveness.new_nonce()
        token = liveness.sign_owner("palpite", "s", self.now, nonce)
        with self.assertRaises(liveness.AuthError):
            liveness.cancel(self.conn, self.key, "s", self.now, nonce, token, self.now)

    def test_cancel_is_recorded_in_the_audit_chain(self):
        self.cancel()
        events = [r["event"] for r in self.conn.execute("SELECT event FROM audit_log ORDER BY seq")]
        self.assertIn("cancelled", events)


if __name__ == "__main__":
    unittest.main()