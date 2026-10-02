import json
import unittest

from dmks import audit, config as config_mod, liveness, store

from .helpers import DEVICE_SECRET, T0, Base


class AuditChain(Base):
    def test_chain_is_intact(self):
        for i in range(10):
            audit.append(self.conn, self.key, T0 + i, "event", {"i": i})
        ok, count, bad, reason = audit.verify(self.conn, self.key)
        self.assertTrue(ok, reason)
        self.assertEqual(count, 10)
        self.assertIsNone(bad)

    def test_edited_entry_is_detected(self):
        for i in range(5):
            audit.append(self.conn, self.key, T0 + i, "event", {"i": i})
        self.conn.execute("UPDATE audit_log SET detail=? WHERE seq=3", (json.dumps({"i": 999}),))
        ok, _, bad, _ = audit.verify(self.conn, self.key)
        self.assertFalse(ok)
        self.assertEqual(bad, 3)

    def test_deleted_entry_is_detected(self):
        for i in range(5):
            audit.append(self.conn, self.key, T0 + i, "event", {"i": i})
        self.conn.execute("DELETE FROM audit_log WHERE seq=3")
        ok, _, bad, _ = audit.verify(self.conn, self.key)
        self.assertFalse(ok)
        self.assertEqual(bad, 4)

    def test_reordering_is_detected(self):
        for i in range(4):
            audit.append(self.conn, self.key, T0 + i, "event", {"i": i})
        self.conn.execute("UPDATE audit_log SET at=? WHERE seq=2", (T0 + 99,))
        ok, _, _, _ = audit.verify(self.conn, self.key)
        self.assertFalse(ok)

    def test_other_key_does_not_verify(self):
        audit.append(self.conn, self.key, T0, "event", {"i": 0})
        ok, _, _, _ = audit.verify(self.conn, config_mod.new_audit_key())
        self.assertFalse(ok)

    def test_forged_appended_entry_is_detected(self):
        audit.append(self.conn, self.key, T0, "event", {"i": 0})
        seq, digest = audit.head(self.conn)
        self.conn.execute(
            "INSERT INTO audit_log(seq, at, event, detail, prev_hash, hash) VALUES(?,?,?,?,?,?)",
            (seq + 1, T0 + 1, "cancelled", "{}", digest, "f" * 64),
        )
        ok, _, bad, _ = audit.verify(self.conn, self.key)
        self.assertFalse(ok)
        self.assertEqual(bad, seq + 1)

    def test_key_is_not_stored_on_server(self):
        self.enroll("phone")
        stored = store.get_device(self.conn, "phone")["key_hex"]
        self.assertNotIn(DEVICE_SECRET, stored)
        self.assertEqual(stored, liveness.device_key_hex(DEVICE_SECRET))


if __name__ == "__main__":
    unittest.main()