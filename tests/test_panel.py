"""The panel's own security properties.

The panel is the one place where a stolen secret would be worst: whoever holds
it can keep the switch quiet forever, which is the same as never firing. So the
tests below are mostly about what must NOT be possible.
"""

import json
import threading
import unittest
import urllib.error
import urllib.request

from dmks import liveness, store
from dmks.server import serve

from .helpers import DAY, T0, Base

PASSWORD = "correct horse battery staple"


class PanelBase(Base):
    """Base already builds a switch with an owner key; we add a panel password."""

    def setUp(self):
        super().setUp()
        with store.tx(self.conn):
            store.set_owner_pwhash(self.conn, "s", liveness.hash_password(PASSWORD))
        self.audit_key = self.key
        self.start()

    def start(self):
        self.cfg.server.host = "127.0.0.1"
        self.cfg.server.port = 0  # ephemeral, so parallel runs never collide
        httpd = serve(self.cfg, self.conn, self.key)
        httpd.ctx.now = lambda: float(self.now)
        self.addCleanup(httpd.server_close)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{httpd.server_address[1]}"
        return self.conn

    def get(self, path, cookie=None):
        req = urllib.request.Request(self.base + path)
        if cookie:
            req.add_header("Cookie", cookie)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode(), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), e.headers

    def post(self, path, body, cookie=None):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        if cookie:
            req.add_header("Cookie", cookie)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def login(self, password=PASSWORD):
        """Log in and return the raw `Cookie:` header value, or None on failure."""
        req = urllib.request.Request(
            self.base + "/api/login",
            data=json.dumps({"password": password}).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.headers["Set-Cookie"]
        except urllib.error.HTTPError:
            return None


class Page(PanelBase):
    def test_root_serves_the_panel(self):
        status, body, headers = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("<title>dead man's switch</title>", body)

    def test_the_page_asks_no_third_party_for_anything(self):
        """A dead man's switch must not depend on somebody else's CDN.

        It has to load on a bad connection, and a script tag pointing at another
        server hands that server a view of when a person last checked in.
        """
        _, body, _ = self.get("/")
        for needle in ("http://", "https://", "cdn", "integrity="):
            self.assertNotIn(needle, body, f"page references {needle!r}")

    def test_the_page_does_not_leak_a_secret(self):
        _, body, _ = self.get("/")
        for needle in ("owner_key", self.cfg.audit_key.hex()):
            self.assertNotIn(needle, body)


class Auth(PanelBase):
    def test_panel_requires_a_session(self):
        status, body, _ = self.get("/api/panel")
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "no session")

    def test_login_with_the_wrong_password_fails(self):
        self.assertIsNone(self.login("wrong wrong wrong"))
        self.assertEqual(self.get("/api/panel")[0], 401)

    def test_login_sets_an_httponly_samesite_cookie(self):
        raw = self.login()
        self.assertIn("HttpOnly", raw)
        self.assertIn("SameSite=Strict", raw)

    def test_panel_works_with_a_session(self):
        raw = self.login()
        status, body, _ = self.get("/api/panel", raw)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["status"]["switch"], "s")
        self.assertIn("release_after_seconds", payload["status"])
        self.assertTrue(payload["audit"]["ok"])

    def test_a_switch_with_no_password_has_no_panel(self):
        with store.tx(self.conn):
            store.set_owner_pwhash(self.conn, "s", None)
        self.assertIsNone(self.login())

    def test_a_stolen_cookie_alone_cannot_check_in(self):
        """The whole point of asking the password twice.

        Otherwise an unattended browser, a shared tablet or a leaked session is
        exactly as good as never having died at all.
        """
        raw = self.login()
        status, body = self.post("/api/confirm", {}, raw)
        self.assertEqual(status, 401)
        self.assertIn("password", body["error"])

    def test_a_stolen_cookie_cannot_cancel_either(self):
        raw = self.login()
        status, _ = self.post(
            "/api/cancel", {"switch": "s", "ts": T0, "nonce": "x", "token": "y"}, raw
        )
        self.assertEqual(status, 401)


class Confirm(PanelBase):
    def test_the_button_breaks_silence_and_returns_a_receipt(self):
        raw = self.login()
        status, body = self.post("/api/confirm", {"password": PASSWORD}, raw)
        self.assertEqual(status, 200)
        self.assertIn("receipt", body)
        self.assertEqual(body["receipt"]["audit_seq"], 1)  # first entry: the check-in itself
        self.assertEqual(body["receipt"]["at"], T0)
        self.assertEqual(len(body["receipt"]["audit_hash"]), 64)
        self.assertEqual(store.last_checkin_at(self.conn, "s"), T0)

    def test_the_receipt_is_in_the_audit_chain(self):
        from dmks import audit

        raw = self.login()
        _, body = self.post("/api/confirm", {"password": PASSWORD}, raw)
        ok, count, bad, reason = audit.verify(self.conn, self.key)
        self.assertTrue(ok, reason)
        self.assertEqual(count, 1)
        row = self.conn.execute(
            "SELECT * FROM audit_log WHERE seq=?", (body["receipt"]["audit_seq"],)
        ).fetchone()
        self.assertEqual(row["hash"], body["receipt"]["audit_hash"])
        self.assertEqual(row["event"], "owner_confirmed")

    def test_checkin_is_recorded_as_the_owner_not_a_device(self):
        raw = self.login()
        self.post("/api/confirm", {"password": PASSWORD}, raw)
        rows = self.conn.execute("SELECT device_id FROM checkins").fetchall()
        self.assertEqual([r["device_id"] for r in rows], ["owner"])

    def test_checkin_resets_escalation_from_warn(self):
        with store.tx(self.conn):
            store.update_switch(self.conn, "s", state="warn", now=T0, confirm_count=1)
        raw = self.login()
        status, body = self.post("/api/confirm", {"password": PASSWORD}, raw)
        self.assertEqual(status, 200)
        self.assertEqual(body["from_state"], "warn")
        self.assertEqual(body["state"], "ok")
        self.assertEqual(store.get_switch(self.conn, "s")["state"], "ok")
        self.assertEqual(store.get_switch(self.conn, "s")["confirm_count"], 0)

    def test_checkin_after_release_does_not_unsend_the_packet(self):
        """released is terminal. Good news must not rewrite history."""
        with store.tx(self.conn):
            store.update_switch(self.conn, "s", state="released", now=T0, released_at=T0)
        raw = self.login()
        status, body = self.post("/api/confirm", {"password": PASSWORD}, raw)
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "released")
        self.assertEqual(store.get_switch(self.conn, "s")["state"], "released")
        row = self.conn.execute(
            "SELECT event FROM audit_log WHERE seq=?", (body["receipt"]["audit_seq"],)
        ).fetchone()
        self.assertEqual(row["event"], "owner_confirmed_after_release")

    def test_the_owner_can_check_in_more_than_once(self):
        """A fixed nonce here meant exactly one check-in per switch, ever.

        Found by clicking the button twice in the running server, not by the
        suite: every test here checked in only once.
        """
        raw = self.login()
        for expected in range(1, 6):
            status, body = self.post("/api/confirm", {"password": PASSWORD}, raw)
            self.assertEqual(status, 200, body)
            self.assertEqual(body["receipt"]["audit_seq"], expected)
        rows = self.conn.execute("SELECT nonce FROM checkins").fetchall()
        self.assertEqual(len(rows), 5)
        self.assertEqual(len({r["nonce"] for r in rows}), 5, "nonces must differ")

    def test_two_check_ins_at_the_same_instant_still_work(self):
        raw = self.login()
        a = self.post("/api/confirm", {"password": PASSWORD}, raw)
        b = self.post("/api/confirm", {"password": PASSWORD}, raw)
        self.assertEqual(a[0], 200)
        self.assertEqual(b[0], 200)
        self.assertNotEqual(a[1]["receipt"]["audit_hash"], b[1]["receipt"]["audit_hash"])

    def test_wrong_password_on_the_button_changes_nothing(self):
        before = self.conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
        raw = self.login()
        status, _ = self.post("/api/confirm", {"password": "not it"}, raw)
        self.assertEqual(status, 401)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"], before
        )
        self.assertIsNone(store.last_checkin_at(self.conn, "s"))

    def test_empty_password_is_refused(self):
        raw = self.login()
        status, _ = self.post("/api/confirm", {"password": ""}, raw)
        self.assertEqual(status, 401)

    def test_an_audit_entry_alone_cannot_fake_a_checkin(self):
        """The chain is append-only and readable, but it is not writable."""
        from dmks import audit

        before = store.last_checkin_at(self.conn, "s")
        self.conn.execute(
            "INSERT INTO audit_log(seq, at, event, detail, prev_hash, hash) VALUES(?,?,?,?,?,?)",
            (99, T0, "owner_confirmed", "{}", "0" * 64, "f" * 64),
        )
        self.assertIsNone(store.last_checkin_at(self.conn, "s"))
        ok, count, bad, reason = audit.verify(self.conn, self.key)
        self.assertFalse(ok)
        self.assertIsNone(before)


class Throttle(PanelBase):
    """The panel is on the public internet. Without a limit, the password is the
    only thing between a stranger and the power to keep the switch quiet."""

    def test_wrong_passwords_eventually_lock_the_source(self):
        from dmks.server import LOGIN_MAX_FAILURES

        for _ in range(LOGIN_MAX_FAILURES):
            self.assertIsNone(self.login("wrong"))
        # Even the right password is refused once the source is throttled.
        self.assertIsNone(self.login(PASSWORD))
        status, body = self.post("/api/login", {"password": PASSWORD})
        self.assertEqual(status, 429)
        self.assertIn("too many", body["error"])

    def test_a_correct_password_before_the_limit_clears_the_counter(self):
        from dmks.server import LOGIN_MAX_FAILURES

        for _ in range(LOGIN_MAX_FAILURES - 1):
            self.login("wrong")
        self.assertIsNotNone(self.login(PASSWORD))  # not yet throttled
        for _ in range(LOGIN_MAX_FAILURES - 1):
            self.login("wrong")
        self.assertIsNotNone(self.login(PASSWORD))  # counter was cleared

    def test_the_window_expires(self):
        from dmks.server import LOGIN_MAX_FAILURES, LOGIN_WINDOW

        for _ in range(LOGIN_MAX_FAILURES):
            self.login("wrong")
        self.assertIsNone(self.login(PASSWORD))
        self.now += LOGIN_WINDOW + 1
        self.assertIsNotNone(self.login(PASSWORD))

    def test_failed_attempts_do_not_touch_the_audit_chain(self):
        from dmks import audit

        for _ in range(5):
            self.login("wrong")
        ok, count, bad, reason = audit.verify(self.conn, self.key)
        self.assertTrue(ok, reason)
        self.assertEqual(count, 0)


class PasswordHash(unittest.TestCase):
    def test_roundtrip(self):
        h = liveness.hash_password("hunter2 hunter2")
        self.assertTrue(liveness.verify_password(h, "hunter2 hunter2"))
        self.assertFalse(liveness.verify_password(h, "hunter2 hunter3"))

    def test_salt_makes_hashes_differ(self):
        self.assertNotEqual(
            liveness.hash_password("same same same"),
            liveness.hash_password("same same same"),
        )

    def test_garbage_does_not_raise(self):
        self.assertFalse(liveness.verify_password("nonsense", "x"))
        self.assertFalse(liveness.verify_password("", "x"))
        self.assertFalse(liveness.verify_password("a$b$c$d", "x"))