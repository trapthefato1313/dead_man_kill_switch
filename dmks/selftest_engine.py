"""Engine invariants exercised without pytest, used by `dmks selftest`.

These are the properties the whole design rests on. If one of them breaks, the
system is dangerous, so they are checked both here and in tests/.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from . import config as config_mod, engine, liveness, store

T0 = 1_700_000_000


class Harness:
    def __init__(self, root: Path, **overrides):
        self.key = config_mod.new_audit_key()
        self.conn = store.connect(root / "selftest.sqlite3")
        self.now = T0
        thresholds = {
            "warn_after": 7 * 86400,
            "arm_after": 14 * 86400,
            "release_after": 30 * 86400,
            "device_grace": 2 * 86400,
            "quorum_mode": "all",
            "quorum_n": 1,
            "confirmations": 2,
            "release_mode": "hold",
            "clock_skew": 300,
        }
        thresholds.update(overrides)
        with store.tx(self.conn):
            store.create_switch(
                self.conn, "s", name="selftest",
                owner_key=liveness.owner_key_hex("owner-secret"),
                recipients=[], now=self.now, **thresholds,
            )

    def enroll(self, device_id: str, secret: str = "shared"):
        with store.tx(self.conn):
            store.add_device(self.conn, device_id, "s", device_id,
                             liveness.device_key_hex(secret), self.now)

    def checkin(self, device_id: str, secret: str = "shared") -> None:
        nonce = liveness.new_nonce()
        token = liveness.sign_device(secret, "s", device_id, self.now, nonce)
        liveness.checkin(self.conn, self.key, "s", device_id, self.now, nonce, token, self.now)

    def advance(self, seconds: int) -> None:
        self.now += seconds

    def tick(self) -> engine.Evaluation:
        return engine.evaluate(self.conn, self.key, "s", self.now)

    def state(self) -> str:
        return store.get_switch(self.conn, "s")["state"]


CHECKS = []


def check(name: str):
    def wrap(fn):
        CHECKS.append((name, fn))
        return fn

    return wrap


@check("no device enrolled never fires")
def _no_devices(root: Path) -> bool:
    h = Harness(root)
    h.advance(400 * 86400)
    result = h.tick()
    return h.state() == "ok" and not result.quorum_met


@check("escalates ok -> warn -> armed -> released")
def _escalation(root: Path) -> bool:
    h = Harness(root)
    h.enroll("phone")
    h.checkin("phone")

    h.advance(8 * 86400)
    h.tick()
    if h.state() != "ok":
        return False

    h.tick()
    if h.state() != "warn":
        return False

    h.advance(8 * 86400)
    h.tick()
    h.tick()
    if h.state() != "armed":
        return False

    h.advance(20 * 86400)
    h.tick()
    h.tick()
    return h.state() == "released"


@check("a live device blocks the quorum forever")
def _quorum_blocks(root: Path) -> bool:
    h = Harness(root)
    h.enroll("phone")
    h.enroll("laptop")
    h.advance(60 * 86400)
    for _ in range(10):
        h.checkin("laptop")
        h.tick()
        h.advance(86400)
    return h.state() == "ok"


@check("check-in resets escalation")
def _reset(root: Path) -> bool:
    h = Harness(root)
    h.enroll("phone")
    h.advance(8 * 86400)
    h.tick()
    h.tick()
    if h.state() != "warn":
        return False
    h.checkin("phone")
    h.tick()
    return h.state() == "ok"


@check("backwards clock does not escalate")
def _clock_regression(root: Path) -> bool:
    h = Harness(root)
    h.enroll("phone")
    h.advance(60 * 86400)
    h.tick()
    h.tick()
    released = h.state() == "released"
    h.now = T0
    result = h.tick()
    return released and h.state() == "released" and any(
        "clock_regression_ignored" in note for note in result.notes
    )


@check("downtime does not lose escalation")
def _catch_up(root: Path) -> bool:
    h = Harness(root)
    h.enroll("phone")
    h.advance(400 * 86400)
    h.tick()
    h.tick()
    return h.state() == "released"


@check("released is terminal")
def _terminal(root: Path) -> bool:
    h = Harness(root)
    h.enroll("phone")
    h.advance(400 * 86400)
    h.tick()
    h.tick()
    if h.state() != "released":
        return False
    h.checkin("phone")
    h.advance(86400)
    h.tick()
    h.tick()
    return h.state() == "released"


def run_invariants() -> bool:
    ok = True
    for index, (name, fn) in enumerate(CHECKS):
        with tempfile.TemporaryDirectory() as tmp:
            try:
                passed = bool(fn(Path(tmp)))
            except Exception as exc:  # noqa: BLE001
                passed = False
                name = f"{name} [{type(exc).__name__}: {exc}]"
            ok &= passed
            print(f"   [{'ok' if passed else 'FALHOU'}] {index + 1}. {name}")
    return ok