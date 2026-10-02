"""Configuration with defaults tuned to avoid false releases.

The single most dangerous failure mode of a dead man's switch is firing while
the owner is alive (phone stolen, no signal, hospital, holiday, laptop in a
drawer). Every default below is deliberately pessimistic: long windows,
multiple silent devices required, and re-confirmation before each escalation.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path

DAY = 86400

STATES = ("ok", "warn", "armed", "released", "cancelled")

RELEASE_MODES = ("hold", "notify", "publish")


@dataclass
class SwitchConfig:
    name: str
    warn_after: int = 7 * DAY

    # Optional: the owner may express the switch as just two deadlines. When
    # left unset the armed deadline is derived as the midpoint, so the third
    # escalation step still exists as a safety net.
    arm_after: int | None = 14 * DAY

    release_after: int = 30 * DAY

    # A device must be silent for at least this long before it is allowed to
    # count towards the quorum. Stops a single reboot from arming the switch.
    device_grace: int = 2 * DAY

    # "all" = every enabled device must be silent; "n" = at least n devices.
    quorum_mode: str = "all"
    quorum_n: int = 1

    # Escalate only after this many consecutive evaluations that meet the
    # quorum. One bad tick can never jump straight to release.
    confirmations: int = 2

    release_mode: str = "hold"

    # Accept check-in timestamps this far off server time.
    clock_skew: int = 300

    recipients: list[dict] = field(default_factory=list)


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8770
    tick_seconds: int = 3600

    # Delivery. At least one of smtp_* / webhook_urls is needed for "notify".
    # Proton Mail SMTP Submission: smtp.protonmail.ch:587, STARTTLS, and the
    # "password" is an SMTP token from the account settings, not the account
    # password. Only available on paid plans with a custom domain.
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_starttls: bool = True

    webhook_url: str | None = None
    webhook_urls: list[str] = field(default_factory=list)

    owner_email: str | None = None

    def all_webhook_urls(self) -> list[str]:
        """Every configured webhook, de-duplicated, legacy field included."""
        urls = [*self.webhook_urls]
        if self.webhook_url:
            urls.insert(0, self.webhook_url)
        seen: set[str] = set()
        unique: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique.append(url)
        return unique

    # Directory that becomes public when release_mode == "publish".
    publish_dir: str | None = None

    # Bearer token for POST /api/tick. Lets an external cron (for example a
    # GitHub Actions schedule) evaluate the switch without shell access, which
    # is the point: the server going down must not stop the switch from firing.
    tick_token: str | None = None


@dataclass
class Config:
    data_dir: Path
    audit_key: bytes
    server: ServerConfig = field(default_factory=ServerConfig)
    switches: dict[str, SwitchConfig] = field(default_factory=dict)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "dmks.sqlite3"

    @property
    def packets_dir(self) -> Path:
        return self.data_dir / "packets"


def new_audit_key() -> bytes:
    return secrets.token_bytes(32)


def load(data_dir: Path, key: bytes | None = None) -> Config:
    """Load config from <data_dir>/config.json, falling back to defaults."""
    data_dir = Path(data_dir)
    cfg_path = data_dir / "config.json"
    raw: dict = {}
    if cfg_path.exists():
        raw = json.loads(cfg_path.read_text())

    server_fields = {f.name for f in ServerConfig.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    server = ServerConfig(**{k: v for k, v in raw.get("server", {}).items() if k in server_fields})

    switches: dict[str, SwitchConfig] = {}
    for sid, val in raw.get("switches", {}).items():
        allowed = {f.name for f in SwitchConfig.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        switches[sid] = SwitchConfig(**{k: v for k, v in val.items() if k in allowed})

    return Config(
        data_dir=data_dir,
        audit_key=key if key is not None else bytes.fromhex(raw["audit_key"]),
        server=server,
        switches=switches,
    )


def save(cfg: Config) -> None:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "audit_key": cfg.audit_key.hex(),
        "server": asdict(cfg.server),
        "switches": {k: asdict(v) for k, v in cfg.switches.items()},
    }
    path = cfg.data_dir / "config.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def validate(cfg: Config) -> list[str]:
    """Return a list of configuration problems. Empty means valid."""
    problems: list[str] = []
    for sid, sw in cfg.switches.items():
        arm = resolve_arm(sw)
        if not (0 < sw.warn_after < arm < sw.release_after):
            problems.append(
                f"{sid}: thresholds must be strictly increasing, got "
                f"warn={sw.warn_after} arm={arm} release={sw.release_after}"
            )
        if sw.quorum_mode == "all":
            if not sw.recipients:
                problems.append(f"{sid}: quorum 'all' needs at least one enrolled device")
        elif sw.quorum_mode == "n":
            if sw.quorum_n < 1:
                problems.append(f"{sid}: quorum_n must be >= 1")
        else:
            problems.append(f"{sid}: quorum_mode must be 'all' or 'n', got {sw.quorum_mode!r}")
        if sw.release_mode not in RELEASE_MODES:
            problems.append(f"{sid}: release_mode must be one of {RELEASE_MODES}")
        if sw.confirmations < 1:
            problems.append(f"{sid}: confirmations must be >= 1")
        if sw.release_mode in ("notify", "publish"):
            if not sw.recipients:
                problems.append(f"{sid}: release_mode {sw.release_mode!r} needs recipients")
        if sw.release_mode == "notify" and not (
            cfg.server.smtp_host or cfg.server.all_webhook_urls()
        ):
            problems.append(f"{sid}: release_mode 'notify' needs smtp_host or a webhook_url")
        if sw.release_mode == "publish" and not cfg.server.publish_dir:
            problems.append(f"{sid}: release_mode 'publish' needs server.publish_dir")
    return problems


def resolve_arm(sw: SwitchConfig) -> int:
    """The armed deadline, derived when the owner only gave two deadlines."""
    if sw.arm_after is not None:
        return sw.arm_after
    return sw.warn_after + max(1, (sw.release_after - sw.warn_after) // 2)