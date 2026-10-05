"""Deciding whether the clock can be trusted with an irreversible decision.

A dead man's switch acts on the absence of a signal, so the one thing that must
never happen is a wrong "now". A backwards jump is already handled by the
watermark. A *forwards* jump is the dangerous one: an NTP step, a resumed VM, a
timezone bug, and ten years of silence is credited in a single tick.

The watermark cannot fix this on its own, because from one clock alone
"the server was off for ten days" and "the clock jumped ten days" are the same
observation. Telling them apart needs a second clock, which is why corroboration
exists. Without corroboration the only safe move is to credit time slowly and
say so loudly: delay the release, never bring it forward.
"""

from __future__ import annotations

import email.utils
import statistics
import urllib.error
import urllib.request
from dataclasses import dataclass

# Independent enough that one provider being wrong cannot vouch for the clock.
DEFAULT_TIME_SOURCES = (
    "https://www.cloudflare.com",
    "https://www.google.com",
    "https://www.apple.com",
)

# HTTP Date has one-second resolution and a coarse tolerance is fine: we are
# detecting gross disagreement, not sub-second drift.
DEFAULT_TOLERANCE = 900


@dataclass
class Reading:
    source: str
    when: int


@dataclass
class Verdict:
    """ok          - the clock is corroborated, credit the full gap
    uncorroborated - no second clock available, credit up to the cap
    disagree    - the clocks contradict each other, do not escalate at all
    """

    status: str
    external: int | None = None
    spread: int | None = None
    detail: str = ""
    readings: tuple[Reading, ...] = ()

    @property
    def trustworthy(self) -> bool:
        return self.status in ("ok", "uncorroborated")


def read_source(url: str, timeout: float = 5.0) -> int | None:
    """Return the sender's clock from the HTTP Date header, or None.

    The Date header is stamped by the remote host, not derived from anything we
    control, which is the entire reason it is useful here.
    """
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "dmks-clock/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.headers.get("Date")
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if not raw:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    return int(parsed.timestamp())


def assess(
    observed: int,
    sources: tuple[str, ...] = DEFAULT_TIME_SOURCES,
    tolerance: int = DEFAULT_TOLERANCE,
    timeout: float = 5.0,
    probe=None,
) -> Verdict:
    """Compare the local clock against whatever independent clocks answered."""
    probe = probe or (lambda url: read_source(url, timeout))
    readings: list[Reading] = []
    for url in sources:
        try:
            when = probe(url)
        except Exception:  # noqa: BLE001 - a hostile or broken source must not stop the guard
            continue
        if when is not None:
            readings.append(Reading(url, when))

    if not readings:
        return Verdict("uncorroborated", detail="no external time source answered")

    values = [r.when for r in readings]
    median = int(statistics.median(values))
    spread = max(values) - min(values)
    if spread > tolerance:
        return Verdict(
            "disagree",
            external=median,
            spread=spread,
            detail=f"external clocks disagree by {spread}s, above tolerance {tolerance}s",
            readings=tuple(readings),
        )
    drift = abs(median - observed)
    if drift > tolerance:
        return Verdict(
            "disagree",
            external=median,
            spread=spread,
            detail=f"local clock is {drift}s away from the external median {median}",
            readings=tuple(readings),
        )
    return Verdict(
        "ok",
        external=median,
        spread=spread,
        detail=f"local clock corroborated by {len(readings)} source(s), drift {drift}s",
        readings=tuple(readings),
    )