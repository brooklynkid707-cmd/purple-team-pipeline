"""One alert schema across all three detection stacks.

Each stack reports alerts in its own shape (minisiem ``Alert`` dataclass,
Splunk result rows, Sentinel ``SimResult``). :class:`NormalizedAlert` is the
lowest common denominator the scoreboard needs: which stack fired, which rule,
what ATT&CK techniques, when, and the entities involved - plus a ``raw`` bag
for the report appendix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M",
)


def parse_ts(value: Any) -> float | None:
    """Best-effort timestamp -> epoch seconds (UTC)."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+0000"
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(str(value).strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text)
        return dt.timestamp()
    except ValueError:
        return None


_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def techniques_from_tags(tags: list[str]) -> list[str]:
    """Pull ATT&CK technique IDs out of ``attack.t1059.001`` style tags."""
    out: list[str] = []
    for tag in tags:
        m = _TECH_RE.search(tag.upper().replace("ATTACK.T", "T"))
        if m and m.group(0) not in out:
            out.append(m.group(0))
    return out


@dataclass
class NormalizedAlert:
    """A detection from any stack, in one shape."""

    stack: str                       # minisiem | splunk | sentinel
    rule: str                        # rule id / name
    rule_title: str
    techniques: list[str]
    timestamp: float | None          # epoch seconds of the earliest evidence
    severity: str = "medium"
    entities: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stack": self.stack,
            "rule": self.rule,
            "rule_title": self.rule_title,
            "techniques": self.techniques,
            "timestamp": self.timestamp,
            "timestamp_iso": iso(self.timestamp),
            "severity": self.severity,
            "entities": self.entities,
        }


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = ["NormalizedAlert", "parse_ts", "techniques_from_tags", "iso"]
