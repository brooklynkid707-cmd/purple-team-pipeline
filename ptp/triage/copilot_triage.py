"""Triage normalised alerts through ai-soc-copilot (rules backend).

Each :class:`NormalizedAlert` is converted to a copilot ``Alert`` and run
through the copilot ``Pipeline``; the copilot returns a severity, a technique
and a confidence, and keeps its guardrails on (alert text is attacker-
controlled). We keep both the stack's own technique and the copilot's verdict
so the report can show where they agree.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import siblings
from ..detect.normalize import NormalizedAlert, iso

# map a detection stack to the copilot alert `source` enum
_SOURCE = {"minisiem": "siem", "splunk": "siem", "sentinel": "siem"}


@dataclass
class TriageVerdict:
    alert_ref: str                   # "<stack>:<rule>"
    stack: str
    stack_techniques: list[str]
    copilot_severity: str
    copilot_technique: str
    copilot_confidence: float
    flags: list[str] = field(default_factory=list)
    needs_human: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_ref": self.alert_ref, "stack": self.stack,
            "stack_techniques": self.stack_techniques,
            "copilot_severity": self.copilot_severity,
            "copilot_technique": self.copilot_technique,
            "copilot_confidence": round(self.copilot_confidence, 2),
            "flags": self.flags, "needs_human": self.needs_human,
        }


def _to_copilot_alert(schema_mod: Any, alert: NormalizedAlert, index: int) -> Any:
    row = {
        "id": f"PTP-{index:04d}",
        "timestamp": iso(alert.timestamp) or "2026-10-20T00:00:00Z",
        "source": _SOURCE.get(alert.stack, "siem"),
        "rule_name": alert.rule_title[:120] or alert.rule,
        "title": f"[{alert.stack}] {alert.rule_title}"[:160],
        "description": (f"Detection '{alert.rule_title}' fired on {alert.stack} "
                        f"for techniques {', '.join(alert.techniques) or 'n/a'}."),
    }
    for key in ("host", "user", "src_ip", "dst_ip"):
        if key in alert.entities:
            row[key] = alert.entities[key]
    return schema_mod.Alert.from_dict(row)


def triage_alerts(alerts: list[NormalizedAlert], out_dir: str | Path) -> list[TriageVerdict]:
    """Run every alert through the copilot rules reasoner; empty list if unavailable."""
    try:
        workflow, schema = siblings.copilot_modules()
    except siblings.MissingSiblingError:
        return []
    verdicts: list[TriageVerdict] = []
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = workflow.Pipeline(backend="rules", out_dir=str(Path(tmp) / "triage"))
        for i, alert in enumerate(alerts, 1):
            try:
                copilot_alert = _to_copilot_alert(schema, alert, i)
                rec = pipeline.process(copilot_alert)
            except Exception:  # noqa: BLE001 - never let one alert break triage
                continue
            res = rec.result
            verdicts.append(TriageVerdict(
                alert_ref=f"{alert.stack}:{alert.rule}", stack=alert.stack,
                stack_techniques=alert.techniques,
                copilot_severity=res.severity, copilot_technique=res.technique_id,
                copilot_confidence=float(res.confidence), flags=list(res.flags),
                needs_human=bool(res.needs_human),
            ))
    return verdicts


__all__ = ["TriageVerdict", "triage_alerts"]
