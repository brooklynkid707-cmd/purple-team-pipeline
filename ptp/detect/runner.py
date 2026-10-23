"""Run the three detection stacks and normalise their alerts.

Each adapter imports the real sibling package via :mod:`ptp.siblings`, runs it
over the matching telemetry directory, and converts its native results into
:class:`NormalizedAlert` objects. Adapters never raise out of :func:`run_all`:
a stack that is missing or errors is reported with ``ok=False`` and a reason,
so the scoreboard shows "2 of 3 stacks ran" instead of crashing.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import siblings
from .normalize import NormalizedAlert, parse_ts, techniques_from_tags

# Keys that hold a real event timestamp in a Splunk stats row, preferred over
# ``window_start`` (a bin floor that precedes the triggering event and would
# make MTTD negative). Order = preference.
_SPLUNK_TS_KEYS = ("event_time", "_time", "first_seen", "FirstSeen",
                   "first_attempt", "FirstAttempt", "last_seen", "LastSeen", "window_start")
_ENTITY_KEYS = ("user", "target_user", "src_ip", "host", "dest", "dest_ip", "dest_port", "base_domain")


@dataclass
class StackResult:
    stack: str
    ok: bool
    alerts: list[NormalizedAlert] = field(default_factory=list)
    reason: str = ""
    rules_run: int = 0


@dataclass
class DetectionRun:
    results: dict[str, StackResult]

    @property
    def alerts(self) -> list[NormalizedAlert]:
        out: list[NormalizedAlert] = []
        for r in self.results.values():
            out.extend(r.alerts)
        return out

    def by_stack(self, stack: str) -> list[NormalizedAlert]:
        r = self.results.get(stack)
        return r.alerts if r else []


# --------------------------------------------------------------------------- #
# minisiem (Sigma + correlation)
# --------------------------------------------------------------------------- #
def run_minisiem(telemetry_dir: Path) -> StackResult:
    try:
        pipeline_mod, storage_mod, rules_dir = siblings.minisiem_modules()
    except siblings.MissingSiblingError as exc:
        return StackResult("minisiem", False, reason=str(exc))
    data_dir = telemetry_dir / "minisiem"
    if not data_dir.is_dir():
        return StackResult("minisiem", False, reason=f"no telemetry at {data_dir}")
    with tempfile.TemporaryDirectory() as tmp:
        store = storage_mod.Store(str(Path(tmp) / "ptp.db"))
        pipeline = pipeline_mod.Pipeline(store, rules_dir=rules_dir, suppress_seconds=300, persist_alerts=False)
        pipeline.ingest_path(data_dir)
        pipeline.detect_stored()
        alerts = [_from_minisiem(a) for a in pipeline.memory.alerts]
    rules_run = len(pipeline.sigma.rules) + len(pipeline.correlation.rules)
    return StackResult("minisiem", True, alerts=alerts, rules_run=rules_run)


def _from_minisiem(alert: Any) -> NormalizedAlert:
    entities = {}
    for k, v in (("user", alert.user), ("src_ip", alert.source_ip), ("host", alert.host)):
        if v:
            entities[k] = v
    return NormalizedAlert(
        stack="minisiem", rule=alert.rule_id, rule_title=alert.title,
        techniques=list(alert.attack_techniques), timestamp=parse_ts(alert.timestamp),
        severity=alert.severity, entities=entities,
        raw={"rule_type": alert.rule_type, "evidence": len(alert.evidence)},
    )


# --------------------------------------------------------------------------- #
# Splunk harness (SPL evaluator + TA savedsearches)
# --------------------------------------------------------------------------- #
def run_splunk(telemetry_dir: Path) -> StackResult:
    try:
        run_mod, _catalog, app_dir = siblings.splunk_harness()
    except siblings.MissingSiblingError as exc:
        return StackResult("splunk", False, reason=str(exc))
    data_dir = telemetry_dir / "splunk"
    if not data_dir.is_dir():
        return StackResult("splunk", False, reason=f"no telemetry at {data_dir}")
    try:
        results, _count = run_mod.run_all(data_dir, expected=set(), only=None, app_dir=app_dir)
    except Exception as exc:  # noqa: BLE001 - a broken SPL run must not kill the pipeline
        return StackResult("splunk", False, reason=f"harness error: {exc}")
    alerts: list[NormalizedAlert] = []
    for r in results:
        if r.fired:
            alerts.extend(_from_splunk(r))
    return StackResult("splunk", True, alerts=alerts, rules_run=len(results))


def _from_splunk(result: Any) -> list[NormalizedAlert]:
    """One normalised alert per result row (a scheduled search can fire in
    several time bins; each is its own notable at its own timestamp)."""
    det = result.detection
    out: list[NormalizedAlert] = []
    for row in result.rows:
        ts = _earliest_row_ts([row])
        out.append(NormalizedAlert(
            stack="splunk", rule=det.id, rule_title=det.name,
            techniques=list(det.mitre_attack), timestamp=ts,
            severity=det.severity_name, entities=_row_entities([row]),
            raw={"result_count": len(result.rows)},
        ))
    return out or [NormalizedAlert("splunk", det.id, det.name, list(det.mitre_attack),
                                   None, det.severity_name, {}, {"result_count": 0})]


def _earliest_row_ts(rows: list[dict[str, Any]]) -> float | None:
    """Earliest real event time across rows, falling back to window_start only
    if no real event timestamp is present."""
    real: float | None = None
    floor: float | None = None
    for row in rows:
        for key in _SPLUNK_TS_KEYS:
            if key not in row:
                continue
            ts = parse_ts(row[key])
            if ts is None:
                continue
            if key == "window_start":
                floor = ts if floor is None else min(floor, ts)
            else:
                real = ts if real is None else min(real, ts)
    return real if real is not None else floor


def _row_entities(rows: list[dict[str, Any]]) -> dict[str, str]:
    if not rows:
        return {}
    row = rows[0]
    out: dict[str, str] = {}
    for key in _ENTITY_KEYS:
        if key in row and row[key] not in (None, "", []):
            val = row[key]
            out[key] = ",".join(str(v) for v in val[:2]) if isinstance(val, list) else str(val)
    return out


# --------------------------------------------------------------------------- #
# Sentinel (simulate.py KQL-subset evaluator)
# --------------------------------------------------------------------------- #
def run_sentinel(telemetry_dir: Path) -> StackResult:
    try:
        sim, rules_dir = siblings.sentinel_simulator()
    except siblings.MissingSiblingError as exc:
        return StackResult("sentinel", False, reason=str(exc))
    samples_dir = telemetry_dir / "sentinel"
    if not (samples_dir / "SecurityEvent.json").is_file():
        return StackResult("sentinel", False, reason=f"no telemetry at {samples_dir}")
    try:
        results = sim.simulate_dir(rules_dir, samples_dir)
    except Exception as exc:  # noqa: BLE001
        return StackResult("sentinel", False, reason=f"simulate error: {exc}")
    alerts: list[NormalizedAlert] = []
    for r in results:
        if r.supported and r.would_fire:
            alerts.extend(_from_sentinel(r, rules_dir))
    supported = sum(1 for r in results if r.supported)
    return StackResult("sentinel", True, alerts=alerts, rules_run=supported)


def _from_sentinel(result: Any, rules_dir: Path) -> list[NormalizedAlert]:
    import yaml
    rule_doc: dict[str, Any] = {}
    path = rules_dir / result.rule_file
    if path.is_file():
        rule_doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    techniques = list(rule_doc.get("relevantTechniques", []))
    rule = result.rule_file.replace(".yaml", "")
    sev = str(rule_doc.get("severity", "medium")).lower()
    out: list[NormalizedAlert] = []
    for row in result.rows:
        ts = _earliest_row_ts([row]) or _sentinel_row_ts([row])
        out.append(NormalizedAlert(
            stack="sentinel", rule=rule, rule_title=result.rule_name,
            techniques=techniques, timestamp=ts, severity=sev,
            entities=_sentinel_entities([row]), raw={"result_count": len(result.rows)},
        ))
    return out or [NormalizedAlert("sentinel", rule, result.rule_name, techniques, None, sev, {}, {})]


def _sentinel_row_ts(rows: list[dict[str, Any]]) -> float | None:
    best: float | None = None
    for row in rows:
        for key in ("TimeGenerated", "FirstFailure", "FirstSeen"):
            if key in row:
                ts = parse_ts(row[key])
                if ts is not None and (best is None or ts < best):
                    best = ts
    return best


def _sentinel_entities(rows: list[dict[str, Any]]) -> dict[str, str]:
    if not rows:
        return {}
    row = rows[0]
    out: dict[str, str] = {}
    for src, dst in (("SubjectUserName", "user"), ("TargetUserName", "target_user"),
                     ("IpAddress", "src_ip"), ("Computer", "host")):
        if row.get(src):
            out[dst] = str(row[src])
    return out


# --------------------------------------------------------------------------- #
def run_all(telemetry_dir: str | Path) -> DetectionRun:
    """Run every detection stack over ``<telemetry_dir>`` and return their alerts."""
    telemetry_dir = Path(telemetry_dir)
    results = {
        "minisiem": run_minisiem(telemetry_dir),
        "splunk": run_splunk(telemetry_dir),
        "sentinel": run_sentinel(telemetry_dir),
    }
    return DetectionRun(results=results)


__all__ = ["run_all", "run_minisiem", "run_splunk", "run_sentinel", "DetectionRun", "StackResult"]
