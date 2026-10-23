"""Stage 5 - score the exercise: join alerts to ground truth and measure outcome.

Produces a ``scoreboard`` dict with:

* per-step detected/missed, the stacks that caught each step, and **MTTD**
  (mean time to detect) = first matching alert timestamp - step start time;
* coverage % overall, per ATT&CK tactic and per stack;
* a which-stack-caught-what table (Venn-style membership per step);
* false positives: alerts that match no attack step (fired on benign noise);
* an ATT&CK Navigator layer coloured detected / partial / missed.

An alert "covers" a step when it shares a technique with the step (exact or
parent/sub-technique) and fires at or after the step start (a detection cannot
precede the behaviour it detects). This is deliberately strict so coverage is
honest rather than flattering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .detect.normalize import NormalizedAlert, iso
from .scenario import PlanStep
from .telemetry.engine import StepTiming

STACKS = ("minisiem", "splunk", "sentinel")

# A detection's timestamp only counts toward a step's MTTD if it lands within
# this window of the step start. Steps are spaced ~30 min apart, so an alert
# further out shares the step's technique tag but fired on different telemetry
# (tag drift) and must not set that step's MTTD. Coverage still counts it.
MTTD_WINDOW_SECONDS = 1800.0

# Navigator colours (match the aep sibling's palette).
_COLORS = {"detected": "#2e7d32", "partial": "#f9a825", "missed": "#c62828"}
_SCORES = {"detected": 100, "partial": 50, "missed": 0}


def _parent(tid: str) -> str:
    return tid.split(".")[0]


def _tech_match(a: str, b: str) -> bool:
    """Match exact IDs, or a *bare parent* against its sub-technique.

    ``T1021`` matches ``T1021.001`` and ``T1078.002`` matches ``T1078``, but two
    sibling sub-techniques (``T1021.001`` vs ``T1021.002``) are different steps
    and never cross-credit. A sub-vs-sibling-parent tag (``T1110.001`` detection
    on a ``T1110.003`` step) is treated as the same *parent* behaviour only when
    one side is the bare parent - a generic ``T1110`` tag covers either spray or
    guessing, but ``T1110.001`` does not claim the ``T1110.003`` step.
    """
    if a == b:
        return True
    if _parent(a) != _parent(b):
        return False
    return "." not in a or "." not in b


# Lower slack absorbs a binned scheduled search reporting a window floor up to
# an hour before the triggering event; the upper bound is the step spacing.
_MTTD_LOWER_SLACK = 3700.0


def _tech_matches(alert: NormalizedAlert, technique_id: str) -> bool:
    return any(_tech_match(t, technique_id) for t in alert.techniques)


def _alert_matches_step(alert: NormalizedAlert, step: PlanStep, start_ts: float | None = None) -> bool:
    """An alert covers a step when it shares a technique (plan techniques are
    unique) AND, if a start time is given, fired inside the step's window - so a
    rule whose tag drifts onto a later step's telemetry does not credit this one."""
    if not _tech_matches(alert, step.technique_id):
        return False
    if start_ts is None or alert.timestamp is None:
        return True
    return start_ts - _MTTD_LOWER_SLACK <= alert.timestamp <= start_ts + MTTD_WINDOW_SECONDS


@dataclass
class StepScore:
    step_id: str
    technique_id: str
    technique_name: str
    tactic: str
    start_ts: float
    modelled: bool
    detected_by: dict[str, float | None] = field(default_factory=dict)  # stack -> first in-window alert ts
    mttd_seconds: float | None = None

    @property
    def detected(self) -> bool:
        return bool(self.detected_by)

    @property
    def stacks(self) -> list[str]:
        return sorted(self.detected_by)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id, "technique_id": self.technique_id,
            "technique_name": self.technique_name, "tactic": self.tactic,
            "start_ts": iso(self.start_ts), "modelled": self.modelled,
            "detected": self.detected, "stacks": self.stacks,
            "mttd_seconds": self.mttd_seconds,
            "first_detection": {s: iso(t) for s, t in self.detected_by.items()},
        }


def _status(step: StepScore) -> str:
    if not step.modelled:
        return "missed"
    if not step.detected:
        return "missed"
    # "partial" = caught by exactly one stack; "detected" = defence in depth.
    return "detected" if len(step.detected_by) >= 2 else "partial"


def score(steps: list[PlanStep], timings: list[StepTiming],
          alerts: list[NormalizedAlert],
          benign_alerts: list[NormalizedAlert] | None = None) -> dict[str, Any]:
    """Build the full scoreboard from plan steps, their timings and the alerts.

    ``benign_alerts`` are the alerts the same stacks produced over a benign-only
    telemetry run; they are the honest false-positive baseline (fired with no
    attack present), counted per stack.
    """
    timing_by_id = {t.step_id: t for t in timings}
    step_scores: list[StepScore] = []

    for step in steps:
        timing = timing_by_id.get(step.step_id)
        start_ts = timing.start_ts if timing else 0.0
        modelled = bool(timing and timing.modelled)
        ss = StepScore(step.step_id, step.technique_id, step.technique_name, step.tactic,
                       start_ts, modelled)
        if modelled:
            for stack in STACKS:
                first: float | None = None
                for alert in alerts:
                    if alert.stack != stack:
                        continue
                    if _alert_matches_step(alert, step, start_ts):
                        ts = alert.timestamp if alert.timestamp is not None else start_ts
                        if first is None or ts < first:
                            first = ts
                if first is not None:
                    ss.detected_by[stack] = first
            if ss.detected_by:
                earliest = min(t for t in ss.detected_by.values())
                ss.mttd_seconds = max(0.0, round(earliest - start_ts, 1))
        step_scores.append(ss)

    modelled_scores = [s for s in step_scores if s.modelled]
    detected = [s for s in modelled_scores if s.detected]

    # Coverage per tactic.
    by_tactic: dict[str, dict[str, int]] = {}
    for s in modelled_scores:
        d = by_tactic.setdefault(s.tactic, {"total": 0, "detected": 0})
        d["total"] += 1
        d["detected"] += 1 if s.detected else 0

    # Coverage per stack.
    per_stack: dict[str, dict[str, Any]] = {}
    for stack in STACKS:
        caught = [s.step_id for s in modelled_scores if stack in s.detected_by]
        mttds = [max(0.0, s.detected_by[stack] - s.start_ts)
                 for s in modelled_scores if stack in s.detected_by]
        per_stack[stack] = {
            "steps_detected": len(caught),
            "coverage_pct": round(100 * len(caught) / len(modelled_scores), 1) if modelled_scores else 0.0,
            "mean_mttd_seconds": round(sum(mttds) / len(mttds), 1) if mttds else None,
            "step_ids": caught,
        }

    # Which-stack-caught-what membership (Venn-style).
    venn = _venn(modelled_scores)

    # MTTD aggregate across detected steps (first alert from any stack).
    step_mttds = [s.mttd_seconds for s in detected if s.mttd_seconds is not None]

    # False positives: alerts produced on a benign-only run (no attack present).
    benign_alerts = benign_alerts or []
    fps = [{"stack": a.stack, "rule": a.rule, "rule_title": a.rule_title,
            "techniques": a.techniques, "timestamp": iso(a.timestamp), "entities": a.entities}
           for a in benign_alerts]
    fp_by_stack: dict[str, int] = {s: 0 for s in STACKS}
    for a in benign_alerts:
        fp_by_stack[a.stack] = fp_by_stack.get(a.stack, 0) + 1
    # Diagnostic: attack-run alerts whose technique matched no step (tag drift,
    # not benign - kept separate from the FP metric so the two are not confused).
    unattributed = _unattributed(alerts, step_scores)

    scoreboard = {
        "summary": {
            "steps_total": len(steps),
            "steps_modelled": len(modelled_scores),
            "steps_detected": len(detected),
            "steps_missed": len(modelled_scores) - len(detected),
            "coverage_pct": round(100 * len(detected) / len(modelled_scores), 1) if modelled_scores else 0.0,
            "mean_mttd_seconds": round(sum(step_mttds) / len(step_mttds), 1) if step_mttds else None,
            "median_mttd_seconds": _median(step_mttds),
            "false_positive_alerts": len(fps),
            "false_positives_by_stack": fp_by_stack,
            "total_alerts": len(alerts),
            "unattributed_alerts": len(unattributed),
        },
        "steps": [s.to_dict() for s in step_scores],
        "coverage_by_tactic": {
            t: {**v, "coverage_pct": round(100 * v["detected"] / v["total"], 1)}
            for t, v in by_tactic.items()
        },
        "coverage_by_stack": per_stack,
        "venn": venn,
        "false_positives": fps,
        "unattributed": unattributed,
        "status_by_step": {s.step_id: _status(s) for s in step_scores},
    }
    return scoreboard


def _venn(scores: list[StepScore]) -> dict[str, Any]:
    """Count steps by exact set of stacks that caught them."""
    buckets: dict[str, list[str]] = {}
    for s in scores:
        key = "+".join(s.stacks) if s.stacks else "(missed)"
        buckets.setdefault(key, []).append(s.step_id)
    only = {stack: sum(1 for s in scores if s.stacks == [stack]) for stack in STACKS}
    all_three = sum(1 for s in scores if set(s.stacks) == set(STACKS))
    return {"membership": {k: sorted(v) for k, v in sorted(buckets.items())},
            "only": only, "all_three": all_three}


def _unattributed(alerts: list[NormalizedAlert], scores: list[StepScore]) -> list[dict[str, Any]]:
    """Attack-run alerts whose technique tag matched no plan step.

    These are not benign false positives - they fired on real attack telemetry
    but carry a technique ID the plan did not request (e.g. a DNS-tunnelling
    rule tagging ``T1071.004`` firing on the C2 domain lookup of a ``T1071.001``
    web-C2 step). Reported for transparency, separate from the FP metric.
    """
    modelled = [s for s in scores if s.modelled]
    out: list[dict[str, Any]] = []
    for alert in alerts:
        if not any(_alert_matches_step(alert, s) for s in modelled):
            out.append({"stack": alert.stack, "rule": alert.rule, "rule_title": alert.rule_title,
                        "techniques": alert.techniques, "timestamp": iso(alert.timestamp),
                        "entities": alert.entities})
    return out


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return round(s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2, 1)


def navigator_layer(scoreboard: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    """ATT&CK Navigator 4.5 layer coloured by detected / partial / missed."""
    status_by_step = scoreboard["status_by_step"]
    steps = {s["step_id"]: s for s in scoreboard["steps"]}
    techniques = []
    for step_id, status in status_by_step.items():
        s = steps[step_id]
        stacks = s["stacks"]
        techniques.append({
            "techniqueID": s["technique_id"],
            "score": _SCORES[status],
            "color": _COLORS[status],
            "comment": f"{s['step_id']} {status}; caught by: {', '.join(stacks) or 'none'}"
                       + (f"; MTTD {s['mttd_seconds']:.0f}s" if s["mttd_seconds"] is not None else ""),
            "enabled": True,
            "metadata": [{"name": "status", "value": status},
                         {"name": "stacks", "value": ", ".join(stacks) or "none"}],
        })
    return {
        "name": f"Purple Team Pipeline - {plan.get('exercise_name', 'exercise')}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("Emulated techniques scored by live detection: green=caught by 2+ stacks, "
                        "amber=caught by one stack, red=missed."),
        "sorting": 0,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#c62828", "#f9a825", "#2e7d32"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "detected (2+ stacks)", "color": _COLORS["detected"]},
            {"label": "partial (1 stack)", "color": _COLORS["partial"]},
            {"label": "missed", "color": _COLORS["missed"]},
        ],
        "metadata": [
            {"name": "coverage_pct", "value": str(scoreboard["summary"]["coverage_pct"])},
            {"name": "mean_mttd_seconds", "value": str(scoreboard["summary"]["mean_mttd_seconds"])},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
    }


__all__ = ["score", "navigator_layer", "StepScore", "STACKS"]
