"""End-to-end orchestration: plan -> telemetry -> detect -> triage -> score -> report."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import report as report_mod
from . import scenario
from . import score as score_mod
from . import siblings
from .detect import run_all
from .telemetry import TelemetryEngine
from .triage import score_with_mltd, triage_alerts


@dataclass
class RunResult:
    out_dir: Path
    scoreboard: dict[str, Any]
    stacks_ran: list[str]
    artefacts: dict[str, Path] = field(default_factory=dict)

    @property
    def summary(self) -> dict[str, Any]:
        return self.scoreboard["summary"]


def run_pipeline(profile: str, env: str, out_dir: str | Path, *,
                 seed: int = 1337, with_triage: bool = True, with_ml: bool = True,
                 log=print) -> RunResult:
    """Run the whole exercise and write every artefact under ``out_dir``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    log(f"[1/6] planning  profile={profile} env={env}")
    plan = scenario.build_plan(profile, env)
    steps = scenario.flatten_steps(plan)
    (out / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    log(f"      {len(steps)} techniques across {plan['phase_count']} phases")

    log("[2/6] telemetry engine  (synthetic events + benign noise + ground truth)")
    engine = TelemetryEngine(seed=seed)
    telemetry = engine.run(steps, out)
    total_events = sum(telemetry.event_counts.values())
    log(f"      emitted {total_events} events; ground truth for {len(telemetry.modelled_steps)} steps")

    log("[3/6] detection  (mini-SIEM Sigma+correlation / Splunk SPL / Sentinel KQL)")
    run = run_all(out / "telemetry")
    stacks_ran = [k for k, v in run.results.items() if v.ok]
    for stack, res in run.results.items():
        if res.ok:
            log(f"      {stack:9s} {len(res.alerts):>3} alerts from {res.rules_run} rules")
        else:
            log(f"      {stack:9s} UNAVAILABLE: {res.reason.splitlines()[0]}")

    log("      false-positive baseline: re-running stacks on benign-only telemetry")
    benign_dir = out / "_benign"
    engine.run([], benign_dir)
    benign_run = run_all(benign_dir / "telemetry")
    benign_alerts = benign_run.alerts

    log("[4/6] triage  (ai-soc-copilot) + ML scoring (ml-threat-detection)")
    triage = triage_alerts(run.alerts, out) if with_triage else []
    ml_scores = score_with_mltd(out / "telemetry", out) if with_ml else []
    log(f"      copilot verdicts: {len(triage)}; ml detectors: "
        f"{', '.join(m.detector + ('*' if m.ran else '-') for m in ml_scores) or 'none'}")

    log("[5/6] scoring  (coverage, MTTD, Venn, Navigator layer)")
    scoreboard = score_mod.score(steps, telemetry.steps, run.alerts, benign_alerts)
    navigator = score_mod.navigator_layer(scoreboard, plan)
    (out / "scoreboard.json").write_text(json.dumps(scoreboard, indent=2), encoding="utf-8")
    (out / "navigator-layer.json").write_text(json.dumps(navigator, indent=2), encoding="utf-8")

    log("[6/6] report  (Markdown + HTML + SVG timeline + NIST 800-61 incident report)")
    context = {
        "profile": profile, "env": env, "plan": plan, "scoreboard": scoreboard,
        "stacks_ran": stacks_ran,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "alerts": [a.to_dict() for a in run.alerts],
        "triage": [v.to_dict() for v in triage],
        "ml_scores": [m.to_dict() for m in ml_scores],
    }
    context["incident_report_md"] = report_mod.build_incident_markdown(context)
    artefacts = report_mod.write_reports(context, out)
    (out / "triage.json").write_text(json.dumps(context["triage"], indent=2), encoding="utf-8")
    (out / "ml-scores.json").write_text(json.dumps(context["ml_scores"], indent=2), encoding="utf-8")

    # Clean up the benign scratch telemetry (keep the main run tidy).
    _rmtree(benign_dir)

    s = scoreboard["summary"]
    log("")
    log(f"  coverage {s['coverage_pct']}%  ({s['steps_detected']}/{s['steps_modelled']} techniques)   "
        f"mean MTTD {_fmt(s['mean_mttd_seconds'])}   FP {s['false_positive_alerts']}")
    log(f"  report:  {artefacts['md']}")
    log(f"  html:    {artefacts['html']}")
    return RunResult(out_dir=out, scoreboard=scoreboard, stacks_ran=stacks_ran, artefacts=artefacts)


def _fmt(secs: float | None) -> str:
    if secs is None:
        return "n/a"
    if secs < 60:
        return f"{secs:.0f}s"
    m, s = divmod(int(secs), 60)
    return f"{m}m{s:02d}s"


def _rmtree(path: Path) -> None:
    import shutil
    try:
        shutil.rmtree(path)
    except OSError:
        pass


__all__ = ["run_pipeline", "RunResult"]
