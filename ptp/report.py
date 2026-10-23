"""Stage 6 - render the Purple Team Exercise Report.

Three artefacts, all dependency-free:

* ``report.md``    - Markdown: exec summary, kill-chain timeline with detections
  overlaid, coverage tables, gaps with recommended rules, alert appendix.
* ``report.html``  - a self-contained HTML version (inline CSS, the SVG embedded).
* ``timeline.svg`` - a hand-written SVG timeline (no libraries) showing each
  step on the kill chain coloured by detection status.

The incident-report narrative is produced by the ``soc-analyst-toolkit``
sibling from a case file this module assembles from the scoreboard, so the
"what happened / what to do" section is the real SOC report generator's output.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import siblings

_STATUS_LABEL = {"detected": "DETECTED", "partial": "PARTIAL", "missed": "MISSED"}
_STATUS_COLOR = {"detected": "#2e7d32", "partial": "#f9a825", "missed": "#c62828"}
_STACK_LABEL = {"minisiem": "mini-SIEM", "splunk": "Splunk", "sentinel": "Sentinel"}


# --------------------------------------------------------------------------- #
# SVG timeline
# --------------------------------------------------------------------------- #
def timeline_svg(scoreboard: dict[str, Any]) -> str:
    steps = scoreboard["steps"]
    status_by_step = scoreboard["status_by_step"]
    n = len(steps)
    left, top, row_h, width = 230, 70, 30, 980
    height = top + n * row_h + 40
    track_x0, track_x1 = left, width - 230
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'font-family="system-ui,Segoe UI,Arial,sans-serif" font-size="13">',
        f'<rect width="{width}" height="{height}" fill="#0f172a"/>',
        f'<text x="20" y="34" fill="#e2e8f0" font-size="19" font-weight="700">'
        f'Kill chain &#183; emulated techniques vs live detection</text>',
    ]
    legend = [("detected (2+ stacks)", "#2e7d32"), ("partial (1 stack)", "#f9a825"), ("missed", "#c62828")]
    lx = 20
    for label, color in legend:
        parts.append(f'<rect x="{lx}" y="46" width="12" height="12" rx="2" fill="{color}"/>')
        parts.append(f'<text x="{lx + 18}" y="56" fill="#94a3b8">{html.escape(label)}</text>')
        lx += 20 + 9 * len(label)

    for i, step in enumerate(steps):
        y = top + i * row_h + row_h // 2
        status = status_by_step[step["step_id"]]
        color = _STATUS_COLOR[status]
        parts.append(f'<line x1="{track_x0}" y1="{y}" x2="{track_x1}" y2="{y}" stroke="#1e293b" stroke-width="1"/>')
        label = f'{step["step_id"]} {step["technique_id"]} {step["technique_name"]}'
        if len(label) > 34:
            label = label[:33] + "…"
        parts.append(f'<text x="18" y="{y + 4}" fill="#cbd5e1">{html.escape(label)}</text>')
        parts.append(f'<text x="{left - 6}" y="{y + 4}" fill="#64748b" text-anchor="end" font-size="11">'
                     f'{html.escape(step["tactic"])}</text>')
        # progress along the track by phase order
        cx = track_x0 + (track_x1 - track_x0) * (i + 0.5) / n
        parts.append(f'<circle cx="{cx:.0f}" cy="{y}" r="7" fill="{color}" stroke="#0f172a" stroke-width="2"/>')
        stacks = step["stacks"]
        detail = _STATUS_LABEL[status]
        if stacks:
            detail += " &#183; " + ", ".join(_STACK_LABEL.get(s, s) for s in stacks)
            if step["mttd_seconds"] is not None:
                detail += f" &#183; MTTD {step['mttd_seconds']:.0f}s"
        parts.append(f'<text x="{track_x1 + 10}" y="{y + 4}" fill="{color}" font-size="11">{detail}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Markdown report
# --------------------------------------------------------------------------- #
def _bar(pct: float, width: int = 24) -> str:
    filled = round(width * pct / 100)
    return "#" * filled + "-" * (width - filled)


def _recommended_rule(step: dict[str, Any]) -> str:
    tactic = step["tactic"]
    tid = step["technique_id"]
    name = step["technique_name"]
    hints = {
        "discovery": "process-creation rule on net/dsquery/nltest with per-host rate baselining",
        "lateral-movement": "4624 type-3 NTLM / 5140 share-access correlation and 4648 explicit-credential fan-out",
        "collection": "Sysmon 1 rule on rar/7z/wbadmin with staging-path heuristics",
        "privilege-escalation": "Sysmon 1 high-integrity child of a known auto-elevating LOLBin (fodhelper/eventvwr)",
        "credential-access": "4769 RC4 (0x17) TGS volume per account (Kerberoasting)",
        "exfiltration": "per-host outbound byte baseline (eventstats mean+3sigma) and CASB upload volume",
        "impact": "Sysmon 1 rule on vssadmin/wbadmin/bcdedit and service-stop bursts before mass writes",
        "command-and-control": "beacon analysis (interval CV) plus threat-intel domain/IP match",
        "execution": "service-install (7045) to a user-writable ImagePath",
    }
    return hints.get(tactic, f"author a detection for {tid} ({name}) over its expected telemetry")


def markdown_report(context: dict[str, Any]) -> str:
    sb = context["scoreboard"]
    s = sb["summary"]
    plan = context["plan"]
    stacks_ran = context["stacks_ran"]
    lines: list[str] = []
    w = lines.append

    w(f"# Purple Team Exercise Report")
    w("")
    w(f"**Exercise:** {plan.get('exercise_name', 'Adversary emulation')}  ")
    w(f"**Adversary profile:** `{context['profile']}`  ")
    w(f"**Environment:** {plan.get('environment', {}).get('name', context['env'])}  ")
    w(f"**Generated:** {context['generated']}  ")
    w(f"**Detection stacks run:** {', '.join(_STACK_LABEL.get(s_, s_) for s_ in stacks_ran)}")
    w("")
    w("> Authorized emulation on synthetic telemetry. No exploit code or payloads are used; "
      "every technique is represented by the telemetry a defender would expect to observe.")
    w("")

    w("## Executive summary")
    w("")
    w(f"- **{s['steps_detected']} of {s['steps_modelled']} emulated techniques were detected "
      f"({s['coverage_pct']}% coverage).**")
    w(f"- Mean time to detect (MTTD) across detected steps: "
      f"**{_fmt_secs(s['mean_mttd_seconds'])}** (median {_fmt_secs(s['median_mttd_seconds'])}).")
    w(f"- Defence in depth: **{sb['venn']['all_three']}** techniques were caught by all three stacks; "
      f"**{s['steps_missed']}** were missed by every stack.")
    w(f"- False positives on an equivalent benign-only run: **{s['false_positive_alerts']}** "
      f"({', '.join(f'{_STACK_LABEL[k]} {v}' for k, v in s['false_positives_by_stack'].items())}).")
    w("")

    w("## Coverage by detection stack")
    w("")
    w("| Stack | Techniques detected | Coverage | Mean MTTD |")
    w("|---|---|---|---|")
    for stack in ("minisiem", "splunk", "sentinel"):
        v = sb["coverage_by_stack"].get(stack)
        if not v:
            continue
        w(f"| {_STACK_LABEL[stack]} | {v['steps_detected']}/{s['steps_modelled']} "
          f"| {v['coverage_pct']}% | {_fmt_secs(v['mean_mttd_seconds'])} |")
    w(f"| **Combined** | **{s['steps_detected']}/{s['steps_modelled']}** | "
      f"**{s['coverage_pct']}%** | **{_fmt_secs(s['mean_mttd_seconds'])}** |")
    w("")

    w("## Which stack caught what")
    w("")
    w("| Membership | # | Steps |")
    w("|---|---|---|")
    for key, ids in sb["venn"]["membership"].items():
        label = "none (missed)" if key == "(missed)" else " + ".join(_STACK_LABEL.get(k, k) for k in key.split("+"))
        w(f"| {label} | {len(ids)} | {', '.join(ids)} |")
    w("")

    w("## Kill-chain timeline")
    w("")
    w("![Kill-chain timeline](timeline.svg)")
    w("")
    w("| Step | Tactic | Technique | Status | Stacks | MTTD |")
    w("|---|---|---|---|---|---|")
    for step in sb["steps"]:
        status = sb["status_by_step"][step["step_id"]]
        stacks = ", ".join(_STACK_LABEL.get(k, k) for k in step["stacks"]) or "-"
        mttd = _fmt_secs(step["mttd_seconds"]) if step["mttd_seconds"] is not None else "-"
        w(f"| {step['step_id']} | {step['tactic']} | {step['technique_id']} {step['technique_name']} "
          f"| {_STATUS_LABEL[status]} | {stacks} | {mttd} |")
    w("")

    w("## Coverage by ATT&CK tactic")
    w("")
    w("| Tactic | Detected / total | Coverage |")
    w("|---|---|---|")
    for tactic, v in sb["coverage_by_tactic"].items():
        w(f"| {tactic} | {v['detected']}/{v['total']} | `{_bar(v['coverage_pct'])}` {v['coverage_pct']}% |")
    w("")

    missed = [st for st in sb["steps"] if sb["status_by_step"][st["step_id"]] == "missed"]
    w("## Gaps and recommended detections")
    w("")
    if not missed:
        w("No gaps - every emulated technique was detected by at least one stack.")
    else:
        w(f"{len(missed)} techniques produced no matching alert on any stack. Recommended detections:")
        w("")
        w("| Step | Technique | Recommended detection |")
        w("|---|---|---|")
        for st in missed:
            w(f"| {st['step_id']} | {st['technique_id']} {st['technique_name']} | {_recommended_rule(st)} |")
    w("")

    ml = context.get("ml_scores", [])
    if ml:
        w("## Machine-learning scoring (ml-threat-detection)")
        w("")
        w("| Detector | Ran | Units scored | ML alerts | Note |")
        w("|---|---|---|---|---|")
        for m in ml:
            w(f"| {m['detector']} | {'yes' if m['ran'] else 'no'} | {m['scored_units']} "
              f"| {m['alert_count']} | {html.escape(m['reason']) or '-'} |")
        w("")
        for m in ml:
            for a in m.get("alerts", [])[:3]:
                w(f"- `{m['detector']}` score {a['score']}: {html.escape(str(a['message']))[:160]}")
        w("")

    tri = context.get("triage", [])
    if tri:
        agree = sum(1 for v in tri if v["copilot_technique"] in v["stack_techniques"])
        w("## Alert triage (ai-soc-copilot, rules backend)")
        w("")
        w(f"{len(tri)} alerts triaged; the copilot's technique agreed with the detecting stack on "
          f"{agree}/{len(tri)}. All verdicts are queued for human review (nothing auto-closes).")
        w("")

    w("## Incident report (NIST SP 800-61)")
    w("")
    w(context.get("incident_report_md", "_incident report unavailable_"))
    w("")

    w("## Appendix - all alerts")
    w("")
    w("| Stack | Rule | Techniques | Time |")
    w("|---|---|---|---|")
    for a in context["alerts"]:
        w(f"| {_STACK_LABEL.get(a['stack'], a['stack'])} | {html.escape(a['rule_title'])} "
          f"| {', '.join(a['techniques'])} | {a.get('timestamp_iso') or '-'} |")
    w("")
    if sb["unattributed"]:
        w("### Unattributed alerts (fired on attack telemetry, technique tag outside the plan)")
        w("")
        for u in sb["unattributed"]:
            w(f"- {_STACK_LABEL.get(u['stack'], u['stack'])}: {html.escape(u['rule_title'])} "
              f"({', '.join(u['techniques'])})")
        w("")

    w("---")
    w("")
    w("JP Scirica - CompTIA Security+ | linkedin.com/in/jp-scirica")
    return "\n".join(lines)


def _fmt_secs(secs: float | None) -> str:
    if secs is None:
        return "n/a"
    secs = float(secs)
    if secs < 60:
        return f"{secs:.0f}s"
    m, s = divmod(int(secs), 60)
    return f"{m}m {s:02d}s"


# --------------------------------------------------------------------------- #
# Incident-report case file -> soctk
# --------------------------------------------------------------------------- #
def build_incident_markdown(context: dict[str, Any]) -> str:
    """Assemble a soctk case file from the scoreboard and render it with the sibling."""
    try:
        report_mod = siblings.soctk_report()
    except siblings.MissingSiblingError:
        return "_soc-analyst-toolkit not available; incident report skipped._"
    case = _case_from_scoreboard(context)
    import tempfile
    import yaml
    with tempfile.TemporaryDirectory() as tmp:
        case_path = Path(tmp) / "case.yaml"
        case_path.write_text(yaml.safe_dump(case, sort_keys=False), encoding="utf-8")
        try:
            return report_mod.generate(case_path)
        except Exception as exc:  # noqa: BLE001
            return f"_incident report generation failed: {exc}_"


def _case_from_scoreboard(context: dict[str, Any]) -> dict[str, Any]:
    sb = context["scoreboard"]
    s = sb["summary"]
    plan = context["plan"]
    detected_steps = [st for st in sb["steps"] if st["detected"]]
    timeline = []
    for st in sb["steps"][:12]:
        status = sb["status_by_step"][st["step_id"]]
        timeline.append({
            "time": st["start_ts"],
            "source": "purple-team",
            "event": f"{st['technique_id']} {st['technique_name']} ({status})",
            "entity": st["step_id"],
        })
    attack = []
    for st in sb["steps"]:
        attack.append({"tactic": _TACTIC_ID.get(st["tactic"], "TA0000"),
                       "technique": st["technique_id"], "name": st["technique_name"],
                       "evidence": "detected" if st["detected"] else "no alert (gap)"})
    return {
        "id": f"PTX-{datetime.now(timezone.utc):%Y-%m%d}",
        "title": f"Purple-team exercise: {plan.get('exercise_name', 'adversary emulation')}",
        "severity": "high",
        "status": "Closed - exercise",
        "classification": "TLP:AMBER",
        "incident_type": "Authorized adversary emulation (purple team)",
        "analyst": "JP Scirica (purple team)",
        "detection_source": "Purple Team Pipeline across mini-SIEM, Splunk and Sentinel",
        "summary": (f"Emulated the {context['profile']} profile ({s['steps_modelled']} techniques) against the "
                    f"{plan.get('environment', {}).get('name', context['env'])} and measured detection. "
                    f"{s['steps_detected']} techniques were detected ({s['coverage_pct']}% coverage), "
                    f"mean MTTD {_fmt_secs(s['mean_mttd_seconds'])}; {s['steps_missed']} were missed."),
        "impact": (f"Exercise only - no production impact. Detection gaps identified on "
                   f"{s['steps_missed']} techniques, concentrated in discovery, collection and impact."),
        "root_cause": "Detection coverage gaps, not a real intrusion. See the recommended detections.",
        "key_times": {
            "first_activity": sb["steps"][0]["start_ts"] if sb["steps"] else None,
            "detected": next((st["start_ts"] for st in detected_steps), None),
            "contained": sb["steps"][-1]["start_ts"] if sb["steps"] else None,
        },
        "affected_assets": [{"host": "WS-RAD-03", "user": "nrivera", "criticality": "high", "status": "lab replica"}],
        "timeline": timeline,
        "attack": attack,
        "response": {
            "detection_analysis": [
                f"{s['steps_detected']}/{s['steps_modelled']} techniques detected across three stacks",
                f"Mean MTTD {_fmt_secs(s['mean_mttd_seconds'])}; {s['false_positive_alerts']} false positives on benign noise",
            ],
            "containment": ["Exercise - no containment required"],
            "eradication": ["Author the recommended detections for the missed techniques"],
            "recovery": ["Re-run the pipeline after rule changes to confirm the gaps close"],
        },
        "lessons_learned": [
            f"Discovery, collection and impact tactics are the weakest ({_weakest_tactics(sb)})",
            "Stateful correlation (mini-SIEM) adds latency but catches multi-step chains signatures miss",
        ],
        "recommendations": [f"{st['step_id']} {st['technique_id']}: {_recommended_rule(st)}"
                            for st in sb["steps"] if not st["detected"]][:8],
        "evidence": [f"Scoreboard: {s['steps_detected']}/{s['steps_modelled']} detected",
                     f"Navigator layer and timeline committed with this report"],
    }


_TACTIC_ID = {
    "reconnaissance": "TA0043", "resource-development": "TA0042", "initial-access": "TA0001",
    "execution": "TA0002", "persistence": "TA0003", "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005", "credential-access": "TA0006", "discovery": "TA0007",
    "lateral-movement": "TA0008", "collection": "TA0009", "command-and-control": "TA0011",
    "exfiltration": "TA0010", "impact": "TA0040",
}


def _weakest_tactics(sb: dict[str, Any]) -> str:
    items = sorted(sb["coverage_by_tactic"].items(), key=lambda kv: kv[1]["coverage_pct"])
    return ", ".join(f"{t} {v['coverage_pct']:.0f}%" for t, v in items[:3])


# --------------------------------------------------------------------------- #
# HTML report (self-contained)
# --------------------------------------------------------------------------- #
def html_report(context: dict[str, Any], svg: str) -> str:
    sb = context["scoreboard"]
    s = sb["summary"]
    plan = context["plan"]

    def card(label: str, value: str, color: str = "#38bdf8") -> str:
        return (f'<div class="card"><div class="v" style="color:{color}">{html.escape(value)}</div>'
                f'<div class="l">{html.escape(label)}</div></div>')

    rows = []
    for step in sb["steps"]:
        status = sb["status_by_step"][step["step_id"]]
        stacks = ", ".join(_STACK_LABEL.get(k, k) for k in step["stacks"]) or "&mdash;"
        mttd = _fmt_secs(step["mttd_seconds"]) if step["mttd_seconds"] is not None else "&mdash;"
        rows.append(
            f'<tr><td>{step["step_id"]}</td><td>{html.escape(step["tactic"])}</td>'
            f'<td><code>{step["technique_id"]}</code> {html.escape(step["technique_name"])}</td>'
            f'<td><span class="badge" style="background:{_STATUS_COLOR[status]}">{_STATUS_LABEL[status]}</span></td>'
            f'<td>{stacks}</td><td>{mttd}</td></tr>')

    stack_rows = []
    for stack in ("minisiem", "splunk", "sentinel"):
        v = sb["coverage_by_stack"].get(stack)
        if v:
            stack_rows.append(
                f'<tr><td>{_STACK_LABEL[stack]}</td><td>{v["steps_detected"]}/{s["steps_modelled"]}</td>'
                f'<td>{v["coverage_pct"]}%</td><td>{_fmt_secs(v["mean_mttd_seconds"])}</td></tr>')

    tactic_rows = []
    for tactic, v in sb["coverage_by_tactic"].items():
        pct = v["coverage_pct"]
        tactic_rows.append(
            f'<tr><td>{html.escape(tactic)}</td><td>{v["detected"]}/{v["total"]}</td>'
            f'<td><div class="meter"><div style="width:{pct}%"></div></div>{pct}%</td></tr>')

    missed = [st for st in sb["steps"] if sb["status_by_step"][st["step_id"]] == "missed"]
    gap_rows = "".join(
        f'<tr><td>{st["step_id"]}</td><td><code>{st["technique_id"]}</code> {html.escape(st["technique_name"])}</td>'
        f'<td>{html.escape(_recommended_rule(st))}</td></tr>' for st in missed) or \
        '<tr><td colspan="3">No gaps - every technique detected.</td></tr>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Purple Team Exercise Report</title>
<style>
  :root {{ --bg:#0b1120; --panel:#111c33; --ink:#e2e8f0; --muted:#94a3b8; --line:#1e293b; --accent:#38bdf8; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.6 system-ui,Segoe UI,Arial,sans-serif; }}
  .wrap {{ max-width:1040px; margin:0 auto; padding:32px 16px 64px; }}
  h1 {{ font-size:28px; margin:0 0 4px; }}
  h2 {{ font-size:19px; margin:34px 0 12px; border-bottom:1px solid var(--line); padding-bottom:6px; }}
  .meta {{ color:var(--muted); font-size:13.5px; }}
  .note {{ background:var(--panel); border-left:3px solid var(--accent); padding:10px 14px; border-radius:6px; margin:16px 0; color:var(--muted); font-size:13.5px; }}
  .cards {{ display:flex; flex-wrap:wrap; gap:12px; margin:18px 0; }}
  .card {{ flex:1 1 150px; background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px; }}
  .card .v {{ font-size:26px; font-weight:700; }}
  .card .l {{ color:var(--muted); font-size:12.5px; margin-top:2px; }}
  table {{ width:100%; border-collapse:collapse; margin:10px 0; font-size:13.5px; }}
  th,td {{ text-align:left; padding:7px 9px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; }}
  code {{ background:#0b1120; padding:1px 5px; border-radius:4px; color:#7dd3fc; font-size:12.5px; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:999px; font-size:11.5px; font-weight:700; }}
  .meter {{ display:inline-block; width:120px; height:9px; background:#0b1120; border-radius:5px; overflow:hidden; margin-right:8px; vertical-align:middle; }}
  .meter>div {{ height:100%; background:linear-gradient(90deg,#f9a825,#2e7d32); }}
  .svgwrap {{ background:#0f172a; border:1px solid var(--line); border-radius:10px; padding:8px; overflow-x:auto; }}
  .foot {{ color:var(--muted); font-size:13px; margin-top:40px; border-top:1px solid var(--line); padding-top:14px; }}
</style></head>
<body><div class="wrap">
  <h1>Purple Team Exercise Report</h1>
  <div class="meta">{html.escape(plan.get('exercise_name', 'Adversary emulation'))} &middot;
    profile <code>{html.escape(context['profile'])}</code> &middot;
    {html.escape(plan.get('environment', {}).get('name', context['env']))} &middot;
    {html.escape(context['generated'])}</div>
  <div class="note">Authorized emulation on synthetic telemetry. No exploit code or payloads; every technique
    is represented by the telemetry a defender would expect to observe. Stacks run:
    {html.escape(', '.join(_STACK_LABEL.get(x, x) for x in context['stacks_ran']))}.</div>

  <div class="cards">
    {card('coverage', f"{s['coverage_pct']}%", '#38bdf8')}
    {card('techniques detected', f"{s['steps_detected']}/{s['steps_modelled']}", '#2e7d32')}
    {card('mean MTTD', _fmt_secs(s['mean_mttd_seconds']), '#facc15')}
    {card('caught by all 3', str(sb['venn']['all_three']), '#a78bfa')}
    {card('false positives', str(s['false_positive_alerts']), '#f87171')}
  </div>

  <h2>Coverage by detection stack</h2>
  <table><thead><tr><th>Stack</th><th>Detected</th><th>Coverage</th><th>Mean MTTD</th></tr></thead>
  <tbody>{''.join(stack_rows)}
    <tr><td><b>Combined</b></td><td><b>{s['steps_detected']}/{s['steps_modelled']}</b></td>
    <td><b>{s['coverage_pct']}%</b></td><td><b>{_fmt_secs(s['mean_mttd_seconds'])}</b></td></tr></tbody></table>

  <h2>Kill-chain timeline</h2>
  <div class="svgwrap">{svg}</div>

  <h2>Per-step detection</h2>
  <table><thead><tr><th>Step</th><th>Tactic</th><th>Technique</th><th>Status</th><th>Stacks</th><th>MTTD</th></tr></thead>
  <tbody>{''.join(rows)}</tbody></table>

  <h2>Coverage by ATT&amp;CK tactic</h2>
  <table><thead><tr><th>Tactic</th><th>Detected</th><th>Coverage</th></tr></thead>
  <tbody>{''.join(tactic_rows)}</tbody></table>

  <h2>Gaps &amp; recommended detections</h2>
  <table><thead><tr><th>Step</th><th>Technique</th><th>Recommended detection</th></tr></thead>
  <tbody>{gap_rows}</tbody></table>

  <div class="foot">JP Scirica &mdash; CompTIA Security+ | linkedin.com/in/jp-scirica<br>
  Generated by the Purple Team Pipeline across mini-SIEM, Splunk and Microsoft Sentinel detection content.</div>
</div></body></html>
"""


def write_reports(context: dict[str, Any], out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    svg = timeline_svg(context["scoreboard"])
    (out / "timeline.svg").write_text(svg, encoding="utf-8")
    md = markdown_report(context)
    (out / "report.md").write_text(md, encoding="utf-8")
    html_text = html_report(context, svg)
    (out / "report.html").write_text(html_text, encoding="utf-8")
    return {"md": out / "report.md", "html": out / "report.html", "svg": out / "timeline.svg"}


__all__ = ["timeline_svg", "markdown_report", "html_report", "build_incident_markdown", "write_reports"]
