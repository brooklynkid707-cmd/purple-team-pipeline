#!/usr/bin/env python3
"""Render an animated SVG of a finished run's six stages - no external tools.

    python scripts/record_demo.py --run examples/ransomware-affiliate-hospital \
        --out examples/ransomware-affiliate-hospital/demo.svg

The SVG uses SMIL ``<animate>`` so it plays in any browser or GitHub preview
with nothing installed. Each frame highlights one pipeline stage and shows the
headline numbers pulled from ``scoreboard.json``.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

STAGES = [
    ("1  Plan", "aep: adversary profile -> phased ATT&CK plan"),
    ("2  Telemetry", "synthetic events in 3 SIEM formats + benign noise + ground truth"),
    ("3  Detect", "mini-SIEM Sigma/correlation | Splunk SPL | Sentinel KQL"),
    ("4  Triage", "ai-soc-copilot verdicts + ml-threat-detection scoring"),
    ("5  Score", "coverage %, MTTD, Venn, ATT&CK Navigator layer"),
    ("6  Report", "Markdown + HTML + SVG timeline + NIST 800-61 incident report"),
]
FRAME = 1.6  # seconds per stage


def build_svg(sb: dict, profile: str, env: str) -> str:
    s = sb["summary"]
    w, h = 900, 520
    n = len(STAGES)
    total = n * FRAME
    rows = []
    for i, (title, desc) in enumerate(STAGES):
        y = 120 + i * 58
        begin = i * FRAME
        # each stage box fades/greens while it is "active"
        rows.append(f"""
  <g transform="translate(60 {y})">
    <rect width="780" height="46" rx="8" fill="#111c33" stroke="#1e293b"/>
    <rect width="780" height="46" rx="8" fill="#14532d" opacity="0">
      <animate attributeName="opacity" values="0;1;1;0.25" keyTimes="0;0.12;0.8;1"
               dur="{total}s" begin="{begin}s" repeatCount="indefinite"/>
    </rect>
    <circle cx="26" cy="23" r="9" fill="#334155">
      <animate attributeName="fill" values="#334155;#22c55e;#22c55e" keyTimes="0;0.12;1"
               dur="{total}s" begin="{begin}s" repeatCount="indefinite"/>
    </circle>
    <text x="48" y="20" fill="#e2e8f0" font-size="16" font-weight="700">{html.escape(title)}</text>
    <text x="48" y="38" fill="#94a3b8" font-size="12.5">{html.escape(desc)}</text>
  </g>""")

    cards = [
        (f"{s['coverage_pct']}%", "coverage", "#38bdf8"),
        (f"{s['steps_detected']}/{s['steps_modelled']}", "techniques", "#22c55e"),
        (_fmt(s["mean_mttd_seconds"]), "mean MTTD", "#facc15"),
        (str(s["false_positive_alerts"]), "false pos.", "#f87171"),
    ]
    card_svg = []
    for i, (val, lab, color) in enumerate(cards):
        x = 60 + i * 198
        card_svg.append(f"""
  <g transform="translate({x} 430)">
    <rect width="182" height="64" rx="10" fill="#0b1120" stroke="#1e293b"/>
    <text x="16" y="34" fill="{color}" font-size="24" font-weight="800">{html.escape(val)}</text>
    <text x="16" y="52" fill="#94a3b8" font-size="12">{html.escape(lab)}</text>
  </g>""")

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}"
     font-family="system-ui,Segoe UI,Arial,sans-serif">
  <rect width="{w}" height="{h}" fill="#0b1120"/>
  <text x="60" y="52" fill="#e2e8f0" font-size="24" font-weight="800">Purple Team Pipeline</text>
  <text x="60" y="76" fill="#94a3b8" font-size="14">one command: {html.escape(profile)} vs {html.escape(env)}  -  plan to incident report across 7 repos</text>
  {''.join(rows)}
  {''.join(card_svg)}
</svg>"""


def _fmt(secs) -> str:
    if secs is None:
        return "n/a"
    if secs < 60:
        return f"{secs:.0f}s"
    m, s = divmod(int(secs), 60)
    return f"{m}m{s:02d}s"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", default="examples/ransomware-affiliate-hospital")
    p.add_argument("--out", default=None)
    args = p.parse_args(argv)
    run = Path(args.run)
    sb = json.loads((run / "scoreboard.json").read_text(encoding="utf-8"))
    profile, env = "ransomware-affiliate", "hospital"
    plan_path = run / "plan.json"
    if plan_path.is_file():
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        profile = plan.get("profile", profile)
        env = plan.get("environment", {}).get("name", env)
    out = Path(args.out) if args.out else run / "demo.svg"
    out.write_text(build_svg(sb, profile, env), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
