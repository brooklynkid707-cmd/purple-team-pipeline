"""The report renderers produce Markdown, HTML and SVG from a scoreboard - no siblings."""

from __future__ import annotations

from ptp import report as R
from ptp import score as S
from ptp.detect.normalize import NormalizedAlert
from ptp.scenario import PlanStep
from ptp.telemetry.engine import StepTiming


def _fixture_scoreboard():
    steps = [PlanStep("S01", "T1059.001", "PowerShell", "execution", 3, expected_telemetry={}),
             PlanStep("S02", "T1486", "Data Encrypted for Impact", "impact", 13, expected_telemetry={})]
    timings = [StepTiming("S01", "T1059.001", 100.0, 2, True),
               StepTiming("S02", "T1486", 200.0, 1, True)]
    alerts = [NormalizedAlert("minisiem", "r1", "Encoded PowerShell", ["T1059.001"], 100.0),
              NormalizedAlert("splunk", "TDL-007", "PowerShell Encoded", ["T1059.001"], 130.0)]
    sb = S.score(steps, timings, alerts)
    plan = {"exercise_name": "Test exercise", "environment": {"name": "Lab"}, "phase_count": 2}
    context = {"profile": "ransomware-affiliate", "env": "hospital", "plan": plan,
               "scoreboard": sb, "stacks_ran": ["minisiem", "splunk", "sentinel"],
               "generated": "2026-10-23 00:00 UTC",
               "alerts": [a.to_dict() for a in alerts], "triage": [], "ml_scores": [],
               "incident_report_md": "## Incident\nsynthetic"}
    return context, sb


def test_timeline_svg_is_valid_svg():
    _, sb = _fixture_scoreboard()
    svg = R.timeline_svg(sb)
    assert svg.startswith("<svg")
    assert svg.rstrip().endswith("</svg>")
    assert "T1059.001" in svg and "T1486" in svg


def test_markdown_report_has_key_sections():
    context, _ = _fixture_scoreboard()
    md = R.markdown_report(context)
    for heading in ("# Purple Team Exercise Report", "## Executive summary",
                    "## Coverage by detection stack", "## Kill-chain timeline",
                    "## Gaps and recommended detections", "## Appendix"):
        assert heading in md
    assert "50.0% coverage" in md or "50% coverage" in md


def test_html_report_is_self_contained():
    context, sb = _fixture_scoreboard()
    svg = R.timeline_svg(sb)
    html = R.html_report(context, svg)
    assert html.startswith("<!doctype html>")
    assert "<svg" in html                    # SVG embedded, not referenced
    assert "src=" not in html                # no external assets
    assert "Purple Team Exercise Report" in html


def test_write_reports(tmp_path):
    context, _ = _fixture_scoreboard()
    paths = R.write_reports(context, tmp_path)
    assert paths["md"].is_file() and paths["html"].is_file() and paths["svg"].is_file()
    assert paths["svg"].read_text().startswith("<svg")


def test_recommended_rule_is_tactic_aware():
    rec = R._recommended_rule({"tactic": "impact", "technique_id": "T1486", "technique_name": "x"})
    assert "vssadmin" in rec or "service-stop" in rec
