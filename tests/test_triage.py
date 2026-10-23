"""Triage (copilot) and ML scoring (mltd) integrate and degrade gracefully."""

from __future__ import annotations

from ptp.triage import score_with_mltd, triage_alerts
from tests.conftest import requires_siblings

pytestmark = requires_siblings


def test_copilot_triages_alerts(detection):
    verdicts = triage_alerts(detection.alerts[:10], "/tmp/ptp-test-triage")
    assert verdicts, "copilot produced no verdicts"
    for v in verdicts:
        assert v.copilot_severity in ("critical", "high", "medium", "low", "informational")
        assert v.needs_human is True          # nothing auto-closes
        assert v.copilot_technique.startswith("T")


def test_mltd_beacon_catches_c2(telemetry):
    scores = score_with_mltd(telemetry.out_dir / "telemetry", telemetry.out_dir,
                             detectors=("beacon",))
    beacon = next(s for s in scores if s.detector == "beacon")
    assert beacon.ran
    # The clean 60-second C2 beacon must score an alert.
    assert beacon.alerts, "beacon detector found no C2"
    assert any(a["dst_ip"] == "203.0.113.66" for a in beacon.alerts)
