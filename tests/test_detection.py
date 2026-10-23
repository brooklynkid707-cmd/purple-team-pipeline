"""Each detection stack produces at least one alert on the demo scenario."""

from __future__ import annotations

from ptp.detect.normalize import NormalizedAlert, techniques_from_tags
from tests.conftest import requires_siblings

pytestmark = requires_siblings


def test_every_stack_runs(detection):
    for stack in ("minisiem", "splunk", "sentinel"):
        res = detection.results[stack]
        assert res.ok, f"{stack} failed: {res.reason}"
        assert res.rules_run > 0


def test_every_stack_alerts(detection):
    for stack in ("minisiem", "splunk", "sentinel"):
        assert len(detection.by_stack(stack)) >= 1, f"{stack} produced no alerts"


def test_alerts_are_normalised(detection):
    for alert in detection.alerts:
        assert isinstance(alert, NormalizedAlert)
        assert alert.stack in ("minisiem", "splunk", "sentinel")
        assert alert.rule and alert.rule_title
        assert isinstance(alert.techniques, list)


def test_known_techniques_detected(detection):
    """The scenario's loud steps must be caught somewhere."""
    all_techs = {t for a in detection.alerts for t in a.techniques}
    # PowerShell execution, LSASS dump, log clearing and spraying are high-signal.
    for tid in ("T1059.001", "T1003.001", "T1070.001", "T1110.003"):
        assert any(t == tid or t.split(".")[0] == tid.split(".")[0] for t in all_techs), tid


def test_techniques_from_tags():
    assert techniques_from_tags(["attack.t1059.001", "attack.execution"]) == ["T1059.001"]
    assert techniques_from_tags(["attack.t1110", "attack.t1078"]) == ["T1110", "T1078"]
