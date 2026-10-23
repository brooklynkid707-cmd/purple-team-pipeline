"""Scoreboard math (MTTD, coverage, matching) on hand-built fixtures - no siblings."""

from __future__ import annotations

from ptp import score as S
from ptp.detect.normalize import NormalizedAlert
from ptp.scenario import PlanStep
from ptp.telemetry.engine import StepTiming


def _step(sid, tid, tactic="execution", rank=3):
    return PlanStep(step_id=sid, technique_id=tid, technique_name=tid, tactic=tactic,
                    phase_rank=rank, expected_telemetry={})


def _timing(sid, tid, start, modelled=True, n=1):
    return StepTiming(step_id=sid, technique_id=tid, start_ts=start, event_count=n, modelled=modelled)


def _alert(stack, tid, ts, rule="r"):
    return NormalizedAlert(stack=stack, rule=rule, rule_title=rule, techniques=[tid], timestamp=ts)


def test_tech_match_rules():
    assert S._tech_match("T1059.001", "T1059.001")
    assert S._tech_match("T1021", "T1021.001")          # bare parent -> sub
    assert S._tech_match("T1078.002", "T1078")          # sub -> bare parent
    assert not S._tech_match("T1021.001", "T1021.002")  # siblings never cross-match
    assert not S._tech_match("T1059.001", "T1003.001")


def test_mttd_is_first_alert_minus_step_start():
    steps = [_step("S01", "T1059.001")]
    timings = [_timing("S01", "T1059.001", 1000.0)]
    alerts = [_alert("splunk", "T1059.001", 1090.0), _alert("minisiem", "T1059.001", 1150.0)]
    sb = S.score(steps, timings, alerts)
    row = sb["steps"][0]
    assert row["detected"] is True
    assert row["mttd_seconds"] == 90.0            # earliest alert wins
    assert sb["summary"]["coverage_pct"] == 100.0


def test_mttd_clamped_to_zero_for_binned_floor():
    steps = [_step("S01", "T1021.001", tactic="lateral-movement")]
    timings = [_timing("S01", "T1021.001", 9000.0)]
    # window_start floor fires 1800s before the step start.
    alerts = [_alert("splunk", "T1021.001", 7200.0)]
    sb = S.score(steps, timings, alerts)
    assert sb["steps"][0]["detected"] is True
    assert sb["steps"][0]["mttd_seconds"] == 0.0


def test_out_of_window_alert_does_not_credit_step():
    steps = [_step("S01", "T1021.001", tactic="lateral-movement")]
    timings = [_timing("S01", "T1021.001", 1000.0)]
    # Technique matches, but fires far beyond the window (tag drift onto later telemetry).
    alerts = [_alert("splunk", "T1021.001", 1000.0 + S.MTTD_WINDOW_SECONDS + 600)]
    sb = S.score(steps, timings, alerts)
    assert sb["steps"][0]["detected"] is False


def test_coverage_counts_and_tactics():
    steps = [_step("S01", "T1059.001", "execution"), _step("S02", "T1486", "impact"),
             _step("S03", "T1003.001", "credential-access")]
    timings = [_timing("S01", "T1059.001", 100.0), _timing("S02", "T1486", 200.0),
               _timing("S03", "T1003.001", 300.0)]
    alerts = [_alert("minisiem", "T1059.001", 100.0), _alert("splunk", "T1003.001", 300.0)]
    sb = S.score(steps, timings, alerts)
    assert sb["summary"]["steps_detected"] == 2
    assert sb["summary"]["steps_missed"] == 1
    assert round(sb["summary"]["coverage_pct"], 1) == 66.7
    assert sb["coverage_by_tactic"]["impact"]["coverage_pct"] == 0.0
    assert sb["coverage_by_tactic"]["execution"]["coverage_pct"] == 100.0


def test_venn_membership():
    steps = [_step("S01", "T1059.001"), _step("S02", "T1003.001", "credential-access")]
    timings = [_timing("S01", "T1059.001", 100.0), _timing("S02", "T1003.001", 200.0)]
    alerts = [_alert("minisiem", "T1059.001", 100.0), _alert("splunk", "T1059.001", 100.0),
              _alert("sentinel", "T1003.001", 200.0)]
    sb = S.score(steps, timings, alerts)
    assert sb["venn"]["only"]["sentinel"] == 1
    assert "minisiem+splunk" in sb["venn"]["membership"]


def test_false_positives_from_benign_run():
    steps = [_step("S01", "T1059.001")]
    timings = [_timing("S01", "T1059.001", 100.0)]
    attack_alerts = [_alert("minisiem", "T1059.001", 100.0)]
    benign_alerts = [_alert("minisiem", "T1136.001", 50.0, rule="new-user"),
                     _alert("sentinel", "T1136.001", 60.0, rule="new-user")]
    sb = S.score(steps, timings, attack_alerts, benign_alerts)
    assert sb["summary"]["false_positive_alerts"] == 2
    assert sb["summary"]["false_positives_by_stack"]["minisiem"] == 1
    assert sb["summary"]["false_positives_by_stack"]["sentinel"] == 1


def test_status_detected_partial_missed():
    steps = [_step("S01", "T1059.001"), _step("S02", "T1003.001", "credential-access"),
             _step("S03", "T1486", "impact")]
    timings = [_timing("S01", "T1059.001", 100.0), _timing("S02", "T1003.001", 200.0),
               _timing("S03", "T1486", 300.0)]
    alerts = [_alert("minisiem", "T1059.001", 100.0), _alert("splunk", "T1059.001", 100.0),
              _alert("sentinel", "T1003.001", 200.0)]
    sb = S.score(steps, timings, alerts)
    assert sb["status_by_step"]["S01"] == "detected"   # 2+ stacks
    assert sb["status_by_step"]["S02"] == "partial"     # 1 stack
    assert sb["status_by_step"]["S03"] == "missed"


def test_navigator_layer_shape():
    steps = [_step("S01", "T1059.001")]
    timings = [_timing("S01", "T1059.001", 100.0)]
    sb = S.score(steps, timings, [_alert("minisiem", "T1059.001", 100.0)])
    layer = S.navigator_layer(sb, {"exercise_name": "x"})
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"][0]["techniqueID"] == "T1059.001"
    assert layer["techniques"][0]["score"] in (0, 50, 100)
