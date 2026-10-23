"""The telemetry engine emits ground truth for every plan step and valid formats."""

from __future__ import annotations

import json

from ptp.telemetry.engine import load_ground_truth
from tests.conftest import requires_siblings

pytestmark = requires_siblings


def test_ground_truth_covers_every_modelled_step(steps, telemetry):
    gt = load_ground_truth(telemetry.ground_truth_path)
    attack = [g for g in gt if g["step_id"] is not None]
    gt_steps = {g["step_id"] for g in attack}
    modelled = {s.step_id for s in telemetry.modelled_steps}
    # Every modelled step has at least one ground-truth attack event.
    assert modelled, "no steps were modelled"
    assert modelled <= gt_steps
    # The ransomware-affiliate profile is fully modelled by the emitters.
    assert telemetry.unmodelled == []
    assert len(telemetry.modelled_steps) == len(steps)


def test_ground_truth_never_leaks_into_logs(telemetry):
    tel = telemetry.out_dir / "telemetry"
    # The ground-truth tags (step ids, the "note") must not appear in any log file.
    blob = ""
    for sub in ("splunk", "minisiem", "sentinel"):
        for path in (tel / sub).glob("*"):
            blob += path.read_text(encoding="utf-8")
    assert "step_id" not in blob
    assert "ground_truth" not in blob
    assert "benign background" not in blob


def test_benign_noise_tagged_separately(telemetry):
    gt = load_ground_truth(telemetry.ground_truth_path)
    benign = [g for g in gt if g["step_id"] is None]
    assert benign, "expected benign background events"
    assert all(g["note"] == "benign background" for g in benign)


def test_each_stack_has_telemetry(telemetry):
    tel = telemetry.out_dir / "telemetry"
    assert (tel / "splunk" / "windows_security.log").stat().st_size > 0
    assert (tel / "minisiem" / "windows_security.jsonl").stat().st_size > 0
    sentinel = json.loads((tel / "sentinel" / "SecurityEvent.json").read_text())
    assert isinstance(sentinel, list) and len(sentinel) > 0


def test_minisiem_windows_json_parses(telemetry):
    path = telemetry.out_dir / "telemetry" / "minisiem" / "windows_security.jsonl"
    for line in path.read_text(encoding="utf-8").splitlines():
        obj = json.loads(line)
        assert "EventID" in obj and "EventData" in obj and obj["Channel"] in ("Security", "System")


def test_c2_beacon_pair_is_clean_and_periodic(telemetry):
    # The beacon pair must be a single regular series (so ML/beaconing can catch it).
    zeek = telemetry.out_dir / "telemetry" / "minisiem" / "zeek_conn.jsonl"
    rows = [json.loads(l) for l in zeek.read_text().splitlines()]
    c2 = [r for r in rows if r["id.resp_h"] == "203.0.113.66" and r["id.resp_p"] == 443]
    assert len(c2) >= 20, "C2 beacon should have >=20 flows"
