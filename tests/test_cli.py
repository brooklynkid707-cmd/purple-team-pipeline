"""CLI: doctor, profiles, and the slow end-to-end run (marked ``slow``)."""

from __future__ import annotations

import json

import pytest

from ptp import cli
from tests.conftest import requires_siblings


@requires_siblings
def test_doctor_ok(capsys):
    rc = cli.main(["doctor"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "All siblings resolved" in out
    assert out.count("[OK  ]") == 7


@requires_siblings
def test_profiles_lists_ransomware_affiliate(capsys):
    rc = cli.main(["profiles"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ransomware-affiliate" in out


@requires_siblings
@pytest.mark.slow
def test_run_end_to_end(tmp_path):
    out = tmp_path / "run"
    rc = cli.main(["run", "--profile", "ransomware-affiliate", "--env", "hospital",
                   "--out", str(out), "--no-triage", "--no-ml"])
    assert rc == 0
    for name in ("plan.json", "scoreboard.json", "navigator-layer.json",
                 "report.md", "report.html", "timeline.svg"):
        assert (out / name).is_file(), f"missing {name}"
    sb = json.loads((out / "scoreboard.json").read_text())
    # Real coverage on the demo scenario sits in a sane band.
    assert sb["summary"]["steps_modelled"] == 30
    assert sb["summary"]["steps_detected"] >= 8
    assert 0 < sb["summary"]["coverage_pct"] <= 100
    # Each stack contributed.
    for stack in ("minisiem", "splunk", "sentinel"):
        assert sb["coverage_by_stack"][stack]["steps_detected"] >= 1


@requires_siblings
@pytest.mark.slow
def test_replay_and_compare(tmp_path, capsys):
    out = tmp_path / "run"
    cli.main(["run", "--profile", "ransomware-affiliate", "--env", "hospital",
              "--out", str(out), "--no-triage", "--no-ml"])
    capsys.readouterr()
    assert cli.main(["replay", str(out)]) == 0
    assert "coverage" in capsys.readouterr().out
    assert cli.main(["compare", str(out), str(out)]) == 0
    assert "Comparing" in capsys.readouterr().out
