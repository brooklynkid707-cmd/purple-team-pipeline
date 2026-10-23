"""Shared fixtures: a small plan + a telemetry run reused across tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ptp import scenario, siblings  # noqa: E402

PROFILE = "ransomware-affiliate"
ENV = "hospital"


def _siblings_available() -> bool:
    try:
        siblings.require()
        return True
    except siblings.MissingSiblingError:
        return False


requires_siblings = pytest.mark.skipif(not _siblings_available(),
                                       reason="sibling repositories not resolvable (set PORTFOLIO_ROOT)")


@pytest.fixture(scope="session")
def plan():
    return scenario.build_plan(PROFILE, ENV)


@pytest.fixture(scope="session")
def steps(plan):
    return scenario.flatten_steps(plan)


@pytest.fixture(scope="session")
def telemetry(steps, tmp_path_factory):
    from ptp.telemetry import TelemetryEngine
    out = tmp_path_factory.mktemp("telemetry_run")
    result = TelemetryEngine(seed=1337).run(steps, out)
    return result


@pytest.fixture(scope="session")
def detection(telemetry):
    from ptp.detect import run_all
    return run_all(telemetry.out_dir / "telemetry")
