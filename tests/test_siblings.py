"""The sibling resolver finds every repo and imports their packages."""

from __future__ import annotations

import pytest

from ptp import siblings
from tests.conftest import requires_siblings


def test_all_siblings_declared():
    # Seven repos, matching the architecture.
    assert len(siblings.SIBLINGS) == 7
    assert set(siblings.SIBLINGS) == {"aep", "splunk", "minisiem", "sentinel", "copilot", "mltd", "soctk"}


@requires_siblings
def test_status_resolves_all():
    for key, path in siblings.status().items():
        assert path is not None, f"{key} did not resolve"
        assert path.is_dir()


@requires_siblings
def test_require_returns_paths():
    found = siblings.require()
    assert set(found) == set(siblings.SIBLINGS)


def test_missing_message_lists_repo_and_fix():
    msg = siblings.missing_message(["aep", "mltd"])
    assert "ai-adversary-emulation-planner" in msg
    assert "ml-threat-detection" in msg
    assert "setup_siblings.sh" in msg


def test_missing_raises_with_message(monkeypatch):
    monkeypatch.setattr(siblings, "locate", lambda key: None)
    with pytest.raises(siblings.MissingSiblingError) as exc:
        siblings.require("aep")
    assert "ai-adversary-emulation-planner" in str(exc.value)


@requires_siblings
def test_import_sibling_packages():
    kb_mod, env_mod, planner = siblings.aep_modules()
    assert hasattr(planner, "build_plan")
    assert hasattr(kb_mod, "load_kb")
    workflow, schema = siblings.copilot_modules()
    assert hasattr(workflow, "Pipeline")
    assert hasattr(schema, "Alert")


@requires_siblings
def test_clone_urls_point_at_owner():
    for sib in siblings.SIBLINGS.values():
        assert sib.clone_url.startswith("https://github.com/brooklynkid707-cmd/")
