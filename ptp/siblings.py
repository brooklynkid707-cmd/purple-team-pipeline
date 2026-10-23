"""Locate the sibling repositories and make their packages importable.

The pipeline integrates the owner's other portfolio repos *as they are*: no
code is copied. Each sibling is found in this order:

1. ``$PORTFOLIO_ROOT/<repo-name>`` (``PORTFOLIO_ROOT`` defaults to the parent
   directory of this repo, which is how the portfolio is laid out on disk);
2. ``vendor/<repo-name>`` inside this repo (populated by
   ``scripts/setup_siblings.sh`` / ``make setup`` from GitHub).

:func:`require` raises :class:`MissingSiblingError` with a message that lists
every missing repo and how to fetch it, so a half-configured checkout fails
loudly instead of half-working.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent
GITHUB_OWNER = "brooklynkid707-cmd"


@dataclass(frozen=True)
class Sibling:
    """One sibling repository and how we recognise a valid checkout."""

    key: str
    repo: str
    marker: str        # a file that must exist in a valid checkout
    role: str          # what the pipeline uses it for

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{GITHUB_OWNER}/{self.repo}.git"


SIBLINGS: dict[str, Sibling] = {
    s.key: s for s in [
        Sibling("aep", "ai-adversary-emulation-planner", "aep/planner.py",
                "adversary profiles and the phased ATT&CK plan"),
        Sibling("splunk", "splunk-threat-detection-lab", "harness/run_detections.py",
                "event builders and the SPL evaluator with TA-threat-detection"),
        Sibling("minisiem", "siem-from-scratch", "minisiem/pipeline.py",
                "Sigma + correlation detection stack"),
        Sibling("sentinel", "microsoft-sentinel-detection-engineering", "tools/simulate.py",
                "KQL-subset evaluator over SecurityEvent"),
        Sibling("copilot", "ai-soc-copilot", "copilot/workflow.py",
                "alert triage (rules backend)"),
        Sibling("mltd", "ml-threat-detection", "mltd/pipeline.py",
                "beacon / auth / process ML scoring"),
        Sibling("soctk", "soc-analyst-toolkit", "soctk/report.py",
                "NIST 800-61 incident report rendering"),
    ]
}


class MissingSiblingError(RuntimeError):
    """Raised when one or more sibling repositories cannot be found."""


def portfolio_root() -> Path:
    """Directory that holds the sibling checkouts (``PORTFOLIO_ROOT`` or ``..``)."""
    env = os.environ.get("PORTFOLIO_ROOT")
    return Path(env).expanduser().resolve() if env else REPO_ROOT.parent


def vendor_root() -> Path:
    return REPO_ROOT / "vendor"


def locate(key: str) -> Path | None:
    """Return the checkout path for a sibling, or ``None`` if it is missing."""
    sib = SIBLINGS[key]
    for base in (portfolio_root(), vendor_root()):
        candidate = base / sib.repo
        if (candidate / sib.marker).is_file():
            return candidate
    return None


def status() -> dict[str, Path | None]:
    """Map every sibling key to its path (or ``None``)."""
    return {key: locate(key) for key in SIBLINGS}


def missing_message(missing: list[str]) -> str:
    lines = ["missing sibling repositories:"]
    for key in missing:
        sib = SIBLINGS[key]
        lines.append(f"  - {sib.repo:<42} ({sib.role})")
    lines.append("")
    lines.append(f"searched: {portfolio_root()}  and  {vendor_root()}")
    lines.append("fix: set PORTFOLIO_ROOT to the directory holding the checkouts, or run")
    lines.append("     scripts/setup_siblings.sh   (clones them into vendor/ from GitHub)")
    return "\n".join(lines)


def require(*keys: str) -> dict[str, Path]:
    """Resolve the requested siblings (all of them by default) or raise."""
    wanted = list(keys) or list(SIBLINGS)
    found: dict[str, Path] = {}
    missing: list[str] = []
    for key in wanted:
        path = locate(key)
        if path is None:
            missing.append(key)
        else:
            found[key] = path
    if missing:
        raise MissingSiblingError(missing_message(missing))
    return found


def _add_path(path: Path) -> None:
    text = str(path)
    if text not in sys.path:
        # Insert after the current directory so this repo's own packages win.
        sys.path.insert(1, text)


def import_package(key: str, module: str) -> ModuleType:
    """Import ``module`` from a sibling after putting its root on ``sys.path``."""
    root = require(key)[key]
    _add_path(root)
    return importlib.import_module(module)


def import_file(key: str, relative: str, alias: str) -> ModuleType:
    """Import a stand-alone script (not a package) from a sibling under a unique alias.

    Used for ``scripts/generate_logs.py`` (Splunk lab) and ``tools/simulate.py``
    (Sentinel), whose directory names are too generic to put on ``sys.path``.
    """
    if alias in sys.modules:
        return sys.modules[alias]
    root = require(key)[key]
    path = root / relative
    spec = importlib.util.spec_from_file_location(alias, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Typed accessors used by the pipeline stages
# --------------------------------------------------------------------------- #

def aep_modules() -> tuple[ModuleType, ModuleType, ModuleType]:
    """``(aep.kb, aep.environment, aep.planner)``."""
    kb = import_package("aep", "aep.kb")
    env = import_package("aep", "aep.environment")
    planner = import_package("aep", "aep.planner")
    return kb, env, planner


def splunk_generator() -> ModuleType:
    """The Splunk lab's ``scripts/generate_logs.py`` as a module (event builders)."""
    return import_file("splunk", "scripts/generate_logs.py", "ptp_vendor_splunk_generate_logs")


def splunk_harness() -> tuple[ModuleType, ModuleType, Path]:
    """``(harness.run_detections, harness.catalog, app_dir)``."""
    run = import_package("splunk", "harness.run_detections")
    catalog = import_package("splunk", "harness.catalog")
    app_dir = require("splunk")["splunk"] / "TA-threat-detection"
    return run, catalog, app_dir


def minisiem_modules() -> tuple[ModuleType, ModuleType, Path]:
    """``(minisiem.pipeline, minisiem.storage, rules_dir)``."""
    pipeline = import_package("minisiem", "minisiem.pipeline")
    storage = import_package("minisiem", "minisiem.storage")
    return pipeline, storage, require("minisiem")["minisiem"] / "rules"


def sentinel_simulator() -> tuple[ModuleType, Path]:
    """``(tools/simulate.py module, analytics-rules dir)``."""
    sim = import_file("sentinel", "tools/simulate.py", "ptp_vendor_sentinel_simulate")
    return sim, require("sentinel")["sentinel"] / "analytics-rules"


def copilot_modules() -> tuple[ModuleType, ModuleType]:
    """``(copilot.workflow, copilot.schema)``."""
    workflow = import_package("copilot", "copilot.workflow")
    schema = import_package("copilot", "copilot.schema")
    return workflow, schema


def mltd_pipeline() -> tuple[ModuleType, Path]:
    """``(mltd.pipeline, data_dir)`` - the training CSVs live in the sibling."""
    pipeline = import_package("mltd", "mltd.pipeline")
    return pipeline, require("mltd")["mltd"] / "data"


def soctk_report() -> ModuleType:
    """``soctk.report`` (YAML case -> Markdown incident report)."""
    return import_package("soctk", "soctk.report")


__all__ = [
    "SIBLINGS", "Sibling", "MissingSiblingError", "REPO_ROOT", "portfolio_root", "vendor_root",
    "locate", "status", "require", "import_package", "import_file", "aep_modules",
    "splunk_generator", "splunk_harness", "minisiem_modules", "sentinel_simulator",
    "copilot_modules", "mltd_pipeline", "soctk_report",
]
