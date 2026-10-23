"""Stage 1 - build the exercise scenario from an adversary profile and an environment.

Everything here delegates to ``ai-adversary-emulation-planner`` (``aep``): the
actor profiles, the ATT&CK knowledge base and the phased planner are the
sibling's. This module only resolves CLI arguments to the planner's inputs
and flattens the plan into an ordered list of :class:`PlanStep` objects that
the telemetry engine can execute.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import siblings


@dataclass
class PlanStep:
    """One technique from the plan, in kill-chain order."""

    step_id: str                     # S01, S02 ...
    technique_id: str
    technique_name: str
    tactic: str
    phase_rank: int
    expected_telemetry: dict[str, Any]
    objective: str = ""
    detection_checklist: list[dict[str, Any]] = field(default_factory=list)
    risk_rating: str = "medium"
    blind_spots: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "phase_rank": self.phase_rank,
            "objective": self.objective,
            "expected_telemetry": self.expected_telemetry,
            "detection_checklist": self.detection_checklist,
            "risk_rating": self.risk_rating,
            "blind_spots": self.blind_spots,
        }


def list_profiles() -> list[dict[str, str]]:
    """Adversary archetypes shipped by the planner."""
    kb_mod, _, _ = siblings.aep_modules()
    kb = kb_mod.load_kb()
    return [{"id": p.id, "name": p.name, "techniques": str(len(p.techniques))}
            for p in kb.profiles.values()]


def resolve_env(name_or_path: str) -> Path:
    """``hospital`` -> ``<aep>/env/hospital.yaml``; an existing path is used as-is."""
    candidate = Path(name_or_path)
    if candidate.is_file():
        return candidate
    aep_root = siblings.require("aep")["aep"]
    for suffix in ("", ".yaml", ".yml"):
        path = aep_root / "env" / f"{name_or_path}{suffix}"
        if path.is_file():
            return path
    available = sorted(p.stem for p in (aep_root / "env").glob("*.yaml"))
    raise FileNotFoundError(f"unknown environment {name_or_path!r}; available: {available}")


def build_plan(profile: str, env: str, technique_ids: list[str] | None = None) -> dict[str, Any]:
    """Call the sibling planner and return its ``aep-plan/1.0`` document."""
    kb_mod, env_mod, planner = siblings.aep_modules()
    kb = kb_mod.load_kb()
    environment = env_mod.Environment.from_file(resolve_env(env))
    return planner.build_plan(kb, environment, profile_id=profile, technique_ids=technique_ids)


def flatten_steps(plan: dict[str, Any]) -> list[PlanStep]:
    """Plan phases -> ordered steps ``S01..Snn`` (kill-chain order is the plan's)."""
    steps: list[PlanStep] = []
    n = 0
    for phase in plan["phases"]:
        for tech in phase["techniques"]:
            n += 1
            telemetry = tech.get("expected_telemetry", {})
            steps.append(PlanStep(
                step_id=f"S{n:02d}",
                technique_id=tech["technique_id"],
                technique_name=tech["technique_name"],
                tactic=tech["tactic"],
                phase_rank=int(phase.get("phase_rank", 0)),
                objective=tech.get("objective", ""),
                expected_telemetry=telemetry,
                detection_checklist=list(tech.get("detection_checklist", [])),
                risk_rating=tech.get("risk_rating", "medium"),
                blind_spots=list(telemetry.get("blind_spots", [])),
            ))
    return steps


__all__ = ["PlanStep", "list_profiles", "resolve_env", "build_plan", "flatten_steps"]
