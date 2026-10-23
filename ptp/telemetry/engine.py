"""Orchestrate the telemetry engine: plan steps -> events -> stack-specific files.

Produces, under ``<out>/telemetry/``:

* ``splunk/``     the five sourcetype files the Splunk harness ingests
* ``minisiem/``   auth.log + the Windows/Sysmon/firewall/Zeek files minisiem reads
* ``sentinel/``   ``SecurityEvent.json`` (and an empty ``SigninLogs.json``) for simulate.py
* ``ground_truth.jsonl``  one row per emitted attack event: step id, technique,
  timestamp, stack-visible formats - NEVER mixed into the logs the detectors see.

Benign background comes from the Splunk lab's own generator so the attack
signal sits inside realistic noise; benign events are tagged ``step_id=null``
in the ground truth so false positives can be measured.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..scenario import PlanStep
from .builders import Builders
from .emitters import EmitContext, emitter_for
from .formats import ParsedRecord, firewall_to_zeek, to_minisiem, to_sentinel
from .inventory import DEFAULT_INVENTORY, Inventory

# When each step "runs" inside the lab day (hour offset from the dataset start).
# Kill-chain order is preserved; steps are spaced so MTTD per step is meaningful.
STEP_BASE_HOUR = 1.0
STEP_SPACING_HOURS = 0.5


@dataclass
class StepTiming:
    step_id: str
    technique_id: str
    start_ts: float
    event_count: int
    modelled: bool


@dataclass
class TelemetryResult:
    out_dir: Path
    steps: list[StepTiming]
    event_counts: dict[str, int]
    benign_counts: dict[str, int]
    ground_truth_path: Path
    unmodelled: list[str] = field(default_factory=list)

    @property
    def modelled_steps(self) -> list[StepTiming]:
        return [s for s in self.steps if s.modelled]


class TelemetryEngine:
    """Turn a flattened plan into synthetic telemetry across all stack formats."""

    def __init__(self, inventory: Inventory | None = None, *, seed: int = 1337,
                 start: str = "2026-10-20T00:00:00Z", hours: int = 24) -> None:
        self.inv = inventory or DEFAULT_INVENTORY
        self.seed = seed
        self.start = start
        self.hours = hours

    def run(self, steps: list[PlanStep], out_dir: str | Path, *, benign: bool = True) -> TelemetryResult:
        builders = Builders(self.start, self.hours, self.seed, self.inv)
        ctx = EmitContext(builders, self.inv)

        records: list[Any] = []                       # Splunk Record objects (attack)
        ground_truth: list[dict[str, Any]] = []
        timings: list[StepTiming] = []
        unmodelled: list[str] = []

        for i, step in enumerate(steps):
            t0 = builders.at(STEP_BASE_HOUR + i * STEP_SPACING_HOURS)
            emitter = emitter_for(step.technique_id)
            if emitter is None:
                timings.append(StepTiming(step.step_id, step.technique_id, t0, 0, False))
                unmodelled.append(step.technique_id)
                continue
            n = 0
            for rec, note in emitter(ctx, t0):
                records.append(rec)
                parsed = ParsedRecord.from_record(rec)
                ground_truth.append({
                    "step_id": step.step_id,
                    "technique_id": step.technique_id,
                    "technique_name": step.technique_name,
                    "tactic": step.tactic,
                    "timestamp": _iso(parsed.ts),
                    "epoch": parsed.ts,
                    "sourcetype": rec.sourcetype,
                    "note": note,
                })
                n += 1
            timings.append(StepTiming(step.step_id, step.technique_id, t0, n, True))

        benign_records = builders.benign() if benign else []
        for rec in benign_records:
            ground_truth.append({
                "step_id": None, "technique_id": None, "timestamp": _iso(float(rec.ts)),
                "epoch": float(rec.ts), "sourcetype": rec.sourcetype, "note": "benign background",
            })

        out = Path(out_dir)
        tel = out / "telemetry"
        counts = self._write(records + benign_records, tel)
        benign_counts = self._count_by_sourcetype(benign_records)

        gt_path = tel / "ground_truth.jsonl"
        gt_path.write_text("".join(json.dumps(r) + "\n" for r in sorted(ground_truth, key=lambda r: r["epoch"])),
                           encoding="utf-8")

        return TelemetryResult(out_dir=out, steps=timings, event_counts=counts,
                               benign_counts=benign_counts, ground_truth_path=gt_path,
                               unmodelled=unmodelled)

    # -- writers -----------------------------------------------------------
    def _write(self, records: list[Any], tel: Path) -> dict[str, int]:
        splunk_dir = tel / "splunk"
        minisiem_dir = tel / "minisiem"
        sentinel_dir = tel / "sentinel"
        for d in (splunk_dir, minisiem_dir, sentinel_dir):
            d.mkdir(parents=True, exist_ok=True)

        splunk_files = {
            "lab:windows:security": "windows_security.log", "lab:sysmon": "sysmon.log",
            "lab:linux:auth": "linux_auth.log", "lab:firewall": "firewall.log", "lab:dns": "dns.log",
        }
        splunk_buckets: dict[str, list[tuple[float, str]]] = {v: [] for v in splunk_files.values()}
        mini_buckets: dict[str, list[tuple[float, str]]] = {}
        sentinel_rows: list[dict[str, Any]] = []

        parsed_records = sorted((ParsedRecord.from_record(r) for r in records), key=lambda p: p.ts)
        for p in parsed_records:
            # Splunk: verbatim line.
            fname = splunk_files.get(p.sourcetype)
            if fname:
                splunk_buckets[fname].append((p.ts, p.line))
            # minisiem: converted format (+ a Zeek record for allowed firewall flows).
            mini = to_minisiem(p)
            if mini is not None:
                filename, line = mini
                if line is not None:
                    mini_buckets.setdefault(filename, []).append((p.ts, line))
            if p.sourcetype == "lab:firewall":
                zeek = firewall_to_zeek(p)
                if zeek is not None:
                    mini_buckets.setdefault("zeek_conn.jsonl", []).append((p.ts, zeek))
            # Sentinel: SecurityEvent rows.
            row = to_sentinel(p)
            if row is not None:
                sentinel_rows.append(row)

        counts: dict[str, int] = {}
        for fname, items in splunk_buckets.items():
            items.sort(key=lambda x: x[0])
            lines = [line for _, line in items]
            (splunk_dir / fname).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            if lines:
                counts[f"splunk/{fname}"] = len(lines)
        for fname, items in mini_buckets.items():
            items.sort(key=lambda x: x[0])
            lines = [line for _, line in items]
            (minisiem_dir / fname).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            counts[f"minisiem/{fname}"] = len(lines)

        sentinel_rows.sort(key=lambda r: r["TimeGenerated"])
        (sentinel_dir / "SecurityEvent.json").write_text(json.dumps(sentinel_rows, indent=2), encoding="utf-8")
        (sentinel_dir / "SigninLogs.json").write_text("[]", encoding="utf-8")
        counts["sentinel/SecurityEvent.json"] = len(sentinel_rows)
        return counts

    @staticmethod
    def _count_by_sourcetype(records: list[Any]) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in records:
            out[r.sourcetype] = out.get(r.sourcetype, 0) + 1
        return out


def _iso(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_ground_truth(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


__all__ = ["TelemetryEngine", "TelemetryResult", "StepTiming", "load_ground_truth"]
