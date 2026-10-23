"""Behavioural ML scoring of the raw telemetry with ml-threat-detection.

The signature stacks match known patterns; mltd adds anomaly scoring. We train
the sibling's beacon and process detectors on *its own* committed baselines
(so the models are fit the way the author intended) and score CSVs we derive
from this run's telemetry:

* beacon  <- firewall allow/outbound flows (src, dst, port, bytes)
* process <- Sysmon EventCode=1 process-creation lines (parent, image, cmdline)

The auth detector needs geo/ASN/device columns this pipeline does not model,
so it is intentionally left out and reported as such rather than faked.
"""

from __future__ import annotations

import csv
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import siblings

_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _kv(rest: str) -> dict[str, str]:
    out = {}
    for m in _KV_RE.finditer(rest):
        v = m.group(2)
        out[m.group(1)] = v[1:-1] if v.startswith('"') and v.endswith('"') else v
    return out


@dataclass
class MLScore:
    detector: str
    alerts: list[dict[str, Any]] = field(default_factory=list)
    scored_units: int = 0
    ran: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"detector": self.detector, "ran": self.ran, "reason": self.reason,
                "scored_units": self.scored_units, "alert_count": len(self.alerts),
                "alerts": self.alerts}


def _beacon_csv(splunk_dir: Path, dest: Path) -> int:
    fw = splunk_dir / "firewall.log"
    if not fw.is_file():
        return 0
    rows = 0
    with dest.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "proto", "bytes_out", "bytes_in", "label", "attack"])
        for line in fw.read_text(encoding="utf-8").splitlines():
            parts = line.split("|")
            if len(parts) != 11:
                continue
            iso_ts, _fw, action, direction, src, _sp, dst, dport, proto, bin_, bout = parts
            if action != "allow" or direction != "outbound":
                continue
            w.writerow([iso_ts, src, dst, dport, proto, bout, bin_, 0, ""])
            rows += 1
    return rows


def _process_csv(splunk_dir: Path, dest: Path) -> int:
    sysmon = splunk_dir / "sysmon.log"
    if not sysmon.is_file():
        return 0
    rows = 0
    with dest.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "host", "user", "parent_image", "image", "command_line", "label", "attack"])
        for line in sysmon.read_text(encoding="utf-8").splitlines():
            iso_ts, _, rest = line.partition(" ")
            f = _kv(rest)
            if f.get("EventCode") != "1":
                continue
            w.writerow([iso_ts, f.get("host", ""), f.get("User", ""),
                        _basename(f.get("ParentImage", "")), _basename(f.get("Image", "")),
                        f.get("CommandLine", ""), 0, ""])
            rows += 1
    return rows


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1] if path else ""


# The process model is calibrated so 0.5 = the 99th percentile of the sibling's
# *own* benign training data; scored against this pipeline's (different) benign
# mix it over-fires at 0.5, so we raise its display threshold. This cross-
# environment drift is called out honestly in docs/methodology.md.
_DISPLAY_THRESHOLD: dict[str, float] = {"process": 0.7}


def score_with_mltd(telemetry_dir: str | Path, out_dir: str | Path,
                    detectors: tuple[str, ...] = ("beacon", "process")) -> list[MLScore]:
    """Train (on the sibling's baselines) and score the requested mltd detectors."""
    telemetry_dir = Path(telemetry_dir)
    splunk_dir = telemetry_dir / "splunk"
    results: list[MLScore] = []
    try:
        pipeline, train_data_dir = siblings.mltd_pipeline()
    except siblings.MissingSiblingError as exc:
        return [MLScore(d, ran=False, reason=str(exc).splitlines()[0]) for d in detectors]

    with tempfile.TemporaryDirectory() as tmp:
        models_dir = Path(tmp) / "models"
        models_dir.mkdir(parents=True, exist_ok=True)
        scoring_dir = Path(tmp) / "score"
        scoring_dir.mkdir(parents=True, exist_ok=True)
        builders = {"beacon": _beacon_csv, "process": _process_csv}
        for name in detectors:
            if name not in builders:
                results.append(MLScore(name, ran=False, reason="no telemetry mapping for this detector"))
                continue
            try:
                pipeline.train_detector(name, train_data_dir, models_dir)
            except Exception as exc:  # noqa: BLE001
                results.append(MLScore(name, ran=False, reason=f"train failed: {exc}"))
                continue
            csv_path = scoring_dir / f"{name}.csv"
            n = builders[name](splunk_dir, csv_path)
            if n == 0:
                results.append(MLScore(name, ran=False, reason="no matching telemetry to score"))
                continue
            try:
                alerts, scored = pipeline.score_file(name, csv_path, models_dir, None,
                                                     threshold=_DISPLAY_THRESHOLD.get(name))
            except Exception as exc:  # noqa: BLE001
                results.append(MLScore(name, ran=False, reason=f"score failed: {exc}"))
                continue
            trimmed = [{
                "rule": a.get("rule.name"), "score": a.get("mltd.score"),
                "severity": a.get("mltd.severity"), "message": a.get("message"),
                "techniques": a.get("threat.technique.id", []),
                "src_ip": a.get("source.ip"), "dst_ip": a.get("destination.ip"),
                "host": a.get("host.name"),
            } for a in alerts]
            results.append(MLScore(name, alerts=trimmed, scored_units=int(len(scored)), ran=True))
    return results


__all__ = ["MLScore", "score_with_mltd"]
