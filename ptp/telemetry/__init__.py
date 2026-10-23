"""Stage 2 - the telemetry engine.

Turns every plan step into realistic synthetic events, renders them in the
formats each detection stack ingests, mixes in benign background noise, and
keeps the ground truth (which event belongs to which step) in a separate file
the detectors never see.

Modules
-------
inventory   hospital-flavoured hosts, users and addresses (all synthetic)
builders    event builders - the Splunk lab's ``LogGenerator`` plus a few
            extra Windows event IDs it does not ship
emitters    ATT&CK technique -> list of events (one emitter per technique)
formats     the Splunk key=value wire format converted to minisiem JSON /
            auth.log / iptables / Zeek conn and to Sentinel SecurityEvent rows
engine      orchestration: plan -> events -> files + ground_truth.jsonl
"""

from .engine import TelemetryEngine, TelemetryResult

__all__ = ["TelemetryEngine", "TelemetryResult"]
