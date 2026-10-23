"""Stage 4 - triage the normalised alerts and add ML scoring.

Two sibling tools, used for what each does best:

* ``ai-soc-copilot`` (rules backend) takes every normalised alert and returns a
  severity, an ATT&CK technique and a confidence, with the alert's free text
  treated as untrusted (its guardrails stay on). This is the analyst-facing
  verdict layer.
* ``ml-threat-detection`` scores the raw telemetry with its beacon and process
  detectors (trained on the sibling's own baselines) to show where behavioural
  ML adds signal the signature rules do not - e.g. a periodic beacon.

Both are optional: if a sibling is missing, triage degrades gracefully and the
pipeline still scores the signature stacks.
"""

from .copilot_triage import TriageVerdict, triage_alerts
from .mltd_scoring import MLScore, score_with_mltd

__all__ = ["TriageVerdict", "triage_alerts", "MLScore", "score_with_mltd"]
