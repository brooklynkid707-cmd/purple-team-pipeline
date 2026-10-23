"""Purple Team Pipeline - plan an attack, emit telemetry, detect, triage, score, report.

One command runs an adversary emulation from the ATT&CK plan to the incident
report across the owner's detection portfolio and measures the outcome:

    python -m ptp run --profile ransomware-affiliate --env hospital --out runs/demo

The package orchestrates seven sibling repositories (located through
:mod:`ptp.siblings`) and never re-implements them:

* ``ai-adversary-emulation-planner``  -> the phased plan
* ``splunk-threat-detection-lab``     -> event builders + Splunk SPL evaluator
* ``siem-from-scratch``               -> Sigma + correlation engine
* ``microsoft-sentinel-detection-engineering`` -> KQL-subset evaluator
* ``ai-soc-copilot``                  -> alert triage
* ``ml-threat-detection``             -> beacon / auth / process ML scoring
* ``soc-analyst-toolkit``             -> NIST 800-61 incident report
"""

__version__ = "1.0.0"
