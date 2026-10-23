"""Stage 3 - run three detection stacks over the same telemetry.

Each stack is the real sibling detector, run against the format it ingests,
and its alerts are normalised to one :class:`NormalizedAlert` schema so the
scoreboard can compare them like-for-like:

* ``minisiem``  - Sigma + correlation engine over the minisiem-format files
* ``splunk``    - the Splunk harness SPL evaluator with TA-threat-detection
* ``sentinel``  - ``simulate.py`` KQL-subset evaluator over SecurityEvent

``run_all`` returns the alerts from every available stack plus a per-stack
status so a missing or failing stack is visible rather than silently absent.
"""

from .normalize import NormalizedAlert
from .runner import DetectionRun, StackResult, run_all

__all__ = ["NormalizedAlert", "DetectionRun", "StackResult", "run_all"]
