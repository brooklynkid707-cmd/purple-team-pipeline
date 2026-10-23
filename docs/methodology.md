# Methodology

## Why purple teaming

A red team proves an attack path exists. A blue team writes detections. Neither,
on its own, answers the question a SOC manager actually has: **"if this actor
hit us tomorrow, what would we catch, how fast, and what would we miss?"**
Purple teaming answers it by running the attack and the defence as one loop and
measuring the overlap. This pipeline automates that loop end to end so the
answer is a number you can track over time, not an opinion from the last
tabletop.

The loop here is: **threat model** (an actor profile from the planner) ->
**emulation** (synthetic telemetry for each technique) -> **detection** (three
real SIEM rule-sets) -> **measurement** (coverage, MTTD, gaps) -> **report**
(what to fix). Re-running after writing a rule closes the loop; `ptp compare`
shows the delta.

## How a step is scored

Each plan step is one ATT&CK technique emitted at a known time. An alert
**covers** a step when:

1. the alert shares the step's technique - exact ID, or a bare parent against
   its sub-technique (`T1021` ↔ `T1021.001`). Two sibling sub-techniques
   (`T1021.001` vs `T1021.002`) never cross-credit; plan techniques are unique,
   so a shared technique identifies the step; **and**
2. the alert fired inside the step's time window (from ~1 h before - to absorb a
   binned scheduled search reporting its window floor - to 30 min after, the
   step spacing). This stops a rule whose tag drifts onto a *later* step's
   telemetry from crediting this one.

A step is **detected** if ≥1 stack covers it, **partial** if exactly one stack
does, **missed** if none do.

## How MTTD is defined

**MTTD (step) = first covering alert's timestamp − step start, clamped to ≥ 0.**
The step start is the time the step's telemetry begins. The alert timestamp is
the earliest real event time in the alert's evidence; for a stateful rule
(correlation, sequence, beaconing) that is the time the evidence *completed*, so
MTTD reflects genuine accumulation latency. For a point-in-time signature rule
it is ~0 (the alert fires on the triggering event). The reported **mean MTTD** is
over detected steps using the earliest stack; **per-stack MTTD** shows each
stack's own latency (correlation stacks are slower, signature stacks near-zero).

Two honest caveats are baked in:

* **Binned scheduled searches.** Splunk/Sentinel scheduled searches report a
  *window* (e.g. a 1-hour bin), whose floor can precede the triggering event.
  The pipeline prefers a real `first_seen`/`TimeGenerated` field when the search
  emits one and only falls back to the bin floor otherwise; a floor earlier than
  the step start clamps MTTD to 0 ("detected within the first window"), it never
  goes negative.
* **Synthetic instantaneous telemetry.** Because events are emitted at a chosen
  time rather than observed over a real network, signature detections look
  instantaneous. MTTD here measures **detection-logic latency**, not ingestion
  or alert-pipeline delay. On a real SIEM you would add scheduler period and
  ingestion lag; this number is the floor, not the field reality.

## False positives

The FP metric is the `splunk-threat-detection-lab` convention: run the exact
same stacks over a **benign-only** telemetry set (identical background noise,
no planted techniques) and count what fires. Those alerts are unambiguous false
positives - they fired with no attack present. This is separate from the
**unattributed** list (alerts on *attack* telemetry whose technique tag sits
outside the plan, e.g. a DNS-tunnelling rule tagging `T1071.004` firing on the
C2 domain lookup of a `T1071.001` web-C2 step). Unattributed alerts are real
detections with tag drift, reported for transparency and never counted as FPs.

## Honest limitations

- **Synthetic telemetry.** Every event is generated, using the
  `splunk-threat-detection-lab` builders plus a few extra Windows event IDs.
  There is no real endpoint, no EDR agent, no packet capture. The emitters
  render the telemetry a defender *would expect* for each technique - they do
  not execute anything. No exploit code or payloads exist anywhere in the repo.
- **Evaluator subsets, not production SIEMs.** The Splunk harness is a
  subset-of-SPL interpreter and the Sentinel tool is a KQL-subset evaluator.
  Sentinel's evaluator runs ~13 of 28 analytics rules (it reports the rest as
  unsupported - `join`, `mv-expand`, `serialize` etc.), and it only ingests the
  `SecurityEvent` table here, so identity/Office/cloud rules cannot fire. These
  are the siblings' documented limits; the pipeline inherits them and the report
  says which stacks ran.
- **Coverage is per-technique, not per-procedure.** One technique = one step. A
  real actor runs many procedures per technique; catching one is scored as
  catching the technique.
- **The ML process detector drifts across environments.** It is calibrated so
  score 0.5 = the 99th percentile of its *own* training baseline; scored against
  this pipeline's (different) benign mix it over-fires at 0.5, so its display
  threshold is raised to 0.7. That cross-environment calibration drift is itself
  a real detection-engineering lesson, surfaced rather than hidden.
- **Profiles are archetypes.** The adversary profiles are composed technique
  sets, not attributed threat intel.

None of this invalidates the exercise: the detections are the owner's real rules,
the gaps they reveal are real gaps in that rule content, and the recommended
detections are the real fixes. It means the *absolute* MTTD and volume numbers
are lab figures, while the *relative* findings (which stack caught what, which
tactics are blind) transfer.
