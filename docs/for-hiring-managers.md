# What the numbers mean (for a hiring manager)

This page reads the scoreboard the way a SOC lead would, and says plainly what
each number does and does not prove about the person who built it.

## The headline

> Emulating a ransomware-affiliate actor (30 ATT&CK techniques) against a
> synthetic hospital network, the portfolio's three detection stacks caught
> **13/30 techniques (43.3%)**, with **3** techniques caught by all three stacks
> and **6** false positives on an equivalent benign-only run.

Read that as: *this candidate can state detection coverage as a measured number,
tie it to a specific threat, and be honest about the gaps.* That is the core of
a detection-engineering / SOC analyst job.

## What each metric is for

- **Coverage % (43.3%).** The share of emulated techniques that produced at
  least one correct alert. It is deliberately *not* 100% - a flattering number
  would mean the test was rigged. Under half, against a realistic hospital
  telemetry profile with deliberate collection blind spots, is a credible and
  useful result. The value is the *breakdown*, not the headline.
- **Coverage by tactic.** Persistence, defense-evasion and command-and-control
  score 100%; **discovery, collection and impact score 0%.** That is a real,
  actionable finding: the loud mid-chain activity is well covered, but the
  "attacker looks around / stages data / detonates ransomware" end of the chain
  is blind. A hiring manager sees someone who can prioritise which detections to
  write next (vssadmin / mass-encryption rules for impact, net/nltest baselining
  for discovery).
- **MTTD.** Mean time to detect. Here signature rules fire ~instantly and the
  stateful correlation rules (mini-SIEM) take longer to accumulate evidence
  (mean 23.7 s vs Splunk 6.0 s vs Sentinel 0.3 s). The point is not the absolute
  seconds (synthetic telemetry - see the methodology doc) but that the candidate
  **defined** MTTD precisely and can compare detection approaches on it.
- **Which stack caught what (Venn).** Splunk-only caught 4 techniques,
  mini-SIEM-only 1, Sentinel-only 1, and 3 were caught by all three. This is the
  argument for defence in depth expressed as data - and shows the candidate
  understands that different telemetry (Sysmon vs Windows Security vs network)
  catches different things.
- **False positives (6, all benign-run).** Measured honestly by re-running the
  stacks on noise with no attack. A candidate who reports their own FP rate is
  one who will tune alerts instead of drowning the queue.

## What it proves about the builder

- **Systems thinking.** Seven separate security tools - a planner, three SIEMs,
  a triage copilot, an ML detector and a report generator - are wired into one
  measured workflow. Nothing is re-implemented; the pipeline imports each real
  repo and fails loudly if one is missing. That is integration work, which is
  most of the job.
- **Threat-informed defence.** The exercise starts from an actor profile and an
  ATT&CK plan, not from the rules that happen to exist - so it finds the gaps
  the rules *don't* cover.
- **Measurement and honesty.** Coverage, MTTD and FPs are defined, computed and
  caveated. The limitations page is as detailed as the results page.
- **It runs.** One command produces the report, the ATT&CK Navigator layer and
  the committed example; `pytest` gates all of it.

## What it does not claim

It is not a benchmark of Splunk vs Sentinel vs a home-grown SIEM - each stack
sees only the telemetry it can ingest here, and two of the three are evaluator
subsets, not the products. It does not use real malware or real network traffic.
The absolute numbers are lab figures; the *relative* findings (which tactics are
blind, which stack is strongest where, which rules to write next) are what
transfer to a real environment.
