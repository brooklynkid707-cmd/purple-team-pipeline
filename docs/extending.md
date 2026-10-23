# Extending the pipeline

## Add an adversary profile

Profiles live in the planner sibling (`ai-adversary-emulation-planner`), not
here. Add one to its `data/actor_profiles.json` (or `scripts/build_kb.py`) with
a technique list, then run the pipeline against it:

```bash
python -m ptp profiles                       # confirm it shows up
python -m ptp run --profile my-new-profile --env hospital
```

Any technique in the profile that the telemetry engine has an emitter for is
exercised; any it does not is reported in the run log as *unmodelled* and listed
honestly rather than silently skipped. To model a new technique, add an emitter
(below).

## Add a telemetry emitter (model a new technique)

Emitters live in [`ptp/telemetry/emitters.py`](../ptp/telemetry/emitters.py).
An emitter takes the shared context and a start time and yields
`(Record, ground_truth_note)` pairs:

```python
def emit_my_technique(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    yield b.sysmon_process(t0, inv.victim_host, b.domain_user(inv.victim_user),
                           f"{b.system32}\\mytool.exe", "mytool.exe --flag",
                           f"{b.system32}\\cmd.exe"), "what this event represents"

EMITTERS["T1234"] = emit_my_technique
```

Use the `Builders` facade (`b`) - it delegates to the Splunk lab's real event
builders and adds a few Windows event IDs. Emit only the telemetry a defender
would observe; never real commands or payloads. The format converters turn your
Splunk-shaped records into the other stacks' formats automatically, so one
emitter feeds all three SIEMs.

## Add a detection stack

A stack is one adapter in [`ptp/detect/runner.py`](../ptp/detect/runner.py) that:

1. imports the real sibling via `ptp/siblings.py` (add it to `SIBLINGS` first);
2. runs it over the matching `telemetry/<stack>/` directory;
3. converts its results into `NormalizedAlert` objects
   (`stack, rule, rule_title, techniques, timestamp, severity, entities`).

Then add it to `run_all()` and to `STACKS` in `ptp/score.py`. The scoreboard,
Venn table, Navigator layer and report pick it up with no further changes -
coverage and MTTD are computed generically over whatever stacks reported.

Return **one alert per firing instance** (e.g. per result row / per correlation
hit), not one per rule: a scheduled search can fire in several time windows, and
each should be matched to its own step.

## Add an environment

Environments are the planner's `env/*.yaml` files (OS mix, collected data
sources, SIEM/EDR). Point at one by name or path:

```bash
python -m ptp run --profile ransomware-affiliate --env /path/to/env.yaml
```

The environment shapes the plan (blind spots, expected telemetry). To make the
*emitted* hosts match a new environment, adjust
[`ptp/telemetry/inventory.py`](../ptp/telemetry/inventory.py).

## Re-run and compare

After changing rule content in a sibling repo, re-run and diff:

```bash
python -m ptp run --profile ransomware-affiliate --env hospital --out runs/after
python -m ptp compare examples/ransomware-affiliate-hospital runs/after
```

`compare` prints the coverage/MTTD/FP deltas and every per-step status change
(e.g. `S16: missed -> partial`), which is the artefact you attach to a
detection-engineering PR.
