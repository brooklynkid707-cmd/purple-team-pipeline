# Integration contract with sibling repositories

Building the pipeline did **not** require changing any sibling repository. Every
sibling is imported and driven through its existing public surface. This file
records the integration points relied on and a few small, optional
improvements that would make future integration cleaner - none are required for
the pipeline to run today.

## Integration points relied on (please keep stable)

These are the exact entry points `ptp/` imports. Treat them as the contract
between this repo and the others:

| Repo | Imported symbol | Used for |
|---|---|---|
| ai-adversary-emulation-planner | `aep.kb.load_kb`, `aep.environment.Environment.from_file`, `aep.planner.build_plan` | the phased plan |
| splunk-threat-detection-lab | `scripts/generate_logs.py` `LogGenerator` + `kv`/`iso_z`/`Record`/`DOMAIN`/`SYSTEM32`/`PS_EXE`/`OFFICE`/`EXPLORER`/`CHROME` | event builders |
| splunk-threat-detection-lab | `harness.run_detections.run_all(data_dir, expected, only, app_dir)` | SPL evaluation |
| siem-from-scratch | `minisiem.pipeline.Pipeline(store, rules_dir=…, persist_alerts=False)`, `minisiem.storage.Store` | Sigma + correlation |
| microsoft-sentinel-detection-engineering | `tools/simulate.py` `simulate_dir(rules_dir, samples_dir)` returning `SimResult(supported, would_fire, rows, rule_file, rule_name)` | KQL evaluation |
| ai-soc-copilot | `copilot.workflow.Pipeline(backend="rules", out_dir=…).process(alert)`, `copilot.schema.Alert.from_dict` | triage |
| ml-threat-detection | `mltd.pipeline.train_detector/score_file/load_detector` | beacon/process scoring |
| soc-analyst-toolkit | `soctk.report.generate(case_path)` | NIST 800-61 report |

If any of these signatures change, update `ptp/siblings.py` and the matching
adapter in `ptp/detect/runner.py`, `ptp/triage/` or `ptp/report.py`.

## Observations (optional, not blockers)

1. **`LogGenerator.benign()` iterates `self.workstations`.** I register the
   hospital hosts on the generator; server-class hosts (`SRV-*`, `FS-*`) have to
   be removed from `workstations` again (kept only for `ws_ip`) so the benign
   loop does not try to pick "favourite destinations" for a server. A small
   `add_host(name, ip, in_benign_rotation=False)` helper on `LogGenerator` would
   make this cleaner. Worked around entirely inside `ptp/telemetry/builders.py`.

2. **mini-SIEM Windows parser covers 4624/4625/4688/4720/4732/1102/7045.** It has
   no mapping for 4698 / 4719 / 4648 / 4776 / 4769, so Kerberoasting (4769),
   pass-the-hash validation (4776) and explicit-credential lateral (4648) can
   never fire on mini-SIEM in this exercise. That is correctly reported as a
   coverage/collection gap, not a bug - but if you want mini-SIEM to compete on
   those, adding those event IDs to `minisiem/parsers/windows.py` is the change.

3. **Sentinel `simulate.py` ingests only tables present in `samples/`.** I emit a
   `SecurityEvent.json` and an empty `SigninLogs.json`. The identity/Office/cloud
   analytics rules therefore cannot fire here. Adding a SigninLogs emitter to
   `ptp/telemetry/` (not a sibling change) would let `signin-*` rules participate.

4. **ml-threat-detection process detector calibration is baseline-specific.**
   Scored against this pipeline's benign mix it over-fires at its native 0.5
   threshold, so I raise the display threshold to 0.7 (documented in
   `docs/methodology.md`). Not a defect - expected cross-environment drift - but
   worth a line in the mltd README that the 0.5 = p99 calibration is per training
   set.

Everything above is handled inside `purple-team-pipeline/`; no edits to the
sibling repos were made.
