"""Command-line interface: ``python -m ptp <run|replay|compare|doctor>``.

    python -m ptp run --profile ransomware-affiliate --env hospital --out runs/demo
    python -m ptp replay runs/demo
    python -m ptp compare runs/a runs/b
    python -m ptp doctor
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, scenario, siblings
from .pipeline import run_pipeline


def _default_out() -> str:
    return f"runs/{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"


def cmd_run(args: argparse.Namespace) -> int:
    try:
        siblings.require()
    except siblings.MissingSiblingError as exc:
        print(exc, file=sys.stderr)
        return 2
    out = args.out or _default_out()
    result = run_pipeline(args.profile, args.env, out, seed=args.seed,
                          with_triage=not args.no_triage, with_ml=not args.no_ml)
    return 0 if result.stacks_ran else 1


def cmd_replay(args: argparse.Namespace) -> int:
    """Re-render the report and re-print the scoreboard from a finished run."""
    run_dir = Path(args.run)
    sb_path = run_dir / "scoreboard.json"
    if not sb_path.is_file():
        print(f"no scoreboard.json in {run_dir} (run `ptp run` first)", file=sys.stderr)
        return 2
    scoreboard = json.loads(sb_path.read_text(encoding="utf-8"))
    s = scoreboard["summary"]
    print(f"Replay of {run_dir}")
    print(f"  coverage {s['coverage_pct']}%  ({s['steps_detected']}/{s['steps_modelled']})   "
          f"mean MTTD {_fmt(s['mean_mttd_seconds'])}   FP {s['false_positive_alerts']}")
    print()
    print(f"  {'step':<5} {'tactic':<22} {'technique':<12} {'status':<9} stacks")
    for st in scoreboard["steps"]:
        status = scoreboard["status_by_step"][st["step_id"]]
        print(f"  {st['step_id']:<5} {st['tactic']:<22} {st['technique_id']:<12} {status:<9} "
              f"{', '.join(st['stacks']) or '-'}")
    print()
    print("  by stack: " + "  ".join(
        f"{k}={v['coverage_pct']}%" for k, v in scoreboard["coverage_by_stack"].items()))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    """Diff two runs' coverage and MTTD (e.g. before/after writing new rules)."""
    a = json.loads((Path(args.run_a) / "scoreboard.json").read_text(encoding="utf-8"))
    b = json.loads((Path(args.run_b) / "scoreboard.json").read_text(encoding="utf-8"))
    sa, sb = a["summary"], b["summary"]
    print(f"Comparing A={args.run_a}  vs  B={args.run_b}\n")
    print(f"  {'metric':<26} {'A':>10} {'B':>10} {'delta':>10}")
    for label, key in (("coverage %", "coverage_pct"), ("techniques detected", "steps_detected"),
                       ("techniques missed", "steps_missed"), ("mean MTTD (s)", "mean_mttd_seconds"),
                       ("false positives", "false_positive_alerts")):
        va, vb = sa.get(key), sb.get(key)
        delta = _delta(va, vb)
        print(f"  {label:<26} {_cell(va):>10} {_cell(vb):>10} {delta:>10}")
    # Per-step status changes.
    sta, stb = a["status_by_step"], b["status_by_step"]
    changed = [(k, sta.get(k), stb.get(k)) for k in sorted(set(sta) | set(stb)) if sta.get(k) != stb.get(k)]
    if changed:
        print("\n  step status changes:")
        for step_id, va, vb in changed:
            print(f"    {step_id}: {va} -> {vb}")
    else:
        print("\n  no per-step status changes")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check every sibling repo resolves and print where it was found."""
    print(f"Purple Team Pipeline {__version__}  -  sibling check")
    print(f"PORTFOLIO_ROOT = {siblings.portfolio_root()}")
    print(f"vendor/        = {siblings.vendor_root()}")
    print()
    rows = siblings.status()
    ok = True
    for key, sib in siblings.SIBLINGS.items():
        path = rows[key]
        mark = "OK  " if path else "MISS"
        where = str(path) if path else "not found"
        if path is None:
            ok = False
        print(f"  [{mark}] {sib.repo:<42} {where}")
        print(f"         -> {sib.role}")
    print()
    if ok:
        print("All siblings resolved. Ready: python -m ptp run --profile ransomware-affiliate --env hospital")
        return 0
    print("Some siblings are missing. Run scripts/setup_siblings.sh or set PORTFOLIO_ROOT.")
    return 1


def _fmt(secs) -> str:
    if secs is None:
        return "n/a"
    if secs < 60:
        return f"{secs:.0f}s"
    m, s = divmod(int(secs), 60)
    return f"{m}m{s:02d}s"


def _cell(v) -> str:
    return "n/a" if v is None else (f"{v:g}" if isinstance(v, (int, float)) else str(v))


def _delta(a, b) -> str:
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        d = b - a
        return f"{d:+g}"
    return "-"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ptp", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"ptp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run the full exercise end to end")
    p_run.add_argument("--profile", default="ransomware-affiliate", help="adversary profile (see aep list-profiles)")
    p_run.add_argument("--env", default="hospital", help="environment name or path to an env yaml")
    p_run.add_argument("--out", help="output directory (default: runs/<timestamp>)")
    p_run.add_argument("--seed", type=int, default=1337, help="telemetry RNG seed")
    p_run.add_argument("--no-triage", action="store_true", help="skip ai-soc-copilot triage")
    p_run.add_argument("--no-ml", action="store_true", help="skip ml-threat-detection scoring")
    p_run.set_defaults(func=cmd_run)

    p_replay = sub.add_parser("replay", help="re-print the scoreboard of a finished run")
    p_replay.add_argument("run", help="a run directory")
    p_replay.set_defaults(func=cmd_replay)

    p_cmp = sub.add_parser("compare", help="diff two runs (before/after rule changes)")
    p_cmp.add_argument("run_a")
    p_cmp.add_argument("run_b")
    p_cmp.set_defaults(func=cmd_compare)

    p_doc = sub.add_parser("doctor", help="check the sibling repositories resolve")
    p_doc.set_defaults(func=cmd_doctor)

    p_prof = sub.add_parser("profiles", help="list available adversary profiles")
    p_prof.set_defaults(func=lambda a: _list_profiles())
    return parser


def _list_profiles() -> int:
    for p in scenario.list_profiles():
        print(f"  {p['id']:<24} {p['techniques']:>3} techniques   {p['name']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
