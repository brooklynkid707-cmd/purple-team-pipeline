"""Technique -> synthetic telemetry emitters.

Each emitter takes a start time and returns the log lines a defender would
expect to observe when a given ATT&CK technique is exercised in an authorized
lab. These are detection fixtures only: benign placeholder command text, no
payloads, no working tooling - exactly the "expected telemetry" the planner's
checklist describes, rendered as events so the detection stacks can be scored.

An emitter yields ``(Record, note)`` pairs. ``note`` is the ground-truth label
kept out of the logs. The dispatch table maps technique IDs (and sub-technique
parents) to emitters; techniques with no emitter are reported as "no telemetry
modelled" so coverage stays honest rather than silently empty.
"""

from __future__ import annotations

import base64
from typing import Callable, Iterator

from .builders import Builders
from .inventory import Inventory

Emitted = tuple[object, str]          # (Record, ground-truth note)
Emitter = Callable[["EmitContext", float], Iterator[Emitted]]

# A short, obviously-inert placeholder used wherever an emitter needs "some
# command text": it carries no operational meaning, only the switches a rule
# keys on (e.g. the presence of "-enc").
PLACEHOLDER = "lab-detection-fixture-benign-placeholder"


class EmitContext:
    """Shared state handed to every emitter."""

    def __init__(self, builders: Builders, inventory: Inventory) -> None:
        self.b = builders
        self.inv = inventory


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


# --------------------------------------------------------------------------- #
# Initial access / execution
# --------------------------------------------------------------------------- #
def emit_spearphish(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.victim_host, inv.victim_user
    target = f"C:\\Users\\{user}\\Downloads\\Imaging_Request_4471.docm"
    yield b.sysmon_file_create(t0, host, b.domain_user(user), b.chrome, target), "attachment written to disk"


def emit_user_execution(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.victim_host, inv.victim_user
    winword = f"{b.office}\\WINWORD.EXE"
    yield (b.sysmon_process(t0, host, b.domain_user(user), f"{b.system32}\\cmd.exe",
                            f'cmd.exe /c "{PLACEHOLDER}.bat"', winword,
                            f'"{winword}" /n "C:\\Users\\{user}\\Downloads\\Imaging_Request_4471.docm"'),
           "office spawns command shell")


def emit_powershell(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.victim_host, inv.victim_user
    cmdline = f"powershell.exe -NoP -NonI -W Hidden -Enc {_b64(PLACEHOLDER)}"
    winword = f"{b.office}\\WINWORD.EXE"
    yield b.sysmon_process(t0, host, b.domain_user(user), b.ps_exe, cmdline, winword), "encoded powershell (sysmon)"
    yield b.win_process(t0 + 0.4, host, user, b.ps_exe, cmdline, winword), "encoded powershell (4688)"


def emit_service_execution(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host = inv.file_server
    image = f"C:\\Windows\\{PLACEHOLDER[:8]}.exe"
    yield b.win_service_installed(t0, host, inv.admin_user, "PTPSvc01", image), "service installed for execution"
    yield (b.sysmon_process(t0 + 1, host, b.domain_user(inv.admin_user), image,
                            f"{PLACEHOLDER[:8]}.exe -run", f"{b.system32}\\services.exe"), "service process started")


# --------------------------------------------------------------------------- #
# Persistence / privilege escalation / defense evasion
# --------------------------------------------------------------------------- #
def emit_scheduled_task(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.victim_host, inv.victim_user
    cmdline = 'schtasks.exe /create /sc minute /mo 15 /tn "PacsSync" /tr "C:\\Users\\Public\\sync.exe" /f'
    yield b.sysmon_process(t0, host, b.domain_user(user), f"{b.system32}\\schtasks.exe", cmdline, f"{b.system32}\\cmd.exe"), "schtasks create"
    yield b.win_task_created(t0 + 1, host, user, "\\PacsSync", "C:\\Users\\Public\\sync.exe"), "4698 task created"


def emit_windows_service(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host = inv.file_server
    image = "C:\\Users\\Public\\pacsupd.exe"
    yield b.win_service_installed(t0, host, inv.admin_user, "PacsUpdater", image), "persistence service installed"


def emit_bypass_uac(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.victim_host, inv.victim_user
    yield (b.sysmon_process_elevated(t0, host, b.domain_user(user), f"{b.system32}\\fodhelper.exe",
                                     "fodhelper.exe", f"{b.system32}\\cmd.exe", "High"),
           "uac bypass via fodhelper (high integrity)")


def emit_token_manipulation(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.file_server, inv.admin_user
    # New-credentials logon (type 9) is the runas/token tell.
    yield b.win_logon(t0, host, user, 9, b.ws_ip(inv.victim_host), True, inv.victim_host), "logon type 9 (token manipulation)"


def emit_impair_defenses(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.file_server, inv.admin_user
    yield b.win_audit_policy_changed(t0, host, user), "audit policy weakened (4719)"
    cmdline = "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true"
    yield b.win_process(t0 + 2, host, user, b.ps_exe, cmdline, f"{b.system32}\\cmd.exe"), "defender tamper command"


def emit_clear_logs(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.file_server, inv.admin_user
    yield b.sysmon_process(t0, host, b.domain_user(user), f"{b.system32}\\wevtutil.exe", "wevtutil.exe cl Security", f"{b.system32}\\cmd.exe"), "wevtutil clear"
    yield b.win_log_cleared(t0 + 1, host, user), "security log cleared (1102)"


# --------------------------------------------------------------------------- #
# Credential access
# --------------------------------------------------------------------------- #
def emit_lsass_dump(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.file_server, inv.admin_user
    source = "C:\\Windows\\Temp\\pd.exe"
    trace = "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4a4|C:\\Windows\\System32\\KERNELBASE.dll+2c3fe|C:\\Windows\\Temp\\pd.exe+1a2b"
    for i, access in enumerate(["0x1FFFFF", "0x1010", "0x1438"]):
        yield b.sysmon_process_access(t0 + i * 2, host, b.domain_user(user), source, f"{b.system32}\\lsass.exe", access, trace), "lsass access (dump mask)"
    yield (b.win_process(t0 + 7, host, user, source, f"pd.exe -ma lsass.exe out.dmp", f"{b.system32}\\cmd.exe"),
           "lsass dump command line (4688)")


def emit_kerberoast(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    for i, svc in enumerate(["MSSQLSvc/srv-ehr-db-01:1433", "HTTP/srv-pacs-01", "CIFS/fs-01"]):
        yield b.win_kerberos_tgs(t0 + i * 3, inv.dc, inv.service_user, svc, b.ws_ip(inv.victim_host)), "kerberoast RC4 TGS (4769)"


def emit_password_spray(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    # One failure each against many accounts from one IP (4625) + the DC NTLM view (4776).
    for i, user in enumerate(inv.spray_users):
        yield b.win_logon(t0 + i * 14, inv.dc, user, 3, inv.attacker_ip, False, "WORKSTATION", "0xC000006A"), "spray failed logon (4625)"
        yield b.win_ntlm_validation(t0 + i * 14 + 0.3, inv.dc, user, "WORKSTATION", "0xC000006A"), "spray ntlm validation (4776)"


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def _discovery_cmd(ctx: EmitContext, t0: float, tool: str, args: str, note: str) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.victim_host, inv.victim_user
    yield b.sysmon_process(t0, host, b.domain_user(user), f"{b.system32}\\{tool}", f"{tool} {args}", f"{b.system32}\\cmd.exe"), note


def emit_account_discovery(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    yield from _discovery_cmd(ctx, t0, "net.exe", 'group "Domain Admins" /domain', "domain account discovery")


def emit_remote_system_discovery(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    # A host sweep on the clinical subnet (Zeek/firewall view) + a net view.
    yield from _discovery_cmd(ctx, t0, "net.exe", "view /all", "remote system discovery (net view)")
    for i, dst in enumerate(inv.sweep_targets):
        yield b.sysmon_network(t0 + 2 + i * 3, inv.victim_host, b.domain_user(inv.victim_user), f"{b.system32}\\net.exe", dst, 445, "-"), "host sweep (smb probe)"


def emit_domain_trust_discovery(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    yield from _discovery_cmd(ctx, t0, "nltest.exe", "/domain_trusts", "domain trust discovery")


# --------------------------------------------------------------------------- #
# Lateral movement
# --------------------------------------------------------------------------- #
def emit_external_remote_services(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    # A single VPN / external remote-interactive logon from the attacker IP -
    # realistically hard to tell from a legitimate remote worker (often a gap).
    yield b.win_logon(t0, inv.vpn_server, inv.service_user, 10, inv.attacker_ip, True, "REMOTE-VPN"), "external remote service logon"


def emit_rdp(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    src = b.ws_ip(inv.victim_host)
    for i, host in enumerate(inv.rdp_targets):
        yield b.win_logon(t0 + i * 180, host, inv.admin_user, 10, src, True, inv.victim_host), "rdp lateral logon (type 10)"


def emit_smb(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    user = b.domain_user(inv.admin_user)
    for i, peer in enumerate(inv.smb_targets):
        dst = inv.hosts.get(peer) or b.ws_ip(peer) if peer in inv.hosts else "10.10.0.20"
        try:
            dst = b.ws_ip(peer)
        except KeyError:
            dst = "10.10.0.20"
        yield b.sysmon_network(t0 + i * 16, inv.victim_host, user, f"{b.system32}\\net.exe", dst, 445, peer), "smb fan-out"


def emit_pass_the_hash(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    # NTLM network logon from the pivot host to a server (type 3 NTLM) + DC validation.
    yield b.win_logon(t0, inv.file_server, inv.admin_user, 3, b.ws_ip(inv.victim_host), True, inv.victim_host), "pass-the-hash NTLM logon (type 3)"
    yield b.win_ntlm_validation(t0 + 0.3, inv.dc, inv.admin_user, inv.victim_host, "0x0"), "pth ntlm validation (4776)"


def emit_explicit_creds_lateral(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    for i, target in enumerate(inv.rdp_targets):
        yield (b.win_explicit_credentials(t0 + i * 20, inv.victim_host, inv.admin_user, "administrator",
                                          target, f"{b.system32}\\wsmprovhost.exe", b.ws_ip(inv.victim_host)),
               "explicit-credential lateral (4648)")


def emit_lateral_tool_transfer(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    target = "C:\\Users\\Public\\stage.exe"
    yield b.sysmon_file_create(t0, inv.file_server, b.domain_user(inv.admin_user), f"{b.system32}\\cmd.exe", target), "lateral tool transfer (file drop)"


# --------------------------------------------------------------------------- #
# Collection / C2 / exfil
# --------------------------------------------------------------------------- #
def emit_archive_data(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.file_server, inv.admin_user
    cmdline = 'rar.exe a -r -hp C:\\Users\\Public\\arch.rar \\\\FS-01\\Patients\\'
    yield b.sysmon_process(t0, host, b.domain_user(user), "C:\\Users\\Public\\rar.exe", cmdline, f"{b.system32}\\cmd.exe"), "archive via utility"


def emit_data_local(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.file_server, inv.admin_user
    yield from _discovery_cmd_host(ctx, t0, host, user, "findstr.exe", '/s /i "mrn" C:\\Shares\\Patients\\*', "data from local system")


def _discovery_cmd_host(ctx: EmitContext, t0: float, host: str, user: str, tool: str, args: str, note: str) -> Iterator[Emitted]:
    b = ctx.b
    yield b.sysmon_process(t0, host, b.domain_user(user), f"{ctx.b.system32}\\{tool}", f"{tool} {args}", f"{ctx.b.system32}\\cmd.exe"), note


def emit_web_c2(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host = inv.victim_host
    src = b.ws_ip(host)
    # DNS to a listed C2 domain + a regular-interval beacon to the listed C2 IP (firewall + zeek).
    yield b.sysmon_dns(t0, host, b.domain_user(inv.victim_user), b.ps_exe, inv.c2_domain, f"::ffff:{inv.c2_ip}"), "c2 domain resolved"
    ts = t0
    for _ in range(24):
        ts += 60
        yield b.firewall(ts, "allow", "outbound", src, inv.c2_ip, 443, 620, 280), "c2 beacon (firewall)"


def emit_ingress_tool(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.victim_host, inv.victim_user
    yield b.sysmon_dns(t0, host, b.domain_user(user), b.ps_exe, inv.stage_domain, f"::ffff:{inv.c2_ip}"), "staging domain resolved"
    yield b.sysmon_file_create(t0 + 3, host, b.domain_user(user), b.ps_exe, "C:\\Users\\Public\\upd.dll"), "downloaded tool written"


def emit_exfil_c2(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    # Volume spike to the exfil host (kept off the beacon pair so the C2 beacon
    # stays a clean periodic signal for the ML detector).
    for i in range(6):
        yield b.firewall(t0 + i * 120, "allow", "outbound", b.ws_ip(inv.victim_host), inv.c2_exfil_ip, 443, 90, 42_000_000), "exfil over c2 channel"


def emit_exfil_cloud(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host = inv.victim_host
    yield b.sysmon_dns(t0, host, b.domain_user(inv.victim_user), b.chrome, inv.exfil_cloud_domain, f"::ffff:{inv.exfil_cloud_ip}"), "cloud storage resolved"
    for i in range(6):
        yield b.firewall(t0 + 5 + i * 120, "allow", "outbound", b.ws_ip(host), inv.exfil_cloud_ip, 443, 120, 55_000_000), "exfil to cloud storage"


# --------------------------------------------------------------------------- #
# Impact
# --------------------------------------------------------------------------- #
def emit_service_stop(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.file_server, inv.admin_user
    for i, svc in enumerate(["MSSQLSERVER", "VSS", "BackupExecAgent"]):
        yield b.sysmon_process(t0 + i * 2, host, b.domain_user(user), f"{b.system32}\\net.exe", f"net stop {svc} /y", f"{b.system32}\\cmd.exe"), "service stop (pre-encryption)"


def emit_inhibit_recovery(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.file_server, inv.admin_user
    cmds = [("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
            ("bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled no"),
            ("wbadmin.exe", "wbadmin.exe delete catalog -quiet")]
    for i, (tool, cmd) in enumerate(cmds):
        yield b.sysmon_process(t0 + i * 2, host, b.domain_user(user), f"{b.system32}\\{tool}", cmd, f"{b.system32}\\cmd.exe"), "inhibit system recovery"


def emit_encrypt_impact(ctx: EmitContext, t0: float) -> Iterator[Emitted]:
    b, inv = ctx.b, ctx.inv
    host, user = inv.file_server, inv.admin_user
    enc = "C:\\Users\\Public\\enc.exe"
    for i in range(40):
        target = f"\\\\FS-01\\Patients\\record_{i:04d}.dcm.locked"
        yield b.sysmon_file_create(t0 + i * 0.5, host, b.domain_user(user), enc, target), "mass file encryption"


# --------------------------------------------------------------------------- #
# Dispatch table (technique id -> emitter). Sub-techniques fall back to parent.
# --------------------------------------------------------------------------- #
EMITTERS: dict[str, Emitter] = {
    "T1566.001": emit_spearphish,
    "T1204.002": emit_user_execution,
    "T1059.001": emit_powershell,
    "T1569.002": emit_service_execution,
    "T1053.005": emit_scheduled_task,
    "T1543.003": emit_windows_service,
    "T1548.002": emit_bypass_uac,
    "T1134": emit_token_manipulation,
    "T1562.001": emit_impair_defenses,
    "T1070.001": emit_clear_logs,
    "T1003.001": emit_lsass_dump,
    "T1558.003": emit_kerberoast,
    "T1110.003": emit_password_spray,
    "T1087.002": emit_account_discovery,
    "T1018": emit_remote_system_discovery,
    "T1482": emit_domain_trust_discovery,
    "T1021.001": emit_rdp,
    "T1021.002": emit_smb,
    "T1550.002": emit_pass_the_hash,
    "T1078": emit_explicit_creds_lateral,
    "T1570": emit_lateral_tool_transfer,
    "T1560.001": emit_archive_data,
    "T1005": emit_data_local,
    "T1071.001": emit_web_c2,
    "T1105": emit_ingress_tool,
    "T1041": emit_exfil_c2,
    "T1567.002": emit_exfil_cloud,
    "T1489": emit_service_stop,
    "T1490": emit_inhibit_recovery,
    "T1486": emit_encrypt_impact,
    "T1133": emit_external_remote_services,
}


def emitter_for(technique_id: str) -> Emitter | None:
    """Exact match first, then the parent technique (``T1021.001`` -> ``T1021``)."""
    if technique_id in EMITTERS:
        return EMITTERS[technique_id]
    parent = technique_id.split(".")[0]
    for tid, fn in EMITTERS.items():
        if tid.split(".")[0] == parent:
            return fn
    return None


__all__ = ["EmitContext", "EMITTERS", "emitter_for", "PLACEHOLDER", "Emitted", "Emitter"]
