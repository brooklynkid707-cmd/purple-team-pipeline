"""Event builders.

The Splunk lab's ``scripts/generate_logs.py`` already knows how to write
Windows Security, Sysmon, Linux auth, firewall and DNS lines in the exact
shape its ``props.conf`` parses. We import that ``LogGenerator`` (never copy
it), register the hospital hosts on it, and add the handful of Windows event
IDs it does not ship (7045, 4719, 4648, 4776, 4769) using its own ``kv`` /
``iso_z`` / ``Record`` helpers so every line stays in the same wire format.

Every builder returns a Splunk-format ``Record(ts, sourcetype, line)``; the
converters in :mod:`ptp.telemetry.formats` derive the other stacks' formats
from these lines so all three SIEMs see *the same events*.
"""

from __future__ import annotations

from typing import Any

from .. import siblings
from .inventory import Inventory

SYSTEM_CHANNEL_IDS = {7045}


class Builders:
    """Thin facade over the sibling ``LogGenerator`` plus extra event IDs."""

    def __init__(self, start: str, hours: int, seed: int, inventory: Inventory) -> None:
        gen_mod = siblings.splunk_generator()
        self.mod = gen_mod
        self.gen = gen_mod.LogGenerator(seed=seed, start=start, hours=hours)
        self.inv = inventory
        # Register the hospital hosts so ``ws_ip`` and sysmon_network know them.
        # Only the workstation-class hosts join the benign-noise rotation
        # (the generator picks favourite destinations per workstation); the
        # SRV-* machines are reachable via ``ws_ip`` but stay out of ``favorites``
        # so the benign loop (which iterates ``workstations``) never touches them.
        for host, addr in inventory.hosts.items():
            self.gen.workstations[host] = addr
            if host.startswith("WS-") and host not in self.gen.favorites:
                self.gen.favorites[host] = self.gen.rng.sample(self.gen.external_pool, 4)
        # Any server hosts added above must not be iterated by benign(): drop
        # them from the workstation map but keep their address for ws_ip.
        self._extra_ips = dict(inventory.hosts)
        for host in list(self.gen.workstations):
            if host.startswith("SRV-") or host in ("FS-01", "FS-02"):
                self.gen.workstations.pop(host, None)
        self.domain: str = gen_mod.DOMAIN
        self.system32: str = gen_mod.SYSTEM32
        self.ps_exe: str = gen_mod.PS_EXE
        self.office: str = gen_mod.OFFICE
        self.explorer: str = gen_mod.EXPLORER
        self.chrome: str = gen_mod.CHROME
        self.Record = gen_mod.Record

    # -- delegation to the sibling's builders --------------------------------
    def __getattr__(self, name: str) -> Any:
        # win_logon, win_process, win_user_created, win_group_member_added, win_log_cleared,
        # win_task_created, sysmon_process, sysmon_network, sysmon_imageload,
        # sysmon_process_access, sysmon_file_create, sysmon_dns, linux_line, linux_ssh,
        # linux_sudo, firewall, dns, at, pid, guid, sha256, ws_ip, benign ...
        return getattr(self.gen, name)

    def domain_user(self, user: str) -> str:
        return f"{self.domain}\\{user}"

    def ws_ip(self, host: str) -> str:
        """Resolve a host to its address, including the hospital servers."""
        if host in self.gen.workstations:
            return self.gen.workstations[host]
        if host in self._extra_ips:
            return self._extra_ips[host]
        return self.gen.ws_ip(host)

    # -- extra Windows Security event IDs --------------------------------------
    def _win(self, ts: float, **fields: Any) -> Any:
        return self.Record(ts, "lab:windows:security", f"{self.mod.iso_z(ts)} {self.mod.kv(**fields)}")

    def win_service_installed(self, ts: float, host: str, subject: str, service: str, image_path: str,
                              start_type: str = "demand start", service_type: str = "user mode service") -> Any:
        """7045 - a service was installed in the system (System channel)."""
        return self._win(ts, host=host, EventCode=7045, Account_Name=subject, Account_Domain=self.domain,
                         Service_Name=service, Image_Path=image_path, Service_Type=service_type,
                         Start_Type=start_type, Service_Account="LocalSystem")

    def win_audit_policy_changed(self, ts: float, host: str, subject: str,
                                 subcategory_guid: str = "{0CCE922B-69AE-11D9-BED3-505054503030}",
                                 changes: str = "%%8448, %%8450") -> Any:
        """4719 - system audit policy was changed (success/failure auditing removed)."""
        return self._win(ts, host=host, EventCode=4719, Account_Name=subject, Account_Domain=self.domain,
                         Category_Id="%%8274", Subcategory_Guid=subcategory_guid, Audit_Policy_Changes=changes)

    def win_explicit_credentials(self, ts: float, host: str, subject: str, target_user: str,
                                 target_server: str, process: str, src_ip: str) -> Any:
        """4648 - a logon was attempted using explicit credentials (runas / PsExec fan-out)."""
        return self._win(ts, host=host, EventCode=4648, Account_Name=subject, Account_Domain=self.domain,
                         Target_Account_Name=target_user, Target_Domain=self.domain,
                         Target_Server_Name=target_server, Process_Name=process, Source_Network_Address=src_ip)

    def win_ntlm_validation(self, ts: float, dc: str, user: str, workstation: str, status: str) -> Any:
        """4776 - the DC attempted to validate NTLM credentials (spray signature on the DC)."""
        return self._win(ts, host=dc, EventCode=4776, Account_Name=user, Workstation_Name=workstation,
                         Status=status, Package_Name="MICROSOFT_AUTHENTICATION_PACKAGE_V1_0")

    def win_kerberos_tgs(self, ts: float, dc: str, user: str, service: str, src_ip: str,
                         encryption: str = "0x17") -> Any:
        """4769 - a Kerberos service ticket was requested (RC4 = 0x17 is the Kerberoast tell)."""
        return self._win(ts, host=dc, EventCode=4769, Account_Name=f"{user}@{self.domain}.EXAMPLE.COM",
                         Account_Domain=f"{self.domain}.EXAMPLE.COM", Service_Name=service,
                         Ticket_Encryption_Type=encryption, Ticket_Options="0x40810000",
                         Source_Network_Address=src_ip, Status="0x0")

    # -- Sysmon 1 with an integrity level (UAC bypass needs High) ---------------
    def sysmon_process_elevated(self, ts: float, host: str, user: str, image: str, cmdline: str,
                                parent: str, integrity: str = "High") -> Any:
        g = self.gen
        fields = dict(host=host, EventCode=1, UtcTime=self.mod.iso_z(ts), ProcessGuid=g.guid(), ProcessId=g.pid(),
                      Image=image, CommandLine=cmdline, CurrentDirectory="C:\\Windows\\System32\\",
                      User=user, IntegrityLevel=integrity, Hashes=g.sha256(), ParentProcessId=g.pid(),
                      ParentImage=parent, ParentCommandLine=parent)
        return self.Record(ts, "lab:sysmon", f"{self.mod.iso_z(ts)} {self.mod.kv(**fields)}")


__all__ = ["Builders", "SYSTEM_CHANNEL_IDS"]
