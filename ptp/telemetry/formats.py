"""Render one set of events into the on-disk formats each detection stack ingests.

The emitters produce Splunk-lab ``Record`` objects (ISO-timestamped key=value
or pipe lines). This module is the single place that knows how those lines map
to the other stacks' wire formats, so every SIEM scores *the same events*:

* Splunk lab  - the lines verbatim, one file per sourcetype (what the harness
  and its ``props.conf`` parse).
* minisiem    - Windows Security JSON, Sysmon JSON, auth.log, iptables firewall
  and Zeek conn JSON (what its parsers auto-detect).
* Sentinel    - ``SecurityEvent`` rows (what ``simulate.py`` runs KQL over).

A Splunk ``Record`` is parsed back into its fields once; each converter reads
those fields. Events that a stack has no schema for (e.g. a Sentinel-only table)
are simply not emitted for that stack - that asymmetry is exactly what the
scoreboard measures as per-stack coverage.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

_KV_RE = re.compile(r'(\w+)=("([^"\\]*(?:\\.[^"\\]*)*)"|\S+)')


def _epoch(iso_z: str) -> float:
    return datetime.strptime(iso_z, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


@dataclass
class ParsedRecord:
    """A Splunk ``Record`` decomposed into timestamp, sourcetype and fields."""

    ts: float
    sourcetype: str
    line: str
    fields: dict[str, str]

    @classmethod
    def from_record(cls, rec: Any) -> "ParsedRecord":
        line = rec.line
        sourcetype = rec.sourcetype
        if sourcetype in ("lab:windows:security", "lab:sysmon"):
            # "<iso> key=value key=value ..."
            iso, _, rest = line.partition(" ")
            fields = {m.group(1): _unquote(m.group(2)) for m in _KV_RE.finditer(rest)}
            return cls(_epoch(iso), sourcetype, line, fields)
        if sourcetype == "lab:firewall":
            parts = line.split("|")
            keys = ["_iso", "fw", "action", "direction", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "bytes_in", "bytes_out"]
            fields = dict(zip(keys, parts))
            return cls(_epoch(parts[0]), sourcetype, line, fields)
        # auth.log and dns keep their raw line; timestamp comes from the Record.
        return cls(float(rec.ts), sourcetype, line, {})


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"')
    return value


def _iso_z(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


# --------------------------------------------------------------------------- #
# minisiem converters (ECS-ish JSON / auth.log / iptables / Zeek)
# --------------------------------------------------------------------------- #
_PRIVATE = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")


def to_minisiem(rec: ParsedRecord) -> tuple[str, str] | None:
    """Return ``(filename, line)`` for minisiem, or ``None`` if not representable."""
    st = rec.sourcetype
    if st == "lab:windows:security":
        return "windows_security.jsonl", _win_json(rec)
    if st == "lab:sysmon":
        return "sysmon.jsonl", _sysmon_json(rec)
    if st == "lab:firewall":
        return "firewall.log", _iptables(rec)
    if st == "lab:linux:auth":
        return "auth.log", rec.line               # already auth.log shape
    return None


# Windows event IDs minisiem's windows parser understands.
_MINISIEM_WIN_IDS = {4624, 4625, 4688, 4720, 4732, 1102, 7045}


def _win_json(rec: ParsedRecord) -> str | None:
    f = rec.fields
    eid = int(f.get("EventCode", 0))
    channel = "System" if eid == 7045 else "Security"
    data: dict[str, Any] = {}
    if eid in (4624, 4625):
        data = {
            "TargetUserName": f.get("Account_Name"),
            "TargetDomainName": f.get("Account_Domain"),
            "LogonType": f.get("Logon_Type"),
            "IpAddress": f.get("Source_Network_Address", "-"),
            "IpPort": "-",
            "LogonProcessName": f.get("Logon_Process"),
            "Status": f.get("Status"),
            "SubStatus": f.get("Sub_Status"),
        }
    elif eid == 4688:
        data = {
            "SubjectUserName": f.get("Account_Name"),
            "SubjectDomainName": f.get("Account_Domain"),
            "NewProcessName": f.get("New_Process_Name"),
            "NewProcessId": f.get("New_Process_ID"),
            "CommandLine": f.get("Process_Command_Line"),
            "ParentProcessName": f.get("Creator_Process_Name"),
        }
    elif eid == 4720:
        data = {"SubjectUserName": f.get("Subject_Account_Name"), "TargetUserName": f.get("Target_Account_Name"),
                "TargetDomainName": f.get("Target_Domain")}
    elif eid == 4732:
        data = {"SubjectUserName": f.get("Subject_Account_Name"), "MemberName": f.get("Member_Name"),
                "TargetUserName": f.get("Group_Name")}
    elif eid == 1102:
        data = {"SubjectUserName": f.get("Account_Name")}
    elif eid == 7045:
        data = {"SubjectUserName": f.get("Account_Name"), "ServiceName": f.get("Service_Name"),
                "ImagePath": f.get("Image_Path"), "ServiceType": f.get("Service_Type"),
                "StartType": f.get("Start_Type")}
    else:
        return None  # 4698/4719/4648/4776/4769 have no minisiem windows mapping
    obj = {
        "TimeCreated": _iso_z(rec.ts),
        "EventID": eid,
        "Channel": channel,
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Computer": f.get("host"),
        "EventData": {k: v for k, v in data.items() if v is not None},
    }
    return json.dumps(obj)


# Sysmon event IDs minisiem's sysmon parser understands (1,3,11,22). Others
# (7 image load, 10 process access) are Splunk/Sysmon-only here.
def _sysmon_json(rec: ParsedRecord) -> str | None:
    f = rec.fields
    eid = int(f.get("EventCode", 0))
    data: dict[str, Any] = {"User": f.get("User")}
    if eid == 1:
        data.update({
            "Image": f.get("Image"), "CommandLine": f.get("CommandLine"),
            "ParentImage": f.get("ParentImage"), "ParentCommandLine": f.get("ParentCommandLine"),
            "ProcessId": f.get("ProcessId"), "ProcessGuid": f.get("ProcessGuid"),
            "IntegrityLevel": f.get("IntegrityLevel"), "Hashes": f.get("Hashes"),
            "OriginalFileName": _basename(f.get("Image")),
        })
    elif eid == 3:
        data.update({
            "Image": f.get("Image"), "SourceIp": f.get("SourceIp"), "SourcePort": f.get("SourcePort"),
            "DestinationIp": f.get("DestinationIp"), "DestinationPort": f.get("DestinationPort"),
            "DestinationHostname": f.get("DestinationHostname"), "Protocol": f.get("Protocol", "tcp"),
            "Initiated": f.get("Initiated", "true"),
        })
    elif eid == 11:
        data.update({"Image": f.get("Image"), "TargetFilename": f.get("TargetFilename")})
    elif eid == 22:
        data.update({"Image": f.get("Image"), "QueryName": f.get("QueryName"),
                     "QueryStatus": f.get("QueryStatus", "0"), "QueryResults": f.get("QueryResults")})
    else:
        return None  # EventID 7, 10 -> no minisiem sysmon mapping
    obj = {
        "TimeCreated": _iso_z(rec.ts),
        "EventID": eid,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": f.get("host"),
        "EventData": {k: v for k, v in data.items() if v is not None},
    }
    return json.dumps(obj)


def _iptables(rec: ParsedRecord) -> str:
    """Splunk pipe-delimited firewall line -> iptables kernel log (minisiem firewall parser)."""
    f = rec.fields
    direction_in = f.get("direction") == "inbound"
    prefix = "FW-ACCEPT" if f.get("action") == "allow" else "FW-DROP"
    iface = "IN=eth0 OUT=" if direction_in else "IN= OUT=eth0"
    proto = f.get("proto", "tcp").upper()
    iso = datetime.fromtimestamp(rec.ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return (f"{iso} fw01 kernel: [{prefix}] {iface} MAC=00:11:22:33:44:55 "
            f"SRC={f.get('src_ip')} DST={f.get('dest_ip')} LEN=60 TOS=0x00 PREC=0x00 TTL=54 ID=1 DF "
            f"PROTO={proto} SPT={f.get('src_port')} DPT={f.get('dest_port')} WINDOW=65535 RES=0x00 SYN URGP=0")


def firewall_to_zeek(rec: ParsedRecord) -> str | None:
    """A beacon/exfil firewall allow -> a Zeek conn record (feeds minisiem's beaconing rule)."""
    f = rec.fields
    if f.get("action") != "allow":
        return None
    src = f.get("src_ip", "")
    private = src.startswith(_PRIVATE)
    obj = {
        "ts": rec.ts,
        "uid": f"C{int(rec.ts * 1000) % 10**10}",
        "id.orig_h": src, "id.orig_p": int(f.get("src_port", 0) or 0),
        "id.resp_h": f.get("dest_ip"), "id.resp_p": int(f.get("dest_port", 0) or 0),
        "proto": f.get("proto", "tcp"),
        "service": "ssl" if f.get("dest_port") == "443" else "http",
        "duration": 0.5,
        "orig_bytes": int(f.get("bytes_out", 0) or 0), "resp_bytes": int(f.get("bytes_in", 0) or 0),
        "conn_state": "SF",
        "sensor": "zeek01",
    }
    return json.dumps(obj) if private else None


# --------------------------------------------------------------------------- #
# Sentinel converter (SecurityEvent rows). Sentinel only ingests Windows here.
# --------------------------------------------------------------------------- #
def to_sentinel(rec: ParsedRecord) -> dict[str, Any] | None:
    """Return a ``SecurityEvent`` row for ``simulate.py`` (or ``None``)."""
    if rec.sourcetype != "lab:windows:security":
        return None
    f = rec.fields
    eid = int(f.get("EventCode", 0))
    base = {
        "TimeGenerated": _iso_z(rec.ts),
        "Computer": f.get("host"),
        "EventID": eid,
        "Channel": "Security",
        "EventSourceName": "Microsoft-Windows-Security-Auditing",
        "AccountType": "User",
    }
    if eid in (4624, 4625):
        base.update({
            "Activity": f"{eid} - An account {'was successfully logged on' if eid == 4624 else 'failed to log on'}.",
            "TargetUserName": f.get("Account_Name"), "TargetDomainName": f.get("Account_Domain"),
            "LogonType": int(f.get("Logon_Type", 0) or 0),
            "IpAddress": f.get("Source_Network_Address", "-"),
            "Status": f.get("Status", "0x0"), "SubStatus": f.get("Sub_Status", "0x0"),
            "WorkstationName": f.get("Workstation_Name"),
            "LogonProcessName": f.get("Logon_Process"),
        })
    elif eid == 4688:
        base.update({
            "Activity": "4688 - A new process has been created.",
            "SubjectUserName": f.get("Account_Name"), "SubjectDomainName": f.get("Account_Domain"),
            "Process": _basename(f.get("New_Process_Name")),
            "NewProcessName": f.get("New_Process_Name"), "NewProcessId": f.get("New_Process_ID"),
            "CommandLine": f.get("Process_Command_Line"),
            "ParentProcessName": f.get("Creator_Process_Name"),
            "TokenElevationType": f.get("Token_Elevation_Type", "%%1938"),
        })
    elif eid == 4720:
        base.update({
            "Activity": "4720 - A user account was created.",
            "SubjectUserName": f.get("Subject_Account_Name"), "SubjectDomainName": f.get("Subject_Domain"),
            "TargetUserName": f.get("Target_Account_Name"), "TargetDomainName": f.get("Target_Domain"),
            "TargetSid": "S-1-5-21-1004336348-1177238915-682003330-1180",
        })
    elif eid == 4732:
        base.update({
            "Activity": "4732 - A member was added to a security-enabled local group.",
            "TargetUserName": f.get("Group_Name"), "TargetDomainName": f.get("Group_Domain", "Builtin"),
            "MemberName": f.get("Member_Name"), "MemberSid": "S-1-5-21-1004336348-1177238915-682003330-1180",
            "SubjectUserName": f.get("Subject_Account_Name"), "SubjectDomainName": f.get("Subject_Domain"),
        })
    elif eid == 1102:
        base.update({
            "Activity": "1102 - The audit log was cleared.",
            "SubjectUserName": f.get("Account_Name"), "SubjectDomainName": f.get("Account_Domain"),
            "SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-1105",
        })
    elif eid == 4698:
        base.update({
            "Activity": "4698 - A scheduled task was created.",
            "SubjectUserName": f.get("Account_Name"), "SubjectDomainName": f.get("Account_Domain"),
            "TaskName": f.get("Task_Name"),
            "TaskContent": (f"<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions>"
                            f"<Exec><Command>{f.get('Task_Command', '')}</Command>"
                            f"<Arguments>-run</Arguments></Exec></Actions></Task>"),
        })
    elif eid == 4719:
        base.update({
            "Activity": "4719 - System audit policy was changed.",
            "SubjectUserName": f.get("Account_Name"), "SubjectDomainName": f.get("Account_Domain"),
            "CategoryId": f.get("Category_Id"), "SubcategoryGuid": f.get("Subcategory_Guid"),
            "AuditPolicyChanges": f.get("Audit_Policy_Changes"),
        })
    elif eid == 4648:
        base.update({
            "Activity": "4648 - A logon was attempted using explicit credentials.",
            "SubjectUserName": f.get("Account_Name"), "SubjectDomainName": f.get("Account_Domain"),
            "TargetUserName": f.get("Target_Account_Name"), "TargetServerName": f.get("Target_Server_Name"),
            "ProcessName": f.get("Process_Name"), "IpAddress": f.get("Source_Network_Address"),
        })
    elif eid == 4776:
        base.update({
            "Activity": "4776 - The computer attempted to validate the credentials for an account.",
            "TargetUserName": f.get("Account_Name"), "Workstation": f.get("Workstation_Name"),
            "Status": f.get("Status", "0x0"), "PackageName": f.get("Package_Name"),
        })
    elif eid == 4769:
        base.update({
            "Activity": "4769 - A Kerberos service ticket was requested.",
            "TargetUserName": f.get("Account_Name"), "ServiceName": f.get("Service_Name"),
            "TicketEncryptionType": f.get("Ticket_Encryption_Type"), "IpAddress": f.get("Source_Network_Address"),
            "Status": f.get("Status", "0x0"),
        })
    else:
        return None
    return {k: v for k, v in base.items() if v is not None}


__all__ = ["ParsedRecord", "to_minisiem", "to_sentinel", "firewall_to_zeek"]
