"""Synthetic hospital inventory used by the attack emitters.

Everything is fabricated: RFC 1918 addresses internally, RFC 5737
documentation ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) for
"internet" addresses and ``example.*`` domains. The benign background comes
from the Splunk lab's 60-workstation corporate inventory; these hosts are
added on top so the attack path reads like a hospital network.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Inventory:
    """Named entities the emitters use. Keep it small and recognisable in reports."""

    # Clinical workstations and servers added to the generator's workstation map.
    hosts: dict[str, str] = field(default_factory=lambda: {
        "WS-RAD-03": "10.20.5.53",       # radiology workstation - patient zero
        "WS-ER-07": "10.20.5.57",        # emergency department
        "WS-PHARM-02": "10.20.5.62",     # pharmacy
        "WS-ADMIN-11": "10.20.6.61",     # billing office
        "WS-NURSE-04": "10.20.5.64",     # nursing station
        "SRV-PACS-01": "10.10.0.60",     # imaging archive
        "SRV-EHR-DB-01": "10.10.0.61",   # EHR database
        "SRV-EHR-APP-01": "10.10.0.62",  # EHR application tier
    })
    victim_user: str = "nrivera"           # radiology technologist who opens the attachment
    victim_host: str = "WS-RAD-03"
    admin_user: str = "adm-hwalker"        # domain admin whose hash is stolen
    service_user: str = "svc_backup"       # service account found by the spray
    new_account: str = "svc_pacsmon"       # attacker-created persistence account
    dc: str = "DC-01"
    file_server: str = "FS-01"
    backup_server: str = "SRV-BACKUP-01"
    vpn_server: str = "SRV-VPN-01"
    linux_app_server: str = "srv-app-01"

    # External addresses (all RFC 5737 documentation ranges).
    attacker_ip: str = "198.51.100.77"     # spray / VPN source
    c2_ip: str = "203.0.113.66"            # on both the Splunk and minisiem threat-intel feeds
    c2_exfil_ip: str = "198.51.100.251"    # on both feeds (exfil category) - kept off the beacon pair
    c2_domain: str = "evil-updates.example.net"   # on the minisiem TI feed
    stage_domain: str = "cdn-sync.example.org"    # on the minisiem TI feed
    exfil_cloud_ip: str = "203.0.113.37"
    exfil_cloud_domain: str = "files.example-share.net"

    # Users that the spray step walks through (synthetic hospital directory).
    spray_users: tuple[str, ...] = (
        "nrivera", "jpatel", "mchen", "lokafor", "dgarcia", "akim", "tbrown", "sreed", "pwilson",
        "hwalker", "ecruz", "rlee", "bnguyen", "kyoung", "mscott", "lhall", "jbaker", "cadams",
        "svc_backup", "svc_pacs", "svc_sql", "svc_print", "radiology01", "pharmacy02", "er-charge",
        "nurse-stn4", "billing07", "helpdesk1", "itadmin2", "ctscanner",
    )

    # Lateral-movement targets.
    rdp_targets: tuple[str, ...] = ("SRV-PACS-01", "SRV-EHR-APP-01", "FS-01", "SRV-BACKUP-01", "SRV-EHR-DB-01")
    smb_targets: tuple[str, ...] = ("WS-ER-07", "WS-PHARM-02", "WS-ADMIN-11", "WS-NURSE-04", "SRV-PACS-01",
                                    "SRV-EHR-APP-01", "SRV-EHR-DB-01", "FS-01", "FS-02", "SRV-BACKUP-01",
                                    "SRV-PRINT-01", "DC-02")
    sweep_targets: tuple[str, ...] = tuple(f"10.20.5.{n}" for n in range(50, 66))

    def ip(self, host: str) -> str:
        return self.hosts[host]


DEFAULT_INVENTORY = Inventory()

__all__ = ["Inventory", "DEFAULT_INVENTORY"]
