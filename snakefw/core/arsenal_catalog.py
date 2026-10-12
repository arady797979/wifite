#!/usr/bin/env python3
"""Curated playbooks, MITM profiles, and apt bundles for Snake Arsenal."""
from __future__ import annotations

from typing import Any, Dict, List

# Bettercap caplet names under /usr/share/bettercap/caplets (Kali: bettercap-caplets)
BETTERCAP_CAPLETS_DIR = "/usr/share/bettercap/caplets"

MITM_PROFILES: Dict[str, Dict[str, str]] = {
    "harvest": {
        "label": "Harvest",
        "hint": "ARP spoof + HTTP proxy + PCAP (default lab profile)",
    },
    "hunt": {
        "label": "Hunt",
        "hint": "Harvest + DNS spoof + net probe (map clients and services)",
    },
    "hijack": {
        "label": "Hijack",
        "hint": "Harvest + SSL strip + bundled hstshijack/jsinject caplets when installed",
    },
}

# Ncrack: map common nmap service names → ncrack service ids
NCRACK_PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    443: "https",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm",
    8080: "http",
    8443: "https",
}

APT_BUNDLES: Dict[str, Dict[str, Any]] = {
    "wifi-core": {
        "label": "WiFi lab core",
        "packages": ["seclists", "mdk4", "hostapd", "dnsmasq", "bettercap-caplets"],
        "hint": "Twin, RF, wordlists, and bettercap caplets",
    },
    "wifi-crack": {
        "label": "WiFi cracking extras",
        "packages": ["hashcat", "hcxdumptool", "hcxtools", "reaver", "bully", "cowpatty"],
        "hint": "PMKID, GPU crack, WPS (reaver + bully)",
    },
    "lan-strike": {
        "label": "LAN strike chain",
        "packages": ["nmap", "ncrack", "metasploit-framework", "arp-scan"],
        "hint": "Strike discover → nmap → ncrack credential spray",
    },
    "social-wifi": {
        "label": "Social WiFi (SE)",
        "packages": ["wifiphisher", "wifipumpkin3", "eaphammer", "bettercap-caplets"],
        "hint": "Pumpkin3, Wifiphisher, EAPHammer, bettercap phishing caplets",
    },
}

PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "id": "snake-twin",
        "category": "wifi",
        "title": "Snake Twin (built-in)",
        "summary": "Fluxion-style rogue AP + captive portal with optional deauth.",
        "tools": ["hostapd", "dnsmasq", "mdk4"],
        "builtin": True,
        "tab": "twin",
    },
    {
        "id": "wifipumpkin3",
        "category": "social",
        "title": "WiFi Pumpkin 3",
        "summary": "Modular rogue AP with phishing plugins, captive portal, and REST control.",
        "tools": ["wifipumpkin3", "hostapd"],
        "command_template": (
            "sudo wifipumpkin3 -i {ap_iface} -s snake_{essid_slug} "
            "--no-colors"
        ),
        "docs": "https://wifipumpkin3.github.io/docs/getting-started",
        "note": "Use Plugins → captive portal / phishing in the TUI, or --rest for API.",
    },
    {
        "id": "wifiphisher",
        "category": "social",
        "title": "Wifiphisher",
        "summary": "Automated evil twin with known phishing scenarios (router login, OAuth lure, etc.).",
        "tools": ["wifiphisher"],
        "command_template": (
            "sudo wifiphisher -e {essid} -aI {ap_iface} -iI {ap_iface} "
            "-p known_beacons"
        ),
        "docs": "https://github.com/wifiphisher/wifiphisher",
        "note": "Replace -p with a scenario from wifiphisher --help. Needs two radios for full deauth+AP.",
    },
    {
        "id": "eaphammer",
        "category": "social",
        "title": "EAPHammer",
        "summary": "WPA2-Enterprise evil twin, credential harvesting, and targeted downgrades.",
        "tools": ["eaphammer"],
        "command_template": (
            "sudo eaphammer --cert-wizard  # once per lab\n"
            "sudo eaphammer -i {ap_iface} --channel {channel} "
            "--essid {essid} --creds"
        ),
        "docs": "https://github.com/s0lst1c3/eaphammer",
        "note": "Enterprise lab only; run cert wizard before first use.",
    },
    {
        "id": "bettercap-fb-phish",
        "category": "lan",
        "title": "Bettercap fb-phish (LAN)",
        "summary": "After MITM on a managed iface, run the fb-phish caplet for social login lure.",
        "tools": ["bettercap"],
        "command_template": (
            "sudo bettercap -iface {lan_iface} -caplet /usr/share/bettercap/caplets/fb-phish.cap"
        ),
        "docs": "https://www.bettercap.org/",
        "note": "Use Snake MITM Hijack profile first, or run caplet standalone on the LAN.",
    },
    {
        "id": "ncrack-strike",
        "category": "lan",
        "title": "Ncrack (from Strike)",
        "summary": "Fast parallel login tries on open SSH/RDP/SMB/VNC/HTTP services found by nmap.",
        "tools": ["ncrack"],
        "builtin": True,
        "tab": "strike",
    },
]
