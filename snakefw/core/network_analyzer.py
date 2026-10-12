#!/usr/bin/env python3
"""
Snake Framework - Smart Network Analyzer
Classifies networks as EASY, SUSPICIOUS, HARD, or WPS_TARGET
"""
import subprocess
import re
import json
import os
import time
from dataclasses import dataclass, asdict, field
from typing import List, Optional
from enum import Enum


class ThreatLevel(str, Enum):
    EASY       = "EASY"        # Open/WEP/WPS-enabled, low client count
    MEDIUM     = "MEDIUM"      # WPA2 with handshakes accessible
    HARD       = "HARD"        # WPA3, enterprise, hidden
    SUSPICIOUS = "SUSPICIOUS"  # Honeypot/deauth trap indicators
    WPS_TARGET = "WPS_TARGET"  # WPS locked but pixie-dustable


@dataclass
class NetworkProfile:
    bssid: str
    essid: str
    channel: int
    signal: int          # dBm
    encryption: str      # WEP / WPA / WPA2 / WPA3 / OPN
    cipher: str
    auth: str
    wps: bool
    wps_locked: bool
    clients: int
    beacons: int
    data_packets: int
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    attack_vector: str = ""
    confidence: int = 0   # 0-100
    flags: List[str] = field(default_factory=list)
    client_macs: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self):
        d = asdict(self)
        d['threat_level'] = self.threat_level.value
        return d


class NetworkAnalyzer:
    """
    Scores and classifies WiFi networks for penetration testing.
    Uses heuristics including signal strength, encryption type,
    WPS status, client count, beacon intervals, and hidden SSID detection.
    """

    # Known honeypot SSIDs
    HONEYPOT_PATTERNS = [
        r"^Free[-_\s]?WiFi$", r"^Open[-_\s]?Network$",
        r"^HoneyPot", r"^Canary", r"^trap",
        r"^xfinitywifi$", r"attwifi", r"linksys",
    ]

    # WPS-vulnerable router models (pixie-dust candidates)
    WPS_VULNERABLE_OUI = {
        "C0:4A:00", "00:26:B9", "00:1E:2A", "00:14:BF",
        "00:22:6B", "D0:27:88", "00:0F:66", "18:A6:F7",
        "E4:F4:C6", "70:3A:CB", "C8:BE:19", "14:35:8B",
    }
    ATTACK_TYPES = {
        "OPEN": "NONE",
        "WEP": "WEP",
        "WPS": "WPS_PIXIE",
        "WPA_CLIENT": "WPA_HANDSHAKE",
        "WPA_NO_CLIENT": "WPA_PMKID",
    }

    def analyze(self, raw: dict) -> NetworkProfile:
        """Analyze a raw network dict and return a scored NetworkProfile."""
        profile = NetworkProfile(
            bssid       = raw.get("bssid", "00:00:00:00:00:00").upper(),
            essid       = raw.get("essid", "<hidden>"),
            channel     = int(raw.get("channel", 6)),
            signal      = int(raw.get("signal", -80)),
            encryption  = raw.get("encryption", "WPA2"),
            cipher      = raw.get("cipher", "CCMP"),
            auth        = raw.get("auth", "PSK"),
            wps         = bool(raw.get("wps", False)),
            wps_locked  = bool(raw.get("wps_locked", False)),
            clients     = int(raw.get("clients", 0)),
            client_macs = [str(mac).upper() for mac in raw.get("client_macs", []) if mac],
            beacons     = int(raw.get("beacons", 0)),
            data_packets= int(raw.get("data_packets", 0)),
        )
        self._score(profile)
        return profile

    def _score(self, p: NetworkProfile):
        score = 50  # base
        flags = []

        # ── Encryption scoring ──────────────────────────────────────────────
        enc = p.encryption.upper()
        if "OPN" in enc or enc == "":
            score += 40
            flags.append("OPEN_NETWORK")
            p.attack_vector = self.ATTACK_TYPES["OPEN"]
        elif "WEP" in enc:
            score += 35
            flags.append("WEP")
            p.attack_vector = self.ATTACK_TYPES["WEP"]
        elif "WPA3" in enc:
            score -= 30; flags.append("WPA3")
        elif "WPA2" in enc:
            pass  # neutral
        elif "WPA" in enc:
            score += 5

        # ── WPS scoring ─────────────────────────────────────────────────────
        if p.wps and not p.wps_locked:
            score += 25
            flags.append("WPS_ENABLED")
            p.attack_vector = self.ATTACK_TYPES["WPS"]
        elif p.wps and p.wps_locked:
            oui = ":".join(p.bssid.split(":")[:3])
            if oui in self.WPS_VULNERABLE_OUI:
                score += 15; flags.append("WPS_LOCKED_VULNERABLE")
                p.attack_vector = self.ATTACK_TYPES["WPS"]
            else:
                score -= 5; flags.append("WPS_LOCKED")
                p.threat_level = ThreatLevel.WPS_TARGET

        # ── Signal quality ──────────────────────────────────────────────────
        if p.signal >= -50:
            score += 15; flags.append("STRONG_SIGNAL")
        elif p.signal >= -65:
            score += 8
        elif p.signal <= -80:
            score -= 10; flags.append("WEAK_SIGNAL")

        # ── Client activity (handshake opportunity) ─────────────────────────
        if p.clients > 0:
            score += min(p.clients * 5, 20); flags.append(f"{p.clients}_CLIENTS")
        if p.data_packets > 500:
            score += 10; flags.append("HIGH_TRAFFIC")

        # ── Hidden SSID (suspicious) ────────────────────────────────────────
        if p.essid in ("<hidden>", "", "\x00"):
            score -= 15; flags.append("HIDDEN_SSID")

        # ── Honeypot detection ──────────────────────────────────────────────
        for pattern in self.HONEYPOT_PATTERNS:
            if re.search(pattern, p.essid, re.IGNORECASE):
                score -= 20
                flags.append("HONEYPOT_SUSPECTED")
                p.threat_level = ThreatLevel.SUSPICIOUS
                break

        # ── Enterprise auth (avoid) ─────────────────────────────────────────
        if "MGT" in p.auth.upper() or "EAP" in p.auth.upper():
            score -= 25; flags.append("ENTERPRISE"); p.threat_level = ThreatLevel.HARD

        # ── Final classification ────────────────────────────────────────────
        p.confidence = max(0, min(100, score))
        p.flags = flags

        if p.threat_level not in (ThreatLevel.SUSPICIOUS, ThreatLevel.HARD, ThreatLevel.WPS_TARGET):
            if p.confidence >= 70:
                p.threat_level = ThreatLevel.EASY
            elif p.confidence >= 45:
                p.threat_level = ThreatLevel.MEDIUM
            else:
                p.threat_level = ThreatLevel.HARD

        # Pick best attack if not already set
        if not p.attack_vector:
            if p.clients > 0:
                p.attack_vector = self.ATTACK_TYPES["WPA_CLIENT"]
            elif p.wps:
                p.attack_vector = self.ATTACK_TYPES["WPS"]
            else:
                p.attack_vector = self.ATTACK_TYPES["WPA_NO_CLIENT"]

    def rank_networks(self, networks: List[NetworkProfile]) -> List[NetworkProfile]:
        """Sort networks by crackability (highest confidence first)."""
        priority = {
            ThreatLevel.EASY:       0,
            ThreatLevel.WPS_TARGET: 1,
            ThreatLevel.MEDIUM:     2,
            ThreatLevel.HARD:       3,
            ThreatLevel.SUSPICIOUS: 4,
        }
        return sorted(
            networks,
            key=lambda n: (priority.get(n.threat_level, 99), -n.confidence, n.signal)
        )
