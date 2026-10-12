#!/usr/bin/env python3
"""Build a sanitized engagement report from Snake result files."""
from __future__ import annotations

import datetime
import time
from typing import Any, Dict, List, Tuple

from snakefw.core.cracked_store import cracked_password, load_all_cracked
from snakefw.core.radios import assign_roles
from snakefw.core.session_manager import get_session
from snakefw.core.tool_manager import classify_wireless_ifaces
from snakefw.strike.engine import load_last_report

GUIDANCE: Tuple[Tuple[Tuple[str, ...], str, str], ...] = (
    (
        ("wep",),
        "Retire WEP immediately",
        "WEP can be recovered in minutes. Move the SSID to WPA2/WPA3-Personal or Enterprise.",
    ),
    (
        ("wps", "pixie", "reaver"),
        "Disable WPS",
        "Turn off WPS on the AP and use a long random PSK or 802.1X instead of a PIN.",
    ),
    (
        ("wpa", "psk", "handshake", "pmkid"),
        "Replace the WPA-PSK",
        "Treat the recovered passphrase as compromised. Use WPA3-SAE or a 20+ character random PSK, "
        "and isolate guest devices.",
    ),
    (
        ("ms17-010", "eternalblue"),
        "Patch SMB (MS17-010)",
        "Apply Microsoft security updates, disable SMBv1, and restrict 445 from untrusted VLANs.",
    ),
    (
        ("ftp-anon", "anonymous ftp", "anonymous login"),
        "Disable anonymous FTP",
        "Require authenticated FTP or replace it with SFTP/HTTPS file transfer.",
    ),
    (
        ("rdp", "3389"),
        "Lock down Remote Desktop",
        "Require NLA, restrict source networks, and prefer a VPN or jump host.",
    ),
    (
        ("ssh",),
        "Harden SSH",
        "Disable password auth if keys are in use, keep the daemon updated, and rate-limit brute force.",
    ),
    (
        ("http", "cleartext", "basic auth"),
        "Move admin interfaces to TLS",
        "Do not expose HTTP management on the LAN edge. Use HTTPS and unique admin credentials.",
    ),
)


def _secret_fields(entry: Dict[str, Any]) -> Dict[str, Any]:
    row = dict(entry)
    for field in ("key", "psk", "password", "passphrase", "ascii_key", "hex_key", "pin"):
        if row.get(field):
            row[field] = "••••••••"
    row["has_secret"] = True
    return row


def _match_guidance(text: str) -> List[Dict[str, str]]:
    blob = text.lower()
    hits = []
    for keys, title, detail in GUIDANCE:
        if any(key in blob for key in keys):
            hits.append({"title": title, "detail": detail})
    return hits


def _wireless_timeline(jobs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events = []
    for job in jobs:
        events.append({
            "ts": job.get("started_at") or job.get("ended_at") or 0,
            "kind": job.get("attack") or "job",
            "title": f"{job.get('attack') or 'Job'} · {job.get('essid') or job.get('bssid') or ''}",
            "state": job.get("state") or "",
        })
    events.sort(key=lambda item: item.get("ts") or 0)
    return events[-40:]


def _risk_score(cracked: List[Dict[str, Any]], strike: Dict[str, Any]) -> int:
    score = 0
    for row in cracked:
        attack = str(row.get("attack") or row.get("type") or "").upper()
        if "WEP" in attack:
            score = max(score, 92)
        elif "WPS" in attack:
            score = max(score, 84)
        else:
            score = max(score, 72)
    hosts = strike.get("hosts") or []
    if hosts:
        avg = sum(int(h.get("risk_score") or 0) for h in hosts) / max(len(hosts), 1)
        score = max(score, int(avg))
        high = sum(1 for h in hosts if int(h.get("risk_score") or 0) >= 70)
        if high:
            score = min(100, score + 6)
    findings = strike.get("top_findings") or []
    if any(int(f.get("severity") or 0) >= 8 for f in findings):
        score = max(score, 80)
    return min(100, score)


def build_report(*, include_secrets: bool = False) -> Dict[str, Any]:
    session = get_session()
    cracked_raw = load_all_cracked()
    cracked = cracked_raw if include_secrets else [_secret_fields(row) for row in cracked_raw]
    jobs = session.get_job_history()
    strike = load_last_report() or {}
    plan = assign_roles(
        classify_wireless_ifaces(),
        session_monitor=session.monitor_iface,
    )
    hosts = strike.get("hosts") or []
    findings = strike.get("top_findings") or []

    guidance: List[Dict[str, str]] = []
    seen = set()
    corpus = " ".join(
        [
            " ".join(str(row.get("attack") or row.get("type") or "") for row in cracked_raw),
            " ".join(str(f.get("title") or f.get("detail") or "") for f in findings),
        ]
    )
    for item in _match_guidance(corpus):
        if item["title"] not in seen:
            seen.add(item["title"])
            guidance.append(item)
    if cracked_raw and not guidance:
        guidance.append({
            "title": "Rotate recovered credentials",
            "detail": "A wireless key was recovered. Change it and review who still has access.",
        })
    if not guidance:
        guidance.append({
            "title": "Continue the authorized assessment",
            "detail": "No high-confidence findings yet. Re-run Strike after joining the lab LAN.",
        })

    risk = _risk_score(cracked_raw, strike)
    return {
        "generated_at": time.time(),
        "generated_at_label": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "engagement_id": session.id,
        "include_secrets": include_secrets,
        "summary": {
            "risk_score": risk,
            "networks_seen": len(session.networks),
            "jobs": len(jobs),
            "cracked": len(cracked_raw),
            "hosts": len(hosts),
            "findings": len(findings),
            "dual_radio": plan.get("dual_radio"),
        },
        "radios": {
            "scan_iface": plan.get("scan_iface") or "",
            "attack_iface": plan.get("attack_iface") or "",
            "ap_iface": plan.get("ap_iface") or "",
            "client_iface": plan.get("client_iface") or "",
            "radio_count": plan.get("radio_count") or 0,
            "notes": plan.get("notes") or [],
        },
        "cracked": cracked,
        "timeline": _wireless_timeline(jobs),
        "hosts": hosts,
        "findings": findings,
        "recommended": strike.get("recommended"),
        "guidance": guidance,
    }
