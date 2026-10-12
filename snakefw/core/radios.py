#!/usr/bin/env python3
"""Assign scan / attack / AP / client roles across wireless phys."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence


def _phy_of(name: str, classified: Dict[str, Any]) -> str:
    for item in classified.get("interfaces") or []:
        if item.get("name") == name:
            return str(item.get("phy") or "")
    return ""


def same_phy(left: str, right: str, classified: Dict[str, Any]) -> bool:
    """True when two interface names share a physical radio."""
    if not left or not right:
        return False
    if left == right:
        return True
    phy_left = _phy_of(left, classified)
    phy_right = _phy_of(right, classified)
    return bool(phy_left and phy_right and phy_left == phy_right)


def split_managed(
    managed: Sequence[str],
    monitor: Sequence[str],
    classified: Dict[str, Any],
) -> tuple[List[str], List[str]]:
    """Leftover managed parents share a phy with a monitor vif (airmon-ng)."""
    real: List[str] = []
    leftover: List[str] = []
    for name in managed:
        sibling = any(
            mon != name and same_phy(name, mon, classified) for mon in monitor
        )
        if sibling:
            leftover.append(name)
        else:
            real.append(name)
    return real, leftover


def unique_phys(classified: Dict[str, Any]) -> List[str]:
    seen: List[str] = []
    for item in classified.get("interfaces") or []:
        phy = str(item.get("phy") or "")
        if phy and phy not in seen:
            seen.append(phy)
    return seen


def conflicts_with_scanner(
    iface: str,
    scanner_iface: str,
    classified: Dict[str, Any],
) -> bool:
    """Scan only blocks another job when it occupies the same physical radio."""
    if not iface or not scanner_iface:
        return False
    return same_phy(iface, scanner_iface, classified)


def _first(names: Iterable[str], predicate) -> str:
    for name in names:
        if name and predicate(name):
            return name
    return ""


def assign_roles(
    classified: Dict[str, Any],
    *,
    preferred_ap: str = "",
    preferred_deauth: str = "",
    preferred_scan: str = "",
    preferred_client: str = "",
    session_monitor: str = "",
) -> Dict[str, Any]:
    """Pick interface roles from a classify_wireless_ifaces() snapshot.

    Twin-compatible keys (ap_iface, deauth_iface, verify_iface, single_radio)
    stay stable. Scan/attack/client are extra roles for dual-radio labs.
    """
    managed = list(classified.get("managed") or [])
    monitor = list(classified.get("monitor") or [])
    real_managed, leftover_managed = split_managed(managed, monitor, classified)

    ap_iface = (preferred_ap or "").strip()
    deauth_iface = (preferred_deauth or "").strip()
    if not ap_iface:
        if real_managed:
            ap_iface = real_managed[0]
        elif session_monitor in monitor:
            ap_iface = session_monitor
        elif monitor:
            ap_iface = monitor[0]
        elif leftover_managed:
            ap_iface = leftover_managed[0]
    if not deauth_iface:
        preferred = session_monitor if session_monitor in monitor else ""
        candidates = [preferred] + monitor if preferred else list(monitor)
        deauth_iface = _first(
            candidates,
            lambda name: name != ap_iface and not same_phy(name, ap_iface, classified),
        )
    if ap_iface and deauth_iface and same_phy(ap_iface, deauth_iface, classified):
        deauth_iface = _first(
            monitor,
            lambda name: name != ap_iface and not same_phy(name, ap_iface, classified),
        )

    verify_iface = _first(
        real_managed,
        lambda name: name not in {ap_iface, deauth_iface},
    )
    client_iface = (preferred_client or "").strip() or verify_iface
    if not client_iface:
        client_iface = _first(
            real_managed,
            lambda name: name != ap_iface,
        )

    scan_iface = (preferred_scan or "").strip()
    if scan_iface not in monitor:
        scan_iface = ""
    if not scan_iface and session_monitor in monitor:
        scan_iface = session_monitor
    if not scan_iface:
        if deauth_iface:
            scan_iface = _first(monitor, lambda name: name != deauth_iface) or deauth_iface
        elif monitor:
            scan_iface = monitor[0]

    attack_iface = (preferred_deauth or "").strip()
    if deauth_iface:
        attack_iface = deauth_iface
    elif attack_iface not in monitor:
        attack_iface = ""
    if not attack_iface:
        attack_iface = _first(
            monitor,
            lambda name: name != scan_iface and not same_phy(name, scan_iface, classified),
        ) or scan_iface

    ap_mode = ""
    for item in classified.get("interfaces") or []:
        if item.get("name") == ap_iface:
            ap_mode = str(item.get("mode") or "")
            break
    will_switch = bool(ap_iface and (ap_mode == "monitor" or ap_iface in leftover_managed))

    ap_choices: List[str] = []
    for name in real_managed + leftover_managed + monitor:
        if name and name not in ap_choices:
            ap_choices.append(name)

    phys = unique_phys(classified)
    notes: List[str] = []
    if len(phys) >= 2:
        notes.append(
            f"{len(phys)} radios: scan on {scan_iface or '—'}, "
            f"attack on {attack_iface or '—'}"
        )
    else:
        notes.append("Single radio: scan and capture share the same adapter")
    if client_iface:
        notes.append(f"Client / pivot interface: {client_iface}")
    elif ap_iface:
        notes.append("No spare managed radio for pivot — stop Twin first or add a USB adapter")

    return {
        "ap_iface": ap_iface,
        "deauth_iface": deauth_iface,
        "verify_iface": verify_iface,
        "managed": real_managed,
        "leftover_managed": leftover_managed,
        "monitor": monitor,
        "ap_choices": ap_choices,
        "interfaces": classified.get("interfaces") or [],
        "single_radio": bool(ap_iface and not deauth_iface),
        "will_switch_to_managed": will_switch,
        "scan_iface": scan_iface,
        "attack_iface": attack_iface,
        "client_iface": client_iface,
        "dual_radio": len(phys) >= 2,
        "radio_count": len(phys),
        "notes": notes,
    }
