#!/usr/bin/env python3
"""AP-capable channels, NetworkManager radio claims, and hostapd diagnostics."""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

NM_UNMANAGED_CONF = Path("/etc/NetworkManager/conf.d/99-snake-unmanaged.conf")

FREQ_RE = re.compile(
    r"\*\s+([\d.]+)\s+MHz\s+\[(\d+)\]\s+\(([^)]*)\)(?:\s+\(([^)]*)\))?"
)
COUNTRY_RE = re.compile(r"^country\s+([A-Z0-9]{2}):", re.MULTILINE)
PHY_BLOCK_RE = re.compile(
    r"phy#(\d+)[^\n]*\n(.*?)(?=\nphy#|\Z)",
    re.DOTALL,
)

PREFERRED_24 = (6, 1, 11, 3, 9, 7, 2, 4, 8, 5, 10, 13, 12)
PREFERRED_5 = (36, 40, 44, 48, 149, 153, 157, 161, 165)

CHANNEL_FAIL_MARKERS = (
    "not allowed for ap mode",
    "primary frequency not allowed",
    "hardware does not support configured channel",
    "could not select hw_mode and channel",
    "no ir",
    "configured channel",
)

AP_MODE_FAIL_MARKERS = (
    "could not configure driver mode",
    "interface initialization failed",
    "nl80211: could not configure driver mode",
)


def _run(cmd: list, timeout: int = 8) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def hw_mode_for(channel: int) -> str:
    return "a" if int(channel or 0) > 14 else "g"


def parse_iw_phy(text: str) -> Dict[str, Any]:
    """Parse `iw phy` / `iw phy phyN info` into AP capability and channels."""
    supports_ap = bool(re.search(r"^\s+\*\s+AP\s*$", text or "", re.MULTILINE))
    channels: List[Dict[str, Any]] = []
    seen = set()
    for match in FREQ_RE.finditer(text or ""):
        channel = int(match.group(2))
        power = (match.group(3) or "").strip().lower()
        flags = (match.group(4) or "").strip().lower()
        blob = f"{power} {flags}"
        disabled = "disabled" in blob
        no_ir = "no ir" in blob or "no-ir" in blob
        radar = "radar" in blob
        if channel in seen and not disabled:
            continue
        seen.add(channel)
        channels.append({
            "channel": channel,
            "freq": float(match.group(1)),
            "band": "5" if channel > 14 else "24",
            "disabled": disabled,
            "no_ir": no_ir,
            "radar": radar,
            "ap_ok": (not disabled) and (not no_ir),
        })
    return {
        "supports_ap": supports_ap or bool(channels),
        "channels": channels,
        "ap_24": [row["channel"] for row in channels if row["ap_ok"] and row["channel"] <= 14],
        "ap_5": [row["channel"] for row in channels if row["ap_ok"] and row["channel"] > 14],
    }


def parse_reg_domain(text: str, phy: str = "") -> str:
    """Prefer the phy's self-managed country over the global world domain."""
    raw = text or ""
    phy_num = ""
    if phy:
        phy_num = re.sub(r"^phy", "", phy)
    if phy_num:
        for match in PHY_BLOCK_RE.finditer(raw):
            if match.group(1) == phy_num:
                found = COUNTRY_RE.search(match.group(2))
                if found:
                    return found.group(1).upper()
    found = COUNTRY_RE.search(raw)
    return found.group(1).upper() if found else ""


def _channel_row(radio: Dict[str, Any], channel: int) -> Optional[Dict[str, Any]]:
    for row in radio.get("channels") or []:
        if row.get("channel") == channel:
            return row
    return None


def _ordered(candidates: List[int], preferred: tuple) -> List[int]:
    rank = {ch: idx for idx, ch in enumerate(preferred)}
    return sorted(dict.fromkeys(candidates), key=lambda ch: (rank.get(ch, 1000), ch))


def choose_ap_channel(requested: int, radio: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a hostapd channel this radio is actually allowed to transmit on."""
    requested = int(requested or 0)
    channels = list(radio.get("channels") or [])
    ap_24 = list(radio.get("ap_24") or [])
    ap_5 = list(radio.get("ap_5") or [])
    if not channels:
        channel = requested or 6
        return {
            "channel": channel,
            "requested": requested,
            "hw_mode": hw_mode_for(channel),
            "fallbacks": [6, 1, 11, 149, 36] if not requested else [6, 1, 11],
            "ap_24": ap_24,
            "ap_5": ap_5,
            "supports_ap": True,
            "matched": bool(requested and channel == requested),
            "note": "Could not read this radio's AP channel list; using the target channel and 2.4GHz fallbacks",
            "country": radio.get("country") or "",
            "reason": "unprobed",
        }
    pool = ap_24 + ap_5
    row = _channel_row(radio, requested) if requested else None
    note = ""
    channel = 0
    fallbacks: List[int] = []

    if requested and row and row.get("ap_ok"):
        channel = requested
        note = f"AP on target channel {requested}"
        fallbacks = _ordered([c for c in pool if c != requested], PREFERRED_24 + PREFERRED_5)
    elif requested > 14:
        same = _ordered(ap_5, PREFERRED_5)
        if same:
            channel = same[0]
            why = "NO-IR / DFS" if row and (row.get("no_ir") or row.get("radar")) else "not AP-capable"
            note = (
                f"Target ch{requested} is {why} for AP mode. "
                f"Using 5GHz ch{channel} (TX-ok: {', '.join(str(c) for c in same[:6])})"
            )
            fallbacks = same[1:] + _ordered(ap_24, PREFERRED_24)
        elif ap_24:
            channel = _ordered(ap_24, PREFERRED_24)[0]
            note = (
                f"Target ch{requested} cannot be used for AP (NO-IR/DFS) and this radio "
                f"has no TX-ok 5GHz AP channel. Falling back to 2.4GHz ch{channel}"
            )
            fallbacks = _ordered(ap_24, PREFERRED_24)[1:]
        else:
            note = (
                f"No AP-capable channels on this radio (requested ch{requested}). "
                "Use a USB adapter that supports AP/master mode"
            )
    elif requested >= 1:
        two_g = _ordered(ap_24, PREFERRED_24)
        if two_g:
            channel = two_g[0] if requested not in two_g else requested
            if requested not in two_g:
                note = f"Target ch{requested} is not AP-capable here. Using 2.4GHz ch{channel}"
            else:
                channel = requested
                note = f"AP on target channel {requested}"
            fallbacks = [c for c in two_g if c != channel] + _ordered(ap_5, PREFERRED_5)
        elif ap_5:
            channel = _ordered(ap_5, PREFERRED_5)[0]
            note = f"2.4GHz AP is unavailable; using 5GHz ch{channel}"
            fallbacks = _ordered(ap_5, PREFERRED_5)[1:]
        else:
            note = "No AP-capable channels on this radio"
    else:
        ordered = _ordered(ap_24, PREFERRED_24) + _ordered(ap_5, PREFERRED_5)
        if ordered:
            channel = ordered[0]
            note = f"No target channel; using AP-capable ch{channel}"
            fallbacks = ordered[1:]
        else:
            note = "No AP-capable channels on this radio"

    if not radio.get("supports_ap") and not pool:
        note = "This adapter does not advertise AP mode. Plug in a USB Wi-Fi adapter with AP support"

    return {
        "channel": channel,
        "requested": requested,
        "hw_mode": hw_mode_for(channel or requested or 6),
        "fallbacks": fallbacks[:6],
        "ap_24": ap_24,
        "ap_5": ap_5,
        "supports_ap": bool(radio.get("supports_ap") or pool),
        "matched": bool(channel and requested and channel == requested),
        "note": note,
        "country": radio.get("country") or "",
        "reason": "" if channel else "no-ap-channel",
    }


def hostapd_channel_failed(text: str) -> bool:
    blob = (text or "").lower()
    return any(marker in blob for marker in CHANNEL_FAIL_MARKERS)


def hostapd_ap_mode_failed(text: str) -> bool:
    blob = (text or "").lower()
    return any(marker in blob for marker in AP_MODE_FAIL_MARKERS)


def explain_hostapd_failure(text: str, channel: int, plan: Optional[Dict[str, Any]] = None) -> str:
    plan = plan or {}
    blob = (text or "").lower()
    ap_24 = plan.get("ap_24") or []
    ap_5 = plan.get("ap_5") or []
    if hostapd_channel_failed(text):
        extra = ""
        if ap_24 or ap_5:
            extra = (
                f" TX-ok channels: 2.4GHz {ap_24 or 'none'}, 5GHz {ap_5 or 'none'}."
            )
        return (
            f"hostapd cannot transmit on channel {channel} "
            f"(NO-IR/regulatory or missing AP channel).{extra} "
            "Snake will try a TX-ok fallback automatically."
        )
    if hostapd_ap_mode_failed(text) or "unable to setup interface" in blob:
        return (
            f"hostapd could not put the adapter in AP mode on ch{channel}. "
            "NetworkManager may still own the radio, or this NIC cannot AP. "
            "Use a USB adapter with AP support if fallbacks fail."
        )
    trimmed = " ".join((text or "").strip().split())
    if trimmed:
        return f"hostapd failed: {trimmed[:240]}"
    return "hostapd failed to start — check adapter AP support"


def get_interface_phy(iface: str) -> str:
    if not iface:
        return ""
    try:
        link = Path(f"/sys/class/net/{iface}/phy80211").resolve()
        return link.name
    except OSError:
        pass
    info = _run(["iw", "dev", iface, "info"])
    match = re.search(r"wiphy\s+(\d+)", info.stdout or "")
    return f"phy{match.group(1)}" if match else ""


def probe_ap_radio(iface: str) -> Dict[str, Any]:
    """Live snapshot of AP capability for an interface (any mode)."""
    phy = get_interface_phy(iface)
    phy_text = ""
    if phy:
        phy_text = _run(["iw", "phy", phy, "info"], timeout=6).stdout or ""
    if not phy_text:
        phy_text = _run(["iw", "phy"], timeout=8).stdout or ""
    radio = parse_iw_phy(phy_text)
    radio["phy"] = phy
    radio["iface"] = iface
    radio["country"] = parse_reg_domain(_run(["iw", "reg", "get"]).stdout or "", phy)
    radio["driver"] = _iface_driver(iface)
    return radio


def _iface_driver(iface: str) -> str:
    try:
        link = Path(f"/sys/class/net/{iface}/device/driver").resolve()
        return link.name
    except OSError:
        return ""


def plan_ap_channel(iface: str, requested: int) -> Dict[str, Any]:
    radio = probe_ap_radio(iface)
    plan = choose_ap_channel(requested, radio)
    plan["phy"] = radio.get("phy") or ""
    plan["driver"] = radio.get("driver") or ""
    plan["country"] = radio.get("country") or ""
    if plan.get("driver") == "iwlwifi" and requested > 14 and not plan.get("matched"):
        extra = (
            "Intel iwlwifi often blocks UNII-1 (36–48) AP with NO-IR; "
            "UNII-3 (149–161) or 2.4GHz usually works."
        )
        plan["note"] = f"{plan.get('note', '').rstrip('. ')}. {extra}"
    return plan


def nm_service_active() -> bool:
    if not shutil.which("nmcli") and not shutil.which("systemctl"):
        return False
    result = _run(["systemctl", "is-active", "NetworkManager"])
    return (result.stdout or "").strip() == "active"


def nm_device_unmanaged(iface: str) -> bool:
    if not iface or not shutil.which("nmcli"):
        return not nm_service_active()
    show = _run(["nmcli", "-t", "-f", "GENERAL.STATE", "device", "show", iface])
    text = f"{show.stdout or ''} {show.stderr or ''}".lower()
    if "unmanaged" in text:
        return True
    if "not found" in text or "no such device" in text:
        return not nm_service_active()
    return not nm_service_active()


def _read_unmanaged_ifaces(path: Path) -> List[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return re.findall(r"interface-name:([^,\s]+)", text)


def persist_unmanaged(iface: str, path: Optional[Path] = None) -> bool:
    if not iface:
        return False
    conf = path or NM_UNMANAGED_CONF
    try:
        conf.parent.mkdir(parents=True, exist_ok=True)
        names = _read_unmanaged_ifaces(conf)
        if iface not in names:
            names.append(iface)
        body = "[keyfile]\nunmanaged-devices=" + ",".join(
            f"interface-name:{name}" for name in names
        ) + "\n"
        conf.write_text(body, encoding="utf-8")
        return True
    except OSError:
        return False


def drop_unmanaged(iface: str, path: Optional[Path] = None) -> bool:
    conf = path or NM_UNMANAGED_CONF
    try:
        names = [name for name in _read_unmanaged_ifaces(conf) if name != iface]
        if not names:
            if conf.exists():
                conf.unlink()
            return True
        body = "[keyfile]\nunmanaged-devices=" + ",".join(
            f"interface-name:{name}" for name in names
        ) + "\n"
        conf.write_text(body, encoding="utf-8")
        return True
    except OSError:
        return False


def _reload_networkmanager() -> None:
    if shutil.which("nmcli"):
        _run(["nmcli", "general", "reload"])
        return
    _run(["systemctl", "reload", "NetworkManager"])


def quiet_networkmanager_on(iface: str, log: Optional[Callable] = None) -> dict:
    """Keep NetworkManager off one Wi-Fi radio without killing Ethernet/LAN."""
    state = {
        "iface": iface,
        "nm_unmanaged": False,
        "nm_conf": False,
        "nm_was_active": nm_service_active(),
    }

    def _note(msg: str):
        if log:
            log(msg)

    if not iface:
        return state

    _run(["rfkill", "unblock", "wifi"])
    state["nm_conf"] = persist_unmanaged(iface)
    if state["nm_conf"]:
        _reload_networkmanager()
        time.sleep(0.3)

    if not shutil.which("nmcli"):
        state["nm_unmanaged"] = True
        _note(f"[radio] nmcli not installed — {iface} is free of NetworkManager")
        return state

    if not nm_service_active():
        state["nm_unmanaged"] = True
        _note(f"[radio] NetworkManager is not running — {iface} is free for hostapd")
        return state

    last_err = ""
    for attempt in range(6):
        disc = _run(["nmcli", "device", "disconnect", iface])
        _run(["nmcli", "device", "set", iface, "autoconnect", "no"])
        result = _run(["nmcli", "device", "set", iface, "managed", "no"])
        if result.returncode != 0:
            last_err = (result.stderr or result.stdout or "").strip()
        if nm_device_unmanaged(iface) or result.returncode == 0:
            state["nm_unmanaged"] = True
            _note(f"[radio] NetworkManager released {iface}")
            break
        if "not found" in f"{disc.stderr or ''} {result.stderr or ''}".lower() and attempt < 5:
            time.sleep(0.45)
            continue
        time.sleep(0.35)

    if not state["nm_unmanaged"]:
        _reload_networkmanager()
        time.sleep(0.4)
        _run(["nmcli", "device", "set", iface, "managed", "no"])
        state["nm_unmanaged"] = nm_device_unmanaged(iface)
        if state["nm_unmanaged"]:
            _note(f"[radio] NetworkManager released {iface} after reload")
        else:
            detail = f" ({last_err})" if last_err else ""
            _note(
                f"[radio] could not unmanage {iface}{detail}. "
                "Wrote NM conf.d drop-in; hostapd may still flap if NM grabs the radio"
            )

    _run(["iw", "dev", iface, "disconnect"])
    if shutil.which("wpa_cli"):
        _run(["wpa_cli", "-i", iface, "terminate"])
    _run(["iw", "dev", iface, "set", "power_save", "off"])
    _run(["iwconfig", iface, "power", "off"])
    return state


def restore_networkmanager_on(state: Optional[dict], log: Optional[Callable] = None) -> None:
    if not state:
        return
    iface = state.get("iface") or ""
    if iface:
        drop_unmanaged(iface)
        _reload_networkmanager()
    if iface and state.get("nm_was_active") and shutil.which("nmcli"):
        _run(["nmcli", "device", "set", iface, "autoconnect", "yes"])
        _run(["nmcli", "device", "set", iface, "managed", "yes"])
        if log:
            log(f"[radio] NetworkManager may manage {iface} again")
