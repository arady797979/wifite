#!/usr/bin/env python3
"""
HTTP tool functions for Snake Gemini Agent.
Each public function is exposed to the model via google-genai tool calling.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

import requests

from snakefw.core.agent_bridge import bridge_ready, invoke as bridge_invoke

_DEFAULT_BASE = "http://127.0.0.1:5000"
_TIMEOUT = 120
_http_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="snake-agent-http")


def _use_bridge() -> bool:
    if os.environ.get("SNAKE_AGENT_HTTP", "").lower() in ("1", "true", "yes"):
        return False
    return bridge_ready()


def _base_url() -> str:
    return (os.environ.get("SNAKE_AGENT_BASE") or _DEFAULT_BASE).rstrip("/")


def _http_get(path: str, timeout: int) -> Dict[str, Any]:
    resp = requests.get(f"{_base_url()}{path}", timeout=timeout)
    if resp.content:
        return resp.json()
    return {"ok": False, "error": "empty response", "status_code": resp.status_code}


def _http_post(path: str, payload: Optional[dict], timeout: int) -> Dict[str, Any]:
    resp = requests.post(f"{_base_url()}{path}", json=payload or {}, timeout=timeout)
    if resp.content:
        data = resp.json()
        if isinstance(data, dict):
            data.setdefault("http_status", resp.status_code)
        return data
    return {"ok": False, "error": "empty response", "status_code": resp.status_code}


def _get(path: str, timeout: int = 30) -> Dict[str, Any]:
    if _use_bridge():
        return bridge_invoke("GET", path, timeout=timeout)
    try:
        future = _http_pool.submit(_http_get, path, timeout)
        return future.result(timeout=timeout + 5)
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _post(path: str, payload: Optional[dict] = None, timeout: int = _TIMEOUT) -> Dict[str, Any]:
    if _use_bridge():
        return bridge_invoke("POST", path, payload, timeout=timeout)
    try:
        future = _http_pool.submit(_http_post, path, payload, timeout)
        return future.result(timeout=timeout + 5)
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def get_system_status() -> Dict[str, Any]:
    """Return live session snapshot: state, interface, monitor_iface, networks count, jobs, stats, tools map."""
    status = _get("/api/status")
    health = _get("/api/health")
    return {"status": status, "health": health}


def get_health_preflight() -> Dict[str, Any]:
    """Run readiness check: Python packages, required/optional tools, wordlist tiers, interfaces."""
    return _get("/api/health")


def list_networks() -> Dict[str, Any]:
    """Return all networks from the last scan (ESSID, BSSID, channel, encryption, attack_vector, clients)."""
    return _get("/api/networks")


def list_interfaces() -> Dict[str, Any]:
    """List wireless interfaces and each mode (managed/monitor/unknown)."""
    return _get("/api/interfaces")


def get_radio_plan() -> Dict[str, Any]:
    """Return multi-radio assignment: scan_iface, attack_iface, AP/client roles."""
    return _get("/api/radios")


def get_tool_readiness() -> Dict[str, Any]:
    """Detailed tool catalog with install hints (aircrack, hashcat, bettercap, ncrack, etc.)."""
    return _get("/api/tools")


def list_jobs() -> Dict[str, Any]:
    """List active and recent attack jobs with state, progress, keys, capture paths."""
    return _get("/api/jobs")


def list_cracked_results() -> Dict[str, Any]:
    """Return cracked WPA/WPS keys stored in cracked.json."""
    return _get("/api/cracked")


def get_wordlist_catalog() -> Dict[str, Any]:
    """Return Fast/Smart/Deep wordlist tiers, counts, and active tier."""
    return _get("/api/wordlists")


def select_interface(interface_name: str) -> Dict[str, Any]:
    """Select the primary wireless interface in Snake (does not change mode)."""
    return _post("/api/interface/select", {"interface": interface_name})


def enable_monitor_mode(interface_name: str = "") -> Dict[str, Any]:
    """Enable monitor mode on the given interface (or session default). Requires root."""
    payload = {}
    if interface_name:
        payload["interface"] = interface_name
    return _post("/api/interface/monitor", payload)


def enable_managed_mode(interface_name: str = "") -> Dict[str, Any]:
    """Switch interface back to managed mode (stop using monitor for scans)."""
    payload = {}
    if interface_name:
        payload["interface"] = interface_name
    return _post("/api/interface/managed", payload)


def start_scan(duration_seconds: int = 30, band: str = "bg", channel: int = 0) -> Dict[str, Any]:
    """
    Start airodump scan on the scan radio. band: a, bg, or abg. duration_seconds: 0 = until stop_scan.
    """
    return _post("/api/scan/start", {
        "duration": max(0, min(int(duration_seconds), 600)),
        "band": band if band in ("a", "bg", "abg") else "bg",
        "channel": max(0, min(int(channel or 0), 196)),
    })


def stop_scan() -> Dict[str, Any]:
    """Stop the active WiFi scan."""
    return _post("/api/scan/stop", {})


def plan_attack(
    bssid: str = "",
    essid: str = "",
    attack_type: str = "WPA_HANDSHAKE",
    channel: int = 0,
    network_index: int = -1,
    wordlist_tier: str = "",
) -> Dict[str, Any]:
    """
    Dry-run an attack: validates target and returns required tools without starting a job.
    attack_type: WPA_HANDSHAKE, WPA_PMKID, WPS_PIXIE, WPS_BRUTEFORCE, WEP.
    """
    payload: Dict[str, Any] = {
        "dry_run": True,
        "attack": attack_type,
        "authorized": False,
    }
    if bssid:
        payload["bssid"] = bssid
    if essid:
        payload["essid"] = essid
    if channel > 0:
        payload["channel"] = channel
    if network_index >= 0:
        payload["network_index"] = network_index
    if wordlist_tier:
        payload["wordlist_tier"] = wordlist_tier
    return _post("/api/attack", payload)


def start_attack(
    bssid: str = "",
    essid: str = "",
    attack_type: str = "WPA_HANDSHAKE",
    channel: int = 0,
    network_index: int = -1,
    wordlist_tier: str = "",
    user_authorized: bool = False,
) -> Dict[str, Any]:
    """
    Start a capture/crack job. Set user_authorized=True only after the user confirmed lab authorization.
    attack_type: WPA_HANDSHAKE, WPA_PMKID, WPS_PIXIE, WPS_BRUTEFORCE, WEP.
    """
    if not user_authorized:
        return {
            "ok": False,
            "error": "user_authorized must be True after explicit user consent for this target",
        }
    payload: Dict[str, Any] = {
        "attack": attack_type,
        "authorized": True,
    }
    if bssid:
        payload["bssid"] = bssid
    if essid:
        payload["essid"] = essid
    if channel > 0:
        payload["channel"] = channel
    if network_index >= 0:
        payload["network_index"] = network_index
    if wordlist_tier:
        payload["wordlist_tier"] = wordlist_tier
    return _post("/api/attack", payload)


def start_auto_attack(bssids: List[str], user_authorized: bool = False) -> Dict[str, Any]:
    """Queue up to 5 auto attacks for scanned BSSIDs (uses each network attack_vector)."""
    if not user_authorized:
        return {"ok": False, "error": "user_authorized must be True after explicit user consent"}
    return _post("/api/attack/auto", {"authorized": True, "bssids": list(bssids or [])})


def kill_job(job_id: str) -> Dict[str, Any]:
    """Stop a running or queued job by job ID."""
    return _post(f"/api/job/{job_id}/kill", {})


def select_wordlist_tier(tier: str) -> Dict[str, Any]:
    """Set active crack tier: fast, smart, or deep."""
    return _post("/api/wordlists/select", {"tier": tier})


def rebuild_wordlists() -> Dict[str, Any]:
    """Rebuild Fast/Smart/Deep lists from SecLists (background thread)."""
    return _post("/api/wordlists/build", {})


def get_twin_status() -> Dict[str, Any]:
    """Evil Twin session status, clients, captured portal passwords."""
    return _get("/api/twin/status")


def start_twin(
    essid: str,
    bssid: str = "",
    channel: int = 6,
    stealth_deauth: bool = False,
    user_authorized: bool = False,
) -> Dict[str, Any]:
    """Launch Evil Twin captive portal for essid. Requires hostapd/dnsmasq and root."""
    if not user_authorized:
        return {"ok": False, "error": "user_authorized must be True after explicit user consent"}
    return _post("/api/twin/start", {
        "authorized": True,
        "essid": essid,
        "bssid": bssid,
        "channel": channel,
        "stealth": stealth_deauth,
    })


def stop_twin() -> Dict[str, Any]:
    """Stop Evil Twin AP, portal, and deauth."""
    return _post("/api/twin/stop", {})


def get_rf_status() -> Dict[str, Any]:
    """RF Tools status (deauth/beacon/auth presets)."""
    return _get("/api/rf/status")


def start_rf_attack(
    mode: str,
    bssid: str = "",
    essid: str = "",
    channel: int = 0,
    client_mac: str = "",
    stealth: bool = False,
    user_authorized: bool = False,
) -> Dict[str, Any]:
    """
    Start RF preset on monitor iface. mode: deauth, beacon, or auth. bssid required for deauth/auth.
    """
    if not user_authorized:
        return {"ok": False, "error": "user_authorized must be True after explicit user consent"}
    payload: Dict[str, Any] = {
        "authorized": True,
        "mode": mode,
        "bssid": bssid,
        "essid": essid,
        "channel": channel,
        "stealth": stealth,
    }
    if client_mac:
        payload["client"] = client_mac
    return _post("/api/rf/start", payload)


def stop_rf() -> Dict[str, Any]:
    """Stop active RF job."""
    return _post("/api/rf/stop", {})


def get_mitm_status() -> Dict[str, Any]:
    """MITM sessions and default iface/gateway hints."""
    return _get("/api/mitm/status")


def mitm_discover_hosts(interface: str = "", gateway: str = "") -> Dict[str, Any]:
    """ARP/scan discovery of LAN hosts for MITM target selection (managed interface)."""
    return _post("/api/mitm/discover", {"iface": interface, "gateway": gateway})


def start_mitm(
    interface: str,
    gateway: str,
    target_ips: List[str],
    mitm_profile: str = "harvest",
    user_authorized: bool = False,
) -> Dict[str, Any]:
    """
    Start LAN MITM on managed iface. mitm_profile: harvest, hunt, or hijack.
    target_ips: list of victim IPv4 addresses from discovery.
    """
    if not user_authorized:
        return {"ok": False, "error": "user_authorized must be True after explicit user consent"}
    return _post("/api/mitm/start", {
        "authorized": True,
        "iface": interface,
        "gateway": gateway,
        "targets": target_ips,
        "mitm_profile": mitm_profile,
        "use_bettercap": True,
    })


def stop_mitm() -> Dict[str, Any]:
    """Stop all MITM sessions."""
    return _post("/api/mitm/stop", {})


def get_strike_status() -> Dict[str, Any]:
    """Strike LAN chain status, presets, last report summary."""
    return _get("/api/strike/status")


def start_strike(
    preset: str = "discover",
    user_authorized: bool = False,
) -> Dict[str, Any]:
    """
    Run Strike LAN recon. preset: discover, quick, smart, or deep.
    discover = live hosts only; smart = recommended nmap + NetExec.
    """
    if not user_authorized:
        return {"ok": False, "error": "user_authorized must be True after explicit user consent"}
    return _post("/api/strike/start", {"authorized": True, "preset": preset})


def stop_strike() -> Dict[str, Any]:
    """Stop active Strike chain."""
    return _post("/api/strike/stop", {})


def run_ncrack_on_lan(user_authorized: bool = False) -> Dict[str, Any]:
    """Run ncrack against hosts/ports from Strike results (parallel login audit)."""
    if not user_authorized:
        return {"ok": False, "error": "user_authorized must be True after explicit user consent"}
    return _post("/api/strike/ncrack", {"authorized": True})


def get_pivot_status() -> Dict[str, Any]:
    """Air-to-LAN pivot status (join after crack)."""
    return _get("/api/pivot/status")


def start_pivot(
    essid: str,
    psk: str,
    bssid: str = "",
    launch_strike: bool = True,
    user_authorized: bool = False,
) -> Dict[str, Any]:
    """Join cracked WPA network with wpa_supplicant; optionally start Strike on that iface."""
    if not user_authorized:
        return {"ok": False, "error": "user_authorized must be True after explicit user consent"}
    return _post("/api/pivot/start", {
        "authorized": True,
        "essid": essid,
        "psk": psk,
        "bssid": bssid,
        "launch_strike": launch_strike,
    })


def get_arsenal_catalog() -> Dict[str, Any]:
    """Social playbooks (Pumpkin3, Wifiphisher), apt bundles, MITM profile docs."""
    return _get("/api/arsenal/catalog")


def prepare_arsenal_command(
    playbook_id: str,
    essid: str = "",
    bssid: str = "",
    channel: int = 6,
) -> Dict[str, Any]:
    """
    Build shell command for external SE tool. playbook_id: wifipumpkin3, wifiphisher, eaphammer, etc.
    """
    return _post("/api/arsenal/command", {
        "playbook": playbook_id,
        "essid": essid,
        "bssid": bssid,
        "channel": channel,
    })


# Order matters for documentation only; Gemini receives all callables.
SNAKE_AGENT_TOOLS = [
    get_system_status,
    get_health_preflight,
    list_networks,
    list_interfaces,
    get_radio_plan,
    get_tool_readiness,
    list_jobs,
    list_cracked_results,
    get_wordlist_catalog,
    select_interface,
    enable_monitor_mode,
    enable_managed_mode,
    start_scan,
    stop_scan,
    plan_attack,
    start_attack,
    start_auto_attack,
    kill_job,
    select_wordlist_tier,
    rebuild_wordlists,
    get_twin_status,
    start_twin,
    stop_twin,
    get_rf_status,
    start_rf_attack,
    stop_rf,
    get_mitm_status,
    mitm_discover_hosts,
    start_mitm,
    stop_mitm,
    get_strike_status,
    start_strike,
    stop_strike,
    run_ncrack_on_lan,
    get_pivot_status,
    start_pivot,
    get_arsenal_catalog,
    prepare_arsenal_command,
]
