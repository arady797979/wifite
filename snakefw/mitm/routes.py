#!/usr/bin/env python3
"""
Snake MITM — Flask/SocketIO API routes
Plugged into the main Snake server as a Blueprint.
"""
import os
import re
import json
import time
import threading
import subprocess
import ipaddress
from pathlib import Path
from typing import Optional
from flask import Blueprint, request, jsonify, render_template

from snakefw.core.tool_manager import get_interface_mode, set_managed_mode
from snakefw.eviltwin.engine import twin_busy_ifaces
from snakefw.mitm.engine import MITMSession, discover_hosts, gateway_subnet

MITM_DIR = Path(__file__).resolve().parent
BASE_DIR = MITM_DIR.parent.parent

# Active MITM sessions keyed by session_id
_sessions: dict = {}
_session_lock = threading.Lock()
_discover_lock = threading.Lock()
_discover_running = False

# Will be set by register_socketio()
_socketio = None
_snake_log_cb = None


def register_socketio(sio, log_cb=None):
    global _socketio, _snake_log_cb
    _socketio    = sio
    _snake_log_cb = log_cb


def emit_mitm(event: str, data: dict):
    if _socketio:
        _socketio.emit(f"mitm_{event}", data)


def log(msg: str, level: str = "INFO"):
    if _snake_log_cb:
        _snake_log_cb(msg, level)
    emit_mitm("log", {"ts": time.time(), "level": level, "msg": msg})


mitm_bp = Blueprint("mitm", __name__)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _get_default_gateway(iface: str = "") -> str:
    try:
        cmd = ["ip", "route", "show", "default"]
        if iface:
            cmd += ["dev", iface]
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r'default via (\S+)', result.stdout)
        if m:
            return m.group(1)
        if not iface:
            return ""
        result = subprocess.run(
            ["ip", "route", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)/\d+", line)
            if m:
                parts = m.group(1).split(".")
                return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    except Exception:
        return ""
    return ""


def _get_route_iface() -> str:
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"dev (\S+)", result.stdout)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _get_iface_ipv4(iface: str) -> str:
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _list_lan_ifaces() -> list:
    """Up interfaces that can carry MITM (managed Wi-Fi or Ethernet), Twin radio excluded."""
    busy = twin_busy_ifaces()
    skip = {"lo", "docker0", "virbr0"}
    found = []
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    for line in (result.stdout or "").splitlines():
        match = re.match(r"\d+:\s+([^:@]+)", line)
        if not match:
            continue
        name = match.group(1).strip()
        if name in skip or name in busy or name.startswith("veth"):
            continue
        mode = get_interface_mode(name)
        if mode == "monitor":
            continue
        ipv4 = _get_iface_ipv4(name)
        found.append({
            "name": name,
            "mode": mode if mode != "unknown" else "ethernet",
            "ipv4": ipv4,
            "gateway": _get_default_gateway(name),
        })
    found.sort(key=lambda item: (not bool(item["ipv4"]), not bool(item["gateway"]), item["name"]))
    return found


def _resolve_mitm_iface(requested: str = "") -> str:
    """Prefer a managed/Ethernet iface with IPv4; never pick Twin's AP radio."""
    requested = (requested or "").strip()
    busy = twin_busy_ifaces()
    if requested and requested not in busy and get_interface_mode(requested) != "monitor":
        if _get_iface_ipv4(requested):
            return requested
    route_iface = _get_route_iface()
    if route_iface and route_iface not in busy and get_interface_mode(route_iface) != "monitor":
        if _get_iface_ipv4(route_iface):
            return route_iface
    for item in _list_lan_ifaces():
        if item.get("ipv4"):
            return item["name"]
    if requested and requested not in busy:
        return requested
    return _get_managed_iface()


def _prepare_mitm_iface(requested: str) -> tuple:
    """Restore managed mode when needed and pick a LAN-ready interface."""
    notes = []
    iface = (requested or "").strip()
    busy = twin_busy_ifaces()
    if iface and iface in busy:
        notes.append(f"{iface} is the Twin AP radio — MITM will use another LAN interface")
        iface = ""
    if iface and get_interface_mode(iface) == "monitor":
        log(f"[MITM] {iface} is monitor — restoring managed so it can join the LAN")
        try:
            iface = set_managed_mode(iface, callback=log)
            notes.append(f"Restored {iface} to managed mode")
        except RuntimeError as exc:
            notes.append(str(exc))
            iface = ""
    resolved = _resolve_mitm_iface(iface)
    if not resolved:
        notes.append("No LAN interface found. Connect Ethernet or join Wi-Fi in managed mode")
        return "", notes
    ipv4 = _get_iface_ipv4(resolved)
    gateway = _get_default_gateway(resolved) or _get_default_gateway()
    if get_interface_mode(resolved) == "monitor":
        notes.append(f"{resolved} is still in monitor mode. Switch to managed, then reconnect to the LAN")
    elif not ipv4:
        notes.append(
            f"{resolved} has no IPv4. Connect it to the lab LAN (or plug in Ethernet) then Discover again"
        )
    elif not gateway:
        notes.append(f"{resolved} has {ipv4} but no default gateway. Enter the gateway IP manually")
    else:
        notes.append(f"MITM ready on {resolved} ({ipv4}) via {gateway}")
    return resolved, notes


def _mitm_readiness(iface: str, gateway: str, notes: Optional[list] = None) -> dict:
    mode = get_interface_mode(iface) if iface else "unknown"
    ipv4 = _get_iface_ipv4(iface) if iface else ""
    subnet = gateway_subnet(gateway) if gateway else ""
    lan = _list_lan_ifaces()
    return {
        "iface": iface,
        "mode": mode,
        "ipv4": ipv4,
        "gateway": gateway,
        "subnet": subnet,
        "ready": bool(
            iface
            and gateway
            and mode != "monitor"
            and ipv4
            and subnet
        ),
        "monitor_warning": mode == "monitor",
        "notes": notes or [],
        "lan_ifaces": lan,
        "twin_busy": sorted(twin_busy_ifaces()),
    }


def _get_managed_iface() -> str:
    """Return first managed-mode interface that Twin is not using."""
    busy = twin_busy_ifaces()
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if "Interface" in line:
                iface = line.split()[-1]
                if iface in busy:
                    continue
                mode_out = subprocess.run(
                    ["iwconfig", iface], capture_output=True, text=True, timeout=3
                ).stdout
                if "Managed" in mode_out or "ESSID" in mode_out:
                    return iface
    except Exception:
        pass
    # Fallback to ethernet / any interface
    try:
        result = subprocess.run(["ip", "link", "show", "up"],
                                capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            m = re.match(r'\d+:\s+(\w+):', line)
            if m and m.group(1) not in ("lo", "docker0") and m.group(1) not in busy:
                return m.group(1)
    except Exception:
        pass
    return "eth0"


# ── REST Routes ───────────────────────────────────────────────────────────────
@mitm_bp.route("/api/mitm/status")
def mitm_status():
    with _session_lock:
        active = {k: v.get_snapshot() for k, v in _sessions.items()}
    iface, notes = _prepare_mitm_iface("")
    gw = _get_default_gateway(iface) or _get_default_gateway()
    readiness = _mitm_readiness(iface, gw, notes)
    return jsonify({
        "ok":       True,
        "sessions": active,
        "gateway":  gw,
        "iface":    iface,
        "ip_fwd":   _check_ip_forward(),
        "readiness": readiness,
    })


@mitm_bp.route("/api/mitm/discover", methods=["POST"])
def mitm_discover():
    global _discover_running
    data = request.json or {}
    iface, notes = _prepare_mitm_iface(data.get("iface") or "")
    gateway = (data.get("gateway") or "").strip() or _get_default_gateway(iface)

    if not iface:
        return jsonify({"ok": False, "error": "No LAN interface detected", "notes": notes}), 400
    if get_interface_mode(iface) == "monitor":
        return jsonify({
            "ok": False,
            "error": (
                f"{iface} is still in monitor mode after restore. "
                "Use Managed Mode, reconnect to the lab LAN, then Discover."
            ),
            "notes": notes,
        }), 400
    if not gateway:
        return jsonify({
            "ok": False,
            "error": "No gateway IP. Connect to the target LAN or enter gateway manually.",
            "notes": notes,
        }), 400
    if not _get_iface_ipv4(iface):
        return jsonify({
            "ok": False,
            "error": (
                f"{iface} has no IPv4 address. Join the Wi‑Fi/Ethernet network first, "
                "then run Discover again."
            ),
            "notes": notes,
        }), 400

    with _discover_lock:
        if _discover_running:
            return jsonify({"ok": False, "error": "Discovery already running"}), 429
        _discover_running = True

    def _run():
        global _discover_running
        try:
            hosts = discover_hosts(
                iface, gateway, timeout=15, callback=lambda m: log(m)
            )
            emit_mitm("hosts", {"hosts": [h.to_dict() for h in hosts]})
            log(f"[+] Discovery done: {len(hosts)} hosts found", "SUCCESS")
        finally:
            with _discover_lock:
                _discover_running = False

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({
        "ok": True,
        "msg": "Discovery started...",
        "iface": iface,
        "gateway": gateway,
        "subnet": gateway_subnet(gateway),
    })


@mitm_bp.route("/api/mitm/start", methods=["POST"])
def mitm_start():
    data    = request.json or {}
    iface, notes = _prepare_mitm_iface(data.get("iface") or "")
    gateway = (data.get("gateway") or "").strip() or _get_default_gateway(iface)
    if get_interface_mode(iface) == "monitor":
        return jsonify({
            "ok": False,
            "error": f"{iface} is in monitor mode; Snake could not restore managed mode for MITM",
            "notes": notes,
        }), 400
    targets = data.get("targets", [])   # list of IPs
    dns_spoof  = bool(data.get("dns_spoof", False))
    sslstrip   = bool(data.get("sslstrip", False))
    use_bc     = bool(data.get("use_bettercap", True))
    mitm_profile = str(data.get("mitm_profile") or "harvest").lower()

    if data.get("authorized") is not True:
        return jsonify({"ok": False, "error": "Confirm authorization first"}), 400
    if not iface:
        return jsonify({"ok": False, "error": "No interface available"}), 400
    if not gateway:
        return jsonify({"ok": False, "error": "No gateway detected"}), 400
    if not targets:
        return jsonify({"ok": False, "error": "Select at least one target"}), 400
    try:
        ipaddress.ip_address(gateway)
        targets = [str(ipaddress.ip_address(target)) for target in targets[:32]]
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid gateway or target IP"}), 400

    def _on_packet(pkt_dict):
        emit_mitm("packet", pkt_dict)
        # Highlight credentials immediately
        if pkt_dict.get("credential"):
            emit_mitm("cred", pkt_dict)
            log(f"[💥] CREDENTIAL: {pkt_dict['credential'].get('username','?')} / "
                f"{pkt_dict['credential'].get('password','?')} @ {pkt_dict.get('host','?')}",
                "CRED")

    def _on_log(msg):
        log(msg)

    session = MITMSession(
        iface=iface, gateway=gateway, targets=targets,
        on_packet=_on_packet, on_log=_on_log,
        dns_spoof=dns_spoof, sslstrip=sslstrip,
        use_bettercap=use_bc,
        mitm_profile=mitm_profile,
    )

    def _run():
        session.start()

    threading.Thread(target=_run, daemon=True).start()
    time.sleep(1)

    with _session_lock:
        _sessions[session.session_id] = session

    log(f"[🎯] MITM started: targets={targets or 'subnet'} via {iface}", "ATTACK")
    return jsonify({"ok": True, "session_id": session.session_id})


@mitm_bp.route("/api/mitm/stop", methods=["POST"])
def mitm_stop():
    data = request.json or {}
    sid  = data.get("session_id")

    with _session_lock:
        if sid and sid in _sessions:
            _sessions[sid].stop()
            del _sessions[sid]
        elif not sid:
            # Stop all
            for s in list(_sessions.values()):
                s.stop()
            _sessions.clear()

    log("[*] MITM session(s) stopped. ARP restored.", "WARN")
    return jsonify({"ok": True})


def stop_all_mitm():
    with _session_lock:
        sessions = list(_sessions.values())
        _sessions.clear()
    for session in sessions:
        session.stop()


@mitm_bp.route("/api/mitm/packets")
def mitm_packets():
    sid = request.args.get("session_id")
    n   = int(request.args.get("n", 100))
    with _session_lock:
        if sid and sid in _sessions:
            pkts = list(_sessions[sid].packets)[-n:]
        else:
            pkts = []
            for s in _sessions.values():
                pkts.extend(list(s.packets)[-n:])
    return jsonify({"packets": pkts[-n:]})


@mitm_bp.route("/api/mitm/creds")
def mitm_creds():
    all_creds = []
    with _session_lock:
        for s in _sessions.values():
            all_creds.extend(s.creds)
    return jsonify({"creds": all_creds, "count": len(all_creds)})


@mitm_bp.route("/api/mitm/stats")
def mitm_stats():
    with _session_lock:
        stats = {sid: s.stats.to_dict() for sid, s in _sessions.items()}
    return jsonify({"stats": stats})


def _check_ip_forward() -> bool:
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except Exception:
        return False
