#!/usr/bin/env python3
"""Snake pivot API — opt-in Air-to-LAN join."""
from __future__ import annotations

import time

from flask import Blueprint, jsonify, request

from snakefw.core.cracked_store import cracked_password
from snakefw.core.radios import assign_roles
from snakefw.core.session_manager import get_session
from snakefw.core.tool_manager import classify_wireless_ifaces, find_executable
from snakefw.pivot.engine import (
    get_active_pivot,
    start_pivot,
    stop_pivot,
)
from snakefw.strike.routes import emit_strike

pivot_bp = Blueprint("pivot", __name__)

_socketio = None
_snake_log_cb = None
_teardown_cb = None


def register_socketio(sio, log_cb=None, teardown_cb=None):
    global _socketio, _snake_log_cb, _teardown_cb
    _socketio = sio
    _snake_log_cb = log_cb
    _teardown_cb = teardown_cb


def emit_pivot(event: str, data: dict) -> None:
    if _socketio:
        _socketio.emit(f"pivot_{event}", data)


def log(msg: str, level: str = "INFO") -> None:
    if _snake_log_cb:
        _snake_log_cb(msg, level)
    emit_pivot("log", {"ts": time.time(), "level": level, "msg": msg})


def emit_pivot_ready(entry: dict) -> None:
    """Notify the UI that a PSK is ready for an authorized pivot."""
    payload = {
        "essid": entry.get("essid") or "",
        "bssid": entry.get("bssid") or "",
        "has_key": bool(cracked_password(entry)),
        "source": entry.get("attack") or entry.get("source") or "crack",
    }
    emit_pivot("ready", payload)
    log(f"[Pivot] PSK ready for {payload['essid'] or payload['bssid']} — confirm to join", "INFO")


def _socket_bridge(event: str, data: dict) -> None:
    emit_pivot(event, data)


@pivot_bp.route("/api/pivot/status")
def pivot_status():
    session = get_active_pivot()
    plan = assign_roles(
        classify_wireless_ifaces(),
        session_monitor=get_session().monitor_iface,
    )
    return jsonify({
        "ok": True,
        "session": session.to_dict() if session else None,
        "client_iface": plan.get("client_iface") or "",
        "dual_radio": plan.get("dual_radio"),
        "tools": {
            "wpa_supplicant": bool(find_executable("wpa_supplicant")),
            "dhcp": bool(find_executable("dhclient", "dhcpcd", "udhcpc")),
        },
    })


@pivot_bp.route("/api/pivot/start", methods=["POST"])
def pivot_start():
    data = request.json or {}
    if data.get("authorized") is not True:
        return jsonify({"ok": False, "error": "Confirm you are authorized to join this network"}), 403

    essid = str(data.get("essid") or "").strip()[:128]
    bssid = str(data.get("bssid") or "").strip()
    password = str(
        data.get("psk") or data.get("password") or data.get("key") or ""
    ).strip()
    if not essid:
        return jsonify({"ok": False, "error": "ESSID is required"}), 400
    if not password:
        return jsonify({"ok": False, "error": "A PSK is required to join"}), 400

    try:
        session = start_pivot(
            essid=essid,
            password=password,
            bssid=bssid,
            iface=str(data.get("iface") or ""),
            launch_strike=bool(data.get("launch_strike", True)),
            strike_preset=str(data.get("preset") or "smart"),
            stop_wireless=bool(data.get("stop_wireless", True)),
            socket_cb=_socket_bridge,
            log_cb=lambda m: log(m, "INFO"),
            teardown_cb=_teardown_cb,
            strike_socket_cb=emit_strike,
        )
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 429

    log(f"[Pivot] joining {essid} (Strike={'on' if session.launch_strike else 'off'})", "INFO")
    return jsonify({"ok": True, "session": session.to_dict()})


@pivot_bp.route("/api/pivot/stop", methods=["POST"])
def pivot_stop_api():
    if stop_pivot():
        log("[Pivot] stop requested", "WARN")
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "No active pivot"}), 400
