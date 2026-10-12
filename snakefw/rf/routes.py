#!/usr/bin/env python3
"""Snake RF API — deauth, beacon flood, and auth DoS presets."""
import os
import threading
import time

from flask import Blueprint, jsonify, request

from snakefw.core.radios import assign_roles, conflicts_with_scanner
from snakefw.core.session_manager import SessionState, get_session
from snakefw.core.tool_manager import (
    classify_wireless_ifaces,
    get_interface_mode,
    is_valid_bssid,
    normalize_bssid,
)
from snakefw.rf.engine import (
    RF_MODES,
    RFSession,
    busy_ifaces,
    resolve_rf_tool,
    rf_tool_ready,
    stop_all_rf,
)

rf_bp = Blueprint("rf", __name__)

_socketio = None
_snake_log_cb = None
_job_hooks = {}
_sessions = {}
_session_lock = threading.Lock()


def register_socketio(sio, log_cb=None, job_hooks=None):
    global _socketio, _snake_log_cb, _job_hooks
    _socketio = sio
    _snake_log_cb = log_cb
    _job_hooks = job_hooks or {}


def emit_rf(event: str, data: dict):
    if _socketio:
        _socketio.emit(f"rf_{event}", data)


def log(msg: str, level: str = "INFO"):
    if _snake_log_cb:
        _snake_log_cb(msg, level)
    emit_rf("log", {"ts": time.time(), "level": level, "msg": msg})


def _scanner_iface() -> str:
    getter = _job_hooks.get("scanner_iface")
    return getter() if getter else ""


def _twin_ifaces() -> set:
    getter = _job_hooks.get("twin_ifaces")
    value = getter() if getter else set()
    return set(value or [])


def _register_job(jid: str, runner, stop_event):
    register_runner = _job_hooks.get("register_runner")
    register_stop = _job_hooks.get("register_stop")
    if register_runner and runner:
        register_runner(jid, runner)
    if register_stop and stop_event:
        register_stop(jid, stop_event)


def rf_busy_ifaces() -> set:
    return busy_ifaces()


def stop_rf_job(jid: str) -> bool:
    with _session_lock:
        matches = [s for s in _sessions.values() if s.job_id == jid]
    stopped = False
    for session in matches:
        session.stop()
        stopped = True
    return stopped


def _bounded_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _rf_readiness(iface: str = "") -> dict:
    classified = classify_wireless_ifaces()
    session = get_session()
    plan = assign_roles(classified, session_monitor=session.monitor_iface)
    monitor = plan["monitor"]
    iface = iface or session.attack_iface or plan["attack_iface"] or (monitor[0] if monitor else "")
    tool = resolve_rf_tool()
    mode = get_interface_mode(iface) if iface else "unknown"
    return {
        "iface": iface,
        "mode": mode,
        "monitor": monitor,
        "managed": plan["managed"],
        "interfaces": plan["interfaces"],
        "scan_iface": plan["scan_iface"],
        "attack_iface": plan["attack_iface"],
        "dual_radio": plan["dual_radio"],
        "tool": tool.get("label") or "",
        "mdk4": bool(resolve_rf_tool().get("kind") == "mdk4") if tool.get("path") else False,
        "ready": bool(iface and mode == "monitor" and tool.get("path") and os.geteuid() == 0),
        "root": os.geteuid() == 0,
        "tool_ready": bool(tool.get("path")),
    }


@rf_bp.route("/api/rf/status")
def rf_status():
    with _session_lock:
        active = {sid: session.snapshot() for sid, session in _sessions.items()}
    return jsonify({
        "ok": True,
        "sessions": active,
        "readiness": _rf_readiness(),
        "modes": list(RF_MODES),
    })


@rf_bp.route("/api/rf/start", methods=["POST"])
def rf_start():
    data = request.json or {}
    if data.get("authorized") is not True:
        return jsonify({"ok": False, "error": "Confirm you are authorized to test this target"}), 400

    mode = str(data.get("mode") or RF_MODES[0]).strip().lower()
    if mode not in RF_MODES:
        return jsonify({"ok": False, "error": f"Unsupported RF mode: {mode}"}), 400
    if not rf_tool_ready(mode):
        needed = "mdk4, mdk3, or aircrack-ng" if mode == "deauth" else "mdk4 or mdk3"
        return jsonify({"ok": False, "error": f"Missing RF tool. Install {needed}."}), 400

    session = get_session()
    classified = classify_wireless_ifaces()
    plan = assign_roles(classified, session_monitor=session.monitor_iface)
    iface = (data.get("iface") or data.get("interface") or session.attack_iface or "").strip()
    if not iface:
        iface = plan.get("attack_iface") or session.monitor_iface or ""
    if not iface:
        readiness = _rf_readiness()
        iface = readiness.get("iface") or ""
    if not iface:
        return jsonify({"ok": False, "error": "Select a monitor-mode interface"}), 400
    if get_interface_mode(iface) != "monitor":
        return jsonify({
            "ok": False,
            "error": f"{iface} is not in monitor mode. Enable Monitor Mode first.",
        }), 400

    busy = busy_ifaces() | _twin_ifaces()
    scanner = _scanner_iface()
    if iface in busy:
        return jsonify({
            "ok": False,
            "error": f"{iface} is already in use by Twin or an RF job",
        }), 409
    if conflicts_with_scanner(iface, scanner, classified):
        return jsonify({
            "ok": False,
            "error": f"{iface} is the scan radio. Stop the scan or use the attack radio ({plan.get('attack_iface') or 'another adapter'}).",
        }), 409

    bssid = normalize_bssid(str(data.get("bssid") or ""))
    if bssid and not is_valid_bssid(bssid):
        return jsonify({"ok": False, "error": "Invalid BSSID"}), 400
    if mode in {"deauth", "auth"} and not is_valid_bssid(bssid):
        return jsonify({"ok": False, "error": "A valid BSSID is required for this preset"}), 400

    essid = str(data.get("essid") or "")[:128]
    channel = _bounded_int(data.get("channel"), 0, 0, 196)
    client = normalize_bssid(str(data.get("client") or ""))
    if client and not is_valid_bssid(client):
        return jsonify({"ok": False, "error": "Invalid client MAC"}), 400
    duration = _bounded_int(data.get("duration"), 30, 0, 600)
    stealth = bool(data.get("stealth"))
    rotate_mac = bool(data.get("rotate_mac"))
    burst = _bounded_int(data.get("burst"), 8, 2, 32)

    job_label = f"RF_{mode.upper()}"
    jid = session.add_job(essid or mode, bssid, job_label)
    session.set_state(SessionState.ATTACKING)
    rf_session = RFSession(
        mode=mode,
        iface=iface,
        bssid=bssid,
        essid=essid,
        channel=channel,
        client=client,
        duration=duration,
        job_id=jid,
        stealth=stealth,
        rotate_mac=rotate_mac,
        burst=burst,
        on_log=lambda msg: (session.job_log(jid, msg), log(msg)),
    )

    def _run():
        try:
            rf_session.start()
            _register_job(jid, rf_session.runner, rf_session.stop_event)
            session.update_job(jid, state="RUNNING")
            if _socketio:
                _socketio.emit("job_update", session.jobs[jid].to_dict())
            emit_rf("status", rf_session.snapshot())
            rf_session.wait()
            if rf_session.stop_event.is_set():
                session.update_job(jid, state="KILLED", ended_at=time.time())
            else:
                session.update_job(jid, state="DONE", ended_at=time.time(), progress=100)
        except Exception as exc:
            rf_session.error = str(exc)
            session.update_job(jid, state="FAILED", ended_at=time.time())
            log(f"[RF] {exc}", "ERROR")
        finally:
            rf_session.running = False
            with _session_lock:
                _sessions.pop(rf_session.session_id, None)
            if not any(job.state in {"RUNNING", "QUEUED"} for job in session.jobs.values()):
                session.set_state(SessionState.IDLE)
            if _socketio and jid in session.jobs:
                _socketio.emit("job_update", session.jobs[jid].to_dict())
            emit_rf("status", {"running": False, "job_id": jid})

    with _session_lock:
        _sessions[rf_session.session_id] = rf_session
    threading.Thread(target=_run, daemon=True).start()
    log(f"[RF] Job {jid}: {job_label} on {essid or bssid or iface}", "ATTACK")
    return jsonify({
        "ok": True,
        "job_id": jid,
        "session_id": rf_session.session_id,
        "tool": rf_session.tool.get("label") or "",
    })


@rf_bp.route("/api/rf/stop", methods=["POST"])
def rf_stop():
    data = request.json or {}
    sid = data.get("session_id")
    jid = data.get("job_id")
    session = get_session()
    with _session_lock:
        targets = []
        if sid and sid in _sessions:
            targets = [_sessions[sid]]
        elif jid:
            targets = [item for item in _sessions.values() if item.job_id == jid]
        else:
            targets = list(_sessions.values())
    for item in targets:
        item.stop()
        if item.job_id and item.job_id in session.jobs:
            if session.jobs[item.job_id].state == "RUNNING":
                session.update_job(item.job_id, state="KILLED", ended_at=time.time())
                if _socketio:
                    _socketio.emit("job_update", session.jobs[item.job_id].to_dict())
    if not targets:
        stop_all_rf()
    log("[RF] session(s) stopped", "WARN")
    return jsonify({"ok": True})
