#!/usr/bin/env python3
"""Snake Strike — Flask API for the LAN recon chain."""
from __future__ import annotations

import shutil
import threading
import time
from flask import Blueprint, jsonify, request

from snakefw.mitm.engine import gateway_subnet as _gw_subnet
from snakefw.arsenal.engine import ncrack_busy, run_ncrack_job, parse_ncrack_credentials
from snakefw.strike.engine import (
    NXC_PROFILES,
    NXC_PROTOCOLS,
    PRESETS,
    claim_msf_job,
    default_gateway,
    find_msfconsole,
    find_nxc,
    get_active_session,
    host_msf_queue,
    iface_ipv4,
    list_lan_interfaces,
    load_last_report,
    record_msf_result,
    release_msf_job,
    resolve_strike_iface,
    run_msf_auto_check,
    run_msf_module,
    sanitize_ips,
    start_host_scan,
    start_nxc,
    start_strike,
    stop_all_strike,
    stop_strike,
    valid_ipv4,
)

strike_bp = Blueprint("strike", __name__)

_socketio = None
_snake_log_cb = None


def register_socketio(sio, log_cb=None):
    global _socketio, _snake_log_cb
    _socketio = sio
    _snake_log_cb = log_cb


def emit_strike(event: str, data: dict) -> None:
    if _socketio:
        _socketio.emit(f"strike_{event}", data)


def log(msg: str, level: str = "INFO") -> None:
    if _snake_log_cb:
        _snake_log_cb(msg, level)
    emit_strike("log", {"ts": time.time(), "level": level, "msg": msg})


def _socket_bridge(event: str, data: dict) -> None:
    emit_strike(event, data)


def _lhost_for(iface: str = "") -> str:
    resolved = resolve_strike_iface(iface)
    return iface_ipv4(resolved)


@strike_bp.route("/api/strike/status")
def strike_status():
    session = get_active_session()
    iface = resolve_strike_iface(request.args.get("iface", ""))
    gateway = request.args.get("gateway") or default_gateway(iface)
    subnet = request.args.get("subnet") or (_gw_subnet(gateway) if gateway else "")
    return jsonify({
        "ok": True,
        "session": session.to_dict() if session else None,
        "presets": {k: {"label": v["label"], "hint": v.get("hint", "")} for k, v in PRESETS.items()},
        "nxc_profiles": {k: {"label": v["label"], "hint": v.get("hint", "")} for k, v in NXC_PROFILES.items()},
        "nxc_protocols": list(NXC_PROTOCOLS),
        "iface": iface,
        "ifaces": list_lan_interfaces(),
        "ipv4": iface_ipv4(iface),
        "gateway": gateway,
        "subnet": subnet,
        "tools": {
            "nmap": bool(shutil.which("nmap")),
            "nxc": bool(find_nxc()),
            "msfconsole": bool(find_msfconsole()),
            "ncrack": bool(shutil.which("ncrack")),
        },
        "last_report": load_last_report(),
    })


@strike_bp.route("/api/strike/start", methods=["POST"])
def strike_start():
    data = request.json or {}
    if not data.get("authorized"):
        return jsonify({"ok": False, "error": "Authorization required"}), 403

    preset = str(data.get("preset") or "smart").lower()
    if preset not in PRESETS:
        return jsonify({"ok": False, "error": f"Unknown preset: {preset}"}), 400

    try:
        session = start_strike(
            preset=preset,
            iface=str(data.get("iface") or ""),
            gateway=str(data.get("gateway") or ""),
            subnet=str(data.get("subnet") or ""),
            stop_after=str(data.get("stop_after") or ""),
            socket_cb=_socket_bridge,
            log_cb=lambda m: log(m, "INFO"),
        )
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 429

    if session.phase == "failed" and not session.running:
        return jsonify({"ok": False, "error": session.error, "session": session.to_dict()}), 400

    log(f"[⚡] Strike {PRESETS[session.preset]['label']} on {session.iface} {session.subnet}", "INFO")
    return jsonify({"ok": True, "session": session.to_dict()})


@strike_bp.route("/api/strike/stop", methods=["POST"])
def strike_stop_api():
    if stop_strike():
        log("[⚡] Strike chain stop requested", "WARN")
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "No active Strike chain"}), 400


def _lan_from(data: dict) -> dict:
    return {
        "iface": str(data.get("iface") or ""),
        "gateway": str(data.get("gateway") or ""),
        "subnet": str(data.get("subnet") or ""),
    }


@strike_bp.route("/api/strike/scan-host", methods=["POST"])
def strike_scan_host():
    data = request.json or {}
    if not data.get("authorized"):
        return jsonify({"ok": False, "error": "Authorization required"}), 403
    ips = data.get("ips") or data.get("ip") or []
    if isinstance(ips, str):
        ips = [ips]
    targets = sanitize_ips(list(ips))
    if not targets:
        return jsonify({"ok": False, "error": "Select at least one live host to nmap"}), 400
    preset = str(data.get("preset") or "smart").lower()
    if preset not in PRESETS or preset == "discover":
        preset = "smart"
    try:
        session = start_host_scan(
            targets,
            preset=preset,
            run_nxc=bool(data.get("run_nxc")),
            socket_cb=_socket_bridge,
            log_cb=lambda m: log(m, "INFO"),
            **_lan_from(data),
        )
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 429
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    log(f"[⚡] Nmap {PRESETS[session.preset]['label']} → {', '.join(targets)}", "INFO")
    return jsonify({"ok": True, "session": session.to_dict(), "ips": targets})


@strike_bp.route("/api/strike/nxc", methods=["POST"])
def strike_nxc():
    data = request.json or {}
    if not data.get("authorized"):
        return jsonify({"ok": False, "error": "Authorization required"}), 403
    ips = data.get("ips") or data.get("ip") or []
    if isinstance(ips, str):
        ips = [ips]
    targets = sanitize_ips(list(ips))
    if not targets:
        return jsonify({"ok": False, "error": "Select at least one host for NetExec"}), 400
    try:
        session = start_nxc(
            targets,
            protocol=str(data.get("protocol") or ""),
            profile=str(data.get("profile") or "enum"),
            socket_cb=_socket_bridge,
            log_cb=lambda m: log(m, "INFO"),
            **_lan_from(data),
        )
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 429
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    proto = str(data.get("protocol") or "auto")
    log(f"[⚡] NetExec {data.get('profile') or 'enum'} {proto} → {', '.join(targets)}", "INFO")
    return jsonify({"ok": True, "session": session.to_dict(), "ips": targets})


@strike_bp.route("/api/strike/ncrack", methods=["POST"])
def strike_ncrack():
    data = request.json or {}
    if not data.get("authorized"):
        return jsonify({"ok": False, "error": "Authorization required"}), 403
    if ncrack_busy():
        return jsonify({"ok": False, "error": "ncrack already running"}), 429

    ips = data.get("ips") or []
    if isinstance(ips, str):
        ips = [ips]
    targets = sanitize_ips(list(ips))
    session = get_active_session()
    report = load_last_report()
    hosts = (session.hosts if session else None) or report.get("hosts") or []
    if not targets:
        targets = sanitize_ips([h.get("ip") for h in hosts if h.get("ip")])
    if not targets:
        return jsonify({"ok": False, "error": "Discover and nmap hosts first"}), 400
    selected = [h for h in hosts if h.get("ip") in set(targets)]

    def _run():
        try:
            log("[🔓] ncrack login audit on open services…", "INFO")
            _code, log_path, output = run_ncrack_job(
                targets,
                hosts=selected or hosts,
                userlist=str(data.get("userlist") or ""),
                passlist=str(data.get("passlist") or ""),
                log_cb=lambda m: log(m, "INFO"),
                timeout=int(data.get("timeout") or 600),
            )
            creds = parse_ncrack_credentials(output)
            emit_strike("ncrack_done", {"log": log_path, "creds": creds, "targets": targets})
            if creds:
                log(f"[+] ncrack: {len(creds)} hit(s) — {log_path}", "SUCCESS")
        except Exception as exc:
            log(f"[!] ncrack: {exc}", "ERROR")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "msg": "ncrack started", "targets": targets})


@strike_bp.route("/api/strike/report")
def strike_report():
    session = get_active_session()
    return jsonify({
        "ok": True,
        "session": session.to_dict() if session else None,
        "report": load_last_report(),
    })


@strike_bp.route("/api/strike/msf", methods=["POST"])
def strike_msf():
    data = request.json or {}
    action = str(data.get("action") or "check").lower()
    if action == "exploit" and not data.get("authorized"):
        return jsonify({"ok": False, "error": "Exploit requires explicit authorization"}), 403

    module = str(data.get("module") or "").strip()
    rhosts = str(data.get("rhosts") or data.get("ip") or "").strip()
    if not module or not rhosts:
        return jsonify({"ok": False, "error": "module and rhosts required"}), 400
    if not claim_msf_job():
        return jsonify({"ok": False, "error": "A Metasploit job is already running"}), 429

    lhost = _lhost_for(str(data.get("iface") or ""))

    def _run():
        try:
            log(f"[🎯] MSF {action}: {module} → {rhosts}", "INFO")
            result = run_msf_module(module, rhosts, action=action, lhost=lhost)
            record_msf_result(result)
            emit_strike("msf_result", result)
            verdict = result.get("verdict") or ""
            if result.get("likely_vulnerable"):
                log(f"[+] MSF {verdict}: {module} on {rhosts}", "SUCCESS")
            elif result.get("ok"):
                log(f"[*] MSF {verdict or 'done'}: {module}", "INFO")
            else:
                log(f"[!] MSF: {result.get('error', 'failed')}", "ERROR")
        finally:
            release_msf_job()

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "msg": f"Metasploit {action} started"})


@strike_bp.route("/api/strike/msf/auto-check", methods=["POST"])
def strike_msf_auto():
    data = request.json or {}
    if not data.get("authorized"):
        return jsonify({"ok": False, "error": "Authorization required"}), 403

    session = get_active_session()
    report = load_last_report()
    queue = []
    if session and session.msf_queue:
        queue = session.msf_queue
    elif report.get("msf_queue"):
        queue = report["msf_queue"]
    extra = data.get("items") or []
    if extra:
        queue = extra + queue
    target_ip = str(data.get("ip") or data.get("rhosts") or "").strip()
    if target_ip:
        if not valid_ipv4(target_ip):
            return jsonify({"ok": False, "error": "Invalid host IPv4"}), 400
        host_queue = host_msf_queue(target_ip)
        queue = host_queue + [item for item in queue if (item.get("ip") or item.get("rhosts")) == target_ip]
    if not queue:
        return jsonify({"ok": False, "error": "Nothing to check — discover and nmap a host first"}), 400

    lhost = _lhost_for(str(data.get("iface") or ""))

    def _run():
        try:
            log("[🎯] Auto-check: running top Metasploit checks (no exploit)", "INFO")
            results = run_msf_auto_check(
                queue,
                socket_cb=_socket_bridge,
                log_cb=lambda m: log(m, "INFO"),
                lhost=lhost,
            )
            hits = sum(1 for r in results if r.get("likely_vulnerable"))
            log(f"[🎯] Auto-check finished — {hits} likely vulnerable", "SUCCESS" if hits else "INFO")
        except RuntimeError as exc:
            log(f"[!] {exc}", "ERROR")
            emit_strike("msf_batch", {"error": str(exc), "results": []})

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "msg": "Auto-check started (check only)"})
