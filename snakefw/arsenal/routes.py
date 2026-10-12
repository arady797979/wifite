#!/usr/bin/env python3
"""Snake Arsenal API — playbooks, ncrack, install bundles."""
from __future__ import annotations

import threading
import time
from flask import Blueprint, jsonify, request

from snakefw.arsenal.engine import (
    catalog_payload,
    ncrack_busy,
    parse_ncrack_credentials,
    playbook_command,
    run_ncrack_job,
)
from snakefw.core.tool_manager import check_tools
from snakefw.strike.engine import get_active_session, load_last_report, sanitize_ips

arsenal_bp = Blueprint("arsenal", __name__)

_socketio = None
_snake_log_cb = None


def register_socketio(sio, log_cb=None):
    global _socketio, _snake_log_cb
    _socketio = sio
    _snake_log_cb = log_cb


def emit_arsenal(event: str, data: dict) -> None:
    if _socketio:
        _socketio.emit(f"arsenal_{event}", data)


def log(msg: str, level: str = "INFO") -> None:
    if _snake_log_cb:
        _snake_log_cb(msg, level)
    emit_arsenal("log", {"ts": time.time(), "level": level, "msg": msg})


@arsenal_bp.route("/api/arsenal/catalog")
def arsenal_catalog():
    tools = check_tools()
    return jsonify({"ok": True, **catalog_payload(tools), "tools": tools})


@arsenal_bp.route("/api/arsenal/command", methods=["POST"])
def arsenal_command():
    data = request.json or {}
    pb_id = str(data.get("playbook") or "").strip()
    if not pb_id:
        return jsonify({"ok": False, "error": "playbook id required"}), 400
    cmd = playbook_command(
        pb_id,
        essid=str(data.get("essid") or ""),
        bssid=str(data.get("bssid") or ""),
        channel=int(data.get("channel") or 6),
        ap_iface=str(data.get("ap_iface") or data.get("iface") or "wlan0"),
        lan_iface=str(data.get("lan_iface") or "eth0"),
    )
    if not cmd:
        return jsonify({"ok": False, "error": "Unknown playbook or no command template"}), 404
    return jsonify({"ok": True, "playbook": pb_id, "command": cmd})


@arsenal_bp.route("/api/arsenal/ncrack", methods=["POST"])
def arsenal_ncrack():
    data = request.json or {}
    if not data.get("authorized"):
        return jsonify({"ok": False, "error": "Authorization required"}), 403
    if ncrack_busy():
        return jsonify({"ok": False, "error": "ncrack already running"}), 429

    ips = data.get("ips") or data.get("targets") or []
    if isinstance(ips, str):
        ips = [ips]
    targets = sanitize_ips(list(ips))
    if not targets and data.get("use_strike_hosts"):
        session = get_active_session()
        report = load_last_report()
        hosts = (session.hosts if session else None) or report.get("hosts") or []
        targets = sanitize_ips([h.get("ip") for h in hosts if h.get("ip")])
    if not targets:
        return jsonify({"ok": False, "error": "No target IPs (discover LAN in Strike first)"}), 400

    session = get_active_session()
    report = load_last_report()
    all_hosts = (session.hosts if session else None) or report.get("hosts") or []
    selected = [h for h in all_hosts if h.get("ip") in set(targets)]

    userlist = str(data.get("userlist") or "").strip()
    passlist = str(data.get("passlist") or "/usr/share/wordlists/metasploit/unix_users.txt")
    timeout = int(data.get("timeout") or 600)

    def _run():
        try:
            code, log_path, output = run_ncrack_job(
                targets,
                hosts=selected or all_hosts,
                userlist=userlist,
                passlist=passlist,
                log_cb=lambda m: log(m, "INFO"),
                timeout=timeout,
            )
            creds = parse_ncrack_credentials(output)
            emit_arsenal("ncrack_done", {
                "returncode": code,
                "log": log_path,
                "creds": creds,
                "targets": targets,
            })
            if creds:
                log(f"[+] ncrack found {len(creds)} credential hint(s) — see {log_path}", "SUCCESS")
            else:
                log(f"[*] ncrack finished (exit {code}) — log: {log_path}", "INFO")
        except Exception as exc:
            log(f"[!] ncrack: {exc}", "ERROR")
            emit_arsenal("ncrack_done", {"error": str(exc), "targets": targets})

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "msg": "ncrack started", "targets": targets})
