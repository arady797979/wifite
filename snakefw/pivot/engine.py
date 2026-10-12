#!/usr/bin/env python3
"""Join a lab Wi-Fi PSK network and hand off to Strike."""
from __future__ import annotations

import os
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from snakefw.core.paths import LOGS_DIR, ensure_runtime_dirs
from snakefw.core.radios import assign_roles
from snakefw.core.tool_manager import (
    classify_wireless_ifaces,
    find_executable,
    get_interface_mode,
    set_managed_mode,
)
from snakefw.eviltwin.engine import write_wpa_conf
from snakefw.strike.engine import (
    default_gateway,
    iface_ipv4,
    start_strike,
)

ensure_runtime_dirs()

PIVOT_LOG_DIR = LOGS_DIR / "pivot"
PIVOT_LOG_DIR.mkdir(parents=True, exist_ok=True)

_lock = threading.Lock()
_active: Optional["PivotSession"] = None


def get_active_pivot() -> Optional["PivotSession"]:
    with _lock:
        return _active


def _run(cmd: list, timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _release_nm(iface: str) -> None:
    nmcli = find_executable("nmcli")
    if not nmcli:
        return
    try:
        _run([nmcli, "dev", "set", iface, "managed", "no"], timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        pass


def request_dhcp(iface: str, timeout: int = 16) -> str:
    """Ask for an IPv4 lease. Returns the address or empty."""
    existing = iface_ipv4(iface)
    if existing:
        return existing
    candidates = (
        ["dhclient", "-1", "-v", iface],
        ["dhcpcd", "-w", iface],
        ["udhcpc", "-i", iface, "-n"],
    )
    for cmd in candidates:
        if not find_executable(cmd[0]):
            continue
        try:
            _run(cmd, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            continue
        leased = iface_ipv4(iface)
        if leased:
            return leased
    return iface_ipv4(iface)


def _stop_wpa(proc: Optional[subprocess.Popen]) -> None:
    if not proc or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, 15)
    except (ProcessLookupError, PermissionError, OSError):
        proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()


def associate_psk(
    iface: str,
    essid: str,
    password: str,
    work_dir: Path,
    timeout: int = 25,
    on_log: Optional[Callable[[str], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    """Start wpa_supplicant, wait for CONNECTED, then DHCP. Keeps the process."""
    wpa = find_executable("wpa_supplicant")
    if not wpa:
        return {"ok": False, "error": "wpa_supplicant is not installed"}
    if not iface:
        return {"ok": False, "error": "No client interface for pivot"}

    conf = write_wpa_conf(work_dir / "wpa_pivot.conf", essid, password)
    cmd = [wpa, "-i", iface, "-c", str(conf), "-P", str(work_dir / "wpa.pid")]
    if on_log:
        on_log(f"[Pivot] associating {iface} → {essid}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    deadline = time.time() + timeout
    connected = False
    error = ""
    while time.time() < deadline:
        if stop_event and stop_event.is_set():
            error = "stopped"
            break
        if proc.poll() is not None:
            break
        line = proc.stdout.readline() if proc.stdout else ""
        if not line:
            time.sleep(0.2)
            continue
        if "CTRL-EVENT-CONNECTED" in line:
            connected = True
            break
        if "WRONG-KEY" in line or "4-Way Handshake failed" in line:
            error = "PSK rejected by the access point"
            break
        if "SSID-TEMP-DISABLED" in line:
            error = "SSID temporarily disabled (bad key or AP reject)"
            break
    if not connected and not error:
        error = "Timed out waiting for association"
    if not connected:
        _stop_wpa(proc)
        return {"ok": False, "error": error, "ipv4": "", "gateway": "", "proc": None}
    if on_log:
        on_log("[Pivot] associated — requesting DHCP")
    ipv4 = request_dhcp(iface)
    gateway = default_gateway(iface)
    if not ipv4:
        _stop_wpa(proc)
        return {
            "ok": False,
            "error": "Associated but no DHCP lease",
            "ipv4": "",
            "gateway": gateway,
            "proc": None,
        }
    return {"ok": True, "error": "", "ipv4": ipv4, "gateway": gateway, "proc": proc}


class PivotSession:
    def __init__(
        self,
        essid: str,
        bssid: str,
        password: str,
        iface: str = "",
        *,
        launch_strike: bool = True,
        strike_preset: str = "smart",
        stop_wireless: bool = True,
    ):
        self.session_id = str(uuid.uuid4())[:8]
        self.essid = essid
        self.bssid = bssid
        self.password = password
        self.iface = iface
        self.launch_strike = launch_strike
        self.strike_preset = strike_preset
        self.stop_wireless = stop_wireless
        self.phase = "queued"
        self.progress = 0
        self.running = False
        self.error = ""
        self.ipv4 = ""
        self.gateway = ""
        self.started_at = 0.0
        self.finished_at = 0.0
        self.work_dir = PIVOT_LOG_DIR / f"pivot_{self.session_id}"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.wpa_proc: Optional[subprocess.Popen] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "essid": self.essid,
            "bssid": self.bssid,
            "iface": self.iface,
            "phase": self.phase,
            "progress": self.progress,
            "running": self.running,
            "error": self.error,
            "ipv4": self.ipv4,
            "gateway": self.gateway,
            "launch_strike": self.launch_strike,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


def start_pivot(
    essid: str,
    password: str,
    *,
    bssid: str = "",
    iface: str = "",
    launch_strike: bool = True,
    strike_preset: str = "smart",
    stop_wireless: bool = True,
    socket_cb: Optional[Callable] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    teardown_cb: Optional[Callable[[], None]] = None,
    strike_socket_cb: Optional[Callable] = None,
) -> PivotSession:
    global _active
    with _lock:
        if _active and _active.running:
            raise RuntimeError("A pivot is already running")
        session = PivotSession(
            essid=essid,
            bssid=bssid,
            password=password,
            iface=iface,
            launch_strike=launch_strike,
            strike_preset=strike_preset,
            stop_wireless=stop_wireless,
        )
        session.running = True
        session.started_at = time.time()
        _active = session

    session._thread = threading.Thread(
        target=_run_pivot,
        args=(session, socket_cb, log_cb, teardown_cb, strike_socket_cb),
        daemon=True,
    )
    session._thread.start()
    return session


def stop_pivot() -> bool:
    session = get_active_pivot()
    if not session:
        return False
    session._stop.set()
    session.phase = "stopping"
    _stop_wpa(session.wpa_proc)
    session.wpa_proc = None
    session.running = False
    return True


def stop_all_pivot() -> None:
    stop_pivot()


def _emit(socket_cb, event: str, data: dict) -> None:
    if socket_cb:
        socket_cb(event, data)


def _log(log_cb, msg: str) -> None:
    if log_cb:
        log_cb(msg)


def _run_pivot(
    session: PivotSession,
    socket_cb: Optional[Callable],
    log_cb: Optional[Callable[[str], None]],
    teardown_cb: Optional[Callable[[], None]],
    strike_socket_cb: Optional[Callable] = None,
) -> None:
    def phase(name: str, pct: int) -> None:
        session.phase = name
        session.progress = pct
        _emit(socket_cb, "phase", session.to_dict())

    try:
        if session.stop_wireless and teardown_cb:
            phase("teardown", 8)
            _log(log_cb, "[Pivot] stopping wireless jobs that would block the join")
            teardown_cb()

        if session._stop.is_set():
            raise InterruptedError("stopped")

        plan = assign_roles(classify_wireless_ifaces())
        iface = session.iface or plan.get("client_iface") or plan.get("ap_iface") or ""
        if not iface:
            raise RuntimeError("No wireless interface available for pivot")
        session.iface = iface

        phase("managed", 22)
        mode = get_interface_mode(iface)
        if mode == "monitor":
            _log(log_cb, f"[Pivot] switching {iface} to managed")
            iface = set_managed_mode(iface, callback=log_cb)
            session.iface = iface
        _release_nm(iface)

        if session._stop.is_set():
            raise InterruptedError("stopped")

        phase("associate", 45)
        result = associate_psk(
            iface,
            session.essid,
            session.password,
            session.work_dir,
            timeout=25,
            on_log=log_cb,
            stop_event=session._stop,
        )
        if not result.get("ok"):
            raise RuntimeError(result.get("error") or "Association failed")
        session.wpa_proc = result.get("proc")
        session.ipv4 = result.get("ipv4") or ""
        session.gateway = result.get("gateway") or ""

        phase("ready", 78)
        _log(log_cb, f"[Pivot] on {session.essid} as {session.ipv4} via {session.gateway or 'no GW'}")
        _emit(socket_cb, "joined", session.to_dict())

        if session.launch_strike:
            phase("strike", 88)
            _log(log_cb, "[Pivot] launching Strike on the joined LAN")
            strike = start_strike(
                preset=session.strike_preset,
                iface=session.iface,
                gateway=session.gateway,
                socket_cb=strike_socket_cb,
                log_cb=log_cb,
            )
            if strike.phase == "failed" and not strike.running:
                raise RuntimeError(strike.error or "Strike failed to start")

        session.phase = "done"
        session.progress = 100
        session.finished_at = time.time()
        _emit(socket_cb, "complete", session.to_dict())
    except InterruptedError:
        session.phase = "stopped"
        session.error = "stopped"
        session.finished_at = time.time()
        _emit(socket_cb, "complete", session.to_dict())
    except Exception as exc:
        session.phase = "failed"
        session.error = str(exc)
        session.finished_at = time.time()
        _log(log_cb, f"[!] Pivot failed: {exc}")
        _emit(socket_cb, "complete", session.to_dict())
    finally:
        session.running = False
