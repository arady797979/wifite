#!/usr/bin/env python3
"""
Snake Framework - Scanner
Wraps airodump-ng for live network scanning with parsed output.
"""
import csv
import glob
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .network_analyzer import NetworkAnalyzer, NetworkProfile, ThreatLevel


CAPTURES = Path(__file__).resolve().parent.parent / "captures"
CAPTURES.mkdir(parents=True, exist_ok=True)


def _parse_int(value, default: int) -> int:
    text = str(value).strip()
    if not text or not text.lstrip("-").isdigit():
        return default
    return int(text)


def parse_airodump_csv(csv_path: str) -> Optional[List[Dict]]:
    """Parse airodump-ng CSV output into network dicts.

    Returns None when the file cannot be read yet so callers keep the last
    good result instead of wiping the UI on a partial write.
    """
    try:
        with open(csv_path, "r", errors="replace", newline="") as handle:
            lines = [line.replace("\0", "") for line in handle]
    except OSError:
        return None

    try:
        reader = csv.reader(
            lines,
            delimiter=",",
            quoting=csv.QUOTE_ALL,
            skipinitialspace=True,
            escapechar="\\",
        )
        networks: List[Dict] = []
        clients = False
        for row in reader:
            if not row:
                continue
            first = row[0].strip()
            if first == "BSSID":
                clients = False
                continue
            if first == "Station MAC":
                clients = True
                continue
            if clients:
                if len(row) < 6:
                    continue
                ap_bssid = row[5].strip()
                if not ap_bssid or "not associated" in ap_bssid.lower():
                    continue
                station = first.upper()
                for net in networks:
                    if net["bssid"].upper() == ap_bssid.upper():
                        net["clients"] += 1
                        if station and station not in net["client_macs"]:
                            net["client_macs"].append(station)
                        break
                continue
            if len(row) < 14:
                continue
            bssid = row[0].strip()
            if not bssid or len(bssid) < 17:
                continue
            channel = _parse_int(row[3], 0)
            if channel < 1:
                continue
            essid = row[13].strip() if len(row) > 13 else ""
            if not essid or essid.replace("\\x00", "") == "":
                essid = "<hidden>"
            networks.append({
                "bssid":        bssid,
                "essid":        essid,
                "channel":      channel,
                "signal":       _parse_int(row[8], -80),
                "encryption":   row[5].strip(),
                "cipher":       row[6].strip(),
                "auth":         row[7].strip(),
                "wps":          False,
                "wps_locked":   False,
                "clients":      0,
                "client_macs":  [],
                "beacons":      _parse_int(row[9], 0),
                "data_packets": _parse_int(row[10], 0),
            })
    except (csv.Error, ValueError, IndexError):
        return None
    return networks


class Scanner:
    """Live airodump-ng scanner with auto-parsed results."""

    def __init__(self, iface: str, callback: Optional[Callable] = None,
                 channel: int = 0, band: str = "bg"):
        self.iface    = iface
        self.callback = callback
        self.channel  = channel
        self.band     = band
        self.analyzer = NetworkAnalyzer()
        self._proc    = None
        self._thread  = None
        self._running = False
        self._tmpdir  = None
        self._prefix  = None
        self._csv_path = None
        self._err_path = None
        self._warned_empty = False
        self.networks: List[NetworkProfile] = []

    def _cb(self, msg: str):
        if self.callback:
            self.callback(msg)

    def _latest_csv(self) -> Optional[str]:
        if self._csv_path and os.path.exists(self._csv_path):
            return self._csv_path
        if not self._prefix:
            return None
        matches = sorted(glob.glob(self._prefix + "-*.csv"))
        if matches:
            self._csv_path = matches[-1]
            return self._csv_path
        return None

    def _stderr_tail(self, limit: int = 400) -> str:
        if not self._err_path or not os.path.exists(self._err_path):
            return ""
        try:
            with open(self._err_path, "r", errors="replace") as handle:
                text = handle.read().strip()
        except OSError:
            return ""
        text = " ".join(text.split())
        return text[-limit:]

    def start(self) -> "Scanner":
        if self._running:
            return self
        if not shutil.which("airodump-ng"):
            raise RuntimeError("airodump-ng is not installed")
        self._tmpdir   = tempfile.mkdtemp(prefix="snake_scan_")
        self._prefix   = os.path.join(self._tmpdir, "scan")
        self._csv_path = None
        self._err_path = os.path.join(self._tmpdir, "airodump.err")
        self._warned_empty = False

        cmd = [
            "airodump-ng",
            "--background", "1",
            "-w", self._prefix,
            "--output-format", "csv",
            "--write-interval", "1",
        ]
        if self.channel > 0:
            cmd += ["-c", str(self.channel)]
        elif self.band:
            cmd += ["--band", self.band]
        cmd.append(self.iface)

        self._cb(f"[🐍] Scanner starting on {self.iface}...")
        try:
            with open(self._err_path, "w") as err_fh:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=err_fh,
                    start_new_session=True,
                )
        except Exception:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None
            raise
        self._running = True
        self._thread  = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        return self

    def _poll_loop(self):
        started = time.time()
        while self._running:
            time.sleep(1.5)
            if self._proc and self._proc.poll() is not None:
                err = self._stderr_tail()
                self._running = False
                detail = err or "Is the interface in monitor mode and up?"
                self._cb(
                    f"[!] airodump-ng exited (code {self._proc.returncode}). {detail}"
                )
                self._cb("__scanner_exited__")
                return
            self._refresh()
            if (
                not self._warned_empty
                and not self.networks
                and time.time() - started >= 8
            ):
                if not self._latest_csv():
                    self._cb(
                        "[!] airodump-ng has not written results yet. "
                        "Confirm monitor mode and that the adapter can hop channels."
                    )
                self._warned_empty = True

    def _refresh(self):
        csv_path = self._latest_csv()
        if not csv_path:
            return
        raw_nets = parse_airodump_csv(csv_path)
        if raw_nets is None:
            return
        profiles = [self.analyzer.analyze(n) for n in raw_nets]
        self.networks = self.analyzer.rank_networks(profiles)
        if self.callback:
            self.callback("__networks_updated__")

    def _terminate_proc(self):
        if not self._proc or self._proc.poll() is not None:
            return
        try:
            os.killpg(self._proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                self._proc.terminate()
            except Exception:
                pass
        try:
            self._proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(self._proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    self._proc.kill()
                except Exception:
                    pass

    def stop(self):
        self._running = False
        self._terminate_proc()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=4)
        self._refresh()
        if self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None
            self._csv_path = None
            self._prefix = None
            self._err_path = None
        self._cb("[*] Scanner stopped.")

    def get_networks(self) -> List[Dict]:
        return [n.to_dict() for n in self.networks]

    def get_easy_targets(self) -> List[NetworkProfile]:
        return [n for n in self.networks if n.threat_level == ThreatLevel.EASY]

    def get_suspicious(self) -> List[NetworkProfile]:
        return [n for n in self.networks if n.threat_level == ThreatLevel.SUSPICIOUS]


def quick_scan(iface: str, duration: int = 30, callback: Optional[Callable] = None) -> List[Dict]:
    """Blocking scan for `duration` seconds, returns network list."""
    scanner = Scanner(iface, callback=callback)
    scanner.start()
    time.sleep(duration)
    scanner.stop()
    return scanner.get_networks()
