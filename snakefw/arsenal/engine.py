#!/usr/bin/env python3
"""Arsenal runners: ncrack, playbook command builder, apt bundle hints."""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from snakefw.core.arsenal_catalog import (
    APT_BUNDLES,
    MITM_PROFILES,
    NCRACK_PORT_SERVICES,
    PLAYBOOKS,
)
from snakefw.core.paths import LOGS_DIR
from snakefw.core.tool_manager import ProcessRunner, find_executable

ARSENAL_LOG_DIR = LOGS_DIR / "arsenal"
ARSENAL_LOG_DIR.mkdir(parents=True, exist_ok=True)

_ncrack_lock = threading.Lock()
_ncrack_running = False


def slug_essid(essid: str) -> str:
    raw = re.sub(r"[^a-zA-Z0-9]+", "_", (essid or "lab").strip()).strip("_")
    return (raw[:32] or "lab").lower()


def playbook_command(
    playbook_id: str,
    *,
    essid: str = "",
    bssid: str = "",
    channel: int = 6,
    ap_iface: str = "wlan0",
    lan_iface: str = "eth0",
) -> Optional[str]:
    for book in PLAYBOOKS:
        if book.get("id") != playbook_id:
            continue
        tpl = book.get("command_template")
        if not tpl:
            return None
        return tpl.format(
            essid=essid or "LabNetwork",
            essid_slug=slug_essid(essid),
            bssid=bssid or "AA:BB:CC:DD:EE:FF",
            channel=channel or 6,
            ap_iface=ap_iface or "wlan0",
            lan_iface=lan_iface or "eth0",
        )
    return None


def build_ncrack_targets_from_hosts(hosts: List[Dict[str, Any]]) -> List[str]:
    """Build ncrack -p arguments like ssh,rdp:3389 from strike host port lists."""
    services: Set[str] = set()
    for host in hosts:
        for port_row in host.get("ports") or []:
            if str(port_row.get("state", "")).lower() not in ("open", "open|filtered"):
                continue
            try:
                port_num = int(port_row.get("port"))
            except (TypeError, ValueError):
                continue
            svc = NCRACK_PORT_SERVICES.get(port_num)
            if svc:
                services.add(svc if svc != "https" else "ssl/http")
            elif port_num in (80, 8080):
                services.add("http")
            elif port_num in (443, 8443):
                services.add("ssl/http")
    if not services:
        return ["ssh,rdp,ftp,vnc,winrm,http"]
    ordered = sorted(services)
    return [",".join(ordered)]


def build_ncrack_argv(
    ips: List[str],
    hosts: Optional[List[Dict[str, Any]]] = None,
    userlist: str = "",
    passlist: str = "",
) -> List[str]:
    if not find_executable("ncrack"):
        raise RuntimeError("ncrack is not installed (sudo apt install ncrack)")
    targets = [ip.strip() for ip in ips if ip.strip()][:24]
    if not targets:
        raise ValueError("No target IPs for ncrack")

    port_spec = build_ncrack_targets_from_hosts(hosts or [])
    cmd = [
        "ncrack",
        "-T4",
        "--connection-limit", "32",
        "-p", port_spec[0],
    ]
    if userlist and Path(userlist).is_file():
        cmd += ["-U", userlist]
    if passlist and Path(passlist).is_file():
        cmd += ["-P", passlist]
    cmd += targets
    return cmd


def ncrack_busy() -> bool:
    return _ncrack_running


def run_ncrack_job(
    ips: List[str],
    hosts: Optional[List[Dict[str, Any]]] = None,
    userlist: str = "",
    passlist: str = "",
    log_cb: Optional[Callable[[str], None]] = None,
    runner_cb: Optional[Callable] = None,
    timeout: int = 600,
) -> Tuple[int, str, List[str]]:
    """Run ncrack synchronously; returns (returncode, log_path, output_lines)."""
    global _ncrack_running
    with _ncrack_lock:
        if _ncrack_running:
            raise RuntimeError("An ncrack job is already running")
        _ncrack_running = True

    job_id = uuid.uuid4().hex[:8]
    log_path = str(ARSENAL_LOG_DIR / f"ncrack_{job_id}.log")
    lines: List[str] = []
    try:
        cmd = build_ncrack_argv(ips, hosts=hosts, userlist=userlist, passlist=passlist)
        if log_cb:
            log_cb(f"[🔓] ncrack: {' '.join(cmd)}")
        runner = ProcessRunner(
            cmd,
            log_file=log_path,
            callback=log_cb,
            timeout=timeout if timeout > 0 else 0,
        ).start()
        if runner_cb:
            runner_cb(runner)
        runner.wait()
        lines = list(runner.output)
        return runner.returncode or 0, log_path, lines
    finally:
        with _ncrack_lock:
            _ncrack_running = False


def parse_ncrack_credentials(output: List[str]) -> List[Dict[str, str]]:
    creds: List[Dict[str, str]] = []
    combined = "\n".join(output)
    for match in re.finditer(
        r"Discovered\s+credentials?\s+on\s+(\S+)\s+([\d.]+:\d+)\s+['\"]?([^'\"]+)['\"]?\s+['\"]?([^'\"]+)['\"]?",
        combined,
        re.IGNORECASE,
    ):
        creds.append({
            "service": match.group(1),
            "target": match.group(2),
            "user": match.group(3),
            "password": match.group(4),
        })
    for line in output:
        if "credentials:" in line.lower() or "login:" in line.lower():
            creds.append({"raw": line.strip()})
    return creds


def apt_install_command(bundle_id: str) -> str:
    bundle = APT_BUNDLES.get(bundle_id)
    if not bundle:
        raise ValueError(f"Unknown bundle: {bundle_id}")
    pkgs = " ".join(bundle["packages"])
    return f"sudo apt install -y {pkgs}"


def catalog_payload(tools: Dict[str, bool]) -> Dict[str, Any]:
    playbooks = []
    for book in PLAYBOOKS:
        required = book.get("tools") or []
        ready = all(tools.get(name, False) for name in required)
        playbooks.append({**book, "ready": ready, "missing": [t for t in required if not tools.get(t)]})
    bundles = []
    for bid, meta in APT_BUNDLES.items():
        bundles.append({
            "id": bid,
            "label": meta["label"],
            "hint": meta.get("hint", ""),
            "install": apt_install_command(bid),
        })
    return {
        "mitm_profiles": MITM_PROFILES,
        "playbooks": playbooks,
        "bundles": bundles,
    }
