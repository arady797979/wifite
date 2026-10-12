#!/usr/bin/env python3
"""
Snake Strike Engine — chained LAN recon: Nmap → NetExec → Metasploit.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from snakefw.core.paths import LOGS_DIR, RESULTS_DIR
from snakefw.mitm.engine import gateway_subnet
from snakefw.strike.msf_map import pick_recommended, suggest_msf
from snakefw.strike.parsers import (
    classify_role,
    dedupe_findings,
    merge_host_profiles,
    next_action,
    parse_nmap_xml,
    parse_nxc_json_lines,
    parse_nxc_text,
    score_host,
)

STRIKE_RESULTS = RESULTS_DIR / "strike_last.json"
STRIKE_LOG_DIR = LOGS_DIR / "strike"
STRIKE_LOG_DIR.mkdir(parents=True, exist_ok=True)

QUICK_PORTS = "22,80,135,139,443,445,3389,5985,8080"
SMART_PORTS = (
    "21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,993,995,"
    "1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,8080,8443,9200"
)
SMART_SCRIPTS = (
    "smb-vuln-ms17-010,smb-security-mode,ftp-anon,"
    "rdp-enum-encryption,http-title,ssh-hostkey"
)

# ARP + ICMP + TCP/UDP probes so phones, Windows, and IoT that ignore ping still show up.
DISCOVER_FLAGS = [
    "-sn", "-n",
    "-PR",
    "-PE", "-PP",
    "-PS21,22,23,80,135,139,443,445,3389,5985,8080",
    "-PA80,443,445",
    "-T4", "--max-retries", "2",
]

PRESETS = {
    "discover": {
        "label": "Discover",
        "hint": "Find every live host (ARP + TCP ping)",
        "discovery": list(DISCOVER_FLAGS),
        "service": [],
        "nxc": False,
        "nxc_depth": "probe",
        "os_detect": False,
        "stop_after": "discover",
    },
    "quick": {
        "label": "Quick",
        "hint": "Key ports on chosen hosts",
        "discovery": list(DISCOVER_FLAGS),
        "service": ["-Pn", "-sV", "-n", "-T4", "-p", QUICK_PORTS, "--open", "--max-retries", "1"],
        "nxc": True,
        "nxc_depth": "probe",
        "os_detect": False,
        "stop_after": "analyze",
    },
    "smart": {
        "label": "Smart",
        "hint": "Scripts + high-value ports (recommended)",
        "discovery": list(DISCOVER_FLAGS),
        "service": [
            "-Pn", "-sV", "-n", "-T4", "-p", SMART_PORTS, "--open",
            "--script", SMART_SCRIPTS,
        ],
        "nxc": True,
        "nxc_depth": "enum",
        "os_detect": True,
        "stop_after": "analyze",
    },
    "deep": {
        "label": "Deep",
        "hint": "Top 1000 + OS + extra NetExec modules",
        "discovery": list(DISCOVER_FLAGS),
        "service": [
            "-Pn", "-sV", "-sC", "-n", "-T4", "--top-ports", "1000", "--open",
            "--script", SMART_SCRIPTS,
        ],
        "nxc": True,
        "nxc_depth": "vuln",
        "os_detect": True,
        "stop_after": "analyze",
    },
}

NXC_PORT_MAP = {
    21: "ftp",
    22: "ssh",
    88: "ldap",
    135: "wmi",
    139: "smb",
    389: "ldap",
    445: "smb",
    636: "ldap",
    1433: "mssql",
    2049: "nfs",
    3389: "rdp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm",
}

NXC_SVC_MAP = {
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "ssh": "ssh",
    "ftp": "ftp",
    "ldap": "ldap",
    "ms-sql-s": "mssql",
    "http": "http",
    "https": "http",
    "ssl/http": "http",
    "msrpc": "wmi",
    "nfs": "nfs",
    "vnc": "vnc",
}

NXC_PROFILES = {
    "probe": {
        "label": "Identify",
        "hint": "Banner / signing only",
        "flags": {
            "smb": [], "ssh": [], "ftp": [], "winrm": [], "mssql": [],
            "ldap": [], "http": [], "rdp": [], "wmi": [], "nfs": [], "vnc": [],
        },
    },
    "enum": {
        "label": "Enumerate",
        "hint": "Shares, users, sessions",
        "flags": {
            "smb": ["--shares", "--users", "--sessions", "--disks"],
            "ssh": [],
            "ftp": [],
            "winrm": [],
            "mssql": ["--users"],
            "ldap": ["--users", "--groups"],
            "http": [],
            "rdp": [],
            "wmi": ["--users"],
            "nfs": ["--shares"],
            "vnc": [],
        },
    },
    "vuln": {
        "label": "Vuln modules",
        "hint": "NetExec modules for known lab checks",
        "flags": {
            "smb": ["--shares", "--users", "-M", "ms17-010"],
            "ssh": [],
            "ftp": [],
            "winrm": [],
            "mssql": ["--users"],
            "ldap": ["--users"],
            "http": [],
            "rdp": [],
            "wmi": [],
            "nfs": ["--shares"],
            "vnc": [],
        },
    },
}

# Backward-compatible aliases used by the full chain.
NXC_FLAGS = {
    "quick": NXC_PROFILES["probe"]["flags"],
    "probe": NXC_PROFILES["probe"]["flags"],
    "smart": NXC_PROFILES["enum"]["flags"],
    "enum": NXC_PROFILES["enum"]["flags"],
    "deep": NXC_PROFILES["vuln"]["flags"],
    "vuln": NXC_PROFILES["vuln"]["flags"],
}

NXC_PROTOCOLS = ("smb", "ssh", "ftp", "winrm", "mssql", "ldap", "http", "rdp", "wmi", "nfs", "vnc")

_XML_NOISE = re.compile(r"^\s*<(/?\w+|!--|\?xml)")


def find_nxc() -> Optional[str]:
    return shutil.which("nxc") or shutil.which("netexec")


def find_msfconsole() -> Optional[str]:
    for name in ("msfconsole", "/usr/bin/msfconsole", "/opt/metasploit-framework/bin/msfconsole"):
        if name.startswith("/"):
            if Path(name).is_file() and os.access(name, os.X_OK):
                return name
        else:
            found = shutil.which(name)
            if found:
                return found
    return None


def list_lan_interfaces() -> List[str]:
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "up"],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    ifaces: List[str] = []
    for line in (result.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name = parts[1].rstrip(":")
            if name not in ifaces:
                ifaces.append(name)
    return ifaces


def iface_ipv4(iface: str) -> str:
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=5,
        )
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout or "")
        return m.group(1) if m else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def default_gateway(iface: str = "") -> str:
    try:
        cmd = ["ip", "route", "show", "default"]
        if iface:
            cmd += ["dev", iface]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        m = re.search(r"default via (\S+)", result.stdout or "")
        if m:
            return m.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def resolve_strike_iface(requested: str = "") -> str:
    requested = (requested or "").strip()
    if requested and iface_ipv4(requested):
        return requested
    try:
        route_result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        route_result = None
    if route_result:
        m = re.search(r"dev (\S+)", route_result.stdout or "")
        if m and iface_ipv4(m.group(1)):
            return m.group(1)
    for iface in list_lan_interfaces():
        if iface_ipv4(iface):
            return iface
    return requested


@dataclass
class StrikeSession:
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    preset: str = "smart"
    iface: str = ""
    gateway: str = ""
    subnet: str = ""
    phase: str = "idle"
    progress: int = 0
    running: bool = False
    started_at: float = 0.0
    finished_at: float = 0.0
    hosts: List[Dict[str, Any]] = field(default_factory=list)
    top_findings: List[Dict[str, Any]] = field(default_factory=list)
    msf_queue: List[Dict[str, Any]] = field(default_factory=list)
    recommended: Optional[Dict[str, Any]] = None
    msf_results: List[Dict[str, Any]] = field(default_factory=list)
    log_path: str = ""
    error: str = ""
    stop_after: str = "analyze"
    job: str = ""

    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("_stop", None)
        d.pop("_thread", None)
        return d


_active: Optional[StrikeSession] = None
_lock = threading.Lock()
_msf_job_lock = threading.Lock()
_msf_busy = False


def get_active_session() -> Optional[StrikeSession]:
    with _lock:
        return _active


def stop_strike() -> bool:
    with _lock:
        session = _active
    if not session or not session.running:
        return False
    session._stop.set()
    session.phase = "stopping"
    return True


def stop_all_strike() -> None:
    stop_strike()


def _emit(cb: Optional[Callable], event: str, data: dict) -> None:
    if cb:
        cb(event, data)


def _noisy_line(line: str) -> bool:
    return bool(_XML_NOISE.match(line or ""))


def _run_cmd(
    cmd: List[str],
    timeout: int,
    stop: threading.Event,
    log_cb: Optional[Callable[[str], None]] = None,
) -> subprocess.CompletedProcess:
    if log_cb:
        log_cb(f"$ {' '.join(cmd)}")
    if stop.is_set():
        return subprocess.CompletedProcess(cmd, 130, "", "stopped")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))

    chunks: List[str] = []

    def _reader() -> None:
        if not proc.stdout:
            return
        for line in proc.stdout:
            chunks.append(line)
            if log_cb and line.strip() and not _noisy_line(line):
                log_cb(line.rstrip())

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()
    deadline = time.time() + timeout
    while proc.poll() is None:
        if stop.is_set() or time.time() > deadline:
            try:
                os.killpg(proc.pid, 15)
            except (ProcessLookupError, PermissionError):
                proc.terminate()
            break
        time.sleep(0.2)
    reader.join(timeout=3)
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, 9)
        except (ProcessLookupError, PermissionError):
            proc.kill()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    combined = "".join(chunks)
    return subprocess.CompletedProcess(cmd, proc.returncode if proc.returncode is not None else 1, combined, "")


def _nmap_scan(
    iface: str,
    targets: List[str],
    flags: List[str],
    xml_name: str,
    stop: threading.Event,
    log_cb: Optional[Callable[[str], None]],
    timeout: int,
) -> Dict[str, Any]:
    nmap = shutil.which("nmap")
    if not nmap or not targets:
        return {"hosts": [], "summary": {}}
    xml_path = STRIKE_LOG_DIR / xml_name
    cmd = [nmap, *flags, "-e", iface, "-oX", str(xml_path), *targets]
    result = _run_cmd(cmd, timeout=timeout, stop=stop, log_cb=log_cb)
    xml_text = ""
    if xml_path.is_file():
        xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
    if not xml_text:
        xml_text = result.stdout or ""
    return parse_nmap_xml(xml_text)


def valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address((ip or "").strip())
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def sanitize_ips(values: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for raw in values or []:
        ip = str(raw or "").strip()
        if not valid_ipv4(ip) or ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def _blank_host(ip: str, **extra: Any) -> Dict[str, Any]:
    host = {
        "ip": ip,
        "hostname": "",
        "mac": "",
        "vendor": "",
        "os_guess": "",
        "ports": [],
        "services": [],
        "findings": [],
        "sources": ["nmap-discovery"],
        "risk_score": 0,
        "role": "host",
        "next_action": "Scan this device",
        "msf_modules": [],
    }
    host.update(extra)
    return host


def _hosts_by_ip(session: StrikeSession) -> Dict[str, Dict[str, Any]]:
    return {h["ip"]: h for h in session.hosts if h.get("ip")}


def _refresh_session_plan(session: StrikeSession) -> None:
    hosts = list(session.hosts)
    _enrich_hosts(hosts)
    hosts.sort(key=lambda item: -item.get("risk_score", 0))
    session.hosts = hosts
    session.top_findings = _build_top_findings(hosts)
    queue: List[Dict[str, Any]] = []
    for host in hosts:
        for mod in host.get("msf_modules") or []:
            if int(mod.get("severity") or 0) < 4:
                continue
            queue.append({
                **mod,
                "ip": host["ip"],
                "hostname": host.get("hostname") or "",
                "risk_score": host.get("risk_score", 0),
            })
    queue.sort(key=lambda item: (-item.get("severity", 0), -item.get("risk_score", 0)))
    session.msf_queue = queue[:30]
    session.recommended = pick_recommended(hosts)


def _emit_plan(session: StrikeSession, socket_cb: Optional[Callable]) -> None:
    _emit(socket_cb, "hosts", {"hosts": session.hosts, "session_id": session.session_id})
    _emit(socket_cb, "findings", {"findings": session.top_findings, "session_id": session.session_id})
    _emit(socket_cb, "msf", {
        "queue": session.msf_queue,
        "recommended": session.recommended,
        "session_id": session.session_id,
    })


def _protocols_for_host(host: Dict[str, Any]) -> List[str]:
    protos = set()
    for p in host.get("ports") or []:
        port = p.get("port")
        if port in NXC_PORT_MAP:
            protos.add(NXC_PORT_MAP[port])
        svc = (p.get("service") or "").lower()
        mapped = NXC_SVC_MAP.get(svc)
        if mapped:
            protos.add(mapped)
    return sorted(protos)


def _nxc_by_protocol(
    hosts_by_ip: Dict[str, Dict[str, Any]],
    depth: str,
    stop: threading.Event,
    log_cb: Optional[Callable[[str], None]],
    socket_cb: Optional[Callable],
    session_id: str,
    protocol: str = "",
) -> None:
    nxc = find_nxc()
    if not nxc:
        if log_cb:
            log_cb("[!] NetExec (nxc) not installed — skipping protocol checks")
        return

    grouped: Dict[str, List[str]] = {}
    wanted = (protocol or "").lower().strip()
    if wanted and wanted not in NXC_PROTOCOLS:
        if log_cb:
            log_cb(f"[!] Unknown NetExec protocol: {wanted}")
        return
    for ip, host in hosts_by_ip.items():
        protos = [wanted] if wanted else _protocols_for_host(host)
        if wanted and wanted not in _protocols_for_host(host) and not host.get("ports"):
            protos = [wanted]
        for proto in protos:
            if proto:
                grouped.setdefault(proto, []).append(ip)
    if not grouped and wanted:
        grouped[wanted] = list(hosts_by_ip.keys())

    flags_map = NXC_FLAGS.get(depth, NXC_FLAGS["enum"])
    for proto, ips in grouped.items():
        if stop.is_set():
            return
        extra = flags_map.get(proto, [])
        cmd = [nxc, proto, *ips, "--timeout", "8", *extra]
        result = _run_cmd(cmd, timeout=min(240, 30 + 20 * len(ips)), stop=stop, log_cb=log_cb)
        text = result.stdout or ""
        batch = parse_nxc_json_lines(text) or parse_nxc_text(text, protocol=proto)
        by_ip: Dict[str, List[Dict[str, Any]]] = {}
        leftover: List[Dict[str, Any]] = []
        for item in batch:
            ip = item.get("ip")
            if ip and ip in hosts_by_ip:
                by_ip.setdefault(ip, []).append(item)
            else:
                leftover.append(item)
        if leftover and len(ips) == 1:
            by_ip.setdefault(ips[0], []).extend(leftover)
        elif leftover:
            for item in leftover:
                for ip in ips:
                    row = dict(item)
                    row["ip"] = ip
                    by_ip.setdefault(ip, []).append(row)

        for ip, findings in by_ip.items():
            host = hosts_by_ip[ip]
            host.setdefault("findings", []).extend(findings)
            if "netexec" not in host.get("sources", []):
                host.setdefault("sources", []).append("netexec")
            if findings and not host.get("hostname"):
                host["hostname"] = next((f.get("hostname") or "" for f in findings if f.get("hostname")), "")
            _emit(socket_cb, "host_update", {"host": host, "session_id": session_id})


def _enrich_hosts(hosts: List[Dict[str, Any]]) -> None:
    for host in hosts:
        host["findings"] = dedupe_findings(host.get("findings") or [])
        host["role"] = classify_role(host)
        host["msf_modules"] = suggest_msf(host)
        host["risk_score"] = score_host(host)
        host["next_action"] = next_action(host)


def _build_top_findings(hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    all_findings: List[Dict[str, Any]] = []
    for host in hosts:
        for finding in host.get("findings") or []:
            if int(finding.get("severity") or 0) < 4:
                continue
            row = dict(finding)
            row["ip"] = row.get("ip") or host.get("ip")
            row["hostname"] = row.get("hostname") or host.get("hostname")
            all_findings.append(row)
    all_findings.sort(key=lambda x: -int(x.get("severity", 0)))
    return dedupe_findings(all_findings)[:40]


def _save_report(session: StrikeSession) -> None:
    payload = {
        "session_id": session.session_id,
        "preset": session.preset,
        "iface": session.iface,
        "subnet": session.subnet,
        "finished_at": session.finished_at,
        "hosts": session.hosts,
        "top_findings": session.top_findings,
        "msf_queue": session.msf_queue,
        "recommended": session.recommended,
        "msf_results": session.msf_results,
    }
    tmp = STRIKE_RESULTS.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(STRIKE_RESULTS)


def _run_chain(
    session: StrikeSession,
    socket_cb: Optional[Callable],
    log_cb: Optional[Callable[[str], None]],
) -> None:
    preset = PRESETS.get(session.preset, PRESETS["smart"])
    hosts_by_ip: Dict[str, Dict[str, Any]] = {}

    def phase(name: str, pct: int) -> None:
        session.phase = name
        session.progress = pct
        _emit(socket_cb, "phase", {"phase": name, "progress": pct, "session_id": session.session_id})

    try:
        phase("discover", 8)
        target = session.subnet or gateway_subnet(session.gateway) or session.gateway
        if not target:
            raise ValueError("Could not determine scan target (set gateway or subnet)")

        discovered = _nmap_scan(
            session.iface,
            [target],
            list(preset["discovery"]),
            f"nmap_disc_{session.session_id}.xml",
            session._stop,
            log_cb,
            timeout=180,
        )
        if session._stop.is_set():
            raise InterruptedError("stopped")

        live_ips = [h["ip"] for h in discovered.get("hosts") or [] if h.get("ip")]
        for host in discovered.get("hosts") or []:
            if host.get("ip"):
                hosts_by_ip[host["ip"]] = host
        for ip in live_ips:
            if ip not in hosts_by_ip:
                hosts_by_ip[ip] = _blank_host(ip)
        session.hosts = list(hosts_by_ip.values())
        _emit(socket_cb, "hosts", {"hosts": session.hosts, "session_id": session.session_id})
        if log_cb:
            log_cb(f"[+] Discovery found {len(live_ips)} live host(s)")

        if session.stop_after == "discover" or not live_ips:
            _refresh_session_plan(session)
            session.phase = "done"
            session.progress = 100
            session.finished_at = time.time()
            _save_report(session)
            _emit_plan(session, socket_cb)
            _emit(socket_cb, "complete", session.to_dict())
            return

        phase("nmap", 28)
        service_flags = list(preset["service"])
        if preset.get("os_detect") and os.geteuid() == 0:
            service_flags += ["-O", "--osscan-limit"]

        nmap_data = _nmap_scan(
            session.iface,
            live_ips,
            service_flags,
            f"nmap_svc_{session.session_id}.xml",
            session._stop,
            log_cb,
            timeout=max(420, 25 * len(live_ips)),
        )
        if session._stop.is_set():
            raise InterruptedError("stopped")

        for host in nmap_data.get("hosts") or []:
            current = hosts_by_ip.get(host["ip"], _blank_host(host["ip"]))
            hosts_by_ip[host["ip"]] = merge_host_profiles(current, host)
        session.hosts = list(hosts_by_ip.values())
        _emit(socket_cb, "hosts", {"hosts": session.hosts, "session_id": session.session_id})

        if session.stop_after == "nmap":
            _refresh_session_plan(session)
            session.phase = "done"
            session.progress = 100
            session.finished_at = time.time()
            _save_report(session)
            _emit_plan(session, socket_cb)
            _emit(socket_cb, "complete", session.to_dict())
            return

        phase("netexec", 58)
        if preset.get("nxc"):
            _nxc_by_protocol(
                hosts_by_ip,
                str(preset.get("nxc_depth") or "enum"),
                session._stop,
                log_cb,
                socket_cb,
                session.session_id,
            )
        elif log_cb:
            log_cb("[*] NetExec skipped for this preset")

        if session._stop.is_set():
            raise InterruptedError("stopped")

        phase("analyze", 88)
        session.hosts = list(hosts_by_ip.values())
        _refresh_session_plan(session)
        session.phase = "done"
        session.progress = 100
        session.finished_at = time.time()
        _save_report(session)
        _emit_plan(session, socket_cb)
        _emit(socket_cb, "complete", session.to_dict())
    except InterruptedError:
        session.phase = "stopped"
        session.error = "Stopped by user"
        _emit(socket_cb, "complete", session.to_dict())
    except Exception as exc:
        session.phase = "failed"
        session.error = str(exc)
        if log_cb:
            log_cb(f"[!] Strike failed: {exc}")
        _emit(socket_cb, "complete", session.to_dict())
    finally:
        session.running = False


def start_strike(
    preset: str = "smart",
    iface: str = "",
    gateway: str = "",
    subnet: str = "",
    stop_after: str = "",
    socket_cb: Optional[Callable] = None,
    log_cb: Optional[Callable[[str], None]] = None,
) -> StrikeSession:
    global _active
    with _lock:
        if _active and _active.running:
            raise RuntimeError("A Strike chain is already running")
        resolved = resolve_strike_iface(iface)
        chosen = preset if preset in PRESETS else "smart"
        session = StrikeSession(
            preset=chosen,
            iface=resolved,
            gateway=gateway or default_gateway(resolved),
            subnet=subnet or "",
            running=True,
            started_at=time.time(),
            phase="starting",
            progress=0,
            job="discover" if (stop_after or PRESETS[chosen].get("stop_after")) == "discover" else "chain",
            stop_after=stop_after or str(PRESETS[chosen].get("stop_after") or "analyze"),
        )
        if not session.subnet and session.gateway:
            session.subnet = gateway_subnet(session.gateway)
        session.log_path = str(STRIKE_LOG_DIR / f"strike_{session.session_id}.log")
        _active = session

    if not iface_ipv4(session.iface):
        session.running = False
        session.phase = "failed"
        session.error = f"Interface {session.iface or '(none)'} has no IPv4 — join the lab LAN first"
        return session

    if not shutil.which("nmap"):
        session.running = False
        session.phase = "failed"
        session.error = "nmap is not installed (sudo apt install nmap)"
        return session

    session._stop.clear()
    session._thread = threading.Thread(
        target=_run_chain,
        args=(session, socket_cb, log_cb),
        daemon=True,
    )
    session._thread.start()
    return session


def _bind_session(session: StrikeSession) -> None:
    global _active
    with _lock:
        _active = session


def ensure_session(
    iface: str = "",
    gateway: str = "",
    subnet: str = "",
) -> StrikeSession:
    session = get_active_session()
    if session and session.running:
        raise RuntimeError("A Strike job is already running")
    if session:
        if iface:
            session.iface = resolve_strike_iface(iface)
        if gateway:
            session.gateway = gateway
        if subnet:
            session.subnet = subnet
        return session

    report = load_last_report()
    resolved = resolve_strike_iface(iface or report.get("iface") or "")
    session = StrikeSession(
        session_id=str(report.get("session_id") or uuid.uuid4().hex[:8]),
        preset=str(report.get("preset") or "smart"),
        iface=resolved,
        gateway=gateway or report.get("gateway") or default_gateway(resolved),
        subnet=subnet or report.get("subnet") or "",
        hosts=list(report.get("hosts") or []),
        top_findings=list(report.get("top_findings") or []),
        msf_queue=list(report.get("msf_queue") or []),
        recommended=report.get("recommended"),
        msf_results=list(report.get("msf_results") or []),
        phase="idle",
    )
    if not session.subnet and session.gateway:
        session.subnet = gateway_subnet(session.gateway)
    _bind_session(session)
    return session


def _run_host_scans(
    session: StrikeSession,
    ips: List[str],
    preset_name: str,
    run_nxc: bool,
    socket_cb: Optional[Callable],
    log_cb: Optional[Callable[[str], None]],
) -> None:
    preset = PRESETS.get(preset_name, PRESETS["smart"])
    hosts_by_ip = _hosts_by_ip(session)
    try:
        session.phase = "nmap"
        session.progress = 20
        _emit(socket_cb, "phase", {"phase": "nmap", "progress": 20, "session_id": session.session_id})
        if log_cb:
            log_cb(f"[*] Nmap service scan: {', '.join(ips)}")

        service_flags = list(preset.get("service") or PRESETS["smart"]["service"])
        if preset.get("os_detect") and os.geteuid() == 0:
            service_flags += ["-O", "--osscan-limit"]

        nmap_data = _nmap_scan(
            session.iface,
            ips,
            service_flags,
            f"nmap_host_{session.session_id}_{int(time.time())}.xml",
            session._stop,
            log_cb,
            timeout=max(180, 40 * len(ips)),
        )
        if session._stop.is_set():
            raise InterruptedError("stopped")

        for host in nmap_data.get("hosts") or []:
            current = hosts_by_ip.get(host["ip"], _blank_host(host["ip"]))
            hosts_by_ip[host["ip"]] = merge_host_profiles(current, host)
            _emit(socket_cb, "host_update", {"host": hosts_by_ip[host["ip"]], "session_id": session.session_id})
        for ip in ips:
            hosts_by_ip.setdefault(ip, _blank_host(ip))

        if run_nxc:
            session.phase = "netexec"
            session.progress = 60
            _emit(socket_cb, "phase", {"phase": "netexec", "progress": 60, "session_id": session.session_id})
            selected = {ip: hosts_by_ip[ip] for ip in ips if ip in hosts_by_ip}
            _nxc_by_protocol(
                selected,
                str(preset.get("nxc_depth") or "enum"),
                session._stop,
                log_cb,
                socket_cb,
                session.session_id,
            )

        if session._stop.is_set():
            raise InterruptedError("stopped")

        session.hosts = list(hosts_by_ip.values())
        session.phase = "analyze"
        session.progress = 90
        _refresh_session_plan(session)
        session.phase = "done"
        session.progress = 100
        session.finished_at = time.time()
        _save_report(session)
        _emit_plan(session, socket_cb)
        _emit(socket_cb, "complete", session.to_dict())
    except InterruptedError:
        session.phase = "stopped"
        session.error = "Stopped by user"
        _emit(socket_cb, "complete", session.to_dict())
    except Exception as exc:
        session.phase = "failed"
        session.error = str(exc)
        if log_cb:
            log_cb(f"[!] Host scan failed: {exc}")
        _emit(socket_cb, "complete", session.to_dict())
    finally:
        session.running = False
        session.job = ""


def start_host_scan(
    ips: List[str],
    preset: str = "smart",
    run_nxc: bool = False,
    iface: str = "",
    gateway: str = "",
    subnet: str = "",
    socket_cb: Optional[Callable] = None,
    log_cb: Optional[Callable[[str], None]] = None,
) -> StrikeSession:
    targets = sanitize_ips(ips)
    if not targets:
        raise ValueError("Select at least one IPv4 host to scan")
    session = ensure_session(iface=iface, gateway=gateway, subnet=subnet)
    if not session.iface or not iface_ipv4(session.iface):
        raise RuntimeError(f"Interface {session.iface or '(none)'} has no IPv4 — join the lab LAN first")
    if not shutil.which("nmap"):
        raise RuntimeError("nmap is not installed (sudo apt install nmap)")

    session.running = True
    session.error = ""
    session.preset = preset if preset in PRESETS and preset != "discover" else "smart"
    session.job = "scan"
    session.started_at = time.time()
    session._stop.clear()
    session._thread = threading.Thread(
        target=_run_host_scans,
        args=(session, targets, session.preset, run_nxc, socket_cb, log_cb),
        daemon=True,
    )
    session._thread.start()
    return session


def _run_nxc_job(
    session: StrikeSession,
    ips: List[str],
    profile: str,
    protocol: str,
    socket_cb: Optional[Callable],
    log_cb: Optional[Callable[[str], None]],
) -> None:
    hosts_by_ip = _hosts_by_ip(session)
    for ip in ips:
        hosts_by_ip.setdefault(ip, _blank_host(ip))
    try:
        session.phase = "netexec"
        session.progress = 40
        _emit(socket_cb, "phase", {"phase": "netexec", "progress": 40, "session_id": session.session_id})
        selected = {ip: hosts_by_ip[ip] for ip in ips}
        _nxc_by_protocol(
            selected,
            profile if profile in NXC_FLAGS else "enum",
            session._stop,
            log_cb,
            socket_cb,
            session.session_id,
            protocol=protocol,
        )
        if session._stop.is_set():
            raise InterruptedError("stopped")
        session.hosts = list(hosts_by_ip.values())
        _refresh_session_plan(session)
        session.phase = "done"
        session.progress = 100
        session.finished_at = time.time()
        _save_report(session)
        _emit_plan(session, socket_cb)
        _emit(socket_cb, "complete", session.to_dict())
    except InterruptedError:
        session.phase = "stopped"
        session.error = "Stopped by user"
        _emit(socket_cb, "complete", session.to_dict())
    except Exception as exc:
        session.phase = "failed"
        session.error = str(exc)
        if log_cb:
            log_cb(f"[!] NetExec failed: {exc}")
        _emit(socket_cb, "complete", session.to_dict())
    finally:
        session.running = False
        session.job = ""


def start_nxc(
    ips: List[str],
    protocol: str = "",
    profile: str = "enum",
    iface: str = "",
    gateway: str = "",
    subnet: str = "",
    socket_cb: Optional[Callable] = None,
    log_cb: Optional[Callable[[str], None]] = None,
) -> StrikeSession:
    targets = sanitize_ips(ips)
    if not targets:
        raise ValueError("Select at least one IPv4 host for NetExec")
    proto = (protocol or "").lower().strip()
    if proto and proto not in NXC_PROTOCOLS:
        raise ValueError(f"Unknown NetExec protocol: {proto}")
    if not find_nxc():
        raise RuntimeError("NetExec (nxc) is not installed")

    session = ensure_session(iface=iface, gateway=gateway, subnet=subnet)
    session.running = True
    session.error = ""
    session.job = "nxc"
    session.started_at = time.time()
    session._stop.clear()
    session._thread = threading.Thread(
        target=_run_nxc_job,
        args=(session, targets, profile if profile in NXC_FLAGS else "enum", proto, socket_cb, log_cb),
        daemon=True,
    )
    session._thread.start()
    return session


def host_msf_queue(ip: str) -> List[Dict[str, Any]]:
    session = get_active_session()
    report = load_last_report()
    hosts = (session.hosts if session else None) or report.get("hosts") or []
    for host in hosts:
        if host.get("ip") == ip:
            return [
                {**mod, "ip": ip, "hostname": host.get("hostname") or ""}
                for mod in (host.get("msf_modules") or [])
            ]
    return []


def _summarize_msf(text: str) -> Dict[str, Any]:
    low = (text or "").lower()
    if "the target is vulnerable" in low or "host is likely vulnerable" in low:
        verdict = "vulnerable"
    elif "the target is not vulnerable" in low or "is not vulnerable" in low:
        verdict = "safe"
    elif "session" in low and ("opened" in low or "created" in low):
        verdict = "session"
    elif "check is not implemented" in low:
        verdict = "no-check"
    elif "unknown" in low and "vulnerable" in low:
        verdict = "unknown"
    else:
        verdict = "done"
    return {
        "verdict": verdict,
        "likely_vulnerable": verdict in ("vulnerable", "session"),
    }


def run_msf_module(
    module: str,
    rhosts: str,
    action: str = "check",
    extra: Optional[Dict[str, str]] = None,
    timeout: int = 240,
    lhost: str = "",
) -> Dict[str, Any]:
    """Run a single Metasploit module non-interactively via resource script."""
    msf = find_msfconsole()
    if not msf:
        return {"ok": False, "error": "msfconsole not found (install metasploit-framework)"}
    if not re.match(r"^[a-zA-Z0-9_/]+$", module or ""):
        return {"ok": False, "error": "Invalid module path"}
    if not re.match(r"^[\d.]+$", (rhosts or "").strip()):
        return {"ok": False, "error": "Invalid RHOSTS (single IPv4 only)"}

    action = (action or "check").lower()
    if action not in ("check", "exploit", "run"):
        action = "check"

    lines = [
        "setg LogLevel 1",
        f"use {module}",
        f"set RHOSTS {rhosts.strip()}",
    ]
    if lhost and re.match(r"^[\d.]+$", lhost):
        lines.append(f"set LHOST {lhost}")
    for key, val in (extra or {}).items():
        if re.match(r"^[A-Z0-9_]+$", key) and val is not None:
            lines.append(f"set {key} {val}")
    if action == "exploit" and module.startswith("exploit/"):
        lines += ["set ExitOnSession false", "exploit -j -z", "sleep 4"]
    elif action == "check" and module.startswith("exploit/"):
        lines.append("check")
    else:
        lines.append("run")
    lines.append("exit -y")

    rc_path = STRIKE_LOG_DIR / f"msf_{uuid.uuid4().hex[:8]}.rc"
    log_path = STRIKE_LOG_DIR / f"msf_{uuid.uuid4().hex[:8]}.log"
    rc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        result = subprocess.run(
            [msf, "-q", "-r", str(rc_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Metasploit timed out", "module": module, "rhosts": rhosts}
    combined = f"{result.stdout or ''}\n{result.stderr or ''}"
    log_path.write_text(combined, encoding="utf-8")
    summary = _summarize_msf(combined)
    return {
        "ok": True,
        "module": module,
        "rhosts": rhosts,
        "action": action,
        "log": combined[-6000:],
        "log_path": str(log_path),
        **summary,
    }


def run_msf_auto_check(
    items: List[Dict[str, Any]],
    socket_cb: Optional[Callable] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    lhost: str = "",
) -> List[Dict[str, Any]]:
    """Run Check (never exploit) on the top unique module+host pairs."""
    global _msf_busy
    with _msf_job_lock:
        if _msf_busy:
            raise RuntimeError("A Metasploit job is already running")
        _msf_busy = True

    results: List[Dict[str, Any]] = []
    seen = set()
    try:
        for item in items:
            key = (item.get("module"), item.get("ip") or item.get("rhosts"))
            if key in seen or not key[0] or not key[1]:
                continue
            seen.add(key)
            if len(results) >= 8:
                break
            if log_cb:
                log_cb(f"[🎯] Auto-check {item.get('title') or item['module']} → {key[1]}")
            result = run_msf_module(
                str(item["module"]),
                str(key[1]),
                action="check",
                lhost=lhost,
            )
            row = {**item, **result, "ip": key[1]}
            results.append(row)
            _emit(socket_cb, "msf_result", row)
        session = get_active_session()
        if session:
            session.msf_results = (session.msf_results + results)[-30:]
            _save_report(session)
        _emit(socket_cb, "msf_batch", {"results": results})
        return results
    finally:
        with _msf_job_lock:
            _msf_busy = False


def claim_msf_job() -> bool:
    global _msf_busy
    with _msf_job_lock:
        if _msf_busy:
            return False
        _msf_busy = True
        return True


def release_msf_job() -> None:
    global _msf_busy
    with _msf_job_lock:
        _msf_busy = False


def record_msf_result(result: Dict[str, Any]) -> None:
    session = get_active_session()
    if not session:
        return
    session.msf_results = (session.msf_results + [result])[-30:]
    _save_report(session)


def load_last_report() -> Dict[str, Any]:
    if not STRIKE_RESULTS.is_file():
        return {}
    try:
        return json.loads(STRIKE_RESULTS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
