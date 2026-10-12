#!/usr/bin/env python3
"""Parse Nmap XML and NetExec output; score hosts and pick next actions."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List


def extract_nmap_xml(text: str) -> str:
    """Pull the <nmaprun> document out of mixed stdout."""
    if not text:
        return ""
    start = text.find("<nmaprun")
    end = text.rfind("</nmaprun>")
    if start >= 0 and end > start:
        return text[start:end + len("</nmaprun>")]
    return text if "<host" in text else ""


def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    """Return {hosts: [...], summary: {...}} from Nmap -oX output."""
    hosts: List[Dict[str, Any]] = []
    raw = extract_nmap_xml(xml_text or "")
    if not raw.strip():
        return {"hosts": hosts, "summary": {"live": 0, "ports_open": 0}}

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {"hosts": hosts, "summary": {"live": 0, "ports_open": 0, "parse_error": True}}

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = ""
        mac = ""
        vendor = ""
        for addr in host_el.findall("address"):
            kind = addr.get("addrtype")
            if kind == "ipv4":
                ip = addr.get("addr", "")
            elif kind == "mac":
                mac = (addr.get("addr") or "").upper()
                vendor = addr.get("vendor") or ""
        if not ip:
            continue

        hostname = ""
        for hn in host_el.findall("./hostnames/hostname"):
            if hn.get("type") == "user" or not hostname:
                hostname = hn.get("name") or hostname

        os_guess = ""
        os_el = host_el.find("./os/osmatch")
        if os_el is not None:
            os_guess = os_el.get("name") or ""

        ports: List[Dict[str, Any]] = []
        services: List[str] = []
        findings: List[Dict[str, Any]] = []
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is not None and state_el.get("state") != "open":
                continue
            port_id = port_el.get("portid", "")
            proto = port_el.get("protocol", "tcp")
            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "") if svc_el is not None else ""
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""
            banner = " ".join(x for x in (product, version, extrainfo) if x).strip()
            script_findings: List[Dict[str, str]] = []
            for script in port_el.findall("script"):
                script_id = script.get("id", "")
                output = (script.get("output") or "")[:600]
                script_findings.append({"id": script_id, "output": output})
                parsed = _finding_from_nmap_script(script_id, output, ip, port_id, svc_name)
                if parsed:
                    findings.append(parsed)
            ports.append({
                "port": int(port_id) if port_id.isdigit() else port_id,
                "proto": proto,
                "service": svc_name,
                "banner": banner,
                "scripts": script_findings,
            })
            label = svc_name or "unknown"
            if banner:
                label = f"{label} ({banner})"
            services.append(f"{port_id}/{proto}:{label}")

        for script in host_el.findall("./hostscript/script"):
            parsed = _finding_from_nmap_script(
                script.get("id", ""),
                (script.get("output") or "")[:600],
                ip,
                0,
                "host",
            )
            if parsed:
                findings.append(parsed)

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "os_guess": os_guess,
            "ports": ports,
            "services": services,
            "findings": findings,
            "risk_score": 0,
            "role": "host",
            "next_action": "",
            "sources": ["nmap"],
        })

    open_ports = sum(len(h["ports"]) for h in hosts)
    return {
        "hosts": hosts,
        "summary": {"live": len(hosts), "ports_open": open_ports},
    }


def _finding_from_nmap_script(
    script_id: str,
    output: str,
    ip: str,
    port: Any,
    protocol: str,
) -> Dict[str, Any] | None:
    if not output.strip():
        return None
    upper = output.upper()
    interesting = (
        "VULNERABLE" in upper
        or "CVE-" in upper
        or "ANONYMOUS" in upper
        or "MESSAGE_SIGNING" in upper
        or "SIGNING DISABLED" in upper
    )
    if not interesting and script_id not in {
        "smb-vuln-ms17-010",
        "smb-security-mode",
        "ftp-anon",
        "rdp-enum-encryption",
        "http-title",
    }:
        return None
    if script_id == "http-title" and "VULNERABLE" not in upper:
        title = output.strip().splitlines()[0][:80]
        if not title:
            return None
        return {
            "ip": ip,
            "port": int(port) if str(port).isdigit() else 0,
            "protocol": protocol or "http",
            "title": f"HTTP title: {title}",
            "detail": output[:300],
            "severity": 3,
            "source": "nmap",
        }
    severity = 9 if "VULNERABLE" in upper else 7 if "CVE-" in upper else 6
    if "NOT VULNERABLE" in upper or "FALSE" in upper and "VULNERABLE" in upper:
        severity = 2
    return {
        "ip": ip,
        "port": int(port) if str(port).isdigit() else 0,
        "protocol": protocol or "tcp",
        "title": f"nmap:{script_id}",
        "detail": output[:400],
        "severity": severity,
        "source": "nmap",
    }


NXC_LINE = re.compile(
    r"^(?P<proto>\S+)\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<port>\d+)\s+(?P<host>\S+)?\s*(?P<msg>.*)$"
)

_NOISE = re.compile(
    r"(starting|stopping|timeout|connection refused|no route|failed to|"
    r"unable to|error initializing|module failed|keyboard-interactive)",
    re.I,
)


def _clean_title(msg: str) -> str:
    return re.sub(r"^\[.\]\s*", "", (msg or "").strip())[:140]


def _nxc_severity(msg: str) -> int:
    m = (msg or "").lower()
    if _NOISE.search(m) and not any(k in m for k in ("vuln", "cve", "pwn", "signing")):
        return 0
    if any(k in m for k in ("pwn3d", "pwned", "ms17-010", "eternalblue", "zerologon")):
        return 10
    if any(k in m for k in ("signing:false", "signing disabled", "message signing is disabled")):
        return 9
    if any(k in m for k in ("cve-", "vulnerable", "anonymous", "guest login", "null session")):
        return 9
    if m.strip().startswith("[!]"):
        return 8
    if "read" in m and "share" in m:
        return 7
    if m.strip().startswith("[+]"):
        if any(k in m for k in ("windows", "unix", "name:", "domain:", "os:")):
            return 4
        return 6
    if m.strip().startswith("[-]"):
        return 2
    if m.strip().startswith("[*]"):
        return 3
    return 5


def _keep_nxc_finding(msg: str, severity: int) -> bool:
    if severity <= 0:
        return False
    if severity <= 2 and not re.search(r"cve|vuln|signing", msg, re.I):
        return False
    return True


def parse_nxc_text(text: str, protocol: str = "") -> List[Dict[str, Any]]:
    """Parse NetExec console lines into finding records."""
    findings: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("[*]") and "Running" in line:
            continue
        m = NXC_LINE.match(line)
        if m:
            msg = (m.group("msg") or "").strip()
            severity = _nxc_severity(msg)
            if not _keep_nxc_finding(msg, severity):
                continue
            findings.append({
                "ip": m.group("ip"),
                "port": int(m.group("port")) if m.group("port").isdigit() else 0,
                "protocol": (m.group("proto") or protocol).lower(),
                "hostname": (m.group("host") or "").strip(),
                "detail": msg,
                "title": _clean_title(msg) or f"{protocol} result",
                "severity": severity,
                "source": "netexec",
            })
            continue
        if protocol and ("[+]" in line or "[!]" in line or "CVE" in line.upper()):
            severity = _nxc_severity(line)
            if not _keep_nxc_finding(line, severity):
                continue
            findings.append({
                "ip": "",
                "port": 0,
                "protocol": protocol,
                "hostname": "",
                "detail": line,
                "title": _clean_title(line),
                "severity": severity,
                "source": "netexec",
            })
    return findings


def parse_nxc_json_lines(text: str) -> List[Dict[str, Any]]:
    """Best-effort parse for `nxc --json` line-delimited output."""
    findings: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = row.get("ip") or row.get("host") or ""
        msg = row.get("message") or row.get("output") or json.dumps(row)[:200]
        severity = _nxc_severity(str(msg))
        if not _keep_nxc_finding(str(msg), severity):
            continue
        findings.append({
            "ip": ip,
            "port": int(row.get("port") or 0),
            "protocol": row.get("protocol") or row.get("type") or "nxc",
            "hostname": row.get("hostname") or "",
            "detail": msg,
            "title": _clean_title(str(msg)),
            "severity": severity,
            "source": "netexec",
        })
    return findings


def merge_host_profiles(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two host dicts (same IP)."""
    merged = dict(base)
    for key in ("hostname", "mac", "vendor", "os_guess"):
        if not merged.get(key) and extra.get(key):
            merged[key] = extra[key]
    merged.setdefault("ports", [])
    merged.setdefault("services", [])
    merged.setdefault("findings", [])
    merged.setdefault("sources", [])

    known_ports = {(p.get("port"), p.get("proto")) for p in merged["ports"]}
    for p in extra.get("ports") or []:
        key = (p.get("port"), p.get("proto"))
        if key not in known_ports:
            merged["ports"].append(p)
            known_ports.add(key)

    for svc in extra.get("services") or []:
        if svc not in merged["services"]:
            merged["services"].append(svc)

    merged["findings"].extend(extra.get("findings") or [])

    for src in extra.get("sources") or []:
        if src not in merged["sources"]:
            merged["sources"].append(src)

    return merged


def classify_role(host: Dict[str, Any]) -> str:
    ports = {p.get("port") for p in host.get("ports") or []}
    blob = " ".join(
        [
            host.get("os_guess") or "",
            host.get("hostname") or "",
            " ".join(host.get("services") or []),
            " ".join(f.get("title", "") for f in host.get("findings") or []),
        ]
    ).lower()
    if 88 in ports or 389 in ports or "domain controller" in blob or blob.endswith("dc") or " dc " in f" {blob} ":
        return "dc"
    if 445 in ports and any(k in blob for k in ("share", "read", "write", "disk")):
        return "file"
    if 3389 in ports or 5985 in ports or 5986 in ports or "windows" in blob:
        return "windows"
    if any(p in ports for p in (80, 443, 8080, 8443)):
        return "web"
    if 22 in ports and 445 not in ports:
        return "linux"
    return "host"


def next_action(host: Dict[str, Any]) -> str:
    mods = host.get("msf_modules") or []
    if mods:
        top = mods[0]
        verb = "Check" if top.get("action") == "check" or not top.get("can_exploit") else "Review"
        return f"{verb} {top.get('title', 'top module')} on {host.get('ip')}"
    highs = [f for f in host.get("findings") or [] if int(f.get("severity") or 0) >= 8]
    if highs:
        return f"Review: {highs[0].get('title') or 'high finding'}"
    if host.get("ports"):
        return "No critical hits — run NetExec or review services"
    return "Alive — nmap this device next"


def score_host(host: Dict[str, Any]) -> int:
    """0–100 risk score from ports, role, and findings."""
    score = 0
    for p in host.get("ports") or []:
        port = p.get("port")
        if port in (445, 3389, 23, 21, 1433, 5985, 5986, 135):
            score += 8
        elif port in (22, 80, 443, 8080, 8443, 389, 88):
            score += 4
        else:
            score += 1
    seen = set()
    for f in host.get("findings") or []:
        key = (f.get("title"), f.get("ip"), f.get("port"))
        if key in seen:
            continue
        seen.add(key)
        score += min(18, int(f.get("severity") or 5) * 2)
    if host.get("role") == "dc":
        score += 12
    elif host.get("role") == "file":
        score += 6
    return min(100, score)


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for item in findings:
        key = (
            item.get("ip"),
            item.get("title"),
            item.get("port"),
            item.get("source"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
