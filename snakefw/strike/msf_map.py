#!/usr/bin/env python3
"""Map open services and findings to Metasploit suggestions and a next step."""
from __future__ import annotations

import re
from typing import Any, Dict, List

# pattern, module, action, title, severity, why
MSF_RULES: List[tuple] = [
    (r"ms17-010|ms17_010|eternalblue",
     "exploit/windows/smb/ms17_010_eternalblue", "check",
     "MS17-010 EternalBlue", 10, "SMB vuln signature matched"),
    (r"ms08-067|ms08_067",
     "exploit/windows/smb/ms08_067_netapi", "check",
     "MS08-067 NetAPI", 9, "Legacy SMB vuln signature"),
    (r"signing:?\s*false|signing disabled|message_signing.?disabled",
     "auxiliary/scanner/smb/smb_ms17_010", "check",
     "SMB signing off — MS17-010 check", 8, "Unsigned SMB raises wormable risk"),
    (r"null session|null.?session|guest login",
     "auxiliary/scanner/smb/smb_enumshares", "check",
     "SMB guest / null session", 7, "Unauthenticated SMB access"),
    (r"vsftpd 2\.3\.4",
     "exploit/unix/ftp/vsftpd_234_backdoor", "check",
     "vsFTPd 2.3.4 backdoor", 9, "Known lab backdoor banner"),
    (r"anonymous",
     "auxiliary/scanner/ftp/anonymous", "check",
     "FTP anonymous login", 6, "Anonymous FTP reported"),
    (r"apache.*struts|struts2",
     "exploit/multi/http/struts2_content_type_ognl", "check",
     "Apache Struts RCE", 9, "Struts fingerprint"),
    (r"shellshock|cve-2014-6271",
     "exploit/multi/http/apache_mod_cgi_bash_env_exec", "check",
     "Shellshock", 8, "CGI bash env signature"),
    (r"tomcat.*manager|/manager/html",
     "auxiliary/scanner/http/tomcat_mgr_login", "check",
     "Tomcat Manager login", 7, "Manager path exposed"),
    (r"bluekeep|cve-2019-0708",
     "auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "check",
     "BlueKeep (RDP)", 9, "RDP vuln hint"),
    (r"heartbleed|cve-2014-0160",
     "auxiliary/scanner/ssl/openssl_heartbleed", "check",
     "Heartbleed", 8, "OpenSSL heartbeat signature"),
    (r"openssh[_\s]7\.[0-4]",
     "auxiliary/scanner/ssh/ssh_version", "check",
     "Legacy OpenSSH", 5, "Old OpenSSH banner"),
]

PORT_DEFAULTS: Dict[int, List[Dict[str, Any]]] = {
    21: [
        {"module": "auxiliary/scanner/ftp/anonymous", "action": "check",
         "title": "FTP — anonymous check", "severity": 5, "why": "FTP is open"},
    ],
    22: [
        {"module": "auxiliary/scanner/ssh/ssh_version", "action": "check",
         "title": "SSH — version fingerprint", "severity": 3, "why": "SSH is open"},
    ],
    23: [
        {"module": "auxiliary/scanner/telnet/telnet_version", "action": "check",
         "title": "Telnet — version", "severity": 6, "why": "Cleartext Telnet"},
    ],
    80: [
        {"module": "auxiliary/scanner/http/http_version", "action": "check",
         "title": "HTTP — version", "severity": 3, "why": "HTTP is open"},
    ],
    135: [
        {"module": "auxiliary/scanner/smb/smb_ms17_010", "action": "check",
         "title": "RPC/SMB — MS17-010 check", "severity": 6, "why": "Windows RPC exposed"},
    ],
    443: [
        {"module": "auxiliary/scanner/http/http_version", "action": "check",
         "title": "HTTPS — version", "severity": 3, "why": "HTTPS is open"},
    ],
    445: [
        {"module": "auxiliary/scanner/smb/smb_ms17_010", "action": "check",
         "title": "SMB — MS17-010 check", "severity": 8, "why": "SMB 445 is the highest-yield check"},
        {"module": "auxiliary/scanner/smb/smb_enumshares", "action": "check",
         "title": "SMB — share enum", "severity": 5, "why": "List shares without creds if allowed"},
    ],
    1433: [
        {"module": "auxiliary/scanner/mssql/mssql_login", "action": "check",
         "title": "MSSQL — login check", "severity": 6, "why": "MSSQL exposed"},
    ],
    3306: [
        {"module": "auxiliary/scanner/mysql/mysql_version", "action": "check",
         "title": "MySQL — version", "severity": 4, "why": "MySQL exposed"},
    ],
    3389: [
        {"module": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "action": "check",
         "title": "RDP — BlueKeep check", "severity": 8, "why": "RDP is a common lab win"},
    ],
    5900: [
        {"module": "auxiliary/scanner/vnc/vnc_none_auth", "action": "check",
         "title": "VNC — no-auth check", "severity": 7, "why": "VNC often has no password in labs"},
    ],
    5985: [
        {"module": "auxiliary/scanner/winrm/winrm_auth_methods", "action": "check",
         "title": "WinRM — auth methods", "severity": 5, "why": "WinRM is a post-enum path"},
    ],
    5986: [
        {"module": "auxiliary/scanner/winrm/winrm_auth_methods", "action": "check",
         "title": "WinRM TLS — auth methods", "severity": 5, "why": "WinRM over TLS"},
    ],
    8080: [
        {"module": "auxiliary/scanner/http/http_version", "action": "check",
         "title": "HTTP-alt — version", "severity": 3, "why": "Alt HTTP port"},
    ],
    161: [
        {"module": "auxiliary/scanner/snmp/snmp_login", "action": "check",
         "title": "SNMP — community login", "severity": 6, "why": "SNMP often uses public/private"},
    ],
    2049: [
        {"module": "auxiliary/scanner/nfs/nfsmount", "action": "check",
         "title": "NFS — mount export check", "severity": 6, "why": "NFS exports can be world-readable"},
    ],
    2375: [
        {"module": "auxiliary/scanner/http/docker_version", "action": "check",
         "title": "Docker API — version", "severity": 8, "why": "Unauth Docker API is a lab foothold"},
    ],
    6379: [
        {"module": "auxiliary/scanner/redis/redis_server", "action": "check",
         "title": "Redis — unauth check", "severity": 7, "why": "Redis often has no AUTH in labs"},
    ],
    9200: [
        {"module": "auxiliary/scanner/http/elasticsearch_traversal", "action": "check",
         "title": "Elasticsearch — traversal check", "severity": 6, "why": "ES HTTP API exposed"},
    ],
    11211: [
        {"module": "auxiliary/scanner/memcached/memcached_udp_amplifier", "action": "check",
         "title": "Memcached — service check", "severity": 5, "why": "Memcached exposed"},
    ],
    27017: [
        {"module": "auxiliary/scanner/mongodb/mongodb_login", "action": "check",
         "title": "MongoDB — login check", "severity": 6, "why": "Mongo often has no auth"},
    ],
}


def _can_exploit(module: str, action: str) -> bool:
    return module.startswith("exploit/") and action in ("check", "exploit")


def suggest_msf(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return ranked Metasploit suggestions. Check first; exploit is opt-in."""
    seen = set()
    out: List[Dict[str, Any]] = []
    blob = " ".join(
        [
            host.get("os_guess", "") or "",
            host.get("hostname", "") or "",
            " ".join(host.get("services", []) or []),
            " ".join(
                f.get("title", "") + " " + f.get("detail", "")
                for f in (host.get("findings") or [])
            ),
        ]
    ).lower()

    for pattern, module, action, title, severity, why in MSF_RULES:
        if re.search(pattern, blob, re.I):
            key = (module, "check")
            if key not in seen:
                seen.add(key)
                out.append({
                    "module": module,
                    "action": "check",
                    "title": title,
                    "severity": severity,
                    "why": why,
                    "source": "rule",
                    "can_exploit": _can_exploit(module, "exploit"),
                    "recommended": False,
                })

    for port_info in host.get("ports") or []:
        try:
            port = int(port_info.get("port", 0))
        except (TypeError, ValueError):
            continue
        if port not in PORT_DEFAULTS:
            continue
        for item in PORT_DEFAULTS[port]:
            key = (item["module"], item["action"])
            if key in seen:
                continue
            if item["module"].endswith("http_version") and any(
                r["module"].startswith("exploit/multi/http") for r in out
            ):
                continue
            seen.add(key)
            out.append({
                **item,
                "source": "port",
                "port": port,
                "can_exploit": _can_exploit(item["module"], "exploit"),
                "recommended": False,
                "why": item.get("why") or f"Port {port} open",
            })

    out.sort(key=lambda x: -int(x.get("severity", 0)))
    if out:
        out[0]["recommended"] = True
    return out[:8]


def pick_recommended(hosts: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    """Single best next check across the LAN."""
    best: Dict[str, Any] | None = None
    for host in hosts:
        for mod in host.get("msf_modules") or []:
            row = {
                **mod,
                "ip": host.get("ip"),
                "hostname": host.get("hostname") or "",
                "risk_score": host.get("risk_score", 0),
            }
            if not best:
                best = row
                continue
            if int(row.get("severity") or 0) > int(best.get("severity") or 0):
                best = row
            elif (
                int(row.get("severity") or 0) == int(best.get("severity") or 0)
                and int(row.get("risk_score") or 0) > int(best.get("risk_score") or 0)
            ):
                best = row
    return best
