#!/usr/bin/env python3
"""
Snake Framework - Session Manager
Manages active scanning/cracking sessions, state, and persistence.
"""
import json
import os
import time
import threading
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from enum import Enum

from .cracked_store import append_cracked, is_valid_cracked_entry, load_all_cracked
from .paths import CRACKED_FILE, RESULTS_DIR, ensure_runtime_dirs

ensure_runtime_dirs()
HISTORY_FILE = RESULTS_DIR / "job_history.json"

class SessionState(str, Enum):
    IDLE      = "IDLE"
    SCANNING  = "SCANNING"
    ATTACKING = "ATTACKING"
    CRACKING  = "CRACKING"
    DONE      = "DONE"
    ERROR     = "ERROR"


@dataclass
class AttackJob:
    id:         str
    essid:      str
    bssid:      str
    attack:     str
    state:      str = "QUEUED"
    progress:   int = 0
    key:        str = ""
    capture:    str = ""
    hash_file:  str = ""
    online_id:  str = ""
    started_at: float = field(default_factory=time.time)
    ended_at:   float = 0
    logs:       List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


class SnakeSession:
    """Thread-safe session state for Snake."""

    def __init__(self):
        self._lock        = threading.Lock()
        self.id           = str(uuid.uuid4())[:8]
        self.state        = SessionState.IDLE
        self.interface    = ""
        self.monitor_iface = ""
        self.scan_iface    = ""
        self.attack_iface  = ""
        self.networks:     List[Dict] = []
        self.jobs:         Dict[str, AttackJob] = {}
        self.cracked:      List[Dict] = []
        self.log_buffer:   List[Dict] = []   # {ts, level, msg}
        self.stats         = {
            "scans":     0,
            "attacks":   0,
            "cracked":   0,
            "uptime":    time.time(),
        }
        self._load_cracked()

    def _load_cracked(self):
        """Load and sanitize cracked.json (drops entries with no password)."""
        try:
            self.cracked = load_all_cracked()
            self.stats["cracked"] = len(self.cracked)
        except Exception:
            self.cracked = []
            self.stats["cracked"] = 0

    def log(self, msg: str, level: str = "INFO"):
        with self._lock:
            entry = {"ts": time.time(), "level": level, "msg": msg}
            self.log_buffer.append(entry)
            if len(self.log_buffer) > 2000:
                self.log_buffer = self.log_buffer[-1000:]

    def update_networks(self, networks: List[Dict]):
        with self._lock:
            self.networks = networks

    def add_job(self, essid: str, bssid: str, attack: str) -> str:
        jid = str(uuid.uuid4())[:8]
        job = AttackJob(id=jid, essid=essid, bssid=bssid, attack=attack)
        with self._lock:
            self.jobs[jid] = job
            self.stats["attacks"] += 1
        return jid

    def update_job(self, jid: str, **kwargs):
        with self._lock:
            if jid in self.jobs:
                for k, v in kwargs.items():
                    if hasattr(self.jobs[jid], k):
                        setattr(self.jobs[jid], k, v)
                if self.jobs[jid].state in {"DONE", "FAILED", "ERROR", "KILLED", "CRACKED"}:
                    self._save_job_history_locked()

    def job_log(self, jid: str, msg: str):
        with self._lock:
            if jid in self.jobs:
                self.jobs[jid].logs.append(msg)
                if len(self.jobs[jid].logs) > 500:
                    self.jobs[jid].logs = self.jobs[jid].logs[-250:]

    def add_cracked(self, entry: Dict):
        with self._lock:
            if not is_valid_cracked_entry(entry):
                return
            if append_cracked(entry):
                self.cracked = load_all_cracked()
            self.stats["cracked"] = len(self.cracked)

    def set_state(self, state: SessionState):
        with self._lock:
            self.state = state

    def get_snapshot(self) -> Dict:
        with self._lock:
            return {
                "id":       self.id,
                "state":    self.state.value,
                "interface": self.interface,
                "monitor":  self.monitor_iface,
                "scan_iface": self.scan_iface,
                "attack_iface": self.attack_iface,
                "networks": self.networks[:],
                "jobs":     {k: v.to_dict() for k, v in self.jobs.items()},
                "cracked":  self.cracked[:],
                "stats":    {
                    **self.stats,
                    "uptime": int(time.time() - self.stats["uptime"]),
                },
                "logs":     self.log_buffer[-100:],
            }

    def get_recent_logs(self, n: int = 50) -> List[Dict]:
        with self._lock:
            return self.log_buffer[-n:]

    def get_job_history(self) -> List[Dict]:
        try:
            with HISTORY_FILE.open(encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _save_job_history_locked(self) -> None:
        history = self.get_job_history()
        known = {item.get("id") for item in history}
        for job in self.jobs.values():
            if job.state in {"DONE", "FAILED", "ERROR", "KILLED", "CRACKED"}:
                item = job.to_dict()
                if item["id"] in known:
                    history = [item if old.get("id") == item["id"] else old for old in history]
                else:
                    history.append(item)
                    known.add(item["id"])
        self._atomic_write(HISTORY_FILE, history[-500:])

    @staticmethod
    def _atomic_write(path, data) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)


# Global session singleton
_session: Optional[SnakeSession] = None

def get_session() -> SnakeSession:
    global _session
    if _session is None:
        _session = SnakeSession()
    return _session
