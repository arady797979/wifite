#!/usr/bin/env python3
"""Persist failed WPA hashes and submit them to wpa-sec on demand."""
import json
import os
import re
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .cracked_store import append_cracked, is_valid_cracked_entry
from .paths import CAPTURES_DIR, CRACKED_FILE, RESULTS_DIR, ensure_runtime_dirs

ensure_runtime_dirs()
QUEUE_FILE = RESULTS_DIR / "online_queue.json"
PREF_FILE = RESULTS_DIR / "online_pref.json"
WPASEC_URL = "https://wpa-sec.stanev.org"
_lock = threading.Lock()

STATUS_QUEUED = "queued"
STATUS_SUBMITTED = "submitted"
STATUS_CRACKED = "cracked"
STATUS_ERROR = "error"


def _normalize_bssid(value: str) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    if len(raw) != 12:
        return str(value or "").strip().upper().replace("-", ":")
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def _read_json(path: Path, default):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, type(default)) else default
    except (OSError, ValueError):
        return default


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def get_pref() -> dict:
    pref = _read_json(PREF_FILE, {})
    return pref if isinstance(pref, dict) else {}


def set_api_key(key: str) -> dict:
    pref = get_pref()
    pref["api_key"] = (key or "").strip()
    pref["provider"] = "wpa-sec"
    _atomic_write(PREF_FILE, pref)
    return pref


def list_queue() -> List[dict]:
    rows = _read_json(QUEUE_FILE, [])
    return [row for row in rows if isinstance(row, dict)]


def get_item(item_id: str) -> Optional[dict]:
    wanted = (item_id or "").strip()
    return next((row for row in list_queue() if row.get("id") == wanted), None)


def _save_queue(rows: List[dict]) -> None:
    _atomic_write(QUEUE_FILE, rows)


def _safe_name(essid: str, bssid: str) -> str:
    essid_part = re.sub(r"[^A-Za-z0-9]", "", essid or "") or "Unknown"
    bssid_part = _normalize_bssid(bssid).replace(":", "-") or "unknown"
    return f"{essid_part}_{bssid_part}"


def _stage_file(source: str, dest: Path) -> str:
    src = Path(source)
    if not src.is_file():
        return ""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.resolve() != dest.resolve():
        shutil.copy2(src, dest)
    return str(dest)


def enqueue_failed(
    essid: str,
    bssid: str,
    cap_file: str = "",
    hash_file: str = "",
    lists_tried: Optional[List[str]] = None,
) -> Optional[dict]:
    """Copy a missed handshake/hash into the online queue (no upload)."""
    cap_path = Path(cap_file) if cap_file else None
    hash_path = Path(hash_file) if hash_file else None
    if not ((cap_path and cap_path.is_file()) or (hash_path and hash_path.is_file())):
        return None

    item_id = uuid.uuid4().hex[:8]
    stem = _safe_name(essid, bssid)
    staged_cap = ""
    staged_hash = ""
    if cap_path and cap_path.is_file():
        staged_cap = _stage_file(str(cap_path), CAPTURES_DIR / f"pending_{item_id}_{stem}.cap")
    if hash_path and hash_path.is_file():
        staged_hash = _stage_file(
            str(hash_path), CAPTURES_DIR / f"pending_{item_id}_{stem}.hc22000"
        )

    item = {
        "id": item_id,
        "essid": essid,
        "bssid": _normalize_bssid(bssid),
        "cap": staged_cap,
        "hash": staged_hash,
        "status": STATUS_QUEUED,
        "provider": "wpa-sec",
        "key": "",
        "message": "Local Fast/Smart/Deep missed. Ready for online submit.",
        "created_at": int(time.time()),
        "submitted_at": 0,
        "lists_tried": [str(name) for name in (lists_tried or []) if name],
    }
    with _lock:
        rows = list_queue()
        rows.append(item)
        _save_queue(rows)
    return item


def _multipart(fields: Dict[str, str], files: Dict[str, tuple]) -> tuple:
    boundary = f"----Snake{uuid.uuid4().hex}"
    chunks = []
    for name, value in fields.items():
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        chunks.append(str(value).encode("utf-8", "ignore") + b"\r\n")
    for name, (filename, data) in files.items():
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        )
        chunks.append(b"Content-Type: application/octet-stream\r\n\r\n")
        chunks.append(data)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _http(url: str, data: Optional[bytes] = None, headers: Optional[dict] = None, timeout: int = 45):
    request = Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    with urlopen(request, timeout=timeout) as response:
        body = response.read()
        return response.status, body.decode("utf-8", "ignore")


def _upload_file(item: dict) -> Path:
    for key in ("cap", "hash"):
        path = Path(str(item.get(key) or ""))
        if path.is_file() and path.stat().st_size > 0:
            return path
    raise FileNotFoundError("No staged handshake or hash file to upload")


def _update_item(item_id: str, **changes) -> Optional[dict]:
    with _lock:
        rows = list_queue()
        updated = None
        for index, row in enumerate(rows):
            if row.get("id") != item_id:
                continue
            row.update(changes)
            rows[index] = row
            updated = row
            break
        if updated:
            _save_queue(rows)
        return updated


def submit_item(item_id: str) -> dict:
    """Upload one queued capture to wpa-sec. Does not run automatically."""
    item = get_item(item_id)
    if not item:
        raise ValueError("Unknown online-queue item")
    if item.get("status") == STATUS_CRACKED and item.get("key"):
        return item

    path = _upload_file(item)
    payload, content_type = _multipart(
        {"submit": "Submit"},
        {"webfile": (path.name, path.read_bytes())},
    )
    headers = {
        "Content-Type": content_type,
        "User-Agent": "SnakeFramework/1.0 (authorized lab)",
    }
    key = str(get_pref().get("api_key") or "").strip()
    if key:
        headers["Cookie"] = f"key={key}"

    try:
        _status, text = _http(f"{WPASEC_URL}/?submit", data=payload, headers=headers)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        updated = _update_item(item_id, status=STATUS_ERROR, message=f"Submit failed: {exc}")
        return updated or item

    lowered = text.lower()
    if "already" in lowered and "submitted" in lowered:
        message = "Already on wpa-sec. Use Check results after it lands."
        status = STATUS_SUBMITTED
    elif "success" in lowered or "thank" in lowered or "uploaded" in lowered:
        message = "Submitted to wpa-sec. Check results later (API key recommended)."
        status = STATUS_SUBMITTED
    else:
        message = "wpa-sec accepted the upload. Check results later."
        status = STATUS_SUBMITTED

    return _update_item(
        item_id,
        status=status,
        message=message,
        submitted_at=int(time.time()),
    ) or item


def _match_key(line: str, bssid: str, essid: str) -> Optional[str]:
    text = (line or "").strip()
    if not text or text.startswith("#"):
        return None
    parts = text.split(":")
    if len(parts) < 2:
        return None
    compact = _normalize_bssid(bssid).replace(":", "").lower()
    haystack = text.lower().replace("-", "").replace(":", "")
    if compact and compact in haystack:
        key = parts[-1].strip()
        return key or None
    if essid and essid.lower() in text.lower():
        key = parts[-1].strip()
        return key or None
    return None


def check_results() -> List[dict]:
    """Pull wpa-sec potfile (needs API key) and attach any hits to the queue."""
    key = str(get_pref().get("api_key") or "").strip()
    if not key:
        raise ValueError("Save a wpa-sec API key first (Tools → Online queue).")

    headers = {
        "User-Agent": "SnakeFramework/1.0 (authorized lab)",
        "Cookie": f"key={key}",
    }
    try:
        _status, text = _http(f"{WPASEC_URL}/?api&dl=1", headers=headers)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"wpa-sec check failed: {exc}") from exc

    hits = []
    for item in list_queue():
        if item.get("status") == STATUS_CRACKED and item.get("key"):
            continue
        found = None
        for line in text.splitlines():
            found = _match_key(line, str(item.get("bssid") or ""), str(item.get("essid") or ""))
            if found:
                break
        if not found:
            continue
        updated = _update_item(
            item["id"],
            status=STATUS_CRACKED,
            key=found,
            message="Recovered from wpa-sec",
        )
        if updated:
            entry = {
                "type": "WPA_ONLINE",
                "date": int(time.time()),
                "essid": updated.get("essid"),
                "bssid": updated.get("bssid"),
                "key": found,
                "source": "wpa-sec",
                "attack": "WPA_ONLINE",
            }
            if is_valid_cracked_entry(entry):
                append_cracked(entry, paths=[RESULTS_DIR / "cracked.json", CRACKED_FILE])
            hits.append(updated)
    return hits


def download_path(item_id: str) -> Optional[Path]:
    item = get_item(item_id)
    if not item:
        return None
    for key in ("hash", "cap"):
        path = Path(str(item.get(key) or ""))
        if path.is_file():
            return path
    return None
