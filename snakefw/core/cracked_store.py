#!/usr/bin/env python3
"""Load, validate, and persist cracked credentials (wifite + Snake formats)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .paths import CRACKED_FILE, RESULTS_DIR

RESULTS_CRACKED = RESULTS_DIR / "cracked.json"


def cracked_password(entry: Dict[str, Any]) -> str:
    """Return the recovered secret for display, or empty if none."""
    if not isinstance(entry, dict):
        return ""
    for field in ("key", "psk", "password", "passphrase", "ascii_key", "pin", "hex_key"):
        value = entry.get(field)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def is_valid_cracked_entry(entry: Dict[str, Any]) -> bool:
    """True when the record has an identity and a non-empty recovered secret."""
    if not isinstance(entry, dict):
        return False
    essid = str(entry.get("essid") or "").strip()
    bssid = str(entry.get("bssid") or "").strip()
    if not essid and not bssid:
        return False
    return bool(cracked_password(entry))


def normalize_cracked_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure Snake UI always has a `key` field when a secret exists."""
    row = dict(entry)
    secret = cracked_password(row)
    if secret and not str(row.get("key") or "").strip():
        row["key"] = secret
    return row


def _dedupe_key(entry: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(entry.get("bssid") or "").upper(),
        str(entry.get("essid") or ""),
        cracked_password(entry),
    )


def sanitize_cracked_list(entries: List[Any]) -> Tuple[List[Dict[str, Any]], int]:
    """Drop invalid rows; normalize survivors; dedupe by bssid+essid+secret."""
    if not isinstance(entries, list):
        return [], 0
    removed = 0
    valid: List[Dict[str, Any]] = []
    seen = set()
    for raw in entries:
        if not isinstance(raw, dict):
            removed += 1
            continue
        if not is_valid_cracked_entry(raw):
            removed += 1
            continue
        row = normalize_cracked_entry(raw)
        key = _dedupe_key(row)
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        valid.append(row)
    return valid, removed


def _read_json_list(path: Path) -> List[Any]:
    if not path.is_file():
        return []
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, list) else []
    except (OSError, ValueError, json.JSONDecodeError):
        return []


def _atomic_write(path: Path, data: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def load_cracked_from_file(path: Path) -> List[Dict[str, Any]]:
    cleaned, _removed = sanitize_cracked_list(_read_json_list(path))
    return cleaned


def sanitize_cracked_file(path: Path) -> Tuple[List[Dict[str, Any]], int]:
    """Read, clean, rewrite if changed. Returns (valid entries, removed count)."""
    raw = _read_json_list(path)
    cleaned, removed = sanitize_cracked_list(raw)
    if path.is_file() and (removed or len(cleaned) != len(raw)):
        _atomic_write(path, cleaned)
    elif not path.is_file() and cleaned:
        _atomic_write(path, cleaned)
    return cleaned, removed


def load_all_cracked() -> List[Dict[str, Any]]:
    """Merge canonical repo cracked.json and snakefw/results/cracked.json."""
    merged: List[Dict[str, Any]] = []
    removed_total = 0
    for path in (CRACKED_FILE, RESULTS_CRACKED):
        cleaned, removed = sanitize_cracked_file(path)
        removed_total += removed
        merged.extend(cleaned)
    final, dupes = sanitize_cracked_list(merged)
    if dupes and final != merged:
        _atomic_write(CRACKED_FILE, final)
        if RESULTS_CRACKED.is_file():
            _atomic_write(RESULTS_CRACKED, final)
    return final


def append_cracked(entry: Dict[str, Any], paths: Optional[List[Path]] = None) -> bool:
    """Append one valid entry to cracked store(s). Returns False if rejected."""
    if not is_valid_cracked_entry(entry):
        return False
    row = normalize_cracked_entry(entry)
    targets = paths or [CRACKED_FILE, RESULTS_CRACKED]
    saved = False
    for path in targets:
        current = load_cracked_from_file(path)
        if any(_dedupe_key(item) == _dedupe_key(row) for item in current):
            continue
        current.append(row)
        _atomic_write(path, current)
        saved = True
    return saved
