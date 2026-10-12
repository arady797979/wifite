#!/usr/bin/env python3
"""CPU-friendly WPA wordlist catalog, builder, and selector."""
import json
import os
import re
from pathlib import Path
from typing import Iterable, List, Optional

from .paths import (
    BUILTIN_WORDLIST,
    RESULTS_DIR,
    WORDLISTS_DIR,
    ensure_runtime_dirs,
)

ensure_runtime_dirs()
PREF_FILE = RESULTS_DIR / "wordlist_pref.json"
SECLISTS = Path("/usr/share/seclists/Passwords")
HOME_LISTS = Path("/home/kali/wordlists")
HASHCAT_BEST66 = Path("/usr/share/hashcat/rules/best66.rule")

TIER_FAST = "fast"
TIER_SMART = "smart"
TIER_DEEP = "deep"
TIER_TARGET = "target"
DEFAULT_TIER = TIER_SMART
TIER_ORDER = (TIER_FAST, TIER_SMART, TIER_DEEP)

TIER_FILES = {
    TIER_FAST: WORDLISTS_DIR / "snake-fast.txt",
    TIER_SMART: WORDLISTS_DIR / "snake-smart.txt",
    TIER_DEEP: WORDLISTS_DIR / "snake-deep.txt",
}

TIER_META = {
    TIER_FAST: {
        "label": "Fast",
        "hint": "Top probable WPA keys. Seconds on CPU.",
        "timeout": 180,
        "use_rules": True,
    },
    TIER_SMART: {
        "label": "Smart",
        "hint": "Versatile default. If this misses, Snake escalates to Deep.",
        "timeout": 900,
        "use_rules": True,
    },
    TIER_DEEP: {
        "label": "Deep",
        "hint": "WPA-filtered rockyou. Last local pass before the online queue.",
        "timeout": 0,
        "use_rules": False,
    },
}

WIFI_STEMS = (
    "password", "Password", "admin", "welcome", "qwerty", "internet",
    "wireless", "wifi", "router", "home", "family",
)
WIFI_SUFFIXES = (
    "", "1", "12", "123", "1234", "12345", "123456", "!", "@",
) + tuple(str(year) for year in range(1990, 2027))

FAST_SOURCES = (
    SECLISTS / "WiFi-WPA" / "probable-v2-wpa-top62.txt",
    SECLISTS / "WiFi-WPA" / "probable-v2-wpa-top447.txt",
    SECLISTS / "WiFi-WPA" / "probable-v2-wpa-top4800.txt",
    BUILTIN_WORDLIST,
    SECLISTS / "Common-Credentials" / "probable-v2_top-12000.txt",
    SECLISTS / "Common-Credentials" / "darkweb2017_top-10000.txt",
    SECLISTS / "Common-Credentials" / "10k-most-common.txt",
    SECLISTS / "Common-Credentials" / "best1050.txt",
    SECLISTS / "Common-Credentials" / "500-worst-passwords.txt",
    SECLISTS / "Keyboard-Walks" / "Keyboard-Combinations.txt",
)

SMART_EXTRA_SOURCES = (
    SECLISTS / "Common-Credentials" / "Pwdb_top-100000.txt",
    SECLISTS / "Common-Credentials" / "100k-most-used-passwords-NCSC.txt",
    SECLISTS / "Common-Credentials" / "xato-net-10-million-passwords-100000.txt",
    SECLISTS / "Keyboard-Walks" / "walk-the-line.txt",
)

DEEP_SOURCES = (
    HOME_LISTS / "rockyou.txt",
    Path("/usr/share/wordlists/rockyou.txt"),
    SECLISTS / "Common-Credentials" / "xato-net-10-million-passwords-1000000.txt",
    SECLISTS / "Common-Credentials" / "Pwdb_top-1000000.txt",
)


def is_wpa_candidate(line: str) -> bool:
    """True when a line is a plausible WPA-PSK (8–63 bytes)."""
    text = (line or "").strip("\r\n").strip()
    if not text or "\x00" in text:
        return False
    return 8 <= len(text.encode("utf-8", "ignore")) <= 63


def _iter_lines(path: Path) -> Iterable[str]:
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            yield line


def essid_candidates(essid: str, limit: int = 2000) -> List[str]:
    """Build a small ESSID-derived candidate list (names, years, light leet)."""
    raw = (essid or "").strip()
    if not raw:
        return []

    tokens = [part for part in re.split(r"[^A-Za-z0-9]+", raw) if part]
    compact = "".join(tokens)
    camel = "".join(part[:1].upper() + part[1:] for part in tokens if part)
    variants = [
        raw, raw.lower(), raw.upper(), raw.capitalize(),
        compact, compact.lower(), compact.upper(), compact.capitalize(), camel,
        "-".join(tokens), "_".join(tokens), "".join(tokens).lower(),
    ]
    variants.extend(tokens)
    leet = compact.lower().translate(str.maketrans("oaieis", "041315"))
    if leet and leet != compact.lower():
        variants.append(leet)
        variants.append(leet.capitalize())

    suffixes = ("",) + WIFI_SUFFIXES + ("00", "01", "007", "12345678", "password")
    seen = set()
    values = []
    for base in variants:
        text = (base or "").strip()
        if not text:
            continue
        for suffix in suffixes:
            candidate = f"{text}{suffix}"
            if candidate in seen or not is_wpa_candidate(candidate):
                continue
            seen.add(candidate)
            values.append(candidate)
            if len(values) >= limit:
                return values
    return values


def write_target_wordlist(essid: str, dest: Optional[Path] = None) -> Optional[dict]:
    """Write ESSID-derived keys and return a catalog-style entry."""
    keys = essid_candidates(essid)
    if not keys:
        return None
    ensure_runtime_dirs()
    dest = dest or (WORDLISTS_DIR / "snake-target.txt")
    dest.write_text("\n".join(keys) + "\n", encoding="utf-8")
    use_rules = HASHCAT_BEST66.is_file()
    return {
        "tier": TIER_TARGET,
        "label": f"Target ({essid})",
        "hint": "ESSID-derived keys tried first",
        "path": str(dest),
        "exists": True,
        "count": len(keys),
        "timeout": 90,
        "use_rules": use_rules,
        "rule": str(HASHCAT_BEST66) if use_rules else "",
        "active": False,
    }


def cascade_wordlists(tier: str = "", path: str = "") -> List[dict]:
    """Remaining local lists after the chosen starting tier, Deep last."""
    start = resolve_wordlist(tier=tier, path=path)
    start_tier = (start or {}).get("tier") or DEFAULT_TIER
    if start_tier == TIER_FAST:
        names = TIER_ORDER
    elif start_tier == TIER_DEEP:
        names = (TIER_DEEP,)
    elif start_tier == TIER_SMART:
        names = (TIER_SMART, TIER_DEEP)
    else:
        names = (TIER_SMART, TIER_DEEP)

    entries = []
    seen = set()

    def add(entry: Optional[dict]) -> None:
        if not entry or not entry.get("exists"):
            return
        resolved = str(Path(entry["path"]).resolve())
        if resolved in seen:
            return
        seen.add(resolved)
        entries.append(entry)

    if start and start.get("tier") not in TIER_FILES:
        add(start)
    for name in names:
        file_path = TIER_FILES[name]
        if file_path.is_file():
            add(_entry(name, file_path))
    if not any(item.get("tier") == TIER_DEEP for item in entries):
        for candidate in fallback_system_lists():
            extra = Path(candidate)
            if extra.is_file():
                add(_entry("system", extra))
                break
    return entries


def wifi_mutations() -> List[str]:
    values = []
    for stem in WIFI_STEMS:
        for suffix in WIFI_SUFFIXES:
            candidate = f"{stem}{suffix}"
            if is_wpa_candidate(candidate):
                values.append(candidate)
    extras = (
        "12345678", "123456789", "1234567890", "87654321", "11111111",
        "00000000", "qwertyui", "qwerty123", "passw0rd", "admin123",
        "admin1234", "letmein1", "trustno1", "iloveyou", "sunshine",
        "princess", "football", "baseball", "1q2w3e4r", "1qaz2wsx",
        "zaq12wsx", "abcd1234", "asdfasdf", "password1",
    )
    values.extend(item for item in extras if is_wpa_candidate(item))
    return values


def _append_unique(destination: Path, sources: Iterable[Path], seen: set, extras: Iterable[str] = ()) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    added = 0
    with destination.open("w", encoding="utf-8") as out:
        for extra in extras:
            if extra in seen or not is_wpa_candidate(extra):
                continue
            seen.add(extra)
            out.write(extra + "\n")
            added += 1
        for source in sources:
            for raw in _iter_lines(source):
                text = raw.strip("\r\n").strip()
                if text in seen or not is_wpa_candidate(text):
                    continue
                seen.add(text)
                out.write(text + "\n")
                added += 1
    return added


def build_tiered_wordlists() -> dict:
    """Rebuild Fast/Smart/Deep lists from SecLists + local rockyou."""
    ensure_runtime_dirs()
    fast_path = TIER_FILES[TIER_FAST]
    smart_path = TIER_FILES[TIER_SMART]
    deep_path = TIER_FILES[TIER_DEEP]
    fast_count = _append_unique(fast_path, FAST_SOURCES, set(), extras=wifi_mutations())
    smart_count = _append_unique(
        smart_path,
        (fast_path,) + SMART_EXTRA_SOURCES,
        set(),
    )
    deep_sources = (smart_path,) + tuple(path for path in DEEP_SOURCES if path.is_file())
    deep_count = _append_unique(deep_path, deep_sources, set())

    return {
        TIER_FAST: {"path": str(fast_path), "count": fast_count},
        TIER_SMART: {"path": str(smart_path), "count": smart_count},
        TIER_DEEP: {"path": str(deep_path), "count": deep_count},
    }


def count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += chunk.count(b"\n")
    return total


def _pref() -> dict:
    try:
        data = json.loads(PREF_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def set_active_wordlist(tier: str = "", path: str = "") -> dict:
    ensure_runtime_dirs()
    tier = (tier or "").strip().lower()
    if tier and tier not in TIER_FILES:
        raise ValueError("Unknown wordlist tier. Use fast, smart, or deep.")
    chosen = resolve_wordlist(tier=tier, path=path)
    payload = {"tier": chosen["tier"], "path": chosen["path"]}
    temporary = PREF_FILE.with_suffix(PREF_FILE.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, PREF_FILE)
    return chosen


def resolve_wordlist(tier: str = "", path: str = "") -> Optional[dict]:
    path = (path or "").strip()
    if path:
        resolved = Path(path).expanduser()
        if resolved.is_file():
            if not _allowed_wordlist(resolved):
                return None
            detected = next(
                (
                    name for name, file in TIER_FILES.items()
                    if file.is_file() and file.resolve() == resolved.resolve()
                ),
                "",
            )
            return _entry(detected or "custom", resolved)
        if path.lower() in TIER_FILES and not tier:
            tier = path.lower()

    tier = (tier or "").strip().lower()
    if tier in TIER_FILES and TIER_FILES[tier].is_file():
        return _entry(tier, TIER_FILES[tier])

    pref = _pref()
    pref_tier = str(pref.get("tier") or "")
    pref_path = Path(str(pref.get("path") or ""))
    if pref_tier in TIER_FILES and TIER_FILES[pref_tier].is_file():
        return _entry(pref_tier, TIER_FILES[pref_tier])
    if pref_path.is_file() and _allowed_wordlist(pref_path):
        return _entry(pref_tier or "custom", pref_path)

    for name in (DEFAULT_TIER, TIER_FAST, TIER_DEEP):
        if TIER_FILES[name].is_file():
            return _entry(name, TIER_FILES[name])
    if BUILTIN_WORDLIST.is_file():
        return _entry("builtin", BUILTIN_WORDLIST)
    for candidate in fallback_system_lists():
        if Path(candidate).is_file():
            return _entry("system", Path(candidate))
    return None


def _allowed_wordlist(path: Path) -> bool:
    resolved = path.resolve()
    allowed_roots = (
        WORDLISTS_DIR.resolve(),
        BUILTIN_WORDLIST.parent.resolve(),
        Path("/usr/share/wordlists").resolve(),
        Path("/usr/share/seclists").resolve(),
        HOME_LISTS.resolve() if HOME_LISTS.exists() else WORDLISTS_DIR.resolve(),
    )
    return any(
        resolved == root or root in resolved.parents
        for root in allowed_roots
    )


def _entry(tier: str, path: Path) -> dict:
    meta = TIER_META.get(tier)
    if not meta and tier == "builtin":
        meta = {
            "label": "Builtin 4800",
            "hint": "Legacy fallback. Prefer Fast or Smart.",
            "timeout": 120,
            "use_rules": False,
        }
    if not meta:
        meta = {
            "label": path.name,
            "hint": "Custom wordlist",
            "timeout": 600,
            "use_rules": False,
        }
    return {
        "tier": tier,
        "label": meta["label"],
        "hint": meta["hint"],
        "path": str(path),
        "exists": path.is_file(),
        "count": count_lines(path) if path.is_file() else 0,
        "timeout": meta["timeout"],
        "use_rules": bool(meta["use_rules"] and HASHCAT_BEST66.is_file()),
        "rule": str(HASHCAT_BEST66) if meta["use_rules"] and HASHCAT_BEST66.is_file() else "",
        "active": False,
    }


def fallback_system_lists() -> List[str]:
    return [
        str(HOME_LISTS / "rockyou.txt"),
        "/usr/share/wordlists/rockyou.txt",
        str(BUILTIN_WORDLIST),
        "/usr/share/wordlists/fasttrack.txt",
    ]


def list_wordlists() -> dict:
    active = resolve_wordlist()
    active_path = Path(active["path"]).resolve() if active else None
    entries = []
    for tier in (TIER_FAST, TIER_SMART, TIER_DEEP):
        entry = _entry(tier, TIER_FILES[tier])
        entry["active"] = bool(active_path and TIER_FILES[tier].is_file() and TIER_FILES[tier].resolve() == active_path)
        entries.append(entry)
    builtin = _entry("builtin", BUILTIN_WORDLIST)
    builtin["active"] = bool(
        active_path
        and BUILTIN_WORDLIST.is_file()
        and BUILTIN_WORDLIST.resolve() == active_path
        and not any(item["active"] for item in entries)
    )
    entries.append(builtin)
    return {
        "active": active["path"] if active else "",
        "active_tier": active["tier"] if active else "",
        "wordlists": entries,
        "built": all(TIER_FILES[name].is_file() for name in (TIER_FAST, TIER_SMART)),
    }


def get_active_wordlist() -> Optional[str]:
    chosen = resolve_wordlist()
    return chosen["path"] if chosen else None


def wordlist_priority() -> List[str]:
    paths = []
    for name in (TIER_SMART, TIER_FAST, TIER_DEEP):
        paths.append(str(TIER_FILES[name]))
    paths.append(str(BUILTIN_WORDLIST))
    paths.extend(fallback_system_lists())
    seen = set()
    unique = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique
