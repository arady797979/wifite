"""Canonical filesystem locations for Snake Framework."""

from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = PACKAGE_DIR.parent
CAPTURES_DIR = PACKAGE_DIR / "captures"
RESULTS_DIR = PACKAGE_DIR / "results"
WORDLISTS_DIR = PACKAGE_DIR / "wordlists"
LOGS_DIR = PACKAGE_DIR / "logs"
CRACKED_FILE = REPO_DIR / "cracked.json"
BUILTIN_WORDLIST = REPO_DIR / "wordlist-top4800-probable.txt"


def ensure_runtime_dirs() -> None:
    """Create the writable directories used by Snake."""
    for directory in (CAPTURES_DIR, RESULTS_DIR, WORDLISTS_DIR, LOGS_DIR):
        directory.mkdir(parents=True, exist_ok=True)

