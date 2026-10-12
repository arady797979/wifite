#!/usr/bin/env python3
"""
In-process API bridge for the Gemini agent.

Tool calls must not block the Flask worker on HTTP to the same server (deadlock).
When registered, agent tools invoke views via the Flask test client on a worker thread.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

_app = None
_client = None
_init_lock = threading.Lock()
_pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="snake-agent-tool")


def init_agent_bridge(flask_app) -> None:
    """Call once at server startup (run_server)."""
    global _app, _client
    with _init_lock:
        _app = flask_app
        _client = flask_app.test_client()


def bridge_ready() -> bool:
    return _app is not None and _client is not None


def invoke(method: str, path: str, payload: Optional[dict] = None, timeout: int = 120) -> Dict[str, Any]:
    """Run a Snake API route in-process (thread pool)."""
    if not bridge_ready():
        return {"ok": False, "error": "Agent bridge not initialized"}

    def _run():
        with _app.app_context():
            if method.upper() == "GET":
                resp = _client.get(path)
            else:
                resp = _client.post(path, json=payload or {})
            if resp.is_json:
                data = resp.get_json()
                if isinstance(data, dict):
                    data.setdefault("http_status", resp.status_code)
                return data
            return {
                "ok": False,
                "error": (resp.data or b"").decode("utf-8", errors="replace")[:500],
                "http_status": resp.status_code,
            }

    future = _pool.submit(_run)
    try:
        return future.result(timeout=timeout)
    except Exception as exc:
        return {"ok": False, "error": f"bridge invoke failed: {exc}"}
