#!/usr/bin/env python3
"""Snake Gemini Agent API."""
from __future__ import annotations

import threading
import time
from typing import Dict

from flask import Blueprint, jsonify, request

from snakefw.core.agent import (
    agent_configured,
    extract_response_text,
    send_with_retry,
)

agent_bp = Blueprint("agent", __name__)

_active_chats: Dict[str, object] = {}
_chat_lock = threading.Lock()


@agent_bp.route("/api/agent/status")
def agent_status():
    cfg = agent_configured()
    cfg["ok"] = cfg["gemini_api_key_set"] and cfg["google_genai_installed"]
    return jsonify(cfg)


@agent_bp.route("/api/agent/reset", methods=["POST"])
def agent_reset():
    data = request.json or {}
    session_id = str(data.get("session_id") or "default")
    with _chat_lock:
        _active_chats.pop(session_id, None)
    return jsonify({"ok": True, "session_id": session_id})


@agent_bp.route("/api/agent/chat", methods=["POST"])
def chat():
    data = request.json or {}
    user_message = (data.get("message") or "").strip()
    session_id = str(data.get("session_id") or "default")

    if not user_message:
        return jsonify({"ok": False, "error": "Message is required"}), 400

    try:
        chat_session, response = send_with_retry(
            _active_chats,
            session_id,
            user_message,
            store_lock=_chat_lock,
        )
        text = extract_response_text(response)
        if not text:
            text = "(No text response — check Console for tool activity on the server.)"

        return jsonify({
            "ok": True,
            "response": text,
            "session_id": session_id,
            "ts": time.time(),
        })
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Agent error: {exc}"}), 500
