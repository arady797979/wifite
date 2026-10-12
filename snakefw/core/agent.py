#!/usr/bin/env python3
"""Snake Gemini Agent factory."""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, List, Tuple

from snakefw.core.agent_bridge import bridge_ready
from snakefw.core.agent_prompt import SNAKE_AGENT_SYSTEM
from snakefw.core.agent_tools import SNAKE_AGENT_TOOLS

_chat_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="snake-agent-gemini")


def agent_configured() -> dict:
    """Non-secret readiness for /api/agent/status."""
    key = os.environ.get("GEMINI_API_KEY") or ""
    genai_ok = False
    try:
        import google.genai  # noqa: F401
        genai_ok = True
    except ImportError:
        pass
    return {
        "gemini_api_key_set": bool(key and key != "your_actual_api_key_here"),
        "google_genai_installed": genai_ok,
        "model": os.environ.get("SNAKE_AGENT_MODEL", "gemini-3.8-flash"),
        "tool_count": len(SNAKE_AGENT_TOOLS),
        "base_url": os.environ.get("SNAKE_AGENT_BASE", "http://127.0.0.1:5000"),
        "bridge_active": bridge_ready(),
    }


def _build_client_and_chat():
    from google import genai
    from google.genai import types

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or api_key == "your_actual_api_key_here":
        raise ValueError(
            "GEMINI_API_KEY is missing. Export it or add to .env in the repo root."
        )

    model = os.environ.get("SNAKE_AGENT_MODEL", "gemini-3.8-flash")
    client = genai.Client(api_key=api_key)

    config = types.GenerateContentConfig(
        system_instruction=SNAKE_AGENT_SYSTEM,
        temperature=0.25,
        tools=SNAKE_AGENT_TOOLS,
    )
    try:
        config.automatic_function_calling = types.AutomaticFunctionCallingConfig(
            disable=False,
            maximum_remote_calls=32,
        )
    except (AttributeError, TypeError):
        pass

    chat = client.chats.create(model=model, config=config)
    return client, chat


def create_snake_agent():
    try:
        from google import genai  # noqa: F401
        from google.genai import types  # noqa: F401
    except ImportError as exc:
        raise ValueError(
            "google-genai is not installed. Run: pip install google-genai"
        ) from exc

    _client, chat = _build_client_and_chat()
    # Keep client alive on the chat object (SDK may close if client is GC'd).
    chat._snake_genai_client = _client  # type: ignore[attr-defined]
    return chat


def _is_client_closed_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return "client has been closed" in msg or "client closed" in msg


def send_agent_message(chat_session: Any, user_message: str) -> Any:
    """Run Gemini send_message off the Flask worker thread when possible."""

    def _send():
        return chat_session.send_message(user_message)

    return _chat_executor.submit(_send).result(timeout=300)


def send_with_retry(
    session_store: dict,
    session_id: str,
    user_message: str,
    store_lock: threading.Lock | None = None,
) -> Tuple[Any, Any]:
    """
    Send user message; on closed-client errors recreate the chat once.
    Returns (chat_session, response).
    """
    def _get_or_create() -> Any:
        if store_lock:
            with store_lock:
                chat = session_store.get(session_id)
                if chat is None:
                    chat = create_snake_agent()
                    session_store[session_id] = chat
                return chat
        chat = session_store.get(session_id)
        if chat is None:
            chat = create_snake_agent()
            session_store[session_id] = chat
        return chat

    def _replace(chat: Any) -> None:
        if store_lock:
            with store_lock:
                session_store[session_id] = chat
        else:
            session_store[session_id] = chat

    chat = _get_or_create()

    try:
        response = send_agent_message(chat, user_message)
        return chat, response
    except Exception as exc:
        if not _is_client_closed_error(exc):
            raise
        chat = create_snake_agent()
        _replace(chat)
        response = send_agent_message(chat, user_message)
        return chat, response


def extract_response_text(response: Any) -> str:
    """Best-effort text from a Gemini chat response object."""
    if response is None:
        return ""
    text = getattr(response, "text", None)
    if text:
        return str(text).strip()
    try:
        candidates = getattr(response, "candidates", None) or []
        parts: List[str] = []
        for cand in candidates:
            content = getattr(cand, "content", None)
            if not content:
                continue
            for part in getattr(content, "parts", []) or []:
                if getattr(part, "text", None):
                    parts.append(part.text)
        return "\n".join(parts).strip()
    except Exception:
        return str(response)
