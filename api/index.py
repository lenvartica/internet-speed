"""Vercel serverless endpoint for Decan Internet Test."""

import json
import os
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse


def first_header(handler, names, default=""):
    for name in names:
        value = handler.headers.get(name)
        if value:
            return value.split(",")[0].strip()
    return default


def get_client_ip(handler):
    return first_header(
        handler,
        ("x-forwarded-for", "x-real-ip", "cf-connecting-ip"),
        "127.0.0.1",
    )


def network_report(handler):
    ip = get_client_ip(handler)
    forwarded = handler.headers.get("x-forwarded-for", "")
    via = handler.headers.get("via", "")
    forwarded_proto = first_header(handler, ("x-forwarded-proto",), "https")
    is_local = ip in {"127.0.0.1", "::1", "localhost"}

    country = handler.headers.get("x-vercel-ip-country", "")
    region = handler.headers.get("x-vercel-ip-country-region", "")
    city = handler.headers.get("x-vercel-ip-city", "")
    location = ", ".join(part for part in (city, region, country) if part)
    if not location:
        location = "Local development" if is_local else "Location unavailable"

    indicators = []
    if forwarded.count(",") > 1:
        indicators.append("Multiple forwarding hops detected")
    if via:
        indicators.append("A gateway or proxy advertised a Via header")
    if handler.headers.get("x-forwarded-host"):
        indicators.append("Request passed through an edge host")

    https_ok = forwarded_proto.lower() == "https" or os.environ.get("VERCEL", "") == "1"
    if not https_ok:
        indicators.append("Connection is not using HTTPS")

    safe = https_ok and not (forwarded.count(",") > 1 or via)
    verdict = "Safe" if safe else "Exposed"
    return {
        "ip": ip,
        "location": location,
        "country": country or "--",
        "isp": "Edge network / ISP unavailable",
        "protocol": forwarded_proto.upper(),
        "is_https": https_ok,
        "is_local": is_local,
        "indicators": indicators,
        "safety": "protected" if safe else "warning",
        "verdict": verdict,
        "wifi_assessment": "Not detectable from server headers",
        "dns_leak_check": "Not available from browser headers",
        "risk_factors": indicators,
    }


def requested_size(query):
    try:
        return min(max(int(query.get("size", [128])[0]), 16), 4096)
    except (TypeError, ValueError):
        return 128


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, payload):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)

        if path.endswith("/ping"):
            self._send_json({"ok": True, "timestamp": __import__("time").time()})
            return

        if path.endswith("/download"):
            size_kb = requested_size(query)
            self._send_bytes(b"0" * (size_kb * 1024))
            return

        if path.endswith("/info") or path.endswith("/network") or path.endswith("/api") or path.endswith("/index.py"):
            self._send_json(network_report(self))
            return

        self._send_json({"ok": False, "error": "Not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            content_length = max(0, min(int(self.headers.get("Content-Length", "0")), 1024 * 1024))
        except (TypeError, ValueError):
            content_length = 0
        if path.endswith("/ping"):
            if content_length:
                self.rfile.read(min(content_length, 1024 * 1024))
            self._send_json({"ok": True, "received": content_length})
            return
        self._send_json({"ok": False, "error": "Not found"}, 404)

    def log_message(self, format, *args):
        return
