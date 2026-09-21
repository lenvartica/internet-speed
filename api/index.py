import json
import os
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote, urlparse


def first_header(handler, names, default=""):
    for name in names:
        value = handler.headers.get(name)
        if value:
            return value.split(",", 1)[0].strip()
    return default


def get_client_ip(handler):
    return first_header(
        handler,
        ("x-forwarded-for", "x-real-ip", "cf-connecting-ip"),
        "127.0.0.1",
    )


def network_report(handler):
    ip = get_client_ip(handler)
    forwarded_proto = first_header(handler, ("x-forwarded-proto",), "https")

    country = unquote(handler.headers.get("x-vercel-ip-country", ""))
    region = unquote(handler.headers.get("x-vercel-ip-country-region", ""))
    city = unquote(handler.headers.get("x-vercel-ip-city", ""))
    location = ", ".join(part for part in (city, region, country) if part)

    is_local = ip in {"127.0.0.1", "::1", "localhost"}
    if not location:
        location = "Local development" if is_local else "Location unavailable"

    # x-forwarded-* headers are normal infrastructure headers on Vercel.
    # They should not be treated as evidence that the user's connection is exposed.
    indicators = []
    via = handler.headers.get("via", "")
    if via:
        indicators.append("Gateway/proxy Via header present")

    https_ok = forwarded_proto.lower() == "https" or os.environ.get("VERCEL") == "1"
    if not https_ok:
        indicators.append("Connection is not using HTTPS")

    safe = https_ok

    return {
        "ok": True,
        "ip": ip,
        "location": location,
        "country": country or "--",
        "region": region or "--",
        "city": city or "--",
        "isp": "Edge network / ISP unavailable",
        "protocol": forwarded_proto.upper(),
        "is_https": https_ok,
        "is_local": is_local,
        "indicators": indicators,
        "safety": "protected" if safe else "warning",
        "verdict": "Safe" if safe else "Exposed",
        "wifi_assessment": "Not detectable from server headers",
        "dns_leak_check": "Not available from browser headers",
        "risk_factors": indicators,
    }


def requested_size(query):
    try:
        return min(max(int(query.get("size", ["128"])[0]), 16), 4096)
    except (TypeError, ValueError):
        return 128


def requested_route(handler):
    parsed = urlparse(handler.path)
    query = parse_qs(parsed.query)
    # Rewrites send /api/<route> to /api/index.py?route=<route>.
    # Keep a fallback for direct /api/index.py requests.
    route = query.get("route", [""])[0].strip().strip("/").lower()
    if not route:
        path = parsed.path.lower().rstrip("/")
        if path.endswith("/index.py"):
            route = ""
        elif path.startswith("/api/"):
            route = path[len("/api/"):].strip("/")
    return route, query


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, payload):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        try:
            route, query = requested_route(self)

            if route == "health":
                self._send_json({"ok": True, "service": "DECAN Internet Speed Test API"})
                return

            if route == "ping":
                self._send_json({"ok": True, "timestamp": time.time()})
                return

            if route == "info":
                self._send_json(network_report(self))
                return

            if route == "download":
                size_kb = requested_size(query)
                self._send_bytes(b"0" * (size_kb * 1024))
                return

            self._send_json({"ok": False, "error": "Not found", "route": route}, 404)
        except Exception as exc:
            try:
                self._send_json({"ok": False, "error": "Internal server error", "detail": str(exc)}, 500)
            except Exception:
                pass

    def do_POST(self):
        try:
            route, _ = requested_route(self)
            if route not in {"upload", "ping"}:
                self._send_json({"ok": False, "error": "Not found", "route": route}, 404)
                return

            try:
                content_length = max(0, min(int(self.headers.get("Content-Length", "0")), 4 * 1024 * 1024))
            except (TypeError, ValueError):
                content_length = 0

            remaining = content_length
            while remaining:
                chunk = self.rfile.read(min(remaining, 1024 * 1024))
                if not chunk:
                    break
                remaining -= len(chunk)

            self._send_json({"ok": True, "received": content_length})
        except Exception as exc:
            try:
                self._send_json({"ok": False, "error": "Internal server error", "detail": str(exc)}, 500)
            except Exception:
                pass

    def log_message(self, format, *args):
        return
