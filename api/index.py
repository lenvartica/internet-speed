import json
import os
import time
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

    safe = https_ok and not (forwarded.count(",") > 1 or bool(via))
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
        return min(max(int(query.get("size", ["128"])[0]), 16), 4096)
    except (TypeError, ValueError):
        return 128


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        try:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            # Last resort – try to send something
            pass

    def _send_bytes(self, payload):
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(payload)
        except Exception:
            pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.lower()          # make matching case-insensitive
            query = parse_qs(parsed.query)

            # Very forgiving matching (works with /api/ping, /ping, /something/ping/, etc.)
            if "ping" in path:
                self._send_json({"ok": True, "timestamp": time.time()})
                return

            if "download" in path:
                size_kb = requested_size(query)
                self._send_bytes(b"0" * (size_kb * 1024))
                return

            # info / network / root / api
            if (
                "info" in path
                or "network" in path
                or path.rstrip("/") in ("", "/", "/api")
                or path.endswith("/api")
            ):
                self._send_json(network_report(self))
                return

            self._send_json({"ok": False, "error": "Not found", "path": self.path}, 404)

        except Exception as e:
            self._send_json({"ok": False, "error": "Internal server error", "detail": str(e)}, 500)

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.lower()

            try:
                content_length = max(0, min(int(self.headers.get("Content-Length", "0")), 1024 * 1024))
            except (TypeError, ValueError):
                content_length = 0

            if "ping" in path or "upload" in path:
                if content_length > 0:
                    self.rfile.read(content_length)
                self._send_json({"ok": True, "received": content_length})
                return

            self._send_json({"ok": False, "error": "Not found", "path": self.path}, 404)

        except Exception as e:
            self._send_json({"ok": False, "error": "Internal server error", "detail": str(e)}, 500)

    def log_message(self, format, *args):
        # Silence default logging
        return
