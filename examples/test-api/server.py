"""
Example API server for stig-api-scanner integration testing.

Intentional security posture — a mix of PASS and FAIL findings so the scanner
has real output to demonstrate:

  PASS:  /api/v1/health  — public, always 200
  PASS:  /api/v1/users   — returns 401 + WWW-Authenticate without a valid token
  PASS:  /api/v1/users   — returns 200 with a valid Bearer token
  PASS:  TRACE disabled   — returns 405
  PASS:  Unknown path     — generic 404, no internal details leaked

  FAIL:  Missing Strict-Transport-Security header       (V-274600)
  FAIL:  Missing X-Content-Type-Options header          (V-274497)
  FAIL:  Missing X-Frame-Options header                 (V-274497)
  FAIL:  Missing Content-Security-Policy header         (V-274767)
  FAIL:  Missing Cache-Control header                   (V-274607)
  FAIL:  Missing X-RateLimit-* headers                  (V-274612)
  FAIL:  CORS Access-Control-Allow-Origin: * (wildcard) (V-274613)

These intentional gaps let you verify the scanner catches real issues.
Set the pipeline.fail_severity to 'critical' in stig-config.yaml so CI passes
while still surfacing the MEDIUM/HIGH findings via SARIF.

Usage:
  # Generate certs first (handled by CI or setup.sh)
  python3 server.py

Environment variables:
  PORT      Listening port (default: 8443)
  TLS_CERT  Path to PEM certificate (default: cert.pem)
  TLS_KEY   Path to PEM private key (default: key.pem)
  API_TOKEN Expected Bearer token  (default: stig-test-token)
"""

import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

API_TOKEN = os.environ.get("API_TOKEN", "stig-test-token")


class Handler(BaseHTTPRequestHandler):
    # ── Routing ──────────────────────────────────────────────────────────────

    def do_OPTIONS(self):
        """Preflight handler — intentionally uses wildcard CORS (V-274613 FAIL)."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/api/v1/health"):
            self._ok({"status": "ok", "service": "stig-test-api", "version": "1.0.0"})
        elif path.startswith("/api/v1/users"):
            self._protected(lambda: {"users": [], "total": 0, "page": 1, "per_page": 20})
        elif path.startswith("/api/v1/admin"):
            self._protected(lambda: {"config": {}})
        else:
            self._not_found()

    def do_POST(self):
        path = self.path.split("?")[0]
        if path.startswith("/api/v1/users"):
            self._protected(lambda: {"id": 1, "created": True})
        else:
            self._not_found()

    # TRACE is not handled → falls through to 405 below
    def do_TRACE(self):
        self._method_not_allowed()

    def do_DELETE(self):
        self._method_not_allowed()

    def do_PUT(self):
        self._method_not_allowed()

    def do_PATCH(self):
        self._method_not_allowed()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _ok(self, body: dict):
        self._respond(200, body)

    def _protected(self, body_fn):
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {API_TOKEN}":
            self._respond(200, body_fn())
        else:
            payload = json.dumps({"error": "unauthorized"}).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("WWW-Authenticate", 'Bearer realm="stig-test-api"')
            self._add_security_headers()
            self.end_headers()
            self.wfile.write(payload)

    def _not_found(self):
        # Generic message — no internal paths or stack traces (V-274615 PASS)
        self._respond(404, {"error": "not found"})

    def _method_not_allowed(self):
        self._respond(405, {"error": "method not allowed"})

    def _respond(self, status: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _add_security_headers(self):
        """
        Intentionally incomplete — omits several required security headers so the
        scanner finds real STIG violations. Add the commented lines to make those
        checks pass and verify the scanner correctly reports PASS instead.
        """
        # PASS: referrer policy is set
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")

        # FAIL: missing headers (uncomment to turn these into PASS findings):
        # self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # self.send_header("X-Content-Type-Options", "nosniff")
        # self.send_header("X-Frame-Options", "DENY")
        # self.send_header("Content-Security-Policy", "default-src 'none'")
        # self.send_header("Cache-Control", "no-store, private")
        # self.send_header("X-RateLimit-Limit", "100")
        # self.send_header("X-RateLimit-Remaining", "99")
        # self.send_header("X-RateLimit-Reset", "60")

    def log_message(self, fmt, *args):
        print(f"[test-api] {self.address_string()} {fmt % args}", file=sys.stderr)


def main():
    port = int(os.environ.get("PORT", "8443"))
    cert = os.environ.get("TLS_CERT", "cert.pem")
    key = os.environ.get("TLS_KEY", "key.pem")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    server = HTTPServer(("127.0.0.1", port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"[test-api] https://127.0.0.1:{port}  (token: {API_TOKEN})", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[test-api] Shutting down.", file=sys.stderr)


if __name__ == "__main__":
    main()
