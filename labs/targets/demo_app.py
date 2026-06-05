import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


SCENARIO = os.getenv("LAB_SCENARIO", "all")
FAKE_SECRET = "LAB_ONLY_NOT_A_REAL_SECRET"


class Handler(BaseHTTPRequestHandler):
    def _send(self, status=200, body="", content_type="text/plain", headers=None):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self._send(204, headers={
            "Access-Control-Allow-Origin": self.headers.get("Origin", "*"),
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET,HEAD,OPTIONS,TRACE",
        })

    def do_TRACE(self):
        self._send(200, "TRACE enabled in local demo only")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._send(200, "ok")
        elif path in {"/cors-data", "/api/profile"} and SCENARIO in {"all", "weak-cors"}:
            self._send(200, json.dumps({"account": "LAB-ACCOUNT", "balance": 42}), "application/json", {
                "Access-Control-Allow-Origin": self.headers.get("Origin", "*"),
                "Access-Control-Allow-Credentials": "true",
            })
        elif path == "/redirect" and SCENARIO in {"all", "open-redirect"}:
            destination = parse_qs(parsed.query).get("url", ["/"])[0]
            self._send(302, "", headers={"Location": destination})
        elif path == "/actuator/env" and SCENARIO in {"all", "exposed-actuator"}:
            self._send(200, json.dumps({"LAB_ONLY_TOKEN": FAKE_SECRET}), "application/json")
        elif path in {"/openapi.json", "/swagger.json"} and SCENARIO in {"all", "api-docs"}:
            self._send(200, json.dumps({
                "openapi": "3.0.0",
                "info": {"title": "ARES Lab API", "version": "1.0"},
                "paths": {"/api/profile": {"get": {}}, "/admin/metrics": {"get": {}}},
            }), "application/json")
        elif path == "/app.js" and SCENARIO in {"all", "js-secret"}:
            self._send(200, f'window.LAB_ONLY_TOKEN="{FAKE_SECRET}";', "application/javascript")
        elif path == "/host" and SCENARIO in {"all", "host-header"}:
            host = self.headers.get("Host", "")
            self._send(200, f"absolute_url=http://{host}/reset")
        elif path in {"/", "/frame-target"}:
            self._send(200, "<h1>ARES Local Demo Lab</h1><script src='/app.js'></script>", "text/html")
        else:
            self._send(404, "not found")

    def log_message(self, format, *args):
        return


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
