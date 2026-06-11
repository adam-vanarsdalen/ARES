import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from utils.http_safety import safe_http_request
from utils.roe import parse_roe_policy
from utils.scope_validator import Scope, ScopeValidator


class _RedirectHandler(BaseHTTPRequestHandler):
    requests_seen = 0

    def do_GET(self):
        type(self).requests_seen += 1
        self.send_response(302)
        self.send_header("Location", f"http://127.0.0.2:{self.server.server_port}/private")
        self.end_headers()

    def log_message(self, format, *args):
        return


def test_redirect_to_out_of_scope_private_address_is_blocked_without_body_fetch():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    roe = parse_roe_policy({"engagement": {
        "allowed_ips": ["127.0.0.1"],
        "allowed_cidrs": ["127.0.0.1/32"],
        "allowed_profiles": ["lab"],
        "lab_targets": ["127.0.0.1"],
    }})
    scope = ScopeValidator(
        Scope(ip_ranges=["127.0.0.1/32"]),
        roe=roe,
        profile="lab",
        enforce_resolution=True,
    )
    try:
        _RedirectHandler.requests_seen = 0
        result = safe_http_request(
            f"http://127.0.0.1:{server.server_port}/start",
            scope,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result.error == "redirect_blocked"
    assert result.blocked_redirect["destination_url"].startswith("http://127.0.0.2:")
    assert result.blocked_redirect["body_fetched"] is False
    assert _RedirectHandler.requests_seen == 1
