"""
Follow-on features: CSRF/multi-step login (live local server) + the interactsh client crypto
(register payload, AES-CFB/RSA-OAEP decrypt round-trip, persistence, injected-transport poll —
all without network).
"""

import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from hydra.attack_runtime import InteractshClient, LoginFlow
from hydra.authorization import BugBountyAuthorizationGate


# ── CSRF / multi-step login ──────────────────────────────────────────────────────
class _CsrfApp(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlparse(self.path).path == "/login":
            self.send_response(200)
            self.send_header("Set-Cookie", "csrftoken=COOKIE123")
            self.end_headers()
            self.wfile.write(b'<input type=hidden name="csrf_token" value="TOK-abc-123">')
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        if "csrf_token=TOK-abc-123" in body:
            self.send_response(200)
            self.send_header("Set-Cookie", "session=LOGGEDIN")
            self.end_headers()
        else:
            self.send_response(403)
            self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def csrf_server():
    srv = HTTPServer(("127.0.0.1", 0), _CsrfApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "p.json"))
    g = BugBountyAuthorizationGate()
    g.register_program("local", "custom", in_scope=["127.0.0.1"])
    return g


def test_csrf_login_extracts_token_and_authenticates(gate, csrf_server):
    s = LoginFlow(gate=gate).login(f"{csrf_server}/login", {"user": "alice", "pass": "x"},
                                   csrf_field="csrf_token")
    assert s is not None
    assert s.cookies.get("session") == "LOGGEDIN"     # POST accepted → CSRF token was sent
    assert s.cookies.get("csrftoken") == "COOKIE123"  # pre-login cookie carried


def test_login_without_csrf_field_is_rejected_by_server(gate, csrf_server):
    s = LoginFlow(gate=gate).login(f"{csrf_server}/login", {"user": "a"})   # no csrf → 403
    assert s.cookies.get("session") is None


# ── interactsh client crypto (no network) ───────────────────────────────────────
def _server_encrypt(client: InteractshClient, interaction: dict):
    """Simulate the interactsh server: AES-CFB encrypt the interaction, RSA-wrap the AES key."""
    pub = serialization.load_pem_public_key(base64.b64decode(client.public_key_b64()))
    aes, iv = os.urandom(32), os.urandom(16)
    enc = Cipher(algorithms.AES(aes), modes.CFB(iv)).encryptor()
    ct = iv + enc.update(json.dumps(interaction).encode()) + enc.finalize()
    wrapped = pub.encrypt(aes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                            algorithm=hashes.SHA256(), label=None))
    return {"data": [base64.b64encode(ct).decode()], "aes_key": base64.b64encode(wrapped).decode()}


def test_register_payload_shape():
    c = InteractshClient(server="oast.example")
    p = c.register_payload()
    assert set(p) == {"public-key", "secret-key", "correlation-id"}
    assert base64.b64decode(p["public-key"]).startswith(b"-----BEGIN PUBLIC KEY-----")
    assert c.domain.endswith(".oast.example") and len(c.correlation_id) == 20


def test_decrypt_roundtrip():
    c = InteractshClient(server="oast.example")
    blob = _server_encrypt(c, {"protocol": "dns", "full-id": "tok.abc", "remote-address": "8.8.8.8"})
    out = c.decrypt(blob["data"], blob["aes_key"])
    assert len(out) == 1 and out[0]["protocol"] == "dns" and out[0]["remote_addr"] == "8.8.8.8"


def test_poll_with_injected_fetch():
    c = InteractshClient(server="oast.example")
    blob = _server_encrypt(c, {"protocol": "http", "full-id": "tok.xyz"})
    c._fetch = lambda url: json.dumps(blob).encode()
    out = c.poll()
    assert out and out[0]["protocol"] == "http"


def test_persistence_roundtrip():
    c = InteractshClient(server="oast.example")
    c2 = InteractshClient.from_dict(c.to_dict())
    assert c2.domain == c.domain and c2.secret == c.secret
    blob = _server_encrypt(c, {"protocol": "dns", "full-id": "t"})   # encrypted to c's pubkey
    assert c2.decrypt(blob["data"], blob["aes_key"])[0]["protocol"] == "dns"   # c2 has the key


def test_register_defensive_on_failure():
    c = InteractshClient(server="oast.example", post=lambda url, body: (_ for _ in ()).throw(OSError()))
    assert c.register() is False        # never raises
