"""
interactsh client (attack section — runtime/I/O side, real protocol crypto).

Full out-of-band client for the OOB confirmation loop: it registers an RSA keypair with an interactsh
server (the operator's own, or a public one like oast.fun), hands out the OOB `domain` to embed in
payloads, and `poll()`s + DECRYPTS received interactions (RSA-OAEP-SHA256 unwraps the AES key;
AES-256-CFB decrypts each interaction). Plugs straight into `OOBConfirmer` (its `.poll` matches the
poller interface). This talks ONLY to the OOB server the operator supplies, never the target.

Transport is injectable (`fetch`/`post`) so the crypto is testable offline; the default uses urllib.
Requires `cryptography`. Sessions are serializable (`to_dict`/`from_dict`) so an MCP register→poll
flow can persist the keypair between calls.
"""

from __future__ import annotations

import base64
import json
import secrets
import ssl
import urllib.error
import urllib.request
import uuid
from typing import Callable, Dict, List, Optional

_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"


def _rand(n: int) -> str:
    return "".join(secrets.choice(_ALNUM) for _ in range(n))


class InteractshClient:
    def __init__(self, server: str = "oast.fun", timeout: float = 15.0, verify_tls: bool = True,
                 fetch: Optional[Callable[[str], bytes]] = None,
                 post: Optional[Callable[[str, Dict], int]] = None, _private=None,
                 correlation_id: str = "", secret: str = "", suffix: str = ""):
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.server = server.strip("/")
        self.timeout = timeout
        self._ctx = None if verify_tls else ssl._create_unverified_context()
        self._fetch = fetch
        self._post = post
        self._private = _private or rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.correlation_id = correlation_id or _rand(20)
        self.secret = secret or str(uuid.uuid4())
        self.suffix = suffix or _rand(13)
        self.registered = False

    @property
    def domain(self) -> str:
        """The OOB domain to embed in payloads (wildcard-captured by interactsh)."""
        return f"{self.correlation_id}{self.suffix}.{self.server}"

    # ── crypto ───────────────────────────────────────────────────────────────────
    def public_key_b64(self) -> str:
        from cryptography.hazmat.primitives import serialization
        pem = self._private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(pem).decode()

    def register_payload(self) -> Dict:
        return {"public-key": self.public_key_b64(), "secret-key": self.secret,
                "correlation-id": self.correlation_id}

    def decrypt(self, data_items: List[str], aes_key_b64: str) -> List[Dict]:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        aes_key = self._private.decrypt(
            base64.b64decode(aes_key_b64),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        out: List[Dict] = []
        for item in data_items or []:
            try:
                raw = base64.b64decode(item)
                iv, ct = raw[:16], raw[16:]
                dec = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
                j = json.loads((dec.update(ct) + dec.finalize()).decode("utf-8", "replace"))
            except Exception:
                continue
            host = j.get("full-id") or j.get("unique-id") or ""
            out.append({"host": str(host), "protocol": str(j.get("protocol", "")),
                        "remote_addr": str(j.get("remote-address", "")), "raw": j})
        return out

    # ── transport ────────────────────────────────────────────────────────────────
    def _http_get(self, url: str) -> bytes:
        if self._fetch is not None:
            return self._fetch(url)
        req = urllib.request.Request(url, headers={"User-Agent": "hydra-oob/1.0"})
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self._ctx))
        with opener.open(req, timeout=self.timeout) as r:
            return r.read(1 << 20)

    def _http_post(self, url: str, body: Dict) -> int:
        if self._post is not None:
            return self._post(url, body)
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "hydra-oob/1.0"})
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self._ctx))
        try:
            with opener.open(req, timeout=self.timeout) as r:
                return getattr(r, "status", r.getcode())
        except urllib.error.HTTPError as e:
            return e.code

    def register(self) -> bool:
        try:
            self.registered = self._http_post(
                f"https://{self.server}/register", self.register_payload()) in (200, 201)
        except Exception:
            self.registered = False
        return self.registered

    def poll(self) -> List[Dict]:
        try:
            raw = self._http_get(
                f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}")
            j = json.loads(raw.decode("utf-8", "replace")) if isinstance(raw, (bytes, bytearray)) \
                else raw
            return self.decrypt(j.get("data") or [], j.get("aes_key", ""))
        except Exception:
            return []

    # ── persistence (operator's own OOB session) ────────────────────────────────
    def to_dict(self) -> Dict:
        from cryptography.hazmat.primitives import serialization
        pem = self._private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        return {"server": self.server, "correlation_id": self.correlation_id,
                "secret": self.secret, "suffix": self.suffix, "private_pem": pem}

    @classmethod
    def from_dict(cls, d: Dict, **kw) -> "InteractshClient":
        from cryptography.hazmat.primitives import serialization
        priv = serialization.load_pem_private_key(d["private_pem"].encode(), password=None)
        return cls(server=d["server"], _private=priv, correlation_id=d["correlation_id"],
                   secret=d["secret"], suffix=d["suffix"], **kw)
