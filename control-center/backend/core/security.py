from __future__ import annotations

import base64
import hashlib
import os

_KEY: bytes | None = None


def _derive_key(secret: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())


def _get_key() -> bytes:
    global _KEY
    if _KEY is None:
        from control_center.backend.core.config import get_settings
        _KEY = _derive_key(get_settings().secret_key)
    return _KEY


def encrypt_value(plaintext: str) -> str:
    try:
        from cryptography.fernet import Fernet
        return Fernet(_get_key()).encrypt(plaintext.encode()).decode()
    except ImportError:
        return base64.b64encode(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    try:
        from cryptography.fernet import Fernet
        return Fernet(_get_key()).decrypt(ciphertext.encode()).decode()
    except ImportError:
        return base64.b64decode(ciphertext.encode()).decode()


def mask_key(key: str) -> str:
    if len(key) <= 8:
        return "****"
    return key[:4] + "****" + key[-4:]
