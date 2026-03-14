"""Mosquitto-compatible PBKDF2-SHA512 password hashing."""

import base64
import hashlib
import os

_ITERATIONS: int = 101
_SALT_BYTES: int = 12
_KEY_BYTES: int = 64


def _hash_password(password: str, salt: bytes, iterations: int = _ITERATIONS) -> str:
    """Return a Mosquitto $7$ formatted hash string (without the username prefix)."""
    dk = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations, _KEY_BYTES)
    salt_b64 = base64.b64encode(salt).decode()
    hash_b64 = base64.b64encode(dk).decode()
    return f"$7${iterations}${salt_b64}${hash_b64}"


def format_entry(username: str, password: str) -> str:
    """Return a single Mosquitto password file line: ``username:$7$...``."""
    salt = os.urandom(_SALT_BYTES)
    return f"{username}:{_hash_password(password, salt)}"


def format_entry_with_salt(username: str, password: str, salt: bytes) -> str:
    """Deterministic variant used in tests — accepts an explicit salt."""
    return f"{username}:{_hash_password(password, salt)}"
