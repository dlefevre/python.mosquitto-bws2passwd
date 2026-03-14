"""Mosquitto-compatible PBKDF2-SHA512 password hashing."""

import base64
import hashlib
import hmac
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


def verify_password(password: str, digest: str) -> bool:
    """Check *password* against a ``$7$<iter>$<salt_b64>$<hash_b64>`` digest."""
    parts = digest.split("$")
    # Expected: ['', '7', '<iter>', '<salt_b64>', '<hash_b64>']
    if len(parts) != 5 or parts[1] != "7":
        return False
    iterations = int(parts[2])
    salt = base64.b64decode(parts[3])
    stored_hash = base64.b64decode(parts[4])
    dk = hashlib.pbkdf2_hmac(
        "sha512", password.encode(), salt, iterations, _KEY_BYTES
    )
    return hmac.compare_digest(dk, stored_hash)


def parse_entries(content: str) -> dict[str, str]:
    """Parse a Mosquitto password file into ``{username: full_line}``.

    Blank lines and lines starting with ``#`` are skipped.
    """
    entries: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        username, _sep, _ = stripped.partition(":")
        if _sep:
            entries[username] = stripped
    return entries
