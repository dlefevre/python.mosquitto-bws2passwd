"""Tests for bws2passwd.passwd — password hashing module."""

import base64
import hashlib
import re

import pytest

from bws2passwd.passwd import format_entry, format_entry_with_salt

_FIXED_SALT = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
_ITERATIONS = 101
_KEY_BYTES = 64


class TestFormatEntryWithSalt:
    def test_line_format(self) -> None:
        """Output must be ``username:$7$<int>$<b64>$<b64>``."""
        line = format_entry_with_salt("alice", "secret", _FIXED_SALT)
        assert re.fullmatch(
            r"[^:]+:\$7\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+",
            line,
        ), f"Unexpected format: {line!r}"

    def test_username_prefix(self) -> None:
        line = format_entry_with_salt("alice", "secret", _FIXED_SALT)
        username, rest = line.split(":", 1)
        assert username == "alice"
        assert rest.startswith("$7$")

    def test_field_count(self) -> None:
        """Hash string must have exactly 4 dollar-sign delimited fields after $7."""
        line = format_entry_with_salt("bob", "pass", _FIXED_SALT)
        hash_part = line.split(":", 1)[1]
        # expected: $7$<iter>$<salt>$<hash>  → split("$") gives ['', '7', iter, salt, hash]
        fields = hash_part.split("$")
        assert len(fields) == 5

    def test_iterations_field(self) -> None:
        line = format_entry_with_salt("alice", "x", _FIXED_SALT)
        fields = line.split(":", 1)[1].split("$")
        assert fields[2] == str(_ITERATIONS)

    def test_salt_base64(self) -> None:
        line = format_entry_with_salt("alice", "x", _FIXED_SALT)
        salt_b64 = line.split("$")[3]
        decoded = base64.b64decode(salt_b64)
        assert decoded == _FIXED_SALT

    def test_hash_base64_length(self) -> None:
        """Decoded hash must be 64 bytes (SHA-512 output)."""
        line = format_entry_with_salt("alice", "x", _FIXED_SALT)
        hash_b64 = line.split("$")[4]
        decoded = base64.b64decode(hash_b64)
        assert len(decoded) == _KEY_BYTES

    def test_determinism(self) -> None:
        """Same inputs → same output when salt is fixed."""
        line1 = format_entry_with_salt("alice", "hunter2", _FIXED_SALT)
        line2 = format_entry_with_salt("alice", "hunter2", _FIXED_SALT)
        assert line1 == line2

    def test_different_passwords_differ(self) -> None:
        line1 = format_entry_with_salt("alice", "password1", _FIXED_SALT)
        line2 = format_entry_with_salt("alice", "password2", _FIXED_SALT)
        assert line1 != line2

    def test_hash_correctness(self) -> None:
        """Verify the hash matches a direct PBKDF2 call."""
        line = format_entry_with_salt("alice", "secret", _FIXED_SALT)
        hash_b64 = line.split("$")[4]
        expected_dk = hashlib.pbkdf2_hmac(
            "sha512", b"secret", _FIXED_SALT, _ITERATIONS, _KEY_BYTES
        )
        assert base64.b64decode(hash_b64) == expected_dk


class TestFormatEntry:
    def test_random_salt_used(self) -> None:
        """Two calls with the same credentials should produce different salts."""
        line1 = format_entry("alice", "secret")
        line2 = format_entry("alice", "secret")
        salt1 = line1.split("$")[3]
        salt2 = line2.split("$")[3]
        # Extremely unlikely to collide — if it does, rerun the test suite.
        assert salt1 != salt2

    def test_output_format(self) -> None:
        line = format_entry("carol", "pw")
        assert re.fullmatch(
            r"carol:\$7\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+",
            line,
        ), f"Unexpected format: {line!r}"
