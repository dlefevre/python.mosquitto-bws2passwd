"""Tests for bws2passwd.cli — argument parsing and output routing."""

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bws2passwd.cli import build_parser, main
from bws2passwd.passwd import format_entry_with_salt

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_TOKEN = "0.AAAA.SECRET"
_VALID_ORG_ID = "mock-org-id"

# A minimal org_id extracted from a token whose second segment decodes to JSON
# with an organizationId.  We use "mock-org-id" as the sentinel value and
# patch _extract_org_id so no real token parsing happens.

_MOCK_SECRETS = [("mqtt/alice", "password1"), ("mqtt/bob", "password2")]


def _patch_fetch(secrets: list[tuple[str, str]]) -> "MagicMock":
    """Return a patch context manager for bws2passwd.cli.fetch_secrets."""
    return patch("bws2passwd.cli.fetch_secrets", return_value=secrets) # pyright: ignore[reportReturnType]


# ---------------------------------------------------------------------------
# Argument parser tests
# ---------------------------------------------------------------------------


class TestArgumentParser:
    def test_filter_required(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args([])
        assert exc_info.value.code != 0

    def test_filter_short_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", "mqtt/.*"])
        assert args.filter == "mqtt/.*"

    def test_filter_long_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--filter", "mqtt/.*"])
        assert args.filter == "mqtt/.*"

    def test_output_optional(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", ".*"])
        assert args.output is None

    def test_output_long_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", ".*", "--output", "/tmp/passwd.txt"])
        assert args.output == "/tmp/passwd.txt"

    def test_input_optional(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", ".*"])
        assert args.input is None

    def test_input_short_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", ".*", "-i", "/tmp/existing.txt"])
        assert args.input == "/tmp/existing.txt"

    def test_input_long_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", ".*", "--input", "/tmp/existing.txt"])
        assert args.input == "/tmp/existing.txt"


# ---------------------------------------------------------------------------
# main() integration tests
# ---------------------------------------------------------------------------


class TestMain:
    def test_missing_env_var_exits_nonzero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BWS_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("BWS_ORGANIZATION_ID", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["bws2passwd", "-f", ".*"]):
                main()
        assert exc_info.value.code != 0

    def test_invalid_filter_regex_exits_nonzero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["bws2passwd", "-f", "[invalid"]):
                main()
        assert exc_info.value.code != 0

    def test_stdout_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        with _patch_fetch(_MOCK_SECRETS):
            with patch("sys.argv", ["bws2passwd", "-f", "mqtt/.*"]):
                main()
        captured = capsys.readouterr()
        lines = captured.out.strip().splitlines()
        assert len(lines) == 2
        assert lines[0].startswith("mqtt/alice:")
        assert lines[1].startswith("mqtt/bob:")

    def test_file_output(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        out_file = tmp_path / "passwd.txt"
        with _patch_fetch(_MOCK_SECRETS):
            with patch("sys.argv", ["bws2passwd", "-f", "mqtt/.*", "-o", str(out_file)]):
                main()
        content = out_file.read_text()
        lines = content.strip().splitlines()
        assert len(lines) == 2
        assert lines[0].startswith("mqtt/alice:")

    def test_empty_result_produces_empty_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        with _patch_fetch([]):
            with patch("sys.argv", ["bws2passwd", "-f", "nomatch"]):
                main()
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_output_lines_are_mosquitto_format(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Each output line must match ``username:$7$...$...$...``."""
        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        with _patch_fetch([("alice", "pw")]):
            with patch("sys.argv", ["bws2passwd", "-f", ".*"]):
                main()
        captured = capsys.readouterr()
        line = captured.out.strip()
        assert re.fullmatch(
            r"[^:]+:\$7\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+",
            line,
        ), f"Unexpected format: {line!r}"


# ---------------------------------------------------------------------------
# --input tests
# ---------------------------------------------------------------------------

_FIXED_SALT = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"


class TestInputFlag:
    def test_matching_password_reuses_digest(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        existing_line = format_entry_with_salt("alice", "password1", _FIXED_SALT)
        input_file = tmp_path / "existing.txt"
        input_file.write_text(existing_line + "\n")

        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        out_file = tmp_path / "output.txt"
        with _patch_fetch([("alice", "password1")]):
            with patch(
                "sys.argv",
                ["bws2passwd", "-f", ".*", "-i", str(input_file), "-o", str(out_file)],
            ):
                main()
        output = out_file.read_text().strip()
        assert output == existing_line

    def test_changed_password_generates_new_hash(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        existing_line = format_entry_with_salt("alice", "oldpass", _FIXED_SALT)
        input_file = tmp_path / "existing.txt"
        input_file.write_text(existing_line + "\n")

        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        out_file = tmp_path / "output.txt"
        with _patch_fetch([("alice", "newpass")]):
            with patch(
                "sys.argv",
                ["bws2passwd", "-f", ".*", "-i", str(input_file), "-o", str(out_file)],
            ):
                main()
        output = out_file.read_text().strip()
        assert output != existing_line
        assert output.startswith("alice:$7$")

    def test_extra_entries_in_input_are_dropped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        alice_line = format_entry_with_salt("alice", "pw", _FIXED_SALT)
        extra_line = format_entry_with_salt("eve", "evil", _FIXED_SALT)
        input_file = tmp_path / "existing.txt"
        input_file.write_text(alice_line + "\n" + extra_line + "\n")

        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        out_file = tmp_path / "output.txt"
        with _patch_fetch([("alice", "pw")]):
            with patch(
                "sys.argv",
                ["bws2passwd", "-f", ".*", "-i", str(input_file), "-o", str(out_file)],
            ):
                main()
        lines = out_file.read_text().strip().splitlines()
        assert len(lines) == 1
        assert lines[0] == alice_line

    def test_new_secret_not_in_input_gets_new_hash(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        input_file = tmp_path / "existing.txt"
        input_file.write_text("alice:$7$101$abc$def\n")

        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        with _patch_fetch([("bob", "newpw")]):
            with patch(
                "sys.argv",
                ["bws2passwd", "-f", ".*", "-i", str(input_file)],
            ):
                main()
        captured = capsys.readouterr()
        assert captured.out.startswith("bob:$7$")

    def test_without_input_flag_behaviour_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        with _patch_fetch([("alice", "pw")]):
            with patch("sys.argv", ["bws2passwd", "-f", ".*"]):
                main()
        captured = capsys.readouterr()
        assert re.fullmatch(
            r"[^:]+:\$7\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+",
            captured.out.strip(),
        )

    def test_input_and_output_same_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``-i`` and ``-o`` may point to the same file."""
        existing_line = format_entry_with_salt("alice", "pw", _FIXED_SALT)
        passwd_file = tmp_path / "passwd.txt"
        passwd_file.write_text(existing_line + "\n")

        monkeypatch.setenv("BWS_ACCESS_TOKEN", _VALID_TOKEN)
        monkeypatch.setenv("BWS_ORGANIZATION_ID", _VALID_ORG_ID)
        with _patch_fetch([("alice", "pw")]):
            with patch(
                "sys.argv",
                ["bws2passwd", "-f", ".*", "-i",
                 str(passwd_file), "-o", str(passwd_file)],
            ):
                main()
        output = passwd_file.read_text().strip()
        assert output == existing_line
