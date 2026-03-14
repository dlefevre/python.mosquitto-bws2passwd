"""Command-line entry point for bws2passwd."""

import argparse
import os
import re
import sys

from bws2passwd.bitwarden import fetch_secrets
from bws2passwd.passwd import format_entry, parse_entries, verify_password


def build_parser() -> argparse.ArgumentParser:
    return _build_parser()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bws2passwd",
        description=(
            "Generate a Mosquitto password file from Bitwarden Secrets Manager.\n\n"
            "The Bitwarden machine account access token must be supplied via the "
            "BWS_ACCESS_TOKEN environment variable.\n"
            "The Bitwarden organization ID must be supplied via the BWS_ORGANIZATION_ID environment variable."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--filter",
        required=True,
        metavar="PATTERN",
        help="Regular expression to filter secrets by key/name.",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    parser.add_argument(
        "-i",
        "--input",
        metavar="FILE",
        help="Existing password file. Unchanged passwords reuse their stored digest.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Report entry status (added/changed/unchanged/dropped) on stderr.",
    )
    return parser


def reconcile_entries(
    secrets: list[tuple[str, str]],
    existing: dict[str, str],
    verbose: bool = False,
) -> list[str]:
    """Merge fetched secrets with existing digests.

    Returns sorted password-file lines.  When *verbose* is ``True``,
    status messages (added/changed/unchanged/dropped) are printed to
    stderr.
    """
    sorted_secrets = sorted(secrets, key=lambda s: s[0])
    fetched_keys: set[str] = set()

    lines: list[str] = []
    for key, value in sorted_secrets:
        fetched_keys.add(key)
        entry = existing.get(key)
        if entry is not None:
            digest = entry.split(":", 1)[1]
            if verify_password(value, digest):
                lines.append(entry)
                if verbose:
                    print(f"unchanged: {key}", file=sys.stderr)
                continue
            if verbose:
                print(f"changed: {key}", file=sys.stderr)
        else:
            if verbose:
                print(f"added: {key}", file=sys.stderr)
        lines.append(format_entry(key, value))

    if verbose:
        for key in sorted(existing.keys() - fetched_keys):
            print(f"dropped: {key}", file=sys.stderr)

    return lines


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    access_token = os.environ.get("BWS_ACCESS_TOKEN")
    if not access_token:
        parser.error(f"Environment variable BWS_ACCESS_TOKEN is not set.")
    organization_id = os.environ.get("BWS_ORGANIZATION_ID")
    if not organization_id:
        parser.error(f"Environment variable BWS_ORGANIZATION_ID is not set.")

    try:
        re.compile(args.filter)
    except re.error as exc:
        parser.error(f"Invalid regular expression for --filter: {exc}")

    try:
        secrets = fetch_secrets(access_token, organization_id, args.filter)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    existing: dict[str, str] = {}
    if args.input:
        with open(args.input, encoding="utf-8") as fh:
            existing = parse_entries(fh.read())

    lines = reconcile_entries(secrets, existing, verbose=args.verbose)
    output = "\n".join(lines) + ("\n" if lines else "")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        sys.stdout.write(output)
