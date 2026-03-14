# Copilot Instructions

## Project

Python init container that generates a Mosquitto password file from Bitwarden Secrets Manager. Intended to run in Kubernetes (k3s).

## Architecture

- Entry point: `bws2passwd` CLI tool installed via `[project.scripts]` in `pyproject.toml`.
- `src/bws2passwd/cli.py` — argparse wiring; reads `BWS_ACCESS_TOKEN` env var.
- `src/bws2passwd/bitwarden.py` — wraps `bitwarden-sdk`; extracts org ID from the access token, lists secrets, filters by regexp on secret key/name, fetches matching values.
- `src/bws2passwd/passwd.py` — PBKDF2-HMAC-SHA512 hashing in Mosquitto `$7$` format (`username:$7$<iterations>$<salt_b64>$<hash_b64>`). Does **not** shell out to `mosquitto_passwd`.
- Runs as a Kubernetes init container — exits after completing its task.

## Commands

```sh
# Install / sync dependencies
uv sync

# Run all tests
uv run pytest -v

# Run a single test
uv run pytest tests/test_passwd.py::TestFormatEntryWithSalt::test_line_format

# Lint
uv run ruff check src tests

# Type-check
uv run pyright
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `BWS_ACCESS_TOKEN` | Yes | Bitwarden SM machine account access token. The org ID is extracted from this token — no separate org ID variable is needed. |

## Code Style

- **Formatter**: [Black](https://black.readthedocs.io/) — all code must be Black-compliant. Line length follows Black defaults (88).
- **Import sorting**: [isort](https://pycli.readthedocs.io/projects/isort/) with Black-compatible profile (`profile = "black"`).
- **Type checking**: [Pyright](https://github.com/microsoft/pyright) in strict mode — all code must pass with no errors. Annotate all function signatures and variables where inference is insufficient.
- **Linting**: [Ruff](https://docs.astral.sh/ruff/) for fast lint checks (complements Black; do not use conflicting rules).

## Naming Conventions

- Modules and packages: `snake_case`
- Classes: `PascalCase`
- Functions, variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Type aliases: `PascalCase`

## Testing

- Framework: [pytest](https://docs.pytest.org/)
- Bitwarden SDK is always mocked in tests (`unittest.mock`) — no live API calls.
- `passwd.py` exposes `format_entry_with_salt()` (accepts an explicit salt) for deterministic test assertions.
