# Contributing

## Development setup

Use Python 3.12 or newer from a local checkout:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

The editable installation provides the `panos-tunnel-builder` command. The
repository also includes a `main.py` launcher. Project dependencies and tool
settings are defined in [pyproject.toml](pyproject.toml).

## Checks

Run the same checks as [GitHub Actions](.github/workflows/ci.yml):

```bash
pytest -q
ruff check .
mypy src
pyright
```

Tests use mocks and XML fixtures and do not require a live Panorama connection.
For a coverage report, run `pytest --cov=panos_tunnel_builder --cov-report=term-missing`.
To check packaging, run `python -m pip wheel --no-deps --wheel-dir dist .`.

Pyright/Pylance uses the local `.venv` and checks both `src` and `tests`; mypy
checks `src`. Add regression coverage for behavioral changes, especially
candidate writes, rollback, shared-template scope, and route comparison.

## Repository layout

```text
src/panos_tunnel_builder/   Application and CLI
tests/                    Unit and regression tests
docs/                     Operator and design documentation
.github/workflows/        Continuous integration
```

## Preparing a change

Describe the behavior change and how it was validated. Update the relevant guide
when commands, configuration, supported topologies, or safeguards change. Keep
code and test links in the [validation guide](docs/validation.md) current.
Record live lab evidence separately from mocked tests, including its scope and
limitations. Do not infer production validation from a passing unit suite.

`.env`, `panos-tunnel-builder.toml`, and `migration-snapshots/` are excluded from
Git. Keep credentials and local network artifacts out of commits, including any
configuration files saved under other names. Use placeholder values in examples.

See the [README](README.md) for the documentation index and
[scope and roadmap](docs/roadmap.md) for current boundaries.
