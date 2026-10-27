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
TLS tests also require the `openssl` executable to generate temporary test
certificates; handshakes run in memory without opening network sockets.
For a coverage report, run `pytest --cov=panos_tunnel_builder --cov-report=term-missing`.
To build and check both release archives, use a clean output directory:

```bash
python -m build --outdir /tmp/panos-release-check
python scripts/check_distributions.py /tmp/panos-release-check
```

The archive check verifies the operator guides, examples, local documentation
links, package metadata, and absence of common credential and artifact paths.
It does not scan file contents for secrets. Keep the package-index description
in `README-pypi.md` in sync with the repository README and use absolute links
there so they resolve outside the repository.

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
