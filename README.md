# PAN-OS Tunnel Builder

Migrate existing GlobalProtect Large Scale VPN (LSVPN) deployments to standard
route-based IPsec on firewalls managed by Panorama. The tool discovers the
migration scope, previews replacement objects, optionally loads candidate
configuration, and verifies routes after an operator commits and pushes.

This version supports an optional spoke virtual-router rename, shared spoke templates,
legacy virtual routers, advanced-routing logical-router VRFs, BGP, and OSPFv2.
It does not create greenfield VPNs or commit or push configuration.

## Quick start

From a local checkout, with Python 3.12 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
cp .env.example .env
```

Edit `.env` in the working directory to set `PANORAMA_HOST` and
`PANORAMA_API_KEY`, then check connectivity and preview a migration:

```bash
panos-tunnel-builder status
panos-tunnel-builder build branch-01 --hub-firewall hub-01 --tunnel-address-pool 10.254.0.0/24
```

Replace the firewall names and address pool with values appropriate to your
network. `build` previews by default. Adding `--load-candidate` stages changes
after confirmation. A shared-template migration includes every inheriting spoke.
Candidate-load failures trigger a rollback of the entire Panorama candidate to
running configuration; dirty candidates are rejected by default.

See the [usage guide](docs/usage.md) for staging, post-change verification, and
recovery. Run `panos-tunnel-builder --help` for the command list.

## Documentation

| Document | Purpose |
|---|---|
| [Usage](docs/usage.md) | Preview, stage, verify, and restore a migration. |
| [Configuration](docs/configuration.md) | Environment settings, TOML defaults, and precedence. |
| [Architecture](docs/architecture.md) | Discovery, shared templates, generated objects, and routing behavior. |
| [Validation](docs/validation.md) | Safeguards, code/test traceability, artifacts, and recorded verification. |
| [Scope and roadmap](docs/roadmap.md) | Unsupported features, operator responsibilities, and future work. |
| [Contributing](CONTRIBUTING.md) | Development setup and required checks. |

Latest tunnel-naming changes have local test coverage; live validation remains
before production use. See [validation records](docs/validation.md#verification-records)
for the limits of historical lab results.

## License

[Apache License 2.0](LICENSE).
