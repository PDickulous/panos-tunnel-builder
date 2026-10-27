# PAN-OS Tunnel Builder

Migrate existing GlobalProtect Large Scale VPN (LSVPN) deployments to standard
route-based IPsec on firewalls managed by Panorama. The tool discovers migration
scope, previews replacement objects, optionally loads candidate configuration,
and verifies routes after an operator commits and pushes.

This tool requires Python 3.12 or newer. Its current changes have automated
coverage, but live appliance validation is still required before production use.

```bash
python -m pip install panos-tunnel-builder
panos-tunnel-builder --help
```

Read the [quick start](https://github.com/PDickulous/panos-tunnel-builder#quick-start),
[configuration guide](https://github.com/PDickulous/panos-tunnel-builder/blob/main/docs/configuration.md),
and [usage and recovery guide](https://github.com/PDickulous/panos-tunnel-builder/blob/main/docs/usage.md)
before staging changes. The [repository](https://github.com/PDickulous/panos-tunnel-builder)
includes examples, validation details, and the Apache 2.0 license.
