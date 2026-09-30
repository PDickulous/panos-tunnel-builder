# Usage

[Documentation index](../README.md#documentation)

Install the tool using the [quick start](../README.md#quick-start) and set your
[connection settings](configuration.md). The examples below use placeholder
firewall names and an example address pool.

## Preview a migration

```bash
panos-tunnel-builder status
panos-tunnel-builder build branch-01 --hub-firewall hub-01 --tunnel-address-pool 10.254.0.0/24
```

`status` verifies Panorama connectivity and displays system information. `build`
selects templates and displays the proposed LSVPN replacement. If the firewall,
hub, or address pool is omitted, the tool prompts for it. Select templates by
exact name with `--spoke-template-name` and `--hub-template-name`:

```bash
panos-tunnel-builder build branch-01 --hub-firewall hub-01 \
  --spoke-template-name branch-network --hub-template-name hub-network \
  --tunnel-address-pool 10.254.0.0/24
```

Alternatively use `--spoke-template-menu-number` and
`--hub-template-menu-number`. Set one selector per endpoint. Names are
case-sensitive, must exist in the assigned stack, and must identify templates
with interface configuration. If neither selector is provided, a menu prompts
for a number. Both endpoint virtual systems default to `vsys1`; override them
with `--spoke-vsys` and `--hub-vsys`.

Review the full shared-template scope: all spokes inheriting the satellite's
owning template must migrate together. The pool must have room for one IPv4
`/30` or IPv6 `/127` per tunnel without overlapping existing interface networks.
Existing router names are preserved. If no LSVPN satellite remains, a load
request completes as a no-op; greenfield tunnels are not created.

Generated PSKs are hidden by default. `--show-secrets` displays them; the normal
preview shows only fingerprints.

## Load candidate configuration

```bash
panos-tunnel-builder build branch-01 --hub-firewall hub-01 \
  --tunnel-address-pool 10.254.0.0/24 --load-candidate
```

After confirmation, the tool saves pre-change route snapshots, acquires a
Panorama configuration lock, checks the candidate, saves a Panorama recovery
snapshot, and loads and verifies the replacement objects. It prints the
snapshot and validation-manifest locations. Use `--migration-artifact-directory`
to change the local artifact directory.

Pending candidate changes are rejected by default.
`--allow-pending-candidate-changes` explicitly permits them, but automatic rollback after a failed load discards **all** pending
candidate changes by reverting to running configuration. `--yes` (or TOML
`skip_confirmation = true`) accepts plan/load confirmations
and a detected portal/active-gateway mismatch. It still prompts for missing
inputs and does not bypass validation. See
[confirmation behavior](configuration.md#confirmation-behavior).

The tool never commits or pushes. Review the candidate in Panorama and perform
those operations separately. If the load fails, inspect its error report; a
failed automatic rollback is reported separately because partial changes may
remain. See [validation](validation.md) for transaction checks and artifacts.

## Verify after commit and push

Wait for IKE/IPsec and routing convergence, then run the verifier with the actual
manifest path printed by the load command:

```bash
panos-tunnel-builder routes verify-migration migration-snapshots/LSVPN_MIGRATION_example_validation.json
```

The verifier captures every endpoint again, compares routes and protected
routing configuration against the baselines, and checks configured BGP peer
counts. It permits only manifest-recorded link changes and returns nonzero for
unexpected differences. Older baselines lacking routing configuration or peer
counts report those checks as unavailable.

Post-change snapshots are saved beside the manifest unless `--output-directory`
is supplied. Keep the manifest with its baseline files: relative baseline paths
are resolved from the manifest's directory. The verifier does not wait for
convergence or test application traffic.

## Capture and compare routes independently

```bash
panos-tunnel-builder routes snapshot branch-01 before.json
# Capture again after the operator-controlled change has converged.
panos-tunnel-builder routes snapshot branch-01 after.json
panos-tunnel-builder routes compare before.json after.json
```

Snapshots include every discovered virtual router and logical-router VRF, IPv4
and IPv6 RIB entries, and effective routing configuration. `snapshot` refuses to
overwrite an existing file unless `--overwrite-existing-file` is supplied; use
`--vsys` for another virtual system.

`compare` checks normalized RIB state for the same firewall serial and vsys. It
accepts repeatable `--prefix-map OLD=NEW`, `--interface-map OLD=NEW`, and
`--next-hop-map OLD=NEW` options for expected path changes. It does not perform
the manifest verifier's routing-configuration and BGP-peer-count checks.

## Restore a saved candidate snapshot

```bash
panos-tunnel-builder candidate restore LSVPN_PRE_example.xml
```

Replace the example with a saved Panorama snapshot name. This replaces the
candidate after confirmation; `--yes` skips the prompt. It does not commit or
push the restored configuration. Automatic rollback on load failure uses the
running configuration instead of loading this named snapshot.

## Command help

```bash
panos-tunnel-builder --help
panos-tunnel-builder build --help
panos-tunnel-builder routes verify-migration --help
panos-tunnel-builder candidate restore --help
```

Use `--config FILE.toml` before the command name to supply
[TOML defaults](configuration.md#toml-command-defaults).
