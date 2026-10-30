# Configuration

[Documentation index](../README.md#documentation)

## Connection settings

Set Panorama connection values in the process environment, a `.env` file, or the
`[panorama]` table of a TOML file.

| Environment variable | TOML key | Default | Requirement |
|---|---|---|---|
| `PANORAMA_HOST` | `panorama.host` | None | Required hostname or address. |
| `PANORAMA_API_KEY` | `panorama.api_key` | None | Required API key. |
| `PANORAMA_PORT` | `panorama.port` | `443` | Integer from 1 to 65535. |
| `PANORAMA_VERIFY_SSL` | `panorama.verify_ssl` | `true` | Whether to verify TLS certificates. |
| `PANORAMA_CA_BUNDLE` | `panorama.ca_bundle` | System trust store | Optional path to a PEM CA bundle for Panorama. |

Environment TLS values accept `true`/`false`, `yes`/`no`, `on`/`off`, or `1`/`0`,
ignoring case and surrounding whitespace. Other values fail validation. TOML
requires a boolean for `verify_ssl` and an integer for `port`.

Copy [`.env.example`](../.env.example) to `.env` and replace its placeholder API
key and example host. The CLI reads `.env` only from its current working
directory, regardless of where it is installed. It does not search parent
directories or the installation directory. When running from another directory,
put the file there, export the values, or select a TOML file with `--config`.
TLS verification is enabled by default.

The HTTPS connection verifies both the certificate chain and the Panorama
hostname, including requests redirected through Panorama to a managed firewall.
For a private CA, set `PANORAMA_CA_BUNDLE=/path/to/ca-bundle.pem` or
`ca_bundle = "/path/to/ca-bundle.pem"` in `[panorama]`. The bundle supplies the
trusted CA certificates instead of the default system trust store. Relative
paths resolve from the command's working directory. Missing or invalid bundles
fail before an API request is sent.

Use a Panorama hostname (or IP address) present in its certificate's subject
alternative names. `PANORAMA_VERIFY_SSL=false` explicitly disables certificate
and hostname verification and should be limited to controlled lab use. The TLS
fix means self-signed/untrusted appliances that previously connected despite
`verify_ssl=true` now require a trusted certificate or configured CA bundle.

## TOML command defaults

Copy [the example TOML file](../panos-tunnel-builder.example.toml) to
`panos-tunnel-builder.toml` and edit the connection and command values. The file
is loaded only when explicitly selected, before the command name:

```bash
panos-tunnel-builder --config panos-tunnel-builder.toml build
panos-tunnel-builder --config panos-tunnel-builder.toml build --no-load-candidate
```

Supported command tables are `[status]`, `[build]`, `[routes.snapshot]`,
`[routes.compare]`, `[routes.verify-migration]`, and `[candidate.restore]`.
Use underscore-separated parameter names, such as `tunnel_address_pool`, in
TOML. Repeatable mapping options use arrays of `OLD=NEW` strings. Unknown keys
and malformed TOML are rejected.

## Input names

| Table | Settings | Meaning |
|---|---|---|
| `build` | `spoke_firewall`, `hub_firewall` | Managed firewall hostname or serial number. |
| `build` | `spoke_template_name`, `hub_template_name` | Exact, case-sensitive names in each assigned stack. |
| `build` | `spoke_template_menu_number`, `hub_template_menu_number` | Alternative 1-based menu positions; 0 cancels. |
| `build` | `spoke_vsys`, `hub_vsys` | Virtual systems for the two endpoints. |
| `build` | `spoke_virtual_router_name` | Optional target name for each migrated spoke's legacy virtual router; the hub keeps its name. |
| `routes.compare` | `virtual_router_map` | Expected router renames as an array of `OLD=NEW` strings. |
| `build` | `allow_pending_candidate_changes` | Permit loading over pending Panorama changes; failure rollback discards all pending changes. |
| `build` | `migration_artifact_directory` | Local baseline snapshot and validation-manifest directory. |
| `routes.snapshot` | `output_file`, `overwrite_existing_file` | Local snapshot filename and permission to replace it. |
| `routes.verify-migration` | `manifest_file` | Local validation-manifest JSON filename. |
| `candidate.restore` | `snapshot_name` | Saved configuration name on Panorama, not a local file. |

Prefer template names in saved configuration: menu positions can change when
stack order changes. Set either a name or a menu number for each endpoint.
Names must match a template with interface configuration in that endpoint's
assigned stack. These selections do not narrow the shared-template migration
scope or override discovery of the source-owning templates.

## Confirmation behavior

In `[build]` and `[candidate.restore]`, `skip_confirmation = false` keeps
confirmation prompts (the default). Setting it to `true` is equivalent to
`--yes` / `-y`:

- For `build`, it accepts the plan/template confirmation, candidate-load
  confirmation, and use of the portal gateway when it differs from the active
  gateway. Gateway mismatch warnings are still displayed.
- For `candidate restore`, it accepts replacing the Panorama candidate with the
  named saved configuration, including replacement of all pending changes.
  Configuration and commit locks, the unfinished-job check, and a fresh
  pre-restore checkpoint remain mandatory.
- It does not supply missing inputs. Firewall identities, template selections,
  and the tunnel address pool can still prompt. It does not bypass validation
  or enable candidate loading; `load_candidate` remains a separate setting.

Candidate loading always rechecks the configuration fingerprints captured before
discovery. Neither confirmation settings nor allowing pending candidate changes
can bypass source-drift detection. Changed configuration requires a fresh build
and review.

Explicit `--no-yes` restores confirmations even if the file sets
`skip_confirmation = true`. This setting is not an environment variable.

Boolean options have explicit negative forms, including `--no-load-candidate`,
`--no-allow-pending-candidate-changes`, `--no-show-secrets`, `--no-yes`, and
`--no-overwrite-existing-file` on the commands that expose those options.

## Updating older configuration files

Old TOML keys are rejected. Rename them as follows; changes to `firewall` and
`vsys` apply only to `[build]`, not `[routes.snapshot]`.

| Old key | New key |
|---|---|
| `build.firewall` | `build.spoke_firewall` |
| `build.hub` | `build.hub_firewall` |
| `build.template_number` | `build.spoke_template_menu_number` |
| `build.hub_template_number` | `build.hub_template_menu_number` |
| `build.vsys` | `build.spoke_vsys` |
| `build.allow_dirty_candidate` | `build.allow_pending_candidate_changes` |
| `build.snapshot_directory` | `build.migration_artifact_directory` |
| `routes.snapshot.output` | `routes.snapshot.output_file` |
| `routes.snapshot.force` | `routes.snapshot.overwrite_existing_file` |
| `routes.verify-migration.manifest` | `routes.verify-migration.manifest_file` |
| `candidate.restore.snapshot` | `candidate.restore.snapshot_name` |
| `yes` in build/restore | `skip_confirmation` |

Previous CLI flags remain aliases: `--hub`, `--template-number`,
`--hub-template-number`, build's `--vsys`, `--allow-dirty-candidate`,
`--snapshot-directory`, and snapshot's `--force` (including their negative
boolean forms). Positional argument order is unchanged.

## Precedence

For connection settings, process environment values take precedence over `.env`
values, and `.env` values take precedence over the TOML `[panorama]` table.
The port and TLS defaults apply when no setting is provided.

For command parameters, explicit command-line arguments and options override
TOML command defaults. An explicit template-name option also overrides a
menu-number default from the file, and vice versa. Providing both selectors on
the CLI, or both in TOML without a CLI override, is rejected. Built-in defaults
apply after those. Relative file paths are interpreted from the working directory, not the TOML file's directory.

## Local files

`.env` and the root-level `panos-tunnel-builder.toml` are ignored by Git. If you
use a different filename for credentials, exclude it from version control too.
The checked-in examples contain placeholders only. Migration artifacts default
to the ignored `migration-snapshots/` directory.

For command examples, see [usage](usage.md).
