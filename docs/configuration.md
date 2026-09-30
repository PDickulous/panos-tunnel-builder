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

Environment TLS values accept `true`/`false`, `yes`/`no`, `on`/`off`, or `1`/`0`,
ignoring case and surrounding whitespace. Other values fail validation. TOML
requires a boolean for `verify_ssl` and an integer for `port`.

Copy [`.env.example`](../.env.example) to `.env` and replace its placeholder API
key and example host. TLS verification is enabled by default.

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

Boolean options support explicit negative forms, including `--no-load-candidate`,
`--no-allow-dirty-candidate`, `--no-show-secrets`, `--no-yes`, and `--no-force`
on the commands that expose those options. A file can enable candidate loading
or skip confirmation, so review its defaults before running it.

## Precedence

For connection settings, process environment values take precedence over `.env`
values, and environment values take precedence over the TOML `[panorama]` table.
The port and TLS defaults apply when no setting is provided.

For command parameters, explicit command-line arguments and options override
TOML command defaults. Built-in defaults apply after those. Relative file paths
are interpreted from the working directory, not the TOML file's directory.

## Local files

`.env` and the root-level `panos-tunnel-builder.toml` are ignored by Git. If you
use a different filename for credentials, exclude it from version control too.
The checked-in examples contain placeholders only. Migration artifacts default
to the ignored `migration-snapshots/` directory.

For command examples, see [usage](usage.md).
