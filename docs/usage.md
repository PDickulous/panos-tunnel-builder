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
Router names are preserved by default. Add
`--spoke-virtual-router-name "Branch VR"` (or set
`build.spoke_virtual_router_name` in TOML) to rename each migrated spoke's existing
legacy virtual router when its name differs. The preview displays each rename;
`--load-candidate` applies it after loading and verifying the tunnel migration.
The hub router keeps its existing name. Names are case-sensitive and contain
1–31 letters, numbers, spaces, hyphens, or underscores, without leading or
trailing spaces. See the vendor's [virtual-router name requirements](https://docs.paloaltonetworks.com/ngfw/help/10-1/network/network-virtual-routers/general-settings-of-a-virtual-router).

The rename retains the full router configuration, updates router imports and
`next-vr` references across contributing templates and stack overrides, and is
included in the recovery snapshot and validation manifest. Every firewall
inheriting a changed template must belong to the spoke migration group; isolate
other consumers before renaming. Local firewall router settings or references
that retain the old name must first be moved into Panorama templates; both local
candidate and running configuration are checked. Existing target names, multiple
source routers on one spoke, and logical-router/VRF renames are rejected. A matching name needs
no rename. If no LSVPN satellite remains, a load request completes as a no-op;
greenfield tunnels and standalone router renames are not created.

```bash
panos-tunnel-builder build branch-01 --hub-firewall hub-01 \
  --tunnel-address-pool 10.254.0.0/24 \
  --spoke-virtual-router-name "Branch VR" --load-candidate
```

Generated PSKs are hidden by default. `--show-secrets` displays them; the normal
preview shows only fingerprints.

## Load candidate configuration

```bash
panos-tunnel-builder build branch-01 --hub-firewall hub-01 \
  --tunnel-address-pool 10.254.0.0/24 --load-candidate
```

After confirmation, the tool saves pre-change route snapshots, acquires a
Panorama configuration and commit locks, checks jobs and the candidate, saves a recovery
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

### Configuration and commit protection

Candidate loading and restore require both locks in Panorama's `shared` scope
and permission to query `show jobs all`. After acquisition, any unfinished job
blocks the operation before snapshots or candidate writes. This deliberately
includes non-commit and unknown job types. Failed queries and unrecognized job
responses also block; the tool does not wait for or cancel jobs. Let jobs finish
and retry. Neither `--yes` nor allowing pending candidate changes skips this check.

Only confirmed lock acquisitions authorize cleanup. Existing locks are not taken
over. If an acquisition response is lost, inspect lock ownership manually before
retrying. Cleanup attempts the configuration lock first and commit lock last,
reports each failure independently, and does not automatically switch HA peers.

Protection lasts through verification or the recovery attempt, then ends. Use a
separate API account and an exclusive change window: shared credentials or an
administrator overriding locks can defeat protection. Live competing-administrator
validation is still required.

Before discovery, loading captures an in-memory SHA-256 fingerprint of Panorama's
full candidate and running configurations. It also fingerprints candidate,
running, and effective-running configuration on the hub and every affected spoke
before reading their migration inputs. After acquiring both locks and checking
jobs, it rereads those sources before saving a snapshot or writing candidate
changes. A changed source stops loading even if the change was already committed
and the candidate is clean again. Allowing pending changes does not bypass this
check. Unrelated configuration changes also require a fresh plan because the
comparison deliberately covers full configurations.

On a source-change error, rerun discovery, review the fresh plan, and recapture
route baselines. The tool does not automatically refresh the approved plan or
roll back when this check fails. Missing or failed source reads also stop loading.
Fingerprints are kept in memory and are not added to artifacts. Whitespace and
Panorama's `admin`, `dirtyId`, and `time` metadata are ignored in the comparison.
Panorama locks do not lock managed firewalls or freeze routing, DNS, or active
gateway state; those can change after the comparison. Keep the exclusive change
window and perform post-change verification.

### Artifact or lock-cleanup failures

The validation manifest is constructed and checked for serialization errors
before candidate loading is attempted. After candidate verification, the CLI
reports the verified state, recovery snapshot, baseline paths, and no-commit
boundary before publishing the manifest. The manifest is written to a temporary
file beside its destination, flushed to disk, then renamed atomically.

A lock-release or manifest-publication error returns a nonzero exit status even
if the candidate is verified. The output states that the changes remain staged;
these cleanup errors do not trigger a rollback or delete the route baselines.
When candidate loading itself fails, its original error and rollback outcome
are reported separately from any lock-release failure, and the baselines are
retained for recovery.

Inspect and release any remaining Panorama configuration or commit lock before retrying.
For a manifest-publication failure, correct the local storage problem and inspect
the printed `.json.tmp` staging file. It may be incomplete. If complete, confirm
the snapshot name and baseline references before moving it to the intended
manifest path. If the manifest cannot be recovered, leave the candidate
uncommitted and review recovery using the saved Panorama snapshot. Do not rerun
the migration solely to regenerate a missing manifest: that would operate on
the already-modified candidate.

### Interrupting a load

The recovery snapshot name is printed as soon as Panorama saves it, before
candidate writes begin. If Ctrl-C interrupts a write or candidate verification,
the tool attempts rollback to running configuration before releasing its locks,
reports the outcome, and exits with status 130. Captured local route baselines
are retained and their paths are printed. An interruption before candidate
mutation does not trigger rollback.

Allow the rollback to finish. A second Ctrl-C during rollback is reported as an
unsuccessful rollback; partial candidate changes may remain. The same recovery
handling applies to a Python `SystemExit` during loading. Forced termination,
power loss, or loss of access to Panorama can prevent recovery.

After an unsuccessful or unreported rollback, inspect Panorama's candidate and
configuration and commit locks before retrying. Use the printed snapshot name to review
the pre-migration configuration and, if appropriate, restore it with
`panos-tunnel-builder candidate restore SNAPSHOT_NAME`. Restore replaces the
entire candidate; review pending work first. Snapshot writes are atomic: an
interrupted write does not publish a partial snapshot. No commit or push is
issued by the interruption handler. The pending-change override's global rollback behavior
also applies to interrupted loads.

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

Route capture requires a successful, recognized response for every discovered
routing instance. Unrecognized tables, missing router data, malformed entries,
and inconsistent reported counts stop capture rather than being treated as an
empty table. A recognized empty table is allowed. New snapshots use schema
version 2 and record the routing instances covered by the capture; comparison
requires matching coverage.

Snapshots created before this safeguard use schema version 1 and cannot prove
their route capture was complete. The comparison and migration verifier reject
them. Before a migration, capture a new baseline. If a migration has already
occurred, preserve the old snapshot and manifest and verify the original
baseline manually using independent evidence; a new post-change capture cannot
recreate the pre-change state. Do not rerun a staged migration solely to replace
the baseline. The manifest format itself is unchanged.

The checks validate the response structure and all observed records. They cannot
prove that an appliance returned routes it omitted without indicating truncation;
live testing against the deployed PAN-OS versions remains necessary.

`compare` checks normalized RIB state for the same firewall serial and vsys. It
accepts repeatable `--prefix-map OLD=NEW`, `--interface-map OLD=NEW`, and
`--next-hop-map OLD=NEW` options for expected path changes. It does not perform
the manifest verifier's routing-configuration and BGP-peer-count checks.

## Protecting and sharing artifacts

Route snapshots contain raw effective routing XML. Treat snapshots, manifests,
temporary files, and exported Panorama recovery configurations as sensitive.
They contain firewall identities and topology, and routing XML may include
authentication settings or device-encrypted credentials. Encryption of a value
inside a device configuration does not make the file suitable for public upload.

All local snapshots and manifests are published atomically. On POSIX, new files
and staging files use mode `0600` (owner read/write), even with a permissive
umask; each newly created artifact directory uses mode `0700` before umask
restrictions. Existing directories are left unchanged, so choose a directory
you control. Overwriting a snapshot replaces it with a private file rather than
following a destination symlink. Existing staging files are never overwritten.
Failed snapshot writes remove their staging files where possible; failed
manifest publication retains its private staging file for recovery.

Previously captured files are not changed automatically. Review their access
and restrict them as needed. On Windows, configure and verify user-only ACLs on
the artifact directory; POSIX mode settings do not provide that guarantee.
Filesystem permissions do not encrypt the files or protect copies in backups
and synchronized folders.

For a support request or public issue:

1. Keep the original evidence privately for migration verification. Do not edit
   the baselines or manifests used by the verifier.
2. Prefer a concise error description and a synthetic configuration example.
   If a capture is necessary, make a separate copy in a private directory.
3. In that copy, remove credentials and authentication values, including encrypted
   values; replace identifying hostnames, serials, addresses, routing names, and
   paths consistently with fictional examples. Review nested routing XML inside
   the JSON as well as ordinary JSON fields. Automatic metadata stripping is
   not credential redaction.
4. Inspect the entire sanitized copy before sharing it, including terminal logs.
   Never attach `.env`, API keys, raw Panorama exports, or output produced with
   `--show-secrets`.

The repository ignores default migration directories and generated migration
filenames, including their temporary files. Standalone snapshots saved under
other names, manually copied files, and release archives still require review.
Keep recovery files only as long as your operational retention policy requires.

## Restore a saved candidate snapshot

```bash
panos-tunnel-builder candidate restore LSVPN_PRE_example.xml
```

Replace the example with a saved Panorama snapshot name. This replaces the
**entire candidate, including all pending changes**, after confirmation. This is
intentional for restore; the migration command's dirty-candidate guard does not
apply. `--yes` skips the prompt but still requires locking and checkpoint creation.

The tool acquires both locks, checks jobs, and saves the current candidate
to a fresh `LSVPN_CHK_*.xml` checkpoint. The checkpoint name is printed before
the requested snapshot is loaded. It includes pending work or partial migration
changes present before restore and is not asserted to be a clean running baseline.
If either lock cannot be acquired, jobs cannot be verified as finished, or the
checkpoint cannot be saved, the requested
snapshot is not loaded.

If loading fails or is interrupted, the tool attempts to reload that pre-restore
checkpoint while holding both locks. This preserves the candidate saved before
restore, including pending work, instead of reverting it to running configuration.
If checkpoint recovery also fails or is interrupted, the CLI reports both
failures and warns that partial changes may remain; inspect the candidate and
use the printed checkpoint for manual recovery. An interrupted restore/recovery
returns status 130; other failures return nonzero. Forced termination or loss of
Panorama access may prevent recovery.

Both locks are released after the load or recovery attempt. A failed release is
reported separately and returns nonzero without hiding whether the requested
snapshot loaded or checkpoint recovery succeeded. Inspect and release any
remaining lock before retrying. No restore or recovery step commits or pushes.
During a `build --load-candidate` migration, automatic rollback still reverts to
running configuration; that migration policy differs from snapshot restore's
checkpoint recovery.

## Command help

```bash
panos-tunnel-builder --help
panos-tunnel-builder build --help
panos-tunnel-builder routes verify-migration --help
panos-tunnel-builder candidate restore --help
```

Use `--config FILE.toml` before the command name to supply
[TOML defaults](configuration.md#toml-command-defaults).

When comparing snapshots manually after a router rename, include
`routes compare before.json after.json --virtual-router-map "default=Branch VR"`.
The migration verifier reads this mapping from the spoke's manifest entry.
