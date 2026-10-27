# Public release review — October 27, 2026

Scope: publishing the repository and CLI for other operators. Reviewed commit
`7aa4efe`; no live Panorama operations or application changes were performed.

Follow-up after fixes 1–5: see the [holistic release review](holistic-release-review.md)
for fresh build/install/audit results and additional concurrency findings 6–7.

Recommendation: fix the TLS defect before release. Address the transaction and
artifact failure cases before encouraging candidate loading. An explicitly
experimental release can precede full production qualification, provided the
remaining validation limits are prominent.

## Findings requiring attention

### 1. High: TLS verification is ineffective

**Addressed locally on October 27, 2026:** the transport now uses a verified
SSL context, including managed-firewall requests and regenerated connections.
An optional PEM CA bundle is supported. Regression tests exercise the actual
SDK request context with in-memory TLS handshakes for trusted, untrusted, and
wrong-host certificates and the explicit insecure opt-out. Live appliance
validation remains outstanding. The original finding follows for traceability.

`src/panos_tunnel_builder/panorama_client.py:29` sets
`panorama.xapi.verify_ssl`, but the installed transport (`pan-python 0.17.0`,
through `pan-os-python 1.13.1`) uses `ssl_context`. The assigned attribute does
not enable verification. This contradicts the documented secure default and
could expose API keys and configuration to a network attacker impersonating
Panorama.

Reproduced with a dummy key and a mocked `pan.xapi.urlopen`, without making a
network request: settings had `verify_ssl=True`, but the actual request context
had `check_hostname=False` and `verify_mode=ssl.CERT_NONE`.
The [upstream transport documentation](https://github.com/kevinsteves/pan-python/blob/master/doc/pan.xapi.rst)
also identifies `ssl_context` as the certificate-verification control.

Use a verified SSL context, support an explicit private-CA trust path, and ensure
the context reaches every SDK transport involved in redirected/HA requests.
Add transport-level tests for trusted, untrusted, and wrong-host certificates,
plus the explicit insecure opt-out. Existing config tests validate the setting
but do not validate transport behavior.

### 2. High: interruption can leave a partial candidate

**Addressed locally on October 27, 2026:** `KeyboardInterrupt` and `SystemExit`
during candidate mutation/verification now trigger a rollback attempt before
lock release. The CLI reports the saved snapshot before mutation, retains route
baselines after interruption, and exits with status 130. Regression tests cover
write/verification interruption, rollback failure or interruption, preflight
cancellation, and CLI artifact retention. Forced termination and live appliance
recovery remain outside the automated checks. The original finding follows.

`candidate.py:1941` rolls back on `Exception`, which excludes
`KeyboardInterrupt` and `SystemExit`. Ctrl-C after a mutation can therefore skip
rollback; the `finally` at line 1986 still releases the configuration lock.
The CLI also cleans up route baselines only on `Exception`.

Handle supported cancellation paths after writes begin, attempt rollback, retain
recovery evidence, and report whether the candidate is partial or restored.
Record/print the saved snapshot before mutation. Test interruption during both
mutation and verification. Process termination, power loss, and unreachable
Panorama still require an explicit manual recovery procedure; no Python handler
can guarantee rollback in those cases.

### 3. High: recovery-artifact failures misreport candidate state

**Addressed locally on October 27, 2026:** lock cleanup now preserves the
verified result or original transaction error. The CLI reports cleanup errors
separately and retains baseline files on transaction errors. Manifest construction
and an initial serialization check happen before loading; the verified state and
snapshot are reported before atomic manifest publication. Publication failures
return nonzero, state that the verified changes remain staged, and preserve
baselines and any temporary manifest. Regression tests cover disk-full/flush,
rename, serialization, and lock-release failures, including combined failures.
The original finding follows for traceability.

`cli.py:1673–1686` builds and saves the verification manifest after the candidate
transaction has succeeded. A full disk or manifest-construction error produces a
generic failure even though Panorama has already changed; the normal success
output, including the recovery snapshot name, has not yet been printed.

There is a related path at `candidate.py:1988`: a lock-release failure can mask
the successful transaction result (or the original failure). The CLI then deletes
the baseline files at `cli.py:1669–1672`, even if candidate changes remain.

Separate mutation status, lock-cleanup status, and artifact status. Preserve
baselines when recovery may be needed; always report the snapshot and known
candidate state. Prepare artifacts before mutation where possible and publish
them atomically. Test disk-write and lock-release failures explicitly.

### 4. Medium: local snapshots need sensitive-data handling

**Addressed locally on October 27, 2026:** all local snapshots and manifests now
use private atomic writes (0600 files on POSIX, including staging files) and
owner-only newly created directories. Explicit snapshot overwrite replaces the
destination safely; no-overwrite publication is protected against races.
Generated migration filenames and staging files are ignored outside the default
artifact directory too. Operator documentation now classifies raw routing XML
as sensitive and explains preservation, redaction, sharing, existing files, and
Windows ACL requirements. Raw authentication configuration is preserved for
verification. Tests cover permissive umasks, failed writes, file collisions,
symlinks, and private output from snapshot/migration commands. The original
finding follows for traceability.

`route_validation.py:383` copies complete virtual-router/logical-router XML;
only metadata is stripped. These artifacts include topology and may include
routing authentication configuration, including device-encrypted credentials
where returned by PAN-OS. They should not be treated as safe to publish simply
because generated tunnel PSKs are absent.

`cli.py:201`, `633`, and `1634` use ordinary `write_text`; permissions depend on
the operator's umask. Use restrictive file/directory permissions (0600/0700 on
POSIX), atomic writes, and a documented sharing/redaction procedure. Preserve
the information required for route comparison while protecting raw captures.

### 5. Medium: restore does not use the migration lock discipline

**Addressed locally on October 27, 2026:** the restore CLI now acquires a
configuration lock, saves and reports a fresh checkpoint of the full candidate,
and loads the requested snapshot only after checkpoint creation succeeds.
Failed/interrupted loads attempt checkpoint recovery while holding the lock,
preserving pending work instead of reverting to running configuration.
Recovery and lock-release failures are reported separately; successful loads
are not hidden by lock-cleanup failures. Tests cover contention, save/load and
recovery failures, interruptions, pending-work preservation, confirmation, and
CLI status/output. Live appliance restore validation remains outstanding. The
original finding follows for traceability.

`cli.py:696` calls `load_panorama_snapshot` directly; `candidate.py:844` issues
the load operation without acquiring a configuration lock or saving a fresh
checkpoint. The confirmation does disclose full candidate replacement, but
restore lacks the concurrency and recovery safeguards used during migration.

Apply an explicit lock/checkpoint policy to restore, report pending-change
impact, and test lock contention and load failures. Keep the documented manual
commit/push boundary.

## Public-release preparation

| Priority | Missing or incomplete item | Concrete release requirement |
|---|---|---|
| Before publication | Formal secret/history audit | Run a dedicated secret scanner across all intended public refs and inspect its findings. Review prior `current_status.readme` and `projectdesc.readme`, not only current files. Review any separately uploaded artifacts. |
| Before publication | Sanitized examples | `.env.example` contains the same private host address as the local configuration. Replace it with an obviously fictional example hostname; review historical lab names and addresses for information you do not want public. No actual API-key match was found. |
| Before publication | Security reporting | Add `SECURITY.md` with a working private reporting channel, supported versions, and expectations. Add issue guidance forbidding credentials and raw configuration uploads. |
| Before advertised production use | Compatibility evidence | Record tested Panorama/PAN-OS versions, legacy/advanced routing, shared-template scenarios, and SDK versions. Run current-code lab candidate loads, commit/push checks, IKE/IPsec and routing adjacency checks, traffic tests, and recovery exercises. Existing records explicitly leave current live validation incomplete. |
| Before advertised production use | API account instructions | Document required API permissions for preview, snapshot, candidate load, lock, and restore; certificate/CA setup; key handling; and a tested least-privilege role. |
| Release engineering | Package metadata | Add README metadata, license metadata, project/source/issue URLs, and an experimental maturity classifier to `pyproject.toml`. Add a CLI version flag and release notes. |
| Release engineering | Distribution verification | Build wheel and sdist in CI, inspect contents for unintended files, and smoke-test installation and CLI help/version outside the source checkout. |
| Release engineering | Dependency/security checks | Add dependency vulnerability auditing, automated dependency updates, and secret scanning. Pin CI actions to reviewed commit hashes. Record a reproducible tested dependency set; current CI resolves version ranges each run. |
| Release engineering | Supported Python range | CI only tests 3.12, while metadata accepts every Python version from 3.12 onward. Test the declared supported versions or narrow/document support. |
| Repository administration | Hosting safeguards | Verify branch protection/rulesets, required CI review checks, release permissions, and available secret-scanning/push protection in the hosting service. Remote settings were not inspected in this review. |

The Apache license, contribution guide, operator documentation, preview default,
explicit candidate-load confirmation, dirty-candidate guard, and no-commit/no-push
boundary are already useful foundations. Unsupported greenfield VPNs and OSPFv3
are documented scope limits, not prerequisites for this migration tool's release.

## Verification performed and limits

- 184 tests passed on Python 3.12.3; total statement coverage was 84%.
- Ruff passed; mypy passed for nine source files; Pyright reported zero errors
  and warnings.
- TLS behavior was reproduced against the real installed SDK with network I/O
  mocked out. Other transaction findings are based on control-flow inspection,
  not live failure injection.
- A limited scan of 54 reachable Git-history blobs found no matches for the
  private-key, GitHub-token, AWS-key, and long assigned-secret patterns used.
  Comparison with local connection values found the host in `.env.example`,
  but no local API-key match. This is not a complete secret-scanner audit or a
  guarantee that history contains no sensitive information.
- `.env`, local configuration, and migration snapshots are ignored and are not
  in the tracked-file list. Files under ignored paths must still be excluded
  from manually assembled release archives and support uploads.
- A fresh wheel build could not be completed: this environment could not resolve
  PyPI to fetch the build dependency. A no-isolation attempt also lacked local
  setuptools. This is an environmental verification limit, not proof of a broken
  package. Fresh dependency resolution and vulnerability auditing remain open.
- No live appliance validation, remote repository-settings review, or release
  publication was performed.

Suggested order: correct TLS; harden interrupted/failed transactions and artifact
handling; complete history/security/release setup; then publish an experimental
tag with an explicit compatibility matrix and recorded lab evidence.
