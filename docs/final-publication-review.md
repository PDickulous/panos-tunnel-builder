# Publication review after fixes 1–7 — October 27, 2026

Scope: the current working tree, including untracked implementation and test
files, for publishing the repository and CLI. Base commit remains `7aa4efe`.
This pass changed no application behavior and contacted no live Panorama or
firewall. Findings below continue the numbering from the earlier reviews.

Recommendation: findings 8–10 are addressed locally. Publishing
the repository as experimental is distinct from qualifying candidate loading for
production; current-code appliance qualification remains outstanding.

## Findings

### 8. High: route capture can treat an unrecognized response as an empty RIB

**Addressed locally October 27, 2026.** Capture now rejects unsuccessful or
unrecognized tables, missing router data, malformed records and next hops,
inconsistent counts, and records outside the captured routing scope. Supported
explicit empty tables remain valid. Version 2 route snapshots record instance
coverage, and comparison rejects mismatched coverage and version 1 snapshots
whose completeness cannot be established. Existing version 1 baselines must be
recaptured before migration or independently checked if migration has already
occurred. Regression tests cover both engines and CLI failure paths. Live PAN-OS
response-format validation remains outstanding. After this fix, 435 workspace
tests and the Ruff, mypy, and Pyright checks passed. The original finding follows.

Locations: `route_validation.py:467–491`, `route_validation.py:552–555`, and
`cli.py:686–695`.

The advanced-routing parser returns an empty tuple when the expected JSON
element or router mapping is absent, and silently skips malformed route
collections and records. The legacy parser looks only for direct `result/entry`
children and skips entries without a destination. Neither establishes that the
response is a recognized, complete route listing before accepting zero routes.

If both captures encounter the same unsupported response shape, the normalized
before/after tables can be empty and compare equal. The independent routing
configuration and configured-peer-count checks do not establish RIB capture
completeness. Missing some records can similarly remove evidence from comparison.

Reproduced through the current installed wheel, with API calls mocked: a
successful response containing non-empty route data under an unexpected
`result/routes/entry` wrapper produced zero captured routes. For both virtual
and logical routers, `routes verify-migration` exited 0 and printed
“Migration route verification passed for every endpoint.” This is a simulated
schema-mismatch reproduction, not evidence that a particular PAN-OS version
returns that wrapper. The reproduction script is
`/tmp/panos-final-route-repro.py` in the review workspace.

Required correction: distinguish a recognized empty table from an unreadable or
partial response. Reject unknown envelopes, unexpected JSON structures, and
malformed route records with `RouteValidationError`; preserve capture completeness
per routing instance. Test capture and CLI behavior for supported empty tables,
unexpected successful responses, and mixed valid/invalid records. A comparison
must not pass when required route evidence could not be captured.

### 9. Medium: installed CLI searches for `.env` relative to its installation

**Addressed locally October 27, 2026.** The CLI now reads `.env` from its
working directory only, without searching the installation tree or parent
directories. Explicit process environment values continue to take precedence,
followed by `.env` values and the selected TOML file. Console-script subprocess
tests cover this behavior and intercept connection creation so no network call
is made. All 439 tests passed in the workspace and against the installed wheel;
Ruff, mypy, Pyright, and `git diff --check` passed. The original finding follows
for context.

Location: `config.py:161`; configuration instructions in `README.md:14–26`
and `docs/configuration.md`.

The bare `load_dotenv()` call searches upward from the calling Python file in a
normal console-script invocation. An installed package therefore searches from
its `site-packages` location rather than the directory from which the operator
invoked the CLI. A repository-local virtual environment can mask this because
its ancestor directory happens to contain the repository's `.env`.

Reproduced with the current wheel installed in an external temporary virtual
environment: from a separate directory containing a valid dummy `.env`, with
`PANORAMA_*` process variables removed, `panos-tunnel-builder status` exited 2
with `PANORAMA_HOST is not set`. No network request was made. Configuration tests
currently mock `load_dotenv`, so the passing installed-wheel suite misses this.

Required correction: explicitly define the CLI's dotenv location, preferably
the working directory or an explicit option, and document its precedence.
Preserve explicit process-environment overrides. Add a subprocess test of the
installed console script from outside the repository, testing configuration
resolution without contacting an appliance. Explicit environment variables or
`--config` TOML are available workarounds.

### 10. Low: distribution archives omit operator documentation and examples

**Addressed locally October 27, 2026.** The source archive includes the operator
guides, examples, contributor instructions, and files linked by those guides.
Both archives include a package-index README with absolute documentation links,
repository and documentation metadata, and the license. CI builds and checks
both archives, including sensitive-path exclusion, and smoke tests an installed
wheel. The dotenv example now uses a fictional host. The original finding follows
for context. Validation included 439 workspace tests and 439 installed-wheel
tests, static checks, archive inspection, and an installation from the source
archive. The archive checker rejected deliberately altered archives with a
missing guide, a `.env` file, or missing documentation metadata.

Location: packaging configuration in `pyproject.toml`.

The newly built source archive contains `README.md` but omits `docs/`,
`.env.example`, and `panos-tunnel-builder.example.toml`. Its README links to the
missing guides and instructs the user to copy the missing dotenv example. The
wheel metadata has no project URLs or README description, so package consumers
also lack a direct metadata route to the recovery and validation instructions.
The Apache license file is included in both distributions.

Required correction for package distribution: include the intended guides and
examples in the source archive, add README and project URLs to package metadata,
and assert distribution contents in CI. A wheel can link to hosted documentation;
it need not carry the entire documentation tree. This does not affect users who
clone the complete repository.

## Verification completed

| Check | Result |
|---|---|
| Workspace regression suite | 389 passed on Python 3.12.3 |
| Statement coverage | 86% overall |
| Static checks | Ruff, mypy, Pyright, and `git diff --check` passed |
| Dependency consistency | Workspace and installed-wheel `pip check` passed |
| Isolated build | Current wheel and source archive built with declared build dependencies |
| Archive inspection | No `.env`, JSON artifacts, PEM/key files, or migration-snapshot paths; artifact module and license included |
| Installed-wheel regression suite | 389 passed from `/tmp`, with repository pytest configuration disabled |
| Runtime advisory audit | All 10 resolved runtime dependencies checked; no known vulnerabilities, none skipped |
| Secret scan | 38 current public files and 79 reachable historical text blobs; 24 detector matches, all identical secret hashes to previously reviewed placeholders, fixture values, boolean settings, or the expected IKE identity hash |
| Additional reproductions | Installed dotenv-resolution failure and route-parser false-success demonstrated locally |

Builds are in `/tmp/panos-final-dist`; detailed test/audit logs use the
`/tmp/panos-final-` prefix. Secret verification against external services was
disabled. Ignored local credentials were not included in the scan or printed.
The scan covers available reachable history, not unfetched refs, remote release
attachments, or all possible secret formats. Advisory results are point-in-time.

## Remaining publication preparation

- Make experimental status and the current validation limits prominent in the
  README. It currently singles out tunnel naming, while the new TLS,
  interruption/recovery, locking, and source-drift paths also need appliance
  qualification. Record supported Panorama/PAN-OS versions and API permissions.
- Add a working private vulnerability-reporting route and guidance for sanitized
  issues. `SECURITY.md` and issue templates are absent.
- Decide whether historical lab identifiers are appropriate for publication.
  The private address originally in `.env.example` was replaced with a fictional
  hostname as part of finding 10; it was not an authentication secret.
- Extend CI beyond its Python 3.12 unit/static, installed-console configuration,
  archive-content checks, and wheel smoke test: audit dependencies, scan secrets,
  and test the Python versions the project intends to support.
- Include all intended new files when preparing the release commit. The fixes
  remain working-tree changes, including untracked `artifacts.py` and new tests;
  a push of the existing commit would not publish them. Review the staged diff
  rather than indiscriminately adding local files.
- Verify remote repository visibility, branch protections, security-reporting
  settings, and release permissions before publishing. The connected GitHub
  metadata lookup for the configured origin returned HTTP 404; that does not
  distinguish a private/inaccessible repository from a nonexistent one. Those
  remote settings could not be verified through the connection.

No regression in fixes 1–7 was identified within the checked paths. Passing
automated checks does not establish live lock enforcement, rollback semantics,
successful tunnel establishment, or dataplane forwarding.
