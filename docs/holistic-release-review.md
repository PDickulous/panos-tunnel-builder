# Holistic release review — October 27, 2026

For the review after fixes 1–7, including findings 8–10 and current archive,
installation, and audit results, see the [publication review](final-publication-review.md).

Reviewed the working tree after fixes 1–5, including untracked implementation
and test files, against base commit `7aa4efe`. This was a review and validation
pass; it did not change application behavior or contact a live appliance.

The five fixes pass the automated checks, including a clean installation of the
built wheel. The review identified two additional concurrency gaps. Findings 6 and 7 now have
local implementations and regression tests. Live qualification is still required
before recommending production use.

## Findings

### 6. High: configuration locks do not provide commit exclusion

**Addressed locally October 27, 2026.** Migration and restore now acquire shared
configuration and commit locks, reject unfinished or unverifiable jobs before
mutation, and independently release only confirmed acquisitions. Tests cover
acquisition failures/interruption, job checks, and combined cleanup failures.
Validation after this fix: 345 workspace tests passed; Ruff, mypy, Pyright,
and `git diff --check` passed. Live competing-administrator validation remains
outstanding. The original finding follows for context.

Both `restore_candidate_configuration()` (`candidate.py:951`) and
`load_candidate_configuration()` (`candidate.py:2117`) acquire only a
configuration lock. Neither workflow acquires a commit lock or enforces the
device's automatic commit-lock setting.

Palo Alto distinguishes configuration locks, which restrict candidate edits,
from commit locks, which restrict changes to running configuration. See the
[Panorama lock documentation](https://docs.paloaltonetworks.com/panorama/administration/administer-panorama/manage-locks-for-restricting-configuration-changes).

Consequently, in an environment without enforced commit exclusion, another
privileged administrator could commit while the tool is partway through its
candidate transaction or restore. The tool itself never issues a commit, but
that does not prevent an external commit. The migration's revert-to-running
failure recovery also depends on running configuration remaining a safe baseline.
This is a code/documentation finding, not a reproduced live race.

Recommended follow-up: require both configuration and commit protection before
mutation, account for already queued/running commits, and preserve independent
cleanup outcomes for each lock. Do not remove locks owned by other sessions.
Add failure-injection tests and a live competing-administrator check. Until that
is implemented and validated, use an exclusive change window that prevents
other actors from editing, committing, or pushing during the operation.

### 7. Medium: plans are not bound to an unchanged source configuration

**Addressed locally October 27, 2026.** Candidate-loading builds now capture
Panorama candidate/running fingerprints before discovery, then managed-firewall
candidate/running/effective-running fingerprints before reading endpoint plan
inputs, including all shared-template spokes. Both locks and the job check
precede mandatory source comparison. Changed or unreadable sources stop before
snapshot or mutation, even with pending changes allowed. Committed source drift
that leaves candidate and running equal is covered by regression tests. Digests
stay in memory; the CLI requires a fresh plan and route baselines after drift.

Validation after this fix: 389 workspace tests passed; Ruff, mypy, Pyright, and
`git diff --check` passed. The comparison conservatively covers full configuration.
Panorama locks do not freeze managed-firewall configuration or operational state
after comparison. Live drift/concurrency checks remain outstanding. The original
finding follows for context.

`cli.py:1682` constructs the migration plan before displaying confirmation and
before the transaction acquires its lock. Route captures and placement discovery
also occur before lock acquisition. The clean-candidate guard
(`candidate.py:1119`) compares the current candidate with the current running
configuration; it does not compare either with the configuration used to build
the plan.

If another administrator changes and commits relevant source configuration
during that interval, the candidate can be clean again while the approved plan
is stale. Collision, dependency, and post-write checks are valuable, but they do
not prove that all source values used by the plan are still current. For example,
a source interface/gateway change could invalidate copied endpoint values.
This is a control-flow finding; no live concurrent-change experiment was run.

Recommended follow-up: fingerprint the relevant source configuration used for
planning and compare it after acquiring the locks, aborting on drift. Alternatively,
rediscover and rebuild under the locks and require review if the plan changes.
Test a source change that becomes committed between preview and lock acquisition,
not only a dirty candidate. Live routing state still needs an exclusive change
window and post-change verification.

## Validation results before the finding 6 fix

| Check | Result |
|---|---|
| Workspace tests | 293 passed on Python 3.12.3 |
| Statement coverage | 85% overall; TLS adapter 100%; artifact writer 97% |
| Static checks | Ruff, mypy, Pyright, and `git diff --check` passed |
| Dependency consistency | `pip check` passed in the workspace and clean install |
| Isolated wheel build | Passed using declared build dependencies fetched from PyPI |
| Wheel inspection | New artifact module and license included; no `.env`, migration-snapshot paths, or JSON artifacts in the wheel |
| Clean installation | Wheel installed into a temporary virtual environment; CLI help worked outside the repository |
| Installed-wheel tests | All 293 passed from `/tmp`, with repository pytest configuration disabled so imports used the installed wheel |
| Runtime vulnerability audit | pip-audit 2.10.1 reported no known vulnerabilities in all 10 resolved runtime dependencies; none skipped |
| Repository/history secret scan | detect-secrets 1.5.0 scanned 111 files: 35 current public files and 76 reachable historical blobs; 24 matches reviewed, all placeholders, boolean settings, test fixtures, or an expected IKE identity hash |

The clean installation resolved `pan-os-python 1.13.1`, `pan-python 0.17.0`,
`python-dotenv 1.2.4`, and `typer 0.27.3`. This exercises newer dotenv/Typer patch
versions than the workspace installation. The remaining audited runtime packages
were annotated-doc 0.0.5, markdown-it-py 4.2.0, mdurl 0.1.2, Pygments 2.21.0,
rich 15.0.0, and shellingham 1.5.4.

The secret scan ran locally with credential verification disabled. It included
reachable history and the intended public working-tree files, not ignored local
credentials. No credential leak was identified in the reviewed matches. This
does not cover unfetched remote refs, external release attachments, or every
possible secret format. Vulnerability results reflect the advisory service at
the time of this review, not a guarantee of vulnerability-free dependencies.

## Status of the original fixes

1. TLS: verified contexts are used for the application's Panorama and managed
   firewall transports, including regenerated connections. Certificate acceptance
   and rejection are tested with in-memory TLS handshakes.
2. Interruption: candidate write/verification interruption attempts rollback;
   recovery details and route evidence survive. Forced termination and failed
   network recovery remain documented limits.
3. Failure reporting: verified candidate state, lock cleanup, and manifest
   publication are reported separately. Combined failures are covered.
4. Artifacts: POSIX private permissions, atomic publication, overwrite races,
   symlink behavior, and failed writes are tested. Existing captures and Windows
   ACLs still require operator handling as documented.
5. Restore: checkpoint-before-load ordering, pending-work recovery, interruption,
   and independent lock-cleanup reporting are tested. Finding 6 adds a broader
   commit-exclusion requirement to both restore and migration.

## Remaining public-release work

- Validate findings 6 and 7 on an appliance, then run current-code lab migration, interruption,
  restore, commit/push, adjacency, and traffic validation on explicitly supported
  Panorama/PAN-OS versions. The mocked tests and TLS handshakes do not establish
  appliance behavior or dataplane success.
- Replace the private host address in `.env.example` with an explicitly fictional
  hostname; review historical lab names and network information for publication.
- Add a working private security-reporting policy, safe issue templates, and
  tested API-role/permission instructions.
- Put package-building, installed-wheel smoke tests, dependency auditing, and
  secret scanning into CI. Add a supported-Python matrix; current CI tests only
  3.12 while package metadata accepts later versions.
- Add package README/project URLs/license-expression/maturity metadata, a CLI
  version flag, and release notes. Verify sdist contents as well as the wheel.
- Review remote branch protections and release permissions; remote repository
  settings were not inspected.
- Include the new files in the eventual commit/release. At review time,
  `artifacts.py`, its tests, the TLS tests, and review documents were untracked;
  the five fixes were working-tree changes, not a published release.

Recommended next step: live qualification of the current implementation, then
release automation and the remaining publication work.
