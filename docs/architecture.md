# Architecture

[Documentation index](../README.md#documentation)

The CLI discovers LSVPN deployments, constructs paired IPsec replacements, and
optionally writes a verified Panorama candidate transaction. Router names are
preserved by default; an optional spoke-only virtual-router rename runs inside
the same snapshot, locking, and rollback boundary after migration verification.
It renames complete router objects in contributing templates and stack overrides,
repairs imports and next-router references, and verifies the entire Panorama
candidate against the expected changes. Spoke manifests carry the old-to-new
router mapping for subsequent RIB and routing-configuration comparisons. For operator commands see [usage](usage.md); for transaction diagrams,
code/test links, and verification boundaries see [validation](validation.md).

## Firewall and template discovery

- Resolves managed firewalls by case-insensitive hostname or serial number.
- Supports resolving a short hostname to a managed FQDN.
- Suggests close managed-firewall names when a requested name is not found.
- Detects empty, unknown, and ambiguous firewall identifiers.
- Detects missing, empty, or ambiguous template-stack assignments.
- Preserves the template order reported by the assigned stack.
- Treats only templates containing interface configuration as eligible targets.

## Existing LSVPN discovery

For every spoke inheriting the selected shared template, the tool reads
candidate configuration through Panorama and:

- Finds IPsec tunnels of type `global-protect-satellite` in the selected spoke
  virtual system.
- Captures the satellite tunnel name and tunnel interface.
- Captures the portal address, local interface, and local IPv4/IPv6 address.
- Captures published routes and the publish-connected-routes setting.
- When publish-all is enabled, derives eligible connected networks and static
  destinations from the satellite tunnel interface's exact virtual router or
  logical-router VRF. It excludes default routes and routes using the old LSVPN
  or satellite external interface.
- Captures certificate references, anti-replay, copy-TOS, and tunnel-monitor
  settings.
- Queries the firewall's operational state for its active GlobalProtect gateway,
  gateway address, and tunnel-monitor status.
- Converts operational-command failures into plan warnings so discovery can
  continue where possible.

For the selected hub, the tool:

- Reads effective GlobalProtect portal satellite gateway assignments.
- Falls back to the firewall's effective-running configuration when a targeted
  configuration API query omits portal settings inherited from Panorama
  templates.
- Uses the spoke's active gateway address or name first when multiple portal
  candidates exist, then prefers a spoke serial match when runtime state is not
  available. A serial match is not required because PAN-OS can select satellite
  configurations through enrollment user/group authentication. Treats a device
  value of `any` as unrestricted.
- Requires a single unambiguous gateway after runtime and serial matching;
  unresolved multiple gateways are rejected rather than guessed by priority.
- Warns when the portal-designated gateway differs from the spoke's active
  gateway and can request confirmation.
- Matches the portal gateway to effective GlobalProtect gateway configuration on
  the selected hub by name when possible, or by gateway address and tunnel
  interface when portal, gateway, and site-to-site object names differ.
- Treats the endpoint address as gateway identity when portal configurations use
  different labels for the same gateway, and explicitly rejects ambiguous
  address or tunnel-interface mappings.
- Supports portal gateway endpoints expressed as IPv4, IPv6, CIDR, or FQDN.
  FQDN matching is case-insensitive, accepts a trailing DNS root dot and IDNA
  names, and resolves DNS when the corresponding site-to-site object stores only
  a local IP address.
- Reads the hub gateway's external interface and IPv4/IPv6/floating addresses.
- Reads its LSVPN tunnel interface, interface IPs, IPv6 state, management
  profile, MTU, NetFlow profile, and comment.
- Finds the tunnel interface's virtual-router or logical-router/VRF and zone
  memberships without collapsing the two routing models into one scope.
- Reads template-inherited tunnel interfaces, logical-router memberships, and
  zones from effective-running configuration when SDK running-config discovery
  omits them.
- Reads the IPsec crypto profile, tunnel-monitor settings, access routes, client
  IP pools, and DNS settings available on the hub gateway.

## Standard IPsec migration plan

For each discovered satellite tunnel, the tool creates an in-memory plan and
prints:

- A spoke tunnel and IKE gateway name shared by compatible spoke firewalls,
  plus hub endpoint names based on each destination spoke hostname. Tunnel
  names end in a sequence starting at 1; IKE gateways append `-ike`.
- Reusable spoke interface/address and tunnel-interface values.
- Configured, active, and portal-designated gateway information.
- A proposed peer address, preferring the confirmed portal gateway, then the
  active gateway, then the configured portal address.
- Reusable hub gateway and tunnel-interface details.
- Published routes and relevant tunnel behavior settings.
- A cryptographically random per-spoke pre-shared key represented in generated
  configuration through Panorama `pre-shared-key` variables.
- A moderate, interoperability-oriented IKEv2 profile using AES-256-CBC,
  SHA-256, Diffie-Hellman group 14, and an eight-hour lifetime.
- A moderate ESP profile using AES-256-CBC, SHA-256, PFS group 14, and a
  one-hour lifetime. The migration plan displays only the selected ESP profile;
  it does not display an unused AH alternative.
- A newly allocated, collision-free `tunnel.N` interface on each endpoint. The
  interfaces receive unique point-to-point addresses from the operator-supplied
  pool and copy safe MTU, management, NetFlow, IPv6, and zone/routing-scope
  properties from the LSVPN sources. Candidate links overlapping configured
  interface networks on either firewall are skipped.
- Spoke static routes for the hub access-route list, or a default route when the
  blank LSVPN access-route setting represents full tunneling.
- Hub static routes for explicit or derived satellite-published networks.
- Spoke route metrics equal to ten times the portal gateway routing priority,
  preserving primary/backup preference.
- IKEv2 route-based default any/any traffic selectors. Explicit proxy IDs are
  intentionally omitted for this PAN-OS-to-PAN-OS design.
- Existing tunnel monitoring settings, with the destination changed to the new
  peer tunnel address.
- BGP peers bound to the source tunnel, including peer AS, peer-group type,
  authentication, BFD, and legacy virtual-router timer settings. Shared hub
  tunnel peers are matched to the spoke tunnel address before cloning.
- BGP peer-group routing policy inheritance. Legacy virtual-router export rules
  that target the peer group are recorded, and logical-router address-family,
  filtering-profile/route-map, timer, authentication, and dampening references
  are retained on the staged peer group. This preserves policies that advertise
  loopback prefixes, including link-local `/32` routes, over direct tunnel-bound
  BGP sessions.
- BGP-over-loopback topologies in which OSPF on the LSVPN tunnel provides
  reachability between loopbacks and an existing multihop BGP session carries
  production routes. Reciprocal loopback peers are detected explicitly; the
  existing BGP sessions are preserved rather than duplicated or rebound, while
  the replacement OSPF adjacency restores their underlay reachability.
  Tunnel-bound BGP peers take precedence: if either endpoint binds BGP directly
  to the LSVPN tunnel, loopback-transit candidates are discarded and the direct
  BGP cloning workflow is used instead.
- Reciprocal BGP-over-loopback sessions are also detected when OSPF is absent.
  Existing loopback-sourced BGP sessions remain unchanged, while reciprocal
  `/32` or `/128` static host routes to the peer addresses are installed through
  the new tunnel interfaces. This replaces reachability installed implicitly by
  LSVPN without changing the BGP source addresses. Matching old per-spoke static
  routes are removed from both endpoints while shared hub LSVPN configuration is
  preserved; unrelated old-interface routes remain a blocking dependency.
  Unresolved peer addresses block loading because the required host routes
  cannot be constructed.
- OSPF area/interface membership for legacy virtual routers and logical-router
  VRFs. LSVPN point-to-multipoint interfaces become point-to-point interfaces
  because each replacement tunnel has exactly one peer; cost, authentication,
  BFD, and timer references are retained where the routing model supports them.
- Suppression of LSVPN-derived static routes when matching dynamic-routing
  protocols are discovered on both endpoints.
- Warnings for address mismatches, missing peer data, LSVPN certificate reuse,
  and incomplete configuration data.

The CLI caches a discovered hub gateway source during a run when multiple spoke
satellites refer to the same gateway.

The plan is converted into paired `pan-os-python` objects for
the spoke and hub: IKE crypto profiles, IPsec crypto profiles, IKE gateways,
auto-key IPsec tunnels, tunnel interfaces, zones, legacy virtual routers or
logical-router VRFs, IPv4/IPv6 static routes, BGP peers, and OSPF interfaces.
These objects are staged for preview by default. With `--load-candidate`, they
are added or updated in their source-owning Panorama templates and the obsolete
satellite-side objects and bindings are removed from candidate configuration.

## Shared spoke templates

The template that actually owns the LSVPN satellite is treated as the shared
configuration boundary, independently of the interface-bearing template the
operator initially selects. The tool discovers every template stack that
contains the owner and every managed firewall assigned through those stacks.
All inheriting spokes are migrated as one batch; deleting the shared satellite
for only one firewall is not permitted. Satellite objects owned by multiple
templates must be migrated as separate groups.

The batch must be structurally compatible: satellite names, old and replacement
tunnel-interface layout, vsys, zone, virtual/logical router and VRF, and the
BGP/OSPF/static-routing topology must match. Value differences are represented
with variables. Structural differences stop the migration and identify the
firewall that needs a separate template or migration group.

One reusable IKE gateway and IPsec tunnel are created in the shared LSVPN
template. Tunnel-interface, routing, zone, and import changes are written once
per distinct source-owning network-template placement, so stacks that share the
LSVPN template but use different network templates are handled independently.
Generated device-specific IP fields,
IKE identities, route destinations, and PSKs use deterministic Panorama
variables with per-device template-stack overrides. The hub retains a unique
endpoint and unique variables for every spoke. Endpoint names use the
sanitized destination hostname and a sequence starting at 1. For example, the
hub's tunnel to `branch-01` is `branch-01-1`, and the shared spoke tunnel to
`hub-01` is `hub-01-1`; matching IKE gateways append `-ike`. A shared spoke
template uses the same hub destination name for every member.
Variable names spell out their role, such as
`$ptb-spoke-tunnel-interface-address-<id>` and
`$ptb-hub-ike-pre-shared-key-<id>`. One random PSK is generated per spoke and
assigned to both its spoke override and matching hub variable. Non-secret
SHA-256 pairing fingerprints are stored as companion
variables for auditability, and deterministic ownership-marker variables
distinguish tool-managed variable sets from unrelated variables with colliding
names. Because Panorama does not expose PSK plaintext for comparison, every
rerun rotates each PSK and writes its spoke and hub values together in the same
candidate transaction.

Candidate loading is all-or-nothing. Variables and their overrides are written
inside the same candidate transaction as the replacement objects. A write or
post-write verification failure issues Panorama's candidate rollback; local
pre-route artifacts are retained for recovery. A successful rerun rotates paired
PSK variables; a failed run whose rollback succeeds leaves no variable or PSK
state for the next attempt. If no LSVPN satellite configuration remains, a load request
is treated as a successful no-op.

## Panorama placement and safety

Generated network objects belong in the Panorama templates that own each
firewall's network configuration. The tool preserves the order of templates in
the assigned stack, identifies templates containing eligible interface
configuration, and allows the operator to override the recommended selection.

The default workflow performs Panorama discovery and generates a local preview.
With the explicit `--load-candidate` option, the tool acquires a temporary
Panorama configuration and commit locks, rejects unfinished or unverifiable
jobs, and verifies that candidate configuration
matches running configuration. A dirty candidate is rejected by default because
the failure rollback is global. The explicit `--allow-pending-candidate-changes` option
bypasses that protection with a warning. A clean-candidate run saves a
timestamped `LSVPN_PRE_<id>_<timestamp>.xml` Panorama snapshot; an explicitly
allowed dirty-candidate run labels it `LSVPN_CHK_<id>_<timestamp>.xml` to make
clear that it is a checkpoint containing pre-existing pending changes (both
names fit PAN-OS's 32-character saved-config limit). The tool saves hub and
spoke route snapshots locally, and loads the replacement into candidate
configuration. It creates the new hub and spoke objects in the templates that
own the corresponding source configuration, removes the spoke satellite
tunnel and its obsolete interface/routing bindings, and leaves all hub LSVPN
configuration intact. Before removing the old spoke interface, it audits every
template in the spoke stack and blocks on any interface dependency the migration
does not explicitly understand. After writing, it rereads candidate
configuration to verify the replacement object trees, confirm every intended
spoke cleanup, and prove that the hub LSVPN configuration fingerprint is
unchanged. Unrelated name and variable-type collisions are rejected. Reruns
update objects and variables carrying the tool's ownership markers and rotate
both ends of every PSK pair.

Before inventory discovery, candidate-loading builds fingerprint Panorama's full
candidate and running configurations. Before reading managed-firewall plan inputs,
they fingerprint full candidate, running, and effective-running configuration on
the hub and every spoke in the expanded scope. SHA-256 digests of canonical XML
remain in memory. After lock acquisition and the job check, the transaction
requires all source fingerprints to match, including when pending candidate
changes are explicitly allowed. Drift or unreadable sources stop before snapshot,
preflight writes, or rollback; the operator must build and review a fresh plan.
This catches changes committed between discovery and loading even when candidate
and running match. The comparison covers unrelated configuration conservatively;
it ignores whitespace and the same administrative metadata as the clean-candidate
comparison. It does not lock managed-firewall changes or operational state.

PAN-OS interface imports under `vsys/import/network/interface` are migrated as
part of that workflow. Each replacement tunnel interface is imported into the
same endpoint vsys in the source-owning template, and the obsolete spoke tunnel
import is removed with the old satellite interface.

The tool does not commit Panorama, push template stacks, or commit managed
firewalls. The operator performs those steps separately, captures post-change
routes after convergence, and runs the manifest-based verifier. The named
Panorama snapshot can be loaded back into candidate configuration with the
separate restore command; committing and pushing that rollback remains an
operator-controlled action.

Snapshot restore acquires both locks, checks jobs, and saves a fresh checkpoint of
the current candidate, including any pending changes, before loading the
requested snapshot. The checkpoint name is reported before replacement. A load
failure or interruption attempts to reload that checkpoint under the same locks;
it does not use the migration workflow's global revert-to-running operation.
Checkpoint recovery failures and lock-release failures are reported separately.
A successful load followed by a failed lock release remains a loaded candidate
and returns a nonzero CLI status. Restore never commits or pushes.

Candidate loading is transactional after the rollback snapshot is saved. Any
subsequent object write, spoke cleanup, or post-write verification error causes
the tool to issue Panorama's candidate rollback command before releasing its
configuration and commit locks. This restores candidate configuration to running config
without a commit; it also discards other pending candidate changes. The named
snapshot remains available for manual recovery but is not loaded automatically.
If Panorama rejects the rollback, the command reports both failures and warns
that partial candidate changes may remain.

Only confirmed acquisitions authorize release. Configuration-lock cleanup is
attempted first, then commit-lock cleanup, even if the first release fails.
Both failures are tracked independently of the transaction result. A failed lock
release preserves either the verified result or the original load/rollback
error, and the CLI reports the cleanup error separately. Manifest construction
and an initial serialization check occur before candidate loading. After a
verified load, the CLI reports the remote state before atomically publishing the
manifest. Artifact publication or lock-cleanup failures return nonzero while
preserving the verified candidate and recovery baselines; they do not trigger a
new rollback.

## Spoke interface-management profiles

`management_profiles.py` prepares the canonical `ping-only` profile across spoke
template stacks, evaluating inherited service settings and permitted-IP lists.
It does not infer unrestricted access by combining restricted lists from different
template layers.
It renames a matching profile and its interface references or creates an explicit
ping-enabled, all-other-services-disabled profile without source-IP restrictions.
A correct existing canonical profile is reused. The new spoke tunnels reference
this profile before shared-template compatibility checks; hub settings are copied
from their source as before.

Planning checks ownership, local dependencies, conflicting canonical names, and
consumers outside the selected spoke group. Profile mutations run after the
recovery snapshot and before tunnel writes. The loader verifies the entire
candidate against the expected profile/reference changes and checks the effective
profile again after the tunnel migration. Any failure uses the existing rollback.
