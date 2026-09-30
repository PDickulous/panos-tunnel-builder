import hashlib
import ipaddress
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, cast

import typer
from panos.errors import PanDeviceError
from panos.panorama import Panorama

from .candidate import (
    CandidateLoadError,
    CandidateVariableSet,
    ReplacementTemplatePlacement,
    discover_lsvpn_satellite_template_owner,
    discover_replacement_template_placements,
    load_candidate_configuration,
    load_panorama_snapshot,
    resolve_template_interface_address_reference,
)
from .config import ConfigurationFileError, configure_from_file, load_settings
from .inventory import (
    DiscoveryError,
    FirewallTemplateInventory,
    TemplateCandidate,
    discover_firewall_templates,
    discover_managed_firewall,
    discover_shared_template_scope,
)
from .lsvpn import (
    DEFAULT_VSYS,
    GatewayRuntime,
    HubGatewayCloneSource,
    LsvpnConfigurationError,
    PortalGateway,
    SatelliteConfig,
    StandardIpsecClonePlan,
    StandardIpsecReplacementObjects,
    TunnelInterfaceInventory,
    allocate_tunnel_address_pairs,
    allocate_tunnel_interface_names,
    build_standard_clone_plan,
    build_standard_ipsec_objects,
    discover_active_gateway,
    discover_dynamic_routing,
    discover_hub_gateway_clone_source,
    discover_lsvpn_satellites,
    discover_portal_gateways,
    discover_satellite_published_routes,
    discover_tunnel_interface_inventory,
    endpoints_match,
    match_loopback_bgp_transit,
    resolve_ike_local_endpoint,
    select_single_portal_gateway,
    stage_standard_ipsec_objects,
)
from .panorama_client import create_panorama
from .route_validation import (
    MigrationEndpointValidation,
    MigrationValidationManifest,
    RouteComparison,
    RouteDifference,
    RouteEntry,
    RoutePathMapping,
    RouteSnapshot,
    RouteValidationError,
    capture_route_snapshot,
    compare_route_snapshots,
    compare_routing_configurations,
    find_static_route_names,
    parse_mapping,
)
from .shared_migration import (
    SharedSpokeReplacement,
    prepare_shared_template_variables,
)

app = typer.Typer(
    name="panos-tunnel-builder",
    help="Interactively build and manage PAN-OS IPsec tunnels through Panorama.",
    no_args_is_help=True,
)
routes_app = typer.Typer(
    help="Capture and compare firewall routing-table snapshots.",
    no_args_is_help=True,
)
app.add_typer(routes_app, name="routes")
candidate_app = typer.Typer(
    help="Manage migration changes in Panorama candidate configuration.",
    no_args_is_help=True,
)
app.add_typer(candidate_app, name="candidate")


@dataclass(frozen=True)
class SharedBuildResult:
    spokes: tuple[SharedSpokeReplacement, ...]
    variables: CandidateVariableSet

    @property
    def plans(self) -> tuple[StandardIpsecClonePlan, ...]:
        return tuple(item.plan for item in self.spokes)

    @property
    def replacements(self) -> tuple[StandardIpsecReplacementObjects, ...]:
        return tuple(item.replacement for item in self.spokes)


@app.callback()
def cli(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="TOML file containing Panorama settings and command defaults.",
        ),
    ] = None,
) -> None:
    """Build and manage PAN-OS IPsec tunnels through Panorama."""
    try:
        ctx.default_map = configure_from_file(config)
    except ConfigurationFileError as exc:
        typer.echo(f"Configuration file error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def status() -> None:
    """Verify connectivity to the configured Panorama."""
    try:
        settings = load_settings()
        panorama = create_panorama(settings)

        system_info = panorama.op(
            cmd="<show><system><info></info></system></show>",
            cmd_xml=False,
            xml=True,
        )

        typer.echo("Successfully connected to Panorama")
        typer.echo(system_info)

    except PanDeviceError as exc:
        typer.echo(f"PAN-OS API error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    except Exception as exc:
        typer.echo(
            f"Unexpected error: {type(exc).__name__}: {exc}",
            err=True,
        )
        raise typer.Exit(code=2) from exc


@routes_app.command("snapshot")
def routes_snapshot(
    firewall: Annotated[
        str,
        typer.Argument(help="Managed firewall hostname or serial number."),
    ],
    output: Annotated[
        Path,
        typer.Argument(help="Local JSON file to receive the route snapshot."),
    ],
    vsys: Annotated[
        str,
        typer.Option("--vsys", help="Firewall virtual system to query."),
    ] = DEFAULT_VSYS,
    force: Annotated[
        bool,
        typer.Option(
            "--force/--no-force",
            help="Overwrite an existing snapshot file.",
        ),
    ] = False,
) -> None:
    """Capture all IPv4 and IPv6 RIBs from a managed firewall."""
    try:
        if output.exists() and not force:
            raise RouteValidationError(
                f'Snapshot file "{output}" already exists; use --force to overwrite it.'
            )
        settings = load_settings()
        panorama = create_panorama(settings)
        managed = discover_managed_firewall(panorama, firewall)
        snapshot = capture_route_snapshot(
            panorama,
            managed.name,
            managed.serial,
            vsys,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(snapshot.to_json(), encoding="utf-8")
        typer.echo(
            f'Captured {len(snapshot.routes)} routes from "{managed.name}" '
            f'({managed.serial}) to "{output}".'
        )
    except (DiscoveryError, RouteValidationError) as exc:
        typer.echo(f"Route snapshot error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except PanDeviceError as exc:
        typer.echo(f"PAN-OS API error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(
            f"Unexpected error: {type(exc).__name__}: {exc}",
            err=True,
        )
        raise typer.Exit(code=2) from exc


def _route_scope(difference: RouteDifference) -> str:
    kind, instance, vrf, prefix, protocol = difference.identity
    scope = f"{kind}:{instance}"
    if vrf:
        scope = f"{scope}/{vrf}"
    return f"{scope} {prefix} ({protocol})"


def _route_entry_summary(route: RouteEntry) -> str:
    paths = (
        ", ".join(
            f"{path.next_hop or 'direct'} via {path.interface or 'unknown'}"
            for path in route.paths
        )
        or "no next hop"
    )
    return (
        f"distance={route.distance}, metric={route.metric}, "
        f"selected={route.selected}, installed={route.installed}, paths=[{paths}]"
    )


def _show_route_comparison(comparison: RouteComparison) -> None:
    typer.echo(
        "Route comparison: "
        f"{len(comparison.missing)} missing, "
        f"{len(comparison.added)} added, "
        f"{len(comparison.changed)} changed."
    )
    for label, differences in (
        ("missing", comparison.missing),
        ("added", comparison.added),
        ("changed", comparison.changed),
    ):
        for difference in differences:
            typer.echo(f"  [{label}] {_route_scope(difference)}")
            if label == "changed":
                for route in difference.before:
                    typer.echo(f"    before: {_route_entry_summary(route)}")
                for route in difference.after:
                    typer.echo(f"    after:  {_route_entry_summary(route)}")


@routes_app.command("compare")
def routes_compare(
    before: Annotated[
        Path,
        typer.Argument(help="Baseline route snapshot JSON file."),
    ],
    after: Annotated[
        Path,
        typer.Argument(help="Post-change route snapshot JSON file."),
    ],
    prefix_map: Annotated[
        list[str] | None,
        typer.Option(
            "--prefix-map",
            help="Expected route-prefix replacement as OLD=NEW; repeat as needed.",
        ),
    ] = None,
    interface_map: Annotated[
        list[str] | None,
        typer.Option(
            "--interface-map",
            help="Expected egress-interface replacement as OLD=NEW; repeat as needed.",
        ),
    ] = None,
    next_hop_map: Annotated[
        list[str] | None,
        typer.Option(
            "--next-hop-map",
            help="Expected next-hop replacement as OLD=NEW; repeat as needed.",
        ),
    ] = None,
) -> None:
    """Compare two snapshots and fail when stable RIB state differs."""
    try:
        before_snapshot = RouteSnapshot.from_json(before.read_text(encoding="utf-8"))
        after_snapshot = RouteSnapshot.from_json(after.read_text(encoding="utf-8"))
        comparison = compare_route_snapshots(
            before_snapshot,
            after_snapshot,
            prefix_map=parse_mapping(prefix_map, "prefix"),
            interface_map=parse_mapping(interface_map, "interface"),
            next_hop_map=parse_mapping(next_hop_map, "next-hop"),
        )
        _show_route_comparison(comparison)
        if not comparison.equivalent:
            raise typer.Exit(code=1)
        typer.echo("Route tables match after applying the expected replacements.")
    except RouteValidationError as exc:
        typer.echo(f"Route comparison error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        typer.echo(f"Route snapshot file error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _link_prefixes(address: str) -> tuple[str, str]:
    interface = ipaddress.ip_interface(address)
    host = ipaddress.ip_network(
        f"{interface.ip}/{interface.max_prefixlen}", strict=False
    )
    return str(interface.network), str(host)


def _migration_endpoint_rules(
    role: str,
    plans: tuple[StandardIpsecClonePlan, ...],
    baseline: RouteSnapshot,
) -> tuple[dict[str, str], tuple[RoutePathMapping, ...], tuple[str, ...]]:
    prefix_map: dict[str, str] = {}
    mappings: list[RoutePathMapping] = []
    allowed: list[str] = []
    production_protocols = ("bgp", "ospf", "rip", "static", "unknown")
    for plan in plans:
        source = (
            plan.spoke_tunnel_source
            if role == "spoke"
            else plan.hub_gateway.tunnel_interface
            if plan.hub_gateway is not None
            else None
        )
        new_interface = (
            plan.replacement_spoke_tunnel_interface
            if role == "spoke"
            else plan.replacement_hub_tunnel_interface
        )
        new_local = (
            plan.spoke_tunnel_address if role == "spoke" else plan.hub_tunnel_address
        )
        new_remote = (
            plan.hub_tunnel_address if role == "spoke" else plan.spoke_tunnel_address
        )
        if (
            source is None
            or new_interface is None
            or new_local is None
            or new_remote is None
        ):
            continue
        new_network, new_host = _link_prefixes(new_local)
        allowed.extend((new_network, new_host))
        new_local_ip = str(ipaddress.ip_interface(new_local).ip)
        new_remote_ip = str(ipaddress.ip_interface(new_remote).ip)
        if role == "spoke":
            for old_address in source.ip_addresses:
                old_network, old_host = _link_prefixes(old_address)
                prefix_map.setdefault(old_network, new_network)
                if old_host != old_network:
                    prefix_map.setdefault(old_host, new_host)
                old_ip = str(ipaddress.ip_interface(old_address).ip)
                mappings.append(
                    RoutePathMapping(
                        source.name,
                        old_ip,
                        new_interface,
                        new_local_ip,
                        ("connected", "local"),
                    )
                )
            mappings.extend(
                (
                    RoutePathMapping(
                        source.name,
                        None,
                        new_interface,
                        new_remote_ip,
                        production_protocols,
                    ),
                    RoutePathMapping(
                        source.name,
                        None,
                        new_interface,
                        None,
                        ("connected", "local"),
                    ),
                )
            )
        else:
            spoke_source = plan.spoke_tunnel_source
            affected_prefixes = {
                str(ipaddress.ip_network(prefix, strict=False))
                for prefix in plan.hub_static_routes
            }
            for route in baseline.routes:
                if route.prefix not in affected_prefixes:
                    continue
                for path in route.paths:
                    if path.interface != source.name:
                        continue
                    mappings.append(
                        RoutePathMapping(
                            source.name,
                            path.next_hop,
                            new_interface,
                            new_remote_ip,
                            (route.protocol,),
                            (route.prefix,),
                        )
                    )
            for old_address in (
                spoke_source.ip_addresses if spoke_source is not None else ()
            ):
                old_ip = str(ipaddress.ip_interface(old_address).ip)
                mappings.extend(
                    (
                        RoutePathMapping(
                            source.name,
                            old_ip,
                            new_interface,
                            new_remote_ip,
                            production_protocols,
                            tuple(affected_prefixes),
                        ),
                        RoutePathMapping(
                            None,
                            old_ip,
                            new_interface,
                            new_remote_ip,
                            production_protocols,
                            tuple(affected_prefixes),
                        ),
                    )
                )
    return (
        prefix_map,
        tuple(dict.fromkeys(mappings)),
        tuple(dict.fromkeys(allowed)),
    )


def _migration_routing_config_scope(
    role: str,
    plans: tuple[StandardIpsecClonePlan, ...],
    baseline: RouteSnapshot,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    mutable_interfaces: list[str] = []
    replaced_interfaces: list[str] = []
    destinations: list[str] = []
    for plan in plans:
        if role == "spoke":
            if plan.spoke_tunnel_source is not None:
                mutable_interfaces.append(plan.spoke_tunnel_source.name)
                replaced_interfaces.append(plan.spoke_tunnel_source.name)
            if plan.replacement_spoke_tunnel_interface is not None:
                mutable_interfaces.append(plan.replacement_spoke_tunnel_interface)
            destinations.extend(plan.spoke_static_routes)
        else:
            if plan.hub_gateway is not None:
                replaced_interfaces.append(plan.hub_gateway.tunnel_interface.name)
            if plan.replacement_hub_tunnel_interface is not None:
                mutable_interfaces.append(plan.replacement_hub_tunnel_interface)
            destinations.extend(plan.hub_static_routes)
    route_names = find_static_route_names(
        baseline,
        interfaces=tuple(dict.fromkeys(replaced_interfaces)),
        destinations=tuple(dict.fromkeys(destinations)),
    )
    return tuple(dict.fromkeys(mutable_interfaces)), route_names


def _build_migration_manifest(
    panorama_snapshot_name: str,
    inventory: FirewallTemplateInventory,
    hub_inventory: FirewallTemplateInventory,
    vsys: str,
    hub_vsys: str,
    route_snapshot_paths: tuple[Path, Path],
    route_snapshots: tuple[RouteSnapshot, RouteSnapshot],
    plans: tuple[StandardIpsecClonePlan, ...],
) -> MigrationValidationManifest:
    endpoints: list[MigrationEndpointValidation] = []
    for role, endpoint_inventory, endpoint_vsys, baseline_path, baseline in (
        ("spoke", inventory, vsys, route_snapshot_paths[0], route_snapshots[0]),
        ("hub", hub_inventory, hub_vsys, route_snapshot_paths[1], route_snapshots[1]),
    ):
        prefix_map, path_mappings, allowed = _migration_endpoint_rules(
            role, plans, baseline
        )
        mutable_interfaces, mutable_route_names = _migration_routing_config_scope(
            role, plans, baseline
        )
        endpoints.append(
            MigrationEndpointValidation(
                role=cast(Literal["spoke", "hub"], role),
                firewall_name=endpoint_inventory.firewall_name,
                serial=endpoint_inventory.serial,
                vsys=endpoint_vsys,
                baseline_snapshot=baseline_path.name,
                prefix_map=prefix_map,
                path_mappings=path_mappings,
                allowed_added_prefixes=allowed,
                mutable_routing_interfaces=mutable_interfaces,
                mutable_route_names=mutable_route_names,
            )
        )
    return MigrationValidationManifest(
        schema_version=1,
        created_at=datetime.now(UTC).isoformat(),
        panorama_snapshot_name=panorama_snapshot_name,
        endpoints=tuple(endpoints),
    )


def _build_group_migration_manifest(
    panorama_snapshot_name: str,
    spokes: tuple[FirewallTemplateInventory, ...],
    hub: FirewallTemplateInventory,
    vsys: str,
    hub_vsys: str,
    baselines: dict[tuple[str, str], tuple[Path, RouteSnapshot]],
    plans: tuple[StandardIpsecClonePlan, ...],
) -> MigrationValidationManifest:
    endpoints: list[MigrationEndpointValidation] = []
    for spoke in spokes:
        path, baseline = baselines[("spoke", spoke.serial)]
        spoke_plans = tuple(
            plan for plan in plans if plan.spoke_identity == spoke.serial
        )
        prefix_map, mappings, allowed = _migration_endpoint_rules(
            "spoke", spoke_plans, baseline
        )
        mutable_interfaces, mutable_route_names = _migration_routing_config_scope(
            "spoke", spoke_plans, baseline
        )
        endpoints.append(
            MigrationEndpointValidation(
                role="spoke",
                firewall_name=spoke.firewall_name,
                serial=spoke.serial,
                vsys=vsys,
                baseline_snapshot=path.name,
                prefix_map=prefix_map,
                path_mappings=mappings,
                allowed_added_prefixes=allowed,
                mutable_routing_interfaces=mutable_interfaces,
                mutable_route_names=mutable_route_names,
            )
        )
    hub_path, hub_baseline = baselines[("hub", hub.serial)]
    prefix_map, mappings, allowed = _migration_endpoint_rules(
        "hub", plans, hub_baseline
    )
    mutable_interfaces, mutable_route_names = _migration_routing_config_scope(
        "hub", plans, hub_baseline
    )
    endpoints.append(
        MigrationEndpointValidation(
            role="hub",
            firewall_name=hub.firewall_name,
            serial=hub.serial,
            vsys=hub_vsys,
            baseline_snapshot=hub_path.name,
            prefix_map=prefix_map,
            path_mappings=mappings,
            allowed_added_prefixes=allowed,
            mutable_routing_interfaces=mutable_interfaces,
            mutable_route_names=mutable_route_names,
        )
    )
    return MigrationValidationManifest(
        schema_version=1,
        created_at=datetime.now(UTC).isoformat(),
        panorama_snapshot_name=panorama_snapshot_name,
        endpoints=tuple(endpoints),
    )


@routes_app.command("verify-migration")
def routes_verify_migration(
    manifest: Annotated[
        Path,
        typer.Argument(help="Migration validation manifest JSON file."),
    ],
    output_directory: Annotated[
        Path | None,
        typer.Option(
            "--output-directory",
            help="Directory for post-change snapshots; defaults beside the manifest.",
        ),
    ] = None,
) -> None:
    """Capture post-change routes and verify them against a saved migration."""
    try:
        migration = MigrationValidationManifest.from_json(
            manifest.read_text(encoding="utf-8")
        )
        panorama = create_panorama(load_settings())
        destination = output_directory or manifest.parent
        destination.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        failed = False
        for endpoint in migration.endpoints:
            baseline_path = Path(endpoint.baseline_snapshot)
            if not baseline_path.is_absolute():
                baseline_path = manifest.parent / baseline_path
            baseline = RouteSnapshot.from_json(
                baseline_path.read_text(encoding="utf-8")
            )
            after = capture_route_snapshot(
                panorama,
                endpoint.firewall_name,
                endpoint.serial,
                endpoint.vsys,
            )
            after_path = destination / (
                f"LSVPN_POST_MIGRATION_{endpoint.role}_"
                f"{endpoint.firewall_name}_{timestamp}_routes.json"
            )
            after_path.write_text(after.to_json(), encoding="utf-8")
            comparison = compare_route_snapshots(
                baseline,
                after,
                prefix_map=endpoint.prefix_map,
                path_mappings=endpoint.path_mappings,
                allowed_added_prefixes=endpoint.allowed_added_prefixes,
                allow_additional_candidates=True,
            )
            routing_config_changes = compare_routing_configurations(
                baseline,
                after,
                mutable_interfaces=endpoint.mutable_routing_interfaces,
                mutable_route_names=endpoint.mutable_route_names,
            )
            typer.echo(
                f'{endpoint.role.capitalize()} firewall "{endpoint.firewall_name}":'
            )
            bgp_peer_counts_match = (
                baseline.bgp_peer_count is None
                or after.bgp_peer_count == baseline.bgp_peer_count
            )
            if baseline.bgp_peer_count is None:
                typer.echo(
                    "  Configured BGP peers: unavailable in this older baseline"
                )
            else:
                typer.echo(
                    f"  Configured BGP peers: pre={baseline.bgp_peer_count}, "
                    f"post={after.bgp_peer_count}"
                )
            _show_route_comparison(comparison)
            if not baseline.routing_configuration:
                typer.echo(
                    "  Routing configuration: unavailable in this older baseline"
                )
            elif routing_config_changes:
                typer.echo(
                    "  Unexpected routing configuration changes: "
                    f"{', '.join(routing_config_changes)}"
                )
            else:
                typer.echo("  Routing configuration: expected changes only")
            typer.echo(f'  Post-change snapshot: "{after_path}"')
            failed = (
                failed
                or not bgp_peer_counts_match
                or not comparison.equivalent
                or bool(routing_config_changes)
            )
        if failed:
            raise typer.Exit(code=1)
        typer.echo("Migration route verification passed for every endpoint.")
    except RouteValidationError as exc:
        typer.echo(f"Migration route verification error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except PanDeviceError as exc:
        typer.echo(f"PAN-OS API error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        typer.echo(f"Migration validation file error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@candidate_app.command("restore")
def candidate_restore(
    snapshot: Annotated[
        str,
        typer.Argument(help="Named Panorama configuration snapshot to load."),
    ],
    yes: Annotated[
        bool,
        typer.Option(
            "--yes/--no-yes",
            "-y",
            help="Skip the candidate replacement prompt.",
        ),
    ] = False,
) -> None:
    """Restore a saved snapshot to Panorama candidate without committing."""
    try:
        if not yes:
            typer.confirm(
                f'Load "{snapshot}" and replace the Panorama candidate '
                "configuration? No commit or push will be issued.",
                abort=True,
            )
        panorama = create_panorama(load_settings())
        load_panorama_snapshot(panorama, snapshot)
        typer.echo(
            f'Loaded Panorama snapshot "{snapshot}" into candidate configuration. '
            "No commit or push was issued."
        )
    except typer.Abort:
        raise
    except LsvpnConfigurationError as exc:
        typer.echo(f"Candidate restore error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except PanDeviceError as exc:
        typer.echo(f"PAN-OS API error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(
            f"Unexpected error: {type(exc).__name__}: {exc}",
            err=True,
        )
        raise typer.Exit(code=2) from exc


def _show_templates(
    inventory: FirewallTemplateInventory,
    role: str,
) -> None:
    typer.echo(
        f'{role} firewall "{inventory.firewall_name}" ({inventory.serial}) '
        f'uses template stack "{inventory.stack_name}".'
    )
    typer.echo(f"{role} templates in stack:")
    typer.echo("  0. Cancel")
    for index, template in enumerate(inventory.templates, start=1):
        if template.eligible:
            interfaces = ", ".join(template.interface_names)
            typer.echo(f"  {index}. [interfaces] {template.name}: {interfaces}")
        else:
            typer.echo(f"  {index}. [no interfaces] {template.name}")


def _resolve_template(
    inventory: FirewallTemplateInventory,
    requested_number: int | None,
    role: str,
) -> TemplateCandidate:
    eligible = inventory.eligible_templates
    if not eligible:
        raise DiscoveryError(
            f'Template stack "{inventory.stack_name}" has no templates containing '
            "interface configuration."
        )

    recommended_number = next(
        index
        for index, template in enumerate(inventory.templates, start=1)
        if template.eligible
    )

    while True:
        selected_number = requested_number
        if selected_number is None:
            selected_number = typer.prompt(
                f"{role} template number",
                default=recommended_number,
                type=int,
            )

        if selected_number == 0:
            raise typer.Abort()
        if selected_number < 0 or selected_number > len(inventory.templates):
            message = f"Choose a number from 0 to {len(inventory.templates)}."
        else:
            selected = inventory.templates[selected_number - 1]
            if selected.eligible:
                return selected
            message = (
                f'Template "{selected.name}" does not contain interface configuration.'
            )

        if requested_number is not None:
            raise DiscoveryError(message)
        typer.echo(f"Invalid selection: {message}", err=True)


def _heading(title: str) -> None:
    typer.echo(f"\n{title}")


def _show_shared_plan(
    spokes: tuple[SharedSpokeReplacement, ...],
    show_secrets: bool,
) -> None:
    if not spokes:
        return
    first = spokes[0].plan
    _heading("Shared spoke configuration")
    typer.echo(
        f"  Replaces: {first.source_name} on {first.tunnel_interface or '[unknown]'}"
    )
    typer.echo(
        f"  Creates: {first.shared_spoke_tunnel_name} / "
        f"{first.shared_spoke_ike_gateway_name}"
    )
    typer.echo(
        "  Crypto: "
        f"{first.crypto.ike_version.upper()} "
        f"{'+'.join(first.crypto.ike_encryption)}/"
        f"{'+'.join(first.crypto.ike_authentication)}, DH "
        f"{'+'.join(first.crypto.ike_dh_groups)}; "
        f"{first.crypto.ipsec_protocol.upper()} "
        f"{'+'.join(first.crypto.esp_encryption)}/"
        f"{'+'.join(first.crypto.esp_authentication)}, PFS "
        f"{first.crypto.pfs_group}"
    )
    if first.hub_gateway is not None:
        hub_address = (
            first.hub_gateway.external_ipv4
            or first.hub_gateway.external_ipv6
            or first.hub_gateway.address
        )
        typer.echo(
            f"  Hub endpoint: {first.hub_gateway.external_interface} / {hub_address}"
        )
    typer.echo("  Values that differ by firewall use Panorama variables.")

    _heading("Per-spoke tunnel plan")
    warning_spokes: dict[str, list[str]] = {}
    for item in spokes:
        plan = item.plan
        typer.echo(f"  {item.inventory.firewall_name} ({item.inventory.serial})")
        typer.echo(
            f"    WAN: {plan.local_interface or '[unknown]'} / "
            f"{plan.local_address or '[unknown]'} -> "
            f"{plan.peer_address_candidate or '[unknown]'}"
        )
        typer.echo(
            "    Tunnel: spoke "
            f"{plan.replacement_spoke_tunnel_interface} "
            f"({plan.spoke_tunnel_address}) <-> hub "
            f"{plan.replacement_hub_tunnel_interface} "
            f"({plan.hub_tunnel_address})"
        )
        typer.echo(f"    Hub objects: {plan.tunnel_name} / {plan.ike_gateway_name}")
        protocols = ", ".join(plan.spoke_dynamic_routing.protocols) or "static"
        if plan.spoke_dynamic_routing.transit_bgp:
            peers = ", ".join(
                peer.peer_name for peer in plan.spoke_dynamic_routing.transit_bgp
            )
            reachability = (
                "OSPF on the replacement tunnel"
                if plan.spoke_dynamic_routing.ospf
                else "static peer host routes"
            )
            routing = f"loopback BGP ({peers}); reachability via {reachability}"
        else:
            routing = protocols
        typer.echo(f"    Routing: {routing}")
        if plan.spoke_static_routes or plan.hub_static_routes:
            typer.echo(
                "    New static routes: spoke ["
                f"{', '.join(plan.spoke_static_routes) or 'none'}]; hub ["
                f"{', '.join(plan.hub_static_routes) or 'none'}]"
            )
        psk_display = plan.pre_shared_key if show_secrets else "[hidden]"
        fingerprint = hashlib.sha256(plan.pre_shared_key.encode()).hexdigest()[:12]
        typer.echo(
            "    PSK for new variables: "
            f"{psk_display} (SHA-256 {fingerprint}; reruns rotate both endpoints)"
        )
        for warning in plan.warnings:
            warning_spokes.setdefault(warning, []).append(item.inventory.firewall_name)

    if warning_spokes:
        _heading("Notes")
        for warning, names in warning_spokes.items():
            typer.echo(f"  {', '.join(names)}: {warning}")


def _common_tunnel_interface_names(
    inventories: tuple[TunnelInterfaceInventory, ...],
    count: int,
) -> tuple[str, ...]:
    used = {name.casefold() for inventory in inventories for name in inventory.names}
    result: list[str] = []
    for unit in range(1, 10000):
        name = f"tunnel.{unit}"
        if name.casefold() in used:
            continue
        result.append(name)
        used.add(name.casefold())
        if len(result) == count:
            return tuple(result)
    if count == 0:
        return ()
    raise LsvpnConfigurationError(
        f"Unable to allocate {count} tunnel interfaces common to every spoke."
    )


def _build_shared_migration(
    panorama: Panorama,
    spoke_template: str,
    spoke_inventories: tuple[FirewallTemplateInventory, ...],
    hub_inventory: FirewallTemplateInventory,
    hub_template: str,
    tunnel_address_pool: str,
    vsys: str,
    hub_vsys: str,
    yes: bool,
) -> SharedBuildResult:
    portal_gateways = discover_portal_gateways(panorama, hub_inventory.serial, hub_vsys)
    satellites_by_serial: dict[str, tuple[SatelliteConfig, ...]] = {}
    tunnel_inventory_by_serial: dict[str, TunnelInterfaceInventory] = {}
    satellite_shape: tuple[str, ...] | None = None
    for spoke in spoke_inventories:
        satellites = discover_lsvpn_satellites(panorama, spoke.serial, vsys)
        names = tuple(item.name for item in satellites)
        if not satellites:
            raise LsvpnConfigurationError(
                f'Firewall "{spoke.firewall_name}" inherits shared template '
                f'"{spoke_template}" but has no applicable LSVPN satellite.'
            )
        if satellite_shape is None:
            satellite_shape = names
        elif names != satellite_shape:
            raise LsvpnConfigurationError(
                f'Firewall "{spoke.firewall_name}" has LSVPN satellite objects '
                f"{names!r}, but the shared migration group requires "
                f"{satellite_shape!r}. Split the firewalls into separate templates."
            )
        satellites_by_serial[spoke.serial] = satellites
        tunnel_inventory_by_serial[spoke.serial] = discover_tunnel_interface_inventory(
            panorama, spoke.serial, vsys
        )

    assert satellite_shape is not None
    per_spoke_count = len(satellite_shape)
    total_count = per_spoke_count * len(spoke_inventories)
    hub_tunnel_inventory = discover_tunnel_interface_inventory(
        panorama, hub_inventory.serial, hub_vsys
    )
    spoke_tunnel_inventories = tuple(tunnel_inventory_by_serial.values())
    excluded_networks = tuple(
        dict.fromkeys(
            network
            for inventory in (*spoke_tunnel_inventories, hub_tunnel_inventory)
            for network in inventory.configured_networks
        )
    )
    address_pairs = allocate_tunnel_address_pairs(
        tunnel_address_pool, total_count, excluded_networks
    )
    spoke_interfaces = _common_tunnel_interface_names(
        spoke_tunnel_inventories, per_spoke_count
    )
    hub_interfaces = allocate_tunnel_interface_names(hub_tunnel_inventory, total_count)

    planned: list[SharedSpokeReplacement] = []
    hub_sources: dict[tuple[str, str], HubGatewayCloneSource] = {}
    global_index = 0
    for spoke in spoke_inventories:
        spoke_tunnel_inventory = tunnel_inventory_by_serial[spoke.serial]
        for satellite_index, discovered_satellite in enumerate(
            satellites_by_serial[spoke.serial]
        ):
            satellite = _resolve_satellite_ike_endpoint(
                panorama,
                spoke.serial,
                discovered_satellite,
                vsys,
                tuple(template.name for template in spoke.templates),
            )
            spoke_tunnel_source = (
                spoke_tunnel_inventory.find(satellite.tunnel_interface)
                if satellite.tunnel_interface is not None
                else None
            )
            if spoke_tunnel_source is None:
                raise LsvpnConfigurationError(
                    f'LSVPN tunnel interface "{satellite.tunnel_interface}" was '
                    f'not found on spoke "{spoke.firewall_name}".'
                )
            published = discover_satellite_published_routes(
                panorama, spoke.serial, satellite, spoke_tunnel_source, vsys
            )
            runtime = discover_active_gateway(panorama, spoke.serial, satellite, vsys)
            portal_gateway = _resolve_portal_gateway(
                _portal_candidates(portal_gateways, spoke.serial, runtime),
                runtime,
                yes,
            )
            if portal_gateway is None:
                raise LsvpnConfigurationError(
                    f'Firewall "{spoke.firewall_name}" has no selected hub gateway.'
                )
            source_key = (portal_gateway.name, portal_gateway.address)
            hub_gateway = hub_sources.get(source_key)
            if hub_gateway is None:
                hub_gateway = discover_hub_gateway_clone_source(
                    panorama,
                    hub_inventory.serial,
                    portal_gateway,
                    hub_vsys,
                )
                hub_gateway = _resolve_hub_ike_endpoint(
                    panorama,
                    hub_inventory.serial,
                    hub_gateway,
                    hub_vsys,
                    tuple(template.name for template in hub_inventory.templates),
                )
                hub_sources[source_key] = hub_gateway
            spoke_dynamic = discover_dynamic_routing(
                panorama,
                spoke.serial,
                spoke_tunnel_source,
                vsys,
                hub_gateway.tunnel_interface.ip_addresses,
            )
            spoke_peer_addresses = tuple(
                dict.fromkeys(
                    (
                        *spoke_tunnel_source.ip_addresses,
                        *(
                            peer.local_address
                            for peer in spoke_dynamic.bgp
                            if peer.local_address
                        ),
                    )
                )
            )
            hub_dynamic = discover_dynamic_routing(
                panorama,
                hub_inventory.serial,
                hub_gateway.tunnel_interface,
                hub_vsys,
                spoke_peer_addresses,
            )
            spoke_dynamic, hub_dynamic = match_loopback_bgp_transit(
                spoke_dynamic, hub_dynamic
            )
            plan = build_standard_clone_plan(
                satellite,
                runtime,
                portal_gateway,
                hub_gateway,
                spoke_tunnel_source=spoke_tunnel_source,
                replacement_spoke_tunnel_interface=spoke_interfaces[satellite_index],
                replacement_hub_tunnel_interface=hub_interfaces[global_index],
                resolved_published_routes=published,
                tunnel_addresses=address_pairs[global_index],
                spoke_dynamic_routing=spoke_dynamic,
                hub_dynamic_routing=hub_dynamic,
                spoke_identity=spoke.serial,
                spoke_hostname=spoke.firewall_name,
                hub_hostname=hub_inventory.firewall_name,
                tunnel_sequence=satellite_index + 1,
            )
            replacement = build_standard_ipsec_objects(plan, shared_spoke_names=True)
            planned.append(SharedSpokeReplacement(spoke, plan, replacement))
            global_index += 1

    variables = prepare_shared_template_variables(
        spoke_template, hub_template, tuple(planned)
    )
    return SharedBuildResult(tuple(planned), variables)


def _portal_candidates(
    gateways: tuple[PortalGateway, ...],
    spoke_serial: str,
    runtime: GatewayRuntime | None = None,
) -> tuple[PortalGateway, ...]:
    """Prefer serial-specific assignments without requiring a serial match.

    PAN-OS can select a satellite configuration by enrollment user or group as
    well as by device serial.  The authenticated enrollment identity is not
    available in the local satellite configuration, so a serial match is useful
    when present but cannot be used as a mandatory applicability test.
    """
    if runtime and runtime.gateway_address:
        active_matches = tuple(
            gateway
            for gateway in gateways
            if endpoints_match(gateway.address, runtime.gateway_address)
        )
        if active_matches:
            return active_matches
    if runtime and runtime.gateway_name:
        active_name = runtime.gateway_name.casefold()
        active_matches = tuple(
            gateway for gateway in gateways if gateway.name.casefold() == active_name
        )
        if active_matches:
            return active_matches

    serial_matches = tuple(
        gateway for gateway in gateways if spoke_serial in gateway.satellite_serials
    )
    if serial_matches:
        return serial_matches

    unrestricted = tuple(
        gateway for gateway in gateways if not gateway.satellite_serials
    )
    if unrestricted:
        return unrestricted

    # The remaining configurations may be selected by enrollment user/group.
    # Keep them as candidates and let the existing ambiguity checks require a
    # single portal/gateway rather than incorrectly rejecting all of them.
    return gateways


def _resolve_portal_gateway(
    gateways: tuple[PortalGateway, ...],
    runtime: GatewayRuntime,
    accept_mismatch: bool,
) -> PortalGateway | None:
    if not gateways:
        typer.echo(
            "No applicable satellite gateways were found in the selected hub's "
            "portal configuration."
        )
        return None

    active_matches: tuple[PortalGateway, ...] = ()
    if runtime.gateway_address:
        active_matches = tuple(
            gateway
            for gateway in gateways
            if endpoints_match(gateway.address, runtime.gateway_address)
        )
        if active_matches:
            gateways = active_matches
    if runtime.gateway_name and not active_matches:
        active_name = runtime.gateway_name.casefold()
        active_matches = tuple(
            gateway for gateway in gateways if gateway.name.casefold() == active_name
        )
        if active_matches:
            gateways = active_matches

    selected = select_single_portal_gateway(gateways)
    if selected is None:
        return None
    if runtime.gateway_address and not endpoints_match(
        runtime.gateway_address,
        selected.address,
    ):
        message = (
            f'Portal gateway "{selected.name}" ({selected.address}) differs from '
            f"the active gateway {runtime.gateway_address}"
        )
        typer.echo(f"Warning: {message}.", err=True)
        if not accept_mismatch:
            typer.confirm(f"{message}. Continue with the portal gateway?", abort=True)
    return selected


def _validated_ike_local_reference(
    panorama: Panorama,
    serial: str,
    interface_name: str,
    address: str,
    vsys: str,
    role: str,
) -> tuple[str, str, int]:
    resolved_interface, resolved_address = resolve_ike_local_endpoint(
        panorama,
        serial,
        interface_name,
        address,
        vsys,
        role,
    )
    try:
        version = ipaddress.ip_interface(resolved_address).version
    except ValueError as exc:
        raise LsvpnConfigurationError(
            f"{role.capitalize()} IKE local address reference "
            f'"{resolved_address}" is not an IP interface address.'
        ) from exc
    if resolved_interface.casefold() != interface_name.casefold():
        typer.echo(
            f'Using {role} interface "{resolved_interface}" because it owns '
            f'IKE local address "{resolved_address}".'
        )
    return resolved_interface, resolved_address, version


def _resolve_satellite_ike_endpoint(
    panorama: Panorama,
    serial: str,
    satellite: SatelliteConfig,
    vsys: str,
    template_names: tuple[str, ...],
) -> SatelliteConfig:
    address = satellite.local_ipv4 or satellite.local_ipv6
    if satellite.local_interface is None or address is None:
        return satellite
    interface_name, effective_address, version = _validated_ike_local_reference(
        panorama,
        serial,
        satellite.local_interface,
        address,
        vsys,
        "spoke",
    )
    reference = resolve_template_interface_address_reference(
        panorama,
        template_names,
        interface_name,
        effective_address,
    )
    return replace(
        satellite,
        local_interface=interface_name,
        local_ipv4=effective_address if version == 4 else None,
        local_ipv6=effective_address if version == 6 else None,
        local_address_reference=reference,
    )


def _resolve_hub_ike_endpoint(
    panorama: Panorama,
    serial: str,
    gateway: HubGatewayCloneSource,
    vsys: str,
    template_names: tuple[str, ...],
) -> HubGatewayCloneSource:
    address = (
        gateway.external_ipv4
        or gateway.external_ipv6
        or gateway.floating_ipv4
        or gateway.floating_ipv6
    )
    if gateway.external_interface is None or address is None:
        return gateway
    interface_name, effective_address, version = _validated_ike_local_reference(
        panorama,
        serial,
        gateway.external_interface,
        address,
        vsys,
        "hub",
    )
    reference = resolve_template_interface_address_reference(
        panorama,
        template_names,
        interface_name,
        effective_address,
    )
    return replace(
        gateway,
        external_interface=interface_name,
        external_ipv4=effective_address if version == 4 else None,
        external_ipv6=effective_address if version == 6 else None,
        external_address_reference=reference,
    )


@app.command()
def build(
    firewall: Annotated[
        str | None,
        typer.Argument(help="Firewall hostname or serial number."),
    ] = None,
    template_number: Annotated[
        int | None,
        typer.Option(
            "--template-number",
            "-t",
            help="Spoke template menu number; prompts when omitted.",
        ),
    ] = None,
    hub: Annotated[
        str | None,
        typer.Option(
            "--hub",
            "-H",
            help="Hub firewall hostname or serial; prompts when omitted.",
        ),
    ] = None,
    hub_template_number: Annotated[
        int | None,
        typer.Option(
            "--hub-template-number",
            help="Hub template menu number; prompts when omitted.",
        ),
    ] = None,
    vsys: Annotated[
        str,
        typer.Option(
            "--vsys",
            help="Spoke virtual system containing the LSVPN configuration.",
        ),
    ] = DEFAULT_VSYS,
    hub_vsys: Annotated[
        str,
        typer.Option(
            "--hub-vsys",
            help="Hub virtual system containing the portal and gateway.",
        ),
    ] = DEFAULT_VSYS,
    show_secrets: Annotated[
        bool,
        typer.Option(
            "--show-secrets/--no-show-secrets",
            help="Display generated pre-shared keys in terminal output.",
        ),
    ] = False,
    tunnel_address_pool: Annotated[
        str | None,
        typer.Option(
            "--tunnel-address-pool",
            help=(
                "IPv4 or IPv6 pool used to allocate one /30 or /127 per "
                "replacement tunnel; prompts when omitted for LSVPN."
            ),
        ),
    ] = None,
    load_candidate: Annotated[
        bool,
        typer.Option(
            "--load-candidate/--no-load-candidate",
            help=(
                "Save pre-migration state and load the replacement into the "
                "Panorama candidate configuration without committing."
            ),
        ),
    ] = False,
    allow_dirty_candidate: Annotated[
        bool,
        typer.Option(
            "--allow-dirty-candidate/--no-allow-dirty-candidate",
            help=(
                "Allow loading when Panorama already has pending candidate changes; "
                "an error will revert all pending changes to running configuration."
            ),
        ),
    ] = False,
    snapshot_directory: Annotated[
        Path,
        typer.Option(
            "--snapshot-directory",
            help="Directory for pre-migration route snapshots.",
        ),
    ] = Path("migration-snapshots"),
    yes: Annotated[
        bool,
        typer.Option(
            "--yes/--no-yes",
            "-y",
            help="Accept selections and candidate loading without confirmation.",
        ),
    ] = False,
) -> None:
    """Select the spoke and hub firewalls and their network templates."""
    try:
        firewall_name = firewall or typer.prompt("Spoke Firewall Name")
        settings = load_settings()
        panorama = create_panorama(settings)
        inventory = discover_firewall_templates(panorama, firewall_name)

        if template_number is None:
            _show_templates(inventory, "Spoke")
        selected = _resolve_template(inventory, template_number, "Spoke")
        hub_name = hub or typer.prompt("Hub firewall name")
        hub_inventory = discover_firewall_templates(
            panorama,
            hub_name,
        )
        if hub_inventory.serial == inventory.serial:
            raise DiscoveryError(
                "The hub firewall must be different from the spoke firewall."
            )

        if hub_template_number is None:
            _show_templates(hub_inventory, "Hub")
        hub_selected = _resolve_template(
            hub_inventory,
            hub_template_number,
            "Hub",
        )
        _heading("Selection")
        typer.echo(f"  Requested spoke: {inventory.firewall_name}")
        typer.echo(f'  Spoke template: "{selected.name}"')
        typer.echo(f"  Hub firewall: {hub_inventory.firewall_name}")
        typer.echo(f'  Hub template: "{hub_selected.name}"')
        selected_satellites = discover_lsvpn_satellites(
            panorama, inventory.serial, vsys
        )
        satellite_template = (
            discover_lsvpn_satellite_template_owner(
                panorama,
                tuple(template.name for template in inventory.templates),
                tuple(satellite.name for satellite in selected_satellites),
            )
            if selected_satellites
            else None
        )
        shared_scope = (
            discover_shared_template_scope(panorama, cast(str, satellite_template))
            if satellite_template is not None
            else None
        )
        spoke_inventories = (
            shared_scope.firewalls if shared_scope is not None else (inventory,)
        )
        if not any(item.serial == inventory.serial for item in spoke_inventories):
            raise DiscoveryError(
                f'Selected firewall "{inventory.firewall_name}" does not inherit '
                f'LSVPN owner template "{satellite_template}".'
            )
        if any(item.serial == hub_inventory.serial for item in spoke_inventories):
            raise DiscoveryError(
                "The selected hub is also in the shared spoke-template scope."
            )
        if selected_satellites:
            typer.echo(f'  LSVPN owner template: "{satellite_template}"')
            _heading(f"Migration scope ({len(spoke_inventories)} spokes)")
            for affected in spoke_inventories:
                typer.echo(
                    f"  {affected.firewall_name} ({affected.serial}) — stack "
                    f'"{affected.stack_name}"'
                )
        if selected_satellites and tunnel_address_pool is None:
            tunnel_address_pool = typer.prompt(
                "Tunnel address pool (IPv4 /30s or IPv6 /127s)",
            )
        shared_build = (
            _build_shared_migration(
                panorama,
                cast(str, satellite_template),
                spoke_inventories,
                hub_inventory,
                hub_selected.name,
                cast(str, tunnel_address_pool),
                vsys,
                hub_vsys,
                yes,
            )
            if selected_satellites
            else SharedBuildResult((), CandidateVariableSet())
        )
        clone_plans = list(shared_build.plans)
        replacements = list(shared_build.replacements)
        if replacements:
            if not load_candidate:
                stage_standard_ipsec_objects(
                    panorama,
                    cast(str, satellite_template),
                    hub_selected.name,
                    tuple(replacements),
                    vsys,
                    hub_vsys,
                )
        else:
            _heading("Discovery result")
            typer.echo(
                "  No LSVPN satellite configuration was found; nothing to migrate."
            )
        _show_shared_plan(shared_build.spokes, show_secrets)

        if not yes:
            typer.confirm(
                f'Use spoke template "{selected.name}" and hub template '
                f'"{hub_selected.name}" on "{hub_inventory.firewall_name}" with '
                f"{len(clone_plans)} LSVPN clone plan(s)?",
                abort=True,
            )

        if load_candidate:
            if not clone_plans:
                _heading("Candidate load result")
                typer.echo("  Status: no LSVPN satellite configuration remains")
                typer.echo("  Changes: none")
                typer.echo("  Commit/push: not issued")
                return
            if len(replacements) != len(clone_plans):
                raise LsvpnConfigurationError(
                    "A complete replacement plan is required before candidate "
                    "configuration can be loaded."
                )
            if allow_dirty_candidate:
                typer.echo(
                    "WARNING: dirty-candidate protection is disabled. A loading "
                    "error will revert every pending Panorama candidate change."
                )
            if not yes:
                typer.confirm(
                    "Load candidate configuration now? This removes the spoke "
                    "LSVPN satellite object and its old tunnel bindings from the "
                    "Panorama candidate configuration. No commit or push is issued.",
                    abort=True,
                )
            timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
            snapshot_directory.mkdir(parents=True, exist_ok=True)
            route_snapshot_paths: list[Path] = []
            baselines: dict[tuple[str, str], tuple[Path, RouteSnapshot]] = {}
            try:
                endpoints = (
                    *(("spoke", item, vsys) for item in spoke_inventories),
                    ("hub", hub_inventory, hub_vsys),
                )
                for role, endpoint_inventory, endpoint_vsys in endpoints:
                    safe_name = re.sub(
                        r"[^A-Za-z0-9_.-]", "-", endpoint_inventory.firewall_name
                    )
                    route_path = snapshot_directory / (
                        f"LSVPN_PRE_MIGRATION_{role}_{safe_name}_{timestamp}_routes.json"
                    )
                    route_snapshot = capture_route_snapshot(
                        panorama,
                        endpoint_inventory.firewall_name,
                        endpoint_inventory.serial,
                        endpoint_vsys,
                    )
                    route_path.write_text(route_snapshot.to_json(), encoding="utf-8")
                    route_snapshot_paths.append(route_path)
                    baselines[(role, endpoint_inventory.serial)] = (
                        route_path,
                        route_snapshot,
                    )

                placement_list: list[ReplacementTemplatePlacement] = []
                for item in shared_build.spokes:
                    placement_list.extend(
                        discover_replacement_template_placements(
                            panorama,
                            tuple(
                                template.name for template in item.inventory.templates
                            ),
                            tuple(
                                template.name for template in hub_inventory.templates
                            ),
                            (item.plan,),
                            vsys,
                            hub_vsys,
                        )
                    )
                placements = tuple(placement_list)
                candidate_result = load_candidate_configuration(
                    panorama,
                    selected.name,
                    tuple(clone_plans),
                    tuple(replacements),
                    placements,
                    vsys,
                    hub_vsys,
                    shared_build.variables,
                    allow_dirty_candidate,
                )
            except Exception:
                for route_path in route_snapshot_paths:
                    route_path.unlink(missing_ok=True)
                raise
            manifest = _build_group_migration_manifest(
                candidate_result.panorama_snapshot_name,
                spoke_inventories,
                hub_inventory,
                vsys,
                hub_vsys,
                baselines,
                tuple(clone_plans),
            )
            spoke_safe_name = re.sub(r"[^A-Za-z0-9_.-]", "-", inventory.firewall_name)
            manifest_path = snapshot_directory / (
                f"LSVPN_MIGRATION_{spoke_safe_name}_{timestamp}_validation.json"
            )
            manifest_path.write_text(manifest.to_json(), encoding="utf-8")
            _heading("Candidate load result")
            typer.echo("  Status: verified in Panorama candidate configuration")
            typer.echo(
                "  Changes: "
                f"{candidate_result.created_or_updated_objects} objects written, "
                f"{candidate_result.removed_satellite_objects} legacy LSVPN "
                "objects, routes, or bindings removed"
            )
            typer.echo(
                f'  Rollback snapshot: "{candidate_result.panorama_snapshot_name}"'
            )
            typer.echo("  Route baselines:")
            for route_path in route_snapshot_paths:
                typer.echo(f'    "{route_path}"')
            typer.echo(f'  Post-check manifest: "{manifest_path}"')
            typer.echo("  Commit/push: not issued")

    except typer.Abort:
        raise
    except CandidateLoadError as exc:
        typer.echo(f"Candidate load error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except (DiscoveryError, LsvpnConfigurationError) as exc:
        typer.echo(f"Discovery error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except PanDeviceError as exc:
        typer.echo(f"PAN-OS API error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(
            f"Unexpected error: {type(exc).__name__}: {exc}",
            err=True,
        )
        raise typer.Exit(code=2) from exc


def main() -> None:
    app()
