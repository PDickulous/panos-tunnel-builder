import hashlib
import ipaddress
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .candidate import (
    CandidateVariableSet,
    DeviceVariableOverride,
    PskFingerprintPair,
    TemplateVariableDefinition,
)
from .inventory import FirewallTemplateInventory
from .lsvpn import (
    EndpointVariableReferences,
    LsvpnConfigurationError,
    StandardIpsecClonePlan,
    StandardIpsecReplacementObjects,
    apply_endpoint_variable_references,
    generate_pre_shared_key,
)


@dataclass(frozen=True)
class SharedSpokeReplacement:
    inventory: FirewallTemplateInventory
    plan: StandardIpsecClonePlan
    replacement: StandardIpsecReplacementObjects


def _variable_name(source: str, field: str, identity: str | None = None) -> str:
    digest = hashlib.sha256(f"{source}\0{identity or ''}".encode()).hexdigest()[:7]
    return f"$ptb-{field}-{digest}"


def _host(address: str) -> str:
    return ipaddress.ip_interface(address).ip.compressed


def _address_type(address: str) -> str:
    try:
        ipaddress.ip_interface(address)
    except ValueError:
        return "fqdn"
    return "ip-netmask"


def _psk_fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()
    return f"{digest[:32]}.{digest[32:]}.psk.ptb.invalid"


def _ownership_value(source: str) -> str:
    digest = hashlib.sha256(source.encode()).hexdigest()[:16]
    return f"panos-tunnel-builder.{digest}.ptb.invalid"


def _definition(
    template: str,
    name: str,
    variable_type: str,
    value: str,
) -> TemplateVariableDefinition:
    return TemplateVariableDefinition(template, name, variable_type, value)


def _override(
    inventory: FirewallTemplateInventory,
    name: str,
    variable_type: str,
    value: str,
) -> DeviceVariableOverride:
    return DeviceVariableOverride(
        inventory.stack_name,
        inventory.serial,
        name,
        variable_type,
        value,
    )


def _route_references(
    template: str,
    source: str,
    identity: str | None,
    endpoint: str,
    destinations: tuple[str, ...],
) -> tuple[
    tuple[TemplateVariableDefinition, ...],
    tuple[tuple[str, str], ...],
]:
    definitions: list[TemplateVariableDefinition] = []
    replacements: list[tuple[str, str]] = []
    for index, destination in enumerate(destinations, start=1):
        name = _variable_name(
            source,
            f"{endpoint}-static-route-{index:03d}-destination",
            identity,
        )
        definitions.append(_definition(template, name, "ip-netmask", destination))
        replacements.append((destination, name))
    return tuple(definitions), tuple(replacements)


def prepare_shared_template_variables(
    spoke_template: str,
    hub_template: str,
    spokes: tuple[SharedSpokeReplacement, ...],
) -> CandidateVariableSet:
    """Variable-back a shared spoke object and each unique hub endpoint."""
    if not spokes:
        raise LsvpnConfigurationError("A shared migration has no spoke plans.")

    definitions: list[TemplateVariableDefinition] = []
    overrides: list[DeviceVariableOverride] = []
    spoke_shapes: dict[str, tuple[bytes, ...]] = {}
    default_psks: dict[str, str] = {}
    psk_pairs: list[PskFingerprintPair] = []
    ownership_markers: list[TemplateVariableDefinition] = []
    hub_owner_sources: set[str] = set()

    for item in spokes:
        plan = item.plan
        if (
            plan.spoke_tunnel_address is None
            or plan.hub_tunnel_address is None
            or plan.local_address is None
            or plan.peer_address_candidate is None
            or plan.hub_gateway is None
        ):
            raise LsvpnConfigurationError(
                f'Replacement tunnel "{plan.tunnel_name}" lacks variable values.'
            )
        source = plan.source_name
        spoke_link = _variable_name(source, "spoke-tunnel-interface-address")
        spoke_local = _variable_name(source, "spoke-tunnel-local-address")
        spoke_peer = _variable_name(source, "spoke-tunnel-peer-address")
        spoke_ike_local = _variable_name(source, "spoke-ike-local-address")
        spoke_ike_peer = _variable_name(source, "spoke-ike-peer-address")
        spoke_psk = _variable_name(source, "spoke-ike-pre-shared-key")
        spoke_psk_fingerprint = _variable_name(source, "spoke-ike-psk-fingerprint")
        owner_name = _variable_name(source, "migration-owner")
        spoke_id = _variable_name(source, "spoke-ike-identity")
        route_defs, route_refs = _route_references(
            spoke_template,
            source,
            None,
            "spoke",
            plan.spoke_static_routes,
        )
        if source not in default_psks:
            default_psks[source] = generate_pre_shared_key()
            spoke_owner = _definition(
                spoke_template,
                owner_name,
                "fqdn",
                _ownership_value(source),
            )
            ownership_markers.append(spoke_owner)
            definitions.extend(
                (
                    spoke_owner,
                    _definition(
                        spoke_template,
                        spoke_link,
                        "ip-netmask",
                        plan.spoke_tunnel_address,
                    ),
                    _definition(
                        spoke_template,
                        spoke_local,
                        "ip-netmask",
                        _host(plan.spoke_tunnel_address),
                    ),
                    _definition(
                        spoke_template,
                        spoke_peer,
                        "ip-netmask",
                        _host(plan.hub_tunnel_address),
                    ),
                    _definition(
                        spoke_template,
                        spoke_ike_local,
                        "ip-netmask",
                        plan.local_address,
                    ),
                    _definition(
                        spoke_template,
                        spoke_ike_peer,
                        _address_type(plan.peer_address_candidate),
                        plan.peer_address_candidate,
                    ),
                    _definition(
                        spoke_template,
                        spoke_psk,
                        "pre-shared-key",
                        default_psks[source],
                    ),
                    _definition(
                        spoke_template,
                        spoke_psk_fingerprint,
                        "fqdn",
                        _psk_fingerprint(default_psks[source]),
                    ),
                    _definition(
                        spoke_template,
                        spoke_id,
                        "fqdn",
                        f"spoke-{item.inventory.serial}.ptb.invalid",
                    ),
                    *route_defs,
                )
            )
        spoke_values = (
            (spoke_link, "ip-netmask", plan.spoke_tunnel_address),
            (spoke_local, "ip-netmask", _host(plan.spoke_tunnel_address)),
            (spoke_peer, "ip-netmask", _host(plan.hub_tunnel_address)),
            (spoke_ike_local, "ip-netmask", plan.local_address),
            (
                spoke_ike_peer,
                _address_type(plan.peer_address_candidate),
                plan.peer_address_candidate,
            ),
            (spoke_psk, "pre-shared-key", plan.pre_shared_key),
            (
                spoke_psk_fingerprint,
                "fqdn",
                _psk_fingerprint(plan.pre_shared_key),
            ),
            (spoke_id, "fqdn", f"spoke-{item.inventory.serial}.ptb.invalid"),
        )
        overrides.extend(
            _override(item.inventory, name, variable_type, value)
            for name, variable_type, value in spoke_values
        )
        overrides.extend(
            _override(
                item.inventory, definition.name, definition.variable_type, destination
            )
            for definition, destination in zip(
                route_defs, plan.spoke_static_routes, strict=True
            )
        )
        spoke_refs = EndpointVariableReferences(
            tunnel_interface_address=spoke_link,
            tunnel_local=spoke_local,
            tunnel_peer=spoke_peer,
            ike_local=spoke_ike_local,
            ike_peer=spoke_ike_peer,
            pre_shared_key=spoke_psk,
            ike_identity=spoke_id,
            route_destinations=route_refs,
        )
        apply_endpoint_variable_references(
            item.replacement.spoke,
            spoke_refs,
            plan.spoke_tunnel_address,
            plan.hub_tunnel_address,
        )

        identity = item.inventory.serial
        hub_link = _variable_name(source, "hub-tunnel-interface-address", identity)
        hub_local = _variable_name(source, "hub-tunnel-local-address", identity)
        hub_peer = _variable_name(source, "hub-tunnel-peer-address", identity)
        hub_ike_local = _variable_name(source, "hub-ike-local-address", identity)
        hub_ike_peer = _variable_name(source, "hub-ike-peer-address", identity)
        hub_psk = _variable_name(source, "hub-ike-pre-shared-key", identity)
        hub_psk_fingerprint = _variable_name(
            source, "hub-ike-psk-fingerprint", identity
        )
        hub_id = _variable_name(source, "hub-ike-identity", identity)
        hub_address = (
            plan.hub_gateway.external_ipv4
            or plan.hub_gateway.external_ipv6
            or plan.hub_gateway.address
        )
        hub_route_defs, hub_route_refs = _route_references(
            hub_template,
            source,
            identity,
            "hub",
            plan.hub_static_routes,
        )
        hub_owner: tuple[TemplateVariableDefinition, ...] = ()
        if source not in hub_owner_sources:
            owner = _definition(
                hub_template,
                owner_name,
                "fqdn",
                _ownership_value(source),
            )
            hub_owner = (owner,)
            ownership_markers.append(owner)
            hub_owner_sources.add(source)
        definitions.extend(
            (
                *hub_owner,
                _definition(
                    hub_template, hub_link, "ip-netmask", plan.hub_tunnel_address
                ),
                _definition(
                    hub_template,
                    hub_local,
                    "ip-netmask",
                    _host(plan.hub_tunnel_address),
                ),
                _definition(
                    hub_template,
                    hub_peer,
                    "ip-netmask",
                    _host(plan.spoke_tunnel_address),
                ),
                _definition(hub_template, hub_ike_local, "ip-netmask", hub_address),
                _definition(
                    hub_template, hub_ike_peer, "ip-netmask", plan.local_address
                ),
                _definition(
                    hub_template, hub_psk, "pre-shared-key", plan.pre_shared_key
                ),
                _definition(
                    hub_template,
                    hub_psk_fingerprint,
                    "fqdn",
                    _psk_fingerprint(plan.pre_shared_key),
                ),
                _definition(
                    hub_template, hub_id, "fqdn", f"spoke-{identity}.ptb.invalid"
                ),
                *hub_route_defs,
            )
        )
        hub_refs = EndpointVariableReferences(
            tunnel_interface_address=hub_link,
            tunnel_local=hub_local,
            tunnel_peer=hub_peer,
            ike_local=hub_ike_local,
            ike_peer=hub_ike_peer,
            pre_shared_key=hub_psk,
            ike_identity=hub_id,
            route_destinations=hub_route_refs,
        )
        apply_endpoint_variable_references(
            item.replacement.hub,
            hub_refs,
            plan.hub_tunnel_address,
            plan.spoke_tunnel_address,
        )
        psk_pairs.append(
            PskFingerprintPair(
                item.inventory.stack_name,
                item.inventory.serial,
                spoke_psk_fingerprint,
                hub_template,
                hub_psk_fingerprint,
            )
        )

        shape = tuple(
            ET.tostring(obj.element(), encoding="utf-8")
            for obj in (
                item.replacement.spoke.ike_gateway,
                item.replacement.spoke.ipsec_tunnel,
                item.replacement.spoke.tunnel_interface,
                item.replacement.spoke.routing_object,
                item.replacement.spoke.zone,
            )
        )
        prior = spoke_shapes.setdefault(source, shape)
        if prior != shape:
            raise LsvpnConfigurationError(
                f'Shared template "{spoke_template}" has structurally '
                f'incompatible LSVPN replacement plans for source "{source}". '
                f'Firewall "{item.inventory.firewall_name}" requires a separate '
                "template or migration group."
            )

    return CandidateVariableSet(
        tuple(definitions),
        tuple(overrides),
        tuple(psk_pairs),
        tuple(ownership_markers),
    )
