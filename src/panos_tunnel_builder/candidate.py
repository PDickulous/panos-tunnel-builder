import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import cast

from panos.base import PanObject
from panos.device import Vsys
from panos.errors import PanNoSuchNode
from panos.network import (
    Bgp,
    BgpPeer,
    BgpPeerGroup,
    IpsecTunnel,
    LogicalRouter,
    Ospf,
    OspfArea,
    OspfAreaInterface,
    StaticRoute,
    StaticRouteV6,
    TunnelInterface,
    VirtualRouter,
    Vrf,
    VrfBgpPeer,
    VrfBgpPeerGroup,
    VrfOspfArea,
    VrfOspfAreaInterface,
    VrfStaticRoute,
    VrfStaticRouteV6,
    Zone,
)
from panos.panorama import Panorama, Template

from .lsvpn import (
    DEFAULT_VSYS,
    HubTunnelInterfaceConfig,
    LsvpnConfigurationError,
    RoutingInstanceConfig,
    StandardIpsecClonePlan,
    StandardIpsecEndpointObjects,
    StandardIpsecReplacementObjects,
    normalize_endpoint,
)
from .management_profiles import (
    PING_ONLY,
    PingOnlyProfilePlan,
    apply_ping_only_profiles,
    verify_ping_only_profiles,
)
from .router_rename import SpokeRouterRename, apply_spoke_router_rename

TOOL_COMMENT_PREFIX = "Managed by panos-tunnel-builder; LSVPN source="
PANORAMA_METADATA_ATTRIBUTES = frozenset({"admin", "dirtyId", "time"})
RoutingScopeFingerprint = tuple[tuple[str, tuple[object, ...]], ...]


class CandidateLoadError(LsvpnConfigurationError):
    """Candidate loading failed, with automatic rollback status included."""

    lock_cleanup_error: str | None = None


class CandidateLoadInterrupted(CandidateLoadError):
    """Candidate loading was cancelled, with automatic rollback status included."""


class CandidateRestoreError(LsvpnConfigurationError):
    """Snapshot restore failed, including checkpoint recovery and lock status."""

    def __init__(self, message: str, *, interrupted: bool = False) -> None:
        super().__init__(message)
        self.interrupted = interrupted
        self.lock_cleanup_error: str | None = None


@dataclass(frozen=True)
class EndpointTemplatePlacement:
    vpn_template: str
    interface_template: str
    routing_template: str
    zone_template: str
    import_template: str | None = None


@dataclass(frozen=True)
class ReplacementTemplatePlacement:
    spoke: EndpointTemplatePlacement
    hub: EndpointTemplatePlacement
    satellite_template: str
    spoke_stack_templates: tuple[str, ...] = ()
    hub_stack_templates: tuple[str, ...] = ()


@dataclass(frozen=True)
class CandidateLoadResult:
    panorama_snapshot_name: str
    created_or_updated_objects: int
    removed_satellite_objects: int
    lock_cleanup_error: str | None = None


@dataclass(frozen=True)
class CandidateRestoreResult:
    snapshot_name: str
    checkpoint_name: str
    lock_cleanup_error: str | None = None


@dataclass
class _CandidateLocks:
    """Only successful acquisitions in this invocation authorize release."""

    configuration: bool = False
    commit: bool = False


@dataclass(frozen=True)
class TemplateVariableDefinition:
    template_name: str
    name: str
    variable_type: str
    value: str


@dataclass(frozen=True)
class DeviceVariableOverride:
    stack_name: str
    serial: str
    name: str
    variable_type: str
    value: str


@dataclass(frozen=True)
class PskFingerprintPair:
    spoke_stack_name: str
    spoke_serial: str
    spoke_fingerprint_name: str
    hub_template_name: str
    hub_fingerprint_name: str


@dataclass(frozen=True)
class CandidateVariableSet:
    definitions: tuple[TemplateVariableDefinition, ...] = ()
    overrides: tuple[DeviceVariableOverride, ...] = ()
    psk_fingerprint_pairs: tuple[PskFingerprintPair, ...] = ()
    ownership_markers: tuple[TemplateVariableDefinition, ...] = ()


def _xpath_literal(value: str) -> str:
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    values: list[str] = []
    for index, part in enumerate(parts):
        if part:
            values.append(f"'{part}'")
        if index < len(parts) - 1:
            values.append('"\'"')
    return f"concat({', '.join(values)})"


def _template_xpath(template_name: str) -> str:
    return (
        "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name="
        f"{_xpath_literal(template_name)}]"
    )


def _template_stack_xpath(stack_name: str) -> str:
    return (
        "/config/devices/entry[@name='localhost.localdomain']/template-stack/"
        f"entry[@name={_xpath_literal(stack_name)}]"
    )


def _variable_entry(name: str, variable_type: str, value: str) -> ET.Element:
    if not name.startswith("$") or not re.fullmatch(r"\$[A-Za-z0-9_.-]+", name):
        raise LsvpnConfigurationError(
            f'Template variable name "{name}" must start with $ and contain '
            "only letters, numbers, dot, underscore, or hyphen."
        )
    supported = {"ip-netmask", "fqdn", "pre-shared-key", "as-number"}
    if variable_type not in supported:
        raise LsvpnConfigurationError(
            f'Template variable "{name}" has unsupported type "{variable_type}".'
        )
    entry = ET.Element("entry", {"name": name})
    type_element = ET.SubElement(entry, "type")
    value_element = ET.SubElement(type_element, variable_type)
    if variable_type == "pre-shared-key":
        ET.SubElement(value_element, "key").text = value
    else:
        value_element.text = value
    return entry


def _variable_type(entry: ET.Element) -> str | None:
    type_element = entry.find("./type")
    if type_element is None or len(type_element) != 1:
        return None
    return type_element[0].tag


def _variable_value(entry: ET.Element) -> str | None:
    variable_type = _variable_type(entry)
    if variable_type is None or variable_type == "pre-shared-key":
        return None
    value = entry.findtext(f"./type/{variable_type}")
    return value.strip() if value and value.strip() else None


def _definition_xpath(definition: TemplateVariableDefinition) -> str:
    return (
        f"{_template_xpath(definition.template_name)}/variable/"
        f"entry[@name={_xpath_literal(definition.name)}]"
    )


def _override_xpath(override: DeviceVariableOverride) -> str:
    return (
        f"{_template_stack_xpath(override.stack_name)}/devices/"
        f"entry[@name={_xpath_literal(override.serial)}]/variable/"
        f"entry[@name={_xpath_literal(override.name)}]"
    )


def _preflight_variables(
    panorama: Panorama,
    variables: CandidateVariableSet,
) -> None:
    psk_presence: list[tuple[str, bool]] = []
    any_existing = False
    marker_keys = {
        (marker.template_name.casefold(), marker.name.casefold())
        for marker in variables.ownership_markers
    }
    seen_definitions: dict[tuple[str, str], TemplateVariableDefinition] = {}
    for definition in variables.definitions:
        key = (definition.template_name.casefold(), definition.name.casefold())
        previous = seen_definitions.get(key)
        if previous is not None and previous != definition:
            raise LsvpnConfigurationError(
                f'Template variable "{definition.name}" has conflicting '
                f'definitions for template "{definition.template_name}".'
            )
        seen_definitions[key] = definition
        xpath = _definition_xpath(definition)
        existing = _candidate_element(panorama, xpath)
        any_existing = any_existing or existing is not None
        if definition.variable_type == "pre-shared-key":
            psk_presence.append((xpath, existing is not None))
        if (
            existing is not None
            and _variable_type(existing) != definition.variable_type
        ):
            raise LsvpnConfigurationError(
                f'Candidate variable "{definition.name}" already exists in '
                f'template "{definition.template_name}" with a different type.'
            )

    seen_overrides: set[tuple[str, str, str]] = set()
    for override in variables.overrides:
        override_key = (
            override.stack_name.casefold(),
            override.serial.casefold(),
            override.name.casefold(),
        )
        if override_key in seen_overrides:
            raise LsvpnConfigurationError(
                f'Duplicate override for variable "{override.name}" on serial '
                f'"{override.serial}".'
            )
        seen_overrides.add(override_key)
        matching = [
            item
            for item in variables.definitions
            if item.name.casefold() == override.name.casefold()
            and item.variable_type == override.variable_type
        ]
        if not matching:
            raise LsvpnConfigurationError(
                f'Device override "{override.name}" has no matching variable '
                "definition in this migration."
            )
        xpath = _override_xpath(override)
        existing = _candidate_element(panorama, xpath)
        any_existing = any_existing or existing is not None
        if existing is not None and _variable_type(existing) != override.variable_type:
            raise LsvpnConfigurationError(
                f'Candidate override "{override.name}" already exists for serial '
                f'"{override.serial}" with a different type.'
            )
        if override.variable_type == "pre-shared-key":
            psk_presence.append((xpath, existing is not None))
    if (
        psk_presence
        and any(found for _, found in psk_presence)
        and not all(found for _, found in psk_presence)
        and not variables.ownership_markers
    ):
        missing = ", ".join(path for path, found in psk_presence if not found)
        raise LsvpnConfigurationError(
            "Existing tool PSK variables are incomplete, so preserving them "
            f"could create mismatched credentials. Missing: {missing}."
        )
    definition_keys = set(seen_definitions)
    if not marker_keys.issubset(definition_keys):
        raise LsvpnConfigurationError(
            "Candidate variable ownership markers must also be included as template "
            "variable definitions."
        )
    if any_existing:
        if not variables.ownership_markers:
            raise LsvpnConfigurationError(
                "Existing generated-name variables have no panos-tunnel-builder "
                "ownership marker, so they will not be overwritten."
            )
        for marker in variables.ownership_markers:
            existing_marker = _candidate_element(
                panorama,
                _definition_xpath(marker),
            )
            if (
                existing_marker is None
                or _variable_type(existing_marker) != marker.variable_type
                or _variable_value(existing_marker) != marker.value
            ):
                raise LsvpnConfigurationError(
                    "Existing generated-name variables cannot be claimed because "
                    f'ownership marker "{marker.name}" is missing or invalid in '
                    f'template "{marker.template_name}".'
                )
    # A rerun rotates every PSK on both endpoints in the same transaction. This
    # repairs manually changed or stale credentials instead of trusting encrypted
    # values that Panorama cannot expose for direct comparison.
    return None


def _write_variables(
    panorama: Panorama,
    variables: CandidateVariableSet,
) -> int:
    written = 0
    for definition in variables.definitions:
        xpath = f"{_template_xpath(definition.template_name)}/variable"
        panorama.xapi.set(
            xpath,
            ET.tostring(
                _variable_entry(
                    definition.name,
                    definition.variable_type,
                    definition.value,
                ),
                encoding="unicode",
            ),
        )
        written += 1
    for override in variables.overrides:
        xpath = (
            f"{_template_stack_xpath(override.stack_name)}/devices/"
            f"entry[@name={_xpath_literal(override.serial)}]/variable"
        )
        panorama.xapi.set(
            xpath,
            ET.tostring(
                _variable_entry(
                    override.name,
                    override.variable_type,
                    override.value,
                ),
                encoding="unicode",
            ),
        )
        written += 1
    return written


def _verify_variables(
    panorama: Panorama,
    variables: CandidateVariableSet,
) -> list[str]:
    issues: list[str] = []
    for definition in variables.definitions:
        xpath = _definition_xpath(definition)
        actual = _candidate_element(panorama, xpath)
        if actual is None:
            issues.append(f'missing template variable "{definition.name}"')
        elif _variable_type(actual) != definition.variable_type:
            issues.append(f'template variable "{definition.name}" has wrong type')
        elif (
            definition.variable_type != "pre-shared-key"
            and _variable_value(actual) != definition.value
        ):
            issues.append(f'template variable "{definition.name}" has wrong value')
    for override in variables.overrides:
        xpath = _override_xpath(override)
        actual = _candidate_element(panorama, xpath)
        if actual is None:
            issues.append(
                f'missing override "{override.name}" for serial "{override.serial}"'
            )
        elif _variable_type(actual) != override.variable_type:
            issues.append(
                f'override "{override.name}" for serial "{override.serial}" '
                "has wrong type"
            )
        elif (
            override.variable_type != "pre-shared-key"
            and _variable_value(actual) != override.value
        ):
            issues.append(
                f'override "{override.name}" for serial "{override.serial}" '
                "has wrong value"
            )
    return issues


def _read_active_template_config(
    panorama: Panorama,
    template_name: str,
) -> ET.Element:
    xpath = f"{_template_xpath(template_name)}/config"
    try:
        return cast(ET.Element, panorama.xapi.show(xpath))
    except PanNoSuchNode:
        return ET.Element("response")


def _raw_interface_addresses(entry: ET.Element) -> tuple[str, ...]:
    addresses: list[str] = []
    for path in (
        "./ip/entry",
        "./layer3/ip/entry",
        "./ipv6/address/entry",
        "./layer3/ipv6/address/entry",
    ):
        addresses.extend(
            name for address in entry.findall(path) if (name := address.get("name"))
        )
    return tuple(dict.fromkeys(addresses))


def resolve_template_interface_address_reference(
    panorama: Panorama,
    template_names: tuple[str, ...],
    interface_name: str,
    effective_address: str,
) -> str:
    """Return the raw template IP reference behind an effective interface IP."""
    references: list[tuple[str, str]] = []
    for template_name in template_names:
        root = _read_active_template_config(panorama, template_name)
        for entry in root.findall(".//network/interface//entry"):
            if entry.get("name", "").casefold() != interface_name.casefold():
                continue
            references.extend(
                (template_name, address) for address in _raw_interface_addresses(entry)
            )
    references = list(dict.fromkeys(references))
    direct = tuple(
        reference
        for _, reference in references
        if normalize_endpoint(reference) == normalize_endpoint(effective_address)
    )
    if direct:
        return direct[0]
    unique = tuple(dict.fromkeys(reference for _, reference in references))
    if len(unique) == 1:
        return unique[0]
    if not unique:
        raise LsvpnConfigurationError(
            f"No template in the assigned stack configures an address on IKE "
            f'interface "{interface_name}".'
        )
    display = ", ".join(
        f"{template_name}:{reference}" for template_name, reference in references
    )
    raise LsvpnConfigurationError(
        f'IKE interface "{interface_name}" has multiple template address '
        f'references and "{effective_address}" cannot be mapped uniquely: '
        f"{display}."
    )


def _unique_owner(
    configs: dict[str, ET.Element],
    description: str,
    predicate: Callable[[ET.Element], bool],
) -> str:
    matches = [name for name, root in configs.items() if predicate(root)]
    if not matches:
        raise LsvpnConfigurationError(
            f"No template in the assigned stack owns {description}."
        )
    if len(matches) > 1:
        raise LsvpnConfigurationError(
            f"Multiple templates own {description}: {', '.join(matches)}."
        )
    return matches[0]


def _owns_tunnel_interface(root: ET.Element, interface_name: str) -> bool:
    wanted = interface_name.casefold()
    return any(
        entry.get("name", "").casefold() == wanted
        for entry in root.findall(".//network/interface/tunnel/units/entry")
    )


def _owns_satellite(root: ET.Element, satellite_name: str) -> bool:
    wanted = satellite_name.casefold()
    return any(
        entry.get("name", "").casefold() == wanted
        and entry.find("./global-protect-satellite") is not None
        for entry in root.findall(".//network/tunnel/ipsec/entry")
    )


def _satellite_owner_predicate(
    satellite_name: str,
) -> Callable[[ET.Element], bool]:
    return lambda root: _owns_satellite(root, satellite_name)


def discover_lsvpn_satellite_template_owner(
    panorama: Panorama,
    template_names: tuple[str, ...],
    satellite_names: tuple[str, ...],
) -> str:
    """Return the single template that owns all selected LSVPN satellites."""
    if not satellite_names:
        raise LsvpnConfigurationError("No LSVPN satellite names were supplied.")
    configs = {
        name: _read_candidate_template_config(panorama, name) for name in template_names
    }
    owners = tuple(
        dict.fromkeys(
            _unique_owner(
                configs,
                f'LSVPN satellite "{satellite_name}"',
                _satellite_owner_predicate(satellite_name),
            )
            for satellite_name in satellite_names
        )
    )
    if len(owners) != 1:
        raise LsvpnConfigurationError(
            "The selected firewall's LSVPN satellite objects are owned by multiple "
            f"templates ({', '.join(owners)}). Migrate each ownership scope as a "
            "separate group."
        )
    return owners[0]


def _owns_routing(
    root: ET.Element,
    routing: RoutingInstanceConfig,
    interface_name: str,
) -> bool:
    if routing.kind == "virtual-router":
        entries = root.findall(".//network/virtual-router/entry")
    else:
        entries = root.findall(".//network/logical-router/entry")
    for entry in entries:
        if entry.get("name", "").casefold() != routing.name.casefold():
            continue
        scope = entry
        if routing.kind == "logical-router":
            scope = next(
                (
                    vrf
                    for vrf in entry.findall("./vrf/entry")
                    if routing.vrf
                    and vrf.get("name", "").casefold() == routing.vrf.casefold()
                ),
                ET.Element("empty"),
            )
        return any(
            member.text and member.text.strip().casefold() == interface_name.casefold()
            for member in scope.findall("./interface/member")
        )
    return False


def _owns_zone(root: ET.Element, zone_name: str, interface_name: str) -> bool:
    for entry in root.findall(".//vsys/entry/zone/entry"):
        if entry.get("name", "").casefold() != zone_name.casefold():
            continue
        return any(
            member.text and member.text.strip().casefold() == interface_name.casefold()
            for member in entry.findall("./network/layer3/member")
        )
    return False


def _owns_vsys_import(
    root: ET.Element,
    vsys: str,
    interface_name: str,
) -> bool:
    wanted = interface_name.casefold()
    for entry in root.findall(".//vsys/entry"):
        if entry.get("name", "").casefold() != vsys.casefold():
            continue
        return any(
            member.text and member.text.strip().casefold() == wanted
            for member in entry.findall("./import/network/interface/member")
        )
    return False


def _single_routing(source: HubTunnelInterfaceConfig) -> RoutingInstanceConfig:
    routing = source.routing_instances or tuple(
        RoutingInstanceConfig("virtual-router", name) for name in source.virtual_routers
    )
    if len(routing) != 1:
        raise LsvpnConfigurationError(
            f'Source interface "{source.name}" does not have one routing scope.'
        )
    return routing[0]


def _single_zone(source: HubTunnelInterfaceConfig) -> str:
    if len(source.zones) != 1:
        raise LsvpnConfigurationError(
            f'Source interface "{source.name}" does not have one security zone.'
        )
    return source.zones[0]


def _endpoint_placement(
    configs: dict[str, ET.Element],
    source: HubTunnelInterfaceConfig,
    endpoint: str,
    vpn_template: str | None = None,
    vsys: str = DEFAULT_VSYS,
) -> EndpointTemplatePlacement:
    routing = _single_routing(source)
    zone = _single_zone(source)
    interface_owner = _unique_owner(
        configs,
        f'{endpoint} tunnel interface "{source.name}"',
        lambda root: _owns_tunnel_interface(root, source.name),
    )
    routing_owner = _unique_owner(
        configs,
        f'{endpoint} routing membership for "{source.name}"',
        lambda root: _owns_routing(root, routing, source.name),
    )
    zone_owner = _unique_owner(
        configs,
        f'{endpoint} zone membership for "{source.name}"',
        lambda root: _owns_zone(root, zone, source.name),
    )
    import_owners = tuple(
        name
        for name, root in configs.items()
        if _owns_vsys_import(root, vsys, source.name)
    )
    if len(import_owners) > 1:
        raise LsvpnConfigurationError(
            f'Multiple templates import {endpoint} interface "{source.name}" '
            f"into {vsys}: {', '.join(import_owners)}."
        )
    return EndpointTemplatePlacement(
        vpn_template=vpn_template or interface_owner,
        interface_template=interface_owner,
        routing_template=routing_owner,
        zone_template=zone_owner,
        import_template=import_owners[0] if import_owners else interface_owner,
    )


def discover_replacement_template_placements(
    panorama: Panorama,
    spoke_template_names: tuple[str, ...],
    hub_template_names: tuple[str, ...],
    plans: tuple[StandardIpsecClonePlan, ...],
    spoke_vsys: str = DEFAULT_VSYS,
    hub_vsys: str = DEFAULT_VSYS,
) -> tuple[ReplacementTemplatePlacement, ...]:
    """Find the exact source-owning templates for every replacement object."""
    spoke_configs = {
        name: _read_candidate_template_config(panorama, name)
        for name in spoke_template_names
    }
    hub_configs = {
        name: _read_candidate_template_config(panorama, name)
        for name in hub_template_names
    }
    placements: list[ReplacementTemplatePlacement] = []
    for plan in plans:
        if plan.spoke_tunnel_source is None or plan.hub_gateway is None:
            raise LsvpnConfigurationError(
                f'Replacement tunnel "{plan.tunnel_name}" has incomplete placement '
                "source data."
            )
        satellite_owner = _unique_owner(
            spoke_configs,
            f'LSVPN satellite "{plan.source_name}"',
            _satellite_owner_predicate(plan.source_name),
        )
        placements.append(
            ReplacementTemplatePlacement(
                spoke=_endpoint_placement(
                    spoke_configs,
                    plan.spoke_tunnel_source,
                    "spoke",
                    satellite_owner,
                    spoke_vsys,
                ),
                hub=_endpoint_placement(
                    hub_configs,
                    plan.hub_gateway.tunnel_interface,
                    "hub",
                    vsys=hub_vsys,
                ),
                satellite_template=satellite_owner,
                spoke_stack_templates=spoke_template_names,
                hub_stack_templates=hub_template_names,
            )
        )
    return tuple(placements)


def _read_candidate_template_config(
    panorama: Panorama,
    template_name: str,
) -> ET.Element:
    xpath = f"{_template_xpath(template_name)}/config"
    try:
        return cast(ET.Element, panorama.xapi.get(xpath))
    except PanNoSuchNode:
        return ET.Element("response")


def _element_path(parent_path: str, element: ET.Element) -> str:
    name = element.get("name")
    component = element.tag + (
        f"[@name={_xpath_literal(name)}]" if name is not None else ""
    )
    return f"{parent_path}/{component}"


def _walk_elements(
    element: ET.Element,
    path: str = "",
) -> tuple[tuple[ET.Element, str], ...]:
    current = _element_path(path, element)
    result = [(element, current)]
    for child in element:
        result.extend(_walk_elements(child, current))
    return tuple(result)


def _known_spoke_reference(
    element: ET.Element,
    path: str,
    attribute: str | None,
    plan: StandardIpsecClonePlan,
    handled_static_routes: frozenset[str] = frozenset(),
) -> bool:
    old_interface = plan.spoke_tunnel_source.name if plan.spoke_tunnel_source else ""
    satellite_marker = (
        f"/network/tunnel/ipsec/entry[@name={_xpath_literal(plan.source_name)}]"
    )
    if satellite_marker in path:
        return True
    if attribute == "name" and "/network/interface/tunnel/units/entry" in path:
        return True
    if element.tag == "member" and path.endswith("/interface/member"):
        if "/virtual-router/" in path or "/logical-router/" in path:
            return True
    if element.tag == "member" and path.endswith("/network/layer3/member"):
        if "/zone/" in path:
            return True
    if element.tag == "member" and path.endswith("/import/network/interface/member"):
        return "/vsys/" in path
    if element.tag == "interface" and "/bgp/" in path:
        direct_peer_names = {peer.peer_name for peer in plan.spoke_dynamic_routing.bgp}
        return any(
            f"entry[@name={_xpath_literal(name)}]" in path for name in direct_peer_names
        )
    if element.tag == "interface" and "/static-route/" in path:
        return any(
            f"entry[@name={_xpath_literal(name)}]" in path
            for name in handled_static_routes
        )
    if attribute == "name" and "/ospf/" in path and "/area/" in path:
        return bool(plan.spoke_dynamic_routing.ospf) and old_interface in path
    return False


def audit_spoke_interface_dependencies(
    panorama: Panorama,
    plan: StandardIpsecClonePlan,
    placement: ReplacementTemplatePlacement,
) -> None:
    """Block removal when candidate config has an unhandled old-interface reference."""
    source = plan.spoke_tunnel_source
    if source is None:
        return
    templates = placement.spoke_stack_templates or tuple(
        dict.fromkeys(
            (
                placement.satellite_template,
                placement.spoke.vpn_template,
                placement.spoke.interface_template,
                placement.spoke.routing_template,
                placement.spoke.zone_template,
            )
        )
    )
    unexpected: list[str] = []
    for template_name in templates:
        root = _read_candidate_template_config(panorama, template_name)
        handled_static_routes = (
            frozenset(_spoke_replaced_static_route_names(root, plan))
            if template_name == placement.spoke.routing_template
            else frozenset()
        )
        for element, path in _walk_elements(root):
            if element.text and element.text.strip() == source.name:
                if not _known_spoke_reference(
                    element,
                    path,
                    None,
                    plan,
                    handled_static_routes,
                ):
                    unexpected.append(f"{template_name}:{path}")
            for attribute, value in element.attrib.items():
                if value == source.name and not _known_spoke_reference(
                    element,
                    path,
                    attribute,
                    plan,
                    handled_static_routes,
                ):
                    unexpected.append(f"{template_name}:{path}/@{attribute}")
    if unexpected:
        display = "; ".join(dict.fromkeys(unexpected))
        raise LsvpnConfigurationError(
            f'Old LSVPN interface "{source.name}" has unsupported candidate '
            f"configuration references: {display}."
        )


def save_pre_migration_snapshot(
    panorama: Panorama,
    spoke_name: str,
    captured_at: datetime | None = None,
    *,
    checkpoint: bool = False,
) -> str:
    """Save current candidate configuration as a clean baseline or checkpoint."""
    captured = captured_at or datetime.now(UTC)
    timestamp = captured.strftime("%y%m%d%H%M%S")
    identifier = hashlib.sha256(
        f"{spoke_name}\0{captured.isoformat()}".encode()
    ).hexdigest()[:5]
    label = "CHK" if checkpoint else "PRE"
    filename = f"LSVPN_{label}_{identifier}_{timestamp}.xml"
    if len(filename) > 32:
        raise LsvpnConfigurationError(
            "Generated Panorama snapshot name exceeds the 32-character limit."
        )
    command = ET.Element("save")
    config = ET.SubElement(command, "config")
    ET.SubElement(config, "to").text = filename
    panorama.op(cmd=ET.tostring(command, encoding="utf-8"), cmd_xml=False)
    return filename


def _validate_snapshot_name(filename: str) -> None:
    if len(filename) > 32 or not re.fullmatch(r"[A-Za-z0-9_.-]+\.xml", filename):
        raise LsvpnConfigurationError(
            "Panorama snapshot names may contain only letters, numbers, dot, "
            "underscore, and hyphen, must end in .xml, and can be at most "
            "32 characters."
        )


def load_panorama_snapshot(panorama: Panorama, filename: str) -> None:
    """Low-level snapshot load; callers own locking and recovery policy."""
    _validate_snapshot_name(filename)
    command = ET.Element("load")
    config = ET.SubElement(command, "config")
    ET.SubElement(config, "from").text = filename
    panorama.op(cmd=ET.tostring(command, encoding="utf-8"), cmd_xml=False)


def _restore_candidate_locked(
    panorama: Panorama,
    filename: str,
    on_checkpoint_saved: Callable[[str], None] | None,
) -> CandidateRestoreResult:
    try:
        checkpoint = save_pre_migration_snapshot(
            panorama, f"restore:{filename}", checkpoint=True
        )
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        raise CandidateRestoreError(
            "Cannot save the pre-restore checkpoint: "
            f"{type(exc).__name__}: {exc}. Candidate replacement was not attempted.",
            interrupted=isinstance(exc, (KeyboardInterrupt, SystemExit)),
        ) from exc
    try:
        if on_checkpoint_saved is not None:
            on_checkpoint_saved(checkpoint)
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        raise CandidateRestoreError(
            f'Pre-restore checkpoint "{checkpoint}" was saved, but restore '
            f"was not attempted: {type(exc).__name__}: {exc}.",
            interrupted=isinstance(exc, (KeyboardInterrupt, SystemExit)),
        ) from exc
    try:
        load_panorama_snapshot(panorama, filename)
    except (Exception, KeyboardInterrupt, SystemExit) as restore_error:
        interrupted = isinstance(restore_error, (KeyboardInterrupt, SystemExit))
        reason = (
            f'Restore of "{filename}" failed: '
            f"{type(restore_error).__name__}: {restore_error}. "
        )
        try:
            # Preserve pending work from before restore, rather than reverting
            # the whole candidate to running configuration.
            load_panorama_snapshot(panorama, checkpoint)
        except (Exception, KeyboardInterrupt, SystemExit) as recovery_error:
            raise CandidateRestoreError(
                reason + "Checkpoint recovery also failed: "
                f"{type(recovery_error).__name__}: {recovery_error}. "
                "Panorama candidate configuration may contain partial changes. "
                f'Pre-restore checkpoint "{checkpoint}" remains available for '
                "manual recovery. No commit or push was issued.",
                interrupted=interrupted
                or isinstance(recovery_error, (KeyboardInterrupt, SystemExit)),
            ) from restore_error
        raise CandidateRestoreError(
            reason + f'Pre-restore checkpoint "{checkpoint}" was reloaded into '
            "candidate configuration, preserving the candidate saved before "
            "restore, including pending changes. No commit or push was issued.",
            interrupted=interrupted,
        ) from restore_error
    return CandidateRestoreResult(filename, checkpoint)


def restore_candidate_configuration(
    panorama: Panorama,
    filename: str,
    *,
    on_checkpoint_saved: Callable[[str], None] | None = None,
) -> CandidateRestoreResult:
    """Replace the candidate under configuration/commit locks and checkpoint it."""
    _validate_snapshot_name(filename)
    locks = _CandidateLocks()
    protected = False
    try:
        _acquire_candidate_locks(
            panorama, locks, f"panos-tunnel-builder snapshot restore: {filename}"
        )
        protected = True
        result = _restore_candidate_locked(panorama, filename, on_checkpoint_saved)
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        cleanup_error = _release_candidate_locks(panorama, locks)
        if isinstance(exc, CandidateRestoreError):
            exc.lock_cleanup_error = cleanup_error
            raise
        error = CandidateRestoreError(
            (
                "Restore did not report a completed outcome: "
                f"{type(exc).__name__}: {exc}. Inspect candidate configuration and "
                "any reported pre-restore checkpoint before retrying."
                if protected
                else f"Candidate protection failed: {type(exc).__name__}: {exc}. "
                "Restore was not attempted; inspect Panorama jobs and lock "
                "ownership before retrying."
            ),
            interrupted=isinstance(exc, (KeyboardInterrupt, SystemExit)),
        )
        error.lock_cleanup_error = cleanup_error
        raise error from exc
    return replace(result, lock_cleanup_error=_release_candidate_locks(panorama, locks))


def rollback_candidate_configuration(panorama: Panorama) -> None:
    """Revert Panorama candidate changes to running config without a commit."""
    command = ET.Element("revert")
    ET.SubElement(command, "config")
    panorama.op(cmd=ET.tostring(command, encoding="utf-8"), cmd_xml=False)


def _template_parent(panorama: Panorama, name: str) -> Template:
    template = Template(name)
    panorama.add(template)
    return template


def _vsys_parent(panorama: Panorama, template_name: str, vsys: str) -> Vsys:
    template = _template_parent(panorama, template_name)
    template_vsys = Vsys(vsys)
    template.add(template_vsys)
    return template_vsys


def _interface_import_xpath(
    template_name: str,
    vsys: str,
    interface_name: str | None = None,
) -> str:
    base = (
        f"{_template_xpath(template_name)}/config/devices/"
        "entry[@name='localhost.localdomain']/vsys/"
        f"entry[@name={_xpath_literal(vsys)}]/import/network/interface"
    )
    if interface_name is None:
        return base
    return f"{base}/member[text()={_xpath_literal(interface_name)}]"


def _ensure_interface_import(
    panorama: Panorama,
    placement: EndpointTemplatePlacement,
    vsys: str,
    interface_name: str,
) -> None:
    template_name = placement.import_template or placement.interface_template
    member_xpath = _interface_import_xpath(template_name, vsys, interface_name)
    if _candidate_element(panorama, member_xpath) is None:
        member = ET.Element("member")
        member.text = interface_name
        panorama.xapi.set(
            _interface_import_xpath(template_name, vsys),
            ET.tostring(member, encoding="unicode"),
        )


def _candidate_element(panorama: Panorama, xpath: str) -> ET.Element | None:
    try:
        response = cast(ET.Element, panorama.xapi.get(xpath))
    except PanNoSuchNode:
        return None
    result = response.find("./result")
    if result is None or not list(result):
        return None
    final_component = xpath.rsplit("/", 1)[-1]
    tag_match = re.match(r"([A-Za-z0-9_.-]+)", final_component)
    target_tag = tag_match.group(1) if tag_match else None
    name_match = re.search(
        r"\[@name=(?:'([^']*)'|\"([^\"]*)\")\]$",
        final_component,
    )
    target_name = (
        next((value for value in name_match.groups() if value is not None), None)
        if name_match
        else None
    )
    if target_tag is not None:
        for element in result.iter(target_tag):
            if target_name is None or element.get("name") == target_name:
                return element
    return list(result)[0]


def _delete_if_present(panorama: Panorama, xpath: str) -> bool:
    if _candidate_element(panorama, xpath) is None:
        return False
    panorama.xapi.delete(xpath)
    return True


def _prepare_endpoint_parents(
    panorama: Panorama,
    endpoint: StandardIpsecEndpointObjects,
    placement: EndpointTemplatePlacement,
    vsys: str,
) -> None:
    vpn_template = _template_parent(panorama, placement.vpn_template)
    interface_template = _template_parent(panorama, placement.interface_template)
    routing_template = _template_parent(panorama, placement.routing_template)
    zone_vsys = _vsys_parent(panorama, placement.zone_template, vsys)
    for item in (
        endpoint.ike_crypto_profile,
        endpoint.ipsec_crypto_profile,
        endpoint.ike_gateway,
        endpoint.ipsec_tunnel,
    ):
        vpn_template.add(item)
    interface_template.add(endpoint.tunnel_interface)
    routing_template.add(endpoint.routing_object)
    zone_vsys.add(endpoint.zone)


def _marker(source_name: str) -> str:
    return f"{TOOL_COMMENT_PREFIX}{source_name}"


def _canonical_xml(element: ET.Element) -> tuple[object, ...]:
    return (
        element.tag,
        tuple(
            sorted(
                (name, value)
                for name, value in element.attrib.items()
                if name not in PANORAMA_METADATA_ATTRIBUTES
            )
        ),
        (element.text or "").strip(),
        tuple(_canonical_xml(child) for child in element),
    )


def _response_config(response: ET.Element) -> ET.Element | None:
    if response.tag == "config":
        return response
    direct = response.find("./result/config")
    return direct if direct is not None else response.find(".//config")


@dataclass(frozen=True)
class SourceConfigurationFingerprint:
    """In-memory source evidence captured before discovery, without raw secrets."""

    serial: str | None
    candidate: str
    running: str
    effective_running: str | None = None


def _source_config_digest(response: object, label: str) -> str:
    if (
        not isinstance(response, ET.Element)
        or response.tag not in {"response", "config"}
        or (response.tag == "response" and response.get("status") != "success")
    ):
        raise LsvpnConfigurationError(
            f"Cannot verify {label}: configuration response was not successful."
        )
    # Accept only the expected full-config envelope, not a nested partial tree.
    config = response if response.tag == "config" else response.find("./result/config")
    if config is None or not len(config):
        raise LsvpnConfigurationError(
            f"Cannot verify {label}: full configuration was not returned."
        )
    return hashlib.sha256(repr(_canonical_xml(config)).encode()).hexdigest()


def capture_source_configuration(
    panorama: Panorama, serial: str | None = None
) -> SourceConfigurationFingerprint:
    """Fingerprint full configuration before reading any plan inputs from it."""
    label = f"firewall {serial}" if serial else "Panorama"
    options = {"extra_qs": {"target": serial}} if serial else {}
    candidate = _source_config_digest(
        panorama.xapi.get("/config", **options), f"{label} candidate"
    )
    running = _source_config_digest(
        panorama.xapi.show("/config", **options), f"{label} running"
    )
    effective = None
    if serial:
        effective = _source_config_digest(
            panorama.op(
                cmd=b"<show><config><effective-running /></config></show>",
                cmd_xml=False,
                extra_qs={"target": serial},
            ),
            f"{label} effective running",
        )
    return SourceConfigurationFingerprint(serial, candidate, running, effective)


def assert_source_configuration_unchanged(
    panorama: Panorama,
    expected: tuple[SourceConfigurationFingerprint, ...],
) -> None:
    """Check the reviewed source under both locks, before snapshot or mutation."""
    if not expected or expected[0].serial is not None:
        raise LsvpnConfigurationError(
            "A pre-discovery Panorama source fingerprint is required for loading."
        )
    for source in expected:
        if capture_source_configuration(panorama, source.serial) != source:
            label = f"firewall {source.serial}" if source.serial else "Panorama"
            raise LsvpnConfigurationError(
                f"Source configuration changed on {label} since discovery. "
                "Candidate loading was not attempted; rebuild and review a fresh "
                "plan and route baselines before retrying."
            )


def assert_clean_candidate_configuration(panorama: Panorama) -> None:
    """Refuse a transaction whose global rollback could erase pending work."""
    candidate_response = cast(ET.Element, panorama.xapi.get("/config"))
    running_response = cast(ET.Element, panorama.xapi.show("/config"))
    candidate_config = _response_config(candidate_response)
    running_config = _response_config(running_response)
    if candidate_config is None or running_config is None:
        raise LsvpnConfigurationError(
            "Panorama did not return both candidate and running configuration, so "
            "candidate cleanliness could not be verified."
        )
    if _canonical_xml(candidate_config) != _canonical_xml(running_config):
        raise LsvpnConfigurationError(
            "Panorama has pending candidate changes. Loading is blocked because an "
            "automatic rollback would discard all pending changes. Commit, revert, "
            "or explicitly allow a dirty candidate before retrying."
        )


def _remove_children(parent: ET.Element, children: list[ET.Element]) -> None:
    for child in children:
        parent.remove(child)


def _normalized_routing_scope(
    root: ET.Element,
    mutable_interfaces: frozenset[str],
    mutable_route_names: frozenset[str] = frozenset(),
) -> ET.Element:
    """Remove only routing nodes expected to change during tunnel replacement."""
    normalized = ET.Element("routing")
    interfaces = {name.casefold() for name in mutable_interfaces}
    route_names = {name.casefold() for name in mutable_route_names}
    for tag in ("virtual-router", "logical-router"):
        for section in root.findall(f".//network/{tag}"):
            normalized.append(deepcopy(section))

    for element in normalized.iter():
        for attribute in PANORAMA_METADATA_ATTRIBUTES:
            element.attrib.pop(attribute, None)

    for parent in normalized.findall(".//interface"):
        _remove_children(
            parent,
            [
                member
                for member in parent.findall("./member")
                if (member.text or "").strip().casefold() in interfaces
            ],
        )

    for container in normalized.findall(".//static-route"):
        _remove_children(
            container,
            [
                entry
                for entry in container.findall("./entry")
                if (
                    any(
                        (value.text or "").strip().casefold() in interfaces
                        for value in entry.findall(".//interface")
                    )
                    or entry.get("name", "").casefold() in route_names
                )
            ],
        )

    for peer_container in normalized.findall(".//peer-group/entry/peer"):
        _remove_children(
            peer_container,
            [
                peer
                for peer in peer_container.findall("./entry")
                if any(
                    (value.text or "").strip().casefold() in interfaces
                    for value in peer.findall("./local-address/interface")
                )
            ],
        )

    for area in normalized.findall(".//ospf/area/entry"):
        interface_container = area.find("./interface")
        if interface_container is None:
            continue
        _remove_children(
            interface_container,
            [
                entry
                for entry in interface_container.findall("./entry")
                if entry.get("name", "").casefold() in interfaces
            ],
        )
    for parent in reversed(list(normalized.iter())):
        for child in list(parent):
            if (
                child.tag in {"static-route", "ip", "ipv6", "routing-table"}
                and not list(child)
                and not child.attrib
                and not (child.text or "").strip()
            ):
                parent.remove(child)
    return normalized


def _routing_scope_fingerprint(
    panorama: Panorama,
    mutable_interfaces: dict[str, frozenset[str]],
    mutable_route_names: dict[str, frozenset[str]] | None = None,
) -> RoutingScopeFingerprint:
    values: list[tuple[str, tuple[object, ...]]] = []
    for template_name in sorted(mutable_interfaces, key=str.casefold):
        root = _read_candidate_template_config(panorama, template_name)
        normalized = _normalized_routing_scope(
            root,
            mutable_interfaces[template_name],
            (mutable_route_names or {}).get(template_name, frozenset()),
        )
        values.append((template_name, _canonical_xml(normalized)))
    return tuple(values)


def _routing_mutable_interfaces(
    plans: tuple[StandardIpsecClonePlan, ...],
    replacements: tuple[StandardIpsecReplacementObjects, ...],
    placements: tuple[ReplacementTemplatePlacement, ...],
) -> dict[str, frozenset[str]]:
    values: dict[str, set[str]] = {}
    for plan, replacement, placement in zip(
        plans, replacements, placements, strict=True
    ):
        spoke = values.setdefault(placement.spoke.routing_template, set())
        spoke.add(str(replacement.spoke.tunnel_interface.name))
        if plan.spoke_tunnel_source is not None:
            spoke.add(plan.spoke_tunnel_source.name)
        values.setdefault(placement.hub.routing_template, set()).add(
            str(replacement.hub.tunnel_interface.name)
        )
    return {name: frozenset(interfaces) for name, interfaces in values.items()}


def _routing_mutable_route_names(
    panorama: Panorama,
    plans: tuple[StandardIpsecClonePlan, ...],
    placements: tuple[ReplacementTemplatePlacement, ...],
) -> dict[str, frozenset[str]]:
    values: dict[str, set[str]] = {}
    for plan, placement in zip(plans, placements, strict=True):
        spoke_root = _read_candidate_template_config(
            panorama, placement.spoke.routing_template
        )
        values.setdefault(placement.spoke.routing_template, set()).update(
            name for name, _ in _spoke_replaced_static_route_specs(spoke_root, plan)
        )
        if plan.hub_gateway is not None:
            hub_root = _read_candidate_template_config(
                panorama, placement.hub.routing_template
            )
            values.setdefault(placement.hub.routing_template, set()).update(
                name
                for name, _ in _replaced_static_route_specs(
                    hub_root,
                    plan.hub_gateway.tunnel_interface,
                    plan.hub_static_routes,
                )
            )
    return {name: frozenset(route_names) for name, route_names in values.items()}


def _preflight_endpoint(
    panorama: Panorama,
    endpoint: StandardIpsecEndpointObjects,
    source_name: str,
) -> bool:
    existing_interface = _candidate_element(panorama, endpoint.tunnel_interface.xpath())
    owned = False
    if existing_interface is not None:
        comment = existing_interface.findtext("comment") or ""
        owned = comment == _marker(source_name)
        if not owned:
            raise LsvpnConfigurationError(
                f'Candidate object "{endpoint.tunnel_interface.name}" already '
                "exists and is not owned by panos-tunnel-builder."
            )
    for item in (endpoint.ike_gateway, endpoint.ipsec_tunnel):
        if _candidate_element(panorama, item.xpath()) is not None and not owned:
            raise LsvpnConfigurationError(
                f'Candidate object "{item.name}" already exists and is not owned '
                "by panos-tunnel-builder."
            )
    for profile in (endpoint.ike_crypto_profile, endpoint.ipsec_crypto_profile):
        existing_profile = _candidate_element(panorama, profile.xpath())
        if existing_profile is not None and _canonical_xml(
            existing_profile
        ) != _canonical_xml(profile.element()):
            raise LsvpnConfigurationError(
                f'Candidate crypto profile "{profile.name}" already exists with '
                "different settings."
            )
    return owned


def _write_endpoint(
    panorama: Panorama,
    endpoint: StandardIpsecEndpointObjects,
    source_name: str,
    owned: bool,
) -> int:
    endpoint.tunnel_interface.comment = _marker(source_name)
    for profile in (endpoint.ike_crypto_profile, endpoint.ipsec_crypto_profile):
        profile.create()
    if owned:
        endpoint.tunnel_interface.apply()
    else:
        endpoint.tunnel_interface.create()
    for item in (endpoint.ike_gateway, endpoint.ipsec_tunnel):
        if _candidate_element(panorama, item.xpath()) is None:
            item.create()
        else:
            item.apply()
    _write_routing_additions(panorama, endpoint.routing_object)
    endpoint.zone.create()
    return 7


def _ensure_routing_interface_member(
    panorama: Panorama,
    parent: VirtualRouter | Vrf,
    interface_name: str,
) -> None:
    member_xpath = (
        f"{parent.xpath()}/interface/member[text()={_xpath_literal(interface_name)}]"
    )
    if _candidate_element(panorama, member_xpath) is None:
        member = ET.Element("member")
        member.text = interface_name
        panorama.xapi.set(
            f"{parent.xpath()}/interface",
            ET.tostring(member, encoding="unicode"),
        )


def _create_or_apply(item: PanObject, panorama: Panorama) -> None:
    if _candidate_element(panorama, item.xpath()) is None:
        item.create()
    else:
        item.apply()


def _write_group_children(
    panorama: Panorama,
    group: BgpPeerGroup | VrfBgpPeerGroup | OspfArea | VrfOspfArea,
    child_type: type[BgpPeer]
    | type[VrfBgpPeer]
    | type[OspfAreaInterface]
    | type[VrfOspfAreaInterface],
) -> None:
    if _candidate_element(panorama, group.xpath()) is None:
        group.create()
        return
    for child in group.findall(child_type):
        _create_or_apply(child, panorama)


def _write_routing_additions(
    panorama: Panorama,
    routing: VirtualRouter | LogicalRouter,
) -> None:
    """Write only replacement leaves, preserving existing routing protocol roots."""
    if isinstance(routing, VirtualRouter):
        for interface_name in routing.interface or []:
            _ensure_routing_interface_member(panorama, routing, interface_name)
        for child in routing.children:
            if isinstance(child, (StaticRoute, StaticRouteV6)):
                _create_or_apply(child, panorama)
            elif isinstance(child, Bgp):
                for group in child.findall(BgpPeerGroup):
                    _write_group_children(panorama, group, BgpPeer)
            elif isinstance(child, Ospf):
                for area in child.findall(OspfArea):
                    _write_group_children(panorama, area, OspfAreaInterface)
        return

    for vrf in routing.findall(Vrf):
        for interface_name in vrf.interface or []:
            _ensure_routing_interface_member(panorama, vrf, interface_name)
        for child in vrf.children:
            if isinstance(child, (VrfStaticRoute, VrfStaticRouteV6)):
                _create_or_apply(child, panorama)
            elif isinstance(child, VrfBgpPeerGroup):
                _write_group_children(panorama, child, VrfBgpPeer)
            elif isinstance(child, VrfOspfArea):
                _write_group_children(panorama, child, VrfOspfAreaInterface)


def _routing_verification_objects(
    routing: VirtualRouter | LogicalRouter,
) -> tuple[PanObject, ...]:
    """Return only leaves intentionally added to an existing routing instance."""
    result: list[PanObject] = []
    containers: list[PanObject]
    if isinstance(routing, VirtualRouter):
        containers = list(routing.children)
    else:
        containers = [child for vrf in routing.findall(Vrf) for child in vrf.children]
    for child in containers:
        if isinstance(
            child,
            (StaticRoute, StaticRouteV6, VrfStaticRoute, VrfStaticRouteV6),
        ):
            result.append(child)
        elif isinstance(child, Bgp):
            result.extend(
                peer
                for group in child.findall(BgpPeerGroup)
                for peer in group.findall(BgpPeer)
            )
        elif isinstance(child, Ospf):
            result.extend(
                interface
                for area in child.findall(OspfArea)
                for interface in area.findall(OspfAreaInterface)
            )
        elif isinstance(child, VrfBgpPeerGroup):
            result.extend(child.findall(VrfBgpPeer))
        elif isinstance(child, VrfOspfArea):
            result.extend(child.findall(VrfOspfAreaInterface))
    return tuple(result)


def _source_routing_parent(
    panorama: Panorama,
    template_name: str,
    routing: RoutingInstanceConfig,
) -> VirtualRouter | Vrf:
    template = _template_parent(panorama, template_name)
    if routing.kind == "virtual-router":
        router = VirtualRouter(routing.name)
        template.add(router)
        return router
    if routing.vrf is None:
        raise LsvpnConfigurationError(
            f'Logical router "{routing.name}" has no source VRF.'
        )
    router = LogicalRouter(routing.name)
    template.add(router)
    vrf = Vrf(routing.vrf)
    router.add(vrf)
    return vrf


def _normalized_route_destination(value: str) -> str | None:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def _spoke_replaced_static_route_names(
    root: ET.Element,
    plan: StandardIpsecClonePlan,
) -> tuple[str, ...]:
    return tuple(name for name, _ in _spoke_replaced_static_route_specs(root, plan))


def _spoke_replaced_static_route_specs(
    root: ET.Element,
    plan: StandardIpsecClonePlan,
) -> tuple[tuple[str, int], ...]:
    source = plan.spoke_tunnel_source
    if source is None:
        return ()
    return _replaced_static_route_specs(root, source, plan.spoke_static_routes)


def _replaced_static_route_specs(
    root: ET.Element,
    source: HubTunnelInterfaceConfig,
    replacement_routes: tuple[str, ...],
) -> tuple[tuple[str, int], ...]:
    """Find old-interface routes recreated by destination on the new tunnel."""
    routing = _single_routing(source)
    router_path = (
        ".//network/virtual-router/entry"
        if routing.kind == "virtual-router"
        else ".//network/logical-router/entry"
    )
    router = next(
        (
            entry
            for entry in root.findall(router_path)
            if entry.get("name", "").casefold() == routing.name.casefold()
        ),
        None,
    )
    if router is None:
        return ()
    scope: ET.Element | None = router
    if routing.kind == "logical-router":
        scope = next(
            (
                entry
                for entry in router.findall("./vrf/entry")
                if entry.get("name", "").casefold() == (routing.vrf or "").casefold()
            ),
            None,
        )
    if scope is None:
        return ()
    replacement_destinations = {
        normalized
        for destination in replacement_routes
        if (normalized := _normalized_route_destination(destination)) is not None
    }
    specs: list[tuple[str, int]] = []
    for version, path in (
        (4, "./routing-table/ip/static-route/entry"),
        (6, "./routing-table/ipv6/static-route/entry"),
    ):
        for entry in scope.findall(path):
            name = entry.get("name")
            destination = _normalized_route_destination(
                entry.findtext("destination", default="")
            )
            interface = (entry.findtext("interface") or "").strip()
            if (
                name
                and interface == source.name
                and destination in replacement_destinations
            ):
                specs.append((name, version))
    return tuple(specs)


def _spoke_replaced_static_route_paths(
    panorama: Panorama,
    plan: StandardIpsecClonePlan,
    placement: ReplacementTemplatePlacement,
) -> tuple[str, ...]:
    root = _read_candidate_template_config(
        panorama,
        placement.spoke.routing_template,
    )
    specs = _spoke_replaced_static_route_specs(root, plan)
    if not specs or plan.spoke_tunnel_source is None:
        return ()
    routing = _single_routing(plan.spoke_tunnel_source)
    parent = _source_routing_parent(
        panorama,
        placement.spoke.routing_template,
        routing,
    )
    paths: list[str] = []
    for name, version in specs:
        route: StaticRoute | StaticRouteV6 | VrfStaticRoute | VrfStaticRouteV6
        if isinstance(parent, VirtualRouter):
            route = StaticRoute(name) if version == 4 else StaticRouteV6(name)
        else:
            route = VrfStaticRoute(name) if version == 4 else VrfStaticRouteV6(name)
        parent.add(route)
        paths.append(route.xpath())
    return tuple(paths)


def _hub_replaced_static_route_paths(
    panorama: Panorama,
    plan: StandardIpsecClonePlan,
    placement: ReplacementTemplatePlacement,
) -> tuple[str, ...]:
    hub = plan.hub_gateway
    if hub is None:
        return ()
    root = _read_candidate_template_config(
        panorama,
        placement.hub.routing_template,
    )
    specs = _replaced_static_route_specs(
        root,
        hub.tunnel_interface,
        plan.hub_static_routes,
    )
    if not specs:
        return ()
    routing = _single_routing(hub.tunnel_interface)
    parent = _source_routing_parent(
        panorama,
        placement.hub.routing_template,
        routing,
    )
    paths: list[str] = []
    for name, version in specs:
        route: StaticRoute | StaticRouteV6 | VrfStaticRoute | VrfStaticRouteV6
        if isinstance(parent, VirtualRouter):
            route = StaticRoute(name) if version == 4 else StaticRouteV6(name)
        else:
            route = VrfStaticRoute(name) if version == 4 else VrfStaticRouteV6(name)
        parent.add(route)
        paths.append(route.xpath())
    return tuple(paths)


def _spoke_dynamic_routing_paths(
    panorama: Panorama,
    plan: StandardIpsecClonePlan,
    placement: ReplacementTemplatePlacement,
) -> tuple[str, ...]:
    source = plan.spoke_tunnel_source
    if source is None:
        return ()
    routing = _single_routing(source)
    parent = _source_routing_parent(
        panorama,
        placement.spoke.routing_template,
        routing,
    )
    paths: list[str] = []
    for peer in plan.spoke_dynamic_routing.bgp:
        if isinstance(parent, VirtualRouter):
            bgp = Bgp()
            parent.add(bgp)
            group = BgpPeerGroup(peer.peer_group_name)
            bgp.add(group)
            old_peer: BgpPeer | VrfBgpPeer = BgpPeer(peer.peer_name)
            group.add(old_peer)
        else:
            group = VrfBgpPeerGroup(peer.peer_group_name)
            parent.add(group)
            old_peer = VrfBgpPeer(peer.peer_name)
            group.add(old_peer)
        paths.append(old_peer.xpath())
    for ospf in plan.spoke_dynamic_routing.ospf:
        if isinstance(parent, VirtualRouter):
            protocol = Ospf()
            parent.add(protocol)
            area = OspfArea(ospf.area_name)
            protocol.add(area)
            old_interface: OspfAreaInterface | VrfOspfAreaInterface = OspfAreaInterface(
                source.name
            )
            area.add(old_interface)
        else:
            vrf_area = VrfOspfArea(ospf.area_name)
            parent.add(vrf_area)
            old_interface = VrfOspfAreaInterface(source.name)
            vrf_area.add(old_interface)
        paths.append(old_interface.xpath())
    return tuple(paths)


def _spoke_cleanup_paths(
    panorama: Panorama,
    plan: StandardIpsecClonePlan,
    placement: ReplacementTemplatePlacement,
    vsys: str,
) -> tuple[str, ...]:
    source = plan.spoke_tunnel_source
    if source is None:
        return ()
    paths = list(_spoke_dynamic_routing_paths(panorama, plan, placement))
    paths.extend(_spoke_replaced_static_route_paths(panorama, plan, placement))
    routing = _single_routing(source)
    routing_parent = _source_routing_parent(
        panorama,
        placement.spoke.routing_template,
        routing,
    )
    routing_member_xpath = (
        f"{routing_parent.xpath()}/interface/member"
        f"[text()={_xpath_literal(source.name)}]"
    )
    paths.append(routing_member_xpath)

    zone = Zone(_single_zone(source))
    _vsys_parent(panorama, placement.spoke.zone_template, vsys).add(zone)
    zone_member_xpath = (
        f"{zone.xpath()}/network/layer3/member[text()={_xpath_literal(source.name)}]"
    )
    paths.append(zone_member_xpath)

    import_template = (
        placement.spoke.import_template or placement.spoke.interface_template
    )
    paths.append(_interface_import_xpath(import_template, vsys, source.name))

    satellite = IpsecTunnel(plan.source_name)
    _template_parent(panorama, placement.satellite_template).add(satellite)
    paths.append(satellite.xpath())

    old_interface = TunnelInterface(source.name)
    _template_parent(panorama, placement.spoke.interface_template).add(old_interface)
    paths.append(old_interface.xpath())
    return tuple(paths)


def _remove_spoke_lsvpn(
    panorama: Panorama,
    plan: StandardIpsecClonePlan,
    placement: ReplacementTemplatePlacement,
    vsys: str,
) -> int:
    return sum(
        int(_delete_if_present(panorama, xpath))
        for xpath in _spoke_cleanup_paths(
            panorama,
            plan,
            placement,
            vsys,
        )
    )


def _remove_replaced_hub_static_routes(
    panorama: Panorama,
    plan: StandardIpsecClonePlan,
    placement: ReplacementTemplatePlacement,
) -> tuple[str, ...]:
    paths = _hub_replaced_static_route_paths(panorama, plan, placement)
    for xpath in paths:
        _delete_if_present(panorama, xpath)
    return paths


def _hub_lsvpn_fingerprint(
    panorama: Panorama,
    placements: tuple[ReplacementTemplatePlacement, ...],
) -> tuple[tuple[str, tuple[object, ...]], ...]:
    template_names = tuple(
        dict.fromkeys(
            name
            for placement in placements
            for name in (
                placement.hub_stack_templates
                or (
                    placement.hub.vpn_template,
                    placement.hub.interface_template,
                    placement.hub.routing_template,
                    placement.hub.zone_template,
                )
            )
        )
    )
    values: list[tuple[str, tuple[object, ...]]] = []
    for template_name in template_names:
        root = _read_candidate_template_config(panorama, template_name)
        for element in root.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag in {"global-protect", "global-protect-site-to-site"}:
                values.append((template_name, _canonical_xml(element)))
    return tuple(values)


def _leaf_signatures(
    element: ET.Element,
    path: str = "",
) -> Counter[tuple[str, str, tuple[tuple[str, str], ...]]]:
    current = f"{path}/{element.tag}"
    signatures: Counter[tuple[str, str, tuple[tuple[str, str], ...]]] = Counter()
    if not list(element):
        attributes = tuple(
            sorted(
                (name, value)
                for name, value in element.attrib.items()
                if name not in PANORAMA_METADATA_ATTRIBUTES
                and not (path == "" and name == "name")
            )
        )
        signatures[(current, (element.text or "").strip(), attributes)] += 1
    for child in element:
        signatures.update(_leaf_signatures(child, current))
    return signatures


def _verify_object_subset(
    panorama: Panorama,
    item: PanObject,
    description: str,
    issues: list[str],
) -> None:
    actual = _candidate_element(panorama, item.xpath())
    if actual is None:
        issues.append(f"missing {description} at {item.xpath()}")
        return
    expected_signatures = _leaf_signatures(item.element())
    actual_signatures = _leaf_signatures(actual)
    for signature, count in expected_signatures.items():
        path, value, attributes = signature
        if path.endswith("/key"):
            if not any(
                candidate_path == path and candidate_value
                for candidate_path, candidate_value, _ in actual_signatures
            ):
                issues.append(f"{description} has no saved pre-shared key")
            continue
        if actual_signatures[signature] < count:
            issues.append(
                f"{description} differs at {path}: expected {value!r} "
                f"with attributes {dict(attributes)!r}"
            )


def _object_tree(root: PanObject) -> tuple[PanObject, ...]:
    result = [root]
    for child in root.children:
        result.extend(_object_tree(child))
    return tuple(result)


def verify_candidate_configuration(
    panorama: Panorama,
    plans: tuple[StandardIpsecClonePlan, ...],
    replacements: tuple[StandardIpsecReplacementObjects, ...],
    placements: tuple[ReplacementTemplatePlacement, ...],
    hub_lsvpn_before: tuple[tuple[str, tuple[object, ...]], ...],
    spoke_vsys: str = DEFAULT_VSYS,
    hub_vsys: str = DEFAULT_VSYS,
    routing_scope_before: RoutingScopeFingerprint | None = None,
    routing_mutable_interfaces: dict[str, frozenset[str]] | None = None,
    routing_mutable_route_names: dict[str, frozenset[str]] | None = None,
    removed_legacy_route_paths: tuple[str, ...] = (),
    variables: CandidateVariableSet | None = None,
) -> None:
    """Reread candidate config and enforce replacement and cleanup invariants."""
    issues: list[str] = []
    if variables is not None:
        issues.extend(_verify_variables(panorama, variables))
    for plan, replacement, placement in zip(
        plans, replacements, placements, strict=True
    ):
        for role, endpoint in (
            ("spoke", replacement.spoke),
            ("hub", replacement.hub),
        ):
            objects = (
                endpoint.ike_crypto_profile,
                endpoint.ipsec_crypto_profile,
                endpoint.ike_gateway,
                endpoint.ipsec_tunnel,
                endpoint.tunnel_interface,
                *_routing_verification_objects(endpoint.routing_object),
                endpoint.zone,
            )
            seen: set[str] = set()
            for item in objects:
                xpath = item.xpath()
                if xpath in seen:
                    continue
                seen.add(xpath)
                _verify_object_subset(
                    panorama,
                    item,
                    f'{role} {type(item).__name__} "{getattr(item, "name", "")}"',
                    issues,
                )
            routing_parent: VirtualRouter | Vrf
            if isinstance(endpoint.routing_object, VirtualRouter):
                routing_parent = endpoint.routing_object
            else:
                routing_parent = endpoint.routing_object.findall(Vrf)[0]
            for interface_name in routing_parent.interface or []:
                member_xpath = (
                    f"{routing_parent.xpath()}/interface/member"
                    f"[text()={_xpath_literal(interface_name)}]"
                )
                if _candidate_element(panorama, member_xpath) is None:
                    issues.append(
                        f"{role} routing instance is missing interface "
                        f'"{interface_name}"'
                    )
        for role, endpoint, endpoint_placement, endpoint_vsys in (
            ("spoke", replacement.spoke, placement.spoke, spoke_vsys),
            ("hub", replacement.hub, placement.hub, hub_vsys),
        ):
            import_template = (
                endpoint_placement.import_template
                or endpoint_placement.interface_template
            )
            import_xpath = _interface_import_xpath(
                import_template,
                endpoint_vsys,
                str(endpoint.tunnel_interface.name),
            )
            if _candidate_element(panorama, import_xpath) is None:
                issues.append(
                    f'{role} tunnel interface "{endpoint.tunnel_interface.name}" '
                    f"is not imported into {endpoint_vsys}"
                )
        for old_xpath in _spoke_cleanup_paths(
            panorama,
            plan,
            placement,
            spoke_vsys,
        ):
            if _candidate_element(panorama, old_xpath) is not None:
                issues.append(f"old spoke LSVPN reference remains at {old_xpath}")

    hub_lsvpn_after = _hub_lsvpn_fingerprint(panorama, placements)
    if hub_lsvpn_after != hub_lsvpn_before:
        issues.append("hub LSVPN portal, gateway, or site-to-site config changed")
    if routing_scope_before is not None and routing_mutable_interfaces is not None:
        routing_scope_after = _routing_scope_fingerprint(
            panorama,
            routing_mutable_interfaces,
            routing_mutable_route_names,
        )
        if routing_scope_after != routing_scope_before:
            before = dict(routing_scope_before)
            after = dict(routing_scope_after)
            changed = sorted(
                name
                for name in before.keys() | after.keys()
                if before.get(name) != after.get(name)
            )
            issues.append(
                "unrelated virtual-router or logical-router configuration changed "
                f"in template(s): {', '.join(changed)}"
            )
    for xpath in removed_legacy_route_paths:
        if _candidate_element(panorama, xpath) is not None:
            issues.append(f"replaced legacy static route remains at {xpath}")
    if issues:
        raise LsvpnConfigurationError(
            "Candidate post-write verification failed: " + "; ".join(issues)
        )


def _load_candidate_configuration_locked(
    panorama: Panorama,
    spoke_name: str,
    plans: tuple[StandardIpsecClonePlan, ...],
    replacements: tuple[StandardIpsecReplacementObjects, ...],
    placements: tuple[ReplacementTemplatePlacement, ...],
    spoke_vsys: str = DEFAULT_VSYS,
    hub_vsys: str = DEFAULT_VSYS,
    variables: CandidateVariableSet | None = None,
    allow_dirty_candidate: bool = False,
    on_snapshot_saved: Callable[[str], None] | None = None,
    spoke_router_rename: SpokeRouterRename | None = None,
    ping_only_profiles: PingOnlyProfilePlan | None = None,
) -> CandidateLoadResult:
    """Save a rollback snapshot and load replacement objects without a commit."""
    if not (len(plans) == len(replacements) == len(placements)):
        raise LsvpnConfigurationError(
            "Plans, replacement objects, and template placements must align."
        )
    if not plans:
        raise LsvpnConfigurationError("No LSVPN replacements are available to load.")

    if not allow_dirty_candidate:
        assert_clean_candidate_configuration(panorama)
    variable_set = variables or CandidateVariableSet()
    _preflight_variables(panorama, variable_set)

    endpoint_ownership: list[tuple[bool, bool]] = []
    for plan, replacement, placement in zip(
        plans, replacements, placements, strict=True
    ):
        if plan.required_inputs:
            raise LsvpnConfigurationError(
                f'Replacement tunnel "{plan.tunnel_name}" still requires: '
                f"{', '.join(plan.required_inputs)}."
            )
        if ping_only_profiles is not None:
            replacement.spoke.tunnel_interface.management_profile = PING_ONLY
        _prepare_endpoint_parents(
            panorama, replacement.spoke, placement.spoke, spoke_vsys
        )
        _prepare_endpoint_parents(panorama, replacement.hub, placement.hub, hub_vsys)
        replacement.spoke.tunnel_interface.comment = _marker(plan.source_name)
        replacement.hub.tunnel_interface.comment = _marker(plan.source_name)
        audit_spoke_interface_dependencies(panorama, plan, placement)
        endpoint_ownership.append(
            (
                _preflight_endpoint(panorama, replacement.spoke, plan.source_name),
                _preflight_endpoint(panorama, replacement.hub, plan.source_name),
            )
        )

    hub_lsvpn_before = _hub_lsvpn_fingerprint(panorama, placements)
    routing_mutable = _routing_mutable_interfaces(plans, replacements, placements)
    mutable_route_names = _routing_mutable_route_names(panorama, plans, placements)
    routing_scope_before = _routing_scope_fingerprint(
        panorama,
        routing_mutable,
        mutable_route_names,
    )
    snapshot_name = save_pre_migration_snapshot(
        panorama,
        spoke_name,
        checkpoint=allow_dirty_candidate,
    )
    if on_snapshot_saved is not None:
        on_snapshot_saved(snapshot_name)
    try:
        written = 0
        removed = 0
        removed_legacy_route_paths: list[str] = []
        if ping_only_profiles is not None:
            written += apply_ping_only_profiles(panorama, ping_only_profiles)
        written += _write_variables(panorama, variable_set)
        written_spokes: set[tuple[str, str, EndpointTemplatePlacement]] = set()
        for plan, replacement, placement, ownership in zip(
            plans, replacements, placements, endpoint_ownership, strict=True
        ):
            spoke_owned, hub_owned = ownership
            spoke_key = (
                placement.satellite_template.casefold(),
                plan.source_name.casefold(),
                placement.spoke,
            )
            if spoke_key not in written_spokes:
                removed += _remove_spoke_lsvpn(
                    panorama,
                    plan,
                    placement,
                    spoke_vsys,
                )
            hub_route_paths = _remove_replaced_hub_static_routes(
                panorama,
                plan,
                placement,
            )
            removed += len(hub_route_paths)
            removed_legacy_route_paths.extend(hub_route_paths)
            if spoke_key not in written_spokes:
                written += _write_endpoint(
                    panorama, replacement.spoke, plan.source_name, spoke_owned
                )
                written_spokes.add(spoke_key)
            written += _write_endpoint(
                panorama, replacement.hub, plan.source_name, hub_owned
            )
            _ensure_interface_import(
                panorama,
                placement.spoke,
                spoke_vsys,
                str(replacement.spoke.tunnel_interface.name),
            )
            _ensure_interface_import(
                panorama,
                placement.hub,
                hub_vsys,
                str(replacement.hub.tunnel_interface.name),
            )
        verify_candidate_configuration(
            panorama,
            plans,
            replacements,
            placements,
            hub_lsvpn_before,
            spoke_vsys,
            hub_vsys,
            routing_scope_before,
            routing_mutable,
            mutable_route_names,
            tuple(removed_legacy_route_paths),
            variable_set,
        )
        if ping_only_profiles is not None:
            verify_ping_only_profiles(panorama, ping_only_profiles)
        if spoke_router_rename is not None:
            written += apply_spoke_router_rename(panorama, spoke_router_rename)
            for replacement in replacements:
                replacement.spoke.routing_object.name = spoke_router_rename.new_name
    except (Exception, KeyboardInterrupt, SystemExit) as load_error:
        interrupted = isinstance(load_error, (KeyboardInterrupt, SystemExit))
        error_type = CandidateLoadInterrupted if interrupted else CandidateLoadError
        reason = (
            f"Candidate loading interrupted ({type(load_error).__name__})"
            if interrupted
            else f"Candidate loading failed: {load_error}"
        )
        try:
            rollback_candidate_configuration(panorama)
        except (Exception, KeyboardInterrupt, SystemExit) as rollback_error:
            raise error_type(
                f"{reason}. Automatic candidate rollback also failed: "
                f"{type(rollback_error).__name__}: {rollback_error}. "
                "Panorama candidate configuration may contain partial migration "
                "changes. The saved "
                f'snapshot "{snapshot_name}" was not loaded.'
            ) from load_error
        raise error_type(
            f"{reason}. Panorama candidate changes "
            "were rolled back to running configuration; no commit or push was "
            f'issued. The saved snapshot "{snapshot_name}" was not loaded.'
        ) from load_error
    return CandidateLoadResult(snapshot_name, written, removed)


def _assert_no_unfinished_jobs(panorama: Panorama) -> None:
    """A new commit lock does not cancel work that was already accepted."""
    response = panorama.op(cmd=b"<show><jobs><all /></jobs></show>", cmd_xml=False)
    if (
        not isinstance(response, ET.Element)
        or response.tag != "response"
        or response.get("status") != "success"
        or (result := response.find("./result")) is None
    ):
        raise LsvpnConfigurationError("Panorama job status could not be verified")
    if (result.text or "").strip() or any(child.tag != "job" for child in result):
        raise LsvpnConfigurationError("Panorama returned an unrecognized job listing")
    pending: list[str] = []
    for job in result:
        identifier = (job.findtext("id") or "").strip()
        kind = (job.findtext("type") or "").strip()
        status = (job.findtext("status") or "").strip().upper()
        if not identifier or not kind or not status:
            raise LsvpnConfigurationError("Panorama returned an incomplete job record")
        # Do not guess that an unknown or newly introduced job type is harmless.
        if status != "FIN":
            pending.append(f"{identifier} ({kind}, {status})")
    if pending:
        raise LsvpnConfigurationError(
            "Panorama has unfinished jobs: "
            + ", ".join(pending)
            + ". Wait for completion and retry; no jobs were cancelled"
        )


def _acquire_candidate_locks(
    panorama: Panorama,
    locks: _CandidateLocks,
    comment: str,
) -> None:
    # Keep acquisition/release on the same Panorama transport. An HA failover
    # must not silently split lock ownership across two appliances.
    if not panorama.add_config_lock(
        comment=comment, scope="shared", retry_on_peer=False
    ):
        raise LsvpnConfigurationError("Configuration lock was not acquired")
    locks.configuration = True
    if not panorama.add_commit_lock(
        comment=comment, scope="shared", retry_on_peer=False
    ):
        raise LsvpnConfigurationError("Commit lock was not acquired")
    locks.commit = True
    _assert_no_unfinished_jobs(panorama)


def _release_candidate_locks(
    panorama: Panorama,
    locks: _CandidateLocks,
) -> str | None:
    errors: list[str] = []
    # Keep commit exclusion until configuration-lock cleanup has been attempted.
    for label, owned, release in (
        ("configuration", locks.configuration, panorama.remove_config_lock),
        ("commit", locks.commit, panorama.remove_commit_lock),
    ):
        if not owned:
            continue
        try:
            if release(scope="shared", retry_on_peer=False) is False:
                raise RuntimeError("lock release was not confirmed")
        except (Exception, KeyboardInterrupt, SystemExit) as exc:
            errors.append(f"{label} lock: {type(exc).__name__}: {exc}")
    return "; ".join(errors) or None


def load_candidate_configuration(
    panorama: Panorama,
    spoke_name: str,
    plans: tuple[StandardIpsecClonePlan, ...],
    replacements: tuple[StandardIpsecReplacementObjects, ...],
    placements: tuple[ReplacementTemplatePlacement, ...],
    spoke_vsys: str = DEFAULT_VSYS,
    hub_vsys: str = DEFAULT_VSYS,
    variables: CandidateVariableSet | None = None,
    allow_dirty_candidate: bool = False,
    on_snapshot_saved: Callable[[str], None] | None = None,
    *,
    source_configuration: tuple[SourceConfigurationFingerprint, ...],
    spoke_router_rename: SpokeRouterRename | None = None,
    ping_only_profiles: PingOnlyProfilePlan | None = None,
) -> CandidateLoadResult:
    """Load under temporary configuration and commit locks after checking jobs."""
    locks = _CandidateLocks()
    protected = False
    try:
        _acquire_candidate_locks(
            panorama, locks, f"panos-tunnel-builder LSVPN migration for {spoke_name}"
        )
        protected = True
        assert_source_configuration_unchanged(panorama, source_configuration)
        result = _load_candidate_configuration_locked(
            panorama,
            spoke_name,
            plans,
            replacements,
            placements,
            spoke_vsys,
            hub_vsys,
            variables,
            allow_dirty_candidate,
            on_snapshot_saved,
            spoke_router_rename,
            ping_only_profiles,
        )
    except (Exception, KeyboardInterrupt, SystemExit) as load_error:
        cleanup_error = _release_candidate_locks(panorama, locks)
        if not protected:
            error_type = (
                CandidateLoadInterrupted
                if isinstance(load_error, (KeyboardInterrupt, SystemExit))
                else CandidateLoadError
            )
            error = error_type(
                "Candidate protection failed: "
                f"{type(load_error).__name__}: {load_error}. Candidate loading "
                "was not attempted; inspect Panorama jobs and lock ownership "
                "before retrying."
            )
            error.lock_cleanup_error = cleanup_error
            raise error from load_error
        if cleanup_error:
            if isinstance(load_error, CandidateLoadError):
                # Preserve the transaction/rollback failure as the primary error.
                load_error.lock_cleanup_error = cleanup_error
            else:
                error_type = (
                    CandidateLoadInterrupted
                    if isinstance(load_error, (KeyboardInterrupt, SystemExit))
                    else CandidateLoadError
                )
                error = error_type(
                    "Candidate loading did not return a verified result: "
                    f"{type(load_error).__name__}: {load_error}. "
                    "Inspect Panorama candidate configuration before retrying."
                )
                error.lock_cleanup_error = cleanup_error
                raise error from load_error
        raise
    return replace(result, lock_cleanup_error=_release_candidate_locks(panorama, locks))
