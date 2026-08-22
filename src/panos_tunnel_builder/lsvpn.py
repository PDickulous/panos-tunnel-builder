import hashlib
import ipaddress
import re
import secrets
import socket
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal, Protocol, cast

from panos.device import Vsys
from panos.errors import PanDeviceError, PanNoSuchNode
from panos.firewall import Firewall
from panos.network import (
    Bgp,
    BgpPeer,
    BgpPeerGroup,
    IkeCryptoProfile,
    IkeGateway,
    IpsecCryptoProfile,
    IpsecTunnel,
    IPv6Address,
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

DEFAULT_VSYS = "vsys1"
PORTAL_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']"
    "/vsys/entry[@name='vsys1']/global-protect/global-protect-portal"
)
GATEWAY_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']"
    "/vsys/entry[@name='vsys1']/global-protect/global-protect-gateway"
)
GATEWAY_TUNNEL_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']"
    "/network/tunnel/global-protect-site-to-site"
)


class LsvpnConfigurationError(RuntimeError):
    """The discovered LSVPN configuration is incomplete or ambiguous."""


class _PanoramaChild(Protocol):
    """Typed view of the SDK's dynamically assigned parent attribute."""

    parent: Panorama | None


def _attach_to_panorama(firewall: Firewall, panorama: Panorama) -> None:
    # pan-os-python initializes PanObject.parent to None without a type annotation,
    # so Pyright infers that the attribute can only ever contain None.
    cast(_PanoramaChild, firewall).parent = panorama


def _vsys_xpath(base_xpath: str, vsys: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", vsys):
        raise LsvpnConfigurationError(f'Invalid virtual system name: "{vsys}".')
    return base_xpath.replace("vsys1", vsys, 1)


def _vsys_scope(root: ET.Element, vsys: str) -> ET.Element | None:
    entries = root.findall(".//vsys/entry")
    if not entries:
        return root
    wanted = vsys.casefold()
    return next(
        (entry for entry in entries if entry.get("name", "").casefold() == wanted),
        None,
    )


@dataclass(frozen=True)
class SatelliteConfig:
    name: str
    tunnel_interface: str | None
    portal_address: str | None
    local_interface: str | None
    local_ipv4: str | None
    local_ipv6: str | None
    publish_connected_routes: bool
    published_routes: tuple[str, ...]
    local_certificate: str | None
    certificate_profile: str | None
    anti_replay: bool
    copy_tos: bool
    tunnel_monitor_enabled: bool
    tunnel_monitor_destination: str | None
    tunnel_monitor_profile: str | None
    local_address_reference: str | None = None


@dataclass(frozen=True)
class GatewayRuntime:
    satellite_name: str
    gateway_name: str | None
    gateway_address: str | None
    status: str | None
    error: str | None = None


@dataclass(frozen=True)
class PortalGateway:
    portal_name: str
    satellite_config_name: str
    name: str
    address: str
    priority: int | None
    satellite_serials: tuple[str, ...]


@dataclass(frozen=True)
class HubTunnelInterfaceConfig:
    name: str
    ip_addresses: tuple[str, ...]
    ipv6_enabled: bool
    management_profile: str | None
    mtu: int | None
    netflow_profile: str | None
    comment: str | None
    virtual_routers: tuple[str, ...]
    zones: tuple[str, ...]
    routing_instances: tuple["RoutingInstanceConfig", ...] = ()


@dataclass(frozen=True)
class RoutingInstanceConfig:
    kind: Literal["virtual-router", "logical-router"]
    name: str
    vrf: str | None = None


@dataclass(frozen=True)
class TunnelInterfaceInventory:
    interfaces: tuple[HubTunnelInterfaceConfig, ...]
    configured_networks: tuple[str, ...] = ()

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(interface.name for interface in self.interfaces)

    def find(self, name: str) -> HubTunnelInterfaceConfig | None:
        wanted = name.casefold()
        return next(
            (
                interface
                for interface in self.interfaces
                if interface.name.casefold() == wanted
            ),
            None,
        )


@dataclass(frozen=True)
class TunnelAddressPair:
    network: str
    hub: str
    spoke: str


@dataclass(frozen=True)
class BgpPeerCloneSource:
    peer_group_name: str
    peer_group_type: str
    peer_name: str
    peer_as: str
    peer_address: str
    local_interface: str
    local_address: str | None
    enabled: bool
    authentication: str | None
    bfd_profile: str | None
    keep_alive_interval: int | None
    min_route_adv_interval: int | None
    multihop: int | None
    open_delay_time: int | None
    hold_time: int | None
    idle_hold_time: int | None
    address_family_ipv4: str | None = None
    address_family_ipv6: str | None = None
    filtering_profile_ipv4: str | None = None
    filtering_profile_ipv6: str | None = None
    timer_profile: str | None = None
    dampening_profile: str | None = None
    export_policy_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class OspfInterfaceCloneSource:
    area_name: str
    area_type: str
    enabled: bool
    passive: bool
    link_type: str
    metric: int | None
    priority: int | None
    hello_interval: int | None
    dead_counts: int | None
    retransmit_interval: int | None
    transit_delay: int | None
    authentication: str | None
    bfd_profile: str | None
    timing: str | None


@dataclass(frozen=True)
class DynamicRoutingCloneSource:
    bgp: tuple[BgpPeerCloneSource, ...] = ()
    transit_bgp: tuple[BgpPeerCloneSource, ...] = ()
    ospf: tuple[OspfInterfaceCloneSource, ...] = ()

    @property
    def protocols(self) -> tuple[str, ...]:
        protocols: list[str] = []
        if self.bgp or self.transit_bgp:
            protocols.append("BGP")
        if self.ospf:
            protocols.append("OSPF")
        return tuple(protocols)


@dataclass(frozen=True)
class HubGatewayCloneSource:
    name: str
    address: str
    external_interface: str | None
    external_ipv4: str | None
    external_ipv6: str | None
    floating_ipv4: str | None
    floating_ipv6: str | None
    tunnel_interface: HubTunnelInterfaceConfig
    ipsec_crypto_profile: str | None
    tunnel_monitor_enabled: bool
    tunnel_monitor_destination: str | None
    tunnel_monitor_profile: str | None
    tunnel_monitor_source: str | None
    access_routes: tuple[str, ...]
    client_ip_pools: tuple[str, ...]
    dns_primary: str | None
    dns_secondary: str | None
    dns_suffix: str | None
    external_address_reference: str | None = None


@dataclass(frozen=True)
class StandardCryptoSettings:
    ike_profile_name: str = "ptb-ike-moderate"
    ike_version: str = "ikev2"
    ike_encryption: tuple[str, ...] = ("aes-256-cbc",)
    ike_authentication: tuple[str, ...] = ("sha256",)
    ike_dh_groups: tuple[str, ...] = ("group14",)
    ike_lifetime_hours: int = 8
    ipsec_profile_name: str = "ptb-ipsec-esp-moderate"
    ipsec_protocol: str = "esp"
    esp_encryption: tuple[str, ...] = ("aes-256-cbc",)
    esp_authentication: tuple[str, ...] = ("sha256",)
    ah_authentication: tuple[str, ...] = ("sha256",)
    pfs_group: str = "group14"
    ipsec_lifetime_hours: int = 1


@dataclass(frozen=True)
class StandardIpsecEndpointObjects:
    ike_crypto_profile: IkeCryptoProfile
    ipsec_crypto_profile: IpsecCryptoProfile
    ike_gateway: IkeGateway
    ipsec_tunnel: IpsecTunnel
    tunnel_interface: TunnelInterface
    routing_object: VirtualRouter | LogicalRouter
    zone: Zone


@dataclass(frozen=True)
class StandardIpsecReplacementObjects:
    spoke: StandardIpsecEndpointObjects
    hub: StandardIpsecEndpointObjects


@dataclass(frozen=True)
class StagedStandardIpsecConfiguration:
    spoke_template: Template
    hub_template: Template
    replacements: tuple[StandardIpsecReplacementObjects, ...]
    spoke_vsys: Vsys
    hub_vsys: Vsys


@dataclass(frozen=True)
class StandardIpsecClonePlan:
    source_name: str
    spoke_identity: str | None
    spoke_hostname: str | None
    hub_hostname: str | None
    tunnel_name: str
    ike_gateway_name: str
    tunnel_interface: str | None
    replacement_spoke_tunnel_interface: str | None
    replacement_hub_tunnel_interface: str | None
    spoke_tunnel_source: HubTunnelInterfaceConfig | None
    spoke_tunnel_address: str | None
    hub_tunnel_address: str | None
    spoke_dynamic_routing: DynamicRoutingCloneSource
    hub_dynamic_routing: DynamicRoutingCloneSource
    local_interface: str | None
    local_address: str | None
    local_address_reference: str | None
    configured_portal_address: str | None
    active_gateway_name: str | None
    active_gateway_address: str | None
    portal_gateway_name: str | None
    portal_gateway_address: str | None
    hub_gateway: HubGatewayCloneSource | None
    peer_address_candidate: str | None
    pre_shared_key: str
    crypto: StandardCryptoSettings
    published_routes: tuple[str, ...]
    spoke_static_routes: tuple[str, ...]
    hub_static_routes: tuple[str, ...]
    spoke_route_metric: int
    proxy_id_mode: str
    anti_replay: bool
    copy_tos: bool
    tunnel_monitor_enabled: bool
    tunnel_monitor_destination: str | None
    tunnel_monitor_profile: str | None
    required_inputs: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def shared_spoke_tunnel_name(self) -> str:
        if self.hub_hostname:
            return _endpoint_object_name(
                self.hub_hostname,
                "shared-spokes",
                self.source_name,
            )
        return f"{self.source_name[:54]}-standard"

    @property
    def shared_spoke_ike_gateway_name(self) -> str:
        if self.hub_hostname:
            return _ike_gateway_name(self.shared_spoke_tunnel_name)
        return f"{self.source_name[:59]}-ike"


@dataclass(frozen=True)
class EndpointVariableReferences:
    tunnel_interface_address: str
    tunnel_local: str
    tunnel_peer: str
    ike_local: str
    ike_peer: str
    pre_shared_key: str
    ike_identity: str | None = None
    route_destinations: tuple[tuple[str, str], ...] = ()


def _string(value: object) -> str | None:
    return str(value) if value not in (None, "") else None


def _strings(value: str | list[str] | None) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def normalize_endpoint(value: str) -> str:
    """Normalize an IP/CIDR literal or DNS name for comparison."""
    candidate = value.strip()
    try:
        return ipaddress.ip_interface(candidate).ip.compressed.casefold()
    except ValueError:
        pass
    hostname = candidate.rstrip(".")
    try:
        return hostname.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return hostname.casefold()


@lru_cache(maxsize=128)
def _resolved_endpoint_addresses(endpoint: str) -> frozenset[str]:
    normalized = normalize_endpoint(endpoint)
    try:
        return frozenset({ipaddress.ip_address(normalized).compressed.casefold()})
    except ValueError:
        pass
    if "." not in normalized:
        return frozenset()
    try:
        results = socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
    except OSError:
        return frozenset()
    addresses: set[str] = set()
    for result in results:
        raw_address = result[4][0]
        if not isinstance(raw_address, str):
            continue
        address = raw_address.partition("%")[0]
        try:
            addresses.add(ipaddress.ip_address(address).compressed.casefold())
        except ValueError:
            continue
    return frozenset(addresses)


def endpoints_match(first: str, second: str) -> bool:
    """Compare IP/CIDR or FQDN endpoints, resolving DNS when necessary."""
    normalized_first = normalize_endpoint(first)
    normalized_second = normalize_endpoint(second)
    if normalized_first == normalized_second:
        return True
    first_addresses = _resolved_endpoint_addresses(normalized_first)
    second_addresses = _resolved_endpoint_addresses(normalized_second)
    return bool(first_addresses and first_addresses.intersection(second_addresses))


def generate_pre_shared_key() -> str:
    """Return a URL-safe PSK with at least 256 bits of entropy."""
    return secrets.token_urlsafe(32)


def _peer_address_type(address: str) -> str:
    normalized = normalize_endpoint(address)
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return "fqdn"
    return "ip"


_DYNAMIC_IKE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
        "fe80::/10",
    )
)


def _requires_dynamic_ike_peer(address: str) -> bool:
    """Treat RFC1918, CGNAT, and IPv6 local addresses as NAT/dynamic peers."""
    try:
        parsed = ipaddress.ip_address(normalize_endpoint(address))
    except ValueError:
        return False
    return any(
        parsed.version == network.version and parsed in network
        for network in _DYNAMIC_IKE_NETWORKS
    )


def _ike_identity(spoke_identity: str | None, source_name: str) -> str:
    identity = spoke_identity or source_name
    value = f"ptb:{identity}:{source_name}".encode()
    return hashlib.sha256(value).hexdigest()


def _to_satellite_config(tunnel: IpsecTunnel) -> SatelliteConfig:
    return SatelliteConfig(
        name=str(tunnel.name),
        tunnel_interface=_string(tunnel.tunnel_interface),
        portal_address=_string(tunnel.gps_portal_address),
        local_interface=_string(tunnel.gps_interface),
        local_ipv4=_string(tunnel.gps_interface_ipv4_ip),
        local_ipv6=_string(tunnel.gps_interface_ipv6_ip),
        publish_connected_routes=bool(tunnel.gps_publish_connected_routes),
        published_routes=_strings(tunnel.gps_publish_routes),
        local_certificate=_string(tunnel.gps_local_certificate),
        certificate_profile=_string(tunnel.gps_certificate_profile),
        anti_replay=bool(tunnel.anti_replay),
        copy_tos=bool(tunnel.copy_tos),
        tunnel_monitor_enabled=bool(tunnel.enable_tunnel_monitor),
        tunnel_monitor_destination=_string(tunnel.tunnel_monitor_dest_ip),
        tunnel_monitor_profile=_string(tunnel.tunnel_monitor_profile),
    )


def discover_lsvpn_satellites(
    panorama: Panorama,
    serial: str,
    vsys: str = DEFAULT_VSYS,
) -> tuple[SatelliteConfig, ...]:
    """Read local satellite tunnel configuration through Panorama."""
    _vsys_xpath(PORTAL_XPATH, vsys)
    firewall = Firewall(serial=serial, vsys=vsys)
    _attach_to_panorama(firewall, panorama)
    tunnels = IpsecTunnel.refreshall(
        firewall,
        running_config=False,
        add=False,
    )
    return tuple(
        _to_satellite_config(tunnel)
        for tunnel in tunnels
        if tunnel.type == "global-protect-satellite"
    )


def _normalized_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].replace("_", "-").casefold()


def _structured_value(
    root: ET.Element,
    names: set[str],
) -> str | None:
    for element in root.iter():
        if _normalized_tag(element.tag) in names and element.text:
            value = element.text.strip()
            if value:
                return value
    return None


def _labeled_value(text: str, label: str) -> str | None:
    match = re.search(
        rf"(?im)^\s*{re.escape(label)}\s*:\s*(\S.*?)\s*$",
        text,
    )
    return match.group(1).strip() if match else None


def _parse_gateway_runtime(
    root: ET.Element,
    satellite_name: str,
) -> GatewayRuntime:
    text = "\n".join(part.strip() for part in root.itertext() if part.strip())
    gateway_name = _structured_value(
        root,
        {"gateway-name", "globalprotect-gateway-name"},
    ) or _labeled_value(text, "GlobalProtect Gateway Name")
    gateway_address = _structured_value(
        root,
        {"gateway-address", "globalprotect-gateway-address"},
    ) or _labeled_value(text, "GlobalProtect Gateway Address")
    status = _structured_value(
        root,
        {"tunnel-monitor-status", "status"},
    ) or _labeled_value(text, "Tunnel Monitor Status")
    return GatewayRuntime(
        satellite_name=satellite_name,
        gateway_name=gateway_name,
        gateway_address=gateway_address,
        status=status,
    )


def discover_active_gateway(
    panorama: Panorama,
    serial: str,
    satellite: SatelliteConfig,
    vsys: str = DEFAULT_VSYS,
) -> GatewayRuntime:
    """Query the satellite's current gateway operational state through Panorama."""
    if satellite.portal_address is None:
        return GatewayRuntime(
            satellite_name=satellite.name,
            gateway_name=None,
            gateway_address=None,
            status=None,
            error="Portal address is unavailable; current gateway was not queried.",
        )

    _vsys_xpath(PORTAL_XPATH, vsys)
    firewall = Firewall(serial=serial, vsys=vsys)
    _attach_to_panorama(firewall, panorama)
    command = ET.Element("show")
    gp_satellite = ET.SubElement(command, "global-protect-satellite")
    current_gateway = ET.SubElement(gp_satellite, "current-gateway")
    ET.SubElement(current_gateway, "gateway").text = satellite.portal_address
    ET.SubElement(current_gateway, "satellite").text = satellite.name

    try:
        response = firewall.op(
            cmd=ET.tostring(command, encoding="utf-8"),
            cmd_xml=False,
        )
    except PanDeviceError as exc:
        return GatewayRuntime(
            satellite_name=satellite.name,
            gateway_name=None,
            gateway_address=None,
            status=None,
            error=str(exc),
        )
    return _parse_gateway_runtime(response, satellite.name)


def _gateway_address(entry: ET.Element) -> str | None:
    for path in (
        "fqdn",
        "ip/fqdn",
        "hostname",
        "ip/ipv4",
        "ip/ipv6",
        "ip",
        "address",
    ):
        value = entry.findtext(path)
        if value and value.strip():
            return value.strip()
    return None


def _satellite_serials(config: ET.Element) -> tuple[str, ...]:
    serials: list[str] = []
    for container in config.iter():
        tag = _normalized_tag(container.tag)
        if "device" not in tag and "serial" not in tag:
            continue
        for entry in container.findall("./entry"):
            name = entry.get("name")
            if name and name.casefold() != "any":
                serials.append(name)
        serials.extend(
            member.text.strip()
            for member in container.findall("./member")
            if member.text
            and member.text.strip()
            and member.text.strip().casefold() != "any"
        )
    return tuple(dict.fromkeys(serials))


def _parse_portal_gateways(
    root: ET.Element,
    vsys: str | None = None,
) -> tuple[PortalGateway, ...]:
    if vsys is not None:
        scoped = _vsys_scope(root, vsys)
        if scoped is None:
            return ()
        root = scoped
    gateways: list[PortalGateway] = []
    for portal in root.findall(".//global-protect-portal/entry"):
        portal_name = portal.get("name", "")
        for config in portal.findall("./satellite-config/configs/entry"):
            config_name = config.get("name", "")
            serials = _satellite_serials(config)
            for gateway in config.findall("./gateways/entry"):
                address = _gateway_address(gateway)
                if address is None:
                    continue
                priority_text = gateway.findtext("priority") or gateway.findtext(
                    "routing-priority"
                )
                try:
                    priority = int(priority_text) if priority_text else None
                except ValueError:
                    priority = None
                gateways.append(
                    PortalGateway(
                        portal_name=portal_name,
                        satellite_config_name=config_name,
                        name=gateway.get("name", address),
                        address=address,
                        priority=priority,
                        satellite_serials=serials,
                    )
                )
    return tuple(gateways)


def discover_portal_gateways(
    panorama: Panorama,
    portal_firewall_serial: str,
    vsys: str = DEFAULT_VSYS,
) -> tuple[PortalGateway, ...]:
    """Read effective portal satellite gateway assignments through Panorama."""
    try:
        response = panorama.xapi.show(
            _vsys_xpath(PORTAL_XPATH, vsys),
            extra_qs={"target": portal_firewall_serial},
        )
    except PanNoSuchNode:
        response = None

    if response is not None:
        gateways = _parse_portal_gateways(response)
        if gateways:
            return gateways

    # A targeted configuration API query can omit configuration inherited from
    # Panorama templates.  Query the firewall's effective-running configuration
    # so pushed portal and satellite settings are included.
    effective = _read_effective_running_config(
        panorama,
        portal_firewall_serial,
        vsys,
    )
    return _parse_portal_gateways(effective, vsys)


def select_single_portal_gateway(
    gateways: tuple[PortalGateway, ...],
) -> PortalGateway | None:
    """Return the sole applicable gateway, rejecting ambiguous portal config."""
    if not gateways:
        return None

    by_portal: dict[str, dict[str, PortalGateway]] = {}
    for gateway in gateways:
        by_portal.setdefault(gateway.portal_name, {})[
            normalize_endpoint(gateway.address)
        ] = gateway

    for portal_name, unique in by_portal.items():
        if len(unique) > 1:
            choice_names = ", ".join(
                f"{item.name} ({item.address})" for item in unique.values()
            )
            raise LsvpnConfigurationError(
                f'Portal "{portal_name}" designates more than one applicable '
                f"satellite gateway: {choice_names}. Only one gateway per portal is "
                "supported."
            )

    gateway_choices = [next(iter(unique.values())) for unique in by_portal.values()]
    distinct = {
        normalize_endpoint(gateway.address): gateway for gateway in gateway_choices
    }
    if len(distinct) > 1:
        names = ", ".join(
            f"{gateway.portal_name}: {gateway.name} ({gateway.address})"
            for gateway in distinct.values()
        )
        raise LsvpnConfigurationError(
            "More than one applicable portal/gateway was found: " + names
        )
    return next(iter(distinct.values()))


def _container_entries(root: ET.Element, tag: str) -> tuple[ET.Element, ...]:
    container = root.find(f".//{tag}")
    if container is None:
        return ()
    return tuple(container.findall("./entry"))


def _named_entry(
    entries: tuple[ET.Element, ...],
    name: str,
) -> ET.Element | None:
    wanted = name.casefold()
    return next(
        (entry for entry in entries if entry.get("name", "").casefold() == wanted),
        None,
    )


def _address_entry(
    entries: tuple[ET.Element, ...],
    address: str,
) -> ET.Element | None:
    matches: list[ET.Element] = []
    for entry in entries:
        configured = _first_text(
            entry,
            (
                "local-address/ip/ipv4",
                "local-address/ip/ipv6",
                "local-address/ipv4",
                "local-address/ipv6",
            ),
        )
        if configured and endpoints_match(configured, address):
            matches.append(entry)
    if len(matches) > 1:
        names = ", ".join(entry.get("name", "[unnamed]") for entry in matches)
        raise LsvpnConfigurationError(
            f"Gateway address {address} matches multiple GlobalProtect "
            f"site-to-site objects: {names}."
        )
    return matches[0] if matches else None


def _first_text(entry: ET.Element | None, paths: tuple[str, ...]) -> str | None:
    if entry is None:
        return None
    for path in paths:
        value = entry.findtext(path)
        if value and value.strip():
            return value.strip()
    return None


def _members(entry: ET.Element | None, paths: tuple[str, ...]) -> tuple[str, ...]:
    if entry is None:
        return ()
    values: list[str] = []
    for path in paths:
        values.extend(
            member.text.strip()
            for member in entry.findall(path)
            if member.text and member.text.strip()
        )
    return tuple(dict.fromkeys(values))


def _yes(value: str | None) -> bool:
    return value is not None and value.casefold() in {"yes", "true", "on", "1"}


def _enabled(value: str | None) -> bool:
    return True if value is None else _yes(value)


def _effective_tunnel_interface(
    root: ET.Element,
    name: str,
) -> TunnelInterface | None:
    wanted = name.casefold()
    entry = next(
        (
            candidate
            for candidate in root.findall(".//network/interface/tunnel/units/entry")
            if candidate.get("name", "").casefold() == wanted
        ),
        None,
    )
    if entry is None:
        return None

    addresses = [
        address
        for address_entry in entry.findall("./ip/entry")
        if (address := address_entry.get("name"))
    ]
    addresses.extend(_members(entry, ("ip/member",)))
    return TunnelInterface(
        name,
        ip=list(dict.fromkeys(addresses)),
        ipv6_enabled=_yes(entry.findtext("ipv6/enabled")),
        management_profile=_first_text(
            entry,
            ("interface-management-profile", "management-profile"),
        ),
        mtu=_int_text(entry.findtext("mtu")),
        netflow_profile=_first_text(entry, ("netflow-profile",)),
        comment=_first_text(entry, ("comment",)),
    )


def _int_text(value: str | None) -> int | None:
    try:
        return int(value) if value else None
    except ValueError:
        return None


def _effective_interface_memberships(
    root: ET.Element,
    interface_name: str,
    vsys: str = DEFAULT_VSYS,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    virtual_routers: list[str] = []
    for path in (
        ".//network/virtual-router/entry",
        ".//network/logical-router/entry",
    ):
        for router in root.findall(path):
            if any(
                member.text and member.text.strip() == interface_name
                for member in router.findall(".//interface/member")
            ):
                name = router.get("name")
                if name:
                    virtual_routers.append(name)

    zones: list[str] = []
    scoped = _vsys_scope(root, vsys)
    zone_root = scoped if scoped is not None else ET.Element("empty")
    for zone in zone_root.findall("./zone/entry"):
        if any(
            member.text and member.text.strip() == interface_name
            for member in zone.findall("./network/layer3/member")
        ):
            name = zone.get("name")
            if name:
                zones.append(name)
    return tuple(dict.fromkeys(virtual_routers)), tuple(dict.fromkeys(zones))


def _effective_routing_memberships(
    root: ET.Element,
    interface_name: str,
) -> tuple[RoutingInstanceConfig, ...]:
    memberships: list[RoutingInstanceConfig] = []
    for router in root.findall(".//network/virtual-router/entry"):
        if any(
            member.text and member.text.strip() == interface_name
            for member in router.findall("./interface/member")
        ):
            name = router.get("name")
            if name:
                memberships.append(RoutingInstanceConfig("virtual-router", name))

    for router in root.findall(".//network/logical-router/entry"):
        router_name = router.get("name")
        if not router_name:
            continue
        for vrf in router.findall("./vrf/entry"):
            if any(
                member.text and member.text.strip() == interface_name
                for member in vrf.findall("./interface/member")
            ):
                vrf_name = vrf.get("name")
                if vrf_name:
                    memberships.append(
                        RoutingInstanceConfig(
                            "logical-router",
                            router_name,
                            vrf_name,
                        )
                    )
    return tuple(dict.fromkeys(memberships))


def _read_effective_config(
    panorama: Panorama,
    serial: str,
    xpath: str,
) -> ET.Element | None:
    try:
        return cast(
            ET.Element,
            panorama.xapi.show(xpath, extra_qs={"target": serial}),
        )
    except PanNoSuchNode:
        return None


def _read_effective_running_config(
    panorama: Panorama,
    serial: str,
    vsys: str = DEFAULT_VSYS,
) -> ET.Element:
    _vsys_xpath(PORTAL_XPATH, vsys)
    firewall = Firewall(serial=serial, vsys=vsys)
    _attach_to_panorama(firewall, panorama)
    return cast(
        ET.Element,
        firewall.op(
            cmd=(
                b"<show><config><effective-running></effective-running></config></show>"
            ),
            cmd_xml=False,
        ),
    )


def discover_tunnel_interface_inventory(
    panorama: Panorama,
    serial: str,
    vsys: str = DEFAULT_VSYS,
) -> TunnelInterfaceInventory:
    """Read tunnel interfaces and their exact routing/zone scope."""
    effective = _read_effective_running_config(panorama, serial, vsys)
    firewall = Firewall(serial=serial, vsys=vsys)
    _attach_to_panorama(firewall, panorama)
    sdk_interfaces = TunnelInterface.refreshall(
        firewall,
        running_config=True,
        add=False,
    )
    routers = VirtualRouter.refreshall(firewall, running_config=True, add=False)
    zones = Zone.refreshall(firewall, running_config=True, add=False)

    by_name = {str(interface.name): interface for interface in sdk_interfaces}
    for entry in effective.findall(".//network/interface/tunnel/units/entry"):
        name = entry.get("name")
        if name and name not in by_name:
            parsed = _effective_tunnel_interface(effective, name)
            if parsed is not None:
                by_name[name] = parsed

    discovered: list[HubTunnelInterfaceConfig] = []
    for name in sorted(by_name, key=_tunnel_interface_sort_key):
        interface = by_name[name]
        routing_instances = list(_effective_routing_memberships(effective, name))
        for router in routers:
            if name in (router.interface or []):
                membership = RoutingInstanceConfig(
                    "virtual-router",
                    str(router.name),
                )
                if membership not in routing_instances:
                    routing_instances.append(membership)
        effective_vrs, effective_zones = _effective_interface_memberships(
            effective,
            name,
            vsys,
        )
        zone_names = [
            str(zone.name) for zone in zones if name in (zone.interface or [])
        ]
        zone_names.extend(zone for zone in effective_zones if zone not in zone_names)
        discovered.append(
            HubTunnelInterfaceConfig(
                name=name,
                ip_addresses=_strings(interface.ip),
                ipv6_enabled=bool(interface.ipv6_enabled),
                management_profile=_string(interface.management_profile),
                mtu=interface.mtu,
                netflow_profile=_string(interface.netflow_profile),
                comment=_string(interface.comment),
                virtual_routers=tuple(
                    dict.fromkeys(
                        (
                            *(membership.name for membership in routing_instances),
                            *effective_vrs,
                        )
                    )
                ),
                zones=tuple(dict.fromkeys(zone_names)),
                routing_instances=tuple(routing_instances),
            )
        )
    configured_networks: list[str] = []
    for entry in effective.findall(".//network/interface//entry"):
        for address in _effective_interface_addresses(entry):
            try:
                configured_networks.append(str(ipaddress.ip_interface(address).network))
            except ValueError:
                continue
    return TunnelInterfaceInventory(
        tuple(discovered),
        tuple(dict.fromkeys(configured_networks)),
    )


def _tunnel_interface_sort_key(name: str) -> tuple[int, int | str]:
    match = re.fullmatch(r"tunnel\.(\d+)", name, re.IGNORECASE)
    return (0, int(match.group(1))) if match else (1, name.casefold())


def allocate_tunnel_interface_names(
    inventory: TunnelInterfaceInventory,
    count: int,
) -> tuple[str, ...]:
    """Allocate the lowest unused PAN-OS tunnel unit names."""
    if count < 0:
        raise ValueError("Tunnel interface count cannot be negative.")
    used = {name.casefold() for name in inventory.names}
    allocated: list[str] = []
    for unit in range(1, 10000):
        candidate = f"tunnel.{unit}"
        if candidate.casefold() not in used:
            allocated.append(candidate)
            used.add(candidate.casefold())
            if len(allocated) == count:
                return tuple(allocated)
    if count == 0:
        return ()
    raise LsvpnConfigurationError(
        f"Unable to allocate {count} unused tunnel interface unit(s)."
    )


def allocate_tunnel_address_pairs(
    pool: str,
    count: int,
    excluded_networks: tuple[str, ...] = (),
) -> tuple[TunnelAddressPair, ...]:
    """Allocate point-to-point links from an operator-supplied address pool."""
    if count < 0:
        raise ValueError("Tunnel address count cannot be negative.")
    try:
        network = ipaddress.ip_network(pool, strict=True)
    except ValueError as exc:
        raise LsvpnConfigurationError(
            f'Tunnel address pool "{pool}" is not a valid network prefix.'
        ) from exc
    link_prefix = 30 if network.version == 4 else 127
    if network.prefixlen > link_prefix:
        raise LsvpnConfigurationError(
            f'Tunnel address pool "{pool}" is too small; use an IPv4 /30 or '
            "larger pool, or an IPv6 /127 or larger pool."
        )
    pairs: list[TunnelAddressPair] = []
    excluded = tuple(_normalized_network(value) for value in excluded_networks)
    for link in network.subnets(new_prefix=link_prefix):
        if any(
            link.version == item.version and link.overlaps(item) for item in excluded
        ):
            continue
        addresses = tuple(link.hosts())
        if len(addresses) < 2:
            continue
        pairs.append(
            TunnelAddressPair(
                network=str(link),
                hub=f"{addresses[0]}/{link_prefix}",
                spoke=f"{addresses[1]}/{link_prefix}",
            )
        )
        if len(pairs) == count:
            return tuple(pairs)
    if count == 0:
        return ()
    raise LsvpnConfigurationError(
        f'Tunnel address pool "{pool}" does not contain {count} available '
        "non-overlapping point-to-point subnet(s)."
    )


def discover_dynamic_routing(
    panorama: Panorama,
    serial: str,
    source_interface: HubTunnelInterfaceConfig,
    vsys: str = DEFAULT_VSYS,
    peer_addresses: tuple[str, ...] = (),
) -> DynamicRoutingCloneSource:
    """Discover BGP peers and OSPF interfaces bound to an LSVPN interface."""
    effective = _read_effective_running_config(panorama, serial, vsys)
    routing = _single_routing_instance(source_interface, "routing")
    entry = _effective_routing_entry(effective, routing)
    if entry is None:
        return DynamicRoutingCloneSource()
    legacy = routing.kind == "virtual-router"
    bgp_root = entry.find("./protocol/bgp" if legacy else "./bgp")
    ospf_root = entry.find("./protocol/ospf" if legacy else "./ospf")
    ospfv3_root = entry.find("./protocol/ospfv3" if legacy else "./ospfv3")
    if ospfv3_root is not None and any(
        interface.get("name") == source_interface.name
        for interface in ospfv3_root.findall("./area/entry/interface/entry")
    ):
        raise LsvpnConfigurationError(
            f'OSPFv3 is configured on source interface "{source_interface.name}"; '
            "OSPFv3 replacement cloning is not yet supported."
        )
    parsed_ospf = _parse_ospf_interfaces(ospf_root, source_interface.name)
    parsed_bgp = _parse_bgp_peers(
        bgp_root,
        source_interface.name,
        peer_addresses,
        effective,
        legacy,
    )
    direct_bgp = tuple(
        peer for peer in parsed_bgp if peer.local_interface == source_interface.name
    )
    return DynamicRoutingCloneSource(
        bgp=direct_bgp,
        transit_bgp=(
            tuple(
                peer
                for peer in parsed_bgp
                if peer.local_interface.casefold().startswith("loopback.")
            )
            if not direct_bgp
            else ()
        ),
        ospf=parsed_ospf,
    )


def _parse_bgp_peers(
    root: ET.Element | None,
    interface_name: str,
    peer_addresses: tuple[str, ...],
    effective: ET.Element,
    legacy: bool,
) -> tuple[BgpPeerCloneSource, ...]:
    if root is None or not _enabled(root.findtext("enable")):
        return ()
    peers: list[BgpPeerCloneSource] = []
    for group in root.findall("./peer-group/entry"):
        group_name = group.get("name")
        if not group_name:
            continue
        group_type_entry = group.find("./type/*")
        group_type = group_type_entry.tag if group_type_entry is not None else "ebgp"
        export_policy_names = (
            tuple(
                rule.get("name", "")
                for rule in root.findall("./policy/export/rules/entry")
                if rule.get("name")
                and any(
                    member.text and member.text.strip() == group_name
                    for member in rule.findall("./used-by/member")
                )
            )
            if legacy
            else ()
        )
        for peer in group.findall("./peer/entry"):
            local_interface = _first_text(
                peer,
                ("local-address/interface",),
            )
            if local_interface is None or (
                local_interface != interface_name
                and not local_interface.casefold().startswith("loopback.")
            ):
                continue
            peer_name = peer.get("name")
            peer_as = _first_text(peer, ("peer-as",))
            peer_address = _first_text(
                peer,
                ("peer-address/ip", "peer-address/fqdn"),
            )
            if not peer_name or peer_as is None or peer_address is None:
                raise LsvpnConfigurationError(
                    f'BGP peer on interface "{interface_name}" has no name, peer '
                    "AS, or peer address."
                )
            if (
                local_interface == interface_name
                and peer_addresses
                and not any(
                    endpoints_match(peer_address, address) for address in peer_addresses
                )
            ):
                continue
            local_address = _first_text(peer, ("local-address/ip",))
            if local_address is None:
                local_address = _effective_interface_primary_address(
                    effective,
                    local_interface,
                )
            peers.append(
                BgpPeerCloneSource(
                    peer_group_name=group_name,
                    peer_group_type=group_type,
                    peer_name=peer_name,
                    peer_as=peer_as,
                    peer_address=peer_address,
                    local_interface=local_interface,
                    local_address=local_address,
                    enabled=_enabled(peer.findtext("enable")),
                    authentication=_first_text(
                        peer,
                        ("connection-options/authentication",),
                    )
                    or _first_text(
                        group,
                        ("connection-options/authentication",),
                    ),
                    bfd_profile=_first_text(peer, ("bfd/profile",)),
                    keep_alive_interval=_int_text(
                        peer.findtext("connection-options/keep-alive-interval")
                    ),
                    min_route_adv_interval=_int_text(
                        peer.findtext("connection-options/min-route-adv-interval")
                    ),
                    multihop=_int_text(peer.findtext("connection-options/multihop"))
                    or _int_text(group.findtext("connection-options/multihop")),
                    open_delay_time=_int_text(
                        peer.findtext("connection-options/open-delay-time")
                    ),
                    hold_time=_int_text(peer.findtext("connection-options/hold-time")),
                    idle_hold_time=_int_text(
                        peer.findtext("connection-options/idle-hold-time")
                    ),
                    address_family_ipv4=_first_text(group, ("address-family/ipv4",)),
                    address_family_ipv6=_first_text(group, ("address-family/ipv6",)),
                    filtering_profile_ipv4=_first_text(
                        group, ("filtering-profile/ipv4",)
                    ),
                    filtering_profile_ipv6=_first_text(
                        group, ("filtering-profile/ipv6",)
                    ),
                    timer_profile=_first_text(group, ("connection-options/timers",)),
                    dampening_profile=_first_text(
                        group, ("connection-options/dampening",)
                    ),
                    export_policy_names=export_policy_names,
                )
            )
    return tuple(peers)


def _parse_ospf_interfaces(
    root: ET.Element | None,
    interface_name: str,
) -> tuple[OspfInterfaceCloneSource, ...]:
    if root is None or not _enabled(root.findtext("enable")):
        return ()
    interfaces: list[OspfInterfaceCloneSource] = []
    for area in root.findall("./area/entry"):
        area_name = area.get("name")
        area_type_entry = area.find("./type/*")
        area_type = area_type_entry.tag if area_type_entry is not None else "normal"
        if not area_name:
            continue
        for interface in area.findall("./interface/entry"):
            if interface.get("name") != interface_name:
                continue
            link_entry = interface.find("./link-type/*")
            interfaces.append(
                OspfInterfaceCloneSource(
                    area_name=area_name,
                    area_type=area_type,
                    enabled=_enabled(interface.findtext("enable")),
                    passive=_yes(interface.findtext("passive")),
                    link_type=link_entry.tag if link_entry is not None else "broadcast",
                    metric=_int_text(interface.findtext("metric")),
                    priority=_int_text(interface.findtext("priority")),
                    hello_interval=_int_text(interface.findtext("hello-interval")),
                    dead_counts=_int_text(interface.findtext("dead-counts")),
                    retransmit_interval=_int_text(
                        interface.findtext("retransmit-interval")
                    ),
                    transit_delay=_int_text(interface.findtext("transit-delay")),
                    authentication=_first_text(
                        interface,
                        ("authentication",),
                    ),
                    bfd_profile=_first_text(interface, ("bfd/profile",)),
                    timing=_first_text(interface, ("timing",)),
                )
            )
    return tuple(interfaces)


def discover_satellite_published_routes(
    panorama: Panorama,
    serial: str,
    satellite: SatelliteConfig,
    source_interface: HubTunnelInterfaceConfig,
    vsys: str = DEFAULT_VSYS,
) -> tuple[str, ...]:
    """Resolve explicit and publish-all satellite routes from effective config."""
    if not satellite.publish_connected_routes:
        return satellite.published_routes

    effective = _read_effective_running_config(panorama, serial, vsys)
    routing = _single_routing_instance(source_interface, "spoke")
    routing_entry = _effective_routing_entry(effective, routing)
    if routing_entry is None:
        scope = routing.name + (f"/{routing.vrf}" if routing.vrf else "")
        raise LsvpnConfigurationError(
            f'Routing instance "{scope}" for satellite tunnel '
            f'"{satellite.name}" was not found in effective configuration.'
        )

    excluded_interfaces = {
        value.casefold()
        for value in (satellite.tunnel_interface, satellite.local_interface)
        if value
    }
    routes = list(satellite.published_routes)
    route_paths = (
        "./routing-table/ip/static-route/entry",
        "./routing-table/ipv6/static-route/entry",
    )
    for path in route_paths:
        for route in routing_entry.findall(path):
            destination = _first_text(route, ("destination",))
            interface = _first_text(route, ("interface",))
            if destination is None or (
                interface and interface.casefold() in excluded_interfaces
            ):
                continue
            network = _normalized_network(destination)
            if network.prefixlen == 0:
                continue
            routes.append(str(network))

    routing_interfaces = tuple(
        dict.fromkeys(
            member.text.strip()
            for member in routing_entry.findall("./interface/member")
            if member.text and member.text.strip()
        )
    )
    for interface_name in routing_interfaces:
        if interface_name.casefold() in excluded_interfaces:
            continue
        for entry in effective.findall(".//network/interface//entry"):
            if entry.get("name", "").casefold() != interface_name.casefold():
                continue
            for address in _effective_interface_addresses(entry):
                network = _normalized_network(address)
                if network.is_link_local or network.is_loopback:
                    continue
                routes.append(str(network))
    return tuple(dict.fromkeys(routes))


def _effective_routing_entry(
    root: ET.Element,
    routing: RoutingInstanceConfig,
) -> ET.Element | None:
    if routing.kind == "virtual-router":
        return next(
            (
                entry
                for entry in root.findall(".//network/virtual-router/entry")
                if entry.get("name", "").casefold() == routing.name.casefold()
            ),
            None,
        )
    router = next(
        (
            entry
            for entry in root.findall(".//network/logical-router/entry")
            if entry.get("name", "").casefold() == routing.name.casefold()
        ),
        None,
    )
    if router is None or routing.vrf is None:
        return None
    return next(
        (
            vrf
            for vrf in router.findall("./vrf/entry")
            if vrf.get("name", "").casefold() == routing.vrf.casefold()
        ),
        None,
    )


def _effective_interface_addresses(entry: ET.Element) -> tuple[str, ...]:
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


def _effective_interface_primary_address(
    root: ET.Element,
    interface_name: str,
) -> str | None:
    wanted = interface_name.casefold()
    for entry in root.findall(".//network/interface//entry"):
        if entry.get("name", "").casefold() != wanted:
            continue
        addresses = _effective_interface_addresses(entry)
        if addresses:
            return addresses[0]
    return None


def resolve_ike_local_endpoint(
    panorama: Panorama,
    serial: str,
    interface_name: str,
    address: str,
    vsys: str = DEFAULT_VSYS,
    role: str = "firewall",
) -> tuple[str, str]:
    """Resolve an IKE local address to its exact configured interface reference."""
    effective = _read_effective_running_config(panorama, serial, vsys)
    configured: list[tuple[str, str]] = []
    for entry in effective.findall(".//network/interface//entry"):
        name = entry.get("name")
        if not name:
            continue
        configured.extend(
            (name, configured_address)
            for configured_address in _effective_interface_addresses(entry)
        )
    configured = list(dict.fromkeys(configured))
    wanted = normalize_endpoint(address)
    matches = tuple(
        (name, configured_address)
        for name, configured_address in configured
        if normalize_endpoint(configured_address) == wanted
    )
    selected_matches = tuple(
        item for item in matches if item[0].casefold() == interface_name.casefold()
    )
    if selected_matches:
        return selected_matches[0]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        locations = ", ".join(
            f"{name} ({configured_address})" for name, configured_address in matches
        )
        raise LsvpnConfigurationError(
            f'The {role} IKE local address "{address}" exists on multiple '
            f"interfaces: {locations}."
        )
    selected_addresses = tuple(
        configured_address
        for name, configured_address in configured
        if name.casefold() == interface_name.casefold()
    )
    available = ", ".join(selected_addresses) or "none"
    raise LsvpnConfigurationError(
        f'The {role} IKE local address "{address}" is not configured on '
        f'interface "{interface_name}" or any other interface. Addresses found '
        f'on "{interface_name}": {available}.'
    )


def match_loopback_bgp_transit(
    spoke: DynamicRoutingCloneSource,
    hub: DynamicRoutingCloneSource,
) -> tuple[DynamicRoutingCloneSource, DynamicRoutingCloneSource]:
    """Keep reciprocal loopback BGP peers whose reachability rides over LSVPN."""
    if spoke.bgp or hub.bgp:
        return (
            DynamicRoutingCloneSource(bgp=spoke.bgp, ospf=spoke.ospf),
            DynamicRoutingCloneSource(bgp=hub.bgp, ospf=hub.ospf),
        )
    spoke_matches: list[BgpPeerCloneSource] = []
    hub_matches: list[BgpPeerCloneSource] = []
    for spoke_peer in spoke.transit_bgp:
        if spoke_peer.local_address is None:
            continue
        for hub_peer in hub.transit_bgp:
            if hub_peer.local_address is None:
                continue
            if endpoints_match(
                spoke_peer.peer_address,
                hub_peer.local_address,
            ) and endpoints_match(
                hub_peer.peer_address,
                spoke_peer.local_address,
            ):
                if spoke_peer not in spoke_matches:
                    spoke_matches.append(spoke_peer)
                if hub_peer not in hub_matches:
                    hub_matches.append(hub_peer)
    return (
        DynamicRoutingCloneSource(
            bgp=spoke.bgp,
            transit_bgp=tuple(spoke_matches),
            ospf=spoke.ospf,
        ),
        DynamicRoutingCloneSource(
            bgp=hub.bgp,
            transit_bgp=tuple(hub_matches),
            ospf=hub.ospf,
        ),
    )


def _bgp_transit_host_routes(
    source: DynamicRoutingCloneSource,
) -> tuple[str, ...]:
    """Return peer host routes needed when loopback BGP has no tunnel IGP."""
    routes: list[str] = []
    for peer in source.transit_bgp:
        addresses = _resolved_endpoint_addresses(peer.peer_address)
        for address in sorted(addresses):
            parsed = ipaddress.ip_address(address)
            routes.append(f"{parsed.compressed}/{parsed.max_prefixlen}")
    return tuple(dict.fromkeys(routes))


def _resolve_gateway_entries(
    gateway_root: ET.Element | None,
    tunnel_root: ET.Element | None,
    gateway: PortalGateway,
    vsys: str = DEFAULT_VSYS,
) -> tuple[ET.Element | None, ET.Element | None]:
    if gateway_root is not None:
        gateway_root = _vsys_scope(gateway_root, vsys)
    gateway_entries = (
        _container_entries(gateway_root, "global-protect-gateway")
        if gateway_root is not None
        else ()
    )
    tunnel_entries = (
        _container_entries(tunnel_root, "global-protect-site-to-site")
        if tunnel_root is not None
        else ()
    )
    tunnel_entry = _named_entry(tunnel_entries, gateway.name)
    if tunnel_entry is None:
        tunnel_entry = _address_entry(tunnel_entries, gateway.address)
    gateway_entry = _named_entry(gateway_entries, gateway.name)

    tunnel_interface = _first_text(tunnel_entry, ("tunnel-interface",))
    if gateway_entry is None and tunnel_interface:
        interface_matches = tuple(
            entry
            for entry in gateway_entries
            if _first_text(
                entry,
                (
                    "satellite-tunnel",
                    "satellite-tunnel-config/tunnel-interface",
                ),
            )
            == tunnel_interface
        )
        if len(interface_matches) > 1:
            names = ", ".join(
                entry.get("name", "[unnamed]") for entry in interface_matches
            )
            raise LsvpnConfigurationError(
                f'Tunnel interface "{tunnel_interface}" matches multiple '
                f"GlobalProtect gateway objects: {names}."
            )
        gateway_entry = interface_matches[0] if interface_matches else None
    return gateway_entry, tunnel_entry


def discover_hub_gateway_clone_source(
    panorama: Panorama,
    serial: str,
    gateway: PortalGateway,
    vsys: str = DEFAULT_VSYS,
) -> HubGatewayCloneSource:
    """Read the hub LSVPN gateway and its referenced interface configuration."""
    effective: ET.Element | None = None
    gateway_root = _read_effective_config(
        panorama,
        serial,
        _vsys_xpath(GATEWAY_XPATH, vsys),
    )
    tunnel_root = _read_effective_config(panorama, serial, GATEWAY_TUNNEL_XPATH)
    gateway_entry, tunnel_entry = _resolve_gateway_entries(
        gateway_root,
        tunnel_root,
        gateway,
        vsys,
    )
    if gateway_entry is None or tunnel_entry is None:
        effective = _read_effective_running_config(panorama, serial, vsys)
        effective_gateway, effective_tunnel = _resolve_gateway_entries(
            effective,
            effective,
            gateway,
            vsys,
        )
        if gateway_entry is None:
            gateway_entry = effective_gateway
        if tunnel_entry is None:
            tunnel_entry = effective_tunnel

    if gateway_entry is None and tunnel_entry is None:
        raise LsvpnConfigurationError(
            f'Portal gateway "{gateway.name}" ({gateway.address}) does not match a '
            "GlobalProtect gateway on the selected hub by name, address, or tunnel "
            "interface."
        )

    tunnel_interface_name = _first_text(
        tunnel_entry,
        (
            "tunnel-interface",
            "satellite-tunnel-config/tunnel-interface",
            "ipsec/tunnel-interface",
        ),
    ) or _first_text(
        gateway_entry,
        (
            "satellite-tunnel",
            "satellite-tunnel-config/tunnel-interface",
            "tunnel-interface",
            "remote-user-tunnel-config/tunnel-interface",
        ),
    )
    if tunnel_interface_name is None:
        raise LsvpnConfigurationError(
            f'GlobalProtect gateway "{gateway.name}" has no LSVPN tunnel interface.'
        )

    firewall = Firewall(serial=serial, vsys=vsys)
    _attach_to_panorama(firewall, panorama)
    interfaces = TunnelInterface.refreshall(firewall, running_config=True, add=False)
    source_interface = next(
        (
            interface
            for interface in interfaces
            if str(interface.name).casefold() == tunnel_interface_name.casefold()
        ),
        None,
    )
    if source_interface is None and effective is not None:
        source_interface = _effective_tunnel_interface(
            effective,
            tunnel_interface_name,
        )
    if source_interface is None:
        if effective is None:
            effective = _read_effective_running_config(panorama, serial, vsys)
        source_interface = _effective_tunnel_interface(
            effective,
            tunnel_interface_name,
        )
    if source_interface is None:
        raise LsvpnConfigurationError(
            f'LSVPN tunnel interface "{tunnel_interface_name}" referenced by gateway '
            f'"{gateway.name}" was not found on the selected hub firewall.'
        )

    virtual_routers = VirtualRouter.refreshall(firewall, running_config=True, add=False)
    zones = Zone.refreshall(firewall, running_config=True, add=False)
    vr_names = tuple(
        str(router.name)
        for router in virtual_routers
        if tunnel_interface_name in (router.interface or [])
    )
    routing_instances = tuple(
        RoutingInstanceConfig("virtual-router", name) for name in vr_names
    )
    zone_names = tuple(
        str(zone.name)
        for zone in zones
        if tunnel_interface_name in (zone.interface or [])
    )
    if effective is None and (not vr_names or not zone_names):
        effective = _read_effective_running_config(panorama, serial, vsys)
    if effective is not None:
        effective_vrs, effective_zones = _effective_interface_memberships(
            effective,
            tunnel_interface_name,
            vsys,
        )
        vr_names = tuple(dict.fromkeys((*vr_names, *effective_vrs)))
        zone_names = tuple(dict.fromkeys((*zone_names, *effective_zones)))
        effective_routing = _effective_routing_memberships(
            effective,
            tunnel_interface_name,
        )
        if effective_routing:
            routing_instances = tuple(
                dict.fromkeys((*routing_instances, *effective_routing))
            )

    general = gateway_entry
    network = tunnel_entry
    ipsec_profile = _first_text(
        network,
        (
            "client/ipsec-crypto-profile",
            "ipsec/ipsec-crypto-profile",
            "ipsec-crypto-profile",
            "satellite-tunnel-config/ipsec-crypto-profile",
        ),
    ) or _first_text(general, ("satellite-tunnel-config/ipsec-crypto-profile",))
    monitor_enabled = _first_text(
        network,
        (
            "client/tunnel-monitor/enable",
            "tunnel-monitor/enable",
            "ipsec/tunnel-monitor/enable",
        ),
    ) or _first_text(general, ("satellite-tunnel-config/tunnel-monitor/enable",))

    source_name = gateway.name
    if gateway_entry is not None:
        configured_name = gateway_entry.get("name")
        if configured_name:
            source_name = configured_name

    return HubGatewayCloneSource(
        name=source_name,
        address=gateway.address,
        external_interface=_first_text(
            general, ("local-address/interface", "external-interface")
        )
        or _first_text(network, ("local-address/interface", "external-interface")),
        external_ipv4=_first_text(
            general, ("local-address/ip/ipv4", "local-address/ipv4")
        )
        or _first_text(network, ("local-address/ip/ipv4", "local-address/ipv4")),
        external_ipv6=_first_text(
            general, ("local-address/ip/ipv6", "local-address/ipv6")
        )
        or _first_text(network, ("local-address/ip/ipv6", "local-address/ipv6")),
        floating_ipv4=_first_text(
            general, ("local-address/floating-ip/ipv4", "local-address/floating-ip")
        ),
        floating_ipv6=_first_text(general, ("local-address/floating-ip/ipv6",)),
        tunnel_interface=HubTunnelInterfaceConfig(
            name=tunnel_interface_name,
            ip_addresses=_strings(source_interface.ip),
            ipv6_enabled=bool(source_interface.ipv6_enabled),
            management_profile=_string(source_interface.management_profile),
            mtu=source_interface.mtu,
            netflow_profile=_string(source_interface.netflow_profile),
            comment=_string(source_interface.comment),
            virtual_routers=vr_names,
            zones=zone_names,
            routing_instances=routing_instances,
        ),
        ipsec_crypto_profile=ipsec_profile,
        tunnel_monitor_enabled=_yes(monitor_enabled),
        tunnel_monitor_destination=_first_text(
            network,
            (
                "client/tunnel-monitor/destination-ip",
                "tunnel-monitor/destination-ip",
                "ipsec/tunnel-monitor/destination-ip",
            ),
        ),
        tunnel_monitor_profile=_first_text(
            network,
            (
                "client/tunnel-monitor/tunnel-monitor-profile",
                "client/tunnel-monitor/profile",
                "tunnel-monitor/tunnel-monitor-profile",
                "tunnel-monitor/profile",
            ),
        ),
        tunnel_monitor_source=_first_text(
            network,
            (
                "client/tunnel-monitor/source-ip",
                "client/tunnel-monitor/source",
                "tunnel-monitor/source-ip",
                "tunnel-monitor/source",
            ),
        ),
        access_routes=_members(
            general,
            (
                "satellite-tunnel-config/access-route/member",
                "satellite-tunnel-config/access-routes/member",
                "access-route/member",
            ),
        ),
        client_ip_pools=_members(
            general,
            (
                "satellite-tunnel-config/ip-pool/member",
                "satellite-tunnel-config/client-ip-pool/member",
                "ip-pool/member",
            ),
        )
        or _members(network, ("client/ip-pool/member",)),
        dns_primary=_first_text(
            general, ("satellite-tunnel-config/dns-server/primary",)
        ),
        dns_secondary=_first_text(
            general, ("satellite-tunnel-config/dns-server/secondary",)
        ),
        dns_suffix=_first_text(general, ("satellite-tunnel-config/dns-suffix",)),
    )


def build_standard_clone_plan(
    satellite: SatelliteConfig,
    runtime: GatewayRuntime | None = None,
    portal_gateway: PortalGateway | None = None,
    hub_gateway: HubGatewayCloneSource | None = None,
    pre_shared_key: str | None = None,
    crypto: StandardCryptoSettings | None = None,
    spoke_tunnel_source: HubTunnelInterfaceConfig | None = None,
    replacement_spoke_tunnel_interface: str | None = None,
    replacement_hub_tunnel_interface: str | None = None,
    resolved_published_routes: tuple[str, ...] | None = None,
    tunnel_addresses: TunnelAddressPair | None = None,
    spoke_dynamic_routing: DynamicRoutingCloneSource | None = None,
    hub_dynamic_routing: DynamicRoutingCloneSource | None = None,
    spoke_identity: str | None = None,
    spoke_hostname: str | None = None,
    hub_hostname: str | None = None,
) -> StandardIpsecClonePlan:
    """Map reusable satellite settings into a standard auto-key tunnel plan."""
    selected_crypto = crypto or StandardCryptoSettings()
    selected_psk = pre_shared_key or generate_pre_shared_key()
    spoke_dynamic = spoke_dynamic_routing or DynamicRoutingCloneSource()
    hub_dynamic = hub_dynamic_routing or DynamicRoutingCloneSource()
    required_inputs: list[str] = []
    warnings: list[str] = []

    active_gateway_address = runtime.gateway_address if runtime else None
    peer_address = (
        portal_gateway.address
        if portal_gateway
        else active_gateway_address or satellite.portal_address
    )
    if (
        active_gateway_address
        and satellite.portal_address
        and not endpoints_match(active_gateway_address, satellite.portal_address)
    ):
        resolution = "." if portal_gateway else "; using the active gateway."
        warnings.insert(
            0,
            f"Active gateway address {active_gateway_address} differs from configured "
            f"portal address {satellite.portal_address}{resolution}",
        )
    elif active_gateway_address is None and satellite.portal_address is not None:
        warnings.insert(
            0,
            "No active gateway address was reported; using the configured portal "
            "address as the peer candidate.",
        )

    if runtime and runtime.error:
        warnings.insert(0, f"Current gateway lookup failed: {runtime.error}")
    if (
        portal_gateway
        and active_gateway_address
        and not endpoints_match(portal_gateway.address, active_gateway_address)
    ):
        warnings.insert(
            0,
            f"Selected portal gateway {portal_gateway.address} differs from "
            f"active gateway {active_gateway_address}; using the confirmed portal "
            "gateway.",
        )
    if peer_address is None:
        required_inputs.append("hub IKE peer address")
        warnings.insert(
            0,
            "Neither the satellite configuration nor runtime state contains a peer "
            "address.",
        )
    if satellite.local_certificate or satellite.certificate_profile:
        warnings.append(
            "LSVPN enrollment certificate settings are not automatically reusable "
            "as standard IKE authentication."
        )
    if tunnel_addresses is None:
        required_inputs.append("replacement tunnel address pool")
    if set(spoke_dynamic.protocols) != set(hub_dynamic.protocols):
        required_inputs.append("matching hub/spoke dynamic-routing configuration")
        warnings.append(
            "Dynamic routing is configured on only one endpoint or uses different "
            "protocols; the replacement requires matching BGP/OSPF configuration."
        )
    loopback_bgp_without_ospf = (
        (spoke_dynamic.transit_bgp or hub_dynamic.transit_bgp)
        and not spoke_dynamic.ospf
        and not hub_dynamic.ospf
    )
    spoke_bgp_host_routes = (
        _bgp_transit_host_routes(spoke_dynamic) if loopback_bgp_without_ospf else ()
    )
    hub_bgp_host_routes = (
        _bgp_transit_host_routes(hub_dynamic) if loopback_bgp_without_ospf else ()
    )
    if loopback_bgp_without_ospf and (
        not spoke_bgp_host_routes or not hub_bgp_host_routes
    ):
        required_inputs.append("loopback BGP peer address resolution")
        warnings.append(
            "BGP uses reciprocal loopback peers but OSPF is not configured on "
            "the LSVPN tunnel, and at least one peer address could not be resolved "
            "for replacement static host-route generation."
        )
    elif loopback_bgp_without_ospf:
        warnings.append(
            "BGP uses reciprocal loopback peers without OSPF on the LSVPN "
            "tunnel. The existing loopback-sourced BGP sessions are preserved, "
            "and static host routes to their peer addresses are placed on the "
            "replacement tunnel interfaces."
        )
    if satellite.publish_connected_routes and resolved_published_routes is None:
        warnings.append(
            "The satellite publishes all connected and static routes; only its "
            "explicit published subnet list is available for automatic hub route "
            "generation, so the additional runtime routes must be reviewed."
        )
        required_inputs.append("satellite connected/static route review")
    if tunnel_addresses is None and (
        satellite.tunnel_monitor_enabled
        or (hub_gateway is not None and hub_gateway.tunnel_monitor_enabled)
    ):
        warnings.append(
            "Tunnel monitoring is deferred because the replacement tunnel "
            "interfaces are intentionally unnumbered. Assign point-to-point "
            "addresses before enabling monitoring."
        )
        required_inputs.append("replacement tunnel-monitor addressing")

    uses_dynamic_routing = bool(spoke_dynamic.protocols or hub_dynamic.protocols)
    spoke_routes = (
        ()
        if uses_dynamic_routing
        else (
            hub_gateway.access_routes
            if hub_gateway is not None and hub_gateway.access_routes
            else (("0.0.0.0/0",) if hub_gateway is not None else ())
        )
    )
    hub_routes = (
        ()
        if uses_dynamic_routing
        else (
            resolved_published_routes
            if resolved_published_routes is not None
            else satellite.published_routes
        )
    )
    spoke_routes = tuple(dict.fromkeys((*spoke_routes, *spoke_bgp_host_routes)))
    hub_routes = tuple(dict.fromkeys((*hub_routes, *hub_bgp_host_routes)))

    if spoke_hostname and hub_hostname:
        tunnel_name = _endpoint_object_name(
            hub_hostname,
            spoke_hostname,
            satellite.name,
        )
        ike_gateway_name = _ike_gateway_name(tunnel_name)
    else:
        tunnel_name = f"{satellite.name}-standard"
        ike_gateway_name = f"{satellite.name}-ike"
    if spoke_identity and not (spoke_hostname and hub_hostname):
        identity_suffix = re.sub(r"[^A-Za-z0-9_.-]", "-", spoke_identity)[-12:]
        tunnel_name = _scoped_replacement_name(
            satellite.name, identity_suffix, "-standard"
        )
        ike_gateway_name = _scoped_replacement_name(
            satellite.name, identity_suffix, "-ike"
        )
    return StandardIpsecClonePlan(
        source_name=satellite.name,
        spoke_identity=spoke_identity,
        spoke_hostname=spoke_hostname,
        hub_hostname=hub_hostname,
        tunnel_name=tunnel_name,
        ike_gateway_name=ike_gateway_name,
        tunnel_interface=satellite.tunnel_interface,
        replacement_spoke_tunnel_interface=replacement_spoke_tunnel_interface,
        replacement_hub_tunnel_interface=replacement_hub_tunnel_interface,
        spoke_tunnel_source=spoke_tunnel_source,
        spoke_tunnel_address=tunnel_addresses.spoke if tunnel_addresses else None,
        hub_tunnel_address=tunnel_addresses.hub if tunnel_addresses else None,
        spoke_dynamic_routing=spoke_dynamic,
        hub_dynamic_routing=hub_dynamic,
        local_interface=satellite.local_interface,
        local_address=satellite.local_ipv4 or satellite.local_ipv6,
        local_address_reference=(
            satellite.local_address_reference
            or satellite.local_ipv4
            or satellite.local_ipv6
        ),
        configured_portal_address=satellite.portal_address,
        active_gateway_name=runtime.gateway_name if runtime else None,
        active_gateway_address=active_gateway_address,
        portal_gateway_name=portal_gateway.name if portal_gateway else None,
        portal_gateway_address=portal_gateway.address if portal_gateway else None,
        hub_gateway=hub_gateway,
        peer_address_candidate=peer_address,
        pre_shared_key=selected_psk,
        crypto=selected_crypto,
        published_routes=satellite.published_routes,
        spoke_static_routes=spoke_routes,
        hub_static_routes=hub_routes,
        spoke_route_metric=(portal_gateway.priority * 10)
        if portal_gateway is not None and portal_gateway.priority is not None
        else 10,
        proxy_id_mode="IKEv2 route-based default any/any (no explicit proxy IDs)",
        anti_replay=satellite.anti_replay,
        copy_tos=satellite.copy_tos,
        tunnel_monitor_enabled=satellite.tunnel_monitor_enabled,
        tunnel_monitor_destination=satellite.tunnel_monitor_destination,
        tunnel_monitor_profile=satellite.tunnel_monitor_profile,
        required_inputs=tuple(dict.fromkeys(required_inputs)),
        warnings=tuple(warnings),
    )


def build_standard_ipsec_objects(
    plan: StandardIpsecClonePlan,
    shared_spoke_names: bool = False,
) -> StandardIpsecReplacementObjects:
    """Build unapplied PAN-OS SDK objects for both replacement endpoints."""
    if plan.peer_address_candidate is None:
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has no hub peer address.'
        )
    if "loopback BGP peer address resolution" in plan.required_inputs:
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has loopback BGP without '
            "OSPF on the LSVPN interface, but a peer address could not be "
            "resolved for a replacement static host route."
        )
    if plan.local_interface is None or plan.local_address is None:
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has no spoke local endpoint.'
        )
    if plan.replacement_spoke_tunnel_interface is None:
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has no allocated spoke '
            "tunnel interface."
        )
    if plan.hub_gateway is None:
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has no hub configuration.'
        )

    hub = plan.hub_gateway
    if plan.replacement_hub_tunnel_interface is None:
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has no allocated hub '
            "tunnel interface."
        )
    if plan.spoke_tunnel_source is None:
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has no spoke tunnel '
            "interface clone source."
        )
    if plan.spoke_tunnel_address is None or plan.hub_tunnel_address is None:
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has no point-to-point '
            "tunnel addresses."
        )
    if set(plan.spoke_dynamic_routing.protocols) != set(
        plan.hub_dynamic_routing.protocols
    ):
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has mismatched dynamic '
            "routing protocols between hub and spoke."
        )
    hub_address = hub.external_ipv4 or hub.external_ipv6 or hub.address
    if hub.external_interface is None or hub_address is None:
        raise LsvpnConfigurationError(
            f'Replacement tunnel "{plan.tunnel_name}" has no hub local endpoint.'
        )

    crypto = plan.crypto

    def crypto_profiles() -> tuple[IkeCryptoProfile, IpsecCryptoProfile]:
        return (
            IkeCryptoProfile(
                crypto.ike_profile_name,
                dh_group=list(crypto.ike_dh_groups),
                authentication=list(crypto.ike_authentication),
                encryption=list(crypto.ike_encryption),
                lifetime_hours=crypto.ike_lifetime_hours,
            ),
            IpsecCryptoProfile(
                crypto.ipsec_profile_name,
                esp_encryption=list(crypto.esp_encryption),
                esp_authentication=list(crypto.esp_authentication),
                dh_group=crypto.pfs_group,
                lifetime_hours=crypto.ipsec_lifetime_hours,
            ),
        )

    spoke_ike_crypto, spoke_ipsec_crypto = crypto_profiles()
    hub_ike_crypto, hub_ipsec_crypto = crypto_profiles()

    spoke_ike_name = (
        plan.shared_spoke_ike_gateway_name
        if shared_spoke_names
        else plan.ike_gateway_name
    )
    spoke_tunnel_name = (
        plan.shared_spoke_tunnel_name if shared_spoke_names else plan.tunnel_name
    )
    spoke_ike = IkeGateway(
        spoke_ike_name,
        version=crypto.ike_version,
        peer_ip_type=_peer_address_type(plan.peer_address_candidate),
        peer_ip_value=normalize_endpoint(plan.peer_address_candidate),
        interface=plan.local_interface,
        local_ip_address_type="ip",
        local_ip_address=plan.local_address_reference,
        auth_type="pre-shared-key",
        pre_shared_key=plan.pre_shared_key,
        enable_nat_traversal=True,
        enable_fragmentation=False,
        ikev2_crypto_profile=crypto.ike_profile_name,
        enable_liveness_check=True,
        liveness_check_interval=5,
    )
    spoke_tunnel = IpsecTunnel(
        spoke_tunnel_name,
        tunnel_interface=plan.replacement_spoke_tunnel_interface,
        type="auto-key",
        ak_ike_gateway=[spoke_ike_name],
        ak_ipsec_crypto_profile=crypto.ipsec_profile_name,
        anti_replay=plan.anti_replay,
        copy_tos=plan.copy_tos,
        enable_tunnel_monitor=plan.tunnel_monitor_enabled,
        tunnel_monitor_dest_ip=_address_only(plan.hub_tunnel_address),
        tunnel_monitor_profile=plan.tunnel_monitor_profile,
    )

    dynamic_spoke = _requires_dynamic_ike_peer(plan.local_address)
    ike_identity = (
        _ike_identity(plan.spoke_identity, plan.source_name) if dynamic_spoke else None
    )
    if dynamic_spoke:
        spoke_ike.local_id_type = "keyid"
        spoke_ike.local_id_value = ike_identity

    hub_ike = IkeGateway(
        plan.ike_gateway_name,
        version=crypto.ike_version,
        peer_ip_type=(
            "dynamic" if dynamic_spoke else _peer_address_type(plan.local_address)
        ),
        peer_ip_value=(
            None if dynamic_spoke else normalize_endpoint(plan.local_address)
        ),
        interface=hub.external_interface,
        local_ip_address_type="ip",
        local_ip_address=hub.external_address_reference or hub_address,
        auth_type="pre-shared-key",
        pre_shared_key=plan.pre_shared_key,
        enable_nat_traversal=True,
        enable_fragmentation=False,
        ikev2_crypto_profile=crypto.ike_profile_name,
        enable_liveness_check=True,
        liveness_check_interval=5,
        peer_id_type="keyid" if dynamic_spoke else None,
        peer_id_value=ike_identity,
        peer_id_check="exact" if dynamic_spoke else None,
    )
    hub_tunnel = IpsecTunnel(
        plan.tunnel_name,
        tunnel_interface=plan.replacement_hub_tunnel_interface,
        type="auto-key",
        ak_ike_gateway=[plan.ike_gateway_name],
        ak_ipsec_crypto_profile=crypto.ipsec_profile_name,
        anti_replay=plan.anti_replay,
        copy_tos=plan.copy_tos,
        enable_tunnel_monitor=hub.tunnel_monitor_enabled,
        tunnel_monitor_dest_ip=_address_only(plan.spoke_tunnel_address),
        tunnel_monitor_profile=hub.tunnel_monitor_profile,
    )

    spoke_interface, spoke_routing, spoke_zone = _build_endpoint_network_objects(
        plan,
        plan.spoke_tunnel_source,
        plan.replacement_spoke_tunnel_interface,
        plan.spoke_static_routes,
        "spoke",
        plan.spoke_route_metric,
        plan.spoke_tunnel_address,
        plan.hub_tunnel_address,
        plan.spoke_dynamic_routing,
        spoke_tunnel_name,
    )
    hub_interface, hub_routing, hub_zone = _build_endpoint_network_objects(
        plan,
        hub.tunnel_interface,
        plan.replacement_hub_tunnel_interface,
        plan.hub_static_routes,
        "hub",
        10,
        plan.hub_tunnel_address,
        plan.spoke_tunnel_address,
        plan.hub_dynamic_routing,
        plan.tunnel_name,
    )
    return StandardIpsecReplacementObjects(
        spoke=StandardIpsecEndpointObjects(
            spoke_ike_crypto,
            spoke_ipsec_crypto,
            spoke_ike,
            spoke_tunnel,
            spoke_interface,
            spoke_routing,
            spoke_zone,
        ),
        hub=StandardIpsecEndpointObjects(
            hub_ike_crypto,
            hub_ipsec_crypto,
            hub_ike,
            hub_tunnel,
            hub_interface,
            hub_routing,
            hub_zone,
        ),
    )


def apply_endpoint_variable_references(
    endpoint: StandardIpsecEndpointObjects,
    references: EndpointVariableReferences,
    concrete_local_tunnel: str,
    concrete_remote_tunnel: str,
) -> None:
    """Replace generated endpoint values with reusable Panorama variables.

    Objects are first built from concrete values so address-family and routing
    validation remains strict.  This final transformation changes only the XML
    values that can legitimately vary per device.
    """
    local_host = _address_only(concrete_local_tunnel)
    remote_host = _address_only(concrete_remote_tunnel)
    endpoint.ike_gateway.local_ip_address = references.ike_local
    if endpoint.ike_gateway.peer_ip_type != "dynamic":
        endpoint.ike_gateway.peer_ip_value = references.ike_peer
    endpoint.ike_gateway.pre_shared_key = references.pre_shared_key
    if references.ike_identity is not None:
        if endpoint.ike_gateway.local_id_value is not None:
            endpoint.ike_gateway.local_id_type = "fqdn"
            endpoint.ike_gateway.local_id_value = references.ike_identity
        if endpoint.ike_gateway.peer_id_value is not None:
            endpoint.ike_gateway.peer_id_type = "fqdn"
            endpoint.ike_gateway.peer_id_value = references.ike_identity

    if endpoint.tunnel_interface.ip:
        endpoint.tunnel_interface.ip = [references.tunnel_interface_address]
    for address in endpoint.tunnel_interface.findall(IPv6Address):
        address.name = references.tunnel_interface_address
    if endpoint.ipsec_tunnel.tunnel_monitor_dest_ip is not None:
        endpoint.ipsec_tunnel.tunnel_monitor_dest_ip = references.tunnel_peer

    destination_map = dict(references.route_destinations)
    for item in _panobject_tree(endpoint.routing_object):
        if isinstance(item, (BgpPeer, VrfBgpPeer)):
            if isinstance(item, BgpPeer):
                if item.local_interface_ip == local_host:
                    item.local_interface_ip = references.tunnel_local
                if item.peer_address_ip == remote_host:
                    item.peer_address_ip = references.tunnel_peer
            else:
                if item.local_address_ip == local_host:
                    item.local_address_ip = references.tunnel_local
                if item.peer_address_value == remote_host:
                    item.peer_address_value = references.tunnel_peer
        if isinstance(
            item, (StaticRoute, StaticRouteV6, VrfStaticRoute, VrfStaticRouteV6)
        ):
            destination = str(item.destination or "")
            replacement = destination_map.get(destination)
            if replacement is not None:
                item.destination = replacement


def _panobject_tree(root: object) -> tuple[object, ...]:
    result = [root]
    for child in getattr(root, "children", ()):  # PanObject is intentionally broad.
        result.extend(_panobject_tree(child))
    return tuple(result)


def _single_routing_instance(
    source: HubTunnelInterfaceConfig,
    endpoint: str,
) -> RoutingInstanceConfig:
    memberships = source.routing_instances or tuple(
        RoutingInstanceConfig("virtual-router", name) for name in source.virtual_routers
    )
    if len(memberships) != 1:
        names = (
            ", ".join(
                f"{item.kind}:{item.name}" + (f"/{item.vrf}" if item.vrf else "")
                for item in memberships
            )
            or "none"
        )
        raise LsvpnConfigurationError(
            f'The {endpoint} source interface "{source.name}" must belong to '
            f"exactly one routing instance; found {names}."
        )
    return memberships[0]


def _single_zone(source: HubTunnelInterfaceConfig, endpoint: str) -> str:
    if len(source.zones) != 1:
        names = ", ".join(source.zones) or "none"
        raise LsvpnConfigurationError(
            f'The {endpoint} source interface "{source.name}" must belong to '
            f"exactly one zone; found {names}."
        )
    return source.zones[0]


def _normalized_network(
    destination: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(destination, strict=False)
    except ValueError as exc:
        raise LsvpnConfigurationError(
            f'Route destination "{destination}" is not a valid IPv4 or IPv6 network.'
        ) from exc


def _address_only(address: str) -> str:
    try:
        return ipaddress.ip_interface(address).ip.compressed
    except ValueError as exc:
        raise LsvpnConfigurationError(
            f'Tunnel interface address "{address}" is invalid.'
        ) from exc


def _route_name(tunnel_name: str, endpoint: str, index: int) -> str:
    suffix = f"-{endpoint}-{index}"
    return f"{tunnel_name[: 63 - len(suffix)]}{suffix}"


def _build_endpoint_network_objects(
    plan: StandardIpsecClonePlan,
    source: HubTunnelInterfaceConfig,
    interface_name: str,
    destinations: tuple[str, ...],
    endpoint: Literal["spoke", "hub"],
    metric: int,
    local_address: str,
    remote_address: str,
    dynamic_routing: DynamicRoutingCloneSource,
    object_name: str | None = None,
) -> tuple[TunnelInterface, VirtualRouter | LogicalRouter, Zone]:
    routing = _single_routing_instance(source, endpoint)
    zone_name = _single_zone(source, endpoint)
    parsed_local_address = ipaddress.ip_interface(local_address)
    interface = TunnelInterface(
        interface_name,
        ip=[local_address] if parsed_local_address.version == 4 else [],
        ipv6_enabled=source.ipv6_enabled
        or any(_normalized_network(route).version == 6 for route in destinations),
        management_profile=source.management_profile,
        mtu=source.mtu,
        netflow_profile=source.netflow_profile,
        comment=f"Standard IPsec replacement for {plan.source_name}",
    )
    if parsed_local_address.version == 6:
        interface.add(IPv6Address(local_address, enable_on_interface=True))
    zone = Zone(zone_name, mode="layer3", interface=[interface_name])

    if routing.kind == "virtual-router":
        routing_object: VirtualRouter | LogicalRouter = VirtualRouter(
            routing.name,
            interface=[interface_name],
        )
        route_parent: VirtualRouter | Vrf = routing_object
    else:
        if routing.vrf is None:
            raise LsvpnConfigurationError(
                f'Logical router "{routing.name}" has no VRF for {endpoint} '
                f'interface "{source.name}".'
            )
        routing_object = LogicalRouter(routing.name, vrf=[routing.vrf])
        route_parent = Vrf(routing.vrf, interface=[interface_name])
        routing_object.add(route_parent)

    for index, destination in enumerate(destinations, start=1):
        network = _normalized_network(destination)
        name = _route_name(object_name or plan.tunnel_name, endpoint, index)
        if isinstance(route_parent, Vrf):
            route = (
                VrfStaticRoute(
                    name,
                    destination=str(network),
                    interface=interface_name,
                    nexthop_type=None,
                    metric=metric,
                )
                if network.version == 4
                else VrfStaticRouteV6(
                    name,
                    destination=str(network),
                    interface=interface_name,
                    nexthop_type=None,
                    metric=metric,
                )
            )
        else:
            route = (
                StaticRoute(
                    name,
                    destination=str(network),
                    interface=interface_name,
                    nexthop_type=None,
                    metric=metric,
                )
                if network.version == 4
                else StaticRouteV6(
                    name,
                    destination=str(network),
                    interface=interface_name,
                    nexthop_type=None,
                    metric=metric,
                )
            )
        route_parent.add(route)
    _add_dynamic_routing(
        routing_object,
        route_parent,
        interface_name,
        local_address,
        remote_address,
        dynamic_routing,
    )
    return interface, routing_object, zone


def _add_dynamic_routing(
    routing_object: VirtualRouter | LogicalRouter,
    route_parent: VirtualRouter | Vrf,
    interface_name: str,
    local_address: str,
    remote_address: str,
    source: DynamicRoutingCloneSource,
) -> None:
    if len(source.bgp) > 1:
        raise LsvpnConfigurationError(
            f'Interface "{interface_name}" resolves to multiple BGP peers.'
        )
    if len(source.ospf) > 1:
        raise LsvpnConfigurationError(
            f'Interface "{interface_name}" resolves to multiple OSPF areas.'
        )
    local_ip = _address_only(local_address)
    remote_ip = _address_only(remote_address)
    if source.ospf and ipaddress.ip_address(local_ip).version != 4:
        raise LsvpnConfigurationError(
            "IPv6 tunnel links with OSPF require OSPFv3, which is not yet "
            "supported; use an IPv4 tunnel address pool for OSPF replacements."
        )

    if source.bgp:
        bgp_source = source.bgp[0]
        peer_name = _replacement_dynamic_name(bgp_source.peer_name)
        if isinstance(route_parent, Vrf):
            group = VrfBgpPeerGroup(
                bgp_source.peer_group_name,
                enable=True,
                type=bgp_source.peer_group_type,
                address_family_ipv4=bgp_source.address_family_ipv4,
                address_family_ipv6=bgp_source.address_family_ipv6,
                filtering_profile_ipv4=bgp_source.filtering_profile_ipv4,
                filtering_profile_ipv6=bgp_source.filtering_profile_ipv6,
                connection_options_timers=bgp_source.timer_profile,
                connection_options_multihop=bgp_source.multihop,
                connection_options_authentication=bgp_source.authentication,
                connection_options_dampening=bgp_source.dampening_profile,
            )
            group.add(
                VrfBgpPeer(
                    peer_name,
                    enable=bgp_source.enabled,
                    peer_as=int(bgp_source.peer_as),
                    local_address_interface=interface_name,
                    local_address_ip=local_ip,
                    peer_address_type="ip",
                    peer_address_value=remote_ip,
                    bfd_profile=bgp_source.bfd_profile,
                )
            )
            route_parent.add(group)
        else:
            bgp = Bgp()
            group = BgpPeerGroup(
                bgp_source.peer_group_name,
                enable=True,
                type=bgp_source.peer_group_type,
            )
            group.add(
                BgpPeer(
                    peer_name,
                    enable=bgp_source.enabled,
                    peer_as=bgp_source.peer_as,
                    enable_mp_bgp=ipaddress.ip_address(remote_ip).version == 6,
                    address_family_identifier=(
                        "ipv6" if ipaddress.ip_address(remote_ip).version == 6 else None
                    ),
                    subsequent_address_unicast=(
                        True if ipaddress.ip_address(remote_ip).version == 6 else None
                    ),
                    local_interface=interface_name,
                    local_interface_ip=local_ip,
                    peer_address_ip=remote_ip,
                    connection_authentication=bgp_source.authentication,
                    connection_keep_alive_interval=bgp_source.keep_alive_interval,
                    connection_min_route_adv_interval=(
                        bgp_source.min_route_adv_interval
                    ),
                    connection_multihop=bgp_source.multihop,
                    connection_open_delay_time=bgp_source.open_delay_time,
                    connection_hold_time=bgp_source.hold_time,
                    connection_idle_hold_time=bgp_source.idle_hold_time,
                    bfd_profile=bgp_source.bfd_profile,
                )
            )
            bgp.add(group)
            routing_object.add(bgp)

    if source.ospf:
        ospf_source = source.ospf[0]
        if isinstance(route_parent, Vrf):
            area = VrfOspfArea(
                ospf_source.area_name,
                type=ospf_source.area_type,
            )
            area.add(
                VrfOspfAreaInterface(
                    interface_name,
                    enable=ospf_source.enabled,
                    passive=ospf_source.passive,
                    link_type="p2p",
                    metric=ospf_source.metric,
                    priority=ospf_source.priority,
                    authentication=ospf_source.authentication,
                    bfd_profile=ospf_source.bfd_profile,
                    timing=ospf_source.timing,
                )
            )
            route_parent.add(area)
        else:
            ospf = Ospf(enable=True)
            area = OspfArea(ospf_source.area_name, type=ospf_source.area_type)
            area.add(
                OspfAreaInterface(
                    interface_name,
                    enable=ospf_source.enabled,
                    passive=ospf_source.passive,
                    link_type="p2p",
                    metric=ospf_source.metric,
                    priority=ospf_source.priority,
                    hello_interval=ospf_source.hello_interval,
                    dead_counts=ospf_source.dead_counts,
                    retransmit_interval=ospf_source.retransmit_interval,
                    transit_delay=ospf_source.transit_delay,
                    authentication=ospf_source.authentication,
                )
            )
            ospf.add(area)
            routing_object.add(ospf)


def _replacement_dynamic_name(name: str) -> str:
    suffix = "-standard"
    return f"{name[: 63 - len(suffix)]}{suffix}"


def _scoped_replacement_name(source: str, identity: str, suffix: str) -> str:
    tail = f"-{identity}{suffix}"
    return f"{source[: 63 - len(tail)]}{tail}"


def _safe_object_name_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "-", value).strip("-.")
    return cleaned or "unnamed"


def _endpoint_object_name(hub: str, spoke: str, source: str) -> str:
    """Build a readable endpoint name with a deterministic three-digit suffix."""
    safe_hub = _safe_object_name_part(hub)
    safe_spoke = _safe_object_name_part(spoke)
    identity = f"{safe_hub.casefold()}\0{safe_spoke.casefold()}\0{source.casefold()}"
    number = (
        int.from_bytes(hashlib.sha256(identity.encode()).digest()[:4], "big") % 1000
    )
    suffix = f"-{number:03d}"
    separator = "-to-"
    # Reserve four characters for the IKE gateway's ``-ike`` suffix so both
    # related objects retain the complete hub/spoke identity.
    available = 59 - len(separator) - len(suffix)
    hub_budget = max(1, available // 2)
    spoke_budget = max(1, available - hub_budget)
    return f"{safe_hub[:hub_budget]}{separator}{safe_spoke[:spoke_budget]}{suffix}"


def _ike_gateway_name(tunnel_name: str) -> str:
    return f"{tunnel_name[:59]}-ike"


def stage_standard_ipsec_objects(
    panorama: Panorama,
    spoke_template_name: str,
    hub_template_name: str,
    replacements: tuple[StandardIpsecReplacementObjects, ...],
    spoke_vsys_name: str = DEFAULT_VSYS,
    hub_vsys_name: str = DEFAULT_VSYS,
) -> StagedStandardIpsecConfiguration:
    """Attach replacement SDK objects to local template trees without API writes."""
    if spoke_template_name.casefold() == hub_template_name.casefold():
        raise LsvpnConfigurationError(
            "Spoke and hub replacement objects cannot be staged in the same "
            "template because their endpoint-specific gateway settings conflict."
        )
    spoke_template = Template(spoke_template_name)
    hub_template = Template(hub_template_name)
    panorama.add(spoke_template)
    panorama.add(hub_template)
    spoke_vsys = Vsys(spoke_vsys_name)
    hub_vsys = Vsys(hub_vsys_name)
    spoke_template.add(spoke_vsys)
    hub_template.add(hub_vsys)

    for template, template_vsys, side_name in (
        (spoke_template, spoke_vsys, "spoke"),
        (hub_template, hub_vsys, "hub"),
    ):
        added_profiles: set[tuple[type[object], str]] = set()
        routing_objects: dict[
            tuple[type[VirtualRouter] | type[LogicalRouter], str],
            VirtualRouter | LogicalRouter,
        ] = {}
        zones: dict[str, Zone] = {}
        spoke_objects: set[str] = set()
        for replacement in replacements:
            endpoint = replacement.spoke if side_name == "spoke" else replacement.hub
            if side_name == "spoke":
                key = str(endpoint.ipsec_tunnel.name).casefold()
                if key in spoke_objects:
                    continue
                spoke_objects.add(key)
            for profile in (
                endpoint.ike_crypto_profile,
                endpoint.ipsec_crypto_profile,
            ):
                profile_key = (type(profile), str(profile.name))
                if profile_key not in added_profiles:
                    template.add(profile)
                    added_profiles.add(profile_key)
            template.add(endpoint.ike_gateway)
            template.add(endpoint.ipsec_tunnel)
            template.add(endpoint.tunnel_interface)

            routing_key = (
                type(endpoint.routing_object),
                str(endpoint.routing_object.name),
            )
            existing_routing = routing_objects.get(routing_key)
            if existing_routing is None:
                template.add(endpoint.routing_object)
                routing_objects[routing_key] = endpoint.routing_object
            else:
                _merge_routing_objects(existing_routing, endpoint.routing_object)

            zone_key = str(endpoint.zone.name).casefold()
            existing_zone = zones.get(zone_key)
            if existing_zone is None:
                template_vsys.add(endpoint.zone)
                zones[zone_key] = endpoint.zone
            else:
                existing_zone.interface = list(
                    dict.fromkeys(
                        (
                            *(existing_zone.interface or []),
                            *(endpoint.zone.interface or []),
                        )
                    )
                )

    return StagedStandardIpsecConfiguration(
        spoke_template=spoke_template,
        hub_template=hub_template,
        replacements=replacements,
        spoke_vsys=spoke_vsys,
        hub_vsys=hub_vsys,
    )


def _merge_routing_objects(
    target: VirtualRouter | LogicalRouter,
    source: VirtualRouter | LogicalRouter,
) -> None:
    if isinstance(target, VirtualRouter) and isinstance(source, VirtualRouter):
        target.interface = list(
            dict.fromkeys((*(target.interface or []), *(source.interface or [])))
        )
        for child in source.children:
            if isinstance(child, Bgp):
                _merge_legacy_bgp(target, child)
            elif isinstance(child, Ospf):
                _merge_legacy_ospf(target, child)
            else:
                target.add(child)
        return
    if isinstance(target, LogicalRouter) and isinstance(source, LogicalRouter):
        target.vrf = list(dict.fromkeys((*(target.vrf or []), *(source.vrf or []))))
        for source_vrf in source.findall(Vrf):
            target_vrf = next(
                (
                    item
                    for item in target.findall(Vrf)
                    if str(item.name).casefold() == str(source_vrf.name).casefold()
                ),
                None,
            )
            if target_vrf is None:
                target.add(source_vrf)
                continue
            target_vrf.interface = list(
                dict.fromkeys(
                    (*(target_vrf.interface or []), *(source_vrf.interface or []))
                )
            )
            for child in source_vrf.children:
                if isinstance(child, VrfBgpPeerGroup):
                    _merge_named_container(target_vrf, child, VrfBgpPeerGroup)
                elif isinstance(child, VrfOspfArea):
                    _merge_named_container(target_vrf, child, VrfOspfArea)
                else:
                    target_vrf.add(child)
        return
    raise LsvpnConfigurationError("Cannot merge different routing instance types.")


def _merge_legacy_bgp(target: VirtualRouter, source: Bgp) -> None:
    bgp = next(iter(target.findall(Bgp)), None)
    if bgp is None:
        target.add(source)
        return
    for group in source.findall(BgpPeerGroup):
        _merge_named_container(bgp, group, BgpPeerGroup)


def _merge_legacy_ospf(target: VirtualRouter, source: Ospf) -> None:
    ospf = next(iter(target.findall(Ospf)), None)
    if ospf is None:
        target.add(source)
        return
    for area in source.findall(OspfArea):
        _merge_named_container(ospf, area, OspfArea)


def _merge_named_container(
    target: Vrf | Bgp | Ospf,
    source: VrfBgpPeerGroup | VrfOspfArea | BgpPeerGroup | OspfArea,
    child_type: type[VrfBgpPeerGroup]
    | type[VrfOspfArea]
    | type[BgpPeerGroup]
    | type[OspfArea],
) -> None:
    existing = next(
        (
            child
            for child in target.findall(child_type)
            if str(child.name).casefold() == str(source.name).casefold()
        ),
        None,
    )
    if existing is None:
        target.add(source)
        return
    existing_names = {str(child.name).casefold() for child in existing.children}
    for child in source.children:
        name = str(child.name).casefold()
        if name in existing_names:
            raise LsvpnConfigurationError(
                f'Dynamic-routing object "{child.name}" would be duplicated in '
                f'"{source.name}".'
            )
        existing.add(child)
        existing_names.add(name)
