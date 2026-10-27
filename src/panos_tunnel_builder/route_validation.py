import ipaddress
import json
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

from panos.panorama import Panorama

from .lsvpn import (
    DEFAULT_VSYS,
    RoutingInstanceConfig,
    _attach_to_panorama,
    _read_effective_running_config,
)
from .panorama_client import Firewall

ROUTE_SNAPSHOT_SCHEMA_VERSION = 2
MANIFEST_SCHEMA_VERSION = 1


class RouteValidationError(RuntimeError):
    """A route snapshot cannot be captured, loaded, or compared safely."""


@dataclass(frozen=True)
class RoutePath:
    next_hop: str | None
    interface: str | None
    weight: int | None = None
    active: bool | None = None


@dataclass(frozen=True)
class RouteEntry:
    routing_kind: Literal["virtual-router", "logical-router"]
    routing_instance: str
    vrf: str | None
    prefix: str
    protocol: str
    distance: int | None
    metric: int | None
    selected: bool | None
    installed: bool | None
    paths: tuple[RoutePath, ...]

    @property
    def identity(self) -> tuple[str, str, str, str, str]:
        return (
            self.routing_kind,
            self.routing_instance,
            self.vrf or "",
            self.prefix,
            self.protocol,
        )


@dataclass(frozen=True)
class RouteSnapshot:
    schema_version: int
    firewall_name: str
    serial: str
    vsys: str
    captured_at: str
    routes: tuple[RouteEntry, ...]
    routing_configuration: tuple[str, ...] = ()
    bgp_peer_count: int | None = None
    captured_routing_instances: tuple[RoutingInstanceConfig, ...] = ()

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, value: str) -> "RouteSnapshot":
        try:
            document = cast(dict[str, Any], json.loads(value))
            schema_version = int(document["schema_version"])
            if schema_version == 1:
                raise RouteValidationError(
                    "Route snapshot schema version 1 does not prove route capture "
                    "completeness. Capture a fresh baseline before migration; "
                    "if migration already occurred, retain the old evidence and "
                    "verify the original baseline manually."
                )
            if schema_version != ROUTE_SNAPSHOT_SCHEMA_VERSION:
                raise RouteValidationError(
                    f"Unsupported route snapshot schema version {schema_version}; "
                    f"expected {ROUTE_SNAPSHOT_SCHEMA_VERSION}."
                )
            routes_value = document["routes"]
            routing_configuration_value = document.get("routing_configuration", [])
            bgp_peer_count_value = document.get("bgp_peer_count")
            instances_value = document.get("captured_routing_instances")
            if not isinstance(routes_value, list):
                raise RouteValidationError("Snapshot routes must be a JSON array.")
            if not isinstance(routing_configuration_value, list) or not all(
                isinstance(item, str) for item in routing_configuration_value
            ):
                raise RouteValidationError(
                    "Snapshot routing_configuration must be an array of XML strings."
                )
            if bgp_peer_count_value is not None and (
                isinstance(bgp_peer_count_value, bool)
                or not isinstance(bgp_peer_count_value, int)
                or bgp_peer_count_value < 0
            ):
                raise RouteValidationError(
                    "Snapshot bgp_peer_count must be a non-negative integer."
                )
            routes = tuple(_route_from_dict(item) for item in routes_value)
            instances = _captured_instances_from_json(instances_value)
            snapshot = cls(
                schema_version=schema_version,
                firewall_name=str(document["firewall_name"]),
                serial=str(document["serial"]),
                vsys=str(document["vsys"]),
                captured_at=str(document["captured_at"]),
                routes=routes,
                routing_configuration=tuple(routing_configuration_value),
                bgp_peer_count=bgp_peer_count_value,
                captured_routing_instances=instances,
            )
            _assert_snapshot_coverage(snapshot)
            return snapshot
        except RouteValidationError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RouteValidationError(f"Invalid route snapshot: {exc}") from exc


@dataclass(frozen=True)
class RouteDifference:
    identity: tuple[str, str, str, str, str]
    before: tuple[RouteEntry, ...]
    after: tuple[RouteEntry, ...]


@dataclass(frozen=True)
class RouteComparison:
    missing: tuple[RouteDifference, ...]
    added: tuple[RouteDifference, ...]
    changed: tuple[RouteDifference, ...]

    @property
    def equivalent(self) -> bool:
        return not (self.missing or self.added or self.changed)


@dataclass(frozen=True)
class RoutePathMapping:
    old_interface: str | None
    old_next_hop: str | None
    new_interface: str | None
    new_next_hop: str | None
    protocols: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class MigrationEndpointValidation:
    role: Literal["spoke", "hub"]
    firewall_name: str
    serial: str
    vsys: str
    baseline_snapshot: str
    prefix_map: dict[str, str]
    path_mappings: tuple[RoutePathMapping, ...]
    allowed_added_prefixes: tuple[str, ...]
    mutable_routing_interfaces: tuple[str, ...] = ()
    mutable_route_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class MigrationValidationManifest:
    schema_version: int
    created_at: str
    panorama_snapshot_name: str
    endpoints: tuple[MigrationEndpointValidation, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, value: str) -> "MigrationValidationManifest":
        try:
            document = cast(dict[str, Any], json.loads(value))
            schema_version = int(document["schema_version"])
            if schema_version != MANIFEST_SCHEMA_VERSION:
                raise RouteValidationError(
                    f"Unsupported migration manifest schema version "
                    f"{schema_version}; expected {MANIFEST_SCHEMA_VERSION}."
                )
            endpoint_values = document["endpoints"]
            if not isinstance(endpoint_values, list) or not endpoint_values:
                raise RouteValidationError(
                    "Migration manifest endpoints must be a non-empty JSON array."
                )
            endpoints = tuple(
                _migration_endpoint_from_dict(item) for item in endpoint_values
            )
            return cls(
                schema_version=schema_version,
                created_at=str(document["created_at"]),
                panorama_snapshot_name=str(document["panorama_snapshot_name"]),
                endpoints=endpoints,
            )
        except RouteValidationError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RouteValidationError(f"Invalid migration manifest: {exc}") from exc


def _migration_endpoint_from_dict(value: Any) -> MigrationEndpointValidation:
    if not isinstance(value, dict):
        raise RouteValidationError("Each migration endpoint must be a JSON object.")
    role = str(value["role"])
    if role not in {"spoke", "hub"}:
        raise RouteValidationError(f'Unknown migration endpoint role "{role}".')
    mappings_value = value.get("path_mappings", [])
    if not isinstance(mappings_value, list):
        raise RouteValidationError("Path mappings must be a JSON array.")
    prefix_map_value = value.get("prefix_map", {})
    if not isinstance(prefix_map_value, dict):
        raise RouteValidationError("Prefix mappings must be a JSON object.")
    allowed_value = value.get("allowed_added_prefixes", [])
    if not isinstance(allowed_value, list):
        raise RouteValidationError("Allowed added prefixes must be a JSON array.")
    mutable_interfaces = value.get("mutable_routing_interfaces", [])
    mutable_route_names = value.get("mutable_route_names", [])
    if not isinstance(mutable_interfaces, list) or not all(
        isinstance(item, str) for item in mutable_interfaces
    ):
        raise RouteValidationError("Mutable routing interfaces must be a JSON array.")
    if not isinstance(mutable_route_names, list) or not all(
        isinstance(item, str) for item in mutable_route_names
    ):
        raise RouteValidationError("Mutable route names must be a JSON array.")
    return MigrationEndpointValidation(
        role=cast(Literal["spoke", "hub"], role),
        firewall_name=str(value["firewall_name"]),
        serial=str(value["serial"]),
        vsys=str(value["vsys"]),
        baseline_snapshot=str(value["baseline_snapshot"]),
        prefix_map={
            str(source): str(destination)
            for source, destination in prefix_map_value.items()
        },
        path_mappings=tuple(_path_mapping_from_dict(item) for item in mappings_value),
        allowed_added_prefixes=tuple(str(item) for item in allowed_value),
        mutable_routing_interfaces=tuple(mutable_interfaces),
        mutable_route_names=tuple(mutable_route_names),
    )


def _captured_instances_from_json(value: Any) -> tuple[RoutingInstanceConfig, ...]:
    if not isinstance(value, list) or not value:
        raise RouteValidationError("Snapshot lacks captured routing instance evidence.")
    instances: list[RoutingInstanceConfig] = []
    for item in value:
        if not isinstance(item, dict):
            raise RouteValidationError("Invalid captured routing instance evidence.")
        kind, name, vrf = item.get("kind"), item.get("name"), item.get("vrf")
        if (
            kind not in ("virtual-router", "logical-router")
            or not isinstance(name, str)
            or not name.strip()
            or (vrf is not None and (not isinstance(vrf, str) or not vrf.strip()))
            or (kind == "virtual-router" and vrf is not None)
        ):
            raise RouteValidationError("Invalid captured routing instance evidence.")
        instances.append(RoutingInstanceConfig(kind, name, vrf))
    if len(set(instances)) != len(instances):
        raise RouteValidationError("Duplicate captured routing instance evidence.")
    return tuple(instances)


def _assert_snapshot_coverage(snapshot: RouteSnapshot) -> None:
    if (
        snapshot.schema_version != ROUTE_SNAPSHOT_SCHEMA_VERSION
        or not snapshot.captured_routing_instances
    ):
        raise RouteValidationError(
            "Route snapshot lacks verified routing-instance capture evidence. "
            "Capture a fresh baseline before migration; if migration already "
            "occurred, retain the old evidence and verify it manually."
        )
    captured = {
        (instance.kind, instance.name.casefold(), (instance.vrf or "").casefold())
        for instance in snapshot.captured_routing_instances
    }
    if len(captured) != len(snapshot.captured_routing_instances):
        raise RouteValidationError("Duplicate captured routing instance evidence.")
    for route in snapshot.routes:
        scope = (
            route.routing_kind,
            route.routing_instance.casefold(),
            (route.vrf or "").casefold(),
        )
        wildcard = (route.routing_kind, route.routing_instance.casefold(), "")
        if scope not in captured and not (
            route.routing_kind == "logical-router" and wildcard in captured
        ):
            raise RouteValidationError(
                f'Route for router "{route.routing_instance}" has no capture evidence.'
            )


def _path_mapping_from_dict(value: Any) -> RoutePathMapping:
    if not isinstance(value, dict):
        raise RouteValidationError("Each path mapping must be a JSON object.")
    protocols = value.get("protocols", [])
    prefixes = value.get("prefixes", [])
    if not isinstance(protocols, list) or not isinstance(prefixes, list):
        raise RouteValidationError(
            "Path mapping protocols and prefixes must be JSON arrays."
        )
    return RoutePathMapping(
        old_interface=_optional_string(value.get("old_interface")),
        old_next_hop=_optional_string(value.get("old_next_hop")),
        new_interface=_optional_string(value.get("new_interface")),
        new_next_hop=_optional_string(value.get("new_next_hop")),
        protocols=tuple(str(protocol).casefold() for protocol in protocols),
        prefixes=tuple(_normalize_prefix(str(prefix)) for prefix in prefixes),
    )


def _route_from_dict(value: Any) -> RouteEntry:
    if not isinstance(value, dict):
        raise RouteValidationError("Each route must be a JSON object.")
    kind = str(value["routing_kind"])
    if kind not in {"virtual-router", "logical-router"}:
        raise RouteValidationError(f'Unknown routing kind "{kind}".')
    paths_value = value.get("paths", [])
    if not isinstance(paths_value, list):
        raise RouteValidationError("Route paths must be a JSON array.")
    if not all(isinstance(path, dict) for path in paths_value):
        raise RouteValidationError("Every route path must be a JSON object.")
    return RouteEntry(
        routing_kind=cast(Literal["virtual-router", "logical-router"], kind),
        routing_instance=str(value["routing_instance"]),
        vrf=_optional_string(value.get("vrf")),
        prefix=_normalize_prefix(str(value["prefix"])),
        protocol=str(value["protocol"]).casefold(),
        distance=_optional_int(value.get("distance")),
        metric=_optional_int(value.get("metric")),
        selected=_optional_bool(value.get("selected")),
        installed=_optional_bool(value.get("installed")),
        paths=tuple(
            RoutePath(
                next_hop=_optional_string(path.get("next_hop")),
                interface=_optional_string(path.get("interface")),
                weight=_optional_int(path.get("weight")),
                active=_optional_bool(path.get("active")),
            )
            for path in paths_value
        ),
    )


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().casefold()
    if normalized in {"yes", "true", "1"}:
        return True
    if normalized in {"no", "false", "0"}:
        return False
    return None


def _normalize_prefix(value: str) -> str:
    stripped = value.strip()
    try:
        return str(ipaddress.ip_network(stripped, strict=False))
    except ValueError:
        return stripped


def _normalize_address(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    try:
        return str(ipaddress.ip_address(stripped))
    except ValueError:
        return stripped.casefold()


def discover_routing_instances(
    panorama: Panorama,
    serial: str,
    vsys: str = DEFAULT_VSYS,
    *,
    effective: ET.Element | None = None,
) -> tuple[RoutingInstanceConfig, ...]:
    """Discover every legacy VR and advanced-routing logical-router VRF."""
    if effective is None:
        effective = _read_effective_running_config(panorama, serial, vsys)
    instances: list[RoutingInstanceConfig] = []
    for router in effective.findall(".//network/virtual-router/entry"):
        if name := router.get("name"):
            instances.append(RoutingInstanceConfig("virtual-router", name))
    for router in effective.findall(".//network/logical-router/entry"):
        name = router.get("name")
        if not name:
            continue
        vrfs = router.findall("./vrf/entry")
        if not vrfs:
            instances.append(RoutingInstanceConfig("logical-router", name))
        for vrf in vrfs:
            if vrf_name := vrf.get("name"):
                instances.append(
                    RoutingInstanceConfig("logical-router", name, vrf_name)
                )
    result = tuple(dict.fromkeys(instances))
    if not result:
        raise RouteValidationError(
            "No virtual routers or logical-router VRFs were found in the "
            "firewall's effective configuration."
        )
    return result


def _strip_metadata(element: ET.Element) -> None:
    for item in element.iter():
        for attribute in ("admin", "dirtyId", "time"):
            item.attrib.pop(attribute, None)


def _routing_configuration_entries(root: ET.Element) -> tuple[str, ...]:
    entries: list[str] = []
    for kind in ("virtual-router", "logical-router"):
        for entry in root.findall(f".//network/{kind}/entry"):
            copied = deepcopy(entry)
            _strip_metadata(copied)
            entries.append(f"{kind}\0{ET.tostring(copied, encoding='unicode')}")
    return tuple(sorted(entries))


def _configured_bgp_peer_count(root: ET.Element) -> int:
    """Count configured BGP peers across legacy and advanced routing."""
    legacy = root.findall(
        ".//network/virtual-router/entry/protocol/bgp/peer-group/entry/peer/entry"
    )
    advanced = root.findall(
        ".//network/logical-router/entry/vrf/entry/bgp/peer-group/entry/peer/entry"
    )
    return len(legacy) + len(advanced)


def _route_command(routing: RoutingInstanceConfig) -> bytes:
    show = ET.Element("show")
    if routing.kind == "virtual-router":
        route = ET.SubElement(ET.SubElement(show, "routing"), "route")
        ET.SubElement(route, "virtual-router").text = routing.name
    else:
        route = ET.SubElement(ET.SubElement(show, "advanced-routing"), "route")
        ET.SubElement(route, "logical-router").text = routing.name
    ET.SubElement(route, "afi").text = "both"
    return cast(bytes, ET.tostring(show, encoding="utf-8"))


def capture_route_snapshot(
    panorama: Panorama,
    firewall_name: str,
    serial: str,
    vsys: str = DEFAULT_VSYS,
    *,
    captured_at: datetime | None = None,
) -> RouteSnapshot:
    """Capture normalized IPv4 and IPv6 RIB entries through Panorama."""
    effective = _read_effective_running_config(panorama, serial, vsys)
    firewall = Firewall(serial=serial, vsys=vsys)
    _attach_to_panorama(firewall, panorama)
    routes: list[RouteEntry] = []
    queried_logical_routers: set[str] = set()
    instances = discover_routing_instances(
        panorama,
        serial,
        vsys,
        effective=effective,
    )
    if not instances:
        raise RouteValidationError("No routing instances were available to capture.")
    for routing in instances:
        if (
            routing.kind == "logical-router"
            and routing.name.casefold() in queried_logical_routers
        ):
            continue
        response = cast(
            ET.Element,
            firewall.op(cmd=_route_command(routing), cmd_xml=False),
        )
        if routing.kind == "logical-router":
            queried_logical_routers.add(routing.name.casefold())
            routes.extend(_parse_advanced_routes(response, routing.name))
        else:
            routes.extend(_parse_legacy_routes(response, routing.name))
    timestamp = captured_at or datetime.now(UTC)
    snapshot = RouteSnapshot(
        schema_version=ROUTE_SNAPSHOT_SCHEMA_VERSION,
        firewall_name=firewall_name,
        serial=serial,
        vsys=vsys,
        captured_at=timestamp.isoformat(),
        routes=tuple(sorted(routes, key=_route_sort_key)),
        routing_configuration=_routing_configuration_entries(effective),
        bgp_peer_count=_configured_bgp_peer_count(effective),
        captured_routing_instances=instances,
    )
    _assert_snapshot_coverage(snapshot)
    return snapshot


def _route_result(response: ET.Element, router: str) -> ET.Element:
    if (
        not isinstance(response, ET.Element)
        or response.tag != "response"
        or response.get("status") != "success"
        or len(response.findall("./result")) != 1
    ):
        raise RouteValidationError(f'Router "{router}" returned an invalid response.')
    result = response.find("./result")
    assert result is not None
    if (result.text or "").strip() or any((item.tail or "").strip() for item in result):
        raise RouteValidationError(f'Router "{router}" returned an unrecognized table.')
    return result


def _route_prefix(value: object, router: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RouteValidationError(
            f'Router "{router}" returned a route without a prefix.'
        )
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise RouteValidationError(
            f'Router "{router}" returned an invalid route prefix: {value!r}.'
        ) from exc


def _route_optional_int(value: object, router: str, field: str) -> int | None:
    parsed = _optional_int(value)
    if value not in (None, "") and (isinstance(value, bool) or parsed is None):
        raise RouteValidationError(f'Router "{router}" returned invalid {field}.')
    if isinstance(value, float):
        raise RouteValidationError(f'Router "{router}" returned invalid {field}.')
    return parsed


def _route_optional_bool(value: object, router: str, field: str) -> bool | None:
    parsed = _optional_bool(value)
    if value not in (None, "") and parsed is None:
        raise RouteValidationError(f'Router "{router}" returned invalid {field}.')
    return parsed


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RouteValidationError("Route JSON contains duplicate object keys.")
        result[key] = value
    return result


def _parse_advanced_routes(
    response: ET.Element,
    logical_router: str,
) -> tuple[RouteEntry, ...]:
    result = _route_result(response, logical_router)
    if len(result) != 1 or result[0].tag != "json" or len(result[0]):
        raise RouteValidationError(
            f'Logical router "{logical_router}" returned an unrecognized route table.'
        )
    json_text = result[0].text
    if not json_text or not json_text.strip():
        raise RouteValidationError(
            f'Logical router "{logical_router}" returned no route JSON.'
        )
    try:
        document = json.loads(json_text, object_pairs_hook=_unique_json_object)
    except json.JSONDecodeError as exc:
        raise RouteValidationError(
            f'Logical router "{logical_router}" returned invalid route JSON: {exc}'
        ) from exc
    if not isinstance(document, dict):
        raise RouteValidationError(
            f'Logical router "{logical_router}" returned an unexpected route result.'
        )
    router_routes = document.get(logical_router)
    if not isinstance(router_routes, dict):
        raise RouteValidationError(
            f'Logical router "{logical_router}" is missing from the route result.'
        )
    routes: list[RouteEntry] = []
    for reported_prefix, candidates in router_routes.items():
        prefix = _route_prefix(reported_prefix, logical_router)
        if not isinstance(candidates, list) or not candidates:
            raise RouteValidationError(
                f'Logical router "{logical_router}" returned invalid route candidates.'
            )
        for candidate in candidates:
            if not isinstance(candidate, dict):
                raise RouteValidationError(
                    f'Logical router "{logical_router}" returned '
                    "an invalid route record."
                )
            if (
                "prefix" in candidate
                and _route_prefix(candidate["prefix"], logical_router) != prefix
            ):
                raise RouteValidationError(
                    f'Logical router "{logical_router}" returned '
                    "a conflicting route prefix."
                )
            protocol, vrf = candidate.get("protocol"), candidate.get("vrfName")
            if (
                not isinstance(protocol, str)
                or not protocol.strip()
                or not isinstance(vrf, str)
                or not vrf.strip()
            ):
                raise RouteValidationError(
                    f'Logical router "{logical_router}" returned '
                    "a route without protocol or VRF."
                )
            next_hops = candidate.get("nexthops")
            if not isinstance(next_hops, list):
                raise RouteValidationError(
                    f'Logical router "{logical_router}" returned invalid next hops.'
                )
            paths: list[RoutePath] = []
            for path in next_hops:
                if not isinstance(path, dict):
                    raise RouteValidationError(
                        f'Logical router "{logical_router}" returned '
                        "an invalid next hop."
                    )
                address, interface = path.get("ip"), path.get("interfaceName")
                if (
                    (address is not None and not isinstance(address, str))
                    or (interface is not None and not isinstance(interface, str))
                    or not (_optional_string(address) or _optional_string(interface))
                ):
                    raise RouteValidationError(
                        f'Logical router "{logical_router}" returned '
                        "an incomplete next hop."
                    )
                paths.append(
                    RoutePath(
                        next_hop=_normalize_address(_optional_string(address)),
                        interface=_optional_string(interface),
                        weight=_route_optional_int(
                            path.get("weight"), logical_router, "next-hop weight"
                        ),
                        active=_route_optional_bool(
                            path.get("active"), logical_router, "next-hop active state"
                        ),
                    )
                )
            routes.append(
                RouteEntry(
                    routing_kind="logical-router",
                    routing_instance=logical_router,
                    vrf=vrf.strip(),
                    prefix=prefix,
                    protocol=protocol.strip().casefold(),
                    distance=_route_optional_int(
                        candidate.get("distance"), logical_router, "distance"
                    ),
                    metric=_route_optional_int(
                        candidate.get("metric"), logical_router, "metric"
                    ),
                    selected=_route_optional_bool(
                        candidate.get("selected"), logical_router, "selected state"
                    ),
                    installed=_route_optional_bool(
                        candidate.get("installed"), logical_router, "installed state"
                    ),
                    paths=tuple(sorted(paths, key=_path_sort_key)),
                )
            )
    return tuple(routes)


def _legacy_protocol(entry: ET.Element) -> str:
    explicit = entry.findtext("protocol") or entry.findtext("type")
    if explicit:
        return explicit.strip().casefold()
    flags = "".join((entry.findtext("flags") or "").split()).replace("*", "")
    for flag, protocol in (
        ("B", "bgp"),
        ("O1", "ospf"),
        ("O2", "ospf"),
        ("Oi", "ospf"),
        ("Oo", "ospf"),
        ("O", "ospf"),
        ("R", "rip"),
        ("S", "static"),
        ("C", "connected"),
        ("H", "local"),
    ):
        if flag in flags:
            return protocol
    return "unknown"


def _parse_legacy_routes(
    response: ET.Element,
    virtual_router: str,
) -> tuple[RouteEntry, ...]:
    result = _route_result(response, virtual_router)
    allowed = {"entry", "flags", "total-count", "count"}
    if any(child.tag not in allowed for child in result):
        raise RouteValidationError(
            f'Virtual router "{virtual_router}" returned an unrecognized route table.'
        )
    if any(len(child) for child in result if child.tag != "entry"):
        raise RouteValidationError(
            f'Virtual router "{virtual_router}" returned invalid route metadata.'
        )
    entries = result.findall("./entry")
    counts = [
        result.get(key)
        for key in ("count", "total-count")
        if result.get(key) is not None
    ]
    counts.extend(
        child.text for child in result if child.tag in {"count", "total-count"}
    )
    if any(
        count is None or not count.isdecimal() or int(count) != len(entries)
        for count in counts
    ):
        raise RouteValidationError(
            f'Virtual router "{virtual_router}" returned an incomplete route table.'
        )
    if not entries and not counts:
        legend = result.findtext("./flags") or ""
        if not legend.strip().casefold().startswith("flags:"):
            raise RouteValidationError(
                f'Virtual router "{virtual_router}" returned an ambiguous '
                "empty route table."
            )
    routes: list[RouteEntry] = []
    for entry in entries:
        for field in (
            "virtual-router",
            "destination",
            "prefix",
            "nexthop",
            "next-hop",
            "interface",
            "flags",
            "protocol",
            "type",
            "distance",
            "admin-distance",
            "metric",
        ):
            fields = entry.findall(field)
            if len(fields) > 1 or any(len(node) for node in fields):
                raise RouteValidationError(
                    f'Virtual router "{virtual_router}" returned a route with '
                    f'invalid or duplicate "{field}" fields.'
                )
        prefix = entry.findtext("destination") or entry.findtext("prefix")
        if not prefix:
            raise RouteValidationError(
                f'Virtual router "{virtual_router}" returned a route without a prefix.'
            )
        router_name = _optional_string(entry.findtext("virtual-router"))
        if router_name and router_name.casefold() != virtual_router.casefold():
            raise RouteValidationError(
                f'Virtual router "{virtual_router}" returned a route '
                "for another router."
            )
        protocol = _legacy_protocol(entry)
        if protocol == "unknown":
            raise RouteValidationError(
                f'Virtual router "{virtual_router}" returned a route without '
                "recognized protocol evidence."
            )
        flags = "".join((entry.findtext("flags") or "").split()).replace("*", "")
        next_hop = _normalize_address(
            _optional_string(entry.findtext("nexthop") or entry.findtext("next-hop"))
        )
        interface = _optional_string(entry.findtext("interface"))
        paths = (
            (RoutePath(next_hop, interface, active="A" in flags),)
            if next_hop is not None or interface is not None
            else ()
        )
        routes.append(
            RouteEntry(
                routing_kind="virtual-router",
                routing_instance=(router_name or virtual_router),
                vrf=None,
                prefix=_route_prefix(prefix, virtual_router),
                protocol=protocol,
                distance=_route_optional_int(
                    entry.findtext("distance") or entry.findtext("admin-distance"),
                    virtual_router,
                    "distance",
                ),
                metric=_route_optional_int(
                    entry.findtext("metric"), virtual_router, "metric"
                ),
                selected=True if "A" in flags else None,
                installed=True if "A" in flags else None,
                paths=paths,
            )
        )
    return tuple(routes)


def _path_sort_key(path: RoutePath) -> tuple[str, str, int, int]:
    return (
        path.next_hop or "",
        path.interface or "",
        path.weight if path.weight is not None else -1,
        int(path.active) if path.active is not None else -1,
    )


def _route_sort_key(route: RouteEntry) -> tuple[Any, ...]:
    return (
        *route.identity,
        route.distance if route.distance is not None else -1,
        route.metric if route.metric is not None else -1,
        str(route.paths),
    )


def _mapped_route(
    route: RouteEntry,
    prefix_map: dict[str, str],
    interface_map: dict[str, str],
    next_hop_map: dict[str, str],
    path_mappings: tuple[RoutePathMapping, ...] = (),
) -> RouteEntry:
    def mapped_path(path: RoutePath) -> RoutePath:
        next_hop = path.next_hop
        interface = path.interface
        for mapping in path_mappings:
            if mapping.protocols and route.protocol not in mapping.protocols:
                continue
            if mapping.prefixes and route.prefix not in {
                _normalize_prefix(prefix) for prefix in mapping.prefixes
            }:
                continue
            if mapping.old_interface is not None and interface != mapping.old_interface:
                continue
            if mapping.old_next_hop is not None and _normalize_address(
                next_hop
            ) != _normalize_address(mapping.old_next_hop):
                continue
            interface = mapping.new_interface or interface
            next_hop = mapping.new_next_hop or next_hop
            break
        return RoutePath(
            next_hop=next_hop_map.get(next_hop, next_hop)
            if next_hop is not None
            else None,
            interface=interface_map.get(interface, interface)
            if interface is not None
            else None,
            weight=path.weight,
            active=path.active,
        )

    return RouteEntry(
        routing_kind=route.routing_kind,
        routing_instance=route.routing_instance,
        vrf=route.vrf,
        prefix=prefix_map.get(route.prefix, route.prefix),
        protocol=route.protocol,
        distance=route.distance,
        metric=route.metric,
        selected=route.selected,
        installed=route.installed,
        paths=tuple(
            sorted(
                (mapped_path(path) for path in route.paths),
                key=_path_sort_key,
            )
        ),
    )


def _remove_children_matching(
    parent: ET.Element,
    predicate: Any,
) -> None:
    for child in list(parent):
        if predicate(child):
            parent.remove(child)


def _normalized_routing_configuration(
    entries: tuple[str, ...],
    mutable_interfaces: tuple[str, ...],
    mutable_route_names: tuple[str, ...],
) -> dict[tuple[str, str], str]:
    interfaces = {value.strip().casefold() for value in mutable_interfaces}
    route_names = {value.casefold() for value in mutable_route_names}
    normalized: dict[tuple[str, str], str] = {}
    for serialized in entries:
        kind, separator, xml = serialized.partition("\0")
        if not separator:
            raise RouteValidationError(
                "Invalid routing configuration entry in route snapshot."
            )
        try:
            entry = ET.fromstring(xml)
        except ET.ParseError as exc:
            raise RouteValidationError(
                f"Invalid routing configuration XML in route snapshot: {exc}"
            ) from exc
        _strip_metadata(entry)

        for container in entry.findall(".//interface"):
            _remove_children_matching(
                container,
                lambda child: (
                    child.tag == "member"
                    and (child.text or "").strip().casefold() in interfaces
                ),
            )
            members = container.findall("./member")
            if members and len(members) == len(container):
                container[:] = sorted(
                    members,
                    key=lambda member: (member.text or "").strip().casefold(),
                )
        for container in entry.findall(".//static-route"):
            _remove_children_matching(
                container,
                lambda child: (
                    child.tag == "entry"
                    and (
                        any(
                            (value.text or "").strip().casefold() in interfaces
                            for value in child.findall(".//interface")
                        )
                        or child.get("name", "").casefold() in route_names
                    )
                ),
            )
        for container in entry.findall(".//peer-group/entry/peer"):
            _remove_children_matching(
                container,
                lambda child: (
                    child.tag == "entry"
                    and any(
                        (value.text or "").strip().casefold() in interfaces
                        for value in child.findall(".//local-address/interface")
                    )
                ),
            )
        for container in entry.findall(".//ospf/area/entry/interface"):
            _remove_children_matching(
                container,
                lambda child: (
                    child.tag == "entry"
                    and child.get("name", "").casefold() in interfaces
                ),
            )

        prunable = {
            "interface",
            "peer",
            "static-route",
            "ip",
            "ipv6",
            "routing-table",
        }
        changed = True
        while changed:
            changed = False
            for parent in entry.iter():
                for child in list(parent):
                    if (
                        child.tag in prunable
                        and not list(child)
                        and not child.attrib
                        and not (child.text or "").strip()
                    ):
                        parent.remove(child)
                        changed = True
        key = (kind, entry.get("name", ""))
        normalized[key] = ET.canonicalize(
            ET.tostring(entry, encoding="unicode"),
            strip_text=True,
        )
    return normalized


def compare_routing_configurations(
    before: RouteSnapshot,
    after: RouteSnapshot,
    *,
    mutable_interfaces: tuple[str, ...] = (),
    mutable_route_names: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Return routing instances with changes outside the approved migration scope."""
    if before.serial != after.serial or before.vsys != after.vsys:
        raise RouteValidationError(
            "Routing configurations must be from the same firewall serial and "
            "virtual system."
        )
    if not before.routing_configuration:
        return ()
    before_entries = _normalized_routing_configuration(
        before.routing_configuration,
        mutable_interfaces,
        mutable_route_names,
    )
    after_entries = _normalized_routing_configuration(
        after.routing_configuration,
        mutable_interfaces,
        mutable_route_names,
    )
    return tuple(
        f"{kind}:{name}"
        for kind, name in sorted(before_entries.keys() | after_entries.keys())
        if before_entries.get((kind, name)) != after_entries.get((kind, name))
    )


def find_static_route_names(
    snapshot: RouteSnapshot,
    *,
    interfaces: tuple[str, ...],
    destinations: tuple[str, ...],
) -> tuple[str, ...]:
    """Find exact baseline static-route names intentionally replaced by a plan."""
    wanted_interfaces = {value.casefold() for value in interfaces}
    wanted_destinations = {_normalize_prefix(value) for value in destinations}
    names: list[str] = []
    for serialized in snapshot.routing_configuration:
        _, separator, xml = serialized.partition("\0")
        if not separator:
            continue
        try:
            entry = ET.fromstring(xml)
        except ET.ParseError:
            continue
        for route in entry.findall(".//static-route/entry"):
            name = route.get("name")
            interface = (route.findtext(".//interface") or "").strip().casefold()
            destination = _normalize_prefix(route.findtext("destination", default=""))
            if (
                name
                and interface in wanted_interfaces
                and destination in wanted_destinations
            ):
                names.append(name)
    return tuple(dict.fromkeys(names))


def compare_route_snapshots(
    before: RouteSnapshot,
    after: RouteSnapshot,
    *,
    prefix_map: dict[str, str] | None = None,
    interface_map: dict[str, str] | None = None,
    next_hop_map: dict[str, str] | None = None,
    path_mappings: tuple[RoutePathMapping, ...] = (),
    allowed_added_prefixes: tuple[str, ...] = (),
    allow_additional_candidates: bool = False,
) -> RouteComparison:
    """Compare stable RIB attributes, optionally mapping expected replacements."""
    if before.serial != after.serial or before.vsys != after.vsys:
        raise RouteValidationError(
            "Route snapshots must be from the same firewall serial and virtual system."
        )
    _assert_snapshot_coverage(before)
    _assert_snapshot_coverage(after)
    if set(before.captured_routing_instances) != set(after.captured_routing_instances):
        raise RouteValidationError(
            "The captured routing instances differ between route snapshots."
        )
    normalized_prefix_map = {
        _normalize_prefix(source): _normalize_prefix(destination)
        for source, destination in (prefix_map or {}).items()
    }
    normalized_next_hop_map = {
        _normalize_address(source) or source: _normalize_address(destination)
        or destination
        for source, destination in (next_hop_map or {}).items()
    }
    mapped_before = tuple(
        _mapped_route(
            route,
            normalized_prefix_map,
            interface_map or {},
            normalized_next_hop_map,
            path_mappings,
        )
        for route in before.routes
    )
    before_groups: defaultdict[tuple[str, str, str, str, str], list[RouteEntry]] = (
        defaultdict(list)
    )
    after_groups: defaultdict[tuple[str, str, str, str, str], list[RouteEntry]] = (
        defaultdict(list)
    )
    for route in mapped_before:
        before_groups[route.identity].append(route)
    for route in after.routes:
        after_groups[route.identity].append(route)

    missing: list[RouteDifference] = []
    added: list[RouteDifference] = []
    changed: list[RouteDifference] = []
    normalized_allowed_prefixes = {
        _normalize_prefix(prefix) for prefix in allowed_added_prefixes
    }
    for identity in sorted(before_groups.keys() | after_groups.keys()):
        before_routes = tuple(sorted(before_groups[identity], key=_route_sort_key))
        after_routes = tuple(sorted(after_groups[identity], key=_route_sort_key))
        difference = RouteDifference(identity, before_routes, after_routes)
        if not after_routes:
            missing.append(difference)
        elif not before_routes:
            if identity[3] not in normalized_allowed_prefixes:
                added.append(difference)
        elif allow_additional_candidates:
            before_counts = Counter(before_routes)
            after_counts = Counter(after_routes)
            if any(
                after_counts[route] < count for route, count in before_counts.items()
            ):
                changed.append(difference)
        elif before_routes != after_routes:
            changed.append(difference)
    return RouteComparison(tuple(missing), tuple(added), tuple(changed))


def parse_mapping(values: list[str] | None, label: str) -> dict[str, str]:
    """Parse repeatable OLD=NEW CLI mappings with useful validation errors."""
    result: dict[str, str] = {}
    for value in values or []:
        old, separator, new = value.partition("=")
        if not separator or not old.strip() or not new.strip():
            raise RouteValidationError(
                f'Invalid {label} mapping "{value}"; expected OLD=NEW.'
            )
        old = old.strip()
        new = new.strip()
        if old in result and result[old] != new:
            raise RouteValidationError(
                f'{label.capitalize()} "{old}" maps to more than one value.'
            )
        result[old] = new
    return result
