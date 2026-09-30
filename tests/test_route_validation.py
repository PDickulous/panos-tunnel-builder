import json
import xml.etree.ElementTree as ET
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from panos_tunnel_builder import cli, route_validation
from panos_tunnel_builder.lsvpn import RoutingInstanceConfig
from panos_tunnel_builder.route_validation import (
    MigrationEndpointValidation,
    MigrationValidationManifest,
    RouteEntry,
    RoutePath,
    RoutePathMapping,
    RouteSnapshot,
    RouteValidationError,
)

runner = CliRunner()


def _snapshot(*routes: RouteEntry, serial: str = "001122") -> RouteSnapshot:
    return RouteSnapshot(
        schema_version=1,
        firewall_name="branch-01",
        serial=serial,
        vsys="vsys1",
        captured_at="2026-08-19T12:00:00+00:00",
        routes=routes,
    )


def _route(
    prefix: str = "10.0.0.0/8",
    interface: str = "tunnel.2",
    next_hop: str = "169.254.1.1",
) -> RouteEntry:
    return RouteEntry(
        routing_kind="logical-router",
        routing_instance="MainLR",
        vrf="default",
        prefix=prefix,
        protocol="bgp",
        distance=20,
        metric=100,
        selected=True,
        installed=True,
        paths=(RoutePath(next_hop, interface, weight=1, active=True),),
    )


def test_parse_advanced_routes_normalizes_vrf_and_multipath() -> None:
    payload = {
        "MainLR": {
            "10.0.0.1/24": [
                {
                    "prefix": "10.0.0.1/24",
                    "protocol": "bgp",
                    "vrfName": "blue",
                    "distance": 20,
                    "metric": 50,
                    "selected": True,
                    "installed": True,
                    "uptime": "00:12:34",
                    "nexthops": [
                        {
                            "ip": "2001:0db8::2",
                            "interfaceName": "tunnel.20",
                            "weight": 1,
                            "active": True,
                        },
                        {
                            "ip": "192.0.2.2",
                            "interfaceName": "tunnel.21",
                            "weight": 2,
                            "active": False,
                        },
                    ],
                }
            ]
        }
    }
    response = ET.fromstring(
        f"<response><result><json>{json.dumps(payload)}</json></result></response>"
    )

    routes = route_validation._parse_advanced_routes(response, "MainLR")

    assert routes == (
        RouteEntry(
            routing_kind="logical-router",
            routing_instance="MainLR",
            vrf="blue",
            prefix="10.0.0.0/24",
            protocol="bgp",
            distance=20,
            metric=50,
            selected=True,
            installed=True,
            paths=(
                RoutePath("192.0.2.2", "tunnel.21", 2, False),
                RoutePath("2001:db8::2", "tunnel.20", 1, True),
            ),
        ),
    )


def test_parse_legacy_routes_uses_flags_for_protocol_and_active_state() -> None:
    response = ET.fromstring(
        """
        <response><result>
          <entry>
            <virtual-router>default</virtual-router>
            <destination>10.10.0.1/16</destination>
            <nexthop>192.0.2.2</nexthop>
            <metric>10</metric><flags>A O2</flags>
            <interface>tunnel.2</interface>
          </entry>
          <entry>
            <virtual-router>default</virtual-router>
            <destination>10.20.0.0/16</destination>
            <nexthop>192.0.2.3</nexthop>
            <metric>100</metric><flags>A?B</flags>
          </entry>
        </result></response>
        """
    )

    routes = route_validation._parse_legacy_routes(response, "default")

    assert routes[0].prefix == "10.10.0.0/16"
    assert routes[0].protocol == "ospf"
    assert routes[0].selected is True
    assert routes[0].paths == (RoutePath("192.0.2.2", "tunnel.2", None, True),)
    assert routes[1].protocol == "bgp"
    assert routes[1].selected is True
    assert routes[1].installed is True
    assert routes[1].paths[0].active is True


@pytest.mark.parametrize(
    ("flags", "protocol", "active"),
    (
        ("A C", "connected", True),
        ("A H", "local", True),
        ("A S", "static", True),
        ("A R", "rip", True),
        ("A O", "ospf", True),
        ("A Oi", "ospf", True),
        ("A Oo", "ospf", True),
        ("A O1", "ospf", True),
        ("A O2", "ospf", True),
        ("A?B E M ~", "bgp", True),
        ("B", "bgp", False),
    ),
)
def test_parse_all_documented_legacy_route_flags(
    flags: str,
    protocol: str,
    active: bool,
) -> None:
    response = ET.fromstring(
        f"""
        <response><result><entry>
          <virtual-router>default</virtual-router>
          <destination>10.0.0.0/8</destination>
          <nexthop>192.0.2.2</nexthop>
          <flags>{flags}</flags>
        </entry></result></response>
        """
    )

    route = route_validation._parse_legacy_routes(response, "default")[0]

    assert route.protocol == protocol
    assert route.paths[0].active is active
    assert route.selected is (True if active else None)
    assert route.installed is (True if active else None)


def test_snapshot_json_round_trip() -> None:
    snapshot = _snapshot(_route())

    restored = RouteSnapshot.from_json(snapshot.to_json())

    assert restored == snapshot


def test_snapshot_rejects_unknown_schema() -> None:
    value = _snapshot().to_json().replace('"schema_version": 1', '"schema_version": 2')

    with pytest.raises(RouteValidationError, match="schema version 2"):
        RouteSnapshot.from_json(value)


def test_snapshot_rejects_non_array_routing_configuration() -> None:
    value = (
        _snapshot()
        .to_json()
        .replace(
            '"routing_configuration": []',
            '"routing_configuration": "not-an-array"',
        )
    )

    with pytest.raises(RouteValidationError, match="array of XML strings"):
        RouteSnapshot.from_json(value)


def test_migration_manifest_json_round_trip() -> None:
    manifest = MigrationValidationManifest(
        schema_version=1,
        created_at="2026-08-19T12:00:00+00:00",
        panorama_snapshot_name="LSVPN_PRE_a1b2c_260819120000.xml",
        endpoints=(
            MigrationEndpointValidation(
                role="spoke",
                firewall_name="branch-01",
                serial="001122",
                vsys="vsys1",
                baseline_snapshot="spoke_routes.json",
                prefix_map={"169.254.1.0/30": "169.254.240.0/30"},
                path_mappings=(
                    RoutePathMapping(
                        "tunnel.2",
                        "169.254.1.1",
                        "tunnel.21",
                        "169.254.240.2",
                        ("bgp",),
                        ("169.254.1.0/30",),
                    ),
                ),
                allowed_added_prefixes=("169.254.240.0/30",),
            ),
        ),
    )

    assert MigrationValidationManifest.from_json(manifest.to_json()) == manifest


def test_compare_reports_missing_added_and_changed_routes() -> None:
    unchanged = _route()
    missing = _route(prefix="10.1.0.0/16")
    changed_before = _route(prefix="10.2.0.0/16")
    changed_after = RouteEntry(
        **{
            **changed_before.__dict__,
            "metric": 200,
        }
    )
    added = _route(prefix="10.3.0.0/16")

    comparison = route_validation.compare_route_snapshots(
        _snapshot(unchanged, missing, changed_before),
        _snapshot(unchanged, changed_after, added),
    )

    assert [item.identity[3] for item in comparison.missing] == ["10.1.0.0/16"]
    assert [item.identity[3] for item in comparison.added] == ["10.3.0.0/16"]
    assert [item.identity[3] for item in comparison.changed] == ["10.2.0.0/16"]
    assert comparison.equivalent is False


def test_routing_configuration_comparison_allows_exact_tunnel_replacement() -> None:
    before_root = ET.fromstring(
        "<config><devices><entry><network><virtual-router><entry name='default'>"
        "<interface><member>ethernet1/1</member><member>tunnel.20</member></interface>"
        "<protocol><bgp><enable>yes</enable></bgp></protocol>"
        "<routing-table><ip><static-route><entry name='old-route'>"
        "<destination>10.0.0.0/8</destination><interface>tunnel.10</interface>"
        "</entry></static-route></ip></routing-table>"
        "</entry></virtual-router></network></entry></devices></config>"
    )
    after_root = ET.fromstring(
        "<config><devices><entry><network><virtual-router><entry name='default'>"
        "<interface><member>ethernet1/1</member><member>tunnel.21</member></interface>"
        "<protocol><bgp><enable>yes</enable></bgp></protocol>"
        "<routing-table><ip><static-route><entry name='replacement-route'>"
        "<destination>10.0.0.0/8</destination><interface>tunnel.21</interface>"
        "</entry></static-route></ip></routing-table>"
        "</entry></virtual-router></network></entry></devices></config>"
    )
    before = replace(
        _snapshot(),
        routing_configuration=route_validation._routing_configuration_entries(
            before_root
        ),
    )
    after = replace(
        _snapshot(),
        routing_configuration=route_validation._routing_configuration_entries(
            after_root
        ),
    )

    assert (
        route_validation.compare_routing_configurations(
            before,
            after,
            mutable_interfaces=("tunnel.20", "tunnel.21"),
            mutable_route_names=("old-route",),
        )
        == ()
    )
    assert route_validation.find_static_route_names(
        before,
        interfaces=("tunnel.10",),
        destinations=("10.0.0.0/8",),
    ) == ("old-route",)


def test_routing_configuration_comparison_detects_unrelated_protocol_change() -> None:
    before_root = ET.fromstring(
        "<config><network><logical-router><entry name='MainLR'><vrf>"
        "<entry name='default'><bgp><enable>yes</enable></bgp></entry>"
        "</vrf></entry></logical-router></network></config>"
    )
    after_root = ET.fromstring(
        "<config><network><logical-router><entry name='MainLR'><vrf>"
        "<entry name='default'><bgp><enable>no</enable></bgp></entry>"
        "</vrf></entry></logical-router></network></config>"
    )
    before = replace(
        _snapshot(),
        routing_configuration=route_validation._routing_configuration_entries(
            before_root
        ),
    )
    after = replace(
        _snapshot(),
        routing_configuration=route_validation._routing_configuration_entries(
            after_root
        ),
    )

    assert route_validation.compare_routing_configurations(before, after) == (
        "logical-router:MainLR",
    )


def test_routing_configuration_ignores_interface_member_order() -> None:
    first = ET.fromstring(
        "<config><network><virtual-router><entry name='default'><interface>"
        "<member>ethernet1/2</member><member>ethernet1/1</member>"
        "</interface></entry></virtual-router></network></config>"
    )
    second = ET.fromstring(
        "<config><network><virtual-router><entry name='default'><interface>"
        "<member>ethernet1/1</member><member>ethernet1/2</member>"
        "</interface></entry></virtual-router></network></config>"
    )
    before = replace(
        _snapshot(),
        routing_configuration=route_validation._routing_configuration_entries(first),
    )
    after = replace(
        _snapshot(),
        routing_configuration=route_validation._routing_configuration_entries(second),
    )

    assert route_validation.compare_routing_configurations(before, after) == ()


def test_compare_accepts_expected_tunnel_replacements() -> None:
    before = _snapshot(_route(prefix="169.254.1.0/30"))
    after = _snapshot(
        _route(
            prefix="169.254.240.0/30",
            interface="tunnel.21",
            next_hop="169.254.240.2",
        )
    )

    comparison = route_validation.compare_route_snapshots(
        before,
        after,
        prefix_map={"169.254.1.0/30": "169.254.240.0/30"},
        interface_map={"tunnel.2": "tunnel.21"},
        next_hop_map={"169.254.1.1": "169.254.240.2"},
    )

    assert comparison.equivalent is True


def test_compare_applies_protocol_scoped_path_mapping() -> None:
    before = _snapshot(_route())
    after = _snapshot(_route(interface="tunnel.21", next_hop="169.254.240.2"))

    comparison = route_validation.compare_route_snapshots(
        before,
        after,
        path_mappings=(
            RoutePathMapping(
                "tunnel.2",
                "169.254.1.1",
                "tunnel.21",
                "169.254.240.2",
                ("bgp",),
            ),
        ),
    )

    assert comparison.equivalent is True


def test_compare_limits_path_mapping_to_selected_prefixes() -> None:
    affected = _route(prefix="10.1.0.0/16")
    unrelated = _route(prefix="10.2.0.0/16")
    after = _snapshot(
        _route(
            prefix="10.1.0.0/16",
            interface="tunnel.21",
            next_hop="169.254.240.2",
        ),
        unrelated,
    )

    comparison = route_validation.compare_route_snapshots(
        _snapshot(affected, unrelated),
        after,
        path_mappings=(
            RoutePathMapping(
                "tunnel.2",
                "169.254.1.1",
                "tunnel.21",
                "169.254.240.2",
                ("bgp",),
                ("10.1.0.0/16",),
            ),
        ),
    )

    assert comparison.equivalent is True


def test_migration_compare_allows_new_link_routes_and_extra_candidates() -> None:
    mapped = _route(interface="tunnel.21", next_hop="169.254.240.2")
    old_candidate = _route()
    link_route = RouteEntry(
        routing_kind="logical-router",
        routing_instance="MainLR",
        vrf="default",
        prefix="169.254.240.0/30",
        protocol="connected",
        distance=0,
        metric=0,
        selected=True,
        installed=True,
        paths=(RoutePath(None, "tunnel.21", active=True),),
    )

    comparison = route_validation.compare_route_snapshots(
        _snapshot(_route()),
        _snapshot(mapped, old_candidate, link_route),
        path_mappings=(
            RoutePathMapping(
                "tunnel.2",
                "169.254.1.1",
                "tunnel.21",
                "169.254.240.2",
                ("bgp",),
            ),
        ),
        allowed_added_prefixes=("169.254.240.0/30",),
        allow_additional_candidates=True,
    )

    assert comparison.equivalent is True


def test_migration_compare_still_rejects_unrelated_added_route() -> None:
    comparison = route_validation.compare_route_snapshots(
        _snapshot(_route()),
        _snapshot(_route(), _route(prefix="203.0.113.0/24")),
        allowed_added_prefixes=("169.254.240.0/30",),
        allow_additional_candidates=True,
    )

    assert [item.identity[3] for item in comparison.added] == ["203.0.113.0/24"]


def test_compare_rejects_different_firewalls() -> None:
    with pytest.raises(RouteValidationError, match="same firewall"):
        route_validation.compare_route_snapshots(
            _snapshot(),
            _snapshot(serial="998877"),
        )


def test_discover_routing_instances_includes_vrs_and_all_vrfs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effective = ET.fromstring(
        """
        <response><result><config><devices><entry><network>
          <virtual-router><entry name="default" /></virtual-router>
          <logical-router><entry name="MainLR"><vrf>
            <entry name="default" /><entry name="blue" />
          </vrf></entry></logical-router>
        </network></entry></devices></config></result></response>
        """
    )
    monkeypatch.setattr(
        route_validation,
        "_read_effective_running_config",
        Mock(return_value=effective),
    )

    result = route_validation.discover_routing_instances(Mock(), "001122")

    assert result == (
        RoutingInstanceConfig("virtual-router", "default"),
        RoutingInstanceConfig("logical-router", "MainLR", "default"),
        RoutingInstanceConfig("logical-router", "MainLR", "blue"),
    )


def test_capture_queries_logical_router_once_for_multiple_vrfs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    op = Mock(
        return_value=ET.fromstring(
            '<response><result><json>{"MainLR": {}}</json></result></response>'
        )
    )
    discover = Mock(
        return_value=(
            RoutingInstanceConfig("logical-router", "MainLR", "default"),
            RoutingInstanceConfig("logical-router", "MainLR", "blue"),
        )
    )
    effective = ET.fromstring("<response><result /></response>")
    read_effective = Mock(return_value=effective)
    monkeypatch.setattr(route_validation, "discover_routing_instances", discover)
    monkeypatch.setattr(
        route_validation, "_read_effective_running_config", read_effective
    )
    monkeypatch.setattr(route_validation.Firewall, "op", op)

    snapshot = route_validation.capture_route_snapshot(
        panorama,
        "branch-01",
        "001122",
        captured_at=datetime(2026, 8, 19, tzinfo=UTC),
    )

    assert snapshot.routes == ()
    assert snapshot.bgp_peer_count == 0
    assert snapshot.captured_at == "2026-08-19T00:00:00+00:00"
    assert op.call_count == 1
    read_effective.assert_called_once_with(panorama, "001122", "vsys1")
    discover.assert_called_once_with(
        panorama,
        "001122",
        "vsys1",
        effective=effective,
    )


def test_counts_configured_legacy_and_advanced_bgp_peers() -> None:
    effective = ET.fromstring(
        """
        <config><network>
          <virtual-router><entry name="default"><protocol><bgp><peer-group>
            <entry name="legacy"><peer><entry name="peer-1" />
              <entry name="peer-2" /></peer></entry>
          </peer-group></bgp></protocol></entry></virtual-router>
          <logical-router><entry name="MainLR"><vrf><entry name="default"><bgp>
            <peer-group><entry name="advanced"><peer>
              <entry name="peer-3" />
            </peer></entry></peer-group>
          </bgp></entry></vrf></entry></logical-router>
        </network></config>
        """
    )

    assert route_validation._configured_bgp_peer_count(effective) == 3


def test_parse_mapping_rejects_malformed_values() -> None:
    with pytest.raises(RouteValidationError, match="expected OLD=NEW"):
        route_validation.parse_mapping(["tunnel.2"], "interface")


def test_compare_cli_returns_success_for_matching_snapshots(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(_snapshot(_route()).to_json(), encoding="utf-8")
    after.write_text(_snapshot(_route()).to_json(), encoding="utf-8")

    result = runner.invoke(cli.app, ["routes", "compare", str(before), str(after)])

    assert result.exit_code == 0
    assert "0 missing, 0 added, 0 changed" in result.output
    assert "Route tables match" in result.output


def test_compare_cli_returns_failure_for_route_drift(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(_snapshot(_route()).to_json(), encoding="utf-8")
    after.write_text(_snapshot().to_json(), encoding="utf-8")

    result = runner.invoke(cli.app, ["routes", "compare", str(before), str(after)])

    assert result.exit_code == 1
    assert "1 missing, 0 added, 0 changed" in result.output


def test_verify_migration_cli_captures_and_compares_post_routes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = replace(_snapshot(_route()), bgp_peer_count=2)
    baseline = tmp_path / "spoke_routes.json"
    baseline.write_text(before.to_json(), encoding="utf-8")
    manifest = MigrationValidationManifest(
        schema_version=1,
        created_at="2026-08-19T12:00:00+00:00",
        panorama_snapshot_name="LSVPN_PRE_a1b2c_260819120000.xml",
        endpoints=(
            MigrationEndpointValidation(
                role="spoke",
                firewall_name="branch-01",
                serial="001122",
                vsys="vsys1",
                baseline_snapshot=baseline.name,
                prefix_map={},
                path_mappings=(
                    RoutePathMapping(
                        "tunnel.2",
                        "169.254.1.1",
                        "tunnel.21",
                        "169.254.240.2",
                        ("bgp",),
                    ),
                ),
                allowed_added_prefixes=(),
            ),
        ),
    )
    manifest_path = tmp_path / "migration.json"
    manifest_path.write_text(manifest.to_json(), encoding="utf-8")
    monkeypatch.setattr(cli, "load_settings", Mock())
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    capture = Mock(
        return_value=replace(
            _snapshot(_route(interface="tunnel.21", next_hop="169.254.240.2")),
            bgp_peer_count=2,
        )
    )
    monkeypatch.setattr(cli, "capture_route_snapshot", capture)

    result = runner.invoke(
        cli.app,
        ["routes", "verify-migration", str(manifest_path)],
    )

    assert result.exit_code == 0
    assert "Configured BGP peers: pre=2, post=2" in result.output
    assert "Migration route verification passed" in result.output
    assert len(tuple(tmp_path.glob("LSVPN_POST_MIGRATION_*_routes.json"))) == 1

    baseline.write_text(
        replace(before, bgp_peer_count=3).to_json(),
        encoding="utf-8",
    )
    mismatch = runner.invoke(
        cli.app,
        ["routes", "verify-migration", str(manifest_path)],
    )

    assert mismatch.exit_code == 1
    assert "Configured BGP peers: pre=3, post=2" in mismatch.output


@pytest.mark.parametrize("endpoints", [[], {}, ""])
def test_manifest_rejects_empty_or_invalid_endpoints(endpoints: object) -> None:
    with pytest.raises(RouteValidationError, match="non-empty JSON array"):
        MigrationValidationManifest.from_json(
            json.dumps({"schema_version": 1, "endpoints": endpoints})
        )
