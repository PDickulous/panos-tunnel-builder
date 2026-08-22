from dataclasses import replace

from panos_tunnel_builder import lsvpn
from panos_tunnel_builder.inventory import (
    FirewallTemplateInventory,
    TemplateCandidate,
)
from panos_tunnel_builder.shared_migration import (
    SharedSpokeReplacement,
    prepare_shared_template_variables,
)


def _inventory(name: str, serial: str, stack: str) -> FirewallTemplateInventory:
    return FirewallTemplateInventory(
        name,
        serial,
        stack,
        (TemplateCandidate("shared", ("ethernet1/1",)),),
    )


def _plan(serial: str, offset: int) -> lsvpn.StandardIpsecClonePlan:
    spoke_source = lsvpn.HubTunnelInterfaceConfig(
        "tunnel.20",
        ("10.99.0.2/30",),
        False,
        None,
        None,
        None,
        None,
        ("default",),
        ("vpn",),
        (lsvpn.RoutingInstanceConfig("virtual-router", "default"),),
    )
    hub_source = replace(spoke_source, name="tunnel.10", ip_addresses=("10.99.0.1/30",))
    hub = lsvpn.HubGatewayCloneSource(
        "hub-gw",
        "198.51.100.1",
        "ethernet1/1",
        "198.51.100.1/24",
        None,
        None,
        None,
        hub_source,
        None,
        False,
        None,
        None,
        None,
        (),
        (),
        None,
        None,
        None,
        "$hub-wan",
    )
    satellite = lsvpn.SatelliteConfig(
        "legacy",
        "tunnel.20",
        "198.51.100.1",
        "ethernet1/1",
        f"203.0.113.{offset}/24",
        None,
        False,
        (),
        None,
        None,
        True,
        False,
        False,
        None,
        None,
    )
    return lsvpn.build_standard_clone_plan(
        satellite,
        portal_gateway=lsvpn.PortalGateway(
            "portal", "satellites", "hub-gw", "198.51.100.1", 1, (serial,)
        ),
        hub_gateway=hub,
        pre_shared_key=f"psk-{serial}",
        spoke_tunnel_source=spoke_source,
        replacement_spoke_tunnel_interface="tunnel.1",
        replacement_hub_tunnel_interface=f"tunnel.{offset}",
        resolved_published_routes=(),
        tunnel_addresses=lsvpn.TunnelAddressPair(
            f"10.251.{offset}.0/30",
            f"10.251.{offset}.1/30",
            f"10.251.{offset}.2/30",
        ),
        spoke_identity=serial,
        spoke_hostname=f"branch-{serial}",
        hub_hostname="hub-01",
    )


def test_shared_spoke_uses_one_structure_with_per_device_values() -> None:
    items = []
    for name, serial, stack, offset in (
        ("branch-1", "001", "stack-1", 50),
        ("branch-2", "002", "stack-2", 51),
    ):
        plan = _plan(serial, offset)
        replacement = lsvpn.build_standard_ipsec_objects(plan, shared_spoke_names=True)
        items.append(
            SharedSpokeReplacement(_inventory(name, serial, stack), plan, replacement)
        )

    variables = prepare_shared_template_variables("shared", "hub", tuple(items))

    assert items[0].replacement.spoke.ike_gateway.name == (
        items[0].plan.shared_spoke_ike_gateway_name
    )
    assert items[1].replacement.spoke.ike_gateway.name == (
        items[1].plan.shared_spoke_ike_gateway_name
    )
    assert "hub-01-to-shared-spokes-" in str(
        items[0].replacement.spoke.ipsec_tunnel.name
    )
    assert "hub-01-to-branch-001-" in str(items[0].replacement.hub.ipsec_tunnel.name)
    assert (
        items[0].replacement.spoke.ike_gateway.pre_shared_key
        == items[1].replacement.spoke.ike_gateway.pre_shared_key
    )
    psk_overrides = [
        item for item in variables.overrides if item.variable_type == "pre-shared-key"
    ]
    assert {item.value for item in psk_overrides} == {"psk-001", "psk-002"}
    assert {item.serial for item in psk_overrides} == {"001", "002"}
    assert len(variables.psk_fingerprint_pairs) == 2
    assert {
        (marker.template_name, marker.name) for marker in variables.ownership_markers
    } == {
        ("shared", variables.ownership_markers[0].name),
        ("hub", variables.ownership_markers[0].name),
    }
    fingerprint_overrides = {
        (item.serial, item.name): item.value
        for item in variables.overrides
        if "spoke-ike-psk-fingerprint" in item.name
    }
    fingerprint_definitions = {
        item.name: item.value
        for item in variables.definitions
        if "hub-ike-psk-fingerprint" in item.name
    }
    for pair in variables.psk_fingerprint_pairs:
        assert (
            fingerprint_overrides[(pair.spoke_serial, pair.spoke_fingerprint_name)]
            == fingerprint_definitions[pair.hub_fingerprint_name]
        )

    variable_names = {
        item.name for item in (*variables.definitions, *variables.overrides)
    }
    assert any("spoke-tunnel-interface-address" in name for name in variable_names)
    assert any("hub-ike-pre-shared-key" in name for name in variable_names)
    assert all(name.startswith("$ptb-") for name in variable_names)
