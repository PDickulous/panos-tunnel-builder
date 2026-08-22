import xml.etree.ElementTree as ET
from dataclasses import replace
from unittest.mock import Mock

import pytest
from panos.firewall import Firewall
from panos.network import IpsecTunnel, TunnelInterface, VirtualRouter, Zone
from panos.panorama import Panorama

from panos_tunnel_builder import lsvpn


def _satellite_tunnel() -> IpsecTunnel:
    return IpsecTunnel(
        "legacy-satellite",
        tunnel_interface="tunnel.2",
        type="global-protect-satellite",
        gps_portal_address="203.0.113.11",
        gps_interface="ethernet1/1",
        gps_interface_ipv4_ip="203.0.113.13/24",
        gps_publish_connected_routes=True,
        gps_publish_routes=["10.20.0.0/16"],
        gps_local_certificate="lsvpn-cert",
        gps_certificate_profile="lsvpn-ca",
        anti_replay=True,
    )


def test_discovers_local_satellite_through_panorama(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    refreshall = Mock(
        return_value=[
            _satellite_tunnel(),
            IpsecTunnel("normal-tunnel", type="auto-key"),
        ]
    )
    monkeypatch.setattr(lsvpn.IpsecTunnel, "refreshall", refreshall)

    result = lsvpn.discover_lsvpn_satellites(panorama, "001122")

    assert len(result) == 1
    assert result[0].name == "legacy-satellite"
    assert result[0].portal_address == "203.0.113.11"
    assert result[0].published_routes == ("10.20.0.0/16",)
    target = refreshall.call_args.args[0]
    assert target.serial == "001122"
    assert target.parent is panorama
    assert refreshall.call_args.kwargs == {
        "running_config": False,
        "add": False,
    }


def test_discovers_satellite_in_requested_vsys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    refreshall = Mock(return_value=[_satellite_tunnel()])
    monkeypatch.setattr(lsvpn.IpsecTunnel, "refreshall", refreshall)

    lsvpn.discover_lsvpn_satellites(panorama, "001122", "vsys2")

    firewall = refreshall.call_args.args[0]
    assert firewall.vsys == "vsys2"


def test_builds_standard_clone_plan_from_reusable_settings() -> None:
    source = lsvpn._to_satellite_config(_satellite_tunnel())

    result = lsvpn.build_standard_clone_plan(
        source,
        pre_shared_key="test-generated-psk",
    )

    assert result.tunnel_name == "legacy-satellite-standard"
    assert result.ike_gateway_name == "legacy-satellite-ike"
    assert result.tunnel_interface == "tunnel.2"
    assert result.local_interface == "ethernet1/1"
    assert result.local_address == "203.0.113.13/24"
    assert result.peer_address_candidate == "203.0.113.11"
    assert result.pre_shared_key == "test-generated-psk"
    assert result.crypto.ike_version == "ikev2"
    assert result.crypto.ike_encryption == ("aes-256-cbc",)
    assert result.crypto.ike_authentication == ("sha256",)
    assert result.crypto.ike_dh_groups == ("group14",)
    assert result.crypto.ipsec_protocol == "esp"
    assert result.crypto.esp_encryption == ("aes-256-cbc",)
    assert result.crypto.esp_authentication == ("sha256",)
    assert result.crypto.ah_authentication == ("sha256",)
    assert result.required_inputs == (
        "replacement tunnel address pool",
        "satellite connected/static route review",
    )
    assert any("certificate" in warning for warning in result.warnings)


def test_generates_unique_high_entropy_pre_shared_keys() -> None:
    first = lsvpn.generate_pre_shared_key()
    second = lsvpn.generate_pre_shared_key()

    assert first != second
    assert len(first) >= 43
    assert len(second) >= 43


def test_scoped_names_keep_spoke_identity_when_source_name_is_long() -> None:
    source = replace(
        lsvpn._to_satellite_config(_satellite_tunnel()),
        name="a-very-long-satellite-name-that-would-otherwise-truncate-the-serial",
    )

    plan = lsvpn.build_standard_clone_plan(
        source,
        pre_shared_key="test-generated-psk",
        spoke_identity="007954000891394",
    )

    assert plan.tunnel_name.endswith("-954000891394-standard")
    assert plan.ike_gateway_name.endswith("-954000891394-ike")
    assert len(plan.tunnel_name) <= 63
    assert len(plan.ike_gateway_name) <= 63


def test_endpoint_names_show_hub_spoke_and_three_digit_collision_number() -> None:
    source = lsvpn._to_satellite_config(_satellite_tunnel())

    plan = lsvpn.build_standard_clone_plan(
        source,
        pre_shared_key="test-generated-psk",
        spoke_identity="001122",
        spoke_hostname="branch 01.example.com",
        hub_hostname="hub-01.example.com",
    )

    assert plan.tunnel_name.startswith("hub-01.example.com-to-branch-01.example.com-")
    assert plan.tunnel_name[-4] == "-"
    assert plan.tunnel_name[-3:].isdigit()
    assert plan.ike_gateway_name == f"{plan.tunnel_name}-ike"
    assert len(plan.tunnel_name) <= 59
    assert len(plan.ike_gateway_name) <= 63


def test_preserves_portal_routing_priority_as_static_route_metric() -> None:
    portal = lsvpn.PortalGateway(
        "portal",
        "satellites",
        "backup",
        "198.51.100.20",
        10,
        (),
    )

    result = lsvpn.build_standard_clone_plan(
        lsvpn._to_satellite_config(_satellite_tunnel()),
        portal_gateway=portal,
        pre_shared_key="test-generated-psk",
    )

    assert result.spoke_route_metric == 100


def test_dynamic_routing_suppresses_lsvpn_derived_static_routes() -> None:
    dynamic = _dynamic_routing_source()
    result = lsvpn.build_standard_clone_plan(
        lsvpn._to_satellite_config(_satellite_tunnel()),
        pre_shared_key="test-generated-psk",
        resolved_published_routes=("10.20.0.0/16",),
        tunnel_addresses=lsvpn.TunnelAddressPair(
            "10.254.0.0/30",
            "10.254.0.1/30",
            "10.254.0.2/30",
        ),
        spoke_dynamic_routing=dynamic,
        hub_dynamic_routing=dynamic,
    )

    assert result.spoke_static_routes == ()
    assert result.hub_static_routes == ()
    assert (
        "matching hub/spoke dynamic-routing configuration" not in result.required_inputs
    )


def test_allocates_lowest_unused_tunnel_interface_names() -> None:
    def interface(name: str) -> lsvpn.HubTunnelInterfaceConfig:
        return lsvpn.HubTunnelInterfaceConfig(
            name=name,
            ip_addresses=(),
            ipv6_enabled=False,
            management_profile=None,
            mtu=None,
            netflow_profile=None,
            comment=None,
            virtual_routers=(),
            zones=(),
        )

    inventory = lsvpn.TunnelInterfaceInventory(
        (interface("tunnel.1"), interface("tunnel.3"), interface("named-tunnel"))
    )
    assert lsvpn.allocate_tunnel_interface_names(inventory, 3) == (
        "tunnel.2",
        "tunnel.4",
        "tunnel.5",
    )


def test_allocates_ipv4_and_ipv6_point_to_point_tunnel_addresses() -> None:
    assert lsvpn.allocate_tunnel_address_pairs("10.254.0.0/29", 2) == (
        lsvpn.TunnelAddressPair("10.254.0.0/30", "10.254.0.1/30", "10.254.0.2/30"),
        lsvpn.TunnelAddressPair("10.254.0.4/30", "10.254.0.5/30", "10.254.0.6/30"),
    )
    assert lsvpn.allocate_tunnel_address_pairs("2001:db8::/126", 2) == (
        lsvpn.TunnelAddressPair(
            "2001:db8::/127",
            "2001:db8::/127",
            "2001:db8::1/127",
        ),
        lsvpn.TunnelAddressPair(
            "2001:db8::2/127",
            "2001:db8::2/127",
            "2001:db8::3/127",
        ),
    )
    assert lsvpn.allocate_tunnel_address_pairs(
        "10.254.0.0/28",
        2,
        ("10.254.0.0/29",),
    ) == (
        lsvpn.TunnelAddressPair("10.254.0.8/30", "10.254.0.9/30", "10.254.0.10/30"),
        lsvpn.TunnelAddressPair(
            "10.254.0.12/30",
            "10.254.0.13/30",
            "10.254.0.14/30",
        ),
    )


def _dynamic_routing_source(
    peer_name: str = "old-peer",
) -> lsvpn.DynamicRoutingCloneSource:
    return lsvpn.DynamicRoutingCloneSource(
        bgp=(
            lsvpn.BgpPeerCloneSource(
                peer_group_name="vpn-peers",
                peer_group_type="ebgp",
                peer_name=peer_name,
                peer_as="65001",
                peer_address="10.99.0.1",
                local_interface="tunnel.2",
                local_address="10.99.0.2",
                enabled=True,
                authentication="bgp-auth",
                bfd_profile="vpn-bfd",
                keep_alive_interval=30,
                min_route_adv_interval=30,
                multihop=0,
                open_delay_time=0,
                hold_time=90,
                idle_hold_time=15,
            ),
        ),
        ospf=(
            lsvpn.OspfInterfaceCloneSource(
                area_name="0.0.0.0",
                area_type="normal",
                enabled=True,
                passive=False,
                link_type="p2mp",
                metric=20,
                priority=1,
                hello_interval=10,
                dead_counts=4,
                retransmit_interval=5,
                transit_delay=1,
                authentication="ospf-auth",
                bfd_profile="vpn-bfd",
                timing="ospf-timers",
            ),
        ),
    )


def test_discovers_and_builds_legacy_bgp_and_ospf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effective = ET.fromstring(
        """
        <response><result><config><devices><entry><network>
          <virtual-router><entry name="default">
            <interface><member>tunnel.2</member></interface>
            <protocol>
              <bgp><enable>yes</enable><peer-group><entry name="vpn-peers">
                <type><ebgp /></type><peer>
                  <entry name="branch-peer"><enable>yes</enable>
                    <peer-as>65001</peer-as>
                    <local-address><interface>tunnel.2</interface>
                      <ip>10.99.0.2</ip></local-address>
                    <peer-address><ip>10.99.0.1</ip></peer-address>
                    <connection-options><authentication>bgp-auth</authentication>
                      <keep-alive-interval>30</keep-alive-interval>
                      <hold-time>90</hold-time></connection-options>
                  </entry>
                  <entry name="other-peer"><peer-as>65002</peer-as>
                    <local-address><interface>tunnel.2</interface></local-address>
                    <peer-address><ip>10.99.0.99</ip></peer-address>
                  </entry>
                  <entry name="loopback-overlay"><peer-as>65000</peer-as>
                    <local-address><interface>loopback.1</interface>
                      <ip>10.255.255.1</ip></local-address>
                    <peer-address><ip>10.255.255.2</ip></peer-address>
                    <connection-options><multihop>2</multihop></connection-options>
                  </entry>
                </peer>
              </entry></peer-group><policy><export><rules>
                <entry name="advertise-loopback"><used-by>
                  <member>vpn-peers</member>
                </used-by><action><allow /></action></entry>
              </rules></export></policy></bgp>
              <ospf><enable>yes</enable><area><entry name="0.0.0.0">
                <type><normal /></type><interface><entry name="tunnel.2">
                  <enable>yes</enable><passive>no</passive>
                  <link-type><p2mp /></link-type><metric>20</metric>
                </entry></interface>
              </entry></area></ospf>
            </protocol>
          </entry></virtual-router>
        </network></entry></devices></config></result></response>
        """
    )

    def fake_op(self: Firewall, **kwargs: object) -> ET.Element:
        return effective

    monkeypatch.setattr(lsvpn.Firewall, "op", fake_op)
    source_interface = lsvpn.HubTunnelInterfaceConfig(
        name="tunnel.2",
        ip_addresses=("10.99.0.2/24",),
        ipv6_enabled=False,
        management_profile=None,
        mtu=None,
        netflow_profile=None,
        comment=None,
        virtual_routers=("default",),
        zones=("vpn",),
        routing_instances=(lsvpn.RoutingInstanceConfig("virtual-router", "default"),),
    )

    discovered = lsvpn.discover_dynamic_routing(
        Mock(),
        "001122",
        source_interface,
        peer_addresses=("10.99.0.1/24",),
    )

    assert discovered.protocols == ("BGP", "OSPF")
    assert len(discovered.bgp) == 1
    assert discovered.bgp[0].peer_name == "branch-peer"
    assert discovered.bgp[0].peer_as == "65001"
    assert discovered.bgp[0].export_policy_names == ("advertise-loopback",)
    assert discovered.transit_bgp == ()
    assert discovered.ospf[0].link_type == "p2mp"

    plan = lsvpn.build_standard_clone_plan(
        lsvpn._to_satellite_config(_satellite_tunnel()),
        pre_shared_key="test-generated-psk",
    )
    _, router, _ = lsvpn._build_endpoint_network_objects(
        plan,
        source_interface,
        "tunnel.3",
        (),
        "spoke",
        10,
        "10.254.0.2/30",
        "10.254.0.1/30",
        discovered,
    )

    assert isinstance(router, lsvpn.VirtualRouter)
    bgp = router.findall(lsvpn.Bgp)[0]
    peer = bgp.findall(lsvpn.BgpPeerGroup)[0].findall(lsvpn.BgpPeer)[0]
    assert peer.name == "branch-peer-standard"
    assert peer.local_interface == "tunnel.3"
    assert peer.local_interface_ip == "10.254.0.2"
    assert peer.peer_address_ip == "10.254.0.1"
    ospf = router.findall(lsvpn.Ospf)[0]
    ospf_interface = ospf.findall(lsvpn.OspfArea)[0].findall(lsvpn.OspfAreaInterface)[0]
    assert ospf_interface.name == "tunnel.3"
    assert ospf_interface.link_type == "p2p"


def test_preserves_loopback_bgp_session_transiting_replacement_ospf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def effective(
        tunnel: str,
        loopback: str,
        local_loopback: str,
        remote_loopback: str,
        peer_name: str,
    ) -> ET.Element:
        return ET.fromstring(
            f"""
            <response><result><config><devices><entry><network>
              <interface><loopback><units><entry name="{loopback}"><ip>
                <entry name="{local_loopback}/32" />
              </ip></entry></units></loopback></interface>
              <virtual-router><entry name="default">
                <interface><member>{tunnel}</member><member>{loopback}</member></interface>
                <protocol>
                  <ospf><enable>yes</enable><area><entry name="0.0.0.0">
                    <interface><entry name="{tunnel}"><enable>yes</enable>
                      <link-type><p2mp /></link-type>
                    </entry><entry name="{loopback}"><enable>yes</enable>
                      <passive>yes</passive>
                    </entry></interface>
                  </entry></area></ospf>
                  <bgp><enable>yes</enable><peer-group><entry name="overlay">
                    <type><ibgp /></type><peer><entry name="{peer_name}">
                      <peer-as>65000</peer-as>
                      <local-address><interface>{loopback}</interface></local-address>
                      <peer-address><ip>{remote_loopback}</ip></peer-address>
                      <connection-options><multihop>2</multihop></connection-options>
                    </entry></peer></entry></peer-group></bgp>
                </protocol>
              </entry></virtual-router>
            </network></entry></devices></config></result></response>
            """
        )

    spoke_effective = effective(
        "tunnel.2",
        "loopback.1",
        "10.255.255.1",
        "10.255.255.2",
        "hub-overlay",
    )
    hub_effective = effective(
        "tunnel.10",
        "loopback.10",
        "10.255.255.2",
        "10.255.255.1",
        "spoke-overlay",
    )

    def fake_op(self: Firewall, **kwargs: object) -> ET.Element:
        return spoke_effective if self.serial == "001122" else hub_effective

    monkeypatch.setattr(lsvpn.Firewall, "op", fake_op)

    def source(name: str) -> lsvpn.HubTunnelInterfaceConfig:
        return lsvpn.HubTunnelInterfaceConfig(
            name=name,
            ip_addresses=("10.99.0.1/24",),
            ipv6_enabled=False,
            management_profile=None,
            mtu=None,
            netflow_profile=None,
            comment=None,
            virtual_routers=("default",),
            zones=("vpn",),
            routing_instances=(
                lsvpn.RoutingInstanceConfig("virtual-router", "default"),
            ),
        )

    spoke = lsvpn.discover_dynamic_routing(Mock(), "001122", source("tunnel.2"))
    hub = lsvpn.discover_dynamic_routing(Mock(), "998877", source("tunnel.10"))
    spoke, hub = lsvpn.match_loopback_bgp_transit(spoke, hub)

    assert spoke.protocols == ("BGP", "OSPF")
    assert hub.protocols == ("BGP", "OSPF")
    assert spoke.bgp == ()
    assert hub.bgp == ()
    assert [peer.peer_name for peer in spoke.transit_bgp] == ["hub-overlay"]
    assert spoke.transit_bgp[0].local_address == "10.255.255.1/32"
    assert [peer.peer_name for peer in hub.transit_bgp] == ["spoke-overlay"]

    plan = lsvpn.build_standard_clone_plan(
        lsvpn._to_satellite_config(_satellite_tunnel()),
        pre_shared_key="test-generated-psk",
        resolved_published_routes=("10.20.0.0/16",),
        tunnel_addresses=lsvpn.TunnelAddressPair(
            "10.254.0.0/30",
            "10.254.0.1/30",
            "10.254.0.2/30",
        ),
        spoke_dynamic_routing=spoke,
        hub_dynamic_routing=hub,
    )
    _, router, _ = lsvpn._build_endpoint_network_objects(
        plan,
        source("tunnel.2"),
        "tunnel.3",
        plan.spoke_static_routes,
        "spoke",
        10,
        "10.254.0.2/30",
        "10.254.0.1/30",
        spoke,
    )

    assert plan.spoke_static_routes == ()
    assert plan.hub_static_routes == ()
    assert router.findall(lsvpn.Bgp) == []
    assert len(router.findall(lsvpn.Ospf)) == 1


def test_detects_loopback_bgp_transit_without_ospf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effective = ET.fromstring(
        """
        <response><result><config><devices><entry><network>
          <interface><loopback><units><entry name="loopback.65"><ip>
            <entry name="169.254.65.1/32" />
          </ip></entry></units></loopback></interface>
          <virtual-router><entry name="default">
            <interface><member>tunnel.2</member><member>loopback.65</member></interface>
            <protocol><bgp><enable>yes</enable><peer-group><entry name="overlay">
              <type><ibgp /></type><peer><entry name="remote-loopback">
                <peer-as>65000</peer-as>
                <local-address><interface>loopback.65</interface></local-address>
                <peer-address><ip>169.254.65.2</ip></peer-address>
                <connection-options><multihop>2</multihop></connection-options>
              </entry></peer></entry></peer-group></bgp></protocol>
          </entry></virtual-router>
        </network></entry></devices></config></result></response>
        """
    )
    monkeypatch.setattr(lsvpn.Firewall, "op", Mock(return_value=effective))
    source = lsvpn.HubTunnelInterfaceConfig(
        name="tunnel.2",
        ip_addresses=(),
        ipv6_enabled=False,
        management_profile=None,
        mtu=None,
        netflow_profile=None,
        comment=None,
        virtual_routers=("default",),
        zones=("vpn",),
        routing_instances=(lsvpn.RoutingInstanceConfig("virtual-router", "default"),),
    )

    dynamic = lsvpn.discover_dynamic_routing(Mock(), "001122", source)

    assert dynamic.bgp == ()
    assert dynamic.ospf == ()
    assert [peer.peer_name for peer in dynamic.transit_bgp] == ["remote-loopback"]
    assert dynamic.protocols == ("BGP",)


def test_builds_static_peer_routes_for_loopback_bgp_without_ospf() -> None:
    def peer(
        name: str,
        local: str,
        remote: str,
        loopback: str,
    ) -> lsvpn.BgpPeerCloneSource:
        return lsvpn.BgpPeerCloneSource(
            peer_group_name="overlay",
            peer_group_type="ebgp",
            peer_name=name,
            peer_as="65001",
            peer_address=remote,
            local_interface=loopback,
            local_address=f"{local}/32",
            enabled=True,
            authentication=None,
            bfd_profile=None,
            keep_alive_interval=None,
            min_route_adv_interval=None,
            multihop=0,
            open_delay_time=None,
            hold_time=None,
            idle_hold_time=None,
        )

    spoke_dynamic = lsvpn.DynamicRoutingCloneSource(
        transit_bgp=(peer("hub", "169.254.101.1", "169.254.1.1", "loopback.100"),)
    )
    hub_dynamic = lsvpn.DynamicRoutingCloneSource(
        transit_bgp=(peer("spoke", "169.254.1.1", "169.254.101.1", "loopback.100"),)
    )
    source = lsvpn.HubTunnelInterfaceConfig(
        name="tunnel.2",
        ip_addresses=(),
        ipv6_enabled=False,
        management_profile=None,
        mtu=None,
        netflow_profile=None,
        comment=None,
        virtual_routers=("default",),
        zones=("vpn",),
        routing_instances=(lsvpn.RoutingInstanceConfig("virtual-router", "default"),),
    )
    plan = lsvpn.build_standard_clone_plan(
        lsvpn._to_satellite_config(_satellite_tunnel()),
        pre_shared_key="test-generated-psk",
        resolved_published_routes=("10.20.0.0/16",),
        tunnel_addresses=lsvpn.TunnelAddressPair(
            "10.254.0.0/30",
            "10.254.0.1/30",
            "10.254.0.2/30",
        ),
        spoke_dynamic_routing=spoke_dynamic,
        hub_dynamic_routing=hub_dynamic,
    )

    assert plan.required_inputs == ()
    assert plan.spoke_static_routes == ("169.254.1.1/32",)
    assert plan.hub_static_routes == ("169.254.101.1/32",)
    _, spoke_router, _ = lsvpn._build_endpoint_network_objects(
        plan,
        source,
        "tunnel.3",
        plan.spoke_static_routes,
        "spoke",
        10,
        "10.254.0.2/30",
        "10.254.0.1/30",
        spoke_dynamic,
    )
    route = spoke_router.findall(lsvpn.StaticRoute)[0]
    assert route.destination == "169.254.1.1/32"
    assert route.interface == "tunnel.3"
    assert spoke_router.findall(lsvpn.Bgp) == []
    assert spoke_dynamic.transit_bgp[0].local_interface == "loopback.100"


def test_preserves_logical_router_route_map_advertising_link_local_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effective = ET.fromstring(
        """
        <response><result><config><devices><entry><network>
          <interface>
            <tunnel><units><entry name="tunnel.2"><ip>
              <entry name="10.99.0.2/30" />
            </ip></entry></units></tunnel>
            <loopback><units><entry name="loopback.65"><ip>
              <entry name="169.254.65.1/32" />
            </ip></entry></units></loopback>
          </interface>
          <logical-router><entry name="MainLR"><vrf><entry name="default">
            <interface><member>tunnel.2</member><member>loopback.65</member></interface>
            <bgp><enable>yes</enable><peer-group><entry name="lsvpn-direct">
              <type><ebgp /></type>
              <address-family><ipv4>ipv4-unicast</ipv4></address-family>
              <filtering-profile><ipv4>advertise-link-local</ipv4></filtering-profile>
              <connection-options><timers>bgp-timers</timers></connection-options>
              <peer><entry name="hub-direct"><peer-as>65001</peer-as>
                <local-address><interface>tunnel.2</interface>
                  <ip>10.99.0.2</ip></local-address>
                <peer-address><ip>10.99.0.1</ip></peer-address>
              </entry></peer>
            </entry></peer-group></bgp>
          </entry></vrf></entry></logical-router>
          <routing-profile><filter><route-maps>
            <entry name="advertise-link-local"><route-map><entry name="permit-loopback">
              <match><ip><address><prefix-list>link-local-loopback</prefix-list>
              </address></ip></match><action>permit</action>
            </entry></route-map></entry>
          </route-maps></filter></routing-profile>
        </network></entry></devices></config></result></response>
        """
    )

    def fake_op(self: Firewall, **kwargs: object) -> ET.Element:
        return effective

    monkeypatch.setattr(lsvpn.Firewall, "op", fake_op)
    source = lsvpn.HubTunnelInterfaceConfig(
        name="tunnel.2",
        ip_addresses=("10.99.0.2/30",),
        ipv6_enabled=False,
        management_profile=None,
        mtu=None,
        netflow_profile=None,
        comment=None,
        virtual_routers=("MainLR",),
        zones=("vpn",),
        routing_instances=(
            lsvpn.RoutingInstanceConfig("logical-router", "MainLR", "default"),
        ),
    )

    dynamic = lsvpn.discover_dynamic_routing(
        Mock(),
        "001122",
        source,
        peer_addresses=("10.99.0.1/30",),
    )

    assert dynamic.protocols == ("BGP",)
    assert dynamic.transit_bgp == ()
    assert dynamic.bgp[0].filtering_profile_ipv4 == "advertise-link-local"
    assert dynamic.bgp[0].address_family_ipv4 == "ipv4-unicast"
    assert dynamic.bgp[0].timer_profile == "bgp-timers"

    plan = lsvpn.build_standard_clone_plan(
        lsvpn._to_satellite_config(_satellite_tunnel()),
        pre_shared_key="test-generated-psk",
    )
    _, router, _ = lsvpn._build_endpoint_network_objects(
        plan,
        source,
        "tunnel.3",
        (),
        "spoke",
        10,
        "10.254.0.2/30",
        "10.254.0.1/30",
        dynamic,
    )

    assert isinstance(router, lsvpn.LogicalRouter)
    group = router.findall(lsvpn.Vrf)[0].findall(lsvpn.VrfBgpPeerGroup)[0]
    assert group.name == "lsvpn-direct"
    assert group.filtering_profile_ipv4 == "advertise-link-local"
    assert group.address_family_ipv4 == "ipv4-unicast"
    assert group.connection_options_timers == "bgp-timers"


def test_builds_logical_router_vrf_network_objects() -> None:
    source = lsvpn.HubTunnelInterfaceConfig(
        name="tunnel.10",
        ip_addresses=(),
        ipv6_enabled=False,
        management_profile=None,
        mtu=1400,
        netflow_profile=None,
        comment=None,
        virtual_routers=("MainLR",),
        zones=("vpn",),
        routing_instances=(
            lsvpn.RoutingInstanceConfig("logical-router", "MainLR", "default"),
        ),
    )
    plan = lsvpn.build_standard_clone_plan(
        lsvpn._to_satellite_config(_satellite_tunnel()),
        pre_shared_key="test-generated-psk",
    )

    interface, router, zone = lsvpn._build_endpoint_network_objects(
        plan,
        source,
        "tunnel.11",
        ("10.0.0.0/8", "2001:db8::/32"),
        "hub",
        10,
        "10.255.0.1/30",
        "10.255.0.2/30",
        _dynamic_routing_source(),
    )

    assert isinstance(router, lsvpn.LogicalRouter)
    vrf = router.findall(lsvpn.Vrf)[0]
    assert vrf.name == "default"
    assert vrf.interface == ["tunnel.11"]
    assert vrf.findall(lsvpn.VrfStaticRoute)[0].destination == "10.0.0.0/8"
    assert vrf.findall(lsvpn.VrfStaticRouteV6)[0].destination == "2001:db8::/32"
    bgp_peer = vrf.findall(lsvpn.VrfBgpPeerGroup)[0].findall(lsvpn.VrfBgpPeer)[0]
    assert bgp_peer.local_address_interface == "tunnel.11"
    assert bgp_peer.peer_address_value == "10.255.0.2"
    ospf_interface = vrf.findall(lsvpn.VrfOspfArea)[0].findall(
        lsvpn.VrfOspfAreaInterface
    )[0]
    assert ospf_interface.name == "tunnel.11"
    assert ospf_interface.link_type == "p2p"
    assert interface.ipv6_enabled is True
    assert zone.interface == ["tunnel.11"]


def test_merges_multiple_dynamic_tunnels_in_one_virtual_router() -> None:
    source = lsvpn.HubTunnelInterfaceConfig(
        name="tunnel.2",
        ip_addresses=("10.99.0.2/24",),
        ipv6_enabled=False,
        management_profile=None,
        mtu=None,
        netflow_profile=None,
        comment=None,
        virtual_routers=("default",),
        zones=("vpn",),
        routing_instances=(lsvpn.RoutingInstanceConfig("virtual-router", "default"),),
    )
    plan = lsvpn.build_standard_clone_plan(
        lsvpn._to_satellite_config(_satellite_tunnel()),
        pre_shared_key="test-generated-psk",
    )
    _, first, _ = lsvpn._build_endpoint_network_objects(
        plan,
        source,
        "tunnel.3",
        (),
        "hub",
        10,
        "10.254.0.1/30",
        "10.254.0.2/30",
        _dynamic_routing_source("peer-one"),
    )
    _, second, _ = lsvpn._build_endpoint_network_objects(
        plan,
        source,
        "tunnel.4",
        (),
        "hub",
        10,
        "10.254.0.5/30",
        "10.254.0.6/30",
        _dynamic_routing_source("peer-two"),
    )

    lsvpn._merge_routing_objects(first, second)

    assert isinstance(first, lsvpn.VirtualRouter)
    assert first.interface == ["tunnel.3", "tunnel.4"]
    bgp = first.findall(lsvpn.Bgp)[0]
    peers = bgp.findall(lsvpn.BgpPeerGroup)[0].findall(lsvpn.BgpPeer)
    assert [peer.name for peer in peers] == [
        "peer-one-standard",
        "peer-two-standard",
    ]
    ospf = first.findall(lsvpn.Ospf)[0]
    interfaces = ospf.findall(lsvpn.OspfArea)[0].findall(lsvpn.OspfAreaInterface)
    assert [interface.name for interface in interfaces] == ["tunnel.3", "tunnel.4"]


def test_discovers_publish_all_routes_from_exact_logical_router_vrf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effective = ET.fromstring(
        """
        <response><result><config><devices><entry><network>
          <interface>
            <ethernet>
              <entry name="ethernet1/3"><layer3><ip>
                <entry name="10.20.1.1/24" />
              </ip></layer3></entry>
              <entry name="ethernet1/1"><layer3><ip>
                <entry name="198.51.100.2/24" />
              </ip></layer3></entry>
            </ethernet>
            <tunnel><units><entry name="tunnel.2" /></units></tunnel>
            <loopback><units><entry name="loopback.1"><ip>
              <entry name="10.255.255.1/32" />
            </ip></entry></units></loopback>
          </interface>
          <logical-router><entry name="MainLR"><vrf><entry name="default">
            <interface>
              <member>ethernet1/3</member><member>ethernet1/1</member>
              <member>tunnel.2</member><member>loopback.1</member>
            </interface>
            <routing-table><ip><static-route>
              <entry name="default"><destination>0.0.0.0/0</destination>
                <interface>ethernet1/1</interface></entry>
              <entry name="branch-extra"><destination>10.30.0.0/16</destination>
                <interface>ethernet1/1</interface></entry>
              <entry name="discard-summary"><destination>10.40.0.0/16</destination>
                <nexthop><discard /></nexthop></entry>
              <entry name="back-to-lsvpn"><destination>10.50.0.0/16</destination>
                <interface>tunnel.2</interface></entry>
            </static-route></ip></routing-table>
          </entry></vrf></entry></logical-router>
        </network></entry></devices></config></result></response>
        """
    )

    def fake_op(self: Firewall, **kwargs: object) -> ET.Element:
        return effective

    monkeypatch.setattr(lsvpn.Firewall, "op", fake_op)
    satellite = lsvpn._to_satellite_config(_satellite_tunnel())
    source = lsvpn.HubTunnelInterfaceConfig(
        name="tunnel.2",
        ip_addresses=(),
        ipv6_enabled=False,
        management_profile=None,
        mtu=None,
        netflow_profile=None,
        comment=None,
        virtual_routers=("MainLR",),
        zones=("lsvpnsat",),
        routing_instances=(
            lsvpn.RoutingInstanceConfig("logical-router", "MainLR", "default"),
        ),
    )

    result = lsvpn.discover_satellite_published_routes(
        Mock(),
        "001122",
        satellite,
        source,
    )

    assert result == (
        "10.20.0.0/16",
        "10.40.0.0/16",
        "10.20.1.0/24",
        "10.255.255.1/32",
    )


def test_builds_unapplied_standard_ipsec_sdk_objects() -> None:
    satellite = lsvpn._to_satellite_config(_satellite_tunnel())
    portal_gateway = lsvpn.PortalGateway(
        "LSVPN-Portal",
        "branches",
        "Denver-Hub",
        "vpn.example.test",
        1,
        (),
    )
    hub_gateway = lsvpn.HubGatewayCloneSource(
        name="LSVPN_GW",
        address="vpn.example.test",
        external_interface="ethernet1/3",
        external_ipv4="198.51.100.20/24",
        external_ipv6=None,
        floating_ipv4=None,
        floating_ipv6=None,
        tunnel_interface=lsvpn.HubTunnelInterfaceConfig(
            name="tunnel.10",
            ip_addresses=("10.255.0.1/24",),
            ipv6_enabled=False,
            management_profile=None,
            mtu=None,
            netflow_profile=None,
            comment=None,
            virtual_routers=("default",),
            zones=("lsvpn",),
        ),
        ipsec_crypto_profile="legacy-profile",
        tunnel_monitor_enabled=True,
        tunnel_monitor_destination="10.255.0.2",
        tunnel_monitor_profile="fail-over",
        tunnel_monitor_source=None,
        access_routes=(),
        client_ip_pools=("10.255.0.0/24",),
        dns_primary=None,
        dns_secondary=None,
        dns_suffix=None,
    )
    plan = lsvpn.build_standard_clone_plan(
        satellite,
        portal_gateway=portal_gateway,
        hub_gateway=hub_gateway,
        pre_shared_key="test-generated-psk",
        spoke_tunnel_source=lsvpn.HubTunnelInterfaceConfig(
            name="tunnel.2",
            ip_addresses=(),
            ipv6_enabled=False,
            management_profile=None,
            mtu=1420,
            netflow_profile=None,
            comment="LSVPN spoke",
            virtual_routers=("default",),
            zones=("lsvpnsat",),
            routing_instances=(
                lsvpn.RoutingInstanceConfig("virtual-router", "default"),
            ),
        ),
        replacement_spoke_tunnel_interface="tunnel.3",
        replacement_hub_tunnel_interface="tunnel.11",
        tunnel_addresses=lsvpn.TunnelAddressPair(
            "10.254.0.0/30",
            "10.254.0.1/30",
            "10.254.0.2/30",
        ),
    )

    result = lsvpn.build_standard_ipsec_objects(plan)

    assert result.spoke.ike_crypto_profile.dh_group == ["group14"]
    assert result.spoke.ike_crypto_profile.authentication == ["sha256"]
    assert result.spoke.ike_crypto_profile.encryption == ["aes-256-cbc"]
    assert result.spoke.ike_crypto_profile.lifetime_hours == 8
    assert result.spoke.ipsec_crypto_profile.esp_encryption == ["aes-256-cbc"]
    assert result.spoke.ipsec_crypto_profile.esp_authentication == ["sha256"]
    assert result.spoke.ipsec_crypto_profile.ah_authentication is None
    assert result.spoke.ipsec_crypto_profile.dh_group == "group14"
    assert result.spoke.ipsec_crypto_profile.lifetime_hours == 1
    assert result.spoke.ike_crypto_profile is not result.hub.ike_crypto_profile
    assert result.spoke.ipsec_crypto_profile is not result.hub.ipsec_crypto_profile
    assert result.spoke.ike_gateway.peer_ip_type == "fqdn"
    assert result.spoke.ike_gateway.peer_ip_value == "vpn.example.test"
    assert result.spoke.ike_gateway.local_ip_address == "203.0.113.13/24"
    assert result.spoke.ike_gateway.pre_shared_key == "test-generated-psk"
    assert result.spoke.ike_gateway.enable_fragmentation is False
    assert result.spoke.ike_gateway.ikev2_crypto_profile == "ptb-ike-moderate"
    assert result.spoke.ipsec_tunnel.type == "auto-key"
    assert result.spoke.ipsec_tunnel.ak_ike_gateway == ["legacy-satellite-ike"]
    assert result.hub.ike_gateway.peer_ip_type == "ip"
    assert result.hub.ike_gateway.peer_ip_value == "203.0.113.13"
    assert result.hub.ike_gateway.local_ip_address == "198.51.100.20/24"
    assert result.hub.ike_gateway.pre_shared_key == "test-generated-psk"
    assert result.hub.ike_gateway.enable_fragmentation is False
    assert result.spoke.ipsec_tunnel.tunnel_interface == "tunnel.3"
    assert result.hub.ipsec_tunnel.tunnel_interface == "tunnel.11"
    assert result.hub.ipsec_tunnel.enable_tunnel_monitor is True
    assert result.hub.ipsec_tunnel.tunnel_monitor_dest_ip == "10.254.0.2"
    assert result.hub.ipsec_tunnel.tunnel_monitor_profile == "fail-over"
    assert result.spoke.tunnel_interface.name == "tunnel.3"
    assert result.spoke.tunnel_interface.ip == ["10.254.0.2/30"]
    assert result.spoke.tunnel_interface.mtu == 1420
    assert result.spoke.zone.name == "lsvpnsat"
    assert result.spoke.zone.interface == ["tunnel.3"]
    assert result.spoke.routing_object.name == "default"
    spoke_routes = result.spoke.routing_object.findall(lsvpn.StaticRoute)
    assert len(spoke_routes) == 1
    assert spoke_routes[0].destination == "0.0.0.0/0"
    assert spoke_routes[0].interface == "tunnel.3"
    assert spoke_routes[0].metric == 10
    hub_routes = result.hub.routing_object.findall(lsvpn.StaticRoute)
    assert len(hub_routes) == 1
    assert hub_routes[0].destination == "10.20.0.0/16"
    assert hub_routes[0].interface == "tunnel.11"

    panorama = Panorama("panorama.example.test")
    panorama._version_info = (11, 1, 0)
    staged = lsvpn.stage_standard_ipsec_objects(
        panorama,
        "spoke-network",
        "hub-network",
        (result,),
    )

    assert result.spoke.ike_gateway.parent is staged.spoke_template
    assert result.spoke.ipsec_tunnel.parent is staged.spoke_template
    assert result.spoke.tunnel_interface.parent is staged.spoke_template
    assert result.spoke.zone.parent is staged.spoke_vsys
    assert result.spoke.routing_object.parent is staged.spoke_template
    assert result.hub.ike_gateway.parent is staged.hub_template
    assert result.hub.ipsec_tunnel.parent is staged.hub_template
    spoke_ike_xml = result.spoke.ike_gateway.element_str().decode()
    spoke_tunnel_xml = result.spoke.ipsec_tunnel.element_str().decode()
    assert "<version>ikev2</version>" in spoke_ike_xml
    assert "<fqdn>vpn.example.test</fqdn>" in spoke_ike_xml
    assert "<key>test-generated-psk</key>" in spoke_ike_xml
    assert "<ike-crypto-profile>ptb-ike-moderate</ike-crypto-profile>" in spoke_ike_xml
    assert "<fragmentation><enable>no</enable></fragmentation>" in spoke_ike_xml
    assert "<auto-key>" in spoke_tunnel_xml
    assert "<ipsec-crypto-profile>ptb-ipsec-esp-moderate" in spoke_tunnel_xml
    assert "<tunnel-interface>tunnel.3</tunnel-interface>" in spoke_tunnel_xml


def test_resolves_ike_address_to_exact_owning_interface_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effective = ET.fromstring(
        """
        <response><result><config><devices><entry><network><interface>
          <ethernet><entry name="ethernet1/1"><layer3><ip>
            <entry name="192.0.2.1/24" />
          </ip><units><entry name="ethernet1/1.20"><ip>
            <entry name="10.1.20.1/24" />
          </ip></entry></units></layer3></entry></ethernet>
        </interface></network></entry></devices></config></result></response>
        """
    )
    monkeypatch.setattr(
        lsvpn,
        "_read_effective_running_config",
        Mock(return_value=effective),
    )

    result = lsvpn.resolve_ike_local_endpoint(
        Mock(),
        "001122",
        "ethernet1/1",
        "10.1.20.1",
        role="spoke",
    )

    assert result == ("ethernet1/1.20", "10.1.20.1/24")


def test_rejects_ike_address_missing_from_all_interfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effective = ET.fromstring(
        """
        <response><result><config><devices><entry><network><interface>
          <ethernet><entry name="ethernet1/1"><layer3><ip>
            <entry name="192.0.2.1/24" />
          </ip></layer3></entry></ethernet>
        </interface></network></entry></devices></config></result></response>
        """
    )
    monkeypatch.setattr(
        lsvpn,
        "_read_effective_running_config",
        Mock(return_value=effective),
    )

    with pytest.raises(
        lsvpn.LsvpnConfigurationError,
        match="is not configured",
    ):
        lsvpn.resolve_ike_local_endpoint(
            Mock(),
            "001122",
            "ethernet1/1",
            "10.1.20.1/24",
            role="spoke",
        )


def test_discovers_active_gateway_through_panorama(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    response = ET.fromstring(
        """
        <response status="success">
          <result>
            <globalprotect-gateway-name>Denver-Hub</globalprotect-gateway-name>
            <globalprotect-gateway-address>198.51.100.20</globalprotect-gateway-address>
            <tunnel-monitor-status>Up</tunnel-monitor-status>
          </result>
        </response>
        """
    )
    captured_firewalls: list[Firewall] = []
    captured_kwargs: dict[str, object] = {}

    def fake_op(self: Firewall, **kwargs: object) -> ET.Element:
        captured_firewalls.append(self)
        captured_kwargs.update(kwargs)
        return response

    monkeypatch.setattr(lsvpn.Firewall, "op", fake_op)
    satellite = lsvpn._to_satellite_config(_satellite_tunnel())

    result = lsvpn.discover_active_gateway(panorama, "001122", satellite)

    assert result.gateway_name == "Denver-Hub"
    assert result.gateway_address == "198.51.100.20"
    assert result.status == "Up"
    firewall = captured_firewalls[0]
    assert firewall.serial == "001122"
    assert firewall.parent is panorama
    command_bytes = captured_kwargs["cmd"]
    assert isinstance(command_bytes, bytes)
    command = ET.fromstring(command_bytes)
    assert command.findtext(".//gateway") == "203.0.113.11"
    assert command.findtext(".//satellite") == "legacy-satellite"
    assert captured_kwargs["cmd_xml"] is False


def test_clone_plan_prefers_different_active_gateway() -> None:
    source = lsvpn._to_satellite_config(_satellite_tunnel())
    runtime = lsvpn.GatewayRuntime(
        satellite_name=source.name,
        gateway_name="Denver-Hub",
        gateway_address="198.51.100.20",
        status="Up",
    )

    result = lsvpn.build_standard_clone_plan(source, runtime)

    assert result.configured_portal_address == "203.0.113.11"
    assert result.active_gateway_address == "198.51.100.20"
    assert result.peer_address_candidate == "198.51.100.20"
    assert any("differs" in warning for warning in result.warnings)


def test_discovers_portal_satellite_gateways_through_panorama() -> None:
    panorama = Mock()
    panorama.xapi.show.return_value = ET.fromstring(
        """
        <response status="success">
          <result>
            <global-protect-portal>
              <entry name="LSVPN-Portal">
                <satellite-config>
                  <configs>
                    <entry name="branches">
                      <devices>
                        <entry name="001122" />
                      </devices>
                      <gateways>
                        <entry name="Denver-Hub">
                          <ip><ipv4>198.51.100.20</ipv4></ip>
                          <priority>1</priority>
                        </entry>
                        <entry name="Backup-Hub">
                          <ip><ipv4>198.51.100.21</ipv4></ip>
                          <priority>10</priority>
                        </entry>
                      </gateways>
                    </entry>
                  </configs>
                </satellite-config>
              </entry>
            </global-protect-portal>
          </result>
        </response>
        """
    )

    result = lsvpn.discover_portal_gateways(panorama, "998877")

    assert [gateway.name for gateway in result] == ["Denver-Hub", "Backup-Hub"]
    assert [gateway.address for gateway in result] == [
        "198.51.100.20",
        "198.51.100.21",
    ]
    assert [gateway.priority for gateway in result] == [1, 10]
    assert result[0].satellite_serials == ("001122",)
    panorama.xapi.show.assert_called_once_with(
        lsvpn.PORTAL_XPATH,
        extra_qs={"target": "998877"},
    )


def test_treats_any_device_as_unrestricted_satellite_config() -> None:
    response = ET.fromstring(
        """
        <response><result><global-protect-portal><entry name="LSVPN-Portal">
          <satellite-config><configs><entry name="authenticated-branches">
            <devices><entry name="any" /></devices>
            <source-user><member>branch-admins</member></source-user>
            <gateways><entry name="Denver-Hub">
              <ip><ipv4>198.51.100.20</ipv4></ip>
            </entry></gateways>
          </entry></configs></satellite-config>
        </entry></global-protect-portal></result></response>
        """
    )

    result = lsvpn._parse_portal_gateways(response)

    assert len(result) == 1
    assert result[0].satellite_serials == ()


@pytest.mark.parametrize(
    ("address_xml", "expected"),
    [
        ("<fqdn>vpn.example.test</fqdn>", "vpn.example.test"),
        ("<ip><fqdn>vpn.example.test</fqdn></ip>", "vpn.example.test"),
    ],
)
def test_parses_portal_gateway_fqdn(address_xml: str, expected: str) -> None:
    response = ET.fromstring(
        f"""
        <response><result><global-protect-portal><entry name="LSVPN-Portal">
          <satellite-config><configs><entry name="branches">
            <gateways><entry name="Primary-Hub">{address_xml}</entry></gateways>
          </entry></configs></satellite-config>
        </entry></global-protect-portal></result></response>
        """
    )

    result = lsvpn._parse_portal_gateways(response)

    assert len(result) == 1
    assert result[0].address == expected


def test_endpoint_matching_normalizes_fqdn_case_and_trailing_dot() -> None:
    assert lsvpn.endpoints_match("VPN.Example.Test.", "vpn.example.test")


def test_endpoint_matching_resolves_fqdn_to_configured_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_getaddrinfo(
        host: str,
        port: object,
        *,
        type: int,
    ) -> list[tuple[object, object, object, str, tuple[str, int]]]:
        assert host == "vpn.example.test"
        return [(object(), object(), object(), "", ("198.51.100.20", 0))]

    lsvpn._resolved_endpoint_addresses.cache_clear()
    monkeypatch.setattr(lsvpn.socket, "getaddrinfo", fake_getaddrinfo)

    assert lsvpn.endpoints_match("vpn.example.test", "198.51.100.20/24")


def test_matches_fqdn_portal_gateway_to_site_to_site_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = ET.fromstring(
        """
        <global-protect-site-to-site><entry name="LSVPN_GW-S">
          <local-address><ip><ipv4>198.51.100.20/24</ipv4></ip></local-address>
        </entry></global-protect-site-to-site>
        """
    )

    def fake_getaddrinfo(
        host: str,
        port: object,
        *,
        type: int,
    ) -> list[tuple[object, object, object, str, tuple[str, int]]]:
        return [(object(), object(), object(), "", ("198.51.100.20", 0))]

    lsvpn._resolved_endpoint_addresses.cache_clear()
    monkeypatch.setattr(lsvpn.socket, "getaddrinfo", fake_getaddrinfo)

    result = lsvpn._address_entry(
        tuple(root.findall("./entry")),
        "vpn.example.test",
    )

    assert result is not None
    assert result.get("name") == "LSVPN_GW-S"


def test_effective_portal_parser_stays_within_requested_vsys() -> None:
    response = ET.fromstring(
        """
        <response><result><config><devices><entry><vsys>
          <entry name="vsys1"><global-protect><global-protect-portal>
            <entry name="Portal-One"><satellite-config><configs>
              <entry name="one"><gateways><entry name="Gateway-One">
                <ip><ipv4>198.51.100.1</ipv4></ip>
              </entry></gateways></entry>
            </configs></satellite-config></entry>
          </global-protect-portal></global-protect></entry>
          <entry name="vsys2"><global-protect><global-protect-portal>
            <entry name="Portal-Two"><satellite-config><configs>
              <entry name="two"><gateways><entry name="Gateway-Two">
                <ip><ipv4>198.51.100.2</ipv4></ip>
              </entry></gateways></entry>
            </configs></satellite-config></entry>
          </global-protect-portal></global-protect></entry>
        </vsys></entry></devices></config></result></response>
        """
    )

    result = lsvpn._parse_portal_gateways(response, "vsys2")

    assert [(gateway.name, gateway.address) for gateway in result] == [
        ("Gateway-Two", "198.51.100.2")
    ]


def test_discovers_template_inherited_portal_from_effective_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    panorama.xapi.show.side_effect = lsvpn.PanNoSuchNode("No such node")
    response = ET.fromstring(
        """
        <response><result><config><devices><entry><vsys><entry name="vsys1">
          <global-protect><global-protect-portal>
            <entry name="LSVPN_Portal" ptpl="hub-template">
              <satellite-config><configs><entry name="lab_sats">
                <source-user><member>satellite-admin</member></source-user>
                <gateways><entry name="primary_gw">
                  <ip><ipv4>198.51.100.20</ipv4></ip>
                  <priority>1</priority>
                </entry></gateways>
              </entry></configs></satellite-config>
            </entry>
          </global-protect-portal></global-protect>
        </entry></vsys></entry></devices></config></result></response>
        """
    )
    captured_firewalls: list[Firewall] = []
    captured_kwargs: dict[str, object] = {}

    def fake_op(self: Firewall, **kwargs: object) -> ET.Element:
        captured_firewalls.append(self)
        captured_kwargs.update(kwargs)
        return response

    monkeypatch.setattr(lsvpn.Firewall, "op", fake_op)

    result = lsvpn.discover_portal_gateways(panorama, "998877")

    assert len(result) == 1
    assert result[0].portal_name == "LSVPN_Portal"
    assert result[0].satellite_config_name == "lab_sats"
    assert result[0].name == "primary_gw"
    assert result[0].address == "198.51.100.20"
    assert result[0].satellite_serials == ()
    firewall = captured_firewalls[0]
    assert firewall.serial == "998877"
    assert firewall.vsys == "vsys1"
    assert firewall.parent is panorama
    assert captured_kwargs == {
        "cmd": (
            b"<show><config><effective-running></effective-running></config></show>"
        ),
        "cmd_xml": False,
    }


def test_rejects_more_than_one_gateway_for_a_portal() -> None:
    gateways = (
        lsvpn.PortalGateway(
            "LSVPN-Portal", "branches", "Hub-A", "198.51.100.20", 1, ()
        ),
        lsvpn.PortalGateway(
            "LSVPN-Portal", "branches", "Hub-B", "198.51.100.21", 2, ()
        ),
    )

    with pytest.raises(lsvpn.LsvpnConfigurationError, match="more than one"):
        lsvpn.select_single_portal_gateway(gateways)


def test_same_gateway_address_with_different_labels_is_not_ambiguous() -> None:
    gateways = (
        lsvpn.PortalGateway(
            "LSVPN-Portal", "serial-config", "Serial-Label", "198.51.100.20", 1, ()
        ),
        lsvpn.PortalGateway(
            "LSVPN-Portal", "user-config", "User-Label", "198.51.100.20", 1, ()
        ),
    )

    result = lsvpn.select_single_portal_gateway(gateways)

    assert result is not None
    assert result.address == "198.51.100.20"


def test_rejects_ambiguous_site_to_site_address_mapping() -> None:
    root = ET.fromstring(
        """
        <global-protect-site-to-site>
          <entry name="Gateway-A">
            <local-address><ip><ipv4>198.51.100.20/24</ipv4></ip></local-address>
          </entry>
          <entry name="Gateway-B">
            <local-address><ip><ipv4>198.51.100.20/32</ipv4></ip></local-address>
          </entry>
        </global-protect-site-to-site>
        """
    )

    with pytest.raises(lsvpn.LsvpnConfigurationError, match="multiple"):
        lsvpn._address_entry(tuple(root.findall("./entry")), "198.51.100.20")


def test_discovers_hub_gateway_clone_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    gateway_config = ET.fromstring(
        """
        <response><result><global-protect-gateway>
          <entry name="Denver-Hub">
            <local-address>
              <interface>ethernet1/3</interface>
              <ip><ipv4>198.51.100.20/24</ipv4></ip>
            </local-address>
            <satellite-tunnel-config>
              <tunnel-interface>tunnel.10</tunnel-interface>
              <access-route><member>10.0.0.0/8</member></access-route>
              <ip-pool><member>10.255.0.0/24</member></ip-pool>
              <dns-server><primary>10.0.0.53</primary></dns-server>
              <dns-suffix>example.test</dns-suffix>
            </satellite-tunnel-config>
          </entry>
        </global-protect-gateway></result></response>
        """
    )
    tunnel_config = ET.fromstring(
        """
        <response><result><global-protect-site-to-site>
          <entry name="Denver-Hub">
            <tunnel-interface>tunnel.10</tunnel-interface>
            <ipsec><ipsec-crypto-profile>lsvpn-ipsec</ipsec-crypto-profile></ipsec>
            <tunnel-monitor>
              <enable>yes</enable>
              <destination-ip>10.255.0.2</destination-ip>
              <tunnel-monitor-profile>fail-over</tunnel-monitor-profile>
              <source-ip>10.255.0.1</source-ip>
            </tunnel-monitor>
          </entry>
        </global-protect-site-to-site></result></response>
        """
    )
    panorama.xapi.show.side_effect = [gateway_config, tunnel_config]
    interface_refresh = Mock(
        return_value=[
            TunnelInterface(
                "tunnel.10",
                ip=["10.255.0.1/24"],
                ipv6_enabled=True,
                management_profile="ping-only",
                mtu=1400,
                netflow_profile="flow-export",
                comment="LSVPN hub",
            )
        ]
    )
    router_refresh = Mock(
        return_value=[VirtualRouter("default", interface=["tunnel.10"])]
    )
    zone_refresh = Mock(
        return_value=[Zone("lsvpn", mode="layer3", interface=["tunnel.10"])]
    )
    monkeypatch.setattr(lsvpn.TunnelInterface, "refreshall", interface_refresh)
    monkeypatch.setattr(lsvpn.VirtualRouter, "refreshall", router_refresh)
    monkeypatch.setattr(lsvpn.Zone, "refreshall", zone_refresh)
    gateway = lsvpn.PortalGateway(
        "LSVPN-Portal",
        "branches",
        "Denver-Hub",
        "198.51.100.20",
        1,
        ("001122",),
    )

    result = lsvpn.discover_hub_gateway_clone_source(panorama, "998877", gateway)

    assert result.external_interface == "ethernet1/3"
    assert result.external_ipv4 == "198.51.100.20/24"
    assert result.ipsec_crypto_profile == "lsvpn-ipsec"
    assert result.tunnel_monitor_enabled is True
    assert result.tunnel_monitor_destination == "10.255.0.2"
    assert result.tunnel_monitor_source == "10.255.0.1"
    assert result.access_routes == ("10.0.0.0/8",)
    assert result.client_ip_pools == ("10.255.0.0/24",)
    assert result.dns_primary == "10.0.0.53"
    assert result.dns_suffix == "example.test"
    assert result.tunnel_interface.name == "tunnel.10"
    assert result.tunnel_interface.ip_addresses == ("10.255.0.1/24",)
    assert result.tunnel_interface.ipv6_enabled is True
    assert result.tunnel_interface.management_profile == "ping-only"
    assert result.tunnel_interface.mtu == 1400
    assert result.tunnel_interface.netflow_profile == "flow-export"
    assert result.tunnel_interface.virtual_routers == ("default",)
    assert result.tunnel_interface.zones == ("lsvpn",)
    assert panorama.xapi.show.call_args_list == [
        ((lsvpn.GATEWAY_XPATH,), {"extra_qs": {"target": "998877"}}),
        ((lsvpn.GATEWAY_TUNNEL_XPATH,), {"extra_qs": {"target": "998877"}}),
    ]
    for refresh in (interface_refresh, router_refresh, zone_refresh):
        firewall = refresh.call_args.args[0]
        assert firewall.serial == "998877"
        assert firewall.parent is panorama
        assert refresh.call_args.kwargs == {"running_config": True, "add": False}


def test_matches_template_gateway_by_address_and_tunnel_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    panorama.xapi.show.side_effect = lsvpn.PanNoSuchNode("No such node")
    effective = ET.fromstring(
        """
        <response><result><config><devices><entry name="localhost.localdomain">
          <network><tunnel><global-protect-site-to-site>
            <entry name="LSVPN_GW-S">
              <client>
                <ip-pool><member>10.205.88.0/24</member></ip-pool>
                <ipsec-crypto-profile>Basics</ipsec-crypto-profile>
              </client>
              <local-address>
                <ip><ipv4>10.1.110.1/24</ipv4></ip>
                <interface>ethernet1/2</interface>
              </local-address>
              <tunnel-interface>tunnel.10</tunnel-interface>
            </entry>
          </global-protect-site-to-site></tunnel>
          <interface><tunnel><units><entry name="tunnel.10">
            <ip><entry name="10.99.1.1/24" /></ip>
            <mtu>1400</mtu>
          </entry></units></tunnel></interface>
          <logical-router><entry name="MainLR"><vrf><entry name="default">
            <interface><member>tunnel.10</member></interface>
          </entry></vrf></entry></logical-router></network>
          <vsys><entry name="vsys1"><global-protect><global-protect-gateway>
            <entry name="LSVPN_GW">
              <satellite-tunnel>tunnel.10</satellite-tunnel>
            </entry>
          </global-protect-gateway></global-protect>
          <zone><entry name="LSVPN"><network><layer3>
            <member>tunnel.10</member>
          </layer3></network></entry></zone></entry>
          <entry name="vsys2"><zone><entry name="WRONG-VSYS">
            <network><layer3><member>tunnel.10</member></layer3></network>
          </entry></zone></entry></vsys>
        </entry></devices></config></result></response>
        """
    )

    def fake_op(self: Firewall, **kwargs: object) -> ET.Element:
        return effective

    monkeypatch.setattr(lsvpn.Firewall, "op", fake_op)
    monkeypatch.setattr(
        lsvpn.TunnelInterface,
        "refreshall",
        Mock(return_value=[]),
    )
    monkeypatch.setattr(lsvpn.VirtualRouter, "refreshall", Mock(return_value=[]))
    monkeypatch.setattr(lsvpn.Zone, "refreshall", Mock(return_value=[]))
    portal_gateway = lsvpn.PortalGateway(
        "LSVPN_Portal",
        "lab_sats",
        "primary_gw",
        "10.1.110.1",
        5,
        (),
    )

    result = lsvpn.discover_hub_gateway_clone_source(
        panorama,
        "998877",
        portal_gateway,
    )

    assert result.name == "LSVPN_GW"
    assert result.external_interface == "ethernet1/2"
    assert result.external_ipv4 == "10.1.110.1/24"
    assert result.tunnel_interface.name == "tunnel.10"
    assert result.tunnel_interface.ip_addresses == ("10.99.1.1/24",)
    assert result.tunnel_interface.mtu == 1400
    assert result.tunnel_interface.virtual_routers == ("MainLR",)
    assert result.tunnel_interface.zones == ("LSVPN",)
    assert result.ipsec_crypto_profile == "Basics"
    assert result.client_ip_pools == ("10.205.88.0/24",)
