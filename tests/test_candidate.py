import xml.etree.ElementTree as ET
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from panos.panorama import Panorama

from panos_tunnel_builder import candidate, lsvpn


def _plan(
    local_address: str = "203.0.113.13/24",
    dynamic: lsvpn.DynamicRoutingCloneSource | None = None,
) -> lsvpn.StandardIpsecClonePlan:
    satellite = lsvpn.SatelliteConfig(
        name="legacy-satellite",
        tunnel_interface="tunnel.2",
        portal_address="198.51.100.20",
        local_interface="ethernet1/1",
        local_ipv4=local_address,
        local_ipv6=None,
        publish_connected_routes=False,
        published_routes=("10.20.0.0/16",),
        local_certificate=None,
        certificate_profile=None,
        anti_replay=True,
        copy_tos=False,
        tunnel_monitor_enabled=False,
        tunnel_monitor_destination=None,
        tunnel_monitor_profile=None,
    )
    spoke_source = lsvpn.HubTunnelInterfaceConfig(
        name="tunnel.2",
        ip_addresses=(),
        ipv6_enabled=False,
        management_profile=None,
        mtu=1400,
        netflow_profile=None,
        comment="LSVPN spoke",
        virtual_routers=("default",),
        zones=("lsvpn",),
        routing_instances=(lsvpn.RoutingInstanceConfig("virtual-router", "default"),),
    )
    hub_interface = lsvpn.HubTunnelInterfaceConfig(
        name="tunnel.10",
        ip_addresses=("10.255.0.1/24",),
        ipv6_enabled=False,
        management_profile=None,
        mtu=1400,
        netflow_profile=None,
        comment="LSVPN hub",
        virtual_routers=("default",),
        zones=("lsvpn",),
        routing_instances=(lsvpn.RoutingInstanceConfig("virtual-router", "default"),),
    )
    hub = lsvpn.HubGatewayCloneSource(
        name="hub-gateway",
        address="198.51.100.20",
        external_interface="ethernet1/3",
        external_ipv4="198.51.100.20/24",
        external_ipv6=None,
        floating_ipv4=None,
        floating_ipv6=None,
        tunnel_interface=hub_interface,
        ipsec_crypto_profile="legacy-profile",
        tunnel_monitor_enabled=False,
        tunnel_monitor_destination=None,
        tunnel_monitor_profile=None,
        tunnel_monitor_source=None,
        access_routes=("10.0.0.0/8",),
        client_ip_pools=("10.255.0.0/24",),
        dns_primary=None,
        dns_secondary=None,
        dns_suffix=None,
    )
    return lsvpn.build_standard_clone_plan(
        satellite,
        portal_gateway=lsvpn.PortalGateway(
            "portal",
            "satellites",
            "hub-gateway",
            "198.51.100.20",
            1,
            (),
        ),
        hub_gateway=hub,
        pre_shared_key="test-generated-psk",
        spoke_tunnel_source=spoke_source,
        replacement_spoke_tunnel_interface="tunnel.3",
        replacement_hub_tunnel_interface="tunnel.11",
        resolved_published_routes=("10.20.0.0/16",),
        tunnel_addresses=lsvpn.TunnelAddressPair(
            "10.254.0.0/30",
            "10.254.0.1/30",
            "10.254.0.2/30",
        ),
        spoke_identity="001122",
        spoke_dynamic_routing=dynamic,
        hub_dynamic_routing=dynamic,
    )


def _template_config(
    tunnel: str,
    zone: str,
    satellite: bool = False,
) -> ET.Element:
    satellite_xml = (
        '<tunnel><ipsec><entry name="legacy-satellite">'
        "<global-protect-satellite /></entry></ipsec></tunnel>"
        if satellite
        else ""
    )
    return ET.fromstring(
        f"""
        <response><result><config><devices><entry>
          <network>
            <interface><tunnel><units><entry name="{tunnel}" />
            </units></tunnel></interface>
            <virtual-router><entry name="default"><interface>
              <member>{tunnel}</member>
            </interface></entry></virtual-router>
            {satellite_xml}
          </network>
          <vsys><entry name="vsys1"><import><network><interface>
            <member>{tunnel}</member>
          </interface></network></import><zone><entry name="{zone}">
            <network><layer3><member>{tunnel}</member></layer3></network>
          </entry></zone></entry></vsys>
        </entry></devices></config></result></response>
        """
    )


def _placement() -> candidate.ReplacementTemplatePlacement:
    return candidate.ReplacementTemplatePlacement(
        spoke=candidate.EndpointTemplatePlacement(
            "spoke-template",
            "spoke-template",
            "spoke-template",
            "spoke-template",
            "spoke-template",
        ),
        hub=candidate.EndpointTemplatePlacement(
            "hub-template",
            "hub-template",
            "hub-template",
            "hub-template",
            "hub-template",
        ),
        satellite_template="spoke-template",
        spoke_stack_templates=("spoke-base", "spoke-template"),
        hub_stack_templates=("hub-base", "hub-template"),
    )


def _panorama() -> tuple[Panorama, Mock]:
    panorama = Panorama("panorama.example.test", api_key="api-key")
    panorama._version_info = (11, 1, 0)
    xapi = Mock()
    panorama._xapi_private = xapi
    return panorama, xapi


def test_discovers_exact_source_template_placement() -> None:
    panorama, xapi = _panorama()
    configs = {
        "spoke-template": _template_config("tunnel.2", "lsvpn", True),
        "spoke-base": ET.fromstring("<response><result /></response>"),
        "hub-template": _template_config("tunnel.10", "lsvpn"),
        "hub-base": ET.fromstring("<response><result /></response>"),
    }

    def show(xpath: str) -> ET.Element:
        return next(root for name, root in configs.items() if name in xpath)

    xapi.get.side_effect = show

    result = candidate.discover_replacement_template_placements(
        panorama,
        ("spoke-base", "spoke-template"),
        ("hub-base", "hub-template"),
        (_plan(),),
    )

    assert result == (_placement(),)


def test_discovers_satellite_owner_independently_of_interface_template() -> None:
    panorama, xapi = _panorama()
    configs = {
        "spoke-network": _template_config("tunnel.2", "lsvpn"),
        "shared-lsvpn": _template_config("tunnel.99", "unused", True),
    }
    xapi.get.side_effect = lambda xpath: next(
        root for name, root in configs.items() if name in xpath
    )

    owner = candidate.discover_lsvpn_satellite_template_owner(
        panorama,
        ("spoke-network", "shared-lsvpn"),
        ("legacy-satellite",),
    )

    assert owner == "shared-lsvpn"


def test_rejects_satellites_owned_by_multiple_templates() -> None:
    panorama, xapi = _panorama()
    first = _template_config("tunnel.2", "lsvpn", True)
    second = ET.fromstring(
        "<response><result><config><devices><entry><network><tunnel><ipsec>"
        '<entry name="second"><global-protect-satellite /></entry>'
        "</ipsec></tunnel></network></entry></devices></config></result></response>"
    )
    configs = {"first": first, "second": second}
    xapi.get.side_effect = lambda xpath: next(
        root for name, root in configs.items() if name in xpath
    )

    with pytest.raises(lsvpn.LsvpnConfigurationError, match="multiple templates"):
        candidate.discover_lsvpn_satellite_template_owner(
            panorama,
            ("first", "second"),
            ("legacy-satellite", "second"),
        )


def test_resolves_effective_ike_address_to_template_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = _panorama()
    template = ET.fromstring(
        """
        <response><result><config><devices><entry><network><interface>
          <ethernet><entry name="ethernet1/2"><layer3><ip>
            <entry name="$eth2-IP" />
          </ip></layer3></entry></ethernet>
        </interface></network></entry></devices></config></result></response>
        """
    )
    monkeypatch.setattr(
        candidate,
        "_read_active_template_config",
        Mock(return_value=template),
    )

    result = candidate.resolve_template_interface_address_reference(
        panorama,
        ("labBasicNetworkConfig",),
        "ethernet1/2",
        "10.1.20.1/24",
    )

    assert result == "$eth2-IP"


def test_saves_named_panorama_pre_migration_snapshot() -> None:
    panorama, xapi = _panorama()

    name = candidate.save_pre_migration_snapshot(
        panorama,
        "branch denver/01",
        datetime(2026, 8, 19, 12, 34, 56, tzinfo=UTC),
    )

    assert name.startswith("LSVPN_PRE_")
    assert name.endswith("_260819123456.xml")
    assert len(name) == 32
    command = xapi.op.call_args.args[0]
    assert b"<save><config><to>" in command
    assert name.encode() in command


def test_dirty_candidate_snapshot_is_labeled_as_checkpoint() -> None:
    panorama, _ = _panorama()

    name = candidate.save_pre_migration_snapshot(
        panorama,
        "branch-01",
        datetime(2026, 8, 19, 12, 34, 56, tzinfo=UTC),
        checkpoint=True,
    )

    assert name.startswith("LSVPN_CHK_")
    assert len(name) == 32


def test_loads_saved_snapshot_without_commit() -> None:
    panorama, xapi = _panorama()
    name = "LSVPN_PRE_a1b2c_260819123456.xml"

    candidate.load_panorama_snapshot(panorama, name)

    command = xapi.op.call_args.args[0]
    assert b"<load><config><from>" in command
    assert name.encode() in command
    assert not xapi.commit.called


def test_clean_candidate_guard_accepts_matching_configuration() -> None:
    panorama, xapi = _panorama()
    candidate_xml = ET.fromstring(
        "<response><result><config dirtyId='9'><shared><entry name='x' />"
        "</shared></config></result></response>"
    )
    running_xml = ET.fromstring(
        "<response><result><config><shared><entry name='x' />"
        "</shared></config></result></response>"
    )
    xapi.get.return_value = candidate_xml
    xapi.show.return_value = running_xml

    candidate.assert_clean_candidate_configuration(panorama)


def test_clean_candidate_guard_rejects_pending_changes() -> None:
    panorama, xapi = _panorama()
    xapi.get.return_value = ET.fromstring(
        "<response><result><config><shared><entry name='pending' />"
        "</shared></config></result></response>"
    )
    xapi.show.return_value = ET.fromstring(
        "<response><result><config><shared /></config></result></response>"
    )

    with pytest.raises(lsvpn.LsvpnConfigurationError, match="pending candidate"):
        candidate.assert_clean_candidate_configuration(panorama)


def test_candidate_element_unwraps_nested_panorama_result() -> None:
    panorama, xapi = _panorama()
    xapi.get.return_value = ET.fromstring(
        """
        <response><result><config><devices><entry name="localhost.localdomain">
          <network><ike><gateway><entry name="wanted">
            <protocol><version>ikev2</version></protocol>
          </entry></gateway></ike></network>
        </entry></devices></config></result></response>
        """
    )

    result = candidate._candidate_element(
        panorama,
        "/config/devices/entry[@name='localhost.localdomain']/network/ike/"
        "gateway/entry[@name='wanted']",
    )

    assert result is not None
    assert result.get("name") == "wanted"
    assert result.findtext("./protocol/version") == "ikev2"


def test_leaf_signatures_ignore_panorama_candidate_audit_metadata() -> None:
    expected = ET.fromstring(
        '<entry name="profile"><dh-group><member>group14</member></dh-group></entry>'
    )
    actual = ET.fromstring(
        """
        <entry name="profile" admin="admin" dirtyId="45" time="2026/08/19">
          <dh-group admin="admin" dirtyId="45" time="2026/08/19">
            <member admin="admin" dirtyId="45" time="2026/08/19">group14</member>
          </dh-group>
        </entry>
        """
    )

    assert candidate._leaf_signatures(actual) == candidate._leaf_signatures(expected)
    assert candidate._canonical_xml(actual) == candidate._canonical_xml(expected)


def test_rejects_unsafe_snapshot_name() -> None:
    panorama, _ = _panorama()

    with pytest.raises(lsvpn.LsvpnConfigurationError, match="must end in .xml"):
        candidate.load_panorama_snapshot(panorama, "../../running-config.xml")


def test_rolls_back_candidate_without_loading_snapshot_or_committing() -> None:
    panorama, xapi = _panorama()

    candidate.rollback_candidate_configuration(panorama)

    command = xapi.op.call_args.args[0]
    assert command == b"<revert><config /></revert>"
    assert not xapi.commit.called


def test_private_spoke_uses_dynamic_hub_peer_and_unique_ike_id() -> None:
    plan = _plan("10.20.30.40/24")

    replacement = lsvpn.build_standard_ipsec_objects(plan)

    assert replacement.hub.ike_gateway.peer_ip_type == "dynamic"
    assert replacement.hub.ike_gateway.peer_ip_value is None
    assert replacement.hub.ike_gateway.peer_id_type == "keyid"
    assert replacement.hub.ike_gateway.peer_id_value == (
        "05642199f924f3f8e4401e2b746255ce09e4c26b0d345c2ff9872fc92bb21396"
    )
    assert replacement.hub.ike_gateway.peer_id_check == "exact"
    assert replacement.spoke.ike_gateway.local_id_type == "keyid"
    assert replacement.spoke.ike_gateway.local_id_value == (
        "05642199f924f3f8e4401e2b746255ce09e4c26b0d345c2ff9872fc92bb21396"
    )


def test_loopback_bgp_without_ospf_uses_static_peer_routes() -> None:
    peer = lsvpn.BgpPeerCloneSource(
        peer_group_name="overlay",
        peer_group_type="ibgp",
        peer_name="remote-loopback",
        peer_as="65000",
        peer_address="169.254.65.2",
        local_interface="loopback.65",
        local_address="169.254.65.1/32",
        enabled=True,
        authentication=None,
        bfd_profile=None,
        keep_alive_interval=None,
        min_route_adv_interval=None,
        multihop=2,
        open_delay_time=None,
        hold_time=None,
        idle_hold_time=None,
    )
    dynamic = lsvpn.DynamicRoutingCloneSource(transit_bgp=(peer,))

    plan = _plan(dynamic=dynamic)

    assert plan.required_inputs == ()
    assert plan.spoke_static_routes == ("169.254.65.2/32",)
    assert plan.hub_static_routes == ("169.254.65.2/32",)
    assert any("static host routes" in warning for warning in plan.warnings)
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    spoke_router = replacement.spoke.routing_object
    route = spoke_router.findall(lsvpn.StaticRoute)[0]
    assert route.interface == "tunnel.3"


def test_loads_candidate_without_commit_and_removes_only_spoke_lsvpn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, xapi = _panorama()
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)

    def get(xpath: str) -> ET.Element:
        old = any(
            value in xpath
            for value in (
                "[@name='tunnel.2']",
                "[text()='tunnel.2']",
                "[@name='legacy-satellite']",
            )
        )
        return ET.fromstring(
            "<response><result><entry /></result></response>"
            if old
            else "<response><result /></response>"
        )

    xapi.get.side_effect = get
    verify = Mock()
    monkeypatch.setattr(candidate, "verify_candidate_configuration", verify)

    result = candidate.load_candidate_configuration(
        panorama,
        "branch-01",
        (plan,),
        (replacement,),
        (_placement(),),
        allow_dirty_candidate=True,
    )

    assert result.created_or_updated_objects == 14
    assert result.removed_satellite_objects == 5
    assert xapi.op.call_count == 3
    mutation_order = [
        call[0] for call in xapi.method_calls if call[0] in {"delete", "set", "edit"}
    ]
    assert mutation_order[0] == "delete"
    assert xapi.set.call_count > 0
    assert xapi.edit.call_count == 0
    import_sets = [
        call
        for call in xapi.set.call_args_list
        if "/import/network/interface" in str(call.args[0])
    ]
    assert any("tunnel.3" in str(call.args[1]) for call in import_sets)
    assert any("tunnel.11" in str(call.args[1]) for call in import_sets)
    deleted_paths = [call.args[0] for call in xapi.delete.call_args_list]
    assert any("legacy-satellite" in xpath for xpath in deleted_paths)
    assert any("tunnel.2" in xpath for xpath in deleted_paths)
    assert any(
        "/import/network/interface/member" in xpath and "tunnel.2" in xpath
        for xpath in deleted_paths
    )
    satellite_delete = next(
        index
        for index, xpath in enumerate(deleted_paths)
        if "legacy-satellite" in xpath
    )
    interface_delete = next(
        index
        for index, xpath in enumerate(deleted_paths)
        if "[@name='tunnel.2']" in xpath
    )
    assert satellite_delete < interface_delete
    assert not any("tunnel.10" in xpath for xpath in deleted_paths)
    assert not any("global-protect-gateway" in xpath for xpath in deleted_paths)
    assert not xapi.commit.called
    verify.assert_called_once()


def test_candidate_collision_fails_before_snapshot_or_write() -> None:
    panorama, xapi = _panorama()
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)

    def get(xpath: str) -> ET.Element:
        if "tunnel.3" in xpath:
            return ET.fromstring(
                "<response><result><entry name='tunnel.3'>"
                "<comment>owned by someone else</comment>"
                "</entry></result></response>"
            )
        return ET.fromstring("<response><result /></response>")

    xapi.get.side_effect = get

    with pytest.raises(lsvpn.LsvpnConfigurationError, match="not owned"):
        candidate.load_candidate_configuration(
            panorama,
            "branch-01",
            (plan,),
            (replacement,),
            (_placement(),),
            allow_dirty_candidate=True,
        )

    assert xapi.op.call_count == 2
    assert not any(b"<save>" in call.args[0] for call in xapi.op.call_args_list)
    assert not xapi.set.called
    assert not xapi.edit.called
    assert not xapi.delete.called


def test_candidate_reload_updates_owned_objects_with_a_fresh_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, xapi = _panorama()
    original_plan = _plan()
    rerun_plan = replace(original_plan, pre_shared_key="new-run-new-psk")
    replacement = lsvpn.build_standard_ipsec_objects(rerun_plan)
    marker = candidate.TOOL_COMMENT_PREFIX + rerun_plan.source_name

    def get(xpath: str) -> ET.Element:
        if "ike-crypto-profiles" in xpath:
            element = replacement.spoke.ike_crypto_profile.element()
        elif "ipsec-crypto-profiles" in xpath:
            element = replacement.spoke.ipsec_crypto_profile.element()
        elif "tunnel.3" in xpath or "tunnel.11" in xpath:
            element = ET.fromstring(f"<entry><comment>{marker}</comment></entry>")
        elif any(
            name in xpath
            for name in (
                rerun_plan.ike_gateway_name,
                rerun_plan.tunnel_name,
                rerun_plan.spoke_ike_gateway_name,
                rerun_plan.spoke_tunnel_name,
            )
        ):
            element = ET.Element("entry")
        else:
            return ET.fromstring("<response><result /></response>")
        result = ET.Element("result")
        result.append(element)
        response = ET.Element("response")
        response.append(result)
        return response

    xapi.get.side_effect = get
    verify = Mock()
    monkeypatch.setattr(candidate, "verify_candidate_configuration", verify)

    result = candidate.load_candidate_configuration(
        panorama,
        "branch-01",
        (rerun_plan,),
        (replacement,),
        (_placement(),),
        allow_dirty_candidate=True,
    )

    assert result.created_or_updated_objects == 14
    assert xapi.edit.call_count == 8
    assert xapi.op.call_count == 3
    assert not xapi.commit.called
    verify.assert_called_once()


def test_partial_retry_creates_missing_gateway_and_ipsec_tunnel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = _panorama()
    plan = _plan()
    endpoint = lsvpn.build_standard_ipsec_objects(plan).spoke
    candidate._prepare_endpoint_parents(
        panorama,
        endpoint,
        _placement().spoke,
        "vsys1",
    )
    gateway_create = Mock()
    gateway_apply = Mock()
    tunnel_create = Mock()
    tunnel_apply = Mock()
    monkeypatch.setattr(endpoint.ike_gateway, "create", gateway_create)
    monkeypatch.setattr(endpoint.ike_gateway, "apply", gateway_apply)
    monkeypatch.setattr(endpoint.ipsec_tunnel, "create", tunnel_create)
    monkeypatch.setattr(endpoint.ipsec_tunnel, "apply", tunnel_apply)
    monkeypatch.setattr(candidate, "_candidate_element", Mock(return_value=None))

    candidate._write_endpoint(panorama, endpoint, plan.source_name, owned=True)

    gateway_create.assert_called_once_with()
    tunnel_create.assert_called_once_with()
    gateway_apply.assert_not_called()
    tunnel_apply.assert_not_called()


def test_candidate_write_failure_automatically_rolls_back_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = _panorama()
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    snapshot = "LSVPN_PRE_a1b2c_260819120000.xml"
    rollback = Mock()
    monkeypatch.setattr(candidate, "audit_spoke_interface_dependencies", Mock())
    monkeypatch.setattr(candidate, "_preflight_endpoint", Mock(return_value=False))
    monkeypatch.setattr(candidate, "_hub_lsvpn_fingerprint", Mock(return_value=()))
    monkeypatch.setattr(candidate, "_routing_scope_fingerprint", Mock(return_value=()))
    monkeypatch.setattr(
        candidate, "_routing_mutable_route_names", Mock(return_value={})
    )
    monkeypatch.setattr(
        candidate,
        "save_pre_migration_snapshot",
        Mock(return_value=snapshot),
    )
    monkeypatch.setattr(
        candidate,
        "_write_endpoint",
        Mock(side_effect=RuntimeError("simulated candidate write failure")),
    )
    monkeypatch.setattr(candidate, "rollback_candidate_configuration", rollback)

    with pytest.raises(candidate.CandidateLoadError, match="rolled back"):
        candidate._load_candidate_configuration_locked(
            panorama,
            "branch-01",
            (plan,),
            (replacement,),
            (_placement(),),
            allow_dirty_candidate=True,
        )

    rollback.assert_called_once_with(panorama)


def test_candidate_write_reports_automatic_rollback_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = _panorama()
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    monkeypatch.setattr(candidate, "audit_spoke_interface_dependencies", Mock())
    monkeypatch.setattr(candidate, "_preflight_endpoint", Mock(return_value=False))
    monkeypatch.setattr(candidate, "_hub_lsvpn_fingerprint", Mock(return_value=()))
    monkeypatch.setattr(candidate, "_routing_scope_fingerprint", Mock(return_value=()))
    monkeypatch.setattr(
        candidate, "_routing_mutable_route_names", Mock(return_value={})
    )
    monkeypatch.setattr(
        candidate,
        "save_pre_migration_snapshot",
        Mock(return_value="LSVPN_PRE_a1b2c_260819120000.xml"),
    )
    monkeypatch.setattr(
        candidate,
        "_write_endpoint",
        Mock(side_effect=RuntimeError("simulated candidate write failure")),
    )
    monkeypatch.setattr(
        candidate,
        "rollback_candidate_configuration",
        Mock(side_effect=RuntimeError("simulated rollback failure")),
    )

    with pytest.raises(
        candidate.CandidateLoadError,
        match="may contain partial migration changes",
    ):
        candidate._load_candidate_configuration_locked(
            panorama,
            "branch-01",
            (plan,),
            (replacement,),
            (_placement(),),
            allow_dirty_candidate=True,
        )


def test_shared_satellite_writes_each_distinct_network_placement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = _panorama()
    first_plan = _plan()
    second_plan = replace(first_plan, spoke_identity="002")
    first_replacement = lsvpn.build_standard_ipsec_objects(first_plan)
    second_replacement = lsvpn.build_standard_ipsec_objects(second_plan)
    first_placement = _placement()
    second_spoke = replace(
        first_placement.spoke,
        interface_template="regional-network",
        routing_template="regional-network",
        zone_template="regional-network",
        import_template="regional-network",
    )
    second_placement = replace(first_placement, spoke=second_spoke)
    write_endpoint = Mock(return_value=7)
    remove_spoke = Mock(return_value=1)
    monkeypatch.setattr(candidate, "audit_spoke_interface_dependencies", Mock())
    monkeypatch.setattr(candidate, "_preflight_endpoint", Mock(return_value=False))
    monkeypatch.setattr(candidate, "_hub_lsvpn_fingerprint", Mock(return_value=()))
    monkeypatch.setattr(candidate, "_routing_scope_fingerprint", Mock(return_value=()))
    monkeypatch.setattr(
        candidate, "_routing_mutable_route_names", Mock(return_value={})
    )
    monkeypatch.setattr(
        candidate,
        "save_pre_migration_snapshot",
        Mock(return_value="LSVPN_PRE_a1b2c_260819120000.xml"),
    )
    monkeypatch.setattr(candidate, "_write_endpoint", write_endpoint)
    monkeypatch.setattr(candidate, "_remove_spoke_lsvpn", remove_spoke)
    monkeypatch.setattr(
        candidate, "_remove_replaced_hub_static_routes", Mock(return_value=())
    )
    monkeypatch.setattr(candidate, "_ensure_interface_import", Mock())
    monkeypatch.setattr(candidate, "verify_candidate_configuration", Mock())

    candidate._load_candidate_configuration_locked(
        panorama,
        "branch-01",
        (first_plan, second_plan),
        (first_replacement, second_replacement),
        (first_placement, second_placement),
        allow_dirty_candidate=True,
    )

    assert remove_spoke.call_count == 2
    spoke_calls = [
        call
        for call in write_endpoint.call_args_list
        if call.args[1] is first_replacement.spoke
        or call.args[1] is second_replacement.spoke
    ]
    assert len(spoke_calls) == 2


def test_writes_template_variables_and_device_overrides() -> None:
    panorama, xapi = _panorama()
    xapi.get.return_value = ET.fromstring("<response><result /></response>")
    variables = candidate.CandidateVariableSet(
        definitions=(
            candidate.TemplateVariableDefinition(
                "shared", "$ptb-link", "ip-netmask", "10.0.0.2/30"
            ),
            candidate.TemplateVariableDefinition(
                "shared", "$ptb-psk", "pre-shared-key", "secret"
            ),
        ),
        overrides=(
            candidate.DeviceVariableOverride(
                "stack", "001", "$ptb-link", "ip-netmask", "10.0.0.2/30"
            ),
            candidate.DeviceVariableOverride(
                "stack", "001", "$ptb-psk", "pre-shared-key", "secret"
            ),
        ),
    )

    candidate._preflight_variables(panorama, variables)
    assert candidate._write_variables(panorama, variables) == 4

    payloads = [call.args[1] for call in xapi.set.call_args_list]
    assert any("<ip-netmask>10.0.0.2/30</ip-netmask>" in item for item in payloads)
    assert any(
        "<pre-shared-key><key>secret</key></pre-shared-key>" in item
        for item in payloads
    )


def test_successful_rerun_rotates_existing_psk_variables() -> None:
    panorama, xapi = _panorama()
    variables = candidate.CandidateVariableSet(
        definitions=(
            candidate.TemplateVariableDefinition(
                "shared", "$ptb-psk", "pre-shared-key", "new-secret"
            ),
        ),
        overrides=(
            candidate.DeviceVariableOverride(
                "stack", "001", "$ptb-psk", "pre-shared-key", "new-secret"
            ),
        ),
    )
    existing = ET.fromstring(
        '<response><result><entry name="$ptb-psk"><type>'
        "<pre-shared-key>encrypted</pre-shared-key></type></entry></result></response>"
    )
    xapi.get.return_value = existing

    assert candidate._write_variables(panorama, variables) == 2
    payloads = [call.args[1] for call in xapi.set.call_args_list]
    assert all("<key>new-secret</key>" in payload for payload in payloads)


def test_incomplete_existing_psk_set_is_rejected_before_write() -> None:
    panorama, xapi = _panorama()
    variables = candidate.CandidateVariableSet(
        definitions=(
            candidate.TemplateVariableDefinition(
                "shared", "$ptb-psk", "pre-shared-key", "new-secret"
            ),
        ),
        overrides=(
            candidate.DeviceVariableOverride(
                "stack", "001", "$ptb-psk", "pre-shared-key", "new-secret"
            ),
        ),
    )

    def get(xpath: str) -> ET.Element:
        if "/template/" in xpath:
            return ET.fromstring(
                '<response><result><entry name="$ptb-psk"><type>'
                "<pre-shared-key>encrypted</pre-shared-key></type>"
                "</entry></result></response>"
            )
        return ET.fromstring("<response><result /></response>")

    xapi.get.side_effect = get

    with pytest.raises(lsvpn.LsvpnConfigurationError, match="incomplete"):
        candidate._preflight_variables(panorama, variables)


def test_existing_variable_without_tool_ownership_marker_is_rejected() -> None:
    panorama, xapi = _panorama()
    variables = candidate.CandidateVariableSet(
        definitions=(
            candidate.TemplateVariableDefinition(
                "shared", "$ptb-link", "ip-netmask", "10.0.0.2/30"
            ),
        )
    )
    xapi.get.return_value = ET.fromstring(
        '<response><result><entry name="$ptb-link"><type>'
        "<ip-netmask>10.0.0.2/30</ip-netmask></type></entry></result></response>"
    )

    with pytest.raises(lsvpn.LsvpnConfigurationError, match="ownership marker"):
        candidate._preflight_variables(panorama, variables)


def test_variable_verification_detects_wrong_non_secret_value() -> None:
    panorama, xapi = _panorama()
    variables = candidate.CandidateVariableSet(
        definitions=(
            candidate.TemplateVariableDefinition(
                "shared", "$ptb-link", "ip-netmask", "10.0.0.2/30"
            ),
        )
    )
    xapi.get.return_value = ET.fromstring(
        '<response><result><entry name="$ptb-link"><type>'
        "<ip-netmask>10.0.0.6/30</ip-netmask></type></entry></result></response>"
    )

    assert candidate._verify_variables(panorama, variables) == [
        'template variable "$ptb-link" has wrong value'
    ]


def test_existing_psks_and_stale_fingerprints_are_rotated_together() -> None:
    panorama, xapi = _panorama()
    owner = candidate.TemplateVariableDefinition(
        "shared",
        "$owner",
        "fqdn",
        "panos-tunnel-builder.test.ptb.invalid",
    )
    variables = candidate.CandidateVariableSet(
        definitions=(
            owner,
            candidate.TemplateVariableDefinition(
                "shared", "$spoke-psk", "pre-shared-key", "new"
            ),
            candidate.TemplateVariableDefinition(
                "hub", "$hub-psk", "pre-shared-key", "new"
            ),
            candidate.TemplateVariableDefinition(
                "hub", "$hub-fp", "fqdn", "planned.psk.ptb.invalid"
            ),
            candidate.TemplateVariableDefinition(
                "shared", "$spoke-fp", "fqdn", "planned.psk.ptb.invalid"
            ),
        ),
        overrides=(
            candidate.DeviceVariableOverride(
                "stack", "001", "$spoke-psk", "pre-shared-key", "new"
            ),
            candidate.DeviceVariableOverride(
                "stack", "001", "$spoke-fp", "fqdn", "planned.psk.ptb.invalid"
            ),
        ),
        psk_fingerprint_pairs=(
            candidate.PskFingerprintPair("stack", "001", "$spoke-fp", "hub", "$hub-fp"),
        ),
        ownership_markers=(owner,),
    )

    def get(xpath: str) -> ET.Element:
        if "psk']" in xpath:
            body = "<pre-shared-key>encrypted</pre-shared-key>"
        elif "spoke-fp" in xpath:
            body = "<fqdn>one.psk.ptb.invalid</fqdn>"
        elif "hub-fp" in xpath:
            body = "<fqdn>two.psk.ptb.invalid</fqdn>"
        elif "$owner" in xpath:
            body = "<fqdn>panos-tunnel-builder.test.ptb.invalid</fqdn>"
        else:
            return ET.fromstring("<response><result /></response>")
        return ET.fromstring(
            f"<response><result><entry><type>{body}</type></entry></result></response>"
        )

    xapi.get.side_effect = get

    candidate._preflight_variables(panorama, variables)
    assert candidate._write_variables(panorama, variables) == 7
    payloads = [call.args[1] for call in xapi.set.call_args_list]
    assert sum("<key>new</key>" in payload for payload in payloads) == 3
    assert sum("planned.psk.ptb.invalid" in payload for payload in payloads) == 3


def test_dependency_audit_allows_handled_lsvpn_references() -> None:
    panorama, xapi = _panorama()
    configs = {
        "spoke-base": ET.fromstring("<response><result /></response>"),
        "spoke-template": _template_config("tunnel.2", "lsvpn", True),
    }
    xapi.get.side_effect = lambda xpath: next(
        root for name, root in configs.items() if name in xpath
    )

    candidate.audit_spoke_interface_dependencies(
        panorama,
        _plan(),
        _placement(),
    )


def test_dependency_audit_replaces_matching_loopback_bgp_static_route() -> None:
    panorama, xapi = _panorama()
    peer = lsvpn.BgpPeerCloneSource(
        peer_group_name="overlay",
        peer_group_type="ebgp",
        peer_name="hub",
        peer_as="65001",
        peer_address="169.254.1.1",
        local_interface="loopback.100",
        local_address="169.254.101.1/32",
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
    plan = _plan(dynamic=lsvpn.DynamicRoutingCloneSource(transit_bgp=(peer,)))
    assert plan.spoke_tunnel_source is not None
    logical_source = replace(
        plan.spoke_tunnel_source,
        virtual_routers=("MainLR",),
        routing_instances=(
            lsvpn.RoutingInstanceConfig("logical-router", "MainLR", "default"),
        ),
    )
    plan = replace(plan, spoke_tunnel_source=logical_source)
    config = ET.fromstring(
        """
        <response><result><config><devices><entry><network>
          <logical-router><entry name="MainLR"><vrf><entry name="default">
            <interface><member>tunnel.2</member></interface>
            <routing-table><ip><static-route><entry name="Lab1LB">
              <destination>169.254.1.1/32</destination>
              <nexthop><ip-address>10.99.1.1</ip-address></nexthop>
              <interface>tunnel.2</interface><metric>10</metric>
            </entry></static-route></ip></routing-table>
          </entry></vrf></entry></logical-router>
        </network></entry></devices></config></result></response>
        """
    )
    xapi.get.side_effect = lambda xpath: (
        config
        if "spoke-template" in xpath
        else ET.fromstring("<response><result /></response>")
    )

    candidate.audit_spoke_interface_dependencies(panorama, plan, _placement())
    paths = candidate._spoke_cleanup_paths(
        panorama,
        plan,
        _placement(),
        "vsys1",
    )

    assert any("Lab1LB" in path and "static-route" in path for path in paths)


def test_replaces_only_matching_per_spoke_hub_static_route() -> None:
    panorama, xapi = _panorama()
    plan = _plan()
    plan = replace(plan, hub_static_routes=("10.20.0.0/16",))
    config = ET.fromstring(
        """
        <response><result><config><devices><entry><network>
          <virtual-router><entry name="default"><routing-table><ip><static-route>
            <entry name="matched"><destination>10.20.0.0/16</destination>
              <interface>tunnel.10</interface></entry>
            <entry name="unrelated"><destination>10.30.0.0/16</destination>
              <interface>tunnel.10</interface></entry>
          </static-route></ip></routing-table></entry></virtual-router>
        </network></entry></devices></config></result></response>
        """
    )
    xapi.get.return_value = config

    paths = candidate._hub_replaced_static_route_paths(
        panorama,
        plan,
        _placement(),
    )

    assert len(paths) == 1
    assert "matched" in paths[0]
    assert "unrelated" not in paths[0]


def test_dependency_audit_blocks_unknown_old_interface_reference() -> None:
    panorama, xapi = _panorama()
    config = ET.fromstring(
        """
        <response><result><config><devices><entry><network>
          <virtual-router><entry name="default"><routing-table><ip>
            <static-route><entry name="unexpected">
              <destination>192.0.2.0/24</destination>
              <interface>tunnel.2</interface>
            </entry></static-route>
          </ip></routing-table></entry></virtual-router>
        </network></entry></devices></config></result></response>
        """
    )
    xapi.get.side_effect = lambda xpath: (
        config
        if "spoke-template" in xpath
        else ET.fromstring("<response><result /></response>")
    )

    with pytest.raises(
        lsvpn.LsvpnConfigurationError,
        match="unsupported candidate configuration references",
    ) as exc_info:
        candidate.audit_spoke_interface_dependencies(
            panorama,
            _plan(),
            _placement(),
        )

    assert "static-route" in str(exc_info.value)
    assert "spoke-template" in str(exc_info.value)


def test_post_write_verification_accepts_complete_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = _panorama()
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    placement = _placement()
    candidate._prepare_endpoint_parents(
        panorama, replacement.spoke, placement.spoke, "vsys1"
    )
    candidate._prepare_endpoint_parents(
        panorama, replacement.hub, placement.hub, "vsys1"
    )
    expected: dict[str, ET.Element] = {}
    for endpoint in (replacement.spoke, replacement.hub):
        objects = (
            endpoint.ike_crypto_profile,
            endpoint.ipsec_crypto_profile,
            endpoint.ike_gateway,
            endpoint.ipsec_tunnel,
            endpoint.tunnel_interface,
            *candidate._object_tree(endpoint.routing_object),
            endpoint.zone,
        )
        expected.update((item.xpath(), item.element()) for item in objects)
        routing_parent = (
            endpoint.routing_object
            if isinstance(endpoint.routing_object, lsvpn.VirtualRouter)
            else endpoint.routing_object.findall(lsvpn.Vrf)[0]
        )
        for interface_name in routing_parent.interface or []:
            expected[
                f"{routing_parent.xpath()}/interface/member[text()='{interface_name}']"
            ] = ET.Element("member")
    for endpoint, endpoint_placement in (
        (replacement.spoke, placement.spoke),
        (replacement.hub, placement.hub),
    ):
        expected[
            candidate._interface_import_xpath(
                endpoint_placement.import_template or "",
                "vsys1",
                str(endpoint.tunnel_interface.name),
            )
        ] = ET.Element("member")
    monkeypatch.setattr(
        candidate,
        "_candidate_element",
        lambda _panorama, xpath: expected.get(xpath),
    )
    monkeypatch.setattr(candidate, "_spoke_cleanup_paths", Mock(return_value=("/old",)))
    fingerprint = (("hub-template", ("global-protect",)),)
    monkeypatch.setattr(
        candidate,
        "_hub_lsvpn_fingerprint",
        Mock(return_value=fingerprint),
    )

    candidate.verify_candidate_configuration(
        panorama,
        (plan,),
        (replacement,),
        (placement,),
        fingerprint,
    )


def test_logical_router_write_does_not_serialize_protocol_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, xapi = _panorama()
    template = lsvpn.Template("routing-template")
    panorama.add(template)
    router = lsvpn.LogicalRouter("MainLR")
    template.add(router)
    vrf = lsvpn.Vrf("default", interface=["tunnel.1"])
    router.add(vrf)
    monkeypatch.setattr(candidate, "_candidate_element", Mock(return_value=None))

    candidate._write_routing_additions(panorama, router)

    assert xapi.set.call_count == 1
    payload = str(xapi.set.call_args.args[1])
    assert "tunnel.1" in payload
    assert "<bgp>" not in payload
    assert "<ospf>" not in payload


def test_routing_scope_normalization_allows_only_tunnel_related_changes() -> None:
    before = ET.fromstring(
        """
        <response><result><config><devices><entry><network><logical-router>
          <entry name="MainLR"><vrf><entry name="default">
            <interface><member>ethernet1/1</member><member>tunnel.20</member></interface>
            <bgp><enable>yes</enable><peer-group><entry name="peers"><peer>
              <entry name="old"><local-address><interface>tunnel.20</interface>
              </local-address></entry>
            </peer></entry></peer-group></bgp>
            <ospf><enable>yes</enable><area><entry name="0.0.0.0"><interface>
              <entry name="tunnel.20"><enable>yes</enable></entry>
            </interface></entry></area></ospf>
          </entry></vrf></entry>
        </logical-router></network></entry></devices></config></result></response>
        """
    )
    after = ET.fromstring(
        """
        <response><result><config><devices><entry><network><logical-router>
          <entry name="MainLR"><vrf><entry name="default">
            <interface><member>ethernet1/1</member><member>tunnel.1</member></interface>
            <routing-table><ip><static-route><entry name="replacement">
              <destination>10.0.0.0/8</destination><interface>tunnel.1</interface>
            </entry></static-route></ip></routing-table>
            <bgp><enable>yes</enable><peer-group><entry name="peers"><peer>
              <entry name="new"><local-address><interface>tunnel.1</interface>
              </local-address></entry>
            </peer></entry></peer-group></bgp>
            <ospf><enable>yes</enable><area><entry name="0.0.0.0"><interface>
              <entry name="tunnel.1"><enable>yes</enable></entry>
            </interface></entry></area></ospf>
          </entry></vrf></entry>
        </logical-router></network></entry></devices></config></result></response>
        """
    )
    mutable = frozenset({"tunnel.20", "tunnel.1"})

    assert candidate._canonical_xml(
        candidate._normalized_routing_scope(before, mutable)
    ) == candidate._canonical_xml(candidate._normalized_routing_scope(after, mutable))


def test_routing_scope_normalization_detects_global_protocol_change() -> None:
    before = ET.fromstring(
        "<config><network><virtual-router><entry name='default'>"
        "<protocol><bgp><enable>yes</enable></bgp></protocol>"
        "</entry></virtual-router></network></config>"
    )
    after = ET.fromstring(
        "<config><network><virtual-router><entry name='default'>"
        "<protocol><bgp><enable>no</enable></bgp></protocol>"
        "</entry></virtual-router></network></config>"
    )

    assert candidate._canonical_xml(
        candidate._normalized_routing_scope(before, frozenset({"tunnel.1"}))
    ) != candidate._canonical_xml(
        candidate._normalized_routing_scope(after, frozenset({"tunnel.1"}))
    )


def test_post_write_verification_blocks_missing_object_and_hub_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = _panorama()
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    monkeypatch.setattr(candidate, "_candidate_element", Mock(return_value=None))
    monkeypatch.setattr(candidate, "_spoke_cleanup_paths", Mock(return_value=()))
    monkeypatch.setattr(
        candidate,
        "_hub_lsvpn_fingerprint",
        Mock(return_value=(("hub-template", ("changed",)),)),
    )

    with pytest.raises(
        lsvpn.LsvpnConfigurationError,
        match="Candidate post-write verification failed",
    ) as exc_info:
        candidate.verify_candidate_configuration(
            panorama,
            (plan,),
            (replacement,),
            (_placement(),),
            (("hub-template", ("original",)),),
        )

    assert "missing spoke" in str(exc_info.value)
    assert "hub LSVPN" in str(exc_info.value)
