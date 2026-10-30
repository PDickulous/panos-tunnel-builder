import xml.etree.ElementTree as ET
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from panos.panorama import Panorama

from panos_tunnel_builder import candidate, lsvpn, router_rename
from panos_tunnel_builder.inventory import FirewallTemplateInventory, TemplateCandidate


@pytest.fixture(autouse=True)
def verified_source(monkeypatch: pytest.MonkeyPatch) -> None:
    # These transaction tests isolate source validation, exercised separately in
    # test_source_configuration.py with real XML and lock sequencing.
    monkeypatch.setattr(candidate, "assert_source_configuration_unchanged", Mock())


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
    xapi.op.return_value = ET.fromstring(
        '<response status="success"><result /></response>'
    )
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


def test_restore_saves_checkpoint_before_replacing_pending_candidate() -> None:
    panorama, xapi = _panorama()
    target = "saved.xml"
    reported: list[str] = []

    def checkpoint_saved(name: str) -> None:
        assert panorama.config_locked and panorama.commit_locked
        commands = [ET.fromstring(call.args[0]) for call in xapi.op.call_args_list]
        assert [command.tag for command in commands] == [
            "request",
            "request",
            "show",
            "save",
        ]
        assert commands[-1].findtext("config/to") == name
        reported.append(name)

    result = candidate.restore_candidate_configuration(
        panorama,
        target,
        on_checkpoint_saved=checkpoint_saved,
    )

    commands = [ET.fromstring(call.args[0]) for call in xapi.op.call_args_list]
    assert commands[0].find("config-lock/add") is not None
    assert commands[1].find("commit-lock/add") is not None
    assert commands[2].find("jobs/all") is not None
    assert commands[3].findtext("config/to") == result.checkpoint_name
    assert commands[4].findtext("config/from") == target
    assert commands[5].find("config-lock/remove") is not None
    assert commands[6].find("commit-lock/remove") is not None
    assert reported == [result.checkpoint_name]
    assert result.checkpoint_name.startswith("LSVPN_CHK_")
    assert len(result.checkpoint_name) <= 32
    assert result.snapshot_name == target
    assert result.lock_cleanup_error is None
    assert not panorama.config_locked
    assert not xapi.commit.called


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("recovery_failure", [None, RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("unlock_failed", [False, True])
def test_restore_failure_recovers_pending_candidate_before_unlock(
    monkeypatch: pytest.MonkeyPatch,
    failure: type[BaseException],
    recovery_failure: type[BaseException] | None,
    unlock_failed: bool,
) -> None:
    panorama, xapi = _panorama()
    state = {"candidate": "pending work before restore"}
    checkpoint = "LSVPN_CHK_a1b2c_260819123456.xml"
    events = Mock()
    original = failure("restore request failed")
    saved_state = state["candidate"]

    def load_snapshot(_panorama: Panorama, name: str) -> None:
        assert panorama.config_locked and panorama.commit_locked
        events.load(name)
        if name == "saved.xml":
            state["candidate"] = "partially replaced"
            raise original
        assert name == checkpoint
        if recovery_failure:
            raise recovery_failure("checkpoint recovery failed")
        state["candidate"] = saved_state

    monkeypatch.setattr(
        candidate, "save_pre_migration_snapshot", Mock(return_value=checkpoint)
    )
    monkeypatch.setattr(candidate, "load_panorama_snapshot", load_snapshot)
    monkeypatch.setattr(panorama, "remove_config_lock", events.unlock)
    if unlock_failed:
        events.unlock.side_effect = RuntimeError("unlock failed")

    with pytest.raises(candidate.CandidateRestoreError) as raised:
        candidate.restore_candidate_configuration(panorama, "saved.xml")

    assert [call[0] for call in events.mock_calls] == ["load", "load", "unlock"]
    assert checkpoint in str(raised.value)
    assert "restore request failed" in str(raised.value)
    assert raised.value.__cause__ is original
    assert raised.value.interrupted is (
        failure is not RuntimeError or recovery_failure is KeyboardInterrupt
    )
    assert bool(raised.value.lock_cleanup_error) is unlock_failed
    if recovery_failure:
        assert state["candidate"] == "partially replaced"
        assert "may contain partial changes" in str(raised.value)
        assert "checkpoint recovery failed" in str(raised.value)
    else:
        assert state["candidate"] == saved_state
        assert "was reloaded" in str(raised.value)
    assert not any(b"<revert>" in call.args[0] for call in xapi.op.call_args_list)
    assert not xapi.commit.called


@pytest.mark.parametrize("stage", ["lock", "checkpoint", "notification"])
def test_restore_preparation_failure_does_not_replace_candidate(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    panorama, _ = _panorama()
    load = Mock()
    release = Mock()
    notify = Mock()
    save = Mock(return_value="checkpoint.xml")
    monkeypatch.setattr(candidate, "save_pre_migration_snapshot", save)
    monkeypatch.setattr(candidate, "load_panorama_snapshot", load)
    monkeypatch.setattr(panorama, "remove_config_lock", release)
    if stage == "lock":
        monkeypatch.setattr(
            panorama, "add_config_lock", Mock(side_effect=RuntimeError("lock held"))
        )
    elif stage == "checkpoint":
        save.side_effect = RuntimeError("cannot save")
    else:
        notify.side_effect = KeyboardInterrupt()
    with pytest.raises(candidate.CandidateRestoreError, match="not attempted"):
        candidate.restore_candidate_configuration(
            panorama, "saved.xml", on_checkpoint_saved=notify
        )
    load.assert_not_called()
    assert release.call_count == int(stage != "lock")
    if stage == "lock":
        save.assert_not_called()


def test_restore_invalid_name_fails_before_locking() -> None:
    panorama, xapi = _panorama()
    with pytest.raises(lsvpn.LsvpnConfigurationError):
        candidate.restore_candidate_configuration(panorama, "../../config.xml")
    assert not xapi.op.called


def test_restore_requires_successful_lock_acquisition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = _panorama()
    monkeypatch.setattr(panorama, "add_config_lock", Mock(return_value=False))
    save = Mock()
    release = Mock()
    monkeypatch.setattr(candidate, "save_pre_migration_snapshot", save)
    monkeypatch.setattr(panorama, "remove_config_lock", release)
    with pytest.raises(candidate.CandidateRestoreError, match="lock was not acquired"):
        candidate.restore_candidate_configuration(panorama, "saved.xml")
    save.assert_not_called()
    release.assert_not_called()


def test_restore_lock_release_failure_preserves_loaded_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, xapi = _panorama()
    monkeypatch.setattr(
        panorama, "remove_config_lock", Mock(side_effect=RuntimeError("unlock failed"))
    )
    result = candidate.restore_candidate_configuration(panorama, "saved.xml")
    assert result.snapshot_name == "saved.xml"
    assert result.checkpoint_name.startswith("LSVPN_CHK_")
    assert (
        result.lock_cleanup_error == "configuration lock: RuntimeError: unlock failed"
    )
    commands = [ET.fromstring(call.args[0]) for call in xapi.op.call_args_list]
    assert [command.tag for command in commands] == [
        "request",
        "request",
        "show",
        "save",
        "load",
        "request",
    ]


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
        source_configuration=(),
    )

    assert result.created_or_updated_objects == 14
    assert result.removed_satellite_objects == 5
    assert xapi.op.call_count == 6
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
            source_configuration=(),
        )

    assert xapi.op.call_count == 5
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
        source_configuration=(),
    )

    assert result.created_or_updated_objects == 14
    assert xapi.edit.call_count == 8
    assert xapi.op.call_count == 6
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


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "phase", ["_write_variables", "_write_endpoint", "verify_candidate_configuration"]
)
@pytest.mark.parametrize("rollback_failure", [None, RuntimeError, KeyboardInterrupt])
def test_interruption_rolls_back_before_unlocking(
    monkeypatch: pytest.MonkeyPatch,
    interruption: type[BaseException],
    phase: str,
    rollback_failure: type[BaseException] | None,
) -> None:
    panorama, xapi = _panorama()
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    snapshot = "LSVPN_PRE_a1b2c_260819120000.xml"
    events = Mock()
    xapi.get.return_value = ET.fromstring("<response><result /></response>")
    for name, value in (
        ("audit_spoke_interface_dependencies", None),
        ("_preflight_endpoint", False),
        ("_hub_lsvpn_fingerprint", ()),
        ("_routing_scope_fingerprint", ()),
        ("_routing_mutable_route_names", {}),
        ("save_pre_migration_snapshot", snapshot),
    ):
        monkeypatch.setattr(candidate, name, Mock(return_value=value))
    monkeypatch.setattr(candidate, phase, Mock(side_effect=interruption()))
    events.rollback.side_effect = rollback_failure() if rollback_failure else None
    monkeypatch.setattr(candidate, "rollback_candidate_configuration", events.rollback)
    monkeypatch.setattr(panorama, "remove_config_lock", events.unlock)

    with pytest.raises(candidate.CandidateLoadInterrupted) as raised:
        candidate.load_candidate_configuration(
            panorama,
            "branch-01",
            (plan,),
            (replacement,),
            (_placement(),),
            allow_dirty_candidate=True,
            on_snapshot_saved=events.snapshot,
            source_configuration=(),
        )

    assert [call[0] for call in events.mock_calls] == ["snapshot", "rollback", "unlock"]
    events.snapshot.assert_called_once_with(snapshot)
    events.rollback.assert_called_once_with(panorama)
    assert snapshot in str(raised.value)
    assert interruption.__name__ in str(raised.value)
    assert isinstance(raised.value.__cause__, interruption)
    if rollback_failure:
        assert "may contain partial migration changes" in str(raised.value)
        assert rollback_failure.__name__ in str(raised.value)
    else:
        assert "rolled back to running configuration" in str(raised.value)
    assert not xapi.commit.called


def test_interruption_before_snapshot_does_not_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, xapi = _panorama()
    plan = _plan()
    rollback = Mock()
    monkeypatch.setattr(
        candidate, "_preflight_variables", Mock(side_effect=KeyboardInterrupt)
    )
    monkeypatch.setattr(candidate, "rollback_candidate_configuration", rollback)
    with pytest.raises(KeyboardInterrupt):
        candidate.load_candidate_configuration(
            panorama,
            "branch-01",
            (plan,),
            (lsvpn.build_standard_ipsec_objects(plan),),
            (_placement(),),
            allow_dirty_candidate=True,
            source_configuration=(),
        )
    rollback.assert_not_called()
    assert not xapi.set.called
    assert not xapi.delete.called
    assert any(b"<remove" in call.args[0] for call in xapi.op.call_args_list)


@pytest.mark.parametrize("cleanup_failure", [RuntimeError, KeyboardInterrupt])
def test_lock_release_failure_preserves_verified_result(
    monkeypatch: pytest.MonkeyPatch,
    cleanup_failure: type[BaseException],
) -> None:
    panorama, _ = _panorama()
    result = candidate.CandidateLoadResult("LSVPN_PRE_a1b2c_260819120000.xml", 14, 5)
    monkeypatch.setattr(
        candidate, "_load_candidate_configuration_locked", Mock(return_value=result)
    )
    release = Mock(side_effect=cleanup_failure("unlock failed"))
    monkeypatch.setattr(panorama, "remove_config_lock", release)
    rollback = Mock()
    monkeypatch.setattr(candidate, "rollback_candidate_configuration", rollback)

    actual = candidate.load_candidate_configuration(
        panorama,
        "branch",
        (),
        (),
        (),
        source_configuration=(),
    )

    assert actual.panorama_snapshot_name == result.panorama_snapshot_name
    assert actual.created_or_updated_objects == 14
    assert (
        actual.lock_cleanup_error
        == f"configuration lock: {cleanup_failure.__name__}: unlock failed"
    )
    rollback.assert_not_called()
    release.assert_called_once()


@pytest.mark.parametrize("interrupted", [False, True])
def test_lock_release_failure_preserves_transaction_error(
    monkeypatch: pytest.MonkeyPatch,
    interrupted: bool,
) -> None:
    panorama, _ = _panorama()
    error_type = (
        candidate.CandidateLoadInterrupted
        if interrupted
        else candidate.CandidateLoadError
    )
    original = error_type("write failed and rollback failed; saved snapshot retained")
    monkeypatch.setattr(
        candidate, "_load_candidate_configuration_locked", Mock(side_effect=original)
    )
    monkeypatch.setattr(
        panorama, "remove_config_lock", Mock(side_effect=RuntimeError("unlock failed"))
    )

    with pytest.raises(error_type) as raised:
        candidate.load_candidate_configuration(
            panorama,
            "branch",
            (),
            (),
            (),
            source_configuration=(),
        )

    assert raised.value is original
    assert "write failed and rollback failed" in str(raised.value)
    assert (
        raised.value.lock_cleanup_error
        == "configuration lock: RuntimeError: unlock failed"
    )


def test_lock_release_failure_reports_original_preflight_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = _panorama()
    original = ValueError("preflight failed")
    monkeypatch.setattr(
        candidate, "_load_candidate_configuration_locked", Mock(side_effect=original)
    )
    monkeypatch.setattr(
        panorama, "remove_config_lock", Mock(side_effect=RuntimeError("unlock failed"))
    )
    with pytest.raises(
        candidate.CandidateLoadError, match="preflight failed"
    ) as raised:
        candidate.load_candidate_configuration(
            panorama,
            "branch",
            (),
            (),
            (),
            source_configuration=(),
        )
    assert raised.value.__cause__ is original
    assert (
        raised.value.lock_cleanup_error
        == "configuration lock: RuntimeError: unlock failed"
    )


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


def _required(root: ET.Element, xpath: str) -> ET.Element:
    result = root.find(xpath)
    assert result is not None, xpath
    return result


def _rename_inventory() -> FirewallTemplateInventory:
    return FirewallTemplateInventory(
        "branch-01",
        "001122",
        "spoke-stack",
        (
            TemplateCandidate("spoke-base", ()),
            TemplateCandidate("spoke-template", ("tunnel.2",)),
        ),
    )


def _rename_config() -> ET.Element:
    return ET.fromstring("""<config><devices><entry name="localhost.localdomain">
      <template>
        <entry name="spoke-base"><config><devices><entry name="localhost.localdomain">
          <network><virtual-router>
            <entry name="default"><protocol><bgp><enable>yes</enable></bgp>
          </protocol></entry>
            <entry name="other"><routing-table><ip><static-route><entry name="leak">
              <destination>10.0.0.0/8</destination><nexthop>
          <next-vr>default</next-vr></nexthop>
            </entry></static-route></ip></routing-table></entry>
          </virtual-router></network>
        </entry></devices></config></entry>
        <entry name="spoke-template"><config><devices>
          <entry name="localhost.localdomain">
          <network><virtual-router><entry name="default"><interface>
          <member>tunnel.2</member>
          <member>ethernet1/1</member></interface></entry></virtual-router></network>
          <vsys><entry name="vsys1"><import><network><virtual-router>
            <member>default</member><member>other</member>
          </virtual-router></network></import></entry></vsys>
        </entry></devices></config></entry>
        <entry name="hub-template"><config><devices><entry name="localhost.localdomain">
          <network><virtual-router><entry name="default"><interface>
          <member>tunnel.10</member></interface></entry></virtual-router></network>
        </entry></devices></config></entry>
      </template>
      <template-stack>
        <entry name="spoke-stack"><templates><member>spoke-base</member>
          <member>spoke-template</member></templates><devices>
          <entry name="001122"/></devices>
          <config><devices><entry name="localhost.localdomain"><network><virtual-router>
            <entry name="default"><ecmp><enable>yes</enable></ecmp></entry>
          </virtual-router></network></entry></devices></config>
        </entry>
        <entry name="hub-stack"><templates><member>hub-template</member></templates>
          <devices><entry name="998877"/></devices></entry>
      </template-stack>
    </entry></devices></config>""")


def _xml_xapi(root: ET.Element, auto_references: bool = False) -> tuple[Panorama, Mock]:
    panorama, xapi = _panorama()

    def get(path: str, **kwargs: object) -> ET.Element:
        assert path == "/config"
        response = ET.Element("response", status="success")
        if "extra_qs" in kwargs:
            ET.SubElement(response, "result").append(
                ET.fromstring(
                    "<config><devices><entry><network/></entry></devices></config>"
                )
            )
        else:
            ET.SubElement(response, "result").append(deepcopy(root))
        return response

    def rename(path: str, new: str) -> None:
        node = _required(root, "." + path.removeprefix("/config"))
        assert node is not None, path
        old = node.get("name", "")
        node.set("name", new)
        if auto_references:
            template = next(
                entry
                for entry in root.findall(".//template/entry")
                + root.findall(".//template-stack/entry")
                if node in entry.iter()
            )
            router_rename.map_router_references(template, {old: new})

    def edit(path: str, xml: str) -> None:
        node = _required(root, "." + path.removeprefix("/config"))
        assert node is not None, path
        replacement = ET.fromstring(xml)
        node.attrib.clear()
        node.attrib.update(replacement.attrib)
        node.text = replacement.text
        node[:] = list(replacement)

    xapi.get.side_effect = get
    xapi.show.return_value = ET.fromstring(
        '<response status="success"><result><config><devices><entry>'
        "<network/></entry></devices></config></result></response>"
    )
    xapi.rename.side_effect = rename
    xapi.edit.side_effect = edit
    return panorama, xapi


@pytest.mark.parametrize("auto_references", [False, True])
def test_spoke_rename_preserves_full_router_and_repairs_inherited_references(
    auto_references: bool,
) -> None:
    root = _rename_config()
    hub_before = ET.tostring(_required(root, ".//template/entry[@name='hub-template']"))
    panorama, xapi = _xml_xapi(root, auto_references)
    rename = router_rename.prepare_spoke_router_rename(
        panorama, (_rename_inventory(),), (_plan(),), "Branch VR"
    )
    assert rename is not None
    assert rename.mapping("001122") == {"default": "Branch VR"}
    assert rename.mapping("998877") == {}
    router_rename.apply_spoke_router_rename(panorama, rename)
    assert xapi.rename.call_count == 3  # Two templates plus stack override.
    assert (
        _required(
            root,
            ".//template/entry[@name='spoke-base']"
            "//entry[@name='Branch VR']/protocol/bgp/enable",
        ).text
        == "yes"
    )
    assert (
        _required(root, ".//template/entry[@name='spoke-base']//next-vr").text
        == "Branch VR"
    )
    imports = root.findall(
        ".//template/entry[@name='spoke-template']//import/network/virtual-router/member"
    )
    assert [node.text for node in imports] == ["Branch VR", "other"]
    assert (
        ET.tostring(_required(root, ".//template/entry[@name='hub-template']"))
        == hub_before
    )
    assert not xapi.commit.called


def test_spoke_rename_matching_name_is_noop() -> None:
    panorama, xapi = _panorama()
    assert (
        router_rename.prepare_spoke_router_rename(
            panorama, (_rename_inventory(),), (_plan(),), "default"
        )
        is None
    )
    assert not xapi.get.called and not xapi.rename.called


@pytest.mark.parametrize(
    "failure", ["collision", "outsider", "hub-sharing", "missing", "assignment"]
)
def test_spoke_rename_rejects_unsafe_scope_before_writes(failure: str) -> None:
    root = _rename_config()
    if failure == "collision":
        ET.SubElement(
            _required(
                root, ".//template/entry[@name='spoke-base']//network/virtual-router"
            ),
            "entry",
            name="Branch VR",
        )
    elif failure == "outsider":
        ET.SubElement(
            _required(root, ".//template-stack/entry[@name='spoke-stack']/devices"),
            "entry",
            name="003344",
        )
    elif failure == "hub-sharing":
        ET.SubElement(
            _required(root, ".//template-stack/entry[@name='hub-stack']/templates"),
            "member",
        ).text = "spoke-base"
    elif failure == "missing":
        for parent in root.findall(".//network/virtual-router"):
            for node in list(parent):
                if node.get("name") == "default":
                    parent.remove(node)
    else:
        _required(
            root, ".//template-stack/entry[@name='spoke-stack']/templates/member"
        ).text = "different-template"
    panorama, xapi = _xml_xapi(root)
    with pytest.raises(lsvpn.LsvpnConfigurationError):
        router_rename.prepare_spoke_router_rename(
            panorama, (_rename_inventory(),), (_plan(),), "Branch VR"
        )
    assert not xapi.rename.called and not xapi.edit.called


def test_spoke_rename_includes_every_participating_shared_spoke() -> None:
    root = _rename_config()
    inventory = _rename_inventory()
    ET.SubElement(
        _required(root, ".//template-stack/entry[@name='spoke-stack']/devices"),
        "entry",
        name="003344",
    )
    panorama, xapi = _xml_xapi(root)
    rename = router_rename.prepare_spoke_router_rename(
        panorama,
        (inventory, replace(inventory, serial="003344")),
        (_plan(), replace(_plan(), spoke_identity="003344")),
        "Branch VR",
    )
    assert rename is not None
    assert rename.mapping("003344") == {"default": "Branch VR"}
    router_rename.apply_spoke_router_rename(panorama, rename)
    assert xapi.rename.call_count == 3


def test_spoke_rename_detects_unrelated_drift() -> None:
    root = _rename_config()
    panorama, xapi = _xml_xapi(root)
    rename = router_rename.prepare_spoke_router_rename(
        panorama, (_rename_inventory(),), (_plan(),), "Branch VR"
    )
    original_edit = xapi.edit.side_effect

    def edit(path: str, xml: str) -> None:
        original_edit(path, xml)
        _required(root, ".//template/entry[@name='hub-template']").set(
            "unexpected", "change"
        )

    xapi.edit.side_effect = edit
    assert rename is not None
    with pytest.raises(lsvpn.LsvpnConfigurationError, match="verification failed"):
        router_rename.apply_spoke_router_rename(panorama, rename)


@pytest.mark.parametrize(
    "invalid", ["", " ", "trailing ", "a" * 32, "bad/name", "bad'name"]
)
def test_spoke_router_name_validation(invalid: str) -> None:
    with pytest.raises(lsvpn.LsvpnConfigurationError, match="1 to 31"):
        router_rename.validate_router_name(invalid)


@pytest.mark.parametrize("fail", [False, True])
def test_spoke_router_rename_runs_within_migration_rollback_boundary(
    monkeypatch: pytest.MonkeyPatch,
    fail: bool,
) -> None:
    panorama, xapi = _panorama()
    xapi.get.return_value = ET.fromstring("<response><result/></response>")
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    events: list[str] = []

    def snapshot(*args: object, **kwargs: object) -> str:
        events.append("snapshot")
        return "LSVPN_PRE_test.xml"

    monkeypatch.setattr(candidate, "save_pre_migration_snapshot", snapshot)
    monkeypatch.setattr(
        candidate,
        "verify_candidate_configuration",
        lambda *args: events.append("verify"),
    )

    def apply(*args: object) -> int:
        events.append("rename")
        if fail:
            raise lsvpn.LsvpnConfigurationError("rename failed")
        return 3

    monkeypatch.setattr(candidate, "apply_spoke_router_rename", apply)
    rollback = Mock()
    monkeypatch.setattr(candidate, "rollback_candidate_configuration", rollback)
    rename = router_rename.SpokeRouterRename("Branch VR", (("001122", "default"),), ())
    arguments = (panorama, "branch", (plan,), (replacement,), (_placement(),))
    if fail:
        with pytest.raises(candidate.CandidateLoadError, match="rolled back"):
            candidate.load_candidate_configuration(
                *arguments,
                allow_dirty_candidate=True,
                source_configuration=(),
                spoke_router_rename=rename,
            )
        rollback.assert_called_once()
        assert replacement.spoke.routing_object.name == "default"
    else:
        result = candidate.load_candidate_configuration(
            *arguments,
            allow_dirty_candidate=True,
            source_configuration=(),
            spoke_router_rename=rename,
        )
        assert result.created_or_updated_objects == 17
        assert replacement.spoke.routing_object.name == "Branch VR"
        assert replacement.hub.routing_object.name == "default"
        assert not rollback.called
    assert events == ["snapshot", "verify", "rename"]
    assert not xapi.commit.called


@pytest.mark.parametrize("load_candidate", [False, True])
def test_spoke_rename_preview_and_load_use_correct_sdk_names(
    load_candidate: bool,
) -> None:
    from panos_tunnel_builder import cli

    panorama, xapi = _xml_xapi(_rename_config())
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    rename = cli._prepare_spoke_router_option(
        panorama,
        (_rename_inventory(),),
        (plan,),
        (replacement,),
        "Branch VR",
        load_candidate,
    )
    assert rename is not None
    assert replacement.spoke.routing_object.name == (
        "default" if load_candidate else "Branch VR"
    )
    assert replacement.hub.routing_object.name == "default"
    assert plan.spoke_tunnel_source is not None
    assert plan.spoke_tunnel_source.virtual_routers == ("default",)
    assert not xapi.rename.called and not xapi.edit.called


def test_spoke_rename_rejects_logical_router_and_multiple_source_routers() -> None:
    plan = _plan()
    source = plan.spoke_tunnel_source
    assert source is not None
    panorama, xapi = _panorama()
    logical = replace(
        plan,
        spoke_tunnel_source=replace(
            source,
            routing_instances=(
                lsvpn.RoutingInstanceConfig("logical-router", "MainLR", "default"),
            ),
        ),
    )
    with pytest.raises(
        lsvpn.LsvpnConfigurationError, match="legacy virtual routers only"
    ):
        router_rename.prepare_spoke_router_rename(
            panorama, (_rename_inventory(),), (logical,), "Branch VR"
        )
    other = replace(
        plan,
        spoke_tunnel_source=replace(
            source,
            routing_instances=(lsvpn.RoutingInstanceConfig("virtual-router", "other"),),
        ),
    )
    with pytest.raises(lsvpn.LsvpnConfigurationError, match="Cannot merge"):
        router_rename.prepare_spoke_router_rename(
            panorama, (_rename_inventory(),), (plan, other), "Branch VR"
        )
    assert not xapi.get.called


def test_spoke_rename_rejects_local_router_name_collision() -> None:
    panorama, xapi = _xml_xapi(_rename_config())
    xapi.show.return_value = ET.fromstring(
        '<response status="success"><result><config><devices><entry>'
        '<network><virtual-router><entry name="Branch VR"/></virtual-router>'
        "</network></entry></devices></config></result></response>"
    )
    with pytest.raises(
        lsvpn.LsvpnConfigurationError, match="already exists on firewall"
    ):
        router_rename.prepare_spoke_router_rename(
            panorama, (_rename_inventory(),), (_plan(),), "Branch VR"
        )
    assert not xapi.rename.called


@pytest.mark.parametrize("running", [False, True])
@pytest.mark.parametrize("setting", ["definition", "reference"])
def test_spoke_rename_blocks_local_settings_that_would_retain_old_name(
    running: bool,
    setting: str,
) -> None:
    panorama, xapi = _xml_xapi(_rename_config())
    xml = (
        '<network><virtual-router><entry name="default"/></virtual-router></network>'
        if setting == "definition"
        else '<vsys><entry name="vsys1"><import><network><virtual-router>'
        "<member>default</member></virtual-router></network></import></entry></vsys>"
    )
    response = ET.fromstring(
        '<response status="success"><result><config><devices><entry>'
        + xml
        + "</entry></devices></config></result></response>"
    )
    if running:
        xapi.show.return_value = response
    else:
        original_get = xapi.get.side_effect

        def get(path: str, **kwargs: object) -> ET.Element:
            return response if "extra_qs" in kwargs else original_get(path, **kwargs)

        xapi.get.side_effect = get
    with pytest.raises(
        lsvpn.LsvpnConfigurationError, match="local router configuration"
    ):
        router_rename.prepare_spoke_router_rename(
            panorama, (_rename_inventory(),), (_plan(),), "Branch VR"
        )
    assert not xapi.rename.called and not xapi.edit.called


def test_spoke_rename_blocks_duplicate_vsys_import_target() -> None:
    root = _rename_config()
    imports = _required(
        root, ".//template/entry[@name='spoke-template']//import/network/virtual-router"
    )
    ET.SubElement(imports, "member").text = "Branch VR"
    panorama, xapi = _xml_xapi(root)
    with pytest.raises(lsvpn.LsvpnConfigurationError, match="already imported"):
        router_rename.prepare_spoke_router_rename(
            panorama, (_rename_inventory(),), (_plan(),), "Branch VR"
        )
    assert not xapi.rename.called


def test_spoke_rename_name_matching_is_case_sensitive() -> None:
    panorama, xapi = _xml_xapi(_rename_config())
    rename = router_rename.prepare_spoke_router_rename(
        panorama, (_rename_inventory(),), (_plan(),), "Default"
    )
    assert rename is not None
    assert rename.mapping("001122") == {"default": "Default"}
    router_rename.apply_spoke_router_rename(panorama, rename)
    assert xapi.rename.call_count == 3


@pytest.mark.parametrize("failure", [None, "apply", "verify", "interrupt"])
def test_ping_only_profile_updates_share_migration_snapshot_and_rollback(
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
) -> None:
    from panos_tunnel_builder.management_profiles import PingOnlyProfilePlan

    panorama, xapi = _panorama()
    xapi.get.return_value = ET.fromstring("<response><result/></response>")
    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    events: list[str] = []

    def snapshot(*args: object, **kwargs: object) -> str:
        events.append("snapshot")
        return "LSVPN_PRE_profiles.xml"

    def apply(*args: object) -> int:
        events.append("profile")
        if failure == "apply":
            raise lsvpn.LsvpnConfigurationError("profile write failed")
        if failure == "interrupt":
            raise KeyboardInterrupt()
        return 1

    def write(*args: object) -> int:
        events.append("endpoint")
        return 7

    def verify(*args: object) -> None:
        events.append("verify-profile")
        if failure == "verify":
            raise lsvpn.LsvpnConfigurationError("profile verification failed")

    monkeypatch.setattr(candidate, "save_pre_migration_snapshot", snapshot)
    monkeypatch.setattr(candidate, "apply_ping_only_profiles", apply)
    monkeypatch.setattr(candidate, "_write_endpoint", write)
    monkeypatch.setattr(candidate, "verify_candidate_configuration", Mock())
    monkeypatch.setattr(candidate, "verify_ping_only_profiles", verify)
    rollback = Mock()
    monkeypatch.setattr(candidate, "rollback_candidate_configuration", rollback)
    profile_plan = PingOnlyProfilePlan((), (), ("spoke-stack",))

    def load() -> candidate.CandidateLoadResult:
        return candidate.load_candidate_configuration(
            panorama,
            "branch",
            (plan,),
            (replacement,),
            (_placement(),),
            allow_dirty_candidate=True,
            source_configuration=(),
            ping_only_profiles=profile_plan,
        )

    if failure:
        error = (
            candidate.CandidateLoadInterrupted
            if failure == "interrupt"
            else candidate.CandidateLoadError
        )
        with pytest.raises(error, match="rolled back"):
            load()
        rollback.assert_called_once()
    else:
        result = load()
        assert result.created_or_updated_objects == 15
        assert not rollback.called
        assert events == [
            "snapshot",
            "profile",
            "endpoint",
            "endpoint",
            "verify-profile",
        ]
    assert events[:2] == ["snapshot", "profile"]
    assert replacement.spoke.tunnel_interface.management_profile == "ping-only"
    assert replacement.hub.tunnel_interface.management_profile is None
    assert not xapi.commit.called


def test_management_profile_preview_assigns_only_spoke_tunnels() -> None:
    from unittest.mock import patch

    from panos_tunnel_builder import cli
    from panos_tunnel_builder.management_profiles import PingOnlyProfilePlan

    plan = _plan()
    replacement = lsvpn.build_standard_ipsec_objects(plan)
    profile_plan = PingOnlyProfilePlan((), (), ("spoke-stack",))
    panorama, xapi = _panorama()
    with patch.object(cli, "prepare_ping_only_profiles", return_value=profile_plan):
        result = cli._prepare_spoke_management_profiles(
            panorama,
            (_rename_inventory(),),
            "spoke-template",
            (replacement,),
        )
    assert result == profile_plan
    assert replacement.spoke.tunnel_interface.management_profile == "ping-only"
    assert replacement.hub.tunnel_interface.management_profile is None
    assert not xapi.set.called and not xapi.rename.called
