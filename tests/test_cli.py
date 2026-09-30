from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from panos_tunnel_builder import cli
from panos_tunnel_builder.candidate import CandidateLoadResult
from panos_tunnel_builder.inventory import (
    FirewallTemplateInventory,
    SharedTemplateScope,
    TemplateCandidate,
)
from panos_tunnel_builder.lsvpn import (
    DynamicRoutingCloneSource,
    GatewayRuntime,
    HubGatewayCloneSource,
    HubTunnelInterfaceConfig,
    PortalGateway,
    RoutingInstanceConfig,
    SatelliteConfig,
    TunnelInterfaceInventory,
)
from panos_tunnel_builder.route_validation import RouteSnapshot

runner = CliRunner()


def _hub_clone_source() -> HubGatewayCloneSource:
    return HubGatewayCloneSource(
        name="Denver-Hub",
        address="198.51.100.20",
        external_interface="ethernet1/3",
        external_ipv4="198.51.100.20/24",
        external_ipv6=None,
        floating_ipv4=None,
        floating_ipv6=None,
        tunnel_interface=HubTunnelInterfaceConfig(
            name="tunnel.10",
            ip_addresses=("10.255.0.1/24",),
            ipv6_enabled=False,
            management_profile="ping-only",
            mtu=1400,
            netflow_profile=None,
            comment="LSVPN hub",
            virtual_routers=("default",),
            zones=("lsvpn",),
        ),
        ipsec_crypto_profile="lsvpn-ipsec",
        tunnel_monitor_enabled=True,
        tunnel_monitor_destination="10.255.0.2",
        tunnel_monitor_profile="fail-over",
        tunnel_monitor_source=None,
        access_routes=("10.0.0.0/8",),
        client_ip_pools=("10.255.0.0/24",),
        dns_primary="10.0.0.53",
        dns_secondary=None,
        dns_suffix="example.test",
    )


def _tunnel_inventories() -> tuple[
    TunnelInterfaceInventory,
    TunnelInterfaceInventory,
]:
    spoke = HubTunnelInterfaceConfig(
        name="tunnel.2",
        ip_addresses=(),
        ipv6_enabled=False,
        management_profile=None,
        mtu=None,
        netflow_profile=None,
        comment=None,
        virtual_routers=("default",),
        zones=("lsvpnsat",),
        routing_instances=(RoutingInstanceConfig("virtual-router", "default"),),
    )
    hub = _hub_clone_source().tunnel_interface
    return TunnelInterfaceInventory((spoke,)), TunnelInterfaceInventory((hub,))


def test_help_lists_status_command() -> None:
    result = runner.invoke(cli.app, ["--help"])

    assert result.exit_code == 0
    assert "status" in result.output
    assert "--config" in result.output
    assert "Interactively build and manage PAN-OS IPsec tunnels" in result.output


def test_status_reports_success(monkeypatch: pytest.MonkeyPatch) -> None:
    panorama = Mock()
    panorama.op.return_value = "<system-info />"
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=panorama))

    result = runner.invoke(cli.app, ["status"])

    assert result.exit_code == 0
    assert "Successfully connected to Panorama" in result.output
    assert "<system-info />" in result.output


def test_status_reports_configuration_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli,
        "load_settings",
        Mock(side_effect=RuntimeError("PANORAMA_HOST is not set")),
    )

    result = runner.invoke(cli.app, ["status"])

    assert result.exit_code == 2
    assert "Unexpected error: RuntimeError: PANORAMA_HOST is not set" in result.output


def test_candidate_restore_loads_snapshot_without_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    load_snapshot = Mock()
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=panorama))
    monkeypatch.setattr(cli, "load_panorama_snapshot", load_snapshot)
    name = "LSVPN_PRE_a1b2c_260819120000.xml"

    result = runner.invoke(
        cli.app,
        ["candidate", "restore", name, "--yes"],
    )

    assert result.exit_code == 0
    load_snapshot.assert_called_once_with(panorama, name)
    assert "No commit or push was issued" in result.output
    assert not panorama.commit.called


def _template_inventory() -> FirewallTemplateInventory:
    return FirewallTemplateInventory(
        firewall_name="branch-01",
        serial="001122",
        stack_name="branch-stack",
        templates=(
            TemplateCandidate("base", ()),
            TemplateCandidate("branch-network", ("ethernet1/1", "ethernet1/2")),
        ),
    )


def _hub_template_inventory() -> FirewallTemplateInventory:
    return FirewallTemplateInventory(
        firewall_name="hub-01",
        serial="998877",
        stack_name="hub-stack",
        templates=(
            TemplateCandidate("hub-base", ()),
            TemplateCandidate("hub-network", ("ethernet1/3",)),
        ),
    )


def _mock_hub_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(side_effect=[_template_inventory(), _hub_template_inventory()]),
    )
    monkeypatch.setattr(
        cli,
        "discover_lsvpn_satellites",
        Mock(return_value=()),
    )
    monkeypatch.setattr(
        cli,
        "discover_active_gateway",
        Mock(),
    )


def test_build_selects_only_template_with_interfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(return_value=_template_inventory()),
    )
    _mock_hub_discovery(monkeypatch)

    result = runner.invoke(
        cli.app,
        [
            "build",
            "branch-01",
            "--template-number",
            "2",
            "--hub",
            "hub-01",
            "--hub-template-number",
            "2",
            "--yes",
        ],
    )

    assert result.exit_code == 0
    assert "0. Cancel" not in result.output
    assert "Requested spoke: branch-01" in result.output
    assert 'Spoke template: "branch-network"' in result.output
    assert "Hub firewall: hub-01" in result.output
    assert 'Hub template: "hub-network"' in result.output


def test_build_uses_toml_command_defaults(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text(
        """
[build]
spoke_firewall = "branch-01"
spoke_template_menu_number = 2
hub_firewall = "hub-01"
hub_template_menu_number = 2
skip_confirmation = true
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    discovery = Mock(side_effect=[_template_inventory(), _hub_template_inventory()])
    monkeypatch.setattr(cli, "discover_firewall_templates", discovery)
    monkeypatch.setattr(cli, "discover_lsvpn_satellites", Mock(return_value=()))

    result = runner.invoke(cli.app, ["--config", str(config), "build"])

    assert result.exit_code == 0
    assert "Requested spoke: branch-01" in result.output
    assert 'Spoke template: "branch-network"' in result.output
    assert "Hub firewall: hub-01" in result.output
    assert 'Hub template: "hub-network"' in result.output
    assert [call.args[1] for call in discovery.call_args_list] == [
        "branch-01",
        "hub-01",
    ]


def test_command_line_value_overrides_toml_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text('[build]\nspoke_firewall = "wrong-branch"\n', encoding="utf-8")
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    discovery = Mock(return_value=_template_inventory())
    monkeypatch.setattr(cli, "discover_firewall_templates", discovery)

    result = runner.invoke(
        cli.app,
        ["--config", str(config), "build", "branch-01", "--template-number", "1"],
    )

    assert result.exit_code == 1
    assert discovery.call_args.args[1] == "branch-01"
    assert "does not contain interface configuration" in result.output


def test_config_file_error_is_reported(tmp_path: Path) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text("[build]\nunknown = true\n", encoding="utf-8")

    result = runner.invoke(cli.app, ["--config", str(config), "build"])

    assert result.exit_code == 2
    assert "Configuration file error" in result.output
    assert "unknown" in result.output


def test_toml_defaults_apply_to_nested_command(tmp_path: Path) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text(
        """
[routes.compare]
before = "missing-before.json"
after = "missing-after.json"
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        cli.app,
        ["--config", str(config), "routes", "compare"],
    )

    assert result.exit_code == 1
    assert "Route snapshot file error" in result.output
    assert "missing-before.json" in result.output


def test_load_candidate_is_successful_noop_when_satellite_is_already_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(side_effect=[_template_inventory(), _hub_template_inventory()]),
    )
    monkeypatch.setattr(cli, "discover_lsvpn_satellites", Mock(return_value=()))
    capture = Mock()
    monkeypatch.setattr(cli, "capture_route_snapshot", capture)

    result = runner.invoke(
        cli.app,
        [
            "build",
            "branch-01",
            "--template-number",
            "2",
            "--hub",
            "hub-01",
            "--hub-template-number",
            "2",
            "--load-candidate",
            "--yes",
        ],
    )

    assert result.exit_code == 0
    assert "no LSVPN satellite configuration remains" in result.output
    assert "Changes: none" in result.output
    capture.assert_not_called()


def test_build_rejects_template_without_interfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(return_value=_template_inventory()),
    )

    result = runner.invoke(
        cli.app,
        ["build", "branch-01", "--template-number", "1", "--yes"],
    )

    assert result.exit_code == 1
    assert "does not contain interface configuration" in result.output


def test_build_allows_user_to_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(return_value=_template_inventory()),
    )

    result = runner.invoke(cli.app, ["build", "branch-01"], input="0\n")

    assert result.exit_code == 1
    assert "Aborted" in result.output
    assert "Unexpected error" not in result.output


def test_build_reprompts_for_invalid_template_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(return_value=_template_inventory()),
    )
    _mock_hub_discovery(monkeypatch)

    result = runner.invoke(
        cli.app,
        ["build", "branch-01", "--hub", "hub-01"],
        input="9\n1\n2\n\ny\n",
    )

    assert result.exit_code == 0
    assert "Choose a number from 0 to 2" in result.output
    assert "does not contain interface configuration" in result.output
    assert 'Spoke template: "branch-network"' in result.output
    assert 'Hub template: "hub-network"' in result.output


def test_build_prompts_for_hub_firewall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(return_value=_template_inventory()),
    )
    _mock_hub_discovery(monkeypatch)

    result = runner.invoke(
        cli.app,
        ["build", "branch-01", "--yes"],
        input="\nhub-01\n\n",
    )

    assert result.exit_code == 0
    assert "Hub firewall hostname or serial number: hub-01" in result.output
    assert 'Hub firewall "hub-01" (998877)' in result.output
    assert "Hub template menu number" in result.output


def test_build_labels_initial_firewall_prompt_as_spoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(return_value=_template_inventory()),
    )

    result = runner.invoke(cli.app, ["build"], input="branch-01\n0\n")

    assert result.exit_code == 1
    assert "Spoke firewall hostname or serial number: branch-01" in result.output


def test_build_rejects_spoke_as_hub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(side_effect=[_template_inventory(), _template_inventory()]),
    )

    result = runner.invoke(
        cli.app,
        ["build", "branch-01", "--hub", "branch-01", "--yes"],
        input="\n",
    )

    assert result.exit_code == 1
    assert "hub firewall must be different" in result.output


def test_build_rejects_hub_stack_without_interface_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hub_without_interfaces = FirewallTemplateInventory(
        firewall_name="hub-01",
        serial="998877",
        stack_name="hub-stack",
        templates=(TemplateCandidate("hub-base", ()),),
    )
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(side_effect=[_template_inventory(), hub_without_interfaces]),
    )

    result = runner.invoke(
        cli.app,
        [
            "build",
            "branch-01",
            "--template-number",
            "2",
            "--hub",
            "hub-01",
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert "hub-stack" in result.output
    assert "no templates containing interface configuration" in result.output


@pytest.mark.parametrize("from_file", [False, True])
def test_build_reports_lsvpn_clone_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    from_file: bool,
) -> None:
    satellite = SatelliteConfig(
        name="legacy-satellite",
        tunnel_interface="tunnel.2",
        portal_address="203.0.113.11",
        local_interface="ethernet1/1",
        local_ipv4="203.0.113.13/24",
        local_ipv6=None,
        publish_connected_routes=True,
        published_routes=("10.20.0.0/16",),
        local_certificate="lsvpn-cert",
        certificate_profile="lsvpn-ca",
        anti_replay=True,
        copy_tos=False,
        tunnel_monitor_enabled=False,
        tunnel_monitor_destination=None,
        tunnel_monitor_profile=None,
    )
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(side_effect=[_template_inventory(), _hub_template_inventory()]),
    )
    monkeypatch.setattr(
        cli,
        "discover_lsvpn_satellites",
        Mock(return_value=(satellite,)),
    )
    monkeypatch.setattr(
        cli,
        "discover_lsvpn_satellite_template_owner",
        Mock(return_value="branch-network"),
    )
    monkeypatch.setattr(
        cli,
        "discover_shared_template_scope",
        Mock(
            return_value=SharedTemplateScope("branch-network", (_template_inventory(),))
        ),
    )
    monkeypatch.setattr(
        cli,
        "resolve_ike_local_endpoint",
        Mock(
            side_effect=lambda _p, _s, interface, address, _v, _r: (
                interface,
                address,
            )
        ),
    )
    monkeypatch.setattr(
        cli,
        "resolve_template_interface_address_reference",
        Mock(side_effect=lambda _p, _t, _i, address: address),
    )
    monkeypatch.setattr(
        cli,
        "discover_active_gateway",
        Mock(
            return_value=GatewayRuntime(
                satellite_name="legacy-satellite",
                gateway_name="Denver-Hub",
                gateway_address="198.51.100.20",
                status="Up",
            )
        ),
    )
    monkeypatch.setattr(
        cli,
        "discover_portal_gateways",
        Mock(
            return_value=(
                PortalGateway(
                    portal_name="LSVPN-Portal",
                    satellite_config_name="branches",
                    name="Denver-Hub",
                    address="198.51.100.20",
                    priority=1,
                    satellite_serials=("001122",),
                ),
            )
        ),
    )
    monkeypatch.setattr(
        cli,
        "discover_hub_gateway_clone_source",
        Mock(return_value=_hub_clone_source()),
    )
    monkeypatch.setattr(
        cli,
        "discover_tunnel_interface_inventory",
        Mock(side_effect=_tunnel_inventories()),
    )
    monkeypatch.setattr(
        cli,
        "discover_satellite_published_routes",
        Mock(return_value=("10.20.0.0/16",)),
    )
    monkeypatch.setattr(
        cli,
        "discover_dynamic_routing",
        Mock(return_value=DynamicRoutingCloneSource()),
    )
    capture_routes = Mock(
        side_effect=(
            RouteSnapshot(
                1,
                "branch-01",
                "001122",
                "vsys1",
                "2026-08-19T12:00:00+00:00",
                (),
            ),
            RouteSnapshot(
                1,
                "hub-01",
                "998877",
                "vsys1",
                "2026-08-19T12:00:00+00:00",
                (),
            ),
        )
    )
    placements = (Mock(),)
    discover_placements = Mock(return_value=placements)
    load_candidate = Mock(
        return_value=CandidateLoadResult(
            "LSVPN_PRE_a1b2c_260819120000.xml",
            14,
            5,
        )
    )
    monkeypatch.setattr(cli, "capture_route_snapshot", capture_routes)
    monkeypatch.setattr(
        cli,
        "discover_replacement_template_placements",
        discover_placements,
    )
    monkeypatch.setattr(cli, "load_candidate_configuration", load_candidate)

    if from_file:
        config = tmp_path / "tunnels.toml"
        config.write_text(
            f'[build]\nmigration_artifact_directory = "{tmp_path}"\n'
            "allow_pending_candidate_changes = true\n",
            encoding="utf-8",
        )
        prefix = ["--config", str(config)]
        artifact_flags: list[str] = []
    else:
        prefix = []
        artifact_flags = [
            "--migration-artifact-directory",
            str(tmp_path),
            "--allow-pending-candidate-changes",
        ]

    result = runner.invoke(
        cli.app,
        [
            *prefix,
            "build",
            "branch-01",
            "--template-number",
            "2",
            "--hub",
            "hub-01",
            "--hub-template-number",
            "2",
            "--load-candidate",
            *artifact_flags,
            "--yes",
        ],
        input="10.254.0.0/24\n",
    )

    assert result.exit_code == 0
    assert "Tunnel address pool (IPv4 /30s or IPv6 /127s)" in result.output
    assert "Shared spoke configuration" in result.output
    assert "Replaces: legacy-satellite on tunnel.2" in result.output
    assert "Creates: hub-01-1 / hub-01-1-ike" in result.output
    assert "Hub endpoint: ethernet1/3 / 198.51.100.20/24" in result.output
    assert "Per-spoke tunnel plan" in result.output
    assert "branch-01 (001122)" in result.output
    assert "WAN: ethernet1/1 / 203.0.113.13/24 -> 198.51.100.20" in result.output
    assert "Tunnel: spoke tunnel.1 (10.254.0.2/30) <-> hub tunnel.1" in result.output
    assert "Hub objects: branch-01-1 / branch-01-1-ike" in result.output
    assert "differs from configured portal address" in result.output
    assert "PSK for new variables: [hidden]" in result.output
    assert "Candidate load result" in result.output
    assert "Status: verified in Panorama candidate configuration" in result.output
    assert "Commit/push: not issued" in result.output
    assert capture_routes.call_count == 2
    assert len(tuple(tmp_path.glob("*_routes.json"))) == 2
    manifests = tuple(tmp_path.glob("*_validation.json"))
    assert len(manifests) == 1
    assert "LSVPN_PRE_a1b2c_260819120000.xml" in manifests[0].read_text()
    assert "Post-check manifest:" in result.output
    assert discover_placements.call_count == 1
    assert load_candidate.call_args.args[8] is True
    assert load_candidate.call_count == 1
    assert load_candidate.call_args.args[3][0].spoke.routing_object.name == "default"
    assert "SHA-256" in result.output
    assert "Crypto: IKEV2 aes-256-cbc/sha256" in result.output
    assert "AH alternative authentication" not in result.output
    assert "Routing: static" in result.output
    assert "New static routes: spoke [10.0.0.0/8]; hub [10.20.0.0/16]" in (
        result.output
    )


def test_build_errors_when_portal_has_multiple_gateways(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    satellite = SatelliteConfig(
        name="legacy-satellite",
        tunnel_interface="tunnel.2",
        portal_address="203.0.113.11",
        local_interface="ethernet1/1",
        local_ipv4="203.0.113.13/24",
        local_ipv6=None,
        publish_connected_routes=True,
        published_routes=(),
        local_certificate=None,
        certificate_profile=None,
        anti_replay=True,
        copy_tos=False,
        tunnel_monitor_enabled=False,
        tunnel_monitor_destination=None,
        tunnel_monitor_profile=None,
    )
    gateways = (
        PortalGateway(
            portal_name="LSVPN-Portal",
            satellite_config_name="branches",
            name="Primary-Hub",
            address="198.51.100.20",
            priority=1,
            satellite_serials=("001122",),
        ),
        PortalGateway(
            portal_name="LSVPN-Portal",
            satellite_config_name="branches",
            name="Backup-Hub",
            address="198.51.100.21",
            priority=10,
            satellite_serials=("001122",),
        ),
    )
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=Mock()))
    monkeypatch.setattr(
        cli,
        "discover_firewall_templates",
        Mock(side_effect=[_template_inventory(), _hub_template_inventory()]),
    )
    monkeypatch.setattr(
        cli,
        "discover_lsvpn_satellites",
        Mock(return_value=(satellite,)),
    )
    monkeypatch.setattr(
        cli,
        "discover_lsvpn_satellite_template_owner",
        Mock(return_value="branch-network"),
    )
    monkeypatch.setattr(
        cli,
        "discover_shared_template_scope",
        Mock(
            return_value=SharedTemplateScope("branch-network", (_template_inventory(),))
        ),
    )
    monkeypatch.setattr(
        cli,
        "resolve_ike_local_endpoint",
        Mock(
            side_effect=lambda _p, _s, interface, address, _v, _r: (
                interface,
                address,
            )
        ),
    )
    monkeypatch.setattr(
        cli,
        "resolve_template_interface_address_reference",
        Mock(side_effect=lambda _p, _t, _i, address: address),
    )
    monkeypatch.setattr(
        cli,
        "discover_active_gateway",
        Mock(
            return_value=GatewayRuntime(
                satellite_name="legacy-satellite",
                gateway_name="Unexpected-Hub",
                gateway_address="192.0.2.50",
                status="Up",
            )
        ),
    )
    monkeypatch.setattr(
        cli,
        "discover_portal_gateways",
        Mock(return_value=gateways),
    )
    monkeypatch.setattr(
        cli,
        "discover_tunnel_interface_inventory",
        Mock(side_effect=_tunnel_inventories()),
    )
    monkeypatch.setattr(
        cli,
        "discover_satellite_published_routes",
        Mock(return_value=()),
    )

    result = runner.invoke(
        cli.app,
        [
            "build",
            "branch-01",
            "--template-number",
            "2",
            "--hub",
            "hub-01",
            "--hub-template-number",
            "2",
            "--tunnel-address-pool",
            "10.254.0.0/24",
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert 'Portal "LSVPN-Portal" designates more than one' in result.output
    assert "Only one gateway per portal is supported" in result.output


def test_portal_candidates_allow_username_selected_configuration() -> None:
    gateway = PortalGateway(
        portal_name="LSVPN-Portal",
        satellite_config_name="authenticated-branches",
        name="Denver-Hub",
        address="198.51.100.20",
        priority=1,
        satellite_serials=("different-device",),
    )

    assert cli._portal_candidates((gateway,), "001122") == (gateway,)


def test_portal_candidates_still_prefer_an_exact_serial_match() -> None:
    username_candidate = PortalGateway(
        portal_name="LSVPN-Portal",
        satellite_config_name="authenticated-branches",
        name="Shared-Hub",
        address="198.51.100.21",
        priority=10,
        satellite_serials=("different-device",),
    )
    serial_candidate = PortalGateway(
        portal_name="LSVPN-Portal",
        satellite_config_name="serial-branches",
        name="Denver-Hub",
        address="198.51.100.20",
        priority=1,
        satellite_serials=("001122",),
    )

    result = cli._portal_candidates(
        (username_candidate, serial_candidate),
        "001122",
    )

    assert result == (serial_candidate,)


def test_active_username_gateway_takes_precedence_over_serial_guess() -> None:
    username_candidate = PortalGateway(
        portal_name="LSVPN-Portal",
        satellite_config_name="authenticated-branches",
        name="User-Hub",
        address="198.51.100.21",
        priority=1,
        satellite_serials=("different-device",),
    )
    serial_candidate = PortalGateway(
        portal_name="LSVPN-Portal",
        satellite_config_name="serial-branches",
        name="Serial-Hub",
        address="198.51.100.20",
        priority=1,
        satellite_serials=("001122",),
    )
    runtime = GatewayRuntime(
        satellite_name="legacy-satellite",
        gateway_name="User-Hub",
        gateway_address="198.51.100.21",
        status="Up",
    )

    result = cli._portal_candidates(
        (serial_candidate, username_candidate),
        "001122",
        runtime,
    )

    assert result == (username_candidate,)


def test_resolve_portal_gateway_prefers_the_active_gateway() -> None:
    gateways = (
        PortalGateway(
            "LSVPN-Portal",
            "branches",
            "Primary-Hub",
            "198.51.100.20",
            1,
            (),
        ),
        PortalGateway(
            "LSVPN-Portal",
            "branches",
            "Backup-Hub",
            "198.51.100.21",
            10,
            (),
        ),
    )
    runtime = GatewayRuntime(
        satellite_name="legacy-satellite",
        gateway_name="Backup-Hub",
        gateway_address="198.51.100.21",
        status="Up",
    )

    result = cli._resolve_portal_gateway(gateways, runtime, True)

    assert result == gateways[1]


def test_build_rejects_removed_router_rename_option() -> None:
    result = runner.invoke(cli.app, ["build", "--virtual-router-name", "branch-vr"])

    assert result.exit_code == 2
    assert "No such option" in result.output


@pytest.mark.parametrize(
    ("setting", "flags", "should_load"),
    [
        ("true", [], True),
        ("false", [], False),
        ("true", ["--no-yes"], False),
        ("false", ["--yes"], True),
    ],
)
def test_restore_confirmation_defaults_and_cli_overrides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
    flags: list[str],
    should_load: bool,
) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text(
        f'[candidate.restore]\nsnapshot_name = "saved.xml"\n'
        f"skip_confirmation = {setting}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "load_settings", Mock())
    monkeypatch.setattr(cli, "create_panorama", Mock())
    load_snapshot = Mock()
    monkeypatch.setattr(cli, "load_panorama_snapshot", load_snapshot)

    result = runner.invoke(
        cli.app,
        ["--config", str(config), "candidate", "restore", *flags],
        input="n\n",
    )

    assert result.exit_code == (0 if should_load else 1)
    assert load_snapshot.call_count == int(should_load)


@pytest.mark.parametrize(
    ("defaults", "flags"),
    [
        (
            "",
            [
                "--spoke-template-name",
                "branch-network",
                "--hub-template-name",
                "hub-network",
            ],
        ),
        (
            'spoke_template_name = "branch-network"\nhub_template_name = "hub-network"',
            [],
        ),
        (
            "spoke_template_menu_number = 1\nhub_template_menu_number = 1",
            [
                "--spoke-template-name",
                "branch-network",
                "--hub-template-name",
                "hub-network",
            ],
        ),
        (
            'spoke_template_name = "base"\nhub_template_name = "base"',
            ["--spoke-template-menu-number", "2", "--hub-template-menu-number", "2"],
        ),
    ],
)
def test_build_selects_template_names_and_cli_overrides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defaults: str,
    flags: list[str],
) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text(
        '[build]\nspoke_firewall = "branch-01"\nhub_firewall = "hub-01"\n'
        'spoke_vsys = "vsys2"\nskip_confirmation = true\n' + defaults,
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "load_settings", Mock())
    monkeypatch.setattr(cli, "create_panorama", Mock())
    discovery = Mock(side_effect=[_template_inventory(), _hub_template_inventory()])
    monkeypatch.setattr(cli, "discover_firewall_templates", discovery)
    satellites = Mock(return_value=())
    monkeypatch.setattr(cli, "discover_lsvpn_satellites", satellites)

    result = runner.invoke(cli.app, ["--config", str(config), "build", *flags])

    assert result.exit_code == 0, result.output
    assert 'Spoke template: "branch-network"' in result.output
    assert 'Hub template: "hub-network"' in result.output
    assert "templates in stack:" not in result.output
    assert satellites.call_args.args[2] == "vsys2"


@pytest.mark.parametrize("role", ["spoke", "hub"])
@pytest.mark.parametrize("from_file", [True, False])
def test_build_rejects_conflicting_template_selectors_before_connecting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    from_file: bool,
) -> None:
    connect = Mock()
    monkeypatch.setattr(cli, "create_panorama", connect)
    if from_file:
        config = tmp_path / "tunnels.toml"
        config.write_text(
            f'[build]\n{role}_template_name = "network"\n'
            f"{role}_template_menu_number = 2\n",
            encoding="utf-8",
        )
        args = ["--config", str(config), "build"]
    else:
        args = [
            "build",
            f"--{role}-template-name",
            "network",
            f"--{role}-template-menu-number",
            "2",
        ]

    result = runner.invoke(cli.app, args)

    assert result.exit_code == 2
    assert f"Choose one {role} template selector" in result.output
    connect.assert_not_called()


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("missing", "Available names"),
        ("BRANCH-NETWORK", "Available names"),
        ("base", "does not contain interface configuration"),
    ],
)
def test_template_name_rejects_unknown_or_ineligible_template(
    name: str, message: str
) -> None:
    with pytest.raises(cli.DiscoveryError, match=message):
        cli._resolve_template(_template_inventory(), None, "Spoke", name)


def test_template_name_selection_is_independent_of_menu_order() -> None:
    inventory = _template_inventory()
    reordered = FirewallTemplateInventory(
        firewall_name=inventory.firewall_name,
        serial=inventory.serial,
        stack_name=inventory.stack_name,
        templates=tuple(reversed(inventory.templates)),
    )

    selected = cli._resolve_template(reordered, None, "Spoke", "branch-network")

    assert selected.name == "branch-network"


@pytest.mark.parametrize(
    ("overwrite", "flags", "should_write"),
    [
        ("true", [], True),
        ("false", ["--overwrite-existing-file"], True),
        ("true", ["--no-overwrite-existing-file"], False),
    ],
)
def test_snapshot_explicit_overwrite_setting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overwrite: str,
    flags: list[str],
    should_write: bool,
) -> None:
    destination = tmp_path / "routes.json"
    destination.write_text("original", encoding="utf-8")
    config = tmp_path / "tunnels.toml"
    config.write_text(
        '[routes.snapshot]\nfirewall = "branch-01"\n'
        f'output_file = "{destination}"\noverwrite_existing_file = {overwrite}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "load_settings", Mock())
    monkeypatch.setattr(cli, "create_panorama", Mock())
    monkeypatch.setattr(cli, "discover_managed_firewall", Mock())
    snapshot = Mock(routes=(), to_json=Mock(return_value="replacement"))
    capture = Mock(return_value=snapshot)
    monkeypatch.setattr(cli, "capture_route_snapshot", capture)

    result = runner.invoke(
        cli.app, ["--config", str(config), "routes", "snapshot", *flags]
    )

    assert result.exit_code == (0 if should_write else 1), result.output
    assert destination.read_text() == ("replacement" if should_write else "original")
    assert capture.call_count == int(should_write)
