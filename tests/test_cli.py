from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from panos_tunnel_builder import artifacts, cli
from panos_tunnel_builder.candidate import (
    CandidateLoadResult,
    CandidateRestoreResult,
    SourceConfigurationFingerprint,
)
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
    name = "LSVPN_PRE_a1b2c_260819120000.xml"
    load_snapshot = Mock(return_value=CandidateRestoreResult(name, "checkpoint.xml"))
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=panorama))
    monkeypatch.setattr(cli, "restore_candidate_configuration", load_snapshot)

    result = runner.invoke(
        cli.app,
        ["candidate", "restore", name, "--yes"],
    )

    assert result.exit_code == 0
    assert load_snapshot.call_args.args == (panorama, name)
    assert callable(load_snapshot.call_args.kwargs["on_checkpoint_saved"])
    assert "No commit or push was issued" in result.output
    assert name in result.output
    assert not panorama.commit.called


@pytest.mark.parametrize(
    "scenario", ["success", "load-failed", "recovery-failed", "interrupted", "unlock"]
)
def test_restore_reports_checkpoint_recovery_and_cleanup_status(
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
) -> None:
    checkpoint = "LSVPN_CHK_a1b2c_260819120000.xml"
    monkeypatch.setattr(cli, "load_settings", Mock())
    monkeypatch.setattr(cli, "create_panorama", Mock())

    def restore(
        panorama: object,
        snapshot: str,
        *,
        on_checkpoint_saved: Callable[[str], None] | None = None,
    ) -> CandidateRestoreResult:
        assert on_checkpoint_saved is not None
        on_checkpoint_saved(checkpoint)
        if scenario in {"load-failed", "recovery-failed", "interrupted"}:
            recovery = (
                "Checkpoint recovery also failed; candidate may contain partial changes"
                if scenario == "recovery-failed"
                else "Pre-restore checkpoint was reloaded"
            )
            error = cli.CandidateRestoreError(
                f'Restore failed. {recovery}. Checkpoint "{checkpoint}".',
                interrupted=scenario == "interrupted",
            )
            if scenario == "recovery-failed":
                error.lock_cleanup_error = "unlock failed"
            raise error
        return CandidateRestoreResult(
            snapshot,
            checkpoint,
            lock_cleanup_error="unlock failed" if scenario == "unlock" else None,
        )

    monkeypatch.setattr(cli, "restore_candidate_configuration", restore)
    result = runner.invoke(cli.app, ["candidate", "restore", "saved.xml", "--yes"])

    assert result.exit_code == (
        0 if scenario == "success" else 130 if scenario == "interrupted" else 1
    )
    assert "Pre-restore checkpoint saved on Panorama" in result.output
    assert checkpoint in result.output
    if scenario in {"success", "unlock"}:
        assert 'Loaded Panorama snapshot "saved.xml"' in result.output
        assert "No commit or push was issued" in result.output
    else:
        assert "Loaded Panorama snapshot" not in result.output
        assert "Restore failed" in result.output
    if scenario in {"unlock", "recovery-failed"}:
        assert "Lock cleanup failed: unlock failed" in result.output


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
    monkeypatch.setattr(
        cli,
        "capture_source_configuration",
        Mock(
            side_effect=lambda _p, serial=None: SourceConfigurationFingerprint(
                serial, "candidate", "running"
            )
        ),
    )
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
@pytest.mark.parametrize(
    "interrupted",
    [
        None,
        "load",
        "rollback",
        "capture",
        "system-exit",
        "unlock",
        "manifest-write",
        "manifest-build",
        "source-drift",
    ],
)
def test_build_reports_lsvpn_clone_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    from_file: bool,
    interrupted: str | None,
) -> None:
    source_capture = Mock(
        side_effect=lambda _p, serial=None: SourceConfigurationFingerprint(
            serial, "candidate", "running"
        )
    )
    monkeypatch.setattr(cli, "capture_source_configuration", source_capture)
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

    if interrupted == "capture":
        capture_routes.side_effect = [
            capture_routes.side_effect.__next__(),
            KeyboardInterrupt(),
        ]
    elif interrupted in {"load", "rollback", "system-exit"}:

        def interrupt_load(*args: object, **kwargs: object) -> None:
            callback = kwargs["on_snapshot_saved"]
            assert callable(callback)
            callback("LSVPN_PRE_a1b2c_260819120000.xml")
            if interrupted == "system-exit":
                raise SystemExit(2)
            status = (
                "rollback also failed; may contain partial migration changes"
                if interrupted == "rollback"
                else "rolled back to running configuration"
            )
            raise cli.CandidateLoadInterrupted(status)

        load_candidate.side_effect = interrupt_load

    if interrupted == "source-drift":
        load_candidate.side_effect = cli.LsvpnConfigurationError(
            "Source configuration changed since discovery. Candidate loading was "
            "not attempted; rebuild and review a fresh plan and route baselines."
        )
    elif interrupted == "unlock":
        load_candidate.return_value = CandidateLoadResult(
            "LSVPN_PRE_a1b2c_260819120000.xml",
            14,
            5,
            lock_cleanup_error="RuntimeError: simulated unlock failure",
        )
    elif interrupted == "manifest-build":
        monkeypatch.setattr(
            cli,
            "_build_group_migration_manifest",
            Mock(side_effect=ValueError("invalid manifest")),
        )
    elif interrupted == "manifest-write":
        original_write = cli.write_private_artifact

        def fail_manifest_write(
            path: Path,
            content: str,
            *,
            overwrite: bool = False,
            retain_staging_on_error: bool = False,
        ) -> None:
            if retain_staging_on_error:
                raise OSError("simulated disk full")
            original_write(path, content, overwrite=overwrite)

        monkeypatch.setattr(cli, "write_private_artifact", fail_manifest_write)

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

    if interrupted == "source-drift":
        assert result.exit_code == 1
        assert "Source configuration changed" in result.output
        assert "rebuild and review a fresh plan" in result.output
        assert not tuple(tmp_path.glob("*_routes.json"))
        assert not tuple(tmp_path.glob("*_validation.json"))
        assert "Recovery snapshot saved" not in result.output
        return
    if interrupted == "manifest-build":
        assert result.exit_code == 1
        assert "Candidate loading was not attempted" in result.output
        load_candidate.assert_not_called()
        assert not tuple(tmp_path.glob("*_routes.json"))
        return
    if interrupted in {"unlock", "manifest-write"}:
        assert result.exit_code == 1
        assert "verified in Panorama candidate configuration" in result.output
        assert "LSVPN_PRE_a1b2c_260819120000.xml" in result.output
        assert "Commit/push: not issued" in result.output
        assert len(tuple(tmp_path.glob("*_routes.json"))) == 2
        if interrupted == "unlock":
            assert "simulated unlock failure" in result.output
            assert len(tuple(tmp_path.glob("*_validation.json"))) == 1
        else:
            assert "simulated disk full" in result.output
            assert "remains staged" in result.output
            assert not tuple(tmp_path.glob("*_validation.json"))
        return
    if interrupted:
        assert result.exit_code == 130
        assert "retained after interruption" in result.output
        baselines = tuple(tmp_path.glob("*_routes.json"))
        assert len(baselines) == (1 if interrupted == "capture" else 2)
        assert all(str(path) in result.output for path in baselines)
        assert not tuple(tmp_path.glob("*_validation.json"))
        if interrupted == "capture":
            load_candidate.assert_not_called()
        else:
            assert "Recovery snapshot saved on Panorama" in result.output
            assert "LSVPN_PRE_a1b2c_260819120000.xml" in result.output
        if interrupted == "rollback":
            assert "may contain partial migration changes" in result.output
        return

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
    if artifacts.os.name == "posix":
        for path in (*tmp_path.glob("*_routes.json"), *manifests):
            assert path.stat().st_mode & 0o777 == 0o600
    assert "LSVPN_PRE_a1b2c_260819120000.xml" in manifests[0].read_text()
    assert "Post-check manifest:" in result.output
    assert discover_placements.call_count == 1
    assert load_candidate.call_args.args[8] is True
    assert load_candidate.call_count == 1
    assert [call.args[1:] for call in source_capture.call_args_list] == [
        (),
        ("001122",),
        ("998877",),
    ]
    assert load_candidate.call_args.kwargs["source_configuration"] == (
        SourceConfigurationFingerprint(None, "candidate", "running"),
        SourceConfigurationFingerprint("001122", "candidate", "running"),
        SourceConfigurationFingerprint("998877", "candidate", "running"),
    )
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
    load_snapshot = Mock(
        return_value=CandidateRestoreResult("saved.xml", "checkpoint.xml")
    )
    monkeypatch.setattr(cli, "restore_candidate_configuration", load_snapshot)

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
    if should_write and artifacts.os.name == "posix":
        assert destination.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("failure", ["fsync", "rename", "serialize"])
@pytest.mark.parametrize("lock_failed", [False, True])
def test_manifest_failure_preserves_candidate_and_recovery_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    failure: str,
    lock_failed: bool,
) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text("baseline evidence")
    destination = tmp_path / "validation.json"
    destination.write_text("previous manifest")
    result = CandidateLoadResult(
        "LSVPN_PRE_a1b2c_260819120000.xml",
        14,
        5,
        lock_cleanup_error="unlock failure" if lock_failed else None,
    )
    endpoint = cli.MigrationEndpointValidation(
        role="spoke",
        firewall_name="branch",
        serial="001122",
        vsys="vsys1",
        baseline_snapshot=baseline.name,
        prefix_map={},
        path_mappings=(),
        allowed_added_prefixes=(),
    )
    manifest = cli.MigrationValidationManifest(1, "test-time", "", (endpoint,))
    if failure == "fsync":
        monkeypatch.setattr(
            artifacts.os, "fsync", Mock(side_effect=OSError("disk full"))
        )
    elif failure == "rename":
        monkeypatch.setattr(Path, "replace", Mock(side_effect=OSError("rename denied")))
    else:
        monkeypatch.setattr(
            cli.MigrationValidationManifest,
            "to_json",
            Mock(side_effect=ValueError("serialization failed")),
        )

    with pytest.raises(cli.CandidateLoadError) as raised:
        cli._finish_candidate_load(result, manifest, destination, [baseline])

    output = capsys.readouterr()
    assert "verified in Panorama candidate configuration" in output.out
    assert result.panorama_snapshot_name in output.out
    assert str(baseline) in output.out
    assert "Commit/push: not issued" in output.out
    assert ("unlock failure" in output.err) is lock_failed
    assert "remains staged" in str(raised.value)
    assert "no rollback was attempted" in str(raised.value)
    assert str(destination) in str(raised.value)
    assert baseline.read_text() == "baseline evidence"
    assert destination.read_text() == "previous manifest"
    staging = destination.with_suffix(".json.tmp")
    if failure != "serialize":
        staged_manifest = cli.MigrationValidationManifest.from_json(staging.read_text())
        assert staged_manifest.panorama_snapshot_name == result.panorama_snapshot_name
    else:
        assert not staging.exists()


def test_transaction_and_lock_errors_retain_baselines_and_report_both(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text("recovery evidence")
    original = cli.CandidateLoadError(
        "write failure; rollback failed; saved snapshot example.xml"
    )
    original.lock_cleanup_error = "unlock failure"
    with pytest.raises(cli.CandidateLoadError) as raised:
        with cli._migration_route_artifacts() as paths:
            paths.append(baseline)
            raise original
    assert raised.value is original
    assert baseline.read_text() == "recovery evidence"
    with pytest.raises(cli.typer.Exit) as exited:
        cli._report_candidate_error(original)
    assert exited.value.exit_code == 1
    output = capsys.readouterr().err
    assert str(baseline) in output
    assert "rollback failed" in output
    assert "example.xml" in output
    assert "unlock failure" in output


def test_artifact_cleanup_failure_does_not_mask_preflight_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    baseline = tmp_path / "baseline.json"
    original = ValueError("preflight failed")
    monkeypatch.setattr(Path, "unlink", Mock(side_effect=OSError("delete denied")))
    with pytest.raises(ValueError) as raised:
        with cli._migration_route_artifacts() as paths:
            paths.append(baseline)
            raise original
    assert raised.value is original
    assert "delete denied" in capsys.readouterr().err


def test_build_captures_shared_sources_before_discovery_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    spoke = _template_inventory()
    hub = _hub_template_inventory()
    extra = replace(spoke, firewall_name="branch-02", serial="003344")
    events: list[str] = []
    panorama = Mock()
    monkeypatch.setattr(cli, "load_settings", Mock(return_value=Mock()))
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=panorama))

    def capture(
        _panorama: object, serial: str | None = None
    ) -> SourceConfigurationFingerprint:
        events.append(f"capture:{serial}")
        return SourceConfigurationFingerprint(serial, "candidate", "running")

    def inventory(_panorama: object, name: str) -> FirewallTemplateInventory:
        events.append(f"inventory:{name}")
        return spoke if name == "branch-01" else hub

    def satellites(*args: object) -> tuple[Mock, ...]:
        events.append("satellites")
        satellite = Mock()
        satellite.name = "legacy"
        return (satellite,)

    def scope(*args: object) -> SharedTemplateScope:
        events.append("scope")
        return SharedTemplateScope("branch-network", (spoke, extra))

    def build(*args: object) -> cli.SharedBuildResult:
        events.append("plan")
        return cli.SharedBuildResult((), cli.CandidateVariableSet())

    monkeypatch.setattr(cli, "capture_source_configuration", capture)
    monkeypatch.setattr(cli, "discover_firewall_templates", inventory)
    monkeypatch.setattr(cli, "discover_lsvpn_satellites", satellites)
    monkeypatch.setattr(
        cli,
        "discover_lsvpn_satellite_template_owner",
        Mock(return_value="branch-network"),
    )
    monkeypatch.setattr(cli, "discover_shared_template_scope", scope)
    monkeypatch.setattr(cli, "_build_shared_migration", build)
    result = runner.invoke(
        cli.app,
        [
            "build",
            "branch-01",
            "--spoke-template-name",
            "branch-network",
            "--hub",
            "hub-01",
            "--hub-template-name",
            "hub-network",
            "--tunnel-address-pool",
            "10.254.0.0/24",
            "--load-candidate",
            "--yes",
        ],
    )
    assert result.exit_code == 0, result.output
    assert events == [
        "capture:None",
        "inventory:branch-01",
        "inventory:hub-01",
        "capture:001122",
        "capture:998877",
        "satellites",
        "scope",
        "capture:003344",
        "plan",
    ]
