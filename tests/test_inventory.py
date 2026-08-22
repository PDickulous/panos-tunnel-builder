from unittest.mock import Mock

import pytest
from panos.device import SystemSettings
from panos.firewall import Firewall
from panos.panorama import TemplateStack

from panos_tunnel_builder import inventory


def _firewall(hostname: str, serial: str) -> Firewall:
    firewall = Firewall(serial=serial)
    firewall.add(SystemSettings(hostname=hostname))
    return firewall


def test_discovers_stack_and_interface_templates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    panorama.refresh_devices.return_value = [_firewall("branch-01", "001122")]
    monkeypatch.setattr(
        inventory.TemplateStack,
        "refreshall",
        Mock(
            return_value=[
                TemplateStack(
                    "branch-stack",
                    templates=["base", "branch-network"],
                    devices=["001122"],
                )
            ]
        ),
    )
    monkeypatch.setattr(
        inventory,
        "_interface_names",
        Mock(
            side_effect=lambda template: (
                ("ethernet1/1", "ethernet1/2")
                if template.name == "branch-network"
                else ()
            )
        ),
    )

    result = inventory.discover_firewall_templates(panorama, "BRANCH-01")

    assert result.firewall_name == "branch-01"
    assert result.serial == "001122"
    assert result.stack_name == "branch-stack"
    assert [template.name for template in result.eligible_templates] == [
        "branch-network"
    ]


def test_unknown_firewall_is_rejected() -> None:
    panorama = Mock()
    panorama.refresh_devices.return_value = [_firewall("branch-01", "001122")]

    with pytest.raises(inventory.DiscoveryError, match="not managed"):
        inventory.discover_firewall_templates(panorama, "missing-firewall")


def test_unknown_firewall_suggests_close_hostname() -> None:
    panorama = Mock()
    panorama.refresh_devices.return_value = [_firewall("branch-denver-01", "001122")]

    with pytest.raises(inventory.DiscoveryError, match="branch-denver-01"):
        inventory.discover_firewall_templates(panorama, "branch-denvr-01")


def test_empty_firewall_name_is_rejected() -> None:
    panorama = Mock()
    panorama.refresh_devices.return_value = [_firewall("branch-01", "001122")]

    with pytest.raises(inventory.DiscoveryError, match="cannot be empty"):
        inventory.discover_firewall_templates(panorama, "   ")


def test_managed_firewall_resolution_is_case_insensitive() -> None:
    panorama = Mock()
    panorama.refresh_devices.return_value = [_firewall("hub-denver-01", "998877")]

    result = inventory.discover_managed_firewall(panorama, "HUB-DENVER-01")

    assert result == inventory.ManagedFirewall(
        name="hub-denver-01",
        serial="998877",
    )


def test_short_hostname_resolves_fqdn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    panorama.refresh_devices.return_value = [
        _firewall("branch-01.example.com", "001122")
    ]
    monkeypatch.setattr(
        inventory.TemplateStack,
        "refreshall",
        Mock(
            return_value=[
                TemplateStack(
                    "branch-stack",
                    templates=["network"],
                    devices=["001122"],
                )
            ]
        ),
    )
    monkeypatch.setattr(
        inventory,
        "_interface_names",
        Mock(return_value=("ethernet1/1",)),
    )

    result = inventory.discover_firewall_templates(panorama, "branch-01")

    assert result.firewall_name == "branch-01.example.com"


def test_firewall_without_stack_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    panorama.refresh_devices.return_value = [_firewall("branch-01", "001122")]
    monkeypatch.setattr(
        inventory.TemplateStack,
        "refreshall",
        Mock(return_value=[]),
    )

    with pytest.raises(inventory.DiscoveryError, match="not assigned"):
        inventory.discover_firewall_templates(panorama, "branch-01")


def test_discovers_every_firewall_inheriting_shared_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama = Mock()
    panorama.refresh_devices.return_value = [
        _firewall("branch-02", "002"),
        _firewall("branch-01", "001"),
    ]
    monkeypatch.setattr(
        inventory.TemplateStack,
        "refreshall",
        Mock(
            return_value=[
                TemplateStack(
                    "branches-a",
                    templates=["base", "shared-network"],
                    devices=["001"],
                ),
                TemplateStack(
                    "branches-b",
                    templates=["shared-network", "regional"],
                    devices=["002"],
                ),
            ]
        ),
    )
    monkeypatch.setattr(inventory, "_interface_names", Mock(return_value=()))

    scope = inventory.discover_shared_template_scope(panorama, "shared-network")

    assert [(item.firewall_name, item.stack_name) for item in scope.firewalls] == [
        ("branch-01", "branches-a"),
        ("branch-02", "branches-b"),
    ]
