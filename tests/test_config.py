from pathlib import Path

import pytest

from panos_tunnel_builder import config as config_module
from panos_tunnel_builder.config import (
    ConfigurationFileError,
    configure_from_file,
    load_settings,
)


def test_loads_panorama_settings_from_toml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config_module, "load_dotenv", lambda: False)
    config = tmp_path / "tunnels.toml"
    config.write_text(
        """
[panorama]
host = "panorama.example.test"
api_key = "secret"
port = 8443
verify_ssl = false

[build]
spoke_firewall = "branch-01"
hub_firewall = "hub-01"
""",
        encoding="utf-8",
    )
    for name in (
        "PANORAMA_HOST",
        "PANORAMA_API_KEY",
        "PANORAMA_PORT",
        "PANORAMA_VERIFY_SSL",
    ):
        monkeypatch.delenv(name, raising=False)

    defaults = configure_from_file(config)
    settings = load_settings()

    assert defaults == {"build": {"firewall": "branch-01", "hub": "hub-01"}}
    assert settings.panorama_host == "panorama.example.test"
    assert settings.panorama_api_key == "secret"
    assert settings.panorama_port == 8443
    assert settings.verify_ssl is False


def test_environment_overrides_panorama_file_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text(
        '[panorama]\nhost = "file-host"\napi_key = "file-key"\n',
        encoding="utf-8",
    )
    configure_from_file(config)
    monkeypatch.setenv("PANORAMA_HOST", "environment-host")
    monkeypatch.setenv("PANORAMA_API_KEY", "environment-key")

    settings = load_settings()

    assert settings.panorama_host == "environment-host"
    assert settings.panorama_api_key == "environment-key"


def test_rejects_unknown_configuration_key(tmp_path: Path) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text('[build]\nhubb = "typo"\n', encoding="utf-8")

    with pytest.raises(ConfigurationFileError, match="hubb"):
        configure_from_file(config)


def test_rejects_invalid_toml(tmp_path: Path) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text("[build\n", encoding="utf-8")

    with pytest.raises(ConfigurationFileError, match="Unable to load"):
        configure_from_file(config)


def test_rejects_invalid_panorama_value_type(tmp_path: Path) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text('[panorama]\nverify_ssl = "false"\n', encoding="utf-8")

    with pytest.raises(ConfigurationFileError, match="must be a boolean"):
        configure_from_file(config)


@pytest.mark.parametrize("value", ["true", "0", "-1", "65536", '"443"'])
def test_rejects_invalid_panorama_port(tmp_path: Path, value: str) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text(f"[panorama]\nport = {value}\n", encoding="utf-8")

    with pytest.raises(ConfigurationFileError, match="1 to 65535"):
        configure_from_file(config)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("PANORAMA_PORT", "0"),
        ("PANORAMA_PORT", "65536"),
        ("PANORAMA_VERIFY_SSL", "tru"),
    ],
)
def test_rejects_invalid_environment_settings(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setattr(config_module, "load_dotenv", lambda: False)
    configure_from_file(None)
    monkeypatch.setenv("PANORAMA_HOST", "example.test")
    monkeypatch.setenv("PANORAMA_API_KEY", "test-key")
    monkeypatch.setenv("PANORAMA_PORT", "443")
    monkeypatch.setenv("PANORAMA_VERIFY_SSL", "true")
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=name):
        load_settings()


def test_rejects_removed_router_rename_setting(tmp_path: Path) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text('[build]\nvirtual_router_name = "branch-vr"\n', encoding="utf-8")

    with pytest.raises(ConfigurationFileError, match="virtual_router_name"):
        configure_from_file(config)


@pytest.mark.parametrize("section", ["build", "candidate.restore"])
@pytest.mark.parametrize("setting", ["yes = false", 'skip_confirmation = "false"'])
def test_rejects_invalid_confirmation_setting(
    tmp_path: Path, section: str, setting: str
) -> None:
    config = tmp_path / "tunnels.toml"
    config.write_text(f"[{section}]\n{setting}\n", encoding="utf-8")

    with pytest.raises(ConfigurationFileError):
        configure_from_file(config)
