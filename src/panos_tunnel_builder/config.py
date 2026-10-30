import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    panorama_host: str
    panorama_api_key: str
    panorama_port: int = 443
    verify_ssl: bool = True
    ca_bundle: str | None = None


class ConfigurationFileError(RuntimeError):
    """Raised when a CLI configuration file cannot be loaded safely."""


_panorama_file_settings: dict[str, object] = {}

# Public TOML names map to the existing Click parameter names.
_COMMAND_KEY_MAPS: dict[tuple[str, ...], dict[str, str]] = {
    ("build",): {
        "spoke_firewall": "firewall",
        "hub_firewall": "hub",
        "spoke_template_menu_number": "template_number",
        "hub_template_menu_number": "hub_template_number",
        "spoke_vsys": "vsys",
        "allow_pending_candidate_changes": "allow_dirty_candidate",
        "migration_artifact_directory": "snapshot_directory",
    },
    ("routes", "snapshot"): {
        "output_file": "output",
        "overwrite_existing_file": "force",
    },
    ("routes", "verify-migration"): {"manifest_file": "manifest"},
    ("candidate", "restore"): {"snapshot_name": "snapshot"},
}

_CONFIGURATION_KEYS: dict[str, object] = {
    "panorama": {"host", "api_key", "port", "verify_ssl", "ca_bundle"},
    "status": set(),
    "build": {
        "spoke_firewall",
        "hub_firewall",
        "spoke_template_name",
        "hub_template_name",
        "spoke_template_menu_number",
        "hub_template_menu_number",
        "spoke_vsys",
        "hub_vsys",
        "spoke_virtual_router_name",
        "show_secrets",
        "tunnel_address_pool",
        "load_candidate",
        "allow_pending_candidate_changes",
        "migration_artifact_directory",
        "skip_confirmation",
    },
    "routes": {
        "snapshot": {"firewall", "output_file", "vsys", "overwrite_existing_file"},
        "compare": {
            "before",
            "after",
            "prefix_map",
            "interface_map",
            "next_hop_map",
            "virtual_router_map",
        },
        "verify-migration": {"manifest_file", "output_directory"},
    },
    "candidate": {"restore": {"snapshot_name", "skip_confirmation"}},
}


def _validate_keys(
    values: dict[str, Any],
    schema: dict[str, object] | set[str],
    location: str,
) -> None:
    unknown = sorted(set(values) - set(schema))
    if unknown:
        names = ", ".join(unknown)
        raise ConfigurationFileError(
            f"Unknown configuration key(s) in {location}: {names}"
        )
    if isinstance(schema, set):
        return
    for key, value in values.items():
        child_schema = schema[key]
        if not isinstance(value, dict):
            raise ConfigurationFileError(
                f'Configuration section "{location}.{key}" must be a table.'
            )
        if not isinstance(child_schema, (dict, set)):
            raise AssertionError("Invalid internal configuration schema.")
        _validate_keys(value, child_schema, f"{location}.{key}")


def configure_from_file(path: Path | None) -> dict[str, Any]:
    """Load Panorama settings and return Click-compatible command defaults."""
    global _panorama_file_settings
    _panorama_file_settings = {}
    if path is None:
        return {}
    try:
        with path.open("rb") as stream:
            values = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationFileError(
            f'Unable to load configuration file "{path}": {exc}'
        ) from exc
    _validate_keys(values, _CONFIGURATION_KEYS, "configuration")
    build_defaults = values.get("build", {})
    if "spoke_virtual_router_name" in build_defaults and not isinstance(
        build_defaults["spoke_virtual_router_name"], str
    ):
        raise ConfigurationFileError(
            "build.spoke_virtual_router_name must be a string."
        )
    panorama = values.pop("panorama", {})
    assert isinstance(panorama, dict)
    for key in ("host", "api_key", "ca_bundle"):
        if key in panorama and not isinstance(panorama[key], str):
            raise ConfigurationFileError(
                f'Configuration value "panorama.{key}" must be a string.'
            )
    if "port" in panorama and (
        type(panorama["port"]) is not int or not 1 <= panorama["port"] <= 65535
    ):
        raise ConfigurationFileError(
            'Configuration value "panorama.port" must be an integer from 1 to 65535.'
        )
    if "verify_ssl" in panorama and not isinstance(panorama["verify_ssl"], bool):
        raise ConfigurationFileError(
            'Configuration value "panorama.verify_ssl" must be a boolean.'
        )
    for location, defaults in (
        ("build", values.get("build", {})),
        ("candidate.restore", values.get("candidate", {}).get("restore", {})),
    ):
        if "skip_confirmation" in defaults:
            skip_confirmation = defaults.pop("skip_confirmation")
            if not isinstance(skip_confirmation, bool):
                raise ConfigurationFileError(
                    f'Configuration value "{location}.skip_confirmation" '
                    "must be a boolean."
                )
            # Click defaults use the Python parameter name for --yes/-y.
            defaults["yes"] = skip_confirmation
    for path_parts, key_map in _COMMAND_KEY_MAPS.items():
        defaults = values
        for part in path_parts:
            defaults = defaults.get(part, {})
        for public_name, parameter_name in key_map.items():
            if public_name in defaults:
                defaults[parameter_name] = defaults.pop(public_name)
    _panorama_file_settings = panorama
    return values


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError("PANORAMA_VERIFY_SSL must be true/false, yes/no, on/off, or 1/0")


def load_settings() -> Settings:
    # The installed package may live outside the operator's working directory.
    # Do not search the installation tree or parents for connection credentials.
    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)

    host = os.getenv("PANORAMA_HOST") or _panorama_file_settings.get("host")
    api_key = os.getenv("PANORAMA_API_KEY") or _panorama_file_settings.get("api_key")

    if not host:
        raise RuntimeError("PANORAMA_HOST is not set")

    if not api_key:
        raise RuntimeError("PANORAMA_API_KEY is not set")

    port = int(
        str(os.getenv("PANORAMA_PORT") or _panorama_file_settings.get("port", 443))
    )
    if not 1 <= port <= 65535:
        raise ValueError("PANORAMA_PORT must be an integer from 1 to 65535")

    return Settings(
        panorama_host=str(host),
        panorama_api_key=str(api_key),
        panorama_port=port,
        ca_bundle=(
            os.getenv("PANORAMA_CA_BUNDLE")
            or str(_panorama_file_settings.get("ca_bundle", ""))
            or None
        ),
        verify_ssl=(
            _parse_bool(value)
            if (value := os.getenv("PANORAMA_VERIFY_SSL")) is not None
            else bool(_panorama_file_settings.get("verify_ssl", True))
        ),
    )
