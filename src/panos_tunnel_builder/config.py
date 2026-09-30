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


class ConfigurationFileError(RuntimeError):
    """Raised when a CLI configuration file cannot be loaded safely."""


_panorama_file_settings: dict[str, object] = {}

_CONFIGURATION_KEYS: dict[str, object] = {
    "panorama": {"host", "api_key", "port", "verify_ssl"},
    "status": set(),
    "build": {
        "firewall",
        "template_number",
        "hub",
        "hub_template_number",
        "vsys",
        "hub_vsys",
        "show_secrets",
        "tunnel_address_pool",
        "load_candidate",
        "allow_dirty_candidate",
        "snapshot_directory",
        "yes",
    },
    "routes": {
        "snapshot": {"firewall", "output", "vsys", "force"},
        "compare": {
            "before",
            "after",
            "prefix_map",
            "interface_map",
            "next_hop_map",
        },
        "verify-migration": {"manifest", "output_directory"},
    },
    "candidate": {"restore": {"snapshot", "yes"}},
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
    panorama = values.pop("panorama", {})
    assert isinstance(panorama, dict)
    for key in ("host", "api_key"):
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
    load_dotenv()

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
        verify_ssl=(
            _parse_bool(value)
            if (value := os.getenv("PANORAMA_VERIFY_SSL")) is not None
            else bool(_panorama_file_settings.get("verify_ssl", True))
        ),
    )
