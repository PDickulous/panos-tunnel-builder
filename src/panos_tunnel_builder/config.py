import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    panorama_host: str
    panorama_api_key: str
    panorama_port: int = 443
    verify_ssl: bool = True


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_settings() -> Settings:
    load_dotenv()

    host = os.getenv("PANORAMA_HOST")
    api_key = os.getenv("PANORAMA_API_KEY")

    if not host:
        raise RuntimeError("PANORAMA_HOST is not set")

    if not api_key:
        raise RuntimeError("PANORAMA_API_KEY is not set")

    return Settings(
        panorama_host=host,
        panorama_api_key=api_key,
        panorama_port=int(os.getenv("PANORAMA_PORT", "443")),
        verify_ssl=_parse_bool(os.getenv("PANORAMA_VERIFY_SSL", "true")),
    )
