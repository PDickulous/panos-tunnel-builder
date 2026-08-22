from typing import Protocol, cast

from panos.panorama import Panorama

from .config import Settings


class _TlsConfigurableXapi(Protocol):
    """Typed view of the XAPI wrapper's runtime TLS setting."""

    verify_ssl: bool


def create_panorama(settings: Settings) -> Panorama:
    """
    Create a Panorama SDK object.

    Creating the object alone does not change Panorama configuration.
    The first SDK operation requiring data will establish the API session.
    """
    panorama = Panorama(
        hostname=settings.panorama_host,
        api_key=settings.panorama_api_key,
        port=settings.panorama_port,
    )

    # pan-os-python exposes the underlying XAPI object.
    # This controls TLS certificate verification for API calls.
    cast(_TlsConfigurableXapi, panorama.xapi).verify_ssl = settings.verify_ssl

    return panorama
