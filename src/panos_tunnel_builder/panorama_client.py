import ssl
from typing import Any

from panos.firewall import Firewall as SdkFirewall
from panos.panorama import Panorama as SdkPanorama

from .config import Settings


# The SDK also dispatches on class names when constructing configuration XPaths.
# Keep its names as well as inheritance when specializing transport generation.
class Panorama(SdkPanorama):
    """Preserve the TLS policy when the SDK regenerates its connection."""

    tls_context: ssl.SSLContext

    def generate_xapi(self) -> Any:
        xapi = super().generate_xapi()
        xapi.ssl_context = self.tls_context
        return xapi


class Firewall(SdkFirewall):
    """Use Panorama's TLS policy for serial-targeted API requests.

    The SDK creates a separate transport for each managed firewall and does not
    inherit the parent's SSL context. These objects must be attached to Panorama
    before their first API operation.
    """

    def generate_xapi(self) -> Any:
        context = self.panorama().xapi.ssl_context
        if context is None:
            raise RuntimeError("Panorama TLS context has not been configured")
        xapi = super().generate_xapi()
        xapi.ssl_context = context
        return xapi


def create_panorama(settings: Settings) -> Panorama:
    """
    Create a Panorama SDK object.

    Creating the object alone does not change Panorama configuration.
    The first SDK operation requiring data will establish the API session.
    """
    context = ssl.create_default_context(cafile=settings.ca_bundle)
    if not settings.verify_ssl:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    panorama = Panorama(
        hostname=settings.panorama_host,
        api_key=settings.panorama_api_key,
        port=settings.panorama_port,
    )

    panorama.tls_context = context

    return panorama
