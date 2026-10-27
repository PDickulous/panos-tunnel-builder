import ssl
import subprocess
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from panos.network import TunnelInterface
from panos.panorama import Panorama as SdkPanorama
from panos.panorama import Template

from panos_tunnel_builder.config import Settings
from panos_tunnel_builder.panorama_client import Firewall, create_panorama


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    directory = tmp_path_factory.mktemp("tls")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=panorama.example.test",
            "-addext",
            "subjectAltName=DNS:panorama.example.test",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def _handshake(
    context: ssl.SSLContext, certificate: tuple[Path, Path], host: str
) -> None:
    """Exercise OpenSSL verification without sockets or a live appliance."""
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(*certificate)
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(client_in, client_out, server_hostname=host)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client_done = server_done = False
    for _ in range(20):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        server_in.write(client_out.read())
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        client_in.write(server_out.read())
        if client_done and server_done:
            return
    pytest.fail("TLS handshake did not complete")


@pytest.mark.parametrize("redirected", [False, True])
@pytest.mark.parametrize("regenerate", [False, True])
@pytest.mark.parametrize(
    ("verify", "trust", "host", "accepted"),
    [
        (True, False, "panorama.example.test", False),
        (True, True, "panorama.example.test", True),
        (True, True, "wrong.example.test", False),
        (False, False, "wrong.example.test", True),
    ],
)
def test_actual_transport_certificate_verification(
    certificate: tuple[Path, Path],
    redirected: bool,
    regenerate: bool,
    verify: bool,
    trust: bool,
    host: str,
    accepted: bool,
) -> None:
    panorama = create_panorama(
        Settings(
            host,
            "dummy-test-key",
            verify_ssl=verify,
            ca_bundle=str(certificate[0]) if trust else None,
        )
    )
    device = panorama
    if redirected:
        device = Firewall(serial="test-serial")
        panorama.add(device)
    original = device.xapi
    if regenerate:
        panorama.update_connection_method()
        device.update_connection_method()
        assert device.xapi is not original
    # Intercept at the HTTP boundary, after the real SDK selects its context.
    with patch("pan.xapi.urlopen", side_effect=RuntimeError("intercepted")) as request:
        with pytest.raises(RuntimeError, match="intercepted"):
            device.op("show system info")
    assert request.call_args is not None
    context = request.call_args.kwargs["context"]
    assert context.verify_mode == (ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)
    assert context.check_hostname is verify
    http_request = request.call_args.kwargs["url"]
    assert urlsplit(http_request.full_url).hostname == host
    if redirected:
        assert parse_qs(http_request.data.decode())["target"] == ["test-serial"]
    if accepted:
        _handshake(context, certificate, host)
    else:
        with pytest.raises(ssl.SSLCertVerificationError):
            _handshake(context, certificate, host)


def test_invalid_ca_file_fails_before_any_request(tmp_path: Path) -> None:
    with patch("pan.xapi.urlopen") as request:
        with pytest.raises(FileNotFoundError):
            create_panorama(
                Settings("example.test", "dummy", ca_bundle=str(tmp_path / "missing"))
            )
    request.assert_not_called()


def test_redirect_requires_configured_parent_tls() -> None:
    panorama = SdkPanorama("example.test", api_key="dummy")
    firewall = Firewall(serial="test-serial")
    panorama.add(firewall)
    with pytest.raises(RuntimeError, match="TLS context"):
        firewall.op("show system info")


def test_tls_specialization_preserves_sdk_xpaths() -> None:
    secure = create_panorama(Settings("example.test", "dummy"))
    standard = SdkPanorama("example.test", api_key="dummy")
    paths = []
    for panorama in (secure, standard):
        panorama._version_info = (11, 1, 0)
        template = panorama.add(Template("test-template"))
        interface = template.add(TunnelInterface("tunnel.1"))
        paths.append(interface.xpath())
    assert paths[0] == paths[1]


def test_ha_peer_uses_its_verified_transport() -> None:
    primary = create_panorama(Settings("primary.example.test", "dummy"))
    peer = create_panorama(Settings("peer.example.test", "dummy"))
    primary.set_ha_peers(peer)
    primary.ha_failed = True
    peer.activate()
    with patch("pan.xapi.urlopen", side_effect=RuntimeError("intercepted")) as request:
        with pytest.raises(RuntimeError, match="intercepted"):
            primary.op("show system info", retry_on_peer=True)
    assert request.call_args is not None
    context = request.call_args.kwargs["context"]
    assert context is peer.xapi.ssl_context
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert (
        urlsplit(request.call_args.kwargs["url"].full_url).hostname
        == "peer.example.test"
    )
