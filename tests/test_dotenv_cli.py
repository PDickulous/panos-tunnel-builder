"""Exercise the installed console script without any appliance connection."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def console_environment(tmp_path: Path) -> dict[str, str]:
    # The interceptor checks settings without printing keys and replaces the
    # Panorama connection before status can issue an API request.
    interceptor = tmp_path / "interceptor"
    interceptor.mkdir()
    (interceptor / "sitecustomize.py").write_text(
        """import os
from types import SimpleNamespace
from panos_tunnel_builder import cli

def offline_create(settings):
    actual = (settings.panorama_host, settings.panorama_api_key,
              str(settings.panorama_port), str(settings.verify_ssl),
              settings.ca_bundle or "")
    expected = tuple(os.environ[name] for name in (
        "TEST_EXPECT_HOST", "TEST_EXPECT_KEY", "TEST_EXPECT_PORT",
        "TEST_EXPECT_TLS", "TEST_EXPECT_CA"))
    if actual != expected:
        raise RuntimeError("offline settings mismatch")
    return SimpleNamespace(op=lambda **kwargs: "offline-settings-verified")

cli.create_panorama = offline_create
""",
        encoding="utf-8",
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PANORAMA_") and key != "PYTHON_DOTENV_DISABLED"
    }
    environment["PYTHONPATH"] = str(interceptor)
    return environment


def _run_console(
    directory: Path, environment: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
    script = Path(sys.executable).parent / (
        "panos-tunnel-builder.exe" if os.name == "nt" else "panos-tunnel-builder"
    )
    assert script.is_file(), "Install the project before running console-script tests"
    return subprocess.run(
        [str(script), *args, "status"],
        cwd=directory,
        env=environment,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )


def _expect(
    environment: dict[str, str], host: str, key: str, port: str, tls: str, ca: str
) -> None:
    environment.update(
        dict(
            zip(
                (
                    "TEST_EXPECT_HOST",
                    "TEST_EXPECT_KEY",
                    "TEST_EXPECT_PORT",
                    "TEST_EXPECT_TLS",
                    "TEST_EXPECT_CA",
                ),
                (host, key, port, tls, ca),
                strict=True,
            )
        )
    )


@pytest.mark.parametrize("mode", ["dotenv", "precedence", "toml"])
def test_installed_console_reads_only_working_directory_dotenv(
    tmp_path: Path,
    console_environment: dict[str, str],
    mode: str,
) -> None:
    workdir = tmp_path / "working"
    workdir.mkdir()
    # Parent .env must never supply settings, even when no local .env exists.
    (tmp_path / ".env").write_text(
        "PANORAMA_HOST=parent.invalid\nPANORAMA_API_KEY=parent-test-key\n",
        encoding="utf-8",
    )
    if mode != "toml":
        (workdir / ".env").write_text(
            "PANORAMA_HOST=cwd.invalid\nPANORAMA_API_KEY=cwd-test-key\n"
            "PANORAMA_PORT=4443\nPANORAMA_VERIFY_SSL=false\n",
            encoding="utf-8",
        )
    config = tmp_path / "settings.toml"
    config.write_text(
        '[panorama]\nhost="toml.invalid"\napi_key="toml-test-key"\n'
        'port=443\nverify_ssl=true\nca_bundle="toml-ca.pem"\n',
        encoding="utf-8",
    )
    if mode == "dotenv":
        _expect(console_environment, "cwd.invalid", "cwd-test-key", "4443", "False", "")
        args: tuple[str, ...] = ()
    elif mode == "precedence":
        console_environment["PANORAMA_HOST"] = "environment.invalid"
        console_environment["PANORAMA_VERIFY_SSL"] = "true"
        _expect(
            console_environment,
            "environment.invalid",
            "cwd-test-key",
            "4443",
            "True",
            "toml-ca.pem",
        )
        args = ("--config", str(config))
    else:
        _expect(
            console_environment,
            "toml.invalid",
            "toml-test-key",
            "443",
            "True",
            "toml-ca.pem",
        )
        args = ("--config", str(config))
    result = _run_console(workdir, console_environment, *args)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "offline-settings-verified" in result.stdout


def test_installed_console_does_not_load_parent_dotenv(
    tmp_path: Path,
    console_environment: dict[str, str],
) -> None:
    workdir = tmp_path / "working"
    workdir.mkdir()
    (tmp_path / ".env").write_text(
        "PANORAMA_HOST=parent.invalid\nPANORAMA_API_KEY=parent-test-key\n",
        encoding="utf-8",
    )
    result = _run_console(workdir, console_environment)
    assert result.returncode != 0
    assert "PANORAMA_HOST is not set" in result.stdout + result.stderr
    assert "offline-settings-verified" not in result.stdout
